"""Contratos do nOS, inclusive evidência ausente e efeitos de orçamento."""

from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from nvg_scanner.collectors import Collector, Context, Unavailable
from nvg_scanner.config import load_config, validate, ConfigError
from nvg_scanner.diff import compare
from nvg_scanner.engine import scan
from nvg_scanner.nos_network import verify
from nvg_scanner.reports import to_json, to_markdown
from nvg_scanner.checks.vault_checks import run as vault_run
from nvg_scanner.checks.storage_checks import run as storage_run
from nvg_scanner.checks.installation_checks import login_configs, fstab_checks
from nvg_scanner.checks.nostr_agent_checks import run as agent_run
from nvg_scanner.checks.kernel_checks import run as kernel_run
from tests.fixtures import ROOT, FakeCollector, metadata
from tests.test_packages import context as package_context, Packages
from tests.test_key_exposure import context as key_context


def policy(profile="installed"):
    return load_config(ROOT / "config/nos.json", profile)


class Native(FakeCollector):
    def __init__(self, state="verified", mode="base", code=None):
        super().__init__()
        self.code = {"verified": 0, "mismatch": 1, "unknown": 2}[state] if code is None else code
        self.document = {"schema_version": 1, "observed_at": datetime.now(timezone.utc).isoformat(),
                         "verification": {"requested": mode, "state": state},
                         "firewall": {"mode": mode, "state": state, "reason": "nft: permissão insuficiente"}}
        self.files["/usr/lib/neovanguard/network-policies.json"] = '{"public":"reference"}'
        for filename in ("/usr/lib/neovanguard/network-policies.json", "/usr/lib/neovanguard/neo-rede.sh"):
            path = Path(filename)
            self.metadata[str(path)] = metadata(0o644, 0, 0)
            for parent in path.parents:
                self.metadata[str(parent)] = metadata(0o755, 0, 0, True)

    def command_status(self, args):
        self.calls.append(tuple(args))
        return self.code, json.dumps(self.document)


class NosTests(unittest.TestCase):
    def test_all_shipped_profiles_validate(self):
        document = json.loads((ROOT / "config/nos.json").read_text())
        for name in document["profiles"]:
            with self.subTest(profile=name): policy(name)

    def test_incompatible_vault_and_vpn_without_endpoints_rejected(self):
        for overrides in ({"vault": True}, {"expected_network_mode": "killswitch-vpn"}, {"target_user": "root;echo leak"}):
            cfg = policy(); cfg.pop("profile"); cfg["nos"].update(overrides)
            with self.assertRaises(ConfigError): validate(cfg)

    def test_native_states_and_fresh_cache(self):
        for state, expected in (("verified", "pass"), ("mismatch", "fail"), ("unknown", "warning")):
            collector = Native(state)
            report = scan(Context(policy(), collector), ["firewall_checks"])
            self.assertEqual(report["results"][0]["status"], expected)
            if state == "unknown": self.assertIn("permissão", report["results"][0]["reason"])
            calls = [c for c in collector.calls if c[0] == "bash"]
            self.assertEqual(len(calls), 1)
            self.assertIn("network_verify", calls[0][4])
            self.assertNotIn("network_apply", repr(collector.calls))

    def test_native_contradiction_missing_fields_stale_unknown_never_pass(self):
        for change in (lambda f: setattr(f, "code", 2),
                       lambda f: f.document.pop("verification"),
                       lambda f: f.document.update(observed_at="2020-01-01T00:00:00+00:00"),
                       lambda f: f.document["firewall"].update(mode="custom"),
                       lambda f: f.document.update(schema_version=True),
                       lambda f: f.metadata.update({"/usr/lib/neovanguard/neo-rede.sh": metadata(0o666, 0, 0)})):
            fake = Native(); change(fake)
            results = scan(Context(policy(), fake), ["firewall_checks"])["results"]
            self.assertTrue(results)
            self.assertTrue(all(r["status"] == "warning" for r in results))

    def test_mode_mismatch_does_not_fallback_to_generic_pass(self):
        fake = Native()
        cfg = policy("tor")
        self.assertEqual(scan(Context(cfg, fake), ["firewall_checks"])["results"][0]["status"], "warning")

    def test_mode_not_inferred_from_markers_tor_skipped_only_by_policy(self):
        ctx = Context(policy(), FakeCollector(files={"/run/neovanguard/tor": "1"}))
        report = scan(ctx, ["tor_checks"])
        self.assertEqual(report["results"][0]["status"], "warning")
        self.assertEqual(report["selection"]["omitted"][0]["module"], "tor_checks")
        ctx.config["nos"]["expected_network_mode"] = "tor"
        report = scan(ctx, ["tor_checks"])
        self.assertTrue(report["results"])
        self.assertFalse(any(r["id"].startswith("engine.") for r in report["results"]))

    def test_quick_selection_records_omission_and_unknown_package_total(self):
        ctx = package_context(); ctx.config["execution"] = {"preset": "quick", "max_seconds": 20, "max_output_bytes": 10000}
        report = scan(ctx)
        self.assertTrue(any(r["module"] == "package_integrity_checks" for r in report["selection"]["omitted"]))
        self.assertIsNone(report["summary"]["package_coverage"]["total_installed"])
        self.assertIn("total instalado desconhecido", to_markdown(report))

    def test_kernel_text_and_numeric_policy(self):
        cfg = policy(); cfg["kernel"] = {"kernel.core_pattern": cfg["kernel"]["kernel.core_pattern"]}
        for raw, expected in (("|/bin/false\n", "pass"), ("core\n", "fail")):
            result = next(kernel_run(Context(cfg, FakeCollector(files={"/proc/sys/kernel/core_pattern": raw}))))
            self.assertEqual(result.status, expected)

    def test_vault_up_flag_not_operstate_and_missing_radio(self):
        cfg = policy("vault-live")
        fake = FakeCollector(commands={"ip": json.dumps([{"flags": ["UP"], "operstate": "DOWN"}])})
        results = {r.id: r for r in vault_run(Context(cfg, fake))}
        self.assertEqual(results["vault.interfaces"].status, "fail")
        self.assertEqual(results["vault.radios"].status, "warning")

    def test_vault_no_radio_is_distinct_from_query_failure(self):
        fake = FakeCollector(commands={"ip": json.dumps([{"flags": ["LOOPBACK", "UP"]}]), "rfkill": '{"rfkilldevices":[]}'} )
        results = {r.id: r for r in vault_run(Context(policy("vault-live"), fake))}
        self.assertEqual(results["vault.interfaces"].status, "pass")
        self.assertEqual(results["vault.radios"].status, "pass")

    def test_mounts_and_zram_writeback(self):
        cfg = policy()
        mounts = [{"target": p, "source": "tmpfs", "fstype": "tmpfs", "options": "rw,nosuid,nodev,noexec"} for p in cfg["nos"]["mounts"]]
        fake = FakeCollector(files={"/proc/swaps": "Filename Type Size Used Priority\n/dev/zram0 partition 100 0 100\n", "/sys/block/zram0/backing_dev": "/dev/disk\n"},
                             commands={"findmnt": json.dumps({"filesystems": mounts})})
        results = list(storage_run(Context(cfg, fake)))
        self.assertTrue(all(r.status == "pass" for r in results if r.id.startswith("storage.mount.")))
        self.assertEqual(next(r.status for r in results if r.id == "storage.swap"), "warning")
        mounts[0]["options"] = "rw,nosuid,nodev"
        fake.commands["findmnt"] = json.dumps({"filesystems": mounts})
        self.assertEqual(next(storage_run(Context(cfg, fake))).status, "fail")

    def test_mounts_overlaid_are_unknown(self):
        row = {"target": "/tmp", "source": "tmpfs", "fstype": "tmpfs", "options": "noexec,nodev,nosuid"}
        fake = FakeCollector(commands={"findmnt": json.dumps({"filesystems": [row, row]})})
        first = next(storage_run(Context(policy(), fake)))
        self.assertEqual(first.status, "warning")

    def test_journald_composed_overrides_and_runtime_warning(self):
        fake = FakeCollector(commands={"systemd-analyze": "[Journal]\nStorage=volatile\n[Journal]\nStorage=persistent\n"})
        results = {r.id: r for r in storage_run(Context(policy(), fake))}
        self.assertEqual(results["storage.journal.Storage"].status, "fail")
        self.assertEqual(results["storage.journal.runtime"].status, "warning")

    def test_agent_no_socket_name_never_guesses_path(self):
        ctx = Context(policy(), FakeCollector())
        with patch("nvg_scanner.checks.nostr_agent_checks.target_user", return_value={"uid": 123, "name": "demo", "runtime": "/run/user/123", "home": "/home/demo"}):
            results = list(agent_run(ctx))
        self.assertEqual(next(r.status for r in results if r.id == "nostr_agent.socket"), "warning")
        self.assertFalse(any("MemoryDenyWriteExecute" in r.id for r in results))

    def test_diff_context_and_numeric_coverage_only(self):
        before = scan(package_context(), ["package_integrity_checks"])
        after = deepcopy(before); after["context"] = {"expected_network_mode": "bunker://sensitive"}
        after["summary"]["package_coverage"]["cryptographically_verified"] = 0
        report = compare(before, after)
        self.assertIn("context", report["comparability_warnings"])
        self.assertEqual(report["package_metrics"]["cryptographically_verified"]["delta"], -1)
        self.assertNotIn("sensitive", to_json(report))

    def test_bunker_and_shamir_do_not_persist_secret_or_reconstruct(self):
        secret = "fixture-credential-private-value"
        uri = "bunker://" + "a" * 64 + "?secret=" + secret
        report = scan(key_context(uri.encode()), ["key_exposure_checks"])
        self.assertEqual(report["results"][0]["status"], "fail")
        self.assertNotIn(secret, to_json(report) + to_markdown(report))
        part = "nvgs2-2-3-1-abcd1234-deadbeef-aabbccdd"
        share_report = scan(key_context(part.encode()), ["key_exposure_checks"])
        self.assertTrue(all(r["status"] == "warning" and r["severity"] == "high" for r in share_report["results"]))
        self.assertNotIn(part, to_json(share_report))
        legacy = deepcopy(report); legacy["results"][0]["id"] = uri
        self.assertNotIn(secret, to_json(compare(legacy, legacy)))

    def test_collector_real_stdout_limit_and_timeout(self):
        collector = Collector(timeout=1)
        collector.max_output_bytes = 1024
        with self.assertRaises(Unavailable):
            collector.command(["python3", "-c", "print('x' * 100000)"])
        with self.assertRaises(Unavailable):
            collector.command(["python3", "-c", "import time; time.sleep(3)"])
        collector.deadline = time.monotonic() - 1
        with self.assertRaises(Unavailable): collector.command(["true"])


class CoverageTests(unittest.TestCase):
    def test_total_not_equal_selected_or_examined(self):
        class Large(Packages):
            def command(self, args):
                if args[-1] == "-Q":
                    return "bitcoin 1.0-1\n" + "".join(f"pkg{i:03} 1-1\n" for i in range(129))
                return super().command(args)
        ctx = package_context(Large()); ctx.config["package_integrity"]["max_packages"] = 128
        report = scan(ctx, ["package_integrity_checks"])
        c = report["summary"]["package_coverage"]
        self.assertEqual((c["total_installed"], c["selected"], c["examined"], c["cryptographically_verified"], c["not_verified"]), (130, 128, 128, 1, 129))
        self.assertIn("1 de 130", to_markdown(report))
        self.assertEqual(c["inconclusive"], 127)

    def test_bad_valid_untrusted_missing_key_and_no_cache(self):
        for status, verified, valid, invalid, trusted in [
            ((1, "[GNUPG:] BADSIG x"), 1, 0, 1, 0),
            ((0, "[GNUPG:] VALIDSIG x\n[GNUPG:] TRUST_MARGINAL"), 1, 1, 0, 0),
            ((2, "[GNUPG:] NO_PUBKEY x"), 0, 0, 0, 0),
            (Unavailable("keyring missing"), 0, 0, 0, 0),
        ]:
            c = scan(package_context(Packages(status)), ["package_integrity_checks"])["summary"]["package_coverage"]
            self.assertEqual((c["cryptographically_verified"], c["valid_signatures"], c["invalid_signatures"], c["trusted_valid_signatures"]), (verified, valid, invalid, trusted))
        fake = Packages(); fake.cached = False
        c = scan(package_context(fake), ["package_integrity_checks"])["summary"]["package_coverage"]
        self.assertEqual(c["verification_attempts"], 0)
        self.assertEqual(c["not_verified"], 2)

    def test_unknown_inventory_is_null(self):
        report = scan(package_context(FakeCollector()), ["package_integrity_checks"])
        c = report["summary"]["package_coverage"]
        self.assertIsNone(c["total_installed"])
        self.assertIsNone(c["coverage_percent"])

    def test_priority_before_limit(self):
        ctx = package_context(); ctx.config["package_integrity"].update(max_packages=1, priority_packages=["foreign"])
        report = scan(ctx, ["package_integrity_checks"])
        self.assertEqual(report["summary"]["package_coverage"]["cryptographically_verified"], 0)
        self.assertTrue(any(r["id"] == "package_integrity.signature.foreign" for r in report["results"]))

    def test_numeric_diff_metrics_reject_text(self):
        report = scan(package_context(), ["package_integrity_checks"])
        report["summary"]["package_coverage"]["total_installed"] = "secret"
        with self.assertRaises(ValueError): compare(report, report)


class AdditionalContractTests(unittest.TestCase):
    def test_valid_nsec_encrypted_container_is_not_read_by_permissions(self):
        from nvg_scanner.checks.permissions_checks import run
        cfg = policy(); cfg["nos"]["features"]["nostr_identity"] = True
        cfg["permissions"]["sensitive_paths"] = [cfg["permissions"]["sensitive_paths"][1]]
        fake = FakeCollector()
        filename = "/home/demo/.local/share/neovanguard/chave.ncryptsec"
        fake.metadata[filename] = metadata()
        for parent in Path(filename).parents:
            fake.metadata[str(parent)] = metadata(0o700, 1000 if str(parent).startswith("/home/demo") else 0, 0, True)
        ctx = Context(cfg, fake)
        ctx.cache["nos.user"] = {"uid": 1000, "home": "/home/demo", "name": "demo", "runtime": "/run/user/1000"}
        results = list(run(ctx))
        self.assertEqual(results[0].status, "pass")
        self.assertFalse(any(c[0] == "read" for c in fake.calls))

    def test_batch_service_queries_populate_cache(self):
        from nvg_scanner.collectors import batch_services, service_properties
        raw = "Id=a.service\nLoadState=loaded\nActiveState=active\nMainPID=1\n\nId=b.service\nLoadState=loaded\nActiveState=active\nMainPID=2\n"
        fake = FakeCollector(commands={"systemctl": raw})
        ctx = Context(policy(), fake)
        batch_services(ctx, {"a.service", "b.service"})
        self.assertEqual(service_properties(ctx, "a.service")["MainPID"], "1")
        self.assertEqual(service_properties(ctx, "b.service")["MainPID"], "2")
        self.assertEqual(len(fake.calls), 1)

    def test_vault_known_activity_survives_malformed_other_row(self):
        fake = FakeCollector(commands={"ip": '[{"flags":["UP"]},{"unexpected":true}]'})
        result = next(vault_run(Context(policy("vault-live"), fake)))
        self.assertEqual(result.status, "fail")
        self.assertEqual(result.evidence["unknown_rows"], 1)

    def test_expensive_modules_run_last(self):
        from tests.fixtures import synthetic_context
        ctx = synthetic_context(); ctx.config["package_integrity"] = package_context().config["package_integrity"]
        report = scan(ctx)
        self.assertEqual(report["modules"][-1], "package_integrity_checks")

    def test_global_deadline_omits_work_and_emits_warning(self):
        ctx = package_context(); ctx.config["execution"] = {"max_seconds": 1, "max_output_bytes": 1024, "preset": "full"}
        with patch("nvg_scanner.engine.time.monotonic", side_effect=[0, 2]):
            report = scan(ctx, ["package_integrity_checks"])
        self.assertEqual(report["results"][0]["status"], "warning")
        self.assertEqual(report["selection"]["omitted"][0]["reason"], "orçamento global de tempo esgotado")

    def test_keyring_cleanup_on_interruption(self):
        collector = Collector()
        with patch("nvg_scanner.engine._scan", side_effect=KeyboardInterrupt):
            with patch.object(collector, "end_scan", wraps=collector.end_scan) as end:
                with self.assertRaises(KeyboardInterrupt): scan(Context(policy(), collector))
                end.assert_called_once()

    def test_domain_score_not_diluted_by_package_count(self):
        from nvg_scanner.models import Result
        from nvg_scanner.scoring import by_domain
        weights = policy()["weights"]
        failure = Result("firewall.failure", "Firewall", "fail", "critical", "Mismatch", "Review")
        scores = []
        for size in (1, 1000):
            results = [failure] + [Result(f"package_integrity.signature.p{i}", "Package", "pass", "high", "Valid", "Preserve") for i in range(size)]
            domains = by_domain(results, weights)
            scores.append(sum(d["score"] for d in domains.values()) / len(domains))
        self.assertEqual(scores, [50, 50])

    def test_sudo_nopasswd_and_sddm_autologin_are_reported_without_content(self):
        class Files(FakeCollector):
            def select_files(self, pattern, max_entries):
                return ([pattern] if pattern in self.files else []), False
            def read_regular_bytes(self, path, limit):
                return self.files[path].encode()[:limit], False
        fake = Files(files={"/etc/sudoers": "liveuser ALL=(ALL) NOPASSWD: ALL\n# private fixture text\n", "/etc/sddm.conf": "[Autologin]\nUser=liveuser\n"})
        fake.metadata = {path: metadata(0o600, 0, 0) for path in fake.files}
        results = list(login_configs(Context(policy(), fake)))
        self.assertTrue(all(r.status == "fail" for r in results))
        self.assertNotIn("private fixture", repr(results))
        self.assertFalse(any("NOPASSWD" in str(r.evidence) for r in results))

    def test_fstab_duplicate_var_log_fails(self):
        row = {"target": "/var/log", "fstype": "tmpfs", "options": "nodev,nosuid,noexec"}
        fake = FakeCollector(commands={"findmnt": json.dumps({"filesystems": [row, row]})})
        results = list(fstab_checks(Context(policy(), fake)))
        self.assertEqual(next(r.status for r in results if r.id == "installation.fstab._var_log"), "fail")

    def test_native_cache_only_within_scan(self):
        fake = Native(); ctx = Context(policy(), fake)
        verify(ctx); verify(ctx)
        self.assertEqual(len([c for c in fake.calls if c[0] == "bash"]), 1)
        scan(ctx, ["firewall_checks"])
        self.assertEqual(len([c for c in fake.calls if c[0] == "bash"]), 2)

    def test_agent_properties_and_socket_type(self):
        import stat
        from nvg_scanner.checks.nostr_agent_checks import PROPERTIES
        user = {"uid": 123, "name": "demo", "runtime": "/run/user/123", "home": "/home/demo"}
        raw = "LoadState=loaded\nActiveState=active\nMainPID=100\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=read-only\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nReadWritePaths=/run/user/123\n"
        fake = FakeCollector(commands={"systemctl": raw})
        for p in ("/", "/run", "/run/user"):
            fake.metadata[p] = metadata(0o755, 0, 0, True)
        fake.metadata["/run/user/123"] = metadata(0o700, 123, 123, True)
        fake.metadata["/run/user/123/agent.sock"] = os.stat_result((stat.S_IFSOCK | 0o600, 1,1,1,123,123,0,0,0,0))
        cfg = policy(); cfg["nos"]["agent_socket"] = "agent.sock"
        with patch("nvg_scanner.checks.nostr_agent_checks.target_user", return_value=user):
            results = {r.id: r for r in agent_run(Context(cfg, fake))}
        self.assertEqual(results["nostr_agent.socket"].status, "pass")
        self.assertEqual(results["nostr_agent.ProtectSystem"].status, "pass")
        self.assertEqual(results["nostr_agent.RestrictAddressFamilies"].status, "pass")
        self.assertEqual(results["nostr_agent.SystemCallFilter"].status, "warning")


class VpnTests(unittest.TestCase):
    def test_endpoints_drift_is_not_hidden_by_up_interface(self):
        from nvg_scanner.checks.vpn_checks import run
        cfg = policy(); cfg["nos"].update(expected_network_mode="killswitch-vpn", vpn_endpoints=[["198.18.0.2", 51820]])
        fake = FakeCollector(commands={"ip": '[{"ifname":"wg0","flags":["UP"]}]',
            ("wg", "show", "wg0", "endpoints"): "public-key 198.18.0.3:51820\n",
            ("wg", "show", "wg0", "latest-handshakes"): "public-key 0\n"})
        results = {r.id: r for r in run(Context(cfg, fake))}
        self.assertEqual(results["vpn.interface"].status, "pass")
        self.assertEqual(results["vpn.endpoints"].status, "fail")
        self.assertEqual(results["vpn.handshakes"].status, "warning")
        self.assertNotIn("public-key", repr(results))

    def test_missing_vpn_tools_remains_inconclusive(self):
        from nvg_scanner.checks.vpn_checks import run
        self.assertTrue(all(r.status == "warning" for r in run(Context(policy(), FakeCollector()))))
