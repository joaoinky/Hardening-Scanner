import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

from nvg_scanner import checks
from nvg_scanner.__main__ import main, write_reports
from nvg_scanner.checks import account_checks, kernel_checks, network_checks, permissions_checks, service_checks, tor_checks
from nvg_scanner.collectors import Collector, Context, Unavailable
from nvg_scanner.config import ConfigError, load_config, validate
from nvg_scanner.engine import discover, scan
from nvg_scanner.models import Result, inconclusive
from nvg_scanner.reports import to_json, to_markdown
from nvg_scanner.scoring import summarize
from tests.fixtures import ROOT, FakeCollector, config, metadata, synthetic_context


class NetworkTests(unittest.TestCase):
    def test_ipv4_ipv6_udp_and_malformed(self):
        sockets, rejected = network_checks.parse_listeners(
            "tcp LISTEN 0 128 127.0.0.1:9050 0.0.0.0:*\n"
            "tcp LISTEN 0 128 [::1]:9050 [::]:*\n"
            "udp UNCONN 0 0 [fe80::1%eth0]:5353 [::]:*\ninvalid\n")
        self.assertEqual(len(sockets), 3)
        self.assertEqual(rejected, 1)
        self.assertIn(("udp", "fe80::1%eth0", 5353), sockets)

    def test_loopback_whitelist_never_authorizes_all_interfaces(self):
        rules = config()["network"]["allowed_listeners"]
        for address in ("0.0.0.0", "::", "*", "192.168.1.3"):
            self.assertFalse(network_checks.allowed(("tcp", address, 9050), rules))
        self.assertTrue(network_checks.allowed(("tcp", "::1", 9050), rules))
        self.assertFalse(network_checks.allowed(("udp", "::1", 9050), rules))

    def test_cidr_and_explicit_wildcard(self):
        rules = [{"protocol": "tcp", "port": 80, "address": "192.168.1.0/24"}]
        self.assertTrue(network_checks.allowed(("tcp", "192.168.1.2", 80), rules))
        self.assertFalse(network_checks.allowed(("tcp", "0.0.0.0", 80), rules))
        rules[0]["address"] = "*"
        self.assertTrue(network_checks.allowed(("tcp", "*", 80), rules))

    def test_unspecified_bind_requires_explicit_authorization(self):
        rules = [{"protocol": "tcp", "port": 80, "address": "::/64"}]
        self.assertFalse(network_checks.allowed(("tcp", "::", 80), rules))
        rules[0]["address"] = "::/0"
        self.assertTrue(network_checks.allowed(("tcp", "::", 80), rules))
        rules[0]["address"] = "::"
        self.assertTrue(network_checks.allowed(("tcp", "::", 80), rules))

    def test_missing_tool_and_invalid_output_never_pass(self):
        for fake in (FakeCollector(), FakeCollector(commands={"ss": "unexpected output"})):
            results = list(network_checks.run(Context(config(), fake)))
            self.assertTrue(results)
            self.assertTrue(all(r.status == "warning" for r in results))


class PermissionTests(unittest.TestCase):
    def setUp(self):
        self.context = synthetic_context()
        self.fake = self.context.collector
        self.entry = self.context.config["permissions"]["sensitive_paths"][0]

    def test_world_readable_key_fails_without_reading_secret(self):
        results = list(permissions_checks.run(self.context))
        self.assertEqual(results[0].status, "fail")
        self.assertFalse(self.fake.calls)

    def test_private_key_and_safe_parents_pass(self):
        self.fake.metadata["/vault/nostr.key"] = metadata(0o600)
        self.assertEqual(list(permissions_checks.run(self.context))[0].status, "pass")

    def test_parent_write_and_owner_mismatch_fail(self):
        self.fake.metadata["/vault/nostr.key"] = metadata(0o600, uid=2000)
        self.fake.metadata["/vault"] = metadata(0o770, directory=True)
        result = list(permissions_checks.run(self.context))[0]
        self.assertEqual(result.status, "fail")
        self.assertIn("/vault", result.evidence["unsafe_parents"])
        self.assertIn("Proprietário", result.description)

    def test_missing_required_and_optional(self):
        del self.fake.metadata["/vault/nostr.key"]
        self.assertEqual(list(permissions_checks.run(self.context))[0].status, "fail")
        self.entry["required"] = False
        self.assertEqual(list(permissions_checks.run(self.context))[0].status, "warning")

    def test_acl_does_not_produce_false_pass(self):
        self.fake.metadata["/vault/nostr.key"] = metadata(0o600)
        self.fake.attributes["/vault/nostr.key"] = ["system.posix_acl_access"]
        self.assertEqual([r.status for r in permissions_checks.run(self.context)], ["warning"])

    def test_symlink_denied_even_if_target_private(self):
        self.fake.metadata["/vault/nostr.key"] = os.stat_result((stat.S_IFLNK | 0o777, 1, 1, 1, 1000, 1000, 0, 0, 0, 0))
        self.fake.targets["/vault/nostr.key"] = "/vault/real.key"
        self.fake.metadata["/vault/real.key"] = metadata(0o600)
        self.assertEqual(list(permissions_checks.run(self.context))[0].status, "fail")

    def test_real_file_does_not_open_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "key"
            path.write_text("synthetic-private-value")
            path.chmod(0o644)
            self.entry.update(path=str(path), uid=os.getuid())
            self.context.collector = Collector()
            results = list(permissions_checks.run(self.context))
            self.assertTrue(any(r.status == "fail" for r in results))
            self.assertNotIn("synthetic-private-value", repr(results))


class TorTests(unittest.TestCase):
    def setUp(self):
        self.context = synthetic_context()
        self.fake = self.context.collector

    def test_external_control_without_authentication_fails(self):
        self.fake.files["/etc/tor/torrc"] = "ControlPort 0.0.0.0:9051\nSafeSocks 1\n"
        results = {r.id: r for r in tor_checks.run(self.context)}
        self.assertEqual(results["tor.controlport"].status, "fail")
        self.assertEqual(results["tor.control_auth"].status, "fail")
        self.assertEqual(results["tor.control_auth"].severity, "critical")

    def test_control_cookie_auth_and_no_hash_in_evidence(self):
        secret = "16:" + "A" * 58
        self.fake.files["/etc/tor/torrc"] = f"ControlPort 9051\nCookieAuthentication 1\nHashedControlPassword {secret}\n"
        results = list(tor_checks.run(self.context))
        self.assertEqual(next(r for r in results if r.id == "tor.control_auth").status, "pass")
        self.assertNotIn(secret, repr(results))

    def test_recursive_include_and_cycle(self):
        self.fake.files["/etc/tor/torrc"] = '%include "/etc/tor/extra.conf"\n'
        self.fake.files["/etc/tor/extra.conf"] = "SafeSocks 1\nSocksPort [::1]:9050\n"
        options, issues = tor_checks.parse_torrc(self.fake, "/etc/tor/torrc")
        self.assertFalse(issues)
        self.assertEqual(options["safesocks"], [["1"]])
        self.fake.files["/etc/tor/extra.conf"] = "%include /etc/tor/torrc\n"
        self.assertTrue(tor_checks.parse_torrc(self.fake, "/etc/tor/torrc")[1])

    def test_ambiguous_config_not_approved(self):
        for content in ("%include relative.conf", "%include /missing.conf", "+SocksPort 9050", "SafeSocks 1\\\n"):
            self.fake.files["/etc/tor/torrc"] = content
            results = list(tor_checks.config_checks(self.context))
            self.assertEqual([r.status for r in results], ["warning"])

    def test_local_resolver_never_proves_absence_of_leaks(self):
        results = {r.id: r for r in tor_checks.dns_checks(self.context)}
        self.assertEqual(results["tor.dns_resolvers"].status, "pass")
        self.assertEqual(results["tor.dns_assurance"].status, "warning")
        self.fake.files["/etc/resolv.conf"] = "nameserver 8.8.8.8\n"
        self.assertEqual(list(tor_checks.dns_checks(self.context))[0].status, "fail")

    def test_inactive_service_not_tool_error(self):
        self.fake.commands["systemctl"] = "LoadState=loaded\nActiveState=inactive\nMainPID=0\n"
        self.assertEqual(next(tor_checks.run(self.context)).status, "fail")

    def test_default_unsafe_socks_and_unknown_endpoint(self):
        self.fake.files["/etc/tor/torrc"] = "SocksPort auto\n"
        results = {r.id: r for r in tor_checks.config_checks(self.context)}
        self.assertEqual(results["tor.socksport"].status, "warning")
        self.assertEqual(results["tor.safe_socks"].status, "fail")


class SystemTests(unittest.TestCase):
    def test_missing_kernel_value_is_warning(self):
        results = list(kernel_checks.run(Context(config(), FakeCollector())))
        self.assertTrue(all(r.status == "warning" for r in results))

    def test_effective_uid_overrides_configured_user(self):
        context = synthetic_context()
        context.collector.commands["systemctl"] = "LoadState=loaded\nActiveState=active\nMainPID=123\nUser=root\n"
        results = list(service_checks.run(context))
        self.assertEqual(results[0].status, "pass")
        context.collector.files["/proc/123/status"] = "Uid:\t0\t0\t0\t0\n"
        self.assertEqual(list(service_checks.run(context))[0].status, "fail")
        context.config["services"]["require_non_root"] = []
        self.assertEqual(list(service_checks.run(context))[0].status, "warning")

    def test_shadow_unreadable_and_empty_password(self):
        context = synthetic_context()
        results = {r.id: r for r in account_checks.run(context)}
        self.assertEqual(results["accounts.password.nvg"].status, "fail")
        context.collector.files["/etc/shadow"] = Unavailable("Sem permissão")
        results = {r.id: r for r in account_checks.run(context)}
        self.assertEqual(results["accounts.shadow"].status, "warning")

    def test_legacy_hash_is_never_serialized(self):
        context = synthetic_context()
        secret = "$1$not-a-real-hash"
        context.collector.files["/etc/shadow"] = f"root:{secret}:19000:0:99999:7:::\nnvg:!:19000:0:99999:7:::\n"
        results = list(account_checks.run(context))
        self.assertEqual(next(r for r in results if r.id == "accounts.password.root").status, "fail")
        self.assertNotIn(secret, repr(results))

    def test_additional_uid_zero_and_empty_shell(self):
        context = synthetic_context()
        context.collector.files["/etc/passwd"] += "backdoor:!:0:0::/root:\n"
        results = {r.id: r for r in account_checks.run(context)}
        self.assertEqual(results["accounts.uid0.backdoor"].status, "fail")
        self.assertEqual(results["accounts.shell.backdoor"].status, "warning")


class EngineConfigReportTests(unittest.TestCase):
    def test_scoring_excludes_warnings_and_exposes_coverage(self):
        results = [Result("a", "a", "pass", "high", "ok", "ok"),
                   Result("b", "b", "fail", "high", "bad", "fix"),
                   inconclusive("c", "c", "missing", "critical")]
        summary = summarize(results, config()["weights"])
        self.assertEqual(summary["score"], 50)
        self.assertEqual(summary["weighted_coverage_percent"], 50)
        self.assertEqual(summary["coverage_percent"], 66.67)
        self.assertIsNone(summarize(results[2:], config()["weights"])["score"])

    def test_new_module_discovered_without_engine_change_and_failure_isolated(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "demo_checks.py").write_text(
                "from nvg_scanner.models import Result\n"
                "def run(context):\n"
                "    yield Result('demo.ok', 'Demo', 'pass', 'low', 'ok', 'ok')\n"
                "    raise RuntimeError('secret-must-not-appear')\n")
            try:
                with patch.object(checks, "__path__", [*checks.__path__, directory]):
                    self.assertIn("demo_checks", discover())
                    report = scan(synthetic_context(), ["demo_checks", "kernel_checks"])
                ids = {r["id"] for r in report["results"]}
                self.assertIn("demo.ok", ids)
                self.assertIn("engine.demo_checks", ids)
                self.assertIn("kernel.kernel.randomize_va_space", ids)
                self.assertNotIn("secret-must-not-appear", to_json(report))
            finally:
                sys.modules.pop("nvg_scanner.checks.demo_checks", None)

    def test_live_profile_replaces_sensitive_path_list(self):
        policy = load_config(ROOT / "config/example.json", "live")
        self.assertEqual(len(policy["permissions"]["sensitive_paths"]), 1)

    def test_invalid_policy_rejected(self):
        changes = [lambda c: c["weights"].update(high=0),
                   lambda c: c["network"]["allowed_listeners"][0].update(port=True),
                   lambda c: c["network"]["allowed_listeners"][0].update(address="localhost"),
                   lambda c: c["permissions"]["sensitive_paths"][0].update(max_mode="777"),
                   lambda c: c["permissions"]["sensitive_paths"][0].update(path="/etc/../shadow"),
                   lambda c: c["services"]["allowed_root_services"].append("tor.service")]
        for change in changes:
            policy = config()
            policy.pop("profile")
            change(policy)
            with self.assertRaises(ConfigError):
                validate(policy)

    def test_duplicate_json_keys_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "config.json")
            path.write_text('{"schema_version": 1, "schema_version": 1}')
            with self.assertRaises(ConfigError):
                load_config(path, "installed")

    def test_report_roundtrip_and_examples_marked(self):
        report = scan(synthetic_context())
        report["example"] = True
        self.assertEqual(json.loads(to_json(report)), report)
        markdown = to_markdown(report)
        self.assertIn("EXEMPLO SINTÉTICO", markdown)
        self.assertIn("FAIL", markdown)
        self.assertIn("WARNING", markdown)

    def test_markdown_evidence_cannot_close_fence(self):
        report = scan(synthetic_context(), ["network_checks"])
        report["results"][0]["evidence"] = {"path": "```\n<script>bad</script>"}
        report["results"][0]["name"] = "<script>bad</script>\x1b[31m"
        markdown = to_markdown(report)
        self.assertIn("````json", markdown)
        self.assertNotIn("\x1b", markdown)
        self.assertIn("&lt;script&gt;", markdown)

    def test_private_output_no_overwrite_and_partial_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory, "a"), Path(directory, "b")
            second.write_text("existing")
            with self.assertRaises(FileExistsError):
                write_reports([(first, "new"), (second, "overwrite")])
            self.assertFalse(first.exists())
            self.assertEqual(second.read_text(), "existing")
            write_reports([(first, "report")])
            self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o600)

    def test_cli_both_and_failure_exit_code(self):
        report = scan(synthetic_context())
        with tempfile.TemporaryDirectory() as directory, patch("nvg_scanner.__main__.scan", return_value=report):
            code = main(["--config", str(ROOT / "config/example.json"), "--format", "both", "--output", directory])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(Path(directory, "report.json").read_text()), report)
            self.assertTrue(Path(directory, "report.md").is_file())

    def test_collector_command_error_redacted(self):
        with self.assertRaises(Unavailable) as caught:
            Collector().command(["python3", "-c", "import sys; print('private-value'); sys.stderr.write('private-error'); sys.exit(1)"])
        self.assertNotIn("private", str(caught.exception))

    def test_collector_command_timeout_becomes_unavailable(self):
        with self.assertRaises(Unavailable):
            Collector(timeout=0.05).command(["python3", "-c", "import time; time.sleep(2)"])

    def test_invalid_plugin_evidence_isolated_before_reporting(self):
        from types import SimpleNamespace
        bad = Result("invalid", "Invalid", "pass", "low", "ok", "ok", {"unsupported": object()})
        with patch("nvg_scanner.engine.importlib.import_module", return_value=SimpleNamespace(run=lambda context: [bad])):
            report = scan(synthetic_context(), ["network_checks"])
        self.assertEqual(report["results"][0]["id"], "engine.network_checks")
        self.assertIsNone(report["summary"]["score"])
        json.loads(to_json(report))


if __name__ == "__main__":
    unittest.main()
