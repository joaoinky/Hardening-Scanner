import unittest
from unittest.mock import patch
import time
import hashlib
from pathlib import Path
import shutil
import tempfile

from nvg_scanner.checks.package_integrity_checks import run, signature_state
from nvg_scanner.collectors import Context, Unavailable
from tests.fixtures import config, FakeCollector


class Packages(FakeCollector):
    def __init__(self, status=(0, "[GNUPG:] VALIDSIG fingerprint\n[GNUPG:] TRUST_FULLY 0 pgp\n")):
        super().__init__()
        self.status = status
        self.cached = True

    def command(self, args):
        if args[0] == "pacman-conf":
            return "core\n" if args[-1] == "--repo-list" else "PackageRequired\nPackageTrustedOnly\nDatabaseOptional\nDatabaseTrustedOnly\n"
        if args[-1] == "-Q": return "bitcoin 1.0-1\nforeign 2-1\n"
        if args[-1] == "-Sl": return "core bitcoin 1.0-1 [installed]\n"
        if "-Qp" in args: return "bitcoin 1.0-1\n"
        raise Unavailable("Comando inesperado na fixture")

    def glob(self, pattern):
        return ["/cache/bitcoin-1.0-1-x86_64.pkg.tar.zst"] if "bitcoin" in pattern and self.cached else []

    def verify_package(self, archive, signature, keyring):
        if isinstance(self.status, Exception): raise self.status
        return self.status


def context(fake=None):
    cfg = config()
    cfg["package_integrity"] = {"enabled": True, "pacman_conf": "/etc/pacman.conf", "db_path": "/var/lib/pacman",
                                "keyring_dir": "/etc/pacman.d/gnupg", "cache_dirs": ["/cache"], "max_packages": 100}
    return Context(cfg, fake or Packages())


class PackageTests(unittest.TestCase):
    def test_signature_and_trust(self):
        cases = [(0, "VALIDSIG", "warning"), (0, "VALIDSIG\n[GNUPG:] TRUST_FULLY", "pass"),
                 (0, "VALIDSIG\n[GNUPG:] TRUST_MARGINAL", "fail"), (1, "BADSIG", "fail"),
                 (2, "NO_PUBKEY", "warning"), (0, "REVKEYSIG", "fail"), (2, "NODATA", "warning")]
        for code, status, expected in cases:
            self.assertEqual(signature_state(code, "[GNUPG:] " + status)[0], expected)

    def test_local_verification_and_foreign_warning(self):
        results = {r.id: r for r in run(context())}
        self.assertEqual(results["package_integrity.signature.bitcoin"].status, "pass")
        self.assertEqual(results["package_integrity.foreign.foreign"].status, "warning")
        self.assertEqual(results["package_integrity.foreign.foreign"].severity, "info")

    def test_missing_archive_does_not_pass_based_on_metadata(self):
        fake = Packages(); fake.cached = False
        result = next(r for r in run(context(fake)) if r.id == "package_integrity.signature.bitcoin")
        self.assertEqual(result.status, "warning")
        self.assertIn("cache", result.reason)

    def test_missing_keyring_is_inconclusive(self):
        results = list(run(context(Packages(Unavailable("Keyring ausente")))))
        self.assertEqual(next(r for r in results if r.id == "package_integrity.signature.bitcoin").status, "warning")

    def test_bad_signature_fails(self):
        results = list(run(context(Packages((1, "[GNUPG:] BADSIG private-identity\n")))))
        self.assertEqual(next(r for r in results if r.id == "package_integrity.signature.bitcoin").status, "fail")
        self.assertNotIn("private-identity", repr(results))

    def test_absent_pacman_is_inconclusive(self):
        results = list(run(context(FakeCollector())))
        self.assertTrue(all(r.status == "warning" for r in results))

    def test_permissive_signature_policy_fails(self):
        class Permissive(Packages):
            def command(self, args):
                if args[0] == "pacman-conf" and args[-1] != "--repo-list":
                    return "PackageOptional\nPackageTrustAll\n"
                return super().command(args)
        results = list(run(context(Permissive())))
        self.assertTrue(all(r.status == "fail" for r in results if ".policy." in r.id))

    @unittest.skipUnless(shutil.which("gpg", path="/usr/sbin:/usr/bin:/sbin:/bin") and shutil.which("gpgconf", path="/usr/sbin:/usr/bin:/sbin:/bin"), "GPG local não disponível")
    def test_real_gpg_valid_tampered_and_original_keyring_unchanged(self):
        from nvg_scanner.collectors import Collector
        collector = Collector(timeout=20)
        with tempfile.TemporaryDirectory(prefix="nvg-public-test-") as directory:
            home = Path(directory, "keyring"); home.mkdir(mode=0o700)
            archive = Path(directory, "archive"); archive.write_bytes(b"public integration fixture")
            signature = Path(str(archive) + ".sig")
            base = ["gpg", "--no-options", "--homedir", str(home), "--batch", "--no-tty",
                    "--pinentry-mode", "loopback", "--passphrase", ""]
            try:
                collector.command([*base, "--quick-generate-key", "NVG disposable test key", "ed25519", "sign", "1d"])
                collector.command([*base, "--output", str(signature), "--detach-sign", str(archive)])
                collector.command([*base, "--check-trustdb"])
                tracked = [p for p in home.iterdir() if p.name in ("pubring.kbx", "pubring.gpg", "trustdb.gpg")]
                hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in tracked}
                collector.begin_scan(time.monotonic() + 30, 1024 * 1024)
                prepare = patch.object(collector, "_prepare_keyring", wraps=collector._prepare_keyring)
                tracked_prepare = prepare.start()
                self.addCleanup(prepare.stop)
                code, output = collector.verify_package(archive, signature, home)
                tags = [line.split()[1] for line in output.splitlines() if line.startswith("[GNUPG:] ") and len(line.split()) > 1]
                self.assertEqual(signature_state(code, output)[0], "pass", ", ".join(tags))
                archive.write_bytes(b"tampered integration fixture")
                code, output = collector.verify_package(archive, signature, home)
                self.assertEqual(signature_state(code, output)[0], "fail")
                self.assertEqual(hashes, {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in tracked})
                self.assertEqual(tracked_prepare.call_count, 1)
                copies = list(collector._keyrings.values())
                collector.end_scan()
                self.assertTrue(all(not Path(p).exists() for p in copies))
            finally:
                collector.end_scan()
                collector.command(["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"])
