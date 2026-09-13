import unittest

from nvg_scanner.config import validate, ConfigError
from nvg_scanner.engine import scan
from tests.fixtures import synthetic_context
from tests.test_key_exposure import context as keys_context


class CompatibilityTests(unittest.TestCase):
    def test_legacy_configuration_keeps_six_modules_and_score(self):
        context = synthetic_context()
        original = scan(context)
        self.assertEqual(len(original["modules"]), 6)
        self.assertFalse(any(r["id"].startswith(("firewall.", "package_integrity.", "key_exposure.")) for r in original["results"]))
        for name in ("firewall", "package_integrity", "key_exposure"):
            context.config[name] = {"enabled": False}
        after = scan(context)
        self.assertEqual(original["summary"], after["summary"])
        self.assertEqual(original["results"], after["results"])

    def test_explicit_disabled_module_is_warning(self):
        report = scan(synthetic_context(), ["key_exposure_checks"])
        self.assertEqual(report["summary"]["counts"]["warning"], 1)
        self.assertIsNone(report["summary"]["score"])

    def test_recursive_patterns_and_excessive_limits_rejected(self):
        for key, value in (("max_file_bytes", 100000000), ("max_files", 10000), ("max_seconds", 300)):
            policy = keys_context().config
            policy.pop("profile")
            policy["key_exposure"][key] = value
            with self.assertRaises(ConfigError): validate(policy)
        for path in ("/tmp/**/*.log", "/home/*/.bash_history", "/tmp/../etc/shadow"):
            policy = keys_context().config; policy.pop("profile")
            policy["key_exposure"]["paths"][0]["path"] = path
            with self.assertRaises(ConfigError): validate(policy)
