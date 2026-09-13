"""Exemplos reproduzíveis; fixtures públicas, sem material privado do usuário."""

from pathlib import Path

from nvg_scanner.collectors import Context
from tests.test_nos import policy, Native
from tests.test_packages import Packages
from nvg_scanner.diff import compare
from nvg_scanner.engine import scan
from nvg_scanner.reports import to_json, to_markdown
from tests.fixtures import synthetic_context, metadata
from tests.test_firewall import fixture, rule
from tests.test_packages import context as packages_context
from tests.test_key_exposure import context as keys_context, VECTORS


def main():
    directory = Path(__file__).resolve().parent
    before_context = synthetic_context()
    before = scan(before_context)
    before_context.collector.metadata["/vault/nostr.key"] = metadata(0o600)
    after = scan(before_context)
    class LargeInventory(Packages):
        def command(self, args):
            if args[-1] == "-Q":
                return "bitcoin 1.0-1\n" + "".join(f"pkg{i:03} 1-1\n" for i in range(129))
            return super().command(args)
    coverage_context = packages_context(LargeInventory())
    coverage_context.config["package_integrity"]["max_packages"] = 128
    examples = {
        "nos": scan(Context(policy(), Native()), ["firewall_checks", "storage_checks"]),
        "package_coverage": scan(coverage_context, ["package_integrity_checks"]),
        "diff": compare(before, after),
        "firewall": scan(fixture([rule({"accept": None})]), ["firewall_checks"]),
        "package_integrity": scan(packages_context(), ["package_integrity_checks"]),
        "key_exposure": scan(keys_context("\nNONWORDSEPARATOR\n".join(VECTORS.values()).encode()), ["key_exposure_checks"]),
    }
    for name, report in examples.items():
        report["example"] = True
        if "generated_at" in report:
            report["generated_at"] = "2026-09-13T12:00:00+00:00"
            report["scope"] = "Dados sintéticos de demonstração; nenhum segredo do usuário."
        (directory / (name + ".json")).write_text(to_json(report), encoding="utf-8")
        (directory / (name + ".md")).write_text(to_markdown(report), encoding="utf-8")


if __name__ == "__main__":
    main()
