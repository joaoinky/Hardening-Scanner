"""Reproduza exemplos com: PYTHONPATH=src python3 -m examples.generate_reports."""

from pathlib import Path

from nvg_scanner.engine import scan
from nvg_scanner.reports import to_json, to_markdown
from tests.fixtures import synthetic_context


def main():
    report = scan(synthetic_context())
    report["generated_at"] = "2026-09-12T12:00:00+00:00"
    report["example"] = True
    report["scope"] = "Host sintético para demonstração dos seis módulos; todos os dados são fictícios."
    directory = Path(__file__).resolve().parent
    (directory / "report.json").write_text(to_json(report), encoding="utf-8")
    (directory / "report.md").write_text(to_markdown(report), encoding="utf-8")


if __name__ == "__main__":
    main()
