"""CLI: stdout para pipelines ou arquivos novos com modo 0600."""

import argparse
import os
from pathlib import Path
import sys

from . import __version__
from .collectors import Collector, Context
from .config import ConfigError, load_config
from .engine import discover, scan
from .reports import to_json, to_markdown


def write_reports(artifacts):
    created = []
    try:
        for path, content in artifacts:
            # O_EXCL impede sobrescrever arquivos/chaves ou seguir symlink existente.
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(path)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(content)
    except OSError:
        for path in created:
            try:
                path.unlink()
            except OSError:
                pass
        raise


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "diff":
        return diff_main(argv[1:])
    parser = argparse.ArgumentParser(description="Auditoria passiva de hardening do NVG OS",
                                     epilog="Compare relatórios existentes com: nvg-scan diff --help")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--config", type=Path, help="Arquivo JSON de política")
    parser.add_argument("--profile", default="installed", help="Perfil do JSON (padrão: installed)")
    parser.add_argument("--format", choices=("json", "markdown", "both"), default="markdown")
    parser.add_argument("--output", type=Path, help="Arquivo de saída; diretório quando --format both")
    parser.add_argument("--checks", nargs="+", help="Módulos específicos, por exemplo network_checks tor_checks")
    parser.add_argument("--list-checks", action="store_true", help="Lista módulos locais disponíveis")
    parser.add_argument("--preset", choices=("quick", "full"), help="Seleção rápida ou completa; omissões aparecem no relatório")
    parser.add_argument("--target-user", help="Conta local auditada pelo perfil nOS")
    args = parser.parse_args(argv)
    if args.list_checks:
        print("\n".join(discover()))
        return 0
    if args.config is None:
        parser.error("--config é obrigatório para executar a auditoria")
    if args.format == "both" and args.output is None:
        parser.error("--format both exige --output DIRETÓRIO")
    try:
        config = load_config(args.config, args.profile)
        if args.preset:
            config.setdefault("execution", {"max_seconds": 120, "max_output_bytes": 8388608, "preset": "full"})["preset"] = args.preset
        if args.target_user:
            if not config.get("nos", {}).get("enabled"):
                raise ConfigError("--target-user exige política nOS habilitada")
            config["nos"]["target_user"] = args.target_user
            from .nos_config import validate_nos
            validate_nos(config)
        context = Context(config, Collector(config["timeout_seconds"]))
        report = scan(context, args.checks)
        if args.format == "both":
            args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
            write_reports([(args.output / "report.json", to_json(report)),
                           (args.output / "report.md", to_markdown(report))])
        else:
            rendered = to_json(report) if args.format == "json" else to_markdown(report)
            if args.output is None:
                sys.stdout.write(rendered)
            else:
                write_reports([(args.output, rendered)])
    except (ConfigError, ValueError) as error:
        print(f"Erro: {error}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"Erro de entrada/saída ({type(error).__name__}); use um destino novo e acessível.", file=sys.stderr)
        return 2
    counts = report["summary"]["counts"]
    return 1 if counts["fail"] else 3 if counts["warning"] else 0


def diff_main(argv):
    from .diff import compare, load_report
    parser = argparse.ArgumentParser(prog="nvg-scan diff", description="Compara relatórios existentes sem executar checks")
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--format", choices=("json", "markdown", "both"), default="markdown")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.format == "both" and args.output is None:
        parser.error("--format both exige --output DIRETÓRIO")
    try:
        report = compare(load_report(args.before), load_report(args.after))
        if args.format == "both":
            args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
            write_reports([(args.output / "diff.json", to_json(report)),
                           (args.output / "diff.md", to_markdown(report))])
        else:
            rendered = to_json(report) if args.format == "json" else to_markdown(report)
            if args.output is None:
                sys.stdout.write(rendered)
            else:
                write_reports([(args.output, rendered)])
    except (ValueError, OSError):
        print("Diff não concluído: entradas inválidas/inacessíveis ou destino indisponível.", file=sys.stderr)
        return 2
    return 1 if report["summary"]["new_fail"] else 3 if report["summary"]["new_warning"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
