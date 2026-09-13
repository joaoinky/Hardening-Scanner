"""Integração real dos checks legados, sem mocks ou alteração de configuração do host.

Cria SOMENTE arquivos descartáveis do teste no workspace, varia seus metadados e
executa os seis módulos preexistentes. Os JSONs são gerados pelo motor real.
"""

from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile

from nvg_scanner.collectors import Collector, Context
from nvg_scanner.config import load_config
from nvg_scanner.diff import compare, load_report
from nvg_scanner.engine import scan
from nvg_scanner.__main__ import write_reports
from nvg_scanner.reports import to_json, to_markdown

LEGACY = ["network_checks", "permissions_checks", "tor_checks", "service_checks", "kernel_checks", "account_checks"]


def main():
    workspace = Path(__file__).resolve().parents[1]
    (workspace / "reports").mkdir(exist_ok=True, mode=0o700)
    output = Path(tempfile.mkdtemp(prefix="diff-real-validation-", dir=workspace / "reports"))
    candidates = [workspace, Path(tempfile.gettempdir()), Path(f"/run/user/{os.getuid()}")]
    def safe(path):
        try:
            return all(p.stat().st_uid in (0, os.getuid()) and not p.stat().st_mode & 0o022
                       for p in (path, *path.parents)) and os.access(path, os.W_OK)
        except OSError:
            return False
    base = next((p for p in candidates if safe(p)), None)
    if base is None:
        raise RuntimeError("Integração requer diretório gravável com ancestrais seguros; não foram alteradas permissões do host")
    with tempfile.TemporaryDirectory(prefix=".diff-real-", dir=base) as directory:
        policy = load_config(workspace / "config/example.json", "live")
        policy["permissions"]["sensitive_paths"] = []
        transitions = {"fail_pass": (0o644, 0o600), "warning_pass": (None, 0o600),
                       "fail_warning": (0o644, None), "pass_fail": (0o600, 0o644),
                       "pass_warning": (0o600, None), "warning_fail": (None, 0o644)}
        for name, (mode, _) in transitions.items():
            path = Path(directory, name)
            if mode is not None:
                path.touch(mode=mode)
                path.chmod(mode)
            policy["permissions"]["sensitive_paths"].append({
                "id": name, "path": str(path), "kind": "file", "max_mode": "0600",
                "uid": os.getuid(), "required": False, "allow_symlink": False, "severity": "critical"})
        before = scan(Context(deepcopy(policy), Collector()), LEGACY)
        for name, (_, mode) in transitions.items():
            path = Path(directory, name)
            if mode is None:
                path.unlink(missing_ok=True)
            else:
                path.touch()
                path.chmod(mode)
        after = scan(Context(deepcopy(policy), Collector()), LEGACY)
        write_reports([(output / "before.json", to_json(before)), (output / "after.json", to_json(after))])
        diff = compare(load_report(output / "before.json"), load_report(output / "after.json"))
        by_id = {c["id"]: c for c in diff["changes"]}
        expected = {"fail_pass": "resolved_fail", "warning_pass": "resolved_warning", "fail_warning": "new_warning",
                    "pass_fail": "new_fail", "pass_warning": "new_warning", "warning_fail": "new_fail"}
        for name, state in expected.items():
            assert by_id["permissions." + name]["transition"] == state, (name, by_id["permissions." + name])
        assert not any(r["id"].startswith("engine.") for report in (before, after) for r in report["results"])
        write_reports([(output / "diff.json", to_json(diff)), (output / "diff.md", to_markdown(diff))])
        print(json.dumps({"validated_real_transitions": expected, "summary": diff["summary"], "output": str(output)}, indent=2))


if __name__ == "__main__":
    main()
