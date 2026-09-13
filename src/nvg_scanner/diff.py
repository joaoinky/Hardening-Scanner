"""Compara snapshots por ID sem reproduzir conteúdo de evidências ou segredos."""

import json
import math

from .models import STATUSES, SEVERITIES


def load_report(path):
    try:
        with open(path, encoding="utf-8") as stream:
            data = stream.read(32 * 1024 * 1024 + 1)
        if len(data) > 32 * 1024 * 1024:
            raise ValueError()
        from .config import no_duplicates
        report = json.loads(data, object_pairs_hook=no_duplicates)
        validate_report(report)
        return report
    except (OSError, ValueError, UnicodeError, TypeError, KeyError):
        raise ValueError("Relatório inválido, inacessível ou maior que 32 MiB") from None


def validate_report(report):
    if not isinstance(report, dict) or report.get("schema_version") != "1.0":
        raise ValueError("Versão de relatório não suportada")
    if not isinstance(report.get("results"), list) or not isinstance(report.get("summary"), dict):
        raise ValueError("Estrutura de relatório inválida")
    ids = set()
    for result in report["results"]:
        if not isinstance(result, dict):
            raise ValueError("Resultado inválido")
        key = result.get("id")
        if not isinstance(key, str) or not key or key in ids:
            raise ValueError("ID ausente ou duplicado")
        ids.add(key)
        if result.get("status") not in STATUSES or result.get("severity") not in SEVERITIES:
            raise ValueError("Status/severidade inválido")
    for key in ("score", "coverage_percent", "weighted_coverage_percent", "domain_balanced_score"):
        number = report["summary"].get(key)
        if number is not None and (type(number) not in (int, float) or not math.isfinite(number) or not 0 <= number <= 100):
            raise ValueError("Métrica inválida")


def transition(before, after):
    if before == after:
        return "unchanged"
    if after == "fail":
        return "new_fail"
    if before == "fail" and after == "pass":
        return "resolved_fail"
    if before == "warning" and after == "pass":
        return "resolved_warning"
    if after == "warning":
        return "new_warning"  # fail → warning permanece não resolvido.
    return "added_pass" if before is None else "removed"


def compare(before, after):
    validate_report(before)
    validate_report(after)
    old = {r["id"]: r for r in before["results"]}
    new = {r["id"]: r for r in after["results"]}
    changes = []
    counts = {k: 0 for k in ("new_fail", "resolved_fail", "new_warning", "resolved_warning",
                             "unchanged", "changed", "added_pass", "added", "removed")}
    for key in sorted(old.keys() | new.keys()):
        a, b = old.get(key), new.get(key)
        presence = "added" if a is None else "removed" if b is None else "both"
        state = transition(a["status"] if a else None, b["status"] if b else None)
        fields = [field for field in ("name", "severity", "description", "recommendation", "evidence", "reason")
                  if a is not None and b is not None and a.get(field) != b.get(field)]
        if state == "unchanged" and fields:
            state = "changed"
        counts[state] += 1
        if presence == "added":
            counts["added"] += 1
        # Não serializar dicionários originais, texto, fragmentos ou hashes de
        # evidência. Mesmo a mudança de segredo só produz evidence_changed.
        from .key_patterns import safe_location
        changes.append({"id": safe_location(key), "presence": presence, "transition": state,
                        "before": {k: a[k] for k in ("status", "severity")} if a else None,
                        "after": {k: b[k] for k in ("status", "severity")} if b else None,
                        "changed_fields": fields})
    metrics = {}
    for key in ("score", "coverage_percent", "weighted_coverage_percent", "domain_balanced_score"):
        a, b = before["summary"].get(key), after["summary"].get(key)
        metrics[key] = {"before": a, "after": b, "delta": round(b - a, 2) if a is not None and b is not None else None}
    differences = [key for key in ("profile", "modules", "scanner") if before.get(key) != after.get(key)]
    if before["summary"].get("weights") != after["summary"].get("weights"):
        differences.append("weights")
    for field in ("context", "selection"):
        if before.get(field) != after.get(field):
            differences.append(field)
    package_metrics = {}
    for key in ("total_installed", "selected", "examined", "cryptographically_verified", "valid_signatures", "invalid_signatures", "trusted_valid_signatures", "not_verified", "coverage_percent"):
        values = []
        for report in (before, after):
            package = report["summary"].get("package_coverage") or {}
            value = package.get(key)
            if value is not None and (type(value) not in (int, float) or not math.isfinite(value) or value < 0):
                raise ValueError("Métrica de pacote inválida")
            values.append(value)
        a, b = values
        package_metrics[key] = {"before": a, "after": b, "delta": round(b - a, 2) if a is not None and b is not None else None}
    return {"schema_version": "1.0", "kind": "diff", "summary": counts,
            "package_metrics": package_metrics,
            "metrics": metrics, "comparability_warnings": differences,
            "limitations": "Removido significa ausente do relatório, não recurso corrigido. Política/inventário podem mudar sem identificação nos relatórios legados. Nenhum conteúdo de evidência é reproduzido.",
            "changes": changes}
