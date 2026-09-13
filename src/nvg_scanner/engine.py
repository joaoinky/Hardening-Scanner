"""Descobre apenas módulos instalados no pacote confiável de checks."""

from datetime import datetime, timezone
import importlib
import json
import pkgutil
import time

from . import nos

from . import __version__, checks
from .models import Result, inconclusive
from .scoring import summarize


def discover():
    return sorted(
        module.name for module in pkgutil.iter_modules(checks.__path__)
        if module.name.endswith("_checks") and not module.name.startswith("_")
    )


def scan(context, module_names=None):
    try:
        return _scan(context, module_names)
    finally:
        if hasattr(context.collector, "end_scan"):
            context.collector.end_scan()


def _scan(context, module_names=None):
    context.cache.clear()  # Um novo scan sempre representa uma nova coleta.
    execution = context.config.get("execution", {})
    deadline = time.monotonic() + execution.get("max_seconds", 3600)
    if hasattr(context.collector, "begin_scan"):
        context.collector.begin_scan(deadline, execution.get("max_output_bytes", 8 * 1024 * 1024))
    available = discover()
    names = available if module_names is None else list(dict.fromkeys(module_names))
    unknown = set(names) - set(available)
    if unknown:
        raise ValueError("Módulos desconhecidos: " + ", ".join(sorted(unknown)))
    modules = {}
    for name in names:
        try:
            modules[name] = importlib.import_module(f"{checks.__name__}.{name}")
        except Exception as error:
            modules[name] = error
    if module_names is None:
        names.sort(key=lambda name: (getattr(modules[name], "SCAN_PRIORITY", 50), name))
    results, ids, executed, omitted = [], set(), [], []
    for name in names:
        try:
            module = modules[name]
            if isinstance(module, Exception):
                raise module
            section = getattr(module, "CONFIG_SECTION", None)
            if not nos.applicable(context.config, name):
                omitted.append({"module": name, "reason": "não aplicável à política solicitada"})
                if module_names is not None:
                    results.append(inconclusive(f"engine.{name}.not_applicable", name, "Módulo solicitado explicitamente, mas não aplicável à política; não executado.", "info"))
                continue
            if execution.get("preset") == "quick" and not getattr(module, "RUN_IN_QUICK", True) and module_names is None:
                omitted.append({"module": name, "reason": "fora da seleção rápida; não avaliado"})
                continue
            if section and not context.config.get(section, {}).get("enabled", False):
                if module_names is not None:
                    executed.append(name)
                    results.append(inconclusive(f"engine.{name}.disabled", name, "Módulo não habilitado na configuração."))
                omitted.append({"module": name, "reason": "não habilitado"})
                continue
            if time.monotonic() >= deadline:
                omitted.append({"module": name, "reason": "orçamento global de tempo esgotado"})
                results.append(inconclusive(f"engine.{name}.budget", name, "Orçamento global de tempo esgotado.", "high"))
                continue
            executed.append(name)
            before = len(results)
            # Iteração preserva resultados anteriores se um plugin falhar no meio.
            for result in module.run(context):
                if not isinstance(result, Result) or result.id in ids or result.id.startswith("engine."):
                    raise ValueError("Resultado inválido ou ID duplicado/reservado")
                json.dumps(result.to_dict(), allow_nan=False)
                results.append(result)
                ids.add(result.id)
            if len(results) == before:
                raise ValueError("Módulo não retornou resultados")
        except Exception as error:
            # Não serializar a mensagem: um plugin pode ter incluído uma chave nela.
            results.append(inconclusive(
                f"engine.{name}", f"Execução do módulo {name}",
                f"Módulo não concluído ({type(error).__name__}); os demais continuam.",
                severity="high",
            ))
    observed_context = nos.metadata(context)
    summary = summarize(results, context.config["weights"])
    from .scoring import by_domain
    summary["domains"] = by_domain(results, context.config["weights"])
    domain_scores = [d["score"] for d in summary["domains"].values() if d["score"] is not None]
    summary["domain_balanced_score"] = round(sum(domain_scores) / len(domain_scores), 2) if domain_scores else None
    summary["critical_failures"] = sum(r.status == "fail" and r.severity == "critical" for r in results)
    inventory = context.cache.get("packages.installed")
    total = len(inventory) if inventory is not None else None
    summary["package_coverage"] = context.cache.get("package_coverage", {
        "total_installed": total, "selected": 0, "examined": 0, "verification_attempts": 0,
        "cryptographically_verified": 0, "valid_signatures": 0, "invalid_signatures": 0,
        "trusted_valid_signatures": 0, "inconclusive": 0, "not_verified": total,
        "coverage_percent": 0.0 if total is not None else None, "state": "não executado"})
    return {
        "schema_version": "1.0",
        "scanner": {"name": "nvg-hardening-scanner", "version": __version__},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "profile": context.config["profile"],
        "modules": executed,
        "scope": "Snapshot passivo do host e namespaces atuais; nenhum teste de exploração ou tráfego de teste.",
        "summary": summary,
        "context": observed_context,
        "selection": {"preset": execution.get("preset", "full"), "omitted": omitted},
        "results": [result.to_dict() for result in results],
    }
