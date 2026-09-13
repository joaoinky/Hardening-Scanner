"""Score de conformidade com a política; não estima probabilidade de invasão."""

from .models import STATUSES


def summarize(results, weights):
    counts = {status: sum(r.status == status for r in results) for status in STATUSES}
    passed = sum(weights[r.severity] for r in results if r.status == "pass")
    evaluated = sum(weights[r.severity] for r in results if r.status != "warning")
    total = sum(weights[r.severity] for r in results)
    return {
        "counts": counts,
        "total": len(results),
        "score": round(100 * passed / evaluated, 2) if evaluated else None,
        "coverage_percent": round(100 * (counts["pass"] + counts["fail"]) / len(results), 2) if results else 0.0,
        "weighted_coverage_percent": round(100 * evaluated / total, 2) if total else 0.0,
        "weights": weights,
        "method": "100 * peso(pass) / peso(pass + fail); warning excluído",
    }


def by_domain(results, weights):
    """Cada domínio tem seu score: quantidade de pacotes não pesa sobre rede."""
    groups = {}
    for result in results:
        groups.setdefault(result.id.split(".", 1)[0], []).append(result)
    return {name: summarize(items, weights) for name, items in sorted(groups.items())}
