"""Duas representações do mesmo relatório, sem reexecutar checks."""

import html
import json
import re


def to_json(report):
    return json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n"


def prose(value):
    # Valores locais também podem conter Markdown/HTML ou escapes de terminal.
    text = "".join(c if c.isprintable() else " " for c in str(value))
    return re.sub(r"([\\`*_{}\[\]()#+.!|>-])", r"\\\1", html.escape(text))


def to_markdown(report):
    if report.get("kind") == "diff":
        return diff_markdown(report)
    summary = report["summary"]
    score = "indisponível" if summary["score"] is None else f"{summary['score']:.2f}/100"
    lines = [
        "# Auditoria de hardening — NVG OS", "",
        f"Perfil: {prose(report['profile'])}  ",
        f"Data UTC: {prose(report['generated_at'])}", "",
        f"**Score de conformidade: {score}**  ",
        f"Cobertura por resultados: {summary['coverage_percent']:.2f}%  ",
        f"Cobertura ponderada: {summary['weighted_coverage_percent']:.2f}%", "",
        f"Pass: {summary['counts']['pass']} · Fail: {summary['counts']['fail']} · Warning: {summary['counts']['warning']}", "",
        "O score considera somente pass/fail, com pesos por severidade. Warnings ficam fora do denominador e reduzem a cobertura. Um score alto com cobertura baixa não comprova segurança.", "",
        prose(report["scope"]), "",
    ]
    package = summary.get("package_coverage")
    if package is not None:
        total = package.get("total_installed")
        verified = package.get("cryptographically_verified", 0)
        if total is None:
            lines += ["**Cobertura criptográfica de pacotes: total instalado desconhecido; verificação não concluída ou não executada.**", ""]
        else:
            lines += [f"**Pacotes verificados criptograficamente: {verified} de {total} ({package['coverage_percent']:.2f}%). Não verificados: {package['not_verified']}.**", "",
                      f"Selecionados: {package['selected']} · Examinados: {package['examined']} · Tentativas: {package['verification_attempts']} · Inconclusivos entre examinados: {package['inconclusive']}", "",
                      f"Assinaturas válidas: {package['valid_signatures']} · Inválidas: {package['invalid_signatures']} · Válidas com confiança suficiente: {package['trusted_valid_signatures']}", "",
                      "Verificado significa resultado criptográfico conclusivo (válido ou inválido), não aprovação. A cobertura é dos artefatos em cache, não dos bytes instalados. Tentativa, cache ausente e chave pública ausente não contam como verificação.", ""]
    if "domains" in summary:
        lines += [f"**Falhas critical: {summary['critical_failures']} · Score equilibrado por domínio: {summary['domain_balanced_score']}**", "",
                  "Cada domínio contribui igualmente para esta média; a quantidade de pacotes não aumenta o peso do domínio. Ambos os scores excluem resultados inconclusivos.", "",
                  "| Domínio | Score | Cobertura ponderada | Fail | Warning |", "| --- | ---: | ---: | ---: | ---: |"]
        for name, domain in summary["domains"].items():
            lines.append(f"| {prose(name)} | {domain['score']} | {domain['weighted_coverage_percent']}% | {domain['counts']['fail']} | {domain['counts']['warning']} |")
        lines += [""]
    if report.get("context"):
        ctx = report["context"]
        lines += [f"Ambiente esperado: {prose(ctx['environment'])} · Rede esperada: {prose(ctx['expected_network_mode'])} · Política: {prose(ctx['policy_version'])}", ""]
    for entry in report.get("selection", {}).get("omitted", []):
        lines += [f"Módulo omitido: {prose(entry['module'])} — {prose(entry['reason'])}", ""]
    if report.get("example"):
        lines += ["**EXEMPLO SINTÉTICO: dados fictícios; não representa auditoria deste host.**", ""]
    for result in report["results"]:
        lines += [f"## [{result['status'].upper()}] {prose(result['name'])}", "",
                  f"ID: {prose(result['id'])} · Severidade: {result['severity']}", "",
                  prose(result["description"]), "",
                  "**Recomendação:** " + prose(result["recommendation"]), ""]
        if result["reason"]:
            lines += ["**Limitação/revisão:** " + prose(result["reason"]), ""]
        if result["evidence"]:
            evidence = json.dumps(result["evidence"], indent=2, ensure_ascii=True)
            fence = "`" * max(3, max((len(m[0]) + 1 for m in re.finditer(r"`+", evidence)), default=0))
            lines += [fence + "json", evidence, fence, ""]
    return "\n".join(lines) + "\n"


def diff_markdown(report):
    counts, score = report["summary"], report["metrics"]["score"]
    lines = ["# Diff de hardening — NVG OS", "",
             f"**{counts['new_fail']} novos fails · {counts['resolved_fail']} fails resolvidos**", "",
             f"Score: {score['before']} → {score['after']} (delta: {score['delta']}).", "",
             f"Novos warnings: {counts['new_warning']} · Warnings resolvidos: {counts['resolved_warning']} · Adicionados: {counts['added']} · Removidos: {counts['removed']}", ""]
    if report.get("example"):
        lines += ["**EXEMPLO SINTÉTICO: nenhuma auditoria real deste host.**", ""]
    for key in ("coverage_percent", "weighted_coverage_percent"):
        metric = report["metrics"][key]
        lines += [f"{key}: {metric['before']} → {metric['after']} (delta: {metric['delta']}).", ""]
    for key, metric in report.get("package_metrics", {}).items():
        lines += [f"Pacotes — {prose(key)}: {metric['before']} → {metric['after']} (delta: {metric['delta']}).", ""]
    if "domain_balanced_score" in report["metrics"]:
        metric = report["metrics"]["domain_balanced_score"]
        lines += [f"Score equilibrado por domínio: {metric['before']} → {metric['after']} (delta: {metric['delta']}).", ""]
    if report["comparability_warnings"]:
        lines += ["**Comparabilidade limitada:** " + ", ".join(report["comparability_warnings"]), ""]
    lines += [report["limitations"], "", "| ID | Presença | Transição | Antes | Depois |", "| --- | --- | --- | --- | --- |"]
    for item in report["changes"]:
        a = item["before"]["status"] if item["before"] else "—"
        b = item["after"]["status"] if item["after"] else "—"
        lines.append(f"| {prose(item['id'])} | {item['presence']} | {item['transition']} | {a} | {b} |")
    return "\n".join(lines) + "\n"
