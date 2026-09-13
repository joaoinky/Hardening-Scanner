"""Consulta valores efetivos, pois arquivos sysctl.d podem ainda não ter sido aplicados."""

from ..collectors import Unavailable
from ..models import Result, inconclusive


def run(context):
    for key, rule in sorted(context.config["kernel"].items()):
        try:
            raw = context.collector.read_text("/proc/sys/" + key.replace(".", "/")).strip()
            value = int(raw) if type(rule["accepted"][0]) is int else raw
        except (Unavailable, ValueError):
            yield inconclusive("kernel." + key, key, "Parâmetro ausente, inacessível ou de tipo inesperado neste kernel/namespace.", rule["severity"])
            continue
        approved = value in rule["accepted"]
        yield Result("kernel." + key, key, "pass" if approved else "fail", rule["severity"],
                     ("Valor efetivo atende à política. " if approved else "Valor efetivo diverge da política. ") + rule["why"],
                     rule["recommendation"], {"actual": value, "accepted": rule["accepted"]})
