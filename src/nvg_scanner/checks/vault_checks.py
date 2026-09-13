"""Vault é intenção; interfaces e rádios devem comprovar o isolamento observado."""

import json
from ..collectors import Unavailable
from ..models import Result, inconclusive

CONFIG_SECTION = "nos"


def run(context):
    # Consultas independentes: atividade conhecida continua FAIL mesmo se a
    # outra fonte estiver indisponível. Não desativar interfaces ou rádios.
    for domain, args, field in (
        ("interfaces", ["ip", "-j", "link", "show"], None),
        ("radios", ["rfkill", "--json", "--output", "ID,TYPE,SOFT,HARD"], "rfkilldevices"),
    ):
        try:
            document = json.loads(context.collector.command(args))
            rows = document if field is None else document[field]
            if not isinstance(rows, list):
                raise ValueError()
            active, unknown = 0, 0
            for row in rows:
                try:
                    if domain == "interfaces":
                        flags = row["flags"]
                        if not isinstance(flags, list) or not all(isinstance(f, str) for f in flags):
                            raise ValueError()
                        active += "LOOPBACK" not in flags and "UP" in flags
                    else:
                        soft, hard = row["soft"], row["hard"]
                        if soft not in ("blocked", "unblocked") or hard not in ("blocked", "unblocked"):
                            raise ValueError()
                        active += soft == hard == "unblocked"
                except (KeyError, TypeError, ValueError):
                    unknown += 1
            # Atividade conhecida prevalece mesmo quando outra linha é inválida.
            if domain == "interfaces" and not rows:
                unknown += 1
            status = "fail" if active else "warning" if unknown else "pass"
            yield Result("vault." + domain, "Isolamento: " + domain, status, "critical",
                         "Atividade incompatível com air-gap." if active else "Observação de recursos de rede no namespace atual.",
                         "Revise isolamento no hardware e repita após hotplug ou mudança de modo.",
                         {"enumerated": len(rows), "active": active, "unknown_rows": unknown},
                         reason="Registros ausentes ou não interpretados impedem confirmar isolamento." if status == "warning" else None)
        except (Unavailable, ValueError, KeyError, TypeError):
            yield inconclusive("vault." + domain, "Isolamento: " + domain, "Consulta ausente, sem permissão ou formato de " + domain + " não interpretado.", "critical")
    installed = context.config["nos"]["environment"] == "installed"
    yield inconclusive("vault.persistence", "Persistência no Vault",
                       "Vault instalado mantém raiz em disco; modo Vault não implica execução integral em RAM." if installed else
                       "Live/copytoram não prova ausência de montagens persistentes ou isolamento físico; revise storage e o hardware.", "high")
