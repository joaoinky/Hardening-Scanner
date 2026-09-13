"""Uma escuta inesperada amplia a superfície de ataque mesmo sem exploração."""
from ..collectors import Unavailable
from ..models import Result, inconclusive
from ..network_state import endpoint, parse_listeners, allowed, collect_listeners


def run(context):
    try:
        listeners, rejected = collect_listeners(context)
    except Unavailable as error:
        yield inconclusive("network.collection", "Coleta de sockets", str(error), "high",
                           "Disponibilize ss (iproute2) e acesso ao namespace de rede a auditar.")
        return
    if rejected:
        yield inconclusive("network.parse", "Interpretação dos sockets", f"{rejected} linhas não reconhecidas; cobertura parcial.", "high")
    if not listeners and not rejected:
        yield Result("network.listeners", "Sockets em escuta", "pass", "high",
                     "Nenhum socket TCP/UDP em escuta observado no namespace atual.", "Mantenha a política mínima de serviços.")
    for listener in listeners:
        protocol, address, port = listener
        approved = allowed(listener, context.config["network"]["allowed_listeners"])
        yield Result(
            f"network.{protocol}.{address}.{port}", "Socket autorizado pela whitelist",
            "pass" if approved else "fail", "high",
            "Escuta prevista na política." if approved else "Escuta ausente da whitelist; exposição externa depende também de rotas e firewall.",
            "Mantenha a regra restrita ao endereço necessário." if approved else
            "Identifique o serviço; restrinja seu bind/desative a escuta ou autorize explicitamente se necessária.",
            {"protocol": protocol, "address": address, "port": port},
        )
