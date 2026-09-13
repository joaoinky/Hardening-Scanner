"""Estado local da VPN, separado do reconhecimento de regras do kill-switch."""

import ipaddress
import json
import time
from ..collectors import Unavailable
from ..models import Result, inconclusive
from ..network_state import endpoint

CONFIG_SECTION = "nos"


def run(context):
    policy = context.config["nos"]
    interface = policy["vpn_interface"]
    try:
        rows = json.loads(context.collector.command(["ip", "-j", "link", "show", "dev", interface]))
        if not isinstance(rows, list) or len(rows) != 1 or rows[0].get("ifname") != interface:
            raise ValueError()
        flags = rows[0]["flags"]
        if not isinstance(flags, list) or not all(isinstance(f, str) for f in flags):
            raise ValueError()
        active = "UP" in flags and "LOOPBACK" not in flags
        yield Result("vpn.interface", "Interface VPN esperada", "pass" if active else "fail", "high",
                     "Interface está administrativamente ativa." if active else "Interface não está administrativamente ativa como exigido.",
                     "Confirme túnel e rotas; UP sozinho não prova conectividade nem identidade do servidor.")
    except (Unavailable, ValueError, KeyError, TypeError):
        yield inconclusive("vpn.interface", "Interface VPN esperada", "Interface não enumerada ou formato indisponível; proteção do túnel não comprovada.", "high")
    try:
        output = context.collector.command(["wg", "show", interface, "endpoints"])
        actual = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) != 2 or parts[1] == "(none)":
                raise ValueError()
            address, port = endpoint(parts[1])
            actual.append((str(ipaddress.ip_address(address)), port))
        if not actual:
            raise ValueError()
        expected = [(str(ipaddress.ip_address(a)), p) for a,p in policy["vpn_endpoints"]]
        ok = set(actual) == set(expected)
        yield Result("vpn.endpoints", "Endpoints WireGuard em execução", "pass" if ok else "fail", "high",
                     "Endpoints atuais correspondem à política." if ok else "Endpoints atuais divergem dos endpoints autorizados no kill-switch.",
                     "Revise mudanças de endpoint e o modo aplicado; o scanner não reaplica regras nem identifica o servidor por uma chave exportada.",
                     {"observed_count": len(actual), "expected_count": len(expected)})
    except (Unavailable, ValueError):
        yield inconclusive("vpn.endpoints", "Endpoints WireGuard em execução", "wg ausente, interface não WireGuard, peer sem endpoint ou formato não interpretado. VPN UDP de outro tipo exige verificação própria.", "high")
    try:
        output = context.collector.command(["wg", "show", interface, "latest-handshakes"])
        stamps = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) != 2:
                raise ValueError()
            stamps.append(int(parts[1]))
        now = time.time()
        if not stamps or any(t < 0 or t > now + 5 for t in stamps):
            raise ValueError()
        recent = sum(t > 0 and now - t <= 180 for t in stamps)
        yield Result("vpn.handshakes", "Observação recente de handshakes", "pass" if recent == len(stamps) else "warning", "medium",
                     "Todos os peers têm handshake nos últimos 180 segundos." if recent == len(stamps) else "Há peers sem handshake recente observado.",
                     "Uma VPN ociosa pode não ter handshake recente; verifique estado e rotas sem interpretar isso como falha automática do firewall.",
                     {"peers": len(stamps), "recent": recent},
                     reason=None if recent == len(stamps) else "Ausência de tráfego recente não distingue ociosidade de túnel indisponível.")
    except (Unavailable, ValueError):
        yield inconclusive("vpn.handshakes", "Observação recente de handshakes", "Histórico local de handshakes não disponível/interpretável; não foram enviados pacotes de teste.", "medium")
