"""Uma escuta inesperada amplia a superfície de ataque mesmo sem exploração."""

import ipaddress

from .collectors import Unavailable


def endpoint(value):
    address, port = value.rsplit(":", 1)
    address = address.strip("[]")
    if address != "*":
        # Mantemos o scope IPv6 na evidência, mas o CIDR compara só o IP.
        ipaddress.ip_address(address.split("%", 1)[0])
    number = int(port)
    if not 1 <= number <= 65535:
        raise ValueError("Porta inválida")
    return address, number


def parse_listeners(output):
    listeners, rejected = set(), 0
    for line in output.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        try:
            if len(fields) < 6 or fields[0] not in ("tcp", "udp"):
                raise ValueError("Formato de ss desconhecido")
            if fields[1] not in ("LISTEN", "UNCONN"):
                raise ValueError("Estado inesperado")
            address, port = endpoint(fields[4])
            listeners.add((fields[0], address, port))
        except (ValueError, IndexError):
            rejected += 1
    return sorted(listeners), rejected


def allowed(listener, rules):
    protocol, address, port = listener
    for rule in rules:
        if rule["protocol"] != protocol or rule["port"] != port:
            continue
        if rule["address"] == "*":
            return True
        if address == "*":
            continue  # Uma permissão loopback nunca autoriza wildcard do ss.
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        net = ipaddress.ip_network(rule["address"], strict=False)
        # :: pertence a ::/64, mas um bind :: escuta em todas as interfaces.
        # Exigir endereço wildcard literal ou CIDR /0 evita aprovação acidental.
        if ip.is_unspecified and net.prefixlen not in (0, net.max_prefixlen):
            continue
        if ip.version == net.version and ip in net:
            return True
    return False


def collect_listeners(context):
    key = "network.listeners"
    if key not in context.cache:
        try:
            context.cache[key] = parse_listeners(context.collector.command(["ss", "-H", "-l", "-n", "-t", "-u"]))
        except Unavailable as error:
            context.cache[key] = error
    value = context.cache[key]
    if isinstance(value, Unavailable):
        raise value
    return value
