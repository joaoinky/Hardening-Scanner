"""Modelo limitado de input: qualquer construção fora do modelo invalida conclusões.

Não usar busca textual por accept/drop: a ordem e o contexto dos vereditos importam.
"""

import ipaddress
import json

from ..collectors import Unavailable
from ..models import Result, inconclusive
from ..network_state import collect_listeners

CONFIG_SECTION = "firewall"


class Unsupported(ValueError):
    pass


def parse_rule(rule):
    conditions, verdict = {}, None
    expressions = rule.get("expr")
    if not isinstance(expressions, list):
        raise Unsupported("expressões da regra ausentes ou inválidas")
    for expression in expressions:
        if not isinstance(expression, dict) or len(expression) != 1:
            raise Unsupported("formato de expressão não reconhecido")
        kind, value = next(iter(expression.items()))
        if verdict is not None:
            raise Unsupported("expressão posterior a veredito terminal")
        if kind == "counter":
            continue
        if kind in ("accept", "drop", "reject"):
            # reject é VEREDITO de regra. Nunca é policy de base chain.
            verdict = kind
        elif kind == "match":
            if not isinstance(value, dict) or value.get("op") != "==":
                raise Unsupported("operador de comparação diferente de igualdade")
            left, right = value.get("left"), value.get("right")
            if not isinstance(left, dict):
                raise Unsupported("operando de comparação não reconhecido")
            if "ct" in left:
                raise Unsupported("estado de conexão/conntrack (ct) não modelado")
            if "meta" in left:
                key = left["meta"].get("key")
                if key in ("iif", "iifname", "oif", "oifname"):
                    raise Unsupported("condição baseada em interface não modelada")
                if key != "l4proto" or right not in ("tcp", "udp", 6, 17):
                    raise Unsupported("metadado de pacote não modelado")
                field, right = "protocol", {6: "tcp", 17: "udp"}.get(right, right)
            elif "payload" in left:
                payload = left["payload"]
                protocol, field = payload.get("protocol"), payload.get("field")
                if protocol in ("tcp", "udp") and field == "dport":
                    if "protocol" in conditions and conditions["protocol"] != protocol:
                        raise Unsupported("condições de protocolo conflitantes")
                    conditions["protocol"] = protocol
                    field = "port"
                    if type(right) is not int or not 1 <= right <= 65535:
                        raise Unsupported("set, intervalo ou porta não literal não modelado")
                elif protocol in ("ip", "ip6") and field == "daddr":
                    field = "address"
                    try:
                        if isinstance(right, dict) and set(right) == {"prefix"}:
                            right = str(right["prefix"]["addr"]) + "/" + str(right["prefix"]["len"])
                        right = ipaddress.ip_network(right, strict=False)
                        if right.version != (4 if protocol == "ip" else 6):
                            raise ValueError()
                    except (ValueError, TypeError, KeyError):
                        raise Unsupported("endereço/set de destino não modelado") from None
                else:
                    raise Unsupported("campo de pacote/origem não modelado")
            else:
                raise Unsupported("expressão de match não modelada")
            if field in conditions and conditions[field] != right:
                raise Unsupported("múltiplas condições para o mesmo campo")
            conditions[field] = right
        else:
            reasons = {"jump": "salto jump para outra chain", "goto": "salto goto para outra chain",
                       "ct": "estado de conexão/conntrack (ct)", "dnat": "NAT (dnat)", "snat": "NAT (snat)",
                       "masquerade": "NAT (masquerade)", "redirect": "NAT (redirect)", "vmap": "mapa de vereditos",
                       "set": "atualização dinâmica de set"}
            raise Unsupported(reasons.get(kind, "tipo de expressão fora do subconjunto suportado"))
    return {"conditions": conditions, "verdict": verdict}


def analyze(document, ipv6):
    records = document.get("nftables") if isinstance(document, dict) else None
    if not isinstance(records, list):
        raise Unsupported("JSON sem lista nftables")
    chains, raw_rules, issues = [], [], []
    for index, item in enumerate(records):
        if not isinstance(item, dict) or len(item) != 1:
            issues.append((index, "registro nftables inválido")); continue
        kind, value = next(iter(item.items()))
        if kind == "metainfo":
            continue
        if not isinstance(value, dict):
            issues.append((index, "objeto nftables inválido")); continue
        if kind == "table":
            if value.get("flags"):
                issues.append((index, "flags de tabela (incluindo dormant) não modeladas"))
        elif kind in ("set", "map", "flowtable"):
            issues.append((index, "set dinâmico não modelado" if "dynamic" in value.get("flags", []) else "set/map/flowtable nomeado não modelado"))
        elif kind == "chain":
            if value.get("type") == "nat":
                issues.append((index, "chain NAT não modelada"))
            elif value.get("hook") == "input" and value.get("family") in ("ip", "ip6", "inet"):
                if value.get("type") != "filter" or value.get("policy", "accept") not in ("accept", "drop"):
                    issues.append((index, "tipo/policy inválido: policy só aceita accept/drop; reject pertence a regras"))
                else:
                    chains.append(value)
            elif value.get("hook") in ("prerouting", "ingress") or value.get("family") in ("bridge", "netdev"):
                issues.append((index, "hook anterior ao input ou família bridge/netdev não modelado"))
        elif kind == "rule":
            raw_rules.append((index, value))
        elif kind not in ("counter",):
            issues.append((index, "objeto nftables fora do modelo"))
    families = ("ip", "ip6") if ipv6 else ("ip",)
    selected = {}
    for family in families:
        candidates = [c for c in chains if c.get("family") in (family, "inet")]
        if len(candidates) > 1:
            issues.append((family, "múltiplas base chains input sobrepostas; prioridade/composição não modelada"))
        selected[family] = candidates[0] if len(candidates) == 1 else None
    parsed = {}
    for index, rule in raw_rules:
        identity = tuple(rule.get(k) for k in ("family", "table", "chain"))
        if any(identity == (c.get("family"), c.get("table"), c.get("name")) for c in chains):
            try:
                parsed.setdefault(identity, []).append(parse_rule(rule))
            except (Unsupported, TypeError, AttributeError) as error:
                reason = str(error) if isinstance(error, Unsupported) else "estrutura de expressão inválida"
                issues.append((index, reason))
    return selected, parsed, issues


def rule_allowed(rule, family, whitelist):
    condition = rule["conditions"]
    address = condition.get("address", ipaddress.ip_network("0.0.0.0/0" if family == "ip" else "::/0"))
    if address.version != (4 if family == "ip" else 6):
        return True  # Regra não aplica a esta família.
    for allowed in whitelist:
        if condition.get("protocol") != allowed["protocol"] or condition.get("port") != allowed["port"]:
            continue
        if allowed["address"] == "*":
            return True
        permitted = ipaddress.ip_network(allowed["address"], strict=False)
        if address.version == permitted.version and address.subnet_of(permitted):
            return True
    return False


def socket_verdict(listener, family, rules, policy):
    proto, address, port = listener
    for rule in rules:
        condition = rule["conditions"]
        if condition.get("protocol", proto) != proto or condition.get("port", port) != port:
            continue
        destination = condition.get("address")
        if destination:
            if destination.version != (4 if family == "ip" else 6):
                continue
            if address == "*" or ipaddress.ip_address(address.split("%", 1)[0]).is_unspecified:
                if destination.prefixlen != 0:
                    raise Unsupported("socket wildcard com regra restrita a destino: cobertura parcial dos endereços")
            elif ipaddress.ip_address(address.split("%", 1)[0]) not in destination:
                continue
        if rule["verdict"]:
            return rule["verdict"], "rule"
    return policy, "chain_policy"


def run(context):
    if context.config["firewall"].get("backend") == "nos":
        from ..nos_network import run as native_run
        yield from native_run(context)
        return
    policy = context.config[CONFIG_SECTION]
    try:
        document = json.loads(context.collector.command(["nft", "-j", "-n", "list", "ruleset"]))
        selected, parsed, issues = analyze(document, policy["require_ipv6"])
    except (Unavailable, ValueError) as error:
        reason = str(error) if isinstance(error, (Unavailable, Unsupported)) else "JSON nftables inválido"
        yield inconclusive("firewall.collection", "Coleta do firewall", reason, "high")
        return
    if issues:
        for index, (location, reason) in enumerate(issues):
            yield inconclusive(f"firewall.unsupported.{index}", "Firewall não interpretado",
                               f"Registro/família {location}: {reason}. Nenhuma conclusão de proteção será emitida para este ruleset.", "high")
        return
    try:
        sockets, rejected = collect_listeners(context)
    except Unavailable as error:
        sockets, rejected = [], 0
        yield inconclusive("firewall.sockets", "Cruzamento com sockets", str(error), "high")
    if rejected:
        yield inconclusive("firewall.sockets_parse", "Cruzamento com sockets", "Saída ss contém linhas não interpretadas; cruzamento parcial.", "high")
    for family, chain in selected.items():
        if chain is None:
            yield Result(f"firewall.{family}.input", "Base chain input", "fail", "high",
                         "Não há base chain input aplicável à família exigida.", "Defina uma política de entrada compatível com a exposição necessária.", {"family": family})
            continue
        rules = parsed.get((chain["family"], chain["table"], chain["name"]), [])
        default = chain.get("policy", "accept")
        catch_all = next((r["verdict"] for r in rules if not r["conditions"] and r["verdict"]), default)
        denied = default == "drop" or catch_all in ("drop", "reject")
        justified = family in policy["accept_justifications"] or not policy["require_default_deny"]
        yield Result(f"firewall.{family}.default", "Política de entrada", "pass" if denied or justified else "fail", "high",
                     "Política de descarte/regra terminal ou exceção explícita identificada." if denied or justified else "Entrada aceita por padrão sem justificativa na política.",
                     "Prefira policy drop ou regra terminal de descarte/reject; revise as exceções explícitas.",
                     {"family": family, "chain_policy": default, "fallback_verdict": catch_all, "justified_accept": justified})
        for index, rule in enumerate(rules):
            if rule["verdict"] == "accept":
                approved = rule_allowed(rule, family, context.config["network"]["allowed_listeners"])
                yield Result(f"firewall.{family}.allow.{index}", "Permissão de entrada versus whitelist", "pass" if approved else "fail", "high",
                             "Regra de aceitação está contida na whitelist." if approved else "Regra permite tráfego além da whitelist, mesmo que não haja listener agora.",
                             "Restrinja protocolo, porta e destino ao necessário.", {"family": family, "rule_index": index})
            if not rule["conditions"] and rule["verdict"]:
                break  # Regras posteriores ao primeiro veredito incondicional são inalcançáveis.
        for listener in sockets:
            address = listener[1]
            if address != "*" and ipaddress.ip_address(address.split("%", 1)[0]).version != (4 if family == "ip" else 6):
                continue
            check_id = f"firewall.{family}.socket.{listener[0]}.{address}.{listener[2]}"
            try:
                verdict, source = socket_verdict(listener, family, rules, default)
            except Unsupported as error:
                yield inconclusive(check_id, "Cobertura do socket", str(error), "high")
                continue
            # Whitelist de bind não autoriza sozinha uma regra mais ampla.
            from ..network_state import allowed
            ok = verdict in ("drop", "reject") or (source == "rule" and allowed(listener, context.config["network"]["allowed_listeners"]))
            yield Result(check_id, "Cobertura do socket", "pass" if ok else "fail", "high",
                         "Socket bloqueado ou permitido explicitamente conforme a whitelist no modelo input." if ok else "Socket aceito sem regra explícita ou fora da whitelist.",
                         "Revise o bind e a regra de entrada correspondente.",
                         {"protocol": listener[0], "address": address, "port": listener[2], "verdict": verdict, "source": source})
