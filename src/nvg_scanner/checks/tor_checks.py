"""Auditoria passiva do Tor: configuração declarada não prova anonimato em execução."""

import ipaddress
from pathlib import Path
import re
import shlex

from ..collectors import Unavailable, service_properties
from ..models import Result, inconclusive
from .network_checks import endpoint


def parse_torrc(collector, filename):
    """Subconjunto conservador do torrc, incluindo arquivos/globs/diretórios absolutos.

    Construções não suportadas invalidam conclusões derivadas do arquivo inteiro,
    pois ignorar um include poderia esconder um ControlPort sem autenticação.
    """
    options, issues, active = {}, [], set()
    file_count = 0

    def visit(path, depth=0):
        nonlocal file_count
        if depth > 16 or file_count >= 128:
            issues.append("Limite de includes atingido")
            return
        try:
            canonical = str(collector.resolve(path))
            if canonical in active:
                issues.append("Ciclo de includes")
                return
            text = collector.read_text(path)
        except (OSError, Unavailable):
            issues.append("Arquivo torrc/include inacessível")
            return
        file_count += 1
        active.add(canonical)
        for line in text.splitlines():
            if line.rstrip().endswith("\\"):
                issues.append("Continuação de linha não suportada pelo parser conservador")
                continue
            try:
                tokens = shlex.split(line, comments=True, posix=True)
            except ValueError:
                issues.append("Sintaxe de aspas não interpretada")
                continue
            if not tokens:
                continue
            key, values = tokens[0].lower(), tokens[1:]
            if key == "%include":
                if len(values) != 1 or not values[0].startswith("/"):
                    issues.append("Include relativo ou sem um único caminho absoluto")
                    continue
                matches = collector.glob(values[0])
                if not matches:
                    issues.append("Include sem correspondência")
                for match in matches:
                    if collector.is_dir(match):
                        for child in collector.glob(str(Path(match) / "*")):
                            if not collector.is_dir(child):
                                visit(child, depth + 1)
                    else:
                        visit(match, depth + 1)
            elif key.startswith(("+", "/")):
                issues.append("Operadores de adição/reset não suportados")
            elif not values:
                issues.append("Diretiva sem valor")
            else:
                options.setdefault(key, []).append(values)
        active.remove(canonical)

    visit(filename)
    return options, sorted(set(issues))


def port_entries(options, key, default):
    parsed = []
    for values in options.get(key, [[default]]):
        token = values[0]
        if token == "0":
            continue
        if token.startswith("unix:") or token == "auto":
            raise ValueError("Endpoint Unix/auto requer inspeção adicional")
        address, port = endpoint("127.0.0.1:" + token if token.isdecimal() else token)
        if address == "*":
            local = False
        else:
            ip = ipaddress.ip_address(address.split("%", 1)[0])
            local = ip.is_loopback or (isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None and ip.ipv4_mapped.is_loopback)
        parsed.append({"address": address, "port": port, "loopback": bool(local)})
    return parsed


def scalar(options, key, default):
    entries = options.get(key, [[default]])
    if len(entries) != 1 or len(entries[0]) != 1:
        raise ValueError("Diretiva escalar repetida ou com múltiplos valores")
    return entries[0][0]


def config_checks(context):
    policy = context.config["tor"]
    options, issues = parse_torrc(context.collector, policy["torrc"])
    if issues:
        yield inconclusive("tor.config", "Leitura da configuração Tor", "; ".join(issues), "high",
                           "Confirme o torrc utilizado pelo serviço e revise construções não interpretadas; o scanner não executa Tor para validar arquivos.")
        return
    control = None
    for key, default in (("socksport", "9050"), ("dnsport", "0"), ("transport", "0"), ("controlport", "0")):
        try:
            ports = port_entries(options, key, default)
        except ValueError:
            yield inconclusive("tor." + key, "Bind de " + key, "Endpoint não interpretado com segurança.", "high")
            continue
        if key == "controlport":
            control = ports
        exposed = any(not port["loopback"] for port in ports)
        yield Result(
            "tor." + key, "Bind de " + key, "fail" if exposed else "pass", "high",
            "Endpoint declarado fora de loopback." if exposed else "Endpoints declarados restritos a loopback ou desativados.",
            "Restrinja endpoints de cliente/controle ao loopback; este perfil é para um host cliente NVG OS.",
            {"endpoints": ports, "source": "torrc declarado; não é configuração efetiva do processo"},
        )
    if policy["require_safe_socks"]:
        # SafeSocks rejeita SOCKS que já entrega IP resolvido; não protege todo o host.
        try:
            value = scalar(options, "safesocks", "0")
            if value not in ("0", "1"):
                raise ValueError("Booleano inválido")
            yield Result("tor.safe_socks", "Proteção contra resolução DNS prévia via SOCKS",
                         "pass" if value == "1" else "fail", "high",
                         "SafeSocks habilitado no arquivo." if value == "1" else "SafeSocks não está habilitado no arquivo.",
                         "Defina SafeSocks 1 e configure clientes para enviar nomes ao proxy (por exemplo, socks5h).")
        except ValueError:
            yield inconclusive("tor.safe_socks", "SafeSocks", "Valor escalar ambíguo ou inválido.", "high")
    if control:
        # Controle sem autenticação permite reconfigurar o Tor por clientes locais.
        try:
            cookie = scalar(options, "cookieauthentication", "0")
            if cookie not in ("0", "1"):
                raise ValueError("Booleano inválido")
            password_entries = options.get("hashedcontrolpassword", [])
            valid_password = any(len(v) == 1 and re.fullmatch(r"16:[0-9a-fA-F]{58}", v[0]) for v in password_entries)
            if password_entries and not valid_password:
                raise ValueError("Hash de controle inválido")
            protected = cookie == "1" or valid_password
            yield Result("tor.control_auth", "Autenticação do ControlPort",
                         "pass" if protected else "fail", "critical",
                         "Autenticação declarada para a porta de controle." if protected else "ControlPort declarado sem autenticação.",
                         "Use CookieAuthentication 1 e proteja o cookie, ou configure autenticação por senha de controle.",
                         {"cookie_authentication": cookie == "1", "password_authentication_declared": bool(valid_password)})
        except ValueError:
            yield inconclusive("tor.control_auth", "Autenticação do ControlPort", "Configuração de autenticação não interpretada com segurança.", "critical")
    if options.get("controlsocket") and options["controlsocket"] != [["0"]]:
        yield inconclusive("tor.control_socket", "Socket Unix de controle", "Permissões e autenticação do ControlSocket exigem revisão adicional.", "high")


def dns_checks(context):
    policy = context.config["tor"]
    try:
        output = context.collector.read_text(policy["resolv_conf"])
        nameservers = []
        for line in output.splitlines():
            parts = re.split(r"[#;]", line, maxsplit=1)[0].split()
            if parts and parts[0] == "nameserver":
                if len(parts) != 2:
                    raise ValueError("nameserver inválido")
                nameservers.append(str(ipaddress.ip_address(parts[1])))
        if not nameservers:
            raise ValueError("Nenhum nameserver explícito")
        permitted = {str(ipaddress.ip_address(value)) for value in policy["allowed_nameservers"]}
        unexpected = sorted(set(nameservers) - permitted)
        yield Result("tor.dns_resolvers", "Resolvedores DNS declarados",
                     "fail" if unexpected else "pass", "high",
                     "Resolvedor fora da política: possível caminho de DNS direto." if unexpected else "Endereços nameserver correspondem à política configurada.",
                     "Verifique a cadeia do resolvedor local, o uso de DNS pelo proxy e as regras de saída IPv4/IPv6.",
                     {"nameservers": nameservers, "unexpected_nameservers": unexpected})
    except (Unavailable, ValueError):
        yield inconclusive("tor.dns_resolvers", "Resolvedores DNS declarados", "resolv.conf ausente, inacessível ou sem nameservers interpretáveis.", "high")
    # Um stub local pode encaminhar DNS diretamente. Aplicativos também podem usar
    # DoH/DoT ou DNS próprio; nem resolv.conf nem DNSPort provam ausência de bypass.
    yield inconclusive("tor.dns_assurance", "Ausência de vazamento DNS",
                       "Não comprovável por estes checks passivos: upstream do stub, firewall, DNS de aplicativos e IPv6 não foram validados de ponta a ponta.",
                       "high", "Revise o encaminhamento do resolvedor e a política de saída; configure aplicações para resolução pelo proxy. DNSPort sozinho não força o tráfego a passar pelo Tor.")


def run(context):
    unit = context.config["tor"]["service"]
    try:
        props = service_properties(context, unit)
        if not {"LoadState", "ActiveState", "MainPID"} <= props.keys():
            raise Unavailable("systemd não forneceu todas as propriedades necessárias")
        active = props["LoadState"] == "loaded" and props["ActiveState"] == "active" and props["MainPID"].isdigit() and int(props["MainPID"]) > 0
        yield Result("tor.service", "Serviço Tor ativo", "pass" if active else "fail", "high",
                     "Unidade ativa com processo principal." if active else "Unidade ausente/inativa ou sem processo principal.",
                     "Confirme a unidade Tor usada pelo NVG OS e examine seu estado e logs locais.",
                     {"unit": unit, "load_state": props["LoadState"], "active_state": props["ActiveState"]})
    except Unavailable as error:
        yield inconclusive("tor.service", "Serviço Tor ativo", str(error), "high")
    yield from config_checks(context)
    yield from dns_checks(context)
    if context.config.get("nos", {}).get("enabled"):
        yield from nos_runtime(context)
    yield inconclusive("tor.runtime_config", "Correspondência com o Tor em execução",
                       "Auditoria do torrc selecionado; defaults-torrc, opções de linha de comando, configuração não recarregada e bootstrap não são verificados.",
                       "high", "Confirme os arquivos e argumentos da unidade e a configuração efetiva do Tor antes de interpretar os resultados como estado em execução.")


def nos_runtime(context):
    """Completa a referência de firewall com identidade real e listeners locais."""
    from ..network_state import collect_listeners
    from .service_checks import effective_uid, service_properties_fresh
    policy = context.config["nos"]
    try:
        props = service_properties(context, context.config["tor"]["service"])
        pid = int(props["MainPID"])
        if pid <= 0:
            raise ValueError()
        uid = effective_uid(context.collector.read_text(f"/proc/{pid}/status"))
        if service_properties_fresh(context, context.config["tor"]["service"]).get("MainPID") != str(pid):
            raise Unavailable("PID Tor mudou durante a coleta")
        yield Result("tor.nos_uid", "UID do Tor e exceção do firewall", "pass" if uid == policy["tor_uid"] else "fail", "critical",
                     "UID efetivo confrontado com a exceção da referência do nOS.", "Mantenha a referência e o UID real do daemon coerentes; não suponha que usuário tor tenha UID fixo.",
                     {"effective_uid": uid, "expected_uid": policy["tor_uid"]})
    except (Unavailable, ValueError, KeyError):
        yield inconclusive("tor.nos_uid", "UID do Tor e exceção do firewall", "Processo Tor/UID não disponível ou mudou durante coleta.", "critical")
    try:
        listeners, rejected = collect_listeners(context)
        if rejected:
            raise Unavailable("Parte dos listeners não foi interpretada")
        for protocol, port in (("udp", 9053), ("tcp", 9040)):
            # Portas pertencem à referência documentada, não a segredos. A
            # escuta não identifica seu dono nem comprova bootstrap/resolução.
            found = any(p == protocol and a in ("127.0.0.1", "::1") and n == port for p,a,n in listeners)
            yield Result(f"tor.nos_listener.{protocol}.{port}", "Destino local do redirecionamento Tor", "pass" if found else "fail", "high",
                         "Listener local esperado presente." if found else "Destino local do redirecionamento não está escutando.",
                         "Confira DNSPort/TransPort, o processo proprietário e bootstrap; ausência bloqueia o fluxo esperado.", {"protocol": protocol, "port": port})
    except Unavailable as error:
        yield inconclusive("tor.nos_listeners", "Destinos locais Tor", str(error), "high")
    try:
        # Sem emitir DNS de teste. Não copiar servidores, domínios de busca ou
        # nomes privados ao relatório; resolução por link exige análise própria.
        raw = context.collector.command(["resolvectl", "dns"])
        if not raw.strip():
            raise Unavailable("Nenhuma informação de DNS por link")
        yield inconclusive("tor.resolved_upstream", "Cadeia systemd-resolved", "Upstreams por link consultados; interpretação das rotas DNS e DNS de aplicações não comprova ausência de bypass. Correlacione com o modo de firewall verificado.", "high")
    except Unavailable:
        yield inconclusive("tor.resolved_upstream", "Cadeia systemd-resolved", "resolvectl indisponível; cadeia do stub não avaliada.", "high")
