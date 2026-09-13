"""Executar como root amplia impacto; necessidade de root exige política explícita."""

from ..collectors import Unavailable, service_properties
from ..models import Result, inconclusive


def effective_uid(text):
    for line in text.splitlines():
        if line.startswith("Uid:"):
            values = line.split()[1:]
            if len(values) != 4:
                break
            return int(values[1])
    raise ValueError("UID efetivo não disponível")


def run(context):
    try:
        output = context.collector.command([
            "systemctl", "list-units", "--type=service", "--state=running",
            "--no-legend", "--no-pager", "--plain", "--full",
        ])
    except Unavailable as error:
        yield inconclusive("services.collection", "Serviços em execução", str(error), "high")
        return
    units = set()
    for line in output.splitlines():
        if line.strip():
            unit = line.split()[0]
            if not unit.endswith(".service"):
                yield inconclusive("services.parse", "Lista de serviços", "Saída de systemctl não reconhecida; enumeração incompleta.", "high")
                return
            units.add(unit)
    policy = context.config["services"]
    if context.config.get("nos", {}).get("enabled"):
        from ..collectors import batch_services
        try:
            batch_services(context, units)
        except Unavailable:
            # Consultas individuais continuam disponíveis; falha em lote não
            # vira aprovação nem impede checks que ainda podem obter evidência.
            pass
    for unit in sorted(units):
        try:
            props = service_properties(context, unit)
            pid = props.get("MainPID", "")
            if not pid.isdigit() or int(pid) <= 0 or props.get("ActiveState") != "active":
                raise Unavailable("Processo principal ausente ou serviço mudou durante a coleta")
            # User= vazio significa root por padrão, mas o daemon pode abandonar
            # privilégios. O UID efetivo em /proc evita esse falso positivo.
            uid = effective_uid(context.collector.read_text(f"/proc/{int(pid)}/status"))
            if service_properties_fresh(context, unit).get("MainPID") != pid:
                raise Unavailable("PID mudou durante a coleta")
        except (Unavailable, ValueError) as error:
            yield inconclusive("services." + unit, "Privilégios de " + unit, str(error), "high")
            continue
        evidence = {"unit": unit, "main_pid": int(pid), "effective_uid": uid}
        severity = "high" if unit in policy["require_non_root"] else "medium"
        if uid != 0 or unit in policy["allowed_root_services"]:
            yield Result("services." + unit, "Privilégios de " + unit, "pass", severity,
                         "Processo principal sem UID root." if uid != 0 else "UID root autorizado explicitamente pela política.",
                         "Mantenha o menor privilégio necessário e revise exceções root periodicamente.", evidence)
        elif unit in policy["require_non_root"]:
            yield Result("services." + unit, "Privilégios de " + unit, "fail", "high",
                         "Processo principal root em serviço que deve executar sem root.",
                         "Configure usuário dedicado na unidade/daemon e ajuste somente os acessos necessários.", evidence)
        else:
            yield Result("services." + unit, "Privilégios de " + unit, "warning", "medium",
                         "Processo principal root sem política de necessidade definida.",
                         "Investigue a necessidade; adicione à lista de exceções justificadas ou exija execução sem root.", evidence,
                         reason="UID root sozinho não demonstra privilégio desnecessário.")
    if context.config.get("nos", {}).get("enabled") and context.config["nos"]["features"]["nostr_relay"]:
        yield from relay_checks(context)
    yield inconclusive("services.scope", "Cobertura dos processos de serviço",
                       "Somente MainPID de unidades systemd running no gerenciador do sistema; filhos, serviços de usuário, contêineres e daemons externos não são enumerados.",
                       "medium", "Complemente a revisão com processos filhos/cgroups e serviços iniciados fora do systemd.")


def service_properties_fresh(context, unit):
    context.cache.pop("service:" + unit, None)
    return service_properties(context, unit)


def relay_checks(context):
    """Dono do runtime vem do processo do serviço, nunca do UID do desktop."""
    from .permissions_checks import audit
    from ..network_state import collect_listeners
    unit = "nostr-relay.service"
    try:
        props = service_properties(context, unit)
        pid = int(props["MainPID"])
        if pid <= 0 or props.get("ActiveState") != "active":
            raise ValueError()
        uid = effective_uid(context.collector.read_text(f"/proc/{pid}/status"))
        yield from audit(context, {"id": "relay_runtime", "path": "/run/neovanguard-relay", "kind": "directory", "max_mode": "0700",
                                   "uid": uid, "required": True, "allow_symlink": False, "severity": "high"})
        listeners, rejected = collect_listeners(context)
        if rejected:
            raise Unavailable("Listeners parcialmente interpretados")
        endpoints = [(p,a,n) for p,a,n in listeners if p == "tcp" and n == 7777]
        ok = bool(endpoints) and all(a == "127.0.0.1" for _,a,_ in endpoints)
        yield Result("services.relay_bind", "Bind do relay local", "pass" if ok else "fail", "high",
                     "Listener na porta do relay restrito ao bind documentado." if ok else "Listener esperado ausente ou exposto além do bind documentado.",
                     "Confirme o processo proprietário do listener; mudanças para LAN exigem política explícita.")
    except (Unavailable, ValueError, KeyError):
        yield inconclusive("services.relay_runtime", "Estado do relay local", "Processo/UID ou listener do relay indisponível.", "high")
