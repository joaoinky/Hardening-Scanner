"""Unidade de usuário e IPC do agente: nunca desbloqueia, assina ou lê a chave."""

import os
from pathlib import Path
import stat

from ..collectors import Unavailable
from ..models import Result, inconclusive
from ..nos import target_user
from .permissions_checks import audit

CONFIG_SECTION = "nos"
PROPERTIES = "LoadState,ActiveState,MainPID,NoNewPrivileges,ProtectSystem,ProtectHome,RestrictNamespaces,RestrictAddressFamilies,ReadWritePaths,SystemCallFilter"


def run(context):
    policy = context.config["nos"]
    try:
        user = target_user(context)
    except Unavailable as error:
        yield inconclusive("nostr_agent.user", "Usuário do agente", str(error), "high")
        return
    try:
        # --machine=user@.host consulta o gerenciador daquele usuário, sem
        # confundir o barramento de root com o da sessão auditada.
        target = [] if user["uid"] == os.geteuid() else ["--machine=" + user["name"] + "@.host"]
        raw = context.collector.command(["systemctl", "--user", *target, "show", "--no-pager", "--property=" + PROPERTIES, "--", policy["agent_unit"]])
        props = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
        if not {"LoadState", "ActiveState", "MainPID"} <= props.keys():
            raise Unavailable("Unidade de usuário sem propriedades básicas")
        active = props["LoadState"] == "loaded" and props["ActiveState"] == "active" and props["MainPID"].isdigit() and int(props["MainPID"]) > 0
        yield Result("nostr_agent.service", "Agente Nostr da sessão", "pass" if active else "fail", "high",
                     "Unidade de usuário ativa com MainPID." if active else "Agente esperado não está ativo na sessão auditada.",
                     "Confirme a sessão Wayland e a unidade de usuário; o scanner não inicia nem desbloqueia o agente.")
        for key, expected in {"NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "read-only"}.items():
            if key not in props:
                yield inconclusive("nostr_agent." + key, "Confinamento: " + key, "Propriedade não retornada.", "high")
                continue
            yield Result("nostr_agent." + key, "Confinamento: " + key, "pass" if props[key] == expected else "fail", "high",
                         "Propriedade efetiva comparada à política distribuída.", "Revise a unidade e drop-ins do usuário; MemoryDenyWriteExecute não é exigido devido ao QML/JIT.")
        families = props.get("RestrictAddressFamilies")
        if families is None or families.startswith("~"):
            yield inconclusive("nostr_agent.RestrictAddressFamilies", "Famílias de sockets do agente", "Propriedade ausente ou lista negativa não modelada.", "high")
        else:
            ok = set(families.split()) == {"AF_UNIX", "AF_INET", "AF_INET6"}
            yield Result("nostr_agent.RestrictAddressFamilies", "Famílias de sockets do agente", "pass" if ok else "fail", "high",
                         "Lista positiva de famílias comparada ao contrato NIP-46/local.", "Exija AF_UNIX, AF_INET e AF_INET6 conforme a unidade distribuída.")
        paths = props.get("ReadWritePaths")
        if paths is None or any(token.startswith(("-", "+")) for token in paths.split()):
            yield inconclusive("nostr_agent.ReadWritePaths", "Escrita permitida ao agente", "Propriedade ausente ou prefixos não interpretados.", "high")
        else:
            ok = set(paths.split()) in ({user["runtime"]}, {"%t"})
            yield Result("nostr_agent.ReadWritePaths", "Escrita permitida ao agente", "pass" if ok else "fail", "high",
                         "Exceções ReadWritePaths confrontadas com o runtime da sessão.", "Revise exceções de escrita da unidade e drop-ins; outras propriedades de sandbox também influenciam o acesso.")
        for key in ("RestrictNamespaces", "SystemCallFilter"):
            yield inconclusive("nostr_agent." + key, "Escopo do confinamento: " + key,
                               "Propriedade retornada, mas sem equivalência integral à referência da unidade." if props.get(key) else "Propriedade ausente/vazia; confinamento não comprovado.", "high")
    except Unavailable as error:
        yield inconclusive("nostr_agent.service", "Agente Nostr da sessão", str(error), "high")
    yield from audit(context, {"id": "agent_runtime", "path": user["runtime"], "kind": "directory", "max_mode": "0700",
                               "uid": user["uid"], "required": True, "allow_symlink": False, "severity": "high"})
    if policy["agent_socket"] is None:
        yield inconclusive("nostr_agent.socket", "Socket do agente", "Nome do socket não está especificado na documentação fornecida; configure agent_socket após conferir o pacote instalado.", "high")
        return
    path = Path(user["runtime"]) / policy["agent_socket"]
    try:
        metadata = context.collector.lstat(path)
        ok = stat.S_ISSOCK(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_uid == user["uid"]
        if context.collector.xattrs(path):
            yield inconclusive("nostr_agent.socket_acl", "ACL do socket", "Atributos estendidos presentes; política de acesso adicional exige revisão.", "high")
        yield Result("nostr_agent.socket", "Permissões do socket do agente", "pass" if ok else "fail", "high",
                     "Socket possui tipo, proprietário e modo esperados." if ok else "Tipo, proprietário ou modo do socket diverge da política.",
                     "Exija socket 0600 no runtime do usuário; permissões não validam SO_PEERCRED, prompt ou expiração.")
    except FileNotFoundError:
        yield Result("nostr_agent.socket", "Socket do agente", "fail", "high", "Socket configurado ausente.", "Confirme nome e estado do agente.")
    except OSError:
        yield inconclusive("nostr_agent.socket", "Socket do agente", "Metadados do socket indisponíveis.", "high")
