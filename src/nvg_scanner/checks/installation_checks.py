"""Resíduos da Live no alvo instalado; nenhuma alteração no boot ou nos discos."""

from ..collectors import Unavailable, service_properties
from ..models import Result, inconclusive
from .storage_checks import mounts

CONFIG_SECTION = "nos"


def run(context):
    policy = context.config["nos"]
    try:
        names = [line.split(":", 1)[0] for line in context.collector.read_text(context.config["accounts"]["passwd_path"]).splitlines()]
        if not names:
            raise Unavailable("passwd vazio")
        yield Result("installation.liveuser", "Conta herdada da Live", "fail" if "liveuser" in names else "pass", "high",
                     "Conta liveuser permanece no alvo." if "liveuser" in names else "Conta liveuser ausente do passwd auditado.",
                     "Revise a limpeza de contas da mídia no sistema instalado.")
    except Unavailable:
        yield inconclusive("installation.liveuser", "Conta herdada da Live", "Não foi possível consultar passwd.", "high")
    for index, path in enumerate(policy["live_artifacts"]):
        try:
            context.collector.lstat(path)
            present = True
        except FileNotFoundError:
            present = False
        except OSError:
            yield inconclusive(f"installation.artifact.{index}", "Resíduo da Live", "Metadados indisponíveis.", "high")
            continue
        yield Result(f"installation.artifact.{index}", "Resíduo da Live", "fail" if present else "pass", "high",
                     "Artefato exclusivo da mídia permanece no alvo." if present else "Artefato exclusivo da mídia ausente.",
                     "Revise a etapa strip_live e a finalidade deste arquivo antes de removê-lo.", {"path": path})
    for unit in policy["live_services"]:
        try:
            props = service_properties(context, unit)
            if not {"LoadState", "ActiveState"} <= props.keys():
                raise Unavailable("Propriedades incompletas")
            bad = props["ActiveState"] in ("active", "activating", "reloading")
            yield Result("installation.service." + unit, "Serviço exclusivo da mídia", "fail" if bad else "pass", "high",
                         "Serviço Live ativo no alvo." if bad else "Serviço Live não está ativo nesta observação.", "Revise unidades herdadas da mídia.", {"unit": unit})
        except Unavailable:
            yield inconclusive("installation.service." + unit, "Serviço exclusivo da mídia", "Estado de serviço indisponível.", "high")
    try:
        rows = mounts(context)
        temporary = any((path == "/etc/pacman.d/gnupg" or path.startswith("/etc/pacman.d/gnupg/")) and row["fstype"] in ("tmpfs", "ramfs", "overlay") for path, row in rows.items())
        yield Result("installation.keyring_mount", "Chaveiro pacman persistente", "fail" if temporary else "pass", "high",
                     "Montagem temporária sobre o chaveiro no alvo instalado." if temporary else "Nenhuma montagem temporária específica sobre o chaveiro foi observada.",
                     "Confirme o chaveiro persistente do alvo; essa observação não comprova persistência da raiz nem validade criptográfica.")
    except (Unavailable, ValueError, KeyError, TypeError):
        yield inconclusive("installation.keyring_mount", "Chaveiro pacman persistente", "Montagens não interpretadas.", "high")
    try:
        raw = context.collector.command(["systemctl", "show", "--no-pager", "--property=ExecStart", "--", "getty@tty1.service"])
        if not raw.startswith("ExecStart="):
            raise Unavailable("ExecStart ausente")
        import re
        autologin = bool(re.search(r"(?:--autologin|-a)(?:=|\s+)root(?:\s|;|$)", raw))
        yield Result("installation.root_autologin", "Autologin root no tty1", "fail" if autologin else "warning", "critical",
                     "Autologin root declarado no comando efetivo." if autologin else "Padrão direto de autologin root não encontrado.",
                     "Revise getty e eventuais wrappers; argumentos do serviço não são persistidos.",
                     reason=None if autologin else "Wrappers e comandos indiretos não são interpretados; ausência do padrão não prova ausência de autologin.")
    except Unavailable:
        yield inconclusive("installation.root_autologin", "Autologin root no tty1", "ExecStart indisponível.", "critical")
    yield from login_configs(context)
    yield from fstab_checks(context)
    # Não afirmar limpeza global com base numa lista finita de caminhos.
    yield inconclusive("installation.scope", "Cobertura pós-instalação", "Lista explícita de artefatos/serviços; includes/aliases de sudoers, SDDM personalizados, initramfs, LUKS e boot efetivo exigem revisão complementar.", "high")


def login_configs(context):
    """Detecta declarações perigosas; inclui limites explícitos de interpretação."""
    import re
    for family, patterns in (
        ("sudo", ["/etc/sudoers", "/etc/sudoers.d/*"]),
        ("sddm", ["/usr/lib/sddm/sddm.conf.d/*.conf", "/etc/sddm.conf.d/*.conf", "/etc/sddm.conf"]),
    ):
        scanned, bad, incomplete = 0, 0, False
        values = {}
        for pattern in patterns:
            try:
                paths, partial = context.collector.select_files(pattern, 128)
                incomplete |= partial
            except (Unavailable, OSError):
                incomplete = True
                continue
            for path in paths:
                if scanned >= 128:
                    incomplete = True
                    break
                try:
                    # Arquivo opcional ausente não é erro; sem arquivo lido não
                    # há conclusão positiva. Nada é emitido sobre seu conteúdo.
                    context.collector.lstat(path)
                    data, partial = context.collector.read_regular_bytes(path, 65536)
                    incomplete |= partial
                    scanned += 1
                    section = None
                    for raw in data.decode("utf-8", errors="strict").splitlines():
                        line = raw.strip()
                        if family == "sudo":
                            if line.startswith(("#include", "@include")):
                                incomplete = True
                            elif line and not line.startswith("#"):
                                if "NOPASSWD:" in line and re.search(r"\b(?:liveuser|ALL)\b", line):
                                    bad += 1
                                if line.endswith("\\"):
                                    incomplete = True
                        elif line and not line.startswith(("#", ";")):
                            if line.startswith("[") and line.endswith("]"):
                                section = line[1:-1]
                            elif section == "Autologin":
                                key, sep, value = line.partition("=")
                                if not sep:
                                    incomplete = True
                                else:
                                    values[key.strip()] = value.strip()
                    del data
                except FileNotFoundError:
                    continue
                except (Unavailable, OSError, UnicodeError):
                    incomplete = True
        if family == "sddm":
            bad = bool(values.get("User"))
        # Sudo inclui aliases, includes externos e ordem: ausência de um padrão
        # NOPASSWD não sustenta PASS. SDDM idem quando não houve leitura completa.
        status = "fail" if bad else "warning"
        yield Result("installation.login." + family, "Configuração de login: " + family, status, "high",
                     "Declaração de autologin/sudo sem senha encontrada no escopo auditado." if bad else "Nenhuma declaração suportada encontrada; cobertura limitada.",
                     "Revise configuração efetiva e herança da Live; o scanner não altera sudoers nem autentica usuários.",
                     {"files_examined": scanned, "incomplete": incomplete},
                     reason=None if bad else "Includes/aliases, outras fontes ou comportamento em execução não são comprovados pela leitura limitada.")


def fstab_checks(context):
    import json
    try:
        rows = json.loads(context.collector.command(["findmnt", "--fstab", "--json", "--list", "--output", "TARGET,SOURCE,FSTYPE,OPTIONS"]))["filesystems"]
        if not isinstance(rows, list):
            raise ValueError()
        for path, options in context.config["nos"]["mounts"].items():
            matches = [row for row in rows if row["target"] == path]
            if not matches and path == "/tmp":
                # /tmp é gerenciado por tmp.mount, não exige entrada no fstab.
                continue
            ok = len(matches) == 1 and matches[0]["fstype"] == "tmpfs" and set(options) <= set(matches[0]["options"].split(","))
            yield Result("installation.fstab." + path.replace("/", "_"), "Montagem persistida de " + path, "pass" if ok else "fail", "high",
                         "Uma entrada atende à política." if ok else "Entrada ausente, duplicada ou divergente da política tmpfs.",
                         "Revise o fstab final, especialmente a substituição de @log em /var/log; compare com storage para o estado ativo.")
    except (Unavailable, ValueError, KeyError, TypeError):
        yield inconclusive("installation.fstab", "fstab final", "Tabela persistida indisponível ou não interpretada.", "high")
