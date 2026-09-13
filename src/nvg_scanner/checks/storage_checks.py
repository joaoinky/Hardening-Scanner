"""Política de persistência: arquivos de configuração não substituem mountinfo."""

import json
import re
from ..collectors import Unavailable
from ..models import Result, inconclusive

CONFIG_SECTION = "nos"


def mounts(context):
    key = "storage.mounts"
    if key not in context.cache:
        document = json.loads(context.collector.command(["findmnt", "--json", "--list", "--output", "TARGET,SOURCE,FSTYPE,OPTIONS"]))
        rows = document["filesystems"]
        if not isinstance(rows, list) or not rows:
            raise ValueError()
        result = {}
        for row in rows:
            if not all(isinstance(row.get(k), str) for k in ("target", "source", "fstype", "options")):
                raise ValueError()
            if row["target"] in result:
                raise Unavailable("Montagens sobrepostas no mesmo destino; visibilidade não determinada")
            result[row["target"]] = row
        context.cache[key] = result
    return context.cache[key]


def run(context):
    policy = context.config["nos"]
    try:
        observed = mounts(context)
        for index, (path, required) in enumerate(policy["mounts"].items()):
            row = observed.get(path)
            ok = row is not None and row["fstype"] == "tmpfs" and set(required) <= set(row["options"].split(","))
            yield Result("storage.mount." + path.replace("/", "_"), "Persistência de " + path, "pass" if ok else "fail", "high",
                         "Montagem tmpfs atende às opções exigidas." if ok else "Montagem tmpfs/opções exigidas ausentes no estado observado.",
                         "Revise as montagens ativas e a configuração persistente do nOS; noexec não impede leitura por interpretadores.",
                         {"target": path, "fstype": row["fstype"] if row else None, "required_options": required})
        if policy["vault"]:
            persistent = [r for r in observed.values() if r["fstype"] not in ("tmpfs", "ramfs", "squashfs", "overlay", "proc", "sysfs", "devtmpfs", "devpts", "cgroup2", "securityfs", "debugfs", "tracefs", "configfs", "pstore", "efivarfs", "fusectl", "mqueue", "hugetlbfs", "autofs", "binfmt_misc")]
            if persistent:
                yield inconclusive("storage.vault_mounts", "Montagens potencialmente persistentes no Vault",
                                   f"{len(persistent)} montagens exigem revisão de persistência; não foram desmontadas nem seus conteúdos lidos.", "high")
    except (Unavailable, ValueError, KeyError, TypeError) as error:
        yield inconclusive("storage.mounts", "Montagens efetivas", str(error) if isinstance(error, Unavailable) else "findmnt não forneceu tabela completa interpretável.", "high")
    try:
        lines = context.collector.read_text("/proc/swaps").splitlines()
        if not lines or lines[0].split() != ["Filename", "Type", "Size", "Used", "Priority"]:
            raise ValueError()
        zram, disk, unknown = 0, 0, 0
        for line in lines[1:]:
            parts = line.split()
            if len(parts) != 5:
                raise ValueError()
            name = parts[0]
            if re.fullmatch(r"/dev/zram[0-9]+", name):
                # ZRAM com writeback pode persistir páginas: nome sozinho não basta.
                try:
                    backing = context.collector.read_text("/sys/block/" + name[5:] + "/backing_dev").strip()
                    if backing == "none":
                        zram += 1
                    else:
                        disk += 1
                except Unavailable:
                    unknown += 1
            else:
                disk += 1
        if disk or unknown:
            yield Result("storage.swap", "Persistência do swap", "warning", "high", "Swap requer avaliação adicional de armazenamento.",
                         "Confirme a cadeia de criptografia dos swaps em disco/arquivo e o writeback de ZRAM; não basta haver ZRAM também.",
                         {"zram_without_writeback": zram, "disk_or_writeback": disk, "unknown": unknown},
                         reason="Proteção criptográfica dos dispositivos/arquivos de swap não comprovada; leitura não acessa páginas de swap.")
        else:
            yield Result("storage.swap", "Persistência do swap", "pass", "high", "Sem swap ativo ou somente ZRAM sem writeback observado.",
                         "Repita após alterações de swap; isso não comprova ausência de outros caminhos de persistência.", {"zram_without_writeback": zram})
    except (Unavailable, ValueError):
        yield inconclusive("storage.swap", "Persistência do swap", "Inventário de swap indisponível ou inválido.", "high")
    try:
        output = context.collector.command(["systemd-analyze", "cat-config", "systemd/journald.conf"])
        section, values = None, {}
        for raw in output.splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", ";")):
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1]
            elif section == "Journal":
                key, sep, value = line.partition("=")
                if not sep or line.endswith("\\"):
                    raise ValueError()
                values[key.strip()] = value.strip()
        for key, expected in policy["journald"].items():
            if key not in values:
                yield inconclusive("storage.journal." + key, "Journald: " + key, "Diretiva não explícita na configuração composta; default não inferido.", "medium")
                continue
            ok = values[key] == expected
            yield Result("storage.journal." + key, "Journald: " + key, "pass" if ok else "fail", "medium",
                         "Configuração composta corresponde à política." if ok else "Configuração composta diverge da política.",
                         "Revise precedência dos drop-ins e confirme a aplicação pelo serviço; saída não contém mensagens do journal.")
        yield inconclusive("storage.journal.runtime", "Aplicação da política de logs", "cat-config descreve arquivos compostos; não comprova recarga do daemon nem ausência de logs históricos em outros destinos.", "medium")
    except (Unavailable, ValueError):
        yield inconclusive("storage.journal", "Política journald", "Configuração composta indisponível ou construção não interpretada.", "medium")
