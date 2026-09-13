"""Auditoria opt-in do próprio usuário no nOS, com limites conservadores desde v1.

Nenhum logger, traceback com valores, fragmento ou hash do segredo é produzido.
Somente contagens por tipo e localização são persistidas. Não há clipboard.
"""

from pathlib import Path
import pwd
import os
import time

from ..collectors import Unavailable
from ..key_patterns import detect, safe_location, wordlist
from ..nos import enabled, target_user
from ..models import Result, inconclusive

SCAN_PRIORITY = 90  # Coleta dispendiosa só depois dos controles do host.
RUN_IN_QUICK = False
CONFIG_SECTION = "key_exposure"


def run(context):
    policy = context.config[CONFIG_SECTION]
    deadline = time.monotonic() + policy["max_seconds"]
    remaining, files_read = policy["max_total_bytes"], 0
    try:
        vocabulary = wordlist()
        home = policy["home_dir"] or (target_user(context)["home"] if enabled(context.config) else pwd.getpwuid(os.getuid()).pw_dir)
    except (Unavailable, OSError, ValueError, KeyError):
        yield inconclusive("key_exposure.setup", "Detecção de chaves", "Wordlist ou diretório do usuário indisponível.", "critical")
        return
    entries = policy["paths"]
    if not entries:
        yield inconclusive("key_exposure.policy", "Escopo de leitura", "Nenhum arquivo explicitamente selecionado.", "critical")
    seen = set()
    for entry in entries:
        selection_id = "key_exposure." + safe_location(entry["id"])
        path = str(Path(home) / entry["path"][2:]) if entry["path"].startswith("~/") else entry["path"]
        try:
            paths, incomplete = context.collector.select_files(path, policy["max_directory_entries"])
        except (Unavailable, OSError):
            yield inconclusive(selection_id + ".selection", "Seleção de arquivos", "Seleção inacessível ou diretório não enumerável.", "critical")
            continue
        if incomplete:
            yield inconclusive(selection_id + ".selection", "Seleção de arquivos", "Limite de entradas de diretório atingido; seleção parcial.", "critical")
        if not paths:
            yield inconclusive(selection_id + ".missing", "Arquivo selecionado", "Arquivo/padrão sem correspondência; conteúdo não avaliado.", "critical")
        for filename in paths:
            # Não ler o mesmo caminho mais de uma vez quando seleções se sobrepõem.
            if filename in seen:
                continue
            seen.add(filename)
            if remaining <= 0 or files_read >= policy["max_files"] or time.monotonic() > deadline:
                yield inconclusive("key_exposure.budget", "Limite de leitura", "Limite global de bytes, arquivos ou tempo atingido; restante não avaliado.", "critical")
                return
            files_read += 1
            # ID vem da seleção + nome (redigido se necessário), nunca de um segredo
            # encontrado ou seu hash. O diff não cria identidade por chave.
            label = safe_location(filename)
            check_id = selection_id + ".file." + label
            if label == "[localização/ID omitido]":
                check_id += "." + str(files_read)
            try:
                data, partial = context.collector.read_regular_bytes(filename, min(policy["max_file_bytes"], remaining))
                remaining -= len(data)
                counts, candidates, timed_out = detect(data.decode("utf-8", errors="replace"), vocabulary, deadline)
                del data
            except (Unavailable, OSError):
                yield inconclusive(check_id, "Exposição de chaves", "Arquivo inacessível, symlink ou não regular; conteúdo não avaliado.", "critical")
                continue
            findings = {kind: count for kind, count in counts.items() if count}
            evidence = {"path": label, "occurrences": findings}
            if findings:
                yield Result(check_id, "Material de chave em texto plano", "fail", "critical",
                             "Padrão de chave/mnemônico validado ou credencial bunker reconhecida no arquivo; não comprova uso, autorização ou saldo.",
                             "Revise a exposição local em ambiente confiável e a necessidade de substituir a chave/carteira; o scanner não remove dados nem movimenta fundos.", evidence)
            elif not (partial or timed_out or any(candidates.values())):
                yield Result(check_id, "Material de chave em texto plano", "pass", "critical",
                             "Nenhum padrão suportado encontrado nos bytes lidos integralmente deste arquivo.",
                             "Evite registrar chaves e mnemônicos em históricos, logs e temporários.", evidence)
            if partial or timed_out or any(candidates.values()):
                reasons = []
                if partial: reasons.append("limite de bytes atingido ou arquivo mudou durante a leitura")
                if timed_out: reasons.append("limite de tempo de análise atingido")
                if candidates.get("nsec") or candidates.get("wif"): reasons.append("candidato nsec/WIF sem validação de checksum; pode ser fragmento ou falso positivo")
                if candidates.get("bunker"): reasons.append("URI bunker sem estrutura de credencial conclusiva")
                if candidates.get("shamir_share"): reasons.append("parte Shamir reconhecida por prefixo; CRC/formato não validado, nenhuma reconstrução ou inferência da seed")
                yield Result(check_id + ".coverage", "Cobertura da detecção", "warning", "high" if candidates.get("shamir_share") and not (partial or timed_out or candidates.get("nsec") or candidates.get("wif") or candidates.get("bunker")) else "critical",
                             "Inspeção incompleta ou candidato não confirmado.", "Revise somente o arquivo indicado, sem copiar seu conteúdo para relatórios.",
                             {"path": label, "candidate_occurrences": {k: v for k, v in candidates.items() if v}}, reason="; ".join(reasons))
