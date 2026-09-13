"""Adaptador somente leitura do contrato network_verify fornecido pelo nOS.

Não interpreta marcadores nem executa network_apply_rules/cache. A biblioteca
instalada é código confiável do OS: exigimos proprietário root e pais protegidos.
"""

from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import stat
import time

from .collectors import Unavailable
from .config import no_duplicates
from .key_patterns import safe_location
from .models import Result, inconclusive


def trusted_file(collector, filename):
    path = Path(filename)
    for item in (path, *path.parents):
        m = collector.lstat(item)
        if m.st_uid != 0 or m.st_mode & 0o022 or stat.S_ISLNK(m.st_mode):
            raise Unavailable("Biblioteca/referência ou ancestral não pertence a root, é gravável ou usa symlink")
        if not (stat.S_ISREG(m.st_mode) if item == path else stat.S_ISDIR(m.st_mode)):
            raise Unavailable("Biblioteca/referência ou ancestral de tipo inesperado")


def verify(context):
    policy = context.config["nos"]
    mode = policy["expected_network_mode"]
    key = "nos.network." + mode
    if key not in context.cache:
        try:
            for path in (policy["network_library"], policy["network_reference"]):
                trusted_file(context.collector, path)
            reference = context.collector.read_text(policy["network_reference"])
            reference_id = hashlib.sha256(reference.encode()).hexdigest()  # Dados PÚBLICOS, nunca chaves.
            args = ["bash", "--noprofile", "--norc", "-c",
                    'source "$1" || exit 2; network_verify "$2" "${@:3}"',
                    "nvg-read-only", policy["network_library"], mode]
            if mode == "killswitch-vpn":
                args += [policy["vpn_interface"], json.dumps(policy["vpn_endpoints"], separators=(",", ":"))]
            started = datetime.now(timezone.utc)
            code, raw = context.collector.command_status(args)
            document = json.loads(raw, object_pairs_hook=no_duplicates)
            if type(document.get("schema_version")) is not int or document["schema_version"] != 1:
                raise Unavailable("Contrato nativo: schema_version não suportado")
            verification = document.get("verification", {})
            state = verification.get("state")
            if verification.get("requested") != mode or state not in ("verified", "mismatch", "unknown"):
                raise Unavailable("Contrato nativo: verification.requested/state ausente ou divergente")
            if code != {"verified": 0, "mismatch": 1, "unknown": 2}[state]:
                raise Unavailable("Contrato nativo: código de saída contradiz verification.state")
            observed = datetime.fromisoformat(document["observed_at"].replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            if observed.tzinfo is None or not started.timestamp() - 2 <= observed.timestamp() <= now.timestamp() + 2:
                raise Unavailable("Contrato nativo: timestamp ausente, antigo ou futuro; cache não é evidência nova")
            domain = document.get("airgap" if mode == "airgap" else "firewall")
            if not isinstance(domain, dict) or domain.get("state") not in ("verified", "mismatch", "unknown"):
                raise Unavailable("Contrato nativo: domínio sem estado reconhecido")
            if state == "verified" and domain["state"] != "verified":
                raise Unavailable("Contrato nativo: domínio contradiz verificação positiva")
            if state == "verified" and mode != "airgap" and domain.get("mode") != mode:
                raise Unavailable("Contrato nativo: modo observado contradiz o solicitado")
            # Só dados estruturados selecionados; não serializar o JSON bruto.
            reasons = []
            def collect_reasons(value):
                if isinstance(value, dict):
                    for field, child in value.items():
                        if field in ("reason", "error", "detail") and isinstance(child, str):
                            reasons.append(safe_location(child)[:512])
                        elif isinstance(child, (dict, list)):
                            collect_reasons(child)
                elif isinstance(value, list):
                    for child in value:
                        collect_reasons(child)
            collect_reasons(domain)
            context.cache[key] = {"state": state, "expected_mode": mode,
                                  "observed_at": observed.isoformat(), "reference_sha256": reference_id,
                                  "reasons": reasons[:16]}
        except (Unavailable, OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            reason = str(error) if isinstance(error, Unavailable) else "Contrato nativo ilegível, JSON inválido ou campo obrigatório ausente"
            context.cache[key] = Unavailable(reason)
    value = context.cache[key]
    if isinstance(value, Unavailable):
        raise value
    return value


def run(context, prefix="firewall"):
    try:
        evidence = verify(context)
        state = evidence["state"]
        status = {"verified": "pass", "mismatch": "fail", "unknown": "warning"}[state]
        yield Result(prefix + ".nos_mode", "Conformidade com o modo de rede solicitado", status, "critical",
                     "Observação nova confrontada com a política solicitada e as referências locais do nOS.",
                     "Revise o modo esperado, as referências distribuídas e o estado do kernel; consulta não comprova anonimato ou isolamento físico.",
                     evidence, reason=("; ".join(evidence["reasons"]) or "Verificador nativo retornou unknown sem motivo detalhado no contrato") if status == "warning" else None)
    except Unavailable as error:
        yield inconclusive(prefix + ".nos_mode", "Conformidade com o modo de rede solicitado", str(error), "critical")
