"""Assinatura de artefatos locais, procedência indicativa e confiança do signatário.

Nunca confundir o campo histórico Validated By com uma reverificação dos bytes.
"""

from pathlib import Path
import re

from ..collectors import Unavailable
from ..models import Result, inconclusive

SCAN_PRIORITY = 100  # Coleta dispendiosa só depois dos controles do host.
RUN_IN_QUICK = False
CONFIG_SECTION = "package_integrity"
TOKEN = re.compile(r"[A-Za-z0-9@._+:-]+(?:-[A-Za-z0-9@._+:-]+)*\Z")


def signature_state(code, output):
    # Só tokens de status conhecidos; nunca exportar GOODSIG (contém identidade).
    tags = set()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "[GNUPG:]":
            tags.add(parts[1])
    if tags & {"BADSIG", "REVKEYSIG", "EXPKEYSIG", "EXPSIG", "KEYREVOKED", "KEYEXPIRED", "SIGEXPIRED"}:
        return "fail", "Assinatura inválida ou signatário/assinatura revogado ou expirado no estado local."
    if "NO_PUBKEY" in tags:
        return "warning", "Chave pública do signatário ausente no keyring local."
    if "VALIDSIG" in tags and code == 0:
        if tags & {"TRUST_MARGINAL", "TRUST_UNDEFINED", "TRUST_NEVER"}:
            return "fail", "Assinatura válida, mas validade/confiança do signatário insuficiente para TrustedOnly."
        if tags & {"TRUST_FULLY", "TRUST_ULTIMATE"}:
            return "pass", "Assinatura criptográfica válida e confiança suficiente no keyring local."
        return "warning", "Assinatura válida sem informação conclusiva de confiança do signatário."
    return "warning", "GPG não forneceu evidência conclusiva de assinatura e confiança."


def crypto_outcome(output):
    """Contagem de evidência matemática, separada da confiança no signatário.

    Expiração/revogação sem VALIDSIG/BADSIG não demonstra que GPG conferiu
    criptograficamente os bytes. Chave ausente e simples tentativa não contam.
    """
    tags = {p[1] for line in output.splitlines()
            if len(p := line.split()) >= 2 and p[0] == "[GNUPG:]"}
    if "BADSIG" in tags:
        return "invalid_signatures"
    if "VALIDSIG" in tags:
        return "valid_signatures"
    return None


def policy_checks(context):
    config_path = context.config[CONFIG_SECTION]["pacman_conf"]
    try:
        repos = context.collector.command(["pacman-conf", "--config", config_path, "--repo-list"]).splitlines()
        queries = [("global", [], "SigLevel"), ("local_file", [], "LocalFileSigLevel")]
        for repo in repos:
            if not TOKEN.fullmatch(repo):
                raise Unavailable("Nome de repositório não interpretado")
            queries.append(("repo." + repo, ["--repo", repo], "SigLevel"))
        for label, extra, directive in queries:
            try:
                raw = context.collector.command(["pacman-conf", "--config", config_path, *extra, directive])
                tokens = raw.split()
                # pacman-conf resolve includes/herança e expande flags Package/Database.
                known = {"Required", "Optional", "Never", "TrustedOnly", "TrustAll",
                         "PackageRequired", "PackageOptional", "PackageNever", "PackageTrustedOnly", "PackageTrustAll",
                         "DatabaseRequired", "DatabaseOptional", "DatabaseNever", "DatabaseTrustedOnly", "DatabaseTrustAll"}
                if not tokens or any(t not in known for t in tokens):
                    raise Unavailable("SigLevel não interpretado completamente")
                requirement, trusted = None, None
                for token in tokens:
                    if token in ("Required", "PackageRequired"): requirement = True
                    if token in ("Optional", "Never", "PackageOptional", "PackageNever"): requirement = False
                    if token in ("TrustedOnly", "PackageTrustedOnly"): trusted = True
                    if token in ("TrustAll", "PackageTrustAll"): trusted = False
                if requirement is None or trusted is None:
                    raise Unavailable("SigLevel não explicita obrigatoriedade/confiança resolvidas")
                ok = requirement and trusted
                yield Result("package_integrity.policy." + label, "Política de assinatura pacman", "pass" if ok else "fail", "high",
                             "Assinaturas obrigatórias com TrustedOnly." if ok else "Política permite pacote sem assinatura ou signatário não confiável.",
                             "Revise SigLevel e LocalFileSigLevel, incluindo políticas dos repositórios NVG OS.")
            except Unavailable as error:
                yield inconclusive("package_integrity.policy." + label, "Política de assinatura pacman", str(error), "high")
    except Unavailable as error:
        yield inconclusive("package_integrity.policy", "Política de assinatura pacman", str(error), "high")


def inventory(output, repository=False):
    packages = {}
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < (3 if repository else 2):
            raise Unavailable("Inventário pacman não interpretado")
        name, version = parts[1:3] if repository else parts[:2]
        if not TOKEN.fullmatch(name) or not TOKEN.fullmatch(version):
            raise Unavailable("Nome/versão de pacote não interpretado")
        if not repository and name in packages:
            raise Unavailable("Pacote duplicado no inventário")
        packages[name] = version
    return packages


def run(context):
    policy = context.config[CONFIG_SECTION]
    coverage = {"total_installed": None, "selected": 0, "examined": 0,
                "verification_attempts": 0, "cryptographically_verified": 0,
                "valid_signatures": 0, "invalid_signatures": 0, "trusted_valid_signatures": 0,
                "inconclusive": 0, "not_verified": None, "coverage_percent": None,
                "selection_limit": policy["max_packages"],
                "scope": "artefatos no cache; não verifica bytes instalados"}
    # Atualizado incrementalmente: uma interrupção não inventa cobertura completa.
    context.cache["package_coverage"] = coverage
    yield from policy_checks(context)
    base = ["pacman", "--config", policy["pacman_conf"], "--dbpath", policy["db_path"]]
    try:
        installed = inventory(context.collector.command([*base, "-Q"]))
        if not installed:
            raise Unavailable("Nenhum pacote instalado listado")
    except Unavailable as error:
        yield inconclusive("package_integrity.inventory", "Inventário de pacotes", str(error), "high")
        return
    try:
        repositories = inventory(context.collector.command([*base, "-Sl"]), repository=True)
        if not repositories:
            raise Unavailable("Bases locais de repositórios vazias")
    except Unavailable as error:
        repositories = None
        yield inconclusive("package_integrity.repositories", "Bases locais de repositórios", str(error), "info")
    context.cache["packages.installed"] = installed
    coverage["total_installed"] = len(installed)
    coverage["not_verified"] = len(installed)
    coverage["coverage_percent"] = 0.0
    priorities = policy.get("priority_packages", [])
    names = sorted(installed, key=lambda name: (priorities.index(name) if name in priorities else len(priorities), name))
    coverage["selected"] = min(len(names), policy["max_packages"])
    if len(names) > policy["max_packages"]:
        yield inconclusive("package_integrity.budget", "Limite de pacotes", "Inventário maior que max_packages; verificação criptográfica parcial.", "high")
    for name in names:
        if repositories is not None and name not in repositories:
            yield inconclusive("package_integrity.foreign." + name, "Pacote fora das bases configuradas",
                               "Pacote não consta das bases locais de repositórios; isso não prova AUR, instalação via -U ou ausência de assinatura.", "info")
    for name in names[:policy["max_packages"]]:
        coverage["examined"] += 1
        check_id = "package_integrity.signature." + name
        try:
            version = installed[name]
            matches = []
            for directory in policy["cache_dirs"]:
                # Epoch nem sempre aparece no nome do arquivo; -Qp confirma nome/versão.
                pattern = str(Path(directory) / (name + "-" + version.split(":", 1)[-1] + "-*.pkg.tar.*"))
                for path in context.collector.glob(pattern):
                    if not path.endswith(".sig") and path.endswith((".zst", ".xz", ".gz", ".bz2", ".lz4", ".lrz", ".lzo", ".Z")):
                        matches.append(path)
            if not matches:
                raise Unavailable("Arquivo da versão instalada ausente do cache; metadados não substituem verificação criptográfica")
            if len(matches) > 1:
                raise Unavailable("Múltiplos arquivos candidatos no cache; escolha inequívoca não disponível")
            archive = matches[0]
            found = inventory(context.collector.command([*base, "-Qp", "--", archive]))
            if found != {name: version}:
                raise Unavailable("Nome/versão do artefato não corresponde ao pacote instalado")
            # Não ler/executar payloads ou scriptlets de instalação.
            coverage["verification_attempts"] += 1
            code, output = context.collector.verify_package(archive, archive + ".sig", policy["keyring_dir"])
            status, reason = signature_state(code, output)
            outcome = crypto_outcome(output)
            if outcome:
                coverage[outcome] += 1
                coverage["cryptographically_verified"] += 1
            if status == "pass":
                coverage["trusted_valid_signatures"] += 1
            if status == "warning":
                yield inconclusive(check_id, "Assinatura do pacote e confiança", reason, "high")
            else:
                yield Result(check_id, "Assinatura do pacote e confiança", status, "high", reason,
                             "Use artefatos assinados por signatários confiáveis; revise o keyring local e sua atualização por procedimento separado.",
                             {"package": name, "version": version, "scope": "arquivo no cache; não é integridade dos arquivos instalados"})
        except (Unavailable, OSError) as error:
            reason = str(error) if isinstance(error, Unavailable) else "Arquivo/keyring inacessível"
            yield inconclusive(check_id, "Assinatura do pacote e confiança", reason, "high")
        finally:
            coverage["not_verified"] = len(installed) - coverage["cryptographically_verified"]
            coverage["inconclusive"] = coverage["examined"] - coverage["cryptographically_verified"]
            coverage["coverage_percent"] = round(100 * coverage["cryptographically_verified"] / len(installed), 2)
    yield inconclusive("package_integrity.scope", "Limites de integridade local",
                       "Assinaturas do cache não comprovam os bytes atualmente instalados nem a procedência histórica. Bases/keyring podem estar desatualizados; sem consulta de revogação online. Confiança só é avaliada para signatários verificáveis.", "info")
