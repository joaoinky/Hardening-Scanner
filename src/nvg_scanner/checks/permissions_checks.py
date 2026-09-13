"""Metadados de chaves: ler conteúdo privado não é necessário para auditar acesso."""

from pathlib import Path
import stat

from ..collectors import Unavailable
from ..nos import enabled, target_user, expand_path
from ..models import Result, inconclusive


def audit(context, entry):
    collector = context.collector
    path = Path(entry["path"])
    check_id = "permissions." + entry["id"]
    evidence = {"path": str(path), "expected_uid": entry["uid"], "max_mode": entry["max_mode"]}
    try:
        collector.lstat(path)
    except FileNotFoundError:
        if entry["required"]:
            yield Result(check_id, "Arquivo/diretório sensível", "fail", entry["severity"],
                         "Caminho obrigatório ausente.", "Confirme o caminho e o provisionamento esperado para este perfil.", evidence)
        else:
            yield inconclusive(check_id, "Arquivo/diretório sensível", "Caminho opcional ausente; permissões não avaliadas.", entry["severity"])
        return
    except OSError as error:
        yield inconclusive(check_id, "Arquivo/diretório sensível", f"Metadados indisponíveis ({type(error).__name__}).", entry["severity"])
        return
    problems, limitations = [], []
    try:
        # Pais graváveis permitem substituir a chave mesmo se ela estiver em 0600.
        lexical = [path, *path.parents]
        links = [str(p) for p in lexical if stat.S_ISLNK(collector.lstat(p).st_mode)]
        if links and not entry["allow_symlink"]:
            problems.append("Links simbólicos no caminho não autorizados")
            evidence["symlinks"] = links
        actual = collector.resolve(path)
        metadata = collector.stat(actual)
        mode = stat.S_IMODE(metadata.st_mode)
        evidence.update({"mode": f"{mode:04o}", "uid": metadata.st_uid, "gid": metadata.st_gid})
        correct_kind = stat.S_ISREG(metadata.st_mode) if entry["kind"] == "file" else stat.S_ISDIR(metadata.st_mode)
        if not correct_kind:
            problems.append("Tipo de arquivo diferente do esperado")
        if mode & ~int(entry["max_mode"], 8):
            problems.append("Bits de permissão excedem a máscara permitida")
        if metadata.st_uid != entry["uid"] or ("gid" in entry and metadata.st_gid != entry["gid"]):
            problems.append("Proprietário/grupo divergente da política")
        unsafe_parents = []
        # Inspeciona ambas as cadeias quando um symlink é explicitamente permitido.
        parents = set(path.parents) | set(actual.parents)
        for parent in sorted(parents, key=str):
            parent_stat = collector.stat(parent)
            if parent_stat.st_mode & 0o022 or parent_stat.st_uid not in (0, entry["uid"]):
                unsafe_parents.append(str(parent))
        if unsafe_parents:
            problems.append("Diretórios ancestrais graváveis por grupo/outros ou controlados por outro UID")
            evidence["unsafe_parents"] = unsafe_parents
        # O modo POSIX sozinho não explica entradas nominativas de ACL.
        for target in sorted({actual, *parents}, key=str):
            try:
                attrs = collector.xattrs(target)
                if any(name.startswith("system.posix_acl_") for name in attrs):
                    limitations.append("ACL POSIX encontrada; entradas nominativas exigem revisão adicional")
            except OSError:
                limitations.append("Não foi possível inspecionar ACLs via atributos estendidos")
    except OSError as error:
        limitations.append(f"Cadeia de metadados incompleta ({type(error).__name__})")
    if problems:
        yield Result(check_id, "Proteção de caminho sensível", "fail", entry["severity"],
                     "; ".join(problems) + ".", "Revise proprietário, máscara de permissões e diretórios ancestrais; mantenha chaves acessíveis somente ao usuário necessário.", evidence)
    elif not limitations:
        yield Result(check_id, "Proteção de caminho sensível", "pass", entry["severity"],
                     "Metadados e diretórios ancestrais atendem à política POSIX.", "Preserve essas permissões ao copiar ou restaurar backups.", evidence)
    if limitations:
        yield inconclusive(check_id + ".coverage", "Cobertura de permissões", "; ".join(sorted(set(limitations))), entry["severity"])


def run(context):
    entries = context.config["permissions"]["sensitive_paths"]
    if not entries:
        yield inconclusive("permissions.policy", "Política de arquivos sensíveis", "Nenhum caminho sensível configurado.", "high")
    applicable_entries = 0
    for original in entries:
        if enabled(context.config) and original.get("feature") and not context.config["nos"]["features"][original["feature"]]:
            continue
        applicable_entries += 1
        entry = dict(original)
        try:
            entry["path"] = expand_path(context, entry["path"])
            if entry["uid"] == "target":
                entry["uid"] = target_user(context)["uid"]
            yield from audit(context, entry)
        except Unavailable as error:
            yield inconclusive("permissions." + entry["id"], "Usuário/caminho sensível", str(error), entry["severity"])
    if entries and not applicable_entries:
        yield inconclusive("permissions.scope", "Escopo de permissões", "Nenhum caminho aplicável às funcionalidades selecionadas.", "info")
