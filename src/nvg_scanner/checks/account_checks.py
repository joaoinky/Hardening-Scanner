"""Contas locais: sem tentativas de login, quebra de hashes ou inferência de força."""

import re

from ..collectors import Unavailable
from ..models import Result, inconclusive


def run(context):
    policy = context.config["accounts"]
    allowed_users = set(policy["allowed_interactive_users"])
    from ..nos import enabled, target_user
    if enabled(context.config):
        try:
            allowed_users.add(target_user(context)["name"])
        except Unavailable as error:
            yield inconclusive("accounts.target_user", "Conta alvo do nOS", str(error), "medium")
    try:
        passwd = context.collector.read_text(policy["passwd_path"])
    except Unavailable as error:
        yield inconclusive("accounts.passwd", "Contas locais", str(error), "high")
        return
    users, malformed = {}, 0
    for line in passwd.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) != 7 or not fields[2].isdigit() or not fields[0] or fields[0] in users:
            malformed += 1
            continue
        name, password, uid, _, _, _, shell = fields
        users[name] = {"uid": int(uid), "shell": shell, "password": password}
    if malformed or not users:
        yield inconclusive("accounts.passwd_parse", "Formato das contas locais", f"{malformed} entradas inválidas/duplicadas; lista vazia ou parcial.", "high")
    for name, user in sorted(users.items()):
        evidence = {"user": name, "uid": user["uid"], "shell": user["shell"]}
        if user["uid"] == 0:
            authorized = name in policy["allowed_uid0"]
            yield Result("accounts.uid0." + name, "Conta com UID 0", "pass" if authorized else "fail", "critical",
                         "Conta UID 0 autorizada." if authorized else "Conta adicional com privilégios integrais fora da política.",
                         "Mantenha apenas contas UID 0 explicitamente necessárias.", evidence)
        # Shell vazio usa /bin/sh em login: não é sinônimo de conta bloqueada.
        if user["shell"] not in policy["non_login_shells"]:
            authorized = name in allowed_users
            yield Result("accounts.shell." + name, "Shell interativo", "pass" if authorized else "warning", "medium",
                         "Shell autorizado pela política." if authorized else "Shell potencialmente interativo sem justificativa registrada.",
                         "Revise o uso da conta; serviços que não precisam de login podem usar nologin.", evidence,
                         reason=None if authorized else "Shell disponível não prova uso nem login permitido; PAM, SSH e bloqueios podem restringir acesso.")
        if user["password"] != "x" and not user["password"].startswith(("!", "*")):
            empty = user["password"] == ""
            yield Result("accounts.passwd_secret." + name, "Campo de senha em passwd", "fail", "critical" if empty else "high",
                         "Campo de senha vazio em passwd." if empty else "Credencial ou marcador não padrão no arquivo passwd legível por usuários.",
                         "Revise a conta e use shadow; um campo vazio pode permitir autenticação sem senha dependendo do PAM.",
                         {"user": name, "empty": empty})
    yield from shadow_checks(context, users)
    yield inconclusive("accounts.password_strength", "Força das senhas e políticas de autenticação",
                       "Força de senhas existentes não é inferível de hashes. PAM, SSH, expiração e identidades NSS/LDAP não são avaliados nesta versão.",
                       "medium", "Revise separadamente políticas de novas senhas, MFA quando aplicável e métodos de autenticação permitidos.")


def shadow_checks(context, users):
    policy = context.config["accounts"]
    try:
        shadow = context.collector.read_text(policy["shadow_path"])
    except Unavailable as error:
        yield inconclusive("accounts.shadow", "Metadados de senha locais", str(error), "high",
                           "Execute com acesso autorizado a shadow para identificar campos vazios e formatos legados; nenhum hash é incluído no relatório.")
        return
    entries, malformed = {}, 0
    for line in shadow.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) != 9 or not fields[0] or fields[0] in entries:
            malformed += 1
        else:
            entries[fields[0]] = fields[1]
    if malformed:
        yield inconclusive("accounts.shadow_parse", "Formato de shadow", f"{malformed} entradas inválidas/duplicadas; auditoria parcial.", "high")
    for name, user in sorted(users.items()):
        if user["password"] != "x":
            continue
        if name not in entries:
            yield inconclusive("accounts.password." + name, "Credencial de " + name, "Conta usa shadow, mas a entrada está ausente ou inválida.", "high")
            continue
        value = entries[name]
        if value == "":
            status, description = "fail", "Campo de senha vazio; acesso sem senha depende do PAM."
        elif value.startswith(("!", "*")):
            status, description = "pass", "Autenticação por senha bloqueada; outros métodos de login não foram avaliados."
        elif any(value.startswith(prefix) for prefix in policy["legacy_hash_prefixes"]) or re.fullmatch(r"[./0-9A-Za-z]{13}", value):
            status, description = "fail", "Formato legado de hash detectado; não implica conhecimento ou quebra da senha."
        else:
            # Só afirmar o que observamos: formato não legado não garante força,
            # custo adequado ou mesmo um hash válido para a implementação local.
            yield inconclusive("accounts.password." + name, "Credencial de " + name,
                               "Credencial não vazia/não bloqueada sem formato legado reconhecido; força e parâmetros não avaliados.", "high")
            continue
        yield Result("accounts.password." + name, "Credencial de " + name, status, "high",
                     description, "Bloqueie senhas desnecessárias ou redefina a credencial conforme a política de autenticação do sistema.",
                     {"user": name})
