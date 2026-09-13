"""Política do nOS: intenção explícita não é inferida de marcadores de sucesso."""

from copy import deepcopy
import os
import pwd
from pathlib import Path

from .collectors import Unavailable

TOR_MODES = {"tor", "killswitch-tor"}


def enabled(config):
    return config.get("nos", {}).get("enabled", False)


def target_user(context):
    if "nos.user" not in context.cache:
        name = context.config.get("nos", {}).get("target_user")
        try:
            entry = pwd.getpwnam(name) if name else pwd.getpwuid(os.geteuid())
            if not name and entry.pw_uid == 0:
                raise Unavailable("Execução root exige target_user explícito para auditar a identidade de usuário")
            context.cache["nos.user"] = {"name": entry.pw_name, "uid": entry.pw_uid, "home": entry.pw_dir,
                                         "runtime": f"/run/user/{entry.pw_uid}"}
        except KeyError:
            raise Unavailable("Usuário alvo não encontrado") from None
    return context.cache["nos.user"]


def expand_path(context, path):
    return str(Path(target_user(context)["home"]) / path[2:]) if path.startswith("~/") else path


def applicable(config, module):
    if not enabled(config):
        return True
    policy = config["nos"]
    if module == "tor_checks":
        return policy["expected_network_mode"] in TOR_MODES
    if module == "vpn_checks":
        return policy["expected_network_mode"] == "killswitch-vpn"
    if module == "vault_checks":
        return policy["vault"]
    if module == "installation_checks":
        return policy["environment"] == "installed"
    if module == "nostr_agent_checks":
        return policy["features"]["nostr_identity"]
    return True


def metadata(context):
    if not enabled(context.config):
        return None
    policy = context.config["nos"]
    # Lista fechada: não copiar configuração, caminhos, endpoints ou credenciais.
    data = {key: deepcopy(policy[key]) for key in ("environment", "expected_network_mode", "vault", "policy_version", "features")}
    try:
        from .key_patterns import safe_location
        values = {}
        for line in context.collector.read_text("/etc/os-release", limit=16384).splitlines():
            key, sep, value = line.partition("=")
            if sep and key in ("ID", "VERSION_ID", "BUILD_ID", "IMAGE_ID", "IMAGE_VERSION"):
                values[key] = safe_location(value.strip().strip('"'))
        data["os_release"] = values
    except Unavailable:
        data["os_release"] = None
    inventory = context.cache.get("packages.installed")
    if inventory is None:
        try:
            from .checks.package_integrity_checks import inventory as parse_inventory
            package_policy = context.config.get("package_integrity", {})
            inventory = parse_inventory(context.collector.command(["pacman", "--config", package_policy.get("pacman_conf", "/etc/pacman.conf"),
                                                                  "--dbpath", package_policy.get("db_path", "/var/lib/pacman"), "-Q"]))
        except Unavailable:
            inventory = None
    if inventory is not None:
        context.cache["packages.installed"] = inventory
    data["release_packages"] = {name: inventory.get(name) if inventory is not None else None for name in policy["release_packages"]}
    return data
