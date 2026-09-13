"""Política externa validada antes de qualquer auditoria."""

from copy import deepcopy
import ipaddress
import json
from pathlib import Path
import re

from .models import SEVERITIES


class ConfigError(ValueError):
    pass


def require(condition, location):
    if not condition:
        # Nunca reproduzir o valor: configuração pode conter caminhos privados.
        raise ConfigError(f"Configuração inválida em {location}")


def object_keys(value, required, optional, location):
    require(isinstance(value, dict), location)
    require(set(required) <= value.keys() <= set(required) | set(optional), location)


def strings(value, location):
    require(isinstance(value, list) and all(isinstance(x, str) and x for x in value), location)


def absolute(value, location):
    require(isinstance(value, str) and value.startswith("/") and "\x00" not in value
            and ".." not in Path(value).parts, location)


def integer(value, minimum, maximum, location):
    require(type(value) is int and minimum <= value <= maximum, location)


def merge(base, override):
    result = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge(result[key], value)
        else:
            # Listas são substituídas, nunca ampliadas silenciosamente.
            result[key] = deepcopy(value)
    return result


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "chave JSON duplicada")
        result[key] = value
    return result


def load_config(path, profile):
    try:
        with open(path, encoding="utf-8") as stream:
            document = json.load(stream, object_pairs_hook=no_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ConfigError("Não foi possível ler um arquivo JSON válido de configuração") from None
    object_keys(document, ["schema_version", "defaults", "profiles"], [], "documento")
    require(type(document["schema_version"]) is int and document["schema_version"] == 1, "schema_version")
    require(isinstance(document["defaults"], dict), "defaults")
    require(isinstance(document["profiles"], dict) and profile in document["profiles"], "profiles")
    require(isinstance(document["profiles"][profile], dict), "profiles selecionado")
    config = merge(document["defaults"], document["profiles"][profile])
    validate(config)
    config["profile"] = profile
    return config


def validate(config):
    object_keys(config, ["timeout_seconds", "weights", "network", "permissions", "tor",
                         "services", "kernel", "accounts"], ["extensions", "firewall", "package_integrity", "key_exposure", "nos", "execution"], "defaults/perfil")
    integer(config["timeout_seconds"], 1, 60, "timeout_seconds")
    object_keys(config["weights"], SEVERITIES, [], "weights")
    for severity, weight in config["weights"].items():
        integer(weight, 1, 1000, f"weights.{severity}")
    require(isinstance(config.get("extensions", {}), dict), "extensions")

    network = config["network"]
    object_keys(network, ["allowed_listeners"], [], "network")
    require(isinstance(network["allowed_listeners"], list), "network.allowed_listeners")
    for rule in network["allowed_listeners"]:
        object_keys(rule, ["protocol", "address", "port"], ["comment"], "listener")
        require(rule["protocol"] in ("tcp", "udp"), "listener.protocol")
        integer(rule["port"], 1, 65535, "listener.port")
        require(isinstance(rule["address"], str), "listener.address")
        if rule["address"] != "*":
            try:
                ipaddress.ip_network(rule["address"], strict=False)
            except ValueError:
                raise ConfigError("listener.address deve ser IP, CIDR ou *") from None

    permissions = config["permissions"]
    object_keys(permissions, ["sensitive_paths"], [], "permissions")
    require(isinstance(permissions["sensitive_paths"], list), "permissions.sensitive_paths")
    ids = set()
    for entry in permissions["sensitive_paths"]:
        object_keys(entry, ["id", "path", "kind", "max_mode", "uid", "required", "allow_symlink", "severity"],
                    ["gid", "feature"], "sensitive_path")
        require(isinstance(entry["id"], str) and re.fullmatch(r"[a-z0-9_-]+", entry["id"]), "sensitive_path.id")
        require(entry["id"] not in ids, "sensitive_path.id duplicado")
        ids.add(entry["id"])
        absolute("/" + entry["path"][2:] if isinstance(entry["path"], str) and entry["path"].startswith("~/") else entry["path"], "sensitive_path.path")
        if "feature" in entry:
            require(entry["feature"] in ("nostr_identity", "nostr_relay", "bitcoin"), "sensitive_path.feature")
        require(entry["kind"] in ("file", "directory"), "sensitive_path.kind")
        require(isinstance(entry["max_mode"], str) and re.fullmatch(r"0[0-7]{3}", entry["max_mode"]), "sensitive_path.max_mode")
        if entry["uid"] != "target":
            integer(entry["uid"], 0, 2**32 - 2, "sensitive_path.uid")
        if "gid" in entry:
            integer(entry["gid"], 0, 2**32 - 2, "sensitive_path.gid")
        require(type(entry["required"]) is bool and type(entry["allow_symlink"]) is bool, "sensitive_path flags")
        require(entry["severity"] in SEVERITIES, "sensitive_path.severity")

    tor = config["tor"]
    object_keys(tor, ["service", "torrc", "resolv_conf", "allowed_nameservers", "require_safe_socks"], [], "tor")
    require(isinstance(tor["service"], str) and re.fullmatch(r"[a-zA-Z0-9_.@:-]+\.service", tor["service"]), "tor.service")
    absolute(tor["torrc"], "tor.torrc")
    absolute(tor["resolv_conf"], "tor.resolv_conf")
    require(type(tor["require_safe_socks"]) is bool, "tor.require_safe_socks")
    strings(tor["allowed_nameservers"], "tor.allowed_nameservers")
    for address in tor["allowed_nameservers"]:
        try:
            ipaddress.ip_address(address)
        except ValueError:
            raise ConfigError("tor.allowed_nameservers deve conter IPs literais") from None

    services = config["services"]
    object_keys(services, ["allowed_root_services", "require_non_root"], [], "services")
    for key in services:
        strings(services[key], f"services.{key}")
    require(not set(services["allowed_root_services"]) & set(services["require_non_root"]), "services políticas conflitantes")

    require(isinstance(config["kernel"], dict) and config["kernel"], "kernel")
    for key, rule in config["kernel"].items():
        require(re.fullmatch(r"[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+", key) is not None, "kernel key")
        object_keys(rule, ["accepted", "severity", "why", "recommendation"], [], "kernel rule")
        require(isinstance(rule["accepted"], list) and rule["accepted"] and (all(type(x) is int for x in rule["accepted"]) or all(isinstance(x, str) and x for x in rule["accepted"])), "kernel.accepted")
        require(rule["severity"] in SEVERITIES, "kernel.severity")
        require(all(isinstance(rule[k], str) and rule[k] for k in ("why", "recommendation")), "kernel descrição")

    accounts = config["accounts"]
    object_keys(accounts, ["passwd_path", "shadow_path", "allowed_uid0", "allowed_interactive_users",
                           "non_login_shells", "legacy_hash_prefixes"], [], "accounts")
    for key in ("passwd_path", "shadow_path"):
        absolute(accounts[key], f"accounts.{key}")
    for key in ("allowed_uid0", "allowed_interactive_users", "non_login_shells", "legacy_hash_prefixes"):
        strings(accounts[key], f"accounts.{key}")
    require(all(x.startswith("$") and x.endswith("$") for x in accounts["legacy_hash_prefixes"]), "accounts.legacy_hash_prefixes")
    validate_optional(config)
    from .nos_config import validate_nos
    validate_nos(config)


def validate_optional(config):
    if "key_exposure" in config:
        import glob
        policy = config["key_exposure"]
        object_keys(policy, ["enabled", "home_dir", "paths", "max_file_bytes", "max_total_bytes", "max_files", "max_seconds", "max_directory_entries"], [], "key_exposure")
        require(type(policy["enabled"]) is bool, "key_exposure.enabled")
        if policy["home_dir"] is not None:
            absolute(policy["home_dir"], "key_exposure.home_dir")
        integer(policy["max_file_bytes"], 1, 1024 * 1024, "key_exposure.max_file_bytes")
        integer(policy["max_total_bytes"], 1, 8 * 1024 * 1024, "key_exposure.max_total_bytes")
        integer(policy["max_files"], 1, 64, "key_exposure.max_files")
        integer(policy["max_seconds"], 1, 30, "key_exposure.max_seconds")
        integer(policy["max_directory_entries"], 1, 1024, "key_exposure.max_directory_entries")
        require(isinstance(policy["paths"], list) and len(policy["paths"]) <= 64, "key_exposure.paths")
        ids = set()
        for entry in policy["paths"]:
            object_keys(entry, ["id", "path"], [], "key_exposure.path")
            require(isinstance(entry["id"], str) and re.fullmatch(r"[a-z0-9_-]{1,48}", entry["id"]), "key_exposure.path.id")
            require(entry["id"] not in ids and "nsec1" not in entry["id"], "key_exposure.path.id duplicado ou sensível")
            ids.add(entry["id"])
            value = entry["path"]
            require(isinstance(value, str), "key_exposure.path.path")
            absolute("/" + value[2:] if value.startswith("~/") else value, "key_exposure.path.path")
            require("**" not in value and not glob.has_magic(str(Path(value).parent)), "key_exposure.path sem recursão/glob nos pais")
    if "package_integrity" in config:
        policy = config["package_integrity"]
        object_keys(policy, ["enabled", "pacman_conf", "db_path", "keyring_dir", "cache_dirs", "max_packages"], ["priority_packages"], "package_integrity")
        require(type(policy["enabled"]) is bool, "package_integrity.enabled")
        for field in ("pacman_conf", "db_path", "keyring_dir"):
            absolute(policy[field], "package_integrity." + field)
        strings(policy["cache_dirs"], "package_integrity.cache_dirs")
        for path in policy["cache_dirs"]:
            absolute(path, "package_integrity.cache_dirs")
        strings(policy.get("priority_packages", []), "package_integrity.priority_packages")
        integer(policy["max_packages"], 1, 10000, "package_integrity.max_packages")
    if "firewall" in config:
        policy = config["firewall"]
        object_keys(policy, ["enabled", "require_default_deny", "require_ipv6", "accept_justifications"], ["backend"], "firewall")
        require(policy.get("backend", "generic") in ("generic", "nos"), "firewall.backend")
        require(policy.get("backend") != "nos" or config.get("nos", {}).get("enabled") is True, "firewall.backend exige nos")
        require(all(type(policy[k]) is bool for k in ("enabled", "require_default_deny", "require_ipv6")), "firewall flags")
        require(isinstance(policy["accept_justifications"], dict), "firewall.accept_justifications")
        for key, reason in policy["accept_justifications"].items():
            require(key in ("ip", "ip6") and isinstance(reason, str) and reason.strip(), "firewall.accept_justifications")
