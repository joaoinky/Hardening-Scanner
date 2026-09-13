"""Validação das extensões opcionais específicas do Neovanguard."""

import re
from .config import absolute, integer, object_keys, require, strings


def validate_nos(config):
    if "execution" in config:
        p = config["execution"]
        object_keys(p, ["max_seconds", "max_output_bytes", "preset"], [], "execution")
        integer(p["max_seconds"], 1, 3600, "execution.max_seconds")
        integer(p["max_output_bytes"], 1024, 32 * 1024 * 1024, "execution.max_output_bytes")
        require(p["preset"] in ("quick", "full"), "execution.preset")
    if "nos" not in config:
        return
    p = config["nos"]
    object_keys(p, ["enabled", "environment", "expected_network_mode", "vault", "target_user", "policy_version", "features",
                    "network_library", "network_reference", "tor_uid", "vpn_interface", "vpn_endpoints",
                    "agent_unit", "agent_socket", "mounts", "journald", "live_artifacts", "live_services", "release_packages"], [], "nos")
    require(type(p["enabled"]) is bool and type(p["vault"]) is bool, "nos flags")
    require(p["environment"] in ("live", "install_media", "installed"), "nos.environment")
    require(p["expected_network_mode"] in ("base", "tor", "killswitch-tor", "killswitch-vpn", "airgap"), "nos.expected_network_mode")
    require(not p["vault"] or p["expected_network_mode"] == "airgap", "nos.vault exige airgap")
    require(p["target_user"] is None or (isinstance(p["target_user"], str) and re.fullmatch(r"[a-z_][a-z0-9_-]*[$]?", p["target_user"])), "nos.target_user")
    require(isinstance(p["policy_version"], str) and re.fullmatch(r"[a-zA-Z0-9._-]{1,64}", p["policy_version"]), "nos.policy_version")
    object_keys(p["features"], ["nostr_identity", "nostr_relay", "bitcoin"], [], "nos.features")
    require(all(type(v) is bool for v in p["features"].values()), "nos.features flags")
    for key in ("network_library", "network_reference"):
        absolute(p[key], "nos." + key)
    integer(p["tor_uid"], 1, 2**32-2, "nos.tor_uid")
    require(isinstance(p["vpn_interface"], str) and re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", p["vpn_interface"])
            and p["vpn_interface"] != "lo", "nos.vpn_interface")
    require(isinstance(p["vpn_endpoints"], list), "nos.vpn_endpoints")
    import ipaddress
    for endpoint in p["vpn_endpoints"]:
        require(isinstance(endpoint, list) and len(endpoint) == 2, "nos.vpn_endpoint")
        try:
            ipaddress.ip_address(endpoint[0])
        except (ValueError, TypeError):
            require(False, "nos.vpn_endpoint.ip")
        integer(endpoint[1], 1, 65535, "nos.vpn_endpoint.port")
    require(p["expected_network_mode"] != "killswitch-vpn" or bool(p["vpn_endpoints"]), "nos.vpn_endpoints obrigatórios no modo VPN")
    require(isinstance(p["agent_unit"], str) and re.fullmatch(r"[a-zA-Z0-9_.@:-]+\.service", p["agent_unit"]), "nos.agent_unit")
    # Nome relativo ao runtime, sem glob ou diretórios; o nome exato é configurável.
    require(p["agent_socket"] is None or (isinstance(p["agent_socket"], str) and re.fullmatch(r"[a-zA-Z0-9_.-]+", p["agent_socket"])), "nos.agent_socket")
    require(p["agent_socket"] not in (".", ".."), "nos.agent_socket")
    require(isinstance(p["mounts"], dict), "nos.mounts")
    for path, options in p["mounts"].items():
        absolute(path, "nos.mounts.path")
        strings(options, "nos.mounts.options")
        require(set(options) <= {"nosuid", "nodev", "noexec"}, "nos.mounts.options")
    require(isinstance(p["journald"], dict) and all(isinstance(k, str) and isinstance(v, str) for k,v in p["journald"].items()), "nos.journald")
    for key in ("live_artifacts", "live_services", "release_packages"):
        strings(p[key], "nos." + key)
    for path in p["live_artifacts"]:
        absolute(path, "nos.live_artifacts")

    require(all(re.fullmatch(r"[a-zA-Z0-9_.@:-]+\.service", unit) for unit in p["live_services"]), "nos.live_services")
    require(all(re.fullmatch(r"[A-Za-z0-9@._+:-]+", name) for name in p["release_packages"]), "nos.release_packages")
