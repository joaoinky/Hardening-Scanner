"""Host inteiramente sintético: testes não dependem de root, Tor ou systemd."""

import fnmatch
import os
from pathlib import Path
import stat

from nvg_scanner.collectors import Unavailable
from nvg_scanner.config import load_config

ROOT = Path(__file__).resolve().parents[1]


def config():
    policy = load_config(ROOT / "config/example.json", "installed")
    # Fixtures legadas representam configuração v1 sem novas seções opcionais.
    for section in ("firewall", "package_integrity", "key_exposure"):
        policy.pop(section, None)
    return policy


def metadata(mode=0o600, uid=1000, gid=1000, directory=False):
    return os.stat_result((mode | (stat.S_IFDIR if directory else stat.S_IFREG), 1, 1, 1, uid, gid, 0, 0, 0, 0))


class FakeCollector:
    def __init__(self, files=None, commands=None):
        self.files = files or {}
        self.commands = commands or {}
        self.metadata = {}
        self.attributes = {}
        self.targets = {}
        self.calls = []

    def read_text(self, path, **kwargs):
        self.calls.append(("read", str(path)))
        value = self.files.get(str(path), Unavailable("Arquivo não disponível na fixture"))
        if isinstance(value, Exception):
            raise value
        return value

    def command(self, args):
        self.calls.append(("command", tuple(args)))
        value = self.commands.get(tuple(args), self.commands.get(args[0], Unavailable("Comando não disponível na fixture")))
        if isinstance(value, Exception):
            raise value
        return value

    def lstat(self, path):
        value = self.metadata.get(str(path))
        if value is None:
            raise FileNotFoundError(str(path))
        if isinstance(value, Exception):
            raise value
        return value

    def stat(self, path):
        return self.lstat(self.targets.get(str(path), str(path)))

    def resolve(self, path):
        return Path(self.targets.get(str(path), str(path)))

    def xattrs(self, path):
        value = self.attributes.get(str(path), [])
        if isinstance(value, Exception):
            raise value
        return value

    def glob(self, pattern):
        return sorted(path for path in self.files if fnmatch.fnmatch(path, pattern))

    def is_dir(self, path):
        return str(path) in self.metadata and stat.S_ISDIR(self.metadata[str(path)].st_mode)


def synthetic_context():
    from nvg_scanner.collectors import Context
    policy = config()
    policy["permissions"]["sensitive_paths"] = [
        {"id": "nostr_demo", "path": "/vault/nostr.key", "kind": "file", "max_mode": "0600", "uid": 1000,
         "required": True, "allow_symlink": False, "severity": "critical"}
    ]
    files = {
        "/etc/tor/torrc": "SocksPort 127.0.0.1:9050\nSafeSocks 1\nControlPort 0\n",
        "/etc/resolv.conf": "nameserver 127.0.0.1\n",
        "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nnvg:x:1000:1000::/home/nvg:/bin/bash\n",
        "/etc/shadow": "root:!:19000:0:99999:7:::\nnvg::19000:0:99999:7:::\n",
        "/proc/123/status": "Name:\ttor\nUid:\t974\t974\t974\t974\n",
    }
    for key, rule in policy["kernel"].items():
        files["/proc/sys/" + key.replace(".", "/")] = str(rule["accepted"][0]) + "\n"
    fake = FakeCollector(files, {
        "ss": "tcp LISTEN 0 128 127.0.0.1:9050 0.0.0.0:*\ntcp LISTEN 0 128 0.0.0.0:8332 0.0.0.0:*\n",
        "systemctl": "LoadState=loaded\nActiveState=active\nMainPID=123\nUser=tor\nDynamicUser=no\n",
        ("systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--no-pager", "--plain", "--full"):
            "tor.service loaded active running Tor\n",
    })
    fake.metadata = {"/": metadata(0o755, 0, 0, True), "/vault": metadata(0o700, directory=True),
                     "/vault/nostr.key": metadata(0o644)}
    return Context(policy, fake)
