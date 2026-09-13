"""Acesso local somente leitura; falhas não revelam conteúdo de arquivos/comandos."""

import glob
import os
from pathlib import Path
import shutil
import subprocess
import stat
import tempfile
import fnmatch
import selectors
import signal
import time
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass, field
from typing import Any


class Unavailable(Exception):
    """Evidência indisponível, nunca uma aprovação implícita."""


class Collector:
    def __init__(self, timeout=5):
        self.timeout = timeout
        self.deadline = float("inf")
        self.max_output_bytes = 8 * 1024 * 1024
        self._stack = None
        self._keyrings = {}

    def begin_scan(self, deadline, max_output_bytes):
        self.end_scan()
        self.deadline = deadline
        self.max_output_bytes = max_output_bytes
        self._stack = ExitStack()

    def end_scan(self):
        if self._stack is not None:
            self._stack.close()
        self._stack = None
        self._keyrings = {}

    def remaining(self):
        remaining = min(self.timeout, self.deadline - time.monotonic())
        if remaining <= 0:
            raise Unavailable("Orçamento global de tempo esgotado")
        return remaining

    def read_text(self, path, limit=2_000_000):
        self.remaining()
        try:
            # Symlinks de configuração (resolv.conf) são permitidos aqui;
            # conteúdo de chaves usa read_regular_bytes com O_NOFOLLOW.
            descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise Unavailable("Configuração não é arquivo regular/procfs")
                value = stream.read(limit + 1)
            if len(value) > limit:
                raise Unavailable("Arquivo excede o limite de leitura")
            return value.decode("utf-8", errors="strict")
        except (OSError, UnicodeError) as error:
            raise Unavailable(f"Leitura indisponível ({type(error).__name__})") from None

    def command(self, args):
        code, output = self.command_status(args)
        if code:
            raise Unavailable(f"{args[0]} retornou código {code}")
        return output

    def command_status(self, args):
        """Retorno estruturado permite distinguir assinatura inválida de coleta ausente."""
        # PATH fixo evita executar um binário colocado no diretório do projeto.
        executable = shutil.which(args[0], path="/usr/sbin:/usr/bin:/sbin:/bin")
        if executable is None:
            raise Unavailable(f"Ferramenta ausente: {args[0]}")
        deadline = time.monotonic() + self.remaining()
        proc = None
        try:
            # stderr é descartado sem armazenamento; stdout é lido em blocos
            # limitados. Um filho não pode manter o scanner preso com pipes abertos.
            proc = subprocess.Popen(
                [executable, *args[1:]], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
                stdin=subprocess.DEVNULL, start_new_session=True,
            )
            chunks, size = [], 0
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise Unavailable("Consulta excedeu limite de tempo")
                    for key, _ in selector.select(min(remaining, 0.1)):
                        block = os.read(key.fileobj.fileno(), min(65536, self.max_output_bytes - size + 1))
                        if not block:
                            selector.unregister(key.fileobj)
                            continue
                        size += len(block)
                        if size > self.max_output_bytes:
                            raise Unavailable("Saída da consulta excedeu limite de bytes; evidência descartada")
                        chunks.append(block)
            code = proc.wait(timeout=max(0.001, deadline - time.monotonic()))
            return code, b"".join(chunks).decode("utf-8", errors="replace")
        except (OSError, subprocess.TimeoutExpired):
            raise Unavailable("Consulta local indisponível ou fora do limite de tempo") from None
        finally:
            if proc is not None:
                if proc.returncode is None:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                proc.wait()
                proc.stdout.close()

    def read_regular_bytes(self, path, limit):
        """Não segue symlinks no componente final, não abre FIFO/dispositivo para leitura.

        O_NONBLOCK evita bloquear no open de FIFO e fstat confirma o objeto aberto.
        O limite usa bytes, incluindo arquivos que crescem durante a leitura.
        """
        self.remaining()
        descriptor = None
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise Unavailable("O alvo não é arquivo regular")
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = None
                data = stream.read(limit + 1)
                final = os.fstat(stream.fileno())
            changed = (metadata.st_size, metadata.st_mtime_ns) != (final.st_size, final.st_mtime_ns)
            return data[:limit], len(data) > limit or changed
        except OSError as error:
            raise Unavailable(f"Arquivo não lido ({type(error).__name__})") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _prepare_keyring(self, keyring, directory):
        copied = False
        for name in ("pubring.gpg", "pubring.kbx", "trustdb.gpg"):
            source = Path(keyring) / name
            try:
                self.lstat(source)
            except FileNotFoundError:
                continue
            data, partial = self.read_regular_bytes(source, 64 * 1024 * 1024)
            if partial:
                raise Unavailable("Keyring excede limite ou mudou durante a leitura")
            target = Path(directory) / name
            target.write_bytes(data)
            target.chmod(0o600)
            copied |= name.startswith("pubring.")
        if not copied or not (Path(directory) / "trustdb.gpg").exists():
            raise Unavailable("Keyring público/trustdb indisponível; keyboxd não suportado")

    @contextmanager
    def keyring_session(self, keyring):
        # Somente durante este scan; nunca reutilizar confiança entre execuções.
        if self._stack is not None:
            key = str(keyring)
            if key not in self._keyrings:
                directory = self._stack.enter_context(tempfile.TemporaryDirectory(prefix="nvg-gpg-"))
                self._prepare_keyring(keyring, directory)
                self._keyrings[key] = directory
            yield self._keyrings[key]
        else:
            with tempfile.TemporaryDirectory(prefix="nvg-gpg-") as directory:
                self._prepare_keyring(keyring, directory)
                yield directory

    def verify_package(self, archive, signature, keyring):
        """Reutiliza snapshot privado de chaves PÚBLICAS; não escreve no host."""
        with self.keyring_session(keyring) as directory:
            data, partial = self.read_regular_bytes(signature, 1024 * 1024)
            if partial:
                raise Unavailable("Assinatura excede limite ou mudou durante a leitura")
            sig = Path(directory) / "package.sig"
            sig.write_bytes(data)
            try:
                return self.command_status([
                    "gpg", "--no-options", "--homedir", directory, "--batch", "--no-tty",
                    "--no-auto-key-retrieve", "--no-auto-key-import", "--auto-key-locate", "clear",
                    "--disable-dirmngr", "--no-autostart", "--no-auto-check-trustdb",
                    "--status-fd", "1", "--verify", str(sig), str(archive),
                ])
            finally:
                sig.unlink(missing_ok=True)

    def lstat(self, path):
        return os.lstat(path)

    def stat(self, path):
        return os.stat(path)

    def resolve(self, path):
        return Path(path).resolve(strict=True)

    def xattrs(self, path):
        return os.listxattr(path)

    def glob(self, pattern):
        return sorted(glob.glob(pattern))

    def select_files(self, pattern, max_entries):
        """Glob somente no nome final, sem recursão nem enumeração ilimitada."""
        path = Path(pattern)
        if not glob.has_magic(path.name):
            return [str(path)], False
        if glob.has_magic(str(path.parent)) or "**" in path.name:
            raise Unavailable("Padrão recursivo não permitido")
        selected, partial = [], False
        with os.scandir(path.parent) as entries:
            for count, entry in enumerate(entries):
                if count >= max_entries:
                    partial = True
                    break
                if fnmatch.fnmatchcase(entry.name, path.name):
                    selected.append(entry.path)
        return sorted(selected), partial

    def is_dir(self, path):
        return Path(path).is_dir()


@dataclass
class Context:
    config: dict[str, Any]
    collector: Collector = field(default_factory=Collector)
    cache: dict[str, Any] = field(default_factory=dict)


def service_properties(context, unit):
    key = "service:" + unit
    if key not in context.cache:
        output = context.collector.command([
            "systemctl", "show", "--no-pager",
            "--property=LoadState,ActiveState,MainPID,User,DynamicUser", "--", unit,
        ])
        context.cache[key] = dict(
            line.split("=", 1) for line in output.splitlines() if "=" in line
        )
    return context.cache[key]


def batch_services(context, units):
    """Lotes pequenos limitam argv; cache dura somente o snapshot corrente."""
    ordered = sorted(units)
    for start in range(0, len(ordered), 64):
        batch = ordered[start:start + 64]
        output = context.collector.command([
            "systemctl", "show", "--no-pager",
            "--property=Id,LoadState,ActiveState,MainPID,User,DynamicUser", "--", *batch,
        ])
        parsed = {}
        for block in output.strip().split("\n\n"):
            props = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
            unit = props.get("Id")
            if unit not in batch or unit in parsed or not {"LoadState", "ActiveState", "MainPID"} <= props.keys():
                raise Unavailable("Lote systemd não interpretado integralmente")
            parsed[unit] = props
        if set(parsed) != set(batch):
            raise Unavailable("Lote systemd incompleto")
        context.cache.update({"service:" + unit: props for unit, props in parsed.items()})
