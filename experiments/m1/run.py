"""Small, fail-closed coordinator for the M1 remote qualification."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
import shlex
import stat
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_NODE_KEYS = {"name", "ssh", "instance_id", "provider_label", "address", "host_key", "hostname"}
_SAFE = re.compile(r"^[A-Za-z0-9._-]+$")
_DNS = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
_RUN_ID = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{10}$")
_FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
_SECRET = re.compile(
    r"(password|passwd|secret|token|authorization|private.?key|credential|access.?key|session|cookie)", re.I
)
SSH_TIMEOUT = 60
_SSH_KNOWN_HOSTS: Path | None = None
_REMOTE_ROOT: str | None = None
_FRESH_LOCAL_ROOTS: set[str] = set()
_LOADED_SECRET_VALUES: set[str] = set()


@dataclass(frozen=True)
class Node:
    name: str
    ssh: str
    instance_id: int
    provider_label: str
    address: str
    host_key: str
    hostname: str = ""

    def __post_init__(self) -> None:
        # Keep direct unit-test construction safe; persisted inventories must declare it.
        if not self.hostname:
            object.__setattr__(self, "hostname", self.address)


@dataclass(frozen=True)
class RunContext:
    run_id: str
    local_root: Path
    remote_root: str


def _absolute_no_symlinks(path: Path) -> Path:
    """Canonicalize trusted OS aliases, then reject symlink or unsafe ancestors."""
    path = Path(path).expanduser()
    absolute = Path(os.path.abspath(path))
    for alias, target in ((Path("/tmp"), Path("/private/tmp")), (Path("/var"), Path("/private/var"))):
        if alias.is_symlink():
            try:
                absolute = target / absolute.relative_to(alias)
            except ValueError:
                pass
            else:
                break
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise ValueError(f"symlink path component: {current}")
        if current.exists():
            st = current.stat()
            trusted_sticky = stat.S_ISDIR(st.st_mode) and bool(st.st_mode & stat.S_ISVTX)
            if st.st_uid not in (0, os.getuid()) or ((st.st_mode & 0o022) and not trusted_sticky):
                raise ValueError(f"unsafe path ancestor: {current}")
    return absolute


def _outside_repository(path: Path, repository: Path | None) -> None:
    if repository is None:
        return
    repo = _absolute_no_symlinks(repository)
    candidate = _absolute_no_symlinks(path)
    try:
        candidate.relative_to(repo)
    except ValueError:
        return
    raise ValueError("path must be outside repository")


def _require_private_directory(path: Path, label: str) -> None:
    st = path.stat()
    if not path.is_dir() or path.is_symlink() or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
        raise ValueError(f"{label} must be an owned directory with exact mode 0700")


def require_private_file(path: Path, repository: Path | None = None) -> None:
    path = _absolute_no_symlinks(path)
    _outside_repository(path, repository)
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"private file required: {path}")
    st = path.stat()
    if st.st_uid != os.getuid():
        raise ValueError("private file is not owned by current user")
    if stat.S_IMODE(st.st_mode) != 0o600:
        raise ValueError("private file must have mode 0600")
    _require_private_directory(path.parent, "private file parent")


def _valid_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or not _SAFE.fullmatch(value):
        raise ValueError(f"invalid {field}")
    return value


def _valid_endpoint(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DNS.fullmatch(value):
        raise ValueError(f"invalid {field}")
    return value


def validate_inventory(value: dict[str, Any]) -> list[Node]:
    if not isinstance(value, dict) or set(value) != {"nodes"} or not isinstance(value["nodes"], list):
        raise ValueError("inventory must contain only nodes")
    if len(value["nodes"]) != 3:
        raise ValueError("exactly three nodes are required")
    nodes: list[Node] = []
    for raw in value["nodes"]:
        if not isinstance(raw, dict) or set(raw) != _NODE_KEYS:
            raise ValueError("node has unexpected keys")
        name = _valid_text(raw["name"], "name")
        ssh_name = raw["ssh"]
        if not isinstance(ssh_name, str) or not ssh_name.startswith("root@"):
            raise ValueError("SSH user must be root")
        address = _valid_endpoint(raw["address"], "address")
        match = re.fullmatch(r"root@([A-Za-z0-9.-]+)", ssh_name)
        if not match or match.group(1) != address:
            raise ValueError("SSH target must be root@address")
        host_key = raw["host_key"]
        if not isinstance(host_key, str) or not _FINGERPRINT.fullmatch(host_key):
            raise ValueError("invalid host key fingerprint")
        if not isinstance(raw["instance_id"], int) or isinstance(raw["instance_id"], bool) or raw["instance_id"] <= 0:
            raise ValueError("invalid instance ID")
        hostname = _valid_endpoint(raw["hostname"], "hostname")
        nodes.append(Node(name, ssh_name, raw["instance_id"], _valid_text(raw["provider_label"], "provider label"), address, host_key, hostname))
    if {node.name for node in nodes} != {"fm1", "fm2", "fm3"}:
        raise ValueError("inventory names must be exactly fm1, fm2, and fm3")
    for field in ("name", "ssh", "instance_id", "provider_label", "address", "host_key"):
        vals = [getattr(n, field) for n in nodes]
        if len(set(vals)) != len(vals):
            raise ValueError(f"duplicate node {field}")
    return nodes


def load_inventory(path: Path, repository: Path | None = None) -> list[Node]:
    require_private_file(path, repository)
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid inventory") from exc
    return validate_inventory(value)


def new_run_context(work_root: Path, repository: Path | None = None) -> RunContext:
    work_root = _absolute_no_symlinks(work_root)
    _outside_repository(work_root, repository)
    if work_root.exists():
        existing = work_root.stat()
        if not work_root.is_dir() or existing.st_uid != os.getuid() or stat.S_IMODE(existing.st_mode) != 0o700:
            raise ValueError("work root must be an owned private directory")
    work_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if work_root.is_symlink() or work_root.stat().st_uid != os.getuid() or stat.S_IMODE(work_root.stat().st_mode) != 0o700:
        raise ValueError("work root must be private and non-symlink")
    work_root.chmod(0o700)
    while True:
        run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:10]
        local = work_root / run_id
        try:
            local.mkdir(mode=0o700)
            break
        except FileExistsError:
            continue
    context = RunContext(run_id, local, f"/var/lib/hat-qualification/{run_id}")
    _FRESH_LOCAL_ROOTS.add(str(local))
    return context


def _context_root(context: RunContext) -> str:
    expected = f"/var/lib/hat-qualification/{context.run_id}"
    if not _RUN_ID.fullmatch(context.run_id) or context.remote_root != expected:
        raise ValueError("unsafe or stale remote run root")
    return expected


def _stdout(result: subprocess.CompletedProcess) -> str:
    value = result.stdout
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value or ""


def _host_key_line(address: str, stdout: str) -> tuple[str, str]:
    lines = [line.strip() for line in stdout.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if len(lines) != 1:
        raise RuntimeError(f"expected exactly one host key for {address}")
    fields = lines[0].split()
    if len(fields) != 3 or fields[0] not in {address, f"[{address}]:22"} or fields[1] != "ssh-ed25519":
        raise RuntimeError(f"invalid host key for {address}")
    return fields[1], lines[0]


def _known_host_fingerprint(address: str) -> tuple[str, str]:
    result = subprocess.run(
        ["ssh-keyscan", "-T", "10", "-t", "ed25519", address],
        capture_output=True, text=True, check=False, timeout=SSH_TIMEOUT,
    )
    if result.returncode:
        raise RuntimeError(f"cannot collect host key for {address}")
    _, line = _host_key_line(address, result.stdout)
    with tempfile.TemporaryDirectory() as directory:
        key = Path(directory) / "key"
        key.write_text(line + "\n", encoding="ascii")
        output = subprocess.run(
            ["ssh-keygen", "-lf", str(key), "-E", "sha256"],
            capture_output=True, text=True, check=False, timeout=SSH_TIMEOUT,
        )
    if output.returncode:
        raise RuntimeError(f"cannot fingerprint host key for {address}")
    fields = output.stdout.split()
    if len(fields) < 2 or not _FINGERPRINT.fullmatch(fields[1]):
        raise RuntimeError(f"invalid host-key fingerprint for {address}")
    return fields[1], line


def build_pinned_known_hosts(nodes: list[Node], directory: Path) -> Path:
    """Create a fresh, mode-0600 known_hosts containing only inventory keys."""
    directory = _absolute_no_symlinks(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    _require_private_directory(directory, "known-host directory")
    path = directory / "known_hosts"
    try:
        with path.open("x", encoding="ascii") as stream:
            for node in nodes:
                fingerprint, line = _known_host_fingerprint(node.address)
                if fingerprint != node.host_key:
                    raise RuntimeError(f"host key mismatch for {node.name}")
                stream.write(line + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        path.chmod(0o600)
        return path
    except Exception:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def _remote_stat(node: Node, path: str) -> tuple[str, int, int, int, str]:
    _validate_node_fields(node)
    result = ssh(node, ["stat", "-c", "%F %u %g %a %n", "--", path], check=False)
    if result.returncode:
        raise RuntimeError(f"remote path does not exist: {path}")
    fields = _stdout(result).strip().split(" ", 4)
    if len(fields) != 5:
        raise RuntimeError(f"invalid remote path metadata: {path}")
    try:
        return fields[0], int(fields[1]), int(fields[2]), int(fields[3], 8), fields[4]
    except ValueError as exc:
        raise RuntimeError(f"invalid remote path metadata: {path}") from exc


def _verify_remote_directory(node: Node, path: str, *, mode: int | None = None) -> None:
    _validate_node_fields(node)
    kind, uid, gid, actual_mode, name = _remote_stat(node, path)
    if kind != "directory" or uid != 0 or gid != 0 or name != path or (actual_mode & 0o022):
        raise RuntimeError(f"remote directory is not trusted: {path}")
    if mode is not None and actual_mode != mode:
        raise RuntimeError(f"remote directory has unsafe mode: {path}")
    real = ssh(node, ["realpath", "-e", "--", path], check=False)
    if real.returncode or _stdout(real).strip() != path:
        raise RuntimeError(f"remote directory is not a real path: {path}")


def ensure_remote_root(node: Node, context: RunContext) -> None:
    global _REMOTE_ROOT
    root = _context_root(context)
    base = "/var/lib/hat-qualification"
    _verify_remote_directory(node, "/var")
    _verify_remote_directory(node, "/var/lib")
    base_result = ssh(node, ["stat", "-c", "%F %u %g %a %n", "--", base], check=False)
    if base_result.returncode:
        # Only an absent path may be bootstrapped; a dangling link is not absent.
        absent = ssh(node, ["test", "!", "-e", base], check=False)
        dangling = ssh(node, ["test", "!", "-L", base], check=False)
        if absent.returncode or dangling.returncode:
            raise RuntimeError("remote qualification base is missing or unsafe")
        created_base = ssh(node, ["mkdir", "-m", "700", "--", base], check=False)
        if created_base.returncode:
            raise RuntimeError("cannot create remote qualification base")
    _verify_remote_directory(node, base, mode=0o700)
    exists = ssh(node, ["test", "!", "-e", root], check=False)
    dangling = ssh(node, ["test", "!", "-L", root], check=False)
    if exists.returncode or dangling.returncode:
        raise RuntimeError("remote run root already exists")
    created = False
    try:
        result = ssh(node, ["mkdir", "-m", "700", "--", root], check=False)
        if result.returncode:
            raise RuntimeError("cannot create fresh remote run root")
        created = True
        kind, uid, gid, mode, name = _remote_stat(node, root)
        if kind != "directory" or uid != 0 or gid != 0 or mode != 0o700 or name != root:
            raise RuntimeError("remote root ownership, mode, or path is unsafe")
        _REMOTE_ROOT = root
    except Exception:
        if created:
            ssh(node, ["rmdir", "--", root], check=False)
        raise


def _transport_options() -> list[str]:
    if _SSH_KNOWN_HOSTS is None:
        raise RuntimeError("SSH pinning context is not initialized")
    return [
        "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={_SSH_KNOWN_HOSTS}",
    ]


def ssh(node: Node, argv: list[str], input: bytes | None = None, *, check: bool = True) -> subprocess.CompletedProcess:
    _validate_node_fields(node)
    if not argv:
        raise ValueError("remote command cannot be empty")
    command = " ".join(shlex.quote(str(arg)) for arg in argv)
    return subprocess.run(
        ["ssh", *_transport_options(), "--", node.ssh, command],
        input=input, capture_output=True, check=check, timeout=SSH_TIMEOUT,
    )


def _remote_destination(destination: str) -> tuple[str, str]:
    if _REMOTE_ROOT is None or not isinstance(destination, str) or not destination.startswith(_REMOTE_ROOT + "/"):
        raise RuntimeError("SCP destination is outside pinned remote run root")
    normalized = posixpath.normpath(destination)
    if normalized != destination or "\\" in destination or normalized == _REMOTE_ROOT:
        raise RuntimeError("SCP destination is outside pinned remote run root")
    parent = posixpath.dirname(normalized)
    if not parent.startswith(_REMOTE_ROOT + "/") and parent != _REMOTE_ROOT:
        raise RuntimeError("SCP destination is outside pinned remote run root")
    return normalized, parent


_REMOTE_FINALIZE_SCRIPT = r'''import os, sys
root, temporary, destination = sys.argv[1:]
if not temporary.startswith(root + "/") or not destination.startswith(root + "/"):
    raise SystemExit("path outside root")
def parts(path):
    value = path[len(root) + 1:].split("/")
    if not value or any(not p or p in (".", "..") for p in value):
        raise SystemExit("invalid path")
    return value
flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
def trusted(fd):
    st = os.fstat(fd)
    if st.st_uid != 0 or st.st_gid != 0 or (st.st_mode & 0o777) != 0o700:
        raise SystemExit("untrusted directory")
def open_parent(path):
    fd = os.open(root, flags); trusted(fd)
    for part in parts(path)[:-1]:
        child = os.open(part, flags, dir_fd=fd); trusted(child); os.close(fd); fd = child
    return fd
parent = open_parent(destination)
try:
    temporary_name = parts(temporary)[-1]
    destination_name = parts(destination)[-1]
    os.stat(temporary_name, dir_fd=parent, follow_symlinks=False)
    temporary_fd = os.open(temporary_name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
    try:
        os.fsync(temporary_fd)
    finally:
        os.close(temporary_fd)
    os.link(temporary_name, destination_name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
    os.unlink(temporary_name, dir_fd=parent)
    os.fsync(parent)
finally:
    os.close(parent)
'''


def scp_to(node: Node, source: Path, destination: str, *, check: bool = True, repository: Path | None = None) -> subprocess.CompletedProcess:
    _validate_node_fields(node)
    source = _absolute_no_symlinks(source)
    _outside_repository(source, repository)
    if not source.is_file() or source.is_symlink():
        raise ValueError("source must be a regular file")
    destination, parent = _remote_destination(destination)
    temporary = parent + "/." + posixpath.basename(destination) + ".hat-copy-" + uuid.uuid4().hex
    result = subprocess.run(
        ["scp", *_transport_options(), "--", str(source), f"{node.ssh}:{temporary}"],
        capture_output=True, check=False, timeout=SSH_TIMEOUT,
    )
    if not isinstance(result.returncode, int) or result.returncode == 0:
        result = ssh(node, ["python3", "-c", _REMOTE_FINALIZE_SCRIPT, _REMOTE_ROOT, temporary, destination], check=False)
    if isinstance(result.returncode, int) and result.returncode:
        ssh(node, ["rm", "-f", "--", temporary], check=False)
        if check:
            raise subprocess.CalledProcessError(result.returncode, ["scp", node.ssh], result.stdout, result.stderr)
    return result


def register_secret(value: str) -> None:
    if value:
        _LOADED_SECRET_VALUES.add(value)


def redact(value: Any) -> Any:
    if isinstance(value, str):
        for secret in sorted(_LOADED_SECRET_VALUES, key=len, reverse=True):
            value = value.replace(secret, "[REDACTED]")
        return value
    if isinstance(value, dict):
        return {key: "[REDACTED]" if _SECRET.search(str(key)) else redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    return value


def append_evidence(path: Path, event: dict[str, Any], repository: Path | None = None) -> None:
    path = _absolute_no_symlinks(path)
    _outside_repository(path, repository)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _require_private_directory(path.parent, "evidence parent")
    if path.exists():
        file_st = path.stat()
        if not path.is_file() or file_st.st_uid != os.getuid() or stat.S_IMODE(file_st.st_mode) != 0o600:
            raise ValueError("evidence file is not private")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as stream:
            fd = -1
            stream.write(json.dumps(redact(event), sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if fd >= 0:
            os.close(fd)


def _require_facts(node: Node, facts: dict[str, str]) -> None:
    required = {"hostname", "release", "boot_id", "memory", "disk", "cpu", "time_sync", "outbound_tls"}
    if not required.issubset(facts):
        raise RuntimeError(f"incomplete facts for {node.name}")
    if not node.hostname or facts["hostname"].strip() != node.hostname:
        raise RuntimeError(f"hostname mismatch for {node.name}")
    release = facts["release"]
    ubuntu_ids = re.findall(r"(?m)^ID=([^\n]*)$", release)
    versions = re.findall(r'(?m)^VERSION_ID="?([^"\n]+)"?\s*$', release)
    if ubuntu_ids != ["ubuntu"] or versions != ["24.04"]:
        raise RuntimeError(f"unsupported Ubuntu release for {node.name}")
    boot_id = facts["boot_id"].strip()
    if not re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", boot_id):
        raise RuntimeError(f"invalid boot ID for {node.name}")
    memory_rows = re.findall(r"(?m)^MemTotal:\s+(\d+)\s+kB\s*$", facts["memory"])
    memory = memory_rows[0] if len(memory_rows) == 1 else None
    cpu = facts["cpu"].strip()
    if not re.fullmatch(r"[1-9][0-9]*", cpu) or int(cpu) < 1 or not memory or int(memory) < 512000:
        raise RuntimeError(f"insufficient resources for {node.name}")
    disk_lines = facts["disk"].splitlines()
    expected_header = "Filesystem 1024-blocks Used Available Capacity Mounted on"
    if len(disk_lines) != 2 or disk_lines[0].split() != expected_header.split():
        raise RuntimeError(f"invalid or full disk report for {node.name}")
    disk_row = disk_lines[1].split()
    if len(disk_row) != 6 or disk_row[5] != "/" or any(not re.fullmatch(r"[0-9]+", disk_row[i]) for i in (1, 2, 3)):
        raise RuntimeError(f"invalid or full disk report for {node.name}")
    if int(disk_row[2]) > int(disk_row[1]) or int(disk_row[3]) > int(disk_row[1]) or not re.fullmatch(r"(?:[0-9]|[1-8][0-9]|90)%", disk_row[4]):
        raise RuntimeError(f"invalid or full disk report for {node.name}")
    if not re.fullmatch(r"NTPSynchronized=yes\n?", facts["time_sync"]):
        raise RuntimeError(f"time is not synchronized for {node.name}")
    if facts["outbound_tls"].strip() != "HAT_M1_TLS_OK":
        raise RuntimeError(f"outbound TLS failed for {node.name}")


def load_linode_env(path: Path, nodes: list[Node] | None = None, repository: Path | None = None) -> dict[str, int]:
    """Strictly parse the four-line credential file without returning its token."""
    require_private_file(path, repository)
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError("linode env is unreadable") from exc
    if len(lines) != 4 or any(not line for line in lines):
        raise ValueError("linode env must contain exactly token and three IDs")
    ids: dict[str, int] = {}
    token_seen = False
    for line in lines:
        token = re.fullmatch(r"export LINODE_TOKEN=(?:'([^'\n]+)'|\"([^\"\n]+)\"|([^\s]+))", line)
        ident = re.fullmatch(r"export (HAT_FM[123]_LINODE_ID)=(['\"]?)(\d+)\2", line)
        if token:
            if token_seen:
                raise ValueError("duplicate Linode token")
            register_secret(next(group for group in token.groups() if group is not None))
            token_seen = True
        elif ident:
            key = ident.group(1)
            if key in ids or int(ident.group(3)) <= 0:
                raise ValueError("duplicate or invalid Linode ID")
            ids[key] = int(ident.group(3))
        else:
            raise ValueError("linode env contains malformed entries")
    if not token_seen or set(ids) != {f"HAT_FM{i}_LINODE_ID" for i in range(1, 4)}:
        raise ValueError("linode env must contain exactly token and three IDs")
    if nodes is not None:
        if {node.name for node in nodes} != {"fm1", "fm2", "fm3"}:
            raise ValueError("inventory names must map to fm1, fm2, and fm3")
        for node in nodes:
            slot = node.name[2:]
            if ids[f"HAT_FM{slot}_LINODE_ID"] != node.instance_id:
                raise ValueError("Linode IDs do not match inventory")
    return ids


def _validate_node_fields(node: Node) -> None:
    if not isinstance(node, Node):
        raise ValueError("invalid node")
    _valid_text(node.name, "name")
    _valid_endpoint(node.address, "address")
    _valid_text(node.provider_label, "provider label")
    _valid_endpoint(node.hostname, "hostname")
    if not isinstance(node.ssh, str) or re.fullmatch(r"root@([A-Za-z0-9.-]+)", node.ssh) is None:
        raise ValueError("SSH user must be root")
    if node.ssh != f"root@{node.address}":
        raise ValueError("SSH target must be root@address")
    if not isinstance(node.host_key, str) or not _FINGERPRINT.fullmatch(node.host_key):
        raise ValueError("invalid host key fingerprint")
    if not isinstance(node.instance_id, int) or isinstance(node.instance_id, bool) or node.instance_id <= 0:
        raise ValueError("invalid instance ID")


def _validate_nodes(nodes: list[Node]) -> None:
    if not isinstance(nodes, list) or len(nodes) != 3 or any(not isinstance(node, Node) for node in nodes):
        raise ValueError("nodes must be exactly three Node values")
    for node in nodes:
        _validate_node_fields(node)
    if {node.name for node in nodes} != {"fm1", "fm2", "fm3"}:
        raise ValueError("nodes must be exactly fm1, fm2, and fm3")
    for field in ("name", "ssh", "instance_id", "provider_label", "address", "host_key"):
        values = [getattr(node, field) for node in nodes]
        if len(set(values)) != 3:
            raise ValueError(f"duplicate node {field}")


def _validate_prerequisites(nodes: list[Node], inventory_path: Path | None, linode_env: Path | None, repository: Path | None) -> None:
    _validate_nodes(nodes)
    if inventory_path is None or linode_env is None:
        raise ValueError("private inventory and Linode env are required")
    expected = load_inventory(inventory_path, repository)
    if expected != nodes:
        raise ValueError("nodes do not match private inventory")
    load_linode_env(linode_env, nodes, repository)


def _validate_local_context(context: RunContext, repository: Path | None = None) -> Path:
    local_root = _absolute_no_symlinks(context.local_root)
    _outside_repository(local_root, repository or Path(__file__).resolve().parents[2])
    if str(local_root) not in _FRESH_LOCAL_ROOTS or local_root.name != context.run_id:
        raise ValueError("local root was not freshly created by new_run_context")
    st = local_root.stat()
    if not local_root.is_dir() or local_root.is_symlink() or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
        raise ValueError("local root must be a private non-symlink directory")
    parent = local_root.parent
    pst = parent.stat()
    if parent.is_symlink() or pst.st_uid != os.getuid() or stat.S_IMODE(pst.st_mode) != 0o700:
        raise ValueError("local root parent must be private")
    return local_root


def _validate_evidence_path(evidence: Path, local_root: Path, repository: Path | None = None) -> Path:
    evidence = _absolute_no_symlinks(evidence)
    _outside_repository(evidence, repository or Path(__file__).resolve().parents[2])
    try:
        evidence.relative_to(local_root)
    except ValueError as exc:
        raise ValueError("evidence must be below the fresh local root") from exc
    return evidence


def _preflight_marker(context: RunContext) -> Path:
    return context.local_root / ".preflight-ok"


def _write_preflight_marker(context: RunContext) -> None:
    marker = _preflight_marker(context)
    fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, (context.run_id + "\n").encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)


def _require_preflight_marker(context: RunContext) -> None:
    marker = _preflight_marker(context)
    if marker.is_symlink() or not marker.is_file():
        raise ValueError("successful preflight marker is required")
    st = marker.stat()
    if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o600 or marker.read_text(encoding="ascii") != context.run_id + "\n":
        raise ValueError("invalid successful preflight marker")


def _credential_digest(path: Path) -> str:
    return hashlib.sha256(_absolute_no_symlinks(path).read_bytes()).hexdigest()


def _write_preflight_handoff(context: RunContext, inventory_path: Path, linode_env: Path) -> None:
    handoff = context.local_root / ".preflight-handoff"
    payload = {
        "run_id": context.run_id,
        "inventory_identity": str(_absolute_no_symlinks(inventory_path)),
        "inventory_sha256": _credential_digest(inventory_path),
        "linode_env_identity": str(_absolute_no_symlinks(linode_env)),
        "linode_env_sha256": _credential_digest(linode_env),
    }
    fd = os.open(handoff, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, (json.dumps(payload, sort_keys=True) + "\n").encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)


def _consume_preflight_handoff(context: RunContext, inventory_path: Path, linode_env: Path) -> None:
    handoff = context.local_root / ".preflight-handoff"
    if handoff.is_symlink() or not handoff.is_file():
        raise ValueError("one-time preflight handoff is required")
    st = handoff.stat()
    if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o600:
        raise ValueError("invalid preflight handoff")
    try:
        payload = json.loads(handoff.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid preflight handoff") from exc
    expected = {
        "run_id": context.run_id,
        "inventory_identity": str(_absolute_no_symlinks(inventory_path)),
        "inventory_sha256": _credential_digest(inventory_path),
        "linode_env_identity": str(_absolute_no_symlinks(linode_env)),
        "linode_env_sha256": _credential_digest(linode_env),
    }
    if payload != expected:
        raise ValueError("preflight handoff does not match credentials")
    consumed = context.local_root / ".preflight-handoff.used"
    if consumed.exists() or consumed.is_symlink():
        raise ValueError("preflight handoff was already consumed")
    try:
        os.link(handoff, consumed, follow_symlinks=False)
        os.unlink(handoff)
    except Exception as exc:
        try:
            consumed.unlink()
        except FileNotFoundError:
            pass
        raise ValueError("could not atomically consume preflight handoff") from exc


def _preflight_impl(nodes: list[Node], context: RunContext, evidence: Path, repository: Path | None = None, inventory_path: Path | None = None, linode_env: Path | None = None) -> None:
    global _SSH_KNOWN_HOSTS
    _validate_prerequisites(nodes, inventory_path, linode_env, repository)
    local_root = _validate_local_context(context, repository)
    evidence = _validate_evidence_path(evidence, local_root, repository)
    with tempfile.TemporaryDirectory(prefix="hat-known-hosts-") as directory:
        _SSH_KNOWN_HOSTS = build_pinned_known_hosts(nodes, Path(directory) / "pins")
        commands = {
            "hostname": ["hostname"], "boot_id": ["cat", "/proc/sys/kernel/random/boot_id"],
            "release": ["cat", "/etc/os-release"], "cpu": ["nproc"],
            "memory": ["cat", "/proc/meminfo"], "disk": ["df", "-P", "/"],
            "time_sync": ["timedatectl", "show", "-p", "NTPSynchronized"],
            "outbound_tls": ["curl", "--fail", "--silent", "--show-error", "-o", "/dev/null", "-w", "HAT_M1_TLS_OK", "https://example.com/"],
        }
        for node in nodes:
            facts: dict[str, str] = {"node": node.name, "address": node.address}
            for label, command in commands.items():
                result = ssh(node, command, check=False)
                if result.returncode:
                    raise RuntimeError(f"preflight failed for {node.name}: {label}")
                facts[label] = _stdout(result)
            _require_facts(node, facts)
            facts["host_key"] = node.host_key
            append_evidence(evidence, {"event": "preflight", "facts": facts}, repository)
        _write_preflight_marker(context)
        _write_preflight_handoff(context, inventory_path, linode_env)


def preflight(nodes: list[Node], context: RunContext, evidence: Path, repository: Path | None = None, *, inventory_path: Path | None = None, linode_env: Path | None = None) -> None:
    global _SSH_KNOWN_HOSTS, _REMOTE_ROOT
    try:
        _preflight_impl(nodes, context, evidence, repository, inventory_path, linode_env)
    finally:
        _SSH_KNOWN_HOSTS = None
        _REMOTE_ROOT = None


def init_remote(nodes: list[Node], context: RunContext, evidence: Path | None = None, repository: Path | None = None, *, inventory_path: Path | None = None, linode_env: Path | None = None) -> None:
    """Mutating phase: require a successful preflight, then create each root."""
    global _SSH_KNOWN_HOSTS, _REMOTE_ROOT
    _validate_prerequisites(nodes, inventory_path, linode_env, repository)
    local_root = _validate_local_context(context, repository)
    _require_preflight_marker(context)
    evidence = _validate_evidence_path(evidence or (local_root / "evidence.jsonl"), local_root, repository)
    try:
        with tempfile.TemporaryDirectory(prefix="hat-known-hosts-") as directory:
            _SSH_KNOWN_HOSTS = build_pinned_known_hosts(nodes, Path(directory) / "pins")
            _consume_preflight_handoff(context, inventory_path, linode_env)
            for node in nodes:
                ensure_remote_root(node, context)
                if evidence is not None:
                    append_evidence(evidence, {"event": "init-remote", "node": node.name, "remote_root": context.remote_root}, repository)
    finally:
        _SSH_KNOWN_HOSTS = None
        _REMOTE_ROOT = None


def storage(nodes=None, context=None, evidence=None, repository=None, *, s3_env=None) -> None:
    """Run the bounded fresh-prefix S3 conditional-operation qualification."""
    from concurrent.futures import ThreadPoolExecutor
    from s3 import client_from_env, Reconciliation
    if s3_env is None: raise ValueError("private S3 env is required")
    client = client_from_env(s3_env, repository)
    prefix = f"qualification/{context.run_id}/"
    ledger = evidence
    def op(name, method, key, body=b"", result=None):
        status, headers, data = result if result is not None else method(key, body)
        event = {"operation": name, "status": status, "request_id": headers.get("x-amz-request-id", headers.get("x-request-id", "")),
                 "etag": headers.get("ETag", headers.get("etag", "")), "payload_sha256": hashlib.sha256(data or body).hexdigest()}
        append_evidence(ledger, event, repository)
        return status, headers, data
    key = prefix + "control/object"
    first = op("put-create", client.put, key, b"one", client.put(key, b"one", if_none_match=True))
    etag = first[1].get("ETag", first[1].get("etag", ""))
    op("head", client.head, key, result=client.head(key)); op("get", client.get, key, result=client.get(key))
    op("put-create-refused", client.put, key, b"other", client.put(key, b"other", if_none_match=True))
    replaced = op("put-replace", client.put, key, b"two", client.put(key, b"two", etag=etag))
    current = replaced[1].get("ETag", replaced[1].get("etag", ""))
    op("put-stale-refused", client.put, key, b"bad", client.put(key, b"bad", etag=etag))
    race_key = prefix + "race/create"
    with ThreadPoolExecutor(max_workers=2) as pool:
        races = list(pool.map(lambda payload: client.put(race_key, payload, if_none_match=True), (b"a", b"b")))
    winners = sum(status in (200, 201, 204) for status, _, _ in races)
    if winners != 1: raise RuntimeError("conditional create race did not produce exactly one winner")
    delete = op("delete-current", client.delete, key, result=client.delete(key, etag=current))
    if delete[0] not in (200, 204): raise RuntimeError("conditional delete failed")
    op("list", lambda k, b: client.list(prefix), prefix, result=client.list(prefix))
    reconciliation = client.reconcile_put(prefix + "reconcile", b"reconcile", '"' + hashlib.md5(b"reconcile").hexdigest() + '"')
    append_evidence(ledger, {"operation": "discarded-response-reconciliation", "result": reconciliation.value}, repository)

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario", choices=["preflight", "init-remote", "storage"])
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--linode-env", type=Path)
    parser.add_argument("--s3-env", type=Path)
    args = parser.parse_args(argv)
    repository = Path(__file__).resolve().parents[2]
    if args.scenario == "storage":
        context = new_run_context(args.work_root, repository)
        storage(context=context, evidence=context.local_root / "evidence.jsonl", repository=repository, s3_env=args.s3_env)
        print("storage passed")
        return 0
    if args.inventory is None or args.linode_env is None:
        parser.error("--inventory and --linode-env are required")
    nodes = load_inventory(args.inventory, repository)
    load_linode_env(args.linode_env, nodes, repository)
    if args.scenario == "preflight":
        context = new_run_context(args.work_root, repository)
        preflight(nodes, context, context.local_root / "evidence.jsonl", repository, inventory_path=args.inventory, linode_env=args.linode_env)
    else:
        work_root = _absolute_no_symlinks(args.work_root)
        candidates = sorted((p for p in work_root.iterdir() if p.is_dir() and _RUN_ID.fullmatch(p.name) and (p / ".preflight-ok").is_file() and (p / ".preflight-handoff").is_file()), reverse=True)
        if not candidates:
            raise ValueError("init-remote requires a successful preflight run")
        local_root = candidates[0]
        context = RunContext(local_root.name, local_root, f"/var/lib/hat-qualification/{local_root.name}")
        _FRESH_LOCAL_ROOTS.add(str(local_root))
        init_remote(nodes, context, local_root / "evidence.jsonl", repository, inventory_path=args.inventory, linode_env=args.linode_env)
    print(f"{args.scenario} passed: {len(nodes)} nodes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
