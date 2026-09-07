"""M1 disposable-node safety foundation; standard library only."""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import posixpath
import re
import shlex
import socket
import subprocess
import sys
import time
import uuid
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_NODE_KEYS = {"name", "ssh", "instance_id", "provider_label", "address", "host_key"}
_SAFE = re.compile(r"^[A-Za-z0-9._-]+$")
_SSH_KNOWN_HOSTS: Path | None = None
_REMOTE_ROOT: str | None = None
_SECRET = re.compile(r"(password|passwd|secret|token|authorization|private.?key|credential|access.?key|session|cookie)", re.I)


@dataclass(frozen=True)
class Node:
    name: str
    ssh: str
    instance_id: int
    provider_label: str
    address: str
    host_key: str


@dataclass(frozen=True)
class RunContext:
    run_id: str
    local_root: Path
    remote_root: str


def require_private_file(path: Path) -> None:
    path = Path(path).expanduser()
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"private file required: {path}")
    st = path.stat()
    if st.st_uid != os.getuid():
        raise ValueError("private file is not owned by current user")
    if (st.st_mode & 0o777) != 0o600:
        raise ValueError("private file must have mode 0600")
    parent = path.parent
    pst = parent.stat()
    if pst.st_uid != os.getuid() or (pst.st_mode & 0o077):
        raise ValueError("private file parent is not private")


def _valid_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or not _SAFE.fullmatch(value):
        raise ValueError(f"invalid {field}")
    return value


def validate_inventory(value: dict[str, Any]) -> list[Node]:
    if not isinstance(value, dict) or set(value) != {"nodes"} or not isinstance(value["nodes"], list):
        raise ValueError("inventory must contain only nodes")
    if len(value["nodes"]) < 3:
        raise ValueError("at least three nodes are required")
    nodes: list[Node] = []
    for raw in value["nodes"]:
        if not isinstance(raw, dict) or set(raw) != _NODE_KEYS:
            raise ValueError("node has unexpected keys")
        name = _valid_text(raw["name"], "name")
        ssh_name = raw["ssh"]
        if not isinstance(ssh_name, str) or not ssh_name.startswith("root@") or not ssh_name[5:]:
            raise ValueError("SSH user must be root")
        address = _valid_text(raw["address"], "address")
        host_key = raw["host_key"]
        if not isinstance(host_key, str) or not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", host_key):
            raise ValueError("invalid host key fingerprint")
        match = re.fullmatch(r"root@([A-Za-z0-9.-]+)", ssh_name)
        if not match or match.group(1) != address:
            raise ValueError("SSH target must be root@address")
        if not isinstance(raw["instance_id"], int) or isinstance(raw["instance_id"], bool) or raw["instance_id"] <= 0:
            raise ValueError("invalid instance ID")
        nodes.append(Node(name, ssh_name, raw["instance_id"], _valid_text(raw["provider_label"], "provider label"), address, host_key))
    for field in ("name", "ssh", "instance_id", "provider_label", "address", "host_key"):
        vals = [getattr(n, field) for n in nodes]
        if len(set(vals)) != len(vals):
            raise ValueError(f"duplicate node {field}")
    return nodes


def load_inventory(path: Path) -> list[Node]:
    require_private_file(path)
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid inventory") from exc
    return validate_inventory(value)


def _reject_symlink_components(path: Path) -> Path:
    path = Path(path).expanduser()
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink() and current not in (Path("/var"), Path("/tmp")):
            raise ValueError(f"symlink path component: {current}")
    return absolute


def new_run_context(work_root: Path, repository: Path | None = None) -> RunContext:
    work_root = _reject_symlink_components(work_root)
    if repository:
        repo = Path(repository).expanduser().resolve()
        try:
            work_root.relative_to(repo)
        except ValueError:
            pass
        else:
            raise ValueError("work root must be outside repository")
    if work_root.is_symlink() or (work_root.exists() and work_root.stat().st_uid != os.getuid()):
        raise ValueError("work root must be an owned non-symlink")
    work_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (work_root.stat().st_mode & 0o077) or work_root.stat().st_uid != os.getuid():
        raise ValueError("work root must be private")
    work_root.chmod(0o700)
    run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:10]
    local = work_root / run_id
    local.mkdir(mode=0o700)
    remote = f"/var/lib/hat-qualification/{run_id}"
    return RunContext(run_id, local, remote)


def ensure_remote_root(node: Node, context: RunContext) -> None:
    global _REMOTE_ROOT
    root = context.remote_root
    if not re.fullmatch(r"/var/lib/hat-qualification/[A-Za-z0-9T_Z-]+", root):
        raise ValueError("unsafe remote root")
    base = "/var/lib/hat-qualification"
    trusted = ssh(node, ["test", "-d", base], check=False)
    if trusted.returncode:
        raise RuntimeError("remote qualification base is missing or unsafe")
    result = ssh(node, ["test", "!", "-e", root], check=False)
    if result.returncode:
        raise RuntimeError("remote run root already exists")
    result = ssh(node, ["mkdir", root], check=False)
    if result.returncode:
        raise RuntimeError("cannot create fresh remote run root")
    result = ssh(node, ["test", "-d", root], check=False)
    if result.returncode:
        raise RuntimeError("remote root is not a directory")
    result = ssh(node, ["stat", "-c", "%u %a", root], check=False)
    if result.stdout.decode().strip() != "0 700":
        raise RuntimeError("remote root ownership or mode unsafe")
    _REMOTE_ROOT = root


def ssh(node: Node, argv: list[str], input: bytes | None = None, *, check: bool = True) -> subprocess.CompletedProcess:
    if not argv:
        raise ValueError("remote command cannot be empty")
    command = " ".join(shlex.quote(str(arg)) for arg in argv)
    options = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes"]
    if _SSH_KNOWN_HOSTS is None:
        raise RuntimeError("SSH pinning context is not initialized")
    options += ["-o", f"UserKnownHostsFile={_SSH_KNOWN_HOSTS}"]
    return subprocess.run(["ssh", *options, "--", node.ssh, command], input=input, capture_output=True, check=check, timeout=60)


def scp_to(node: Node, source: Path, destination: str, *, check: bool = True) -> subprocess.CompletedProcess:
    if not source.is_file() or source.is_symlink():
        raise ValueError("source must be a regular file")
    options = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes"]
    if _SSH_KNOWN_HOSTS is None or _REMOTE_ROOT is None or not destination.startswith(_REMOTE_ROOT + "/"):
        raise RuntimeError("SCP destination is outside pinned remote run root")
    options += ["-o", f"UserKnownHostsFile={_SSH_KNOWN_HOSTS}"]
    destination_path = os.path.normpath(destination)
    if destination_path != destination or not destination_path.startswith(_REMOTE_ROOT + "/"):
        raise RuntimeError("SCP destination is outside pinned remote run root")
    parent = posixpath.dirname(destination_path)
    if ssh(node, ["realpath", "-e", parent], check=False).stdout.decode().strip() != parent:
        raise RuntimeError("SCP destination parent is not a real path under remote root")
    return subprocess.run(["scp", *options, "--", str(source), f"{node.ssh}:{destination_path}"], capture_output=True, check=check, timeout=60)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: "[REDACTED]" if _SECRET.search(str(key)) else redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def append_evidence(path: Path, event: dict[str, Any]) -> None:
    path = Path(path)
    _reject_symlink_components(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.stat().st_uid != os.getuid() or (path.parent.stat().st_mode & 0o077):
        raise ValueError("evidence parent is not private")
    path.touch(mode=0o600, exist_ok=True)
    path.chmod(0o600)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(redact(event), sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def _require_facts(node: Node, facts: dict[str, str]) -> None:
    if facts["hostname"].strip() not in {node.name, node.address}:
        raise RuntimeError(f"hostname mismatch for {node.name}")
    if not re.search(r'^ID=ubuntu$', facts["release"], re.M) or not re.search(r'^VERSION_ID="?24\.04"?$', facts["release"], re.M):
        raise RuntimeError(f"unsupported Ubuntu release for {node.name}")
    if not facts["boot_id"].strip() or not re.fullmatch(r"[0-9a-fA-F-]{16,}", facts["boot_id"].strip()):
        raise RuntimeError(f"invalid boot ID for {node.name}")
    memory = re.search(r"MemTotal:\s+(\d+)", facts["memory"])
    disk_rows = [line.split() for line in facts["disk"].splitlines() if line and not line.startswith("Filesystem")]
    if len(disk_rows) != 1 or len(disk_rows[0]) < 5 or not disk_rows[0][4].endswith("%"):
        raise RuntimeError(f"invalid disk report for {node.name}")
    used = int(disk_rows[0][4][:-1])
    if used < 0 or used > 90 or int(facts["cpu"].strip()) < 1 or not memory or int(memory.group(1)) < 512000:
        raise RuntimeError(f"insufficient resources for {node.name}")
    if not re.search(r"NTPSynchronized=yes", facts["time_sync"], re.I):
        raise RuntimeError(f"time is not synchronized for {node.name}")
    if not facts["outbound_tls"].startswith("HAT_M1_TLS_OK"):
        raise RuntimeError(f"outbound TLS failed for {node.name}")


def _known_host_fingerprint(address: str) -> tuple[str, str]:
    result = subprocess.run(["ssh-keyscan", "-T", "10", "-t", "ed25519", address], capture_output=True, text=True, check=False)
    line = next((line for line in result.stdout.splitlines() if "ssh-ed25519" in line), None)
    if not line:
        raise RuntimeError(f"no pinned host key for {address}")
    with tempfile.TemporaryDirectory() as directory:
        key = Path(directory) / "key"
        key.write_text(" ".join(line.split()[1:]) + "\n", encoding="ascii")
        output = subprocess.run(["ssh-keygen", "-lf", str(key)], capture_output=True, text=True, check=True).stdout
    return output.split()[1], line


def load_linode_env(path: Path, nodes: list[Node] | None = None) -> dict[str, int]:
    require_private_file(path)
    values: dict[str, int] = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"export (HAT_FM[123]_LINODE_ID)=(['\"]?)(\d+)\2", line)
        token = re.fullmatch(r"export LINODE_TOKEN=(['\"])([^'\"]+)\1", line)
        if token:
            continue
        if not match or match.group(1) in values:
            raise ValueError("linode env contains malformed or duplicate entries")
        values[match.group(1)] = int(match.group(3))
    expected = {f"HAT_FM{i}_LINODE_ID" for i in range(1, 4)}
    if set(values) != expected:
        raise ValueError("linode env must contain exactly three node IDs")
    if nodes is not None:
        for node in nodes:
            match = re.fullmatch(r"fm([123])", node.name)
            if not match or values[f"HAT_FM{match.group(1)}_LINODE_ID"] != node.instance_id:
                raise ValueError("Linode IDs do not match inventory")
    return values


def _preflight_impl(nodes: list[Node], context: RunContext, evidence: Path) -> None:
    """Collect and validate read-only host facts; do not create remote state."""
    global _SSH_KNOWN_HOSTS
    evidence = Path(evidence).resolve(strict=False)
    local_root = context.local_root.resolve()
    try:
        evidence.relative_to(local_root)
    except ValueError as exc:
        raise ValueError("evidence must be below the fresh local root") from exc
    with tempfile.TemporaryDirectory() as directory:
        known_hosts = Path(directory) / "known_hosts"
        for node in nodes:
            fingerprint, line = _known_host_fingerprint(node.address)
            if fingerprint != node.host_key:
                raise RuntimeError(f"host key mismatch for {node.name}")
            with known_hosts.open("a", encoding="ascii") as stream:
                stream.write(line + "\n")
        _SSH_KNOWN_HOSTS = known_hosts
        commands = {
            "hostname": ["hostname"], "boot_id": ["cat", "/proc/sys/kernel/random/boot_id"],
            "release": ["cat", "/etc/os-release"], "cpu": ["nproc"],
            "memory": ["cat", "/proc/meminfo"], "disk": ["df", "-P", "/"],
            "time_sync": ["timedatectl", "show", "-p", "NTPSynchronized"],
            "outbound_tls": ["curl", "--fail", "--silent", "--show-error", "-o", "/dev/null", "-w", "HAT_M1_TLS_OK", "https://example.com/"],
        }
        for node in nodes:
            facts = {"node": node.name, "address": node.address}
            for label, command in commands.items():
                result = ssh(node, command, check=False)
                if result.returncode:
                    raise RuntimeError(f"preflight failed for {node.name}: {label}")
                facts[label] = result.stdout.decode("utf-8", "replace")
            _require_facts(node, facts)
            facts["host_key"] = node.host_key
            append_evidence(evidence, {"event": "preflight", "facts": facts})
        _SSH_KNOWN_HOSTS = None


def preflight(nodes: list[Node], context: RunContext, evidence: Path) -> None:
    global _SSH_KNOWN_HOSTS, _REMOTE_ROOT
    try:
        _preflight_impl(nodes, context, evidence)
    finally:
        _SSH_KNOWN_HOSTS = None
        _REMOTE_ROOT = None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario", choices=["preflight"])
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--linode-env", type=Path, required=True)
    args = parser.parse_args(argv)
    nodes = load_inventory(args.inventory)
    load_linode_env(args.linode_env, nodes)
    context = new_run_context(args.work_root, Path(__file__).resolve().parents[2])
    preflight(nodes, context, context.local_root / "evidence.jsonl")
    print(f"preflight passed: {len(nodes)} nodes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
