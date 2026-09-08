"""Small, fail-closed coordinator for the M1 remote qualification."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import platform
import posixpath
import re
import shlex
import stat
import sys
import subprocess
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
import uuid
import zipfile
from dataclasses import dataclass
from enum import Enum
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
REMOTE_PROVISION_TIMEOUT = 1200
FENCE_MAX_AGE = 300
_SSH_KNOWN_HOSTS: Path | None = None
_REMOTE_ROOT: str | None = None
_FRESH_LOCAL_ROOTS: set[str] = set()
_LOADED_SECRET_VALUES: set[str] = set()


class StorageStatus(Enum):
    PASS = "PASS"
    NO_GO = "NO-GO"


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


@dataclass(frozen=True)
class Artifact:
    product: str
    version: str
    filename: str
    url: str
    archive_sha256: str
    executable_sha256: str
    archive_kind: str
    members: tuple[str, ...]
    executable: str


_REQUIRED_PACKAGES = ("ca-certificates", "curl", "python3", "sqlite3", "unzip")
_ARTIFACTS = {
    ("trailbase", "x86_64"): Artifact(
        "trailbase", "0.33.11", "trailbase_v0.33.11_x86_64_linux.zip",
        "https://github.com/trailbaseio/trailbase/releases/download/v0.33.11/trailbase_v0.33.11_x86_64_linux.zip",
        "4d5162c8cb5050c653b6e831e5094decdad1060f2221fab73983693667a75925",
        "4d51d0a1fcce9c11d3470b5d5a330848cfd869bed1f237f0886f06794942b121",
        "zip", ("trail", "CHANGELOG.md", "LICENSE"), "trail",
    ),
    ("trailbase", "aarch64"): Artifact(
        "trailbase", "0.33.11", "trailbase_v0.33.11_aarch64_linux.zip",
        "https://github.com/trailbaseio/trailbase/releases/download/v0.33.11/trailbase_v0.33.11_aarch64_linux.zip",
        "05ce27fe190a69d1f504d410de3267c2132ee7ca4b03f00561c14e1d55fc5aca",
        "4241c50147e85716498b35a9f3d2d4bd5247d86ab4405e21bc7e09e7ddfd01a0",
        "zip", ("trail", "CHANGELOG.md", "LICENSE"), "trail",
    ),
    ("litestream", "x86_64"): Artifact(
        "litestream", "0.5.17", "litestream-0.5.17-linux-x86_64.tar.gz",
        "https://github.com/benbjohnson/litestream/releases/download/v0.5.17/litestream-0.5.17-linux-x86_64.tar.gz",
        "cfb371176d164437ae869f8351cfde49bd1804ae71c61923f75c9cba9c9c006d",
        "200e4248a4cc83da2ca52babe66774f1a71afa993d31373adb0ce0fe12154647",
        "tar.gz", ("LICENSE", "README.md", "etc/litestream.service", "etc/litestream.yml", "litestream"), "litestream",
    ),
    ("litestream", "aarch64"): Artifact(
        "litestream", "0.5.17", "litestream-0.5.17-linux-arm64.tar.gz",
        "https://github.com/benbjohnson/litestream/releases/download/v0.5.17/litestream-0.5.17-linux-arm64.tar.gz",
        "f8ca4a050095c1efbda2c4365172e61bf9d955ea0d9ac42f448b52e51819baa5",
        "47baa971c744f3f0d3ca1f4fe82a7883fc8d4bf67ebe3d673c89ec71364920eb",
        "tar.gz", ("LICENSE", "README.md", "etc/litestream.service", "etc/litestream.yml", "litestream"), "litestream",
    ),
}
_LITESTREAM_CHECKSUMS_SHA256 = "f5c30b11a19ef14fc64581be19aa50ee81dcc7f53eb429737c151630f5129d6f"
_WRITER_UNITS = ("hat-trailbase.service", "hat-litestream.service")


def artifact_for(product: str, machine: str) -> Artifact:
    try:
        return _ARTIFACTS[(product, machine)]
    except KeyError as exc:
        raise ValueError("unsupported product or machine architecture") from exc


def confined_remote_path(root: str, candidate: str) -> str:
    if not isinstance(root, str) or not isinstance(candidate, str):
        raise ValueError("remote paths must be strings")
    normalized = posixpath.normpath(candidate)
    if normalized != candidate or "\\" in candidate or not candidate.startswith(root + "/"):
        raise ValueError("remote path escapes run root")
    return candidate


def missing_packages(installed: set[str]) -> list[str]:
    if not isinstance(installed, set) or not installed <= set(_REQUIRED_PACKAGES):
        raise ValueError("package state contains an unexpected name")
    return sorted(set(_REQUIRED_PACKAGES) - installed)


def _query_required_packages() -> list[str]:
    installed = set()
    for package in _REQUIRED_PACKAGES:
        result = subprocess.run(
            ["dpkg-query", "-W", "-f=${Status}", package], capture_output=True, text=True,
            check=False, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip() == "install ok installed":
            installed.add(package)
    return sorted(installed)


def validate_binary_version(product: str, output: str) -> str:
    patterns = {
        "trailbase": r"^trail v0\.33\.11-[0-9]+-g[0-9a-f]{8} \(\d{4}-\d{2}-\d{2}\)\nsqlite: \d+\.\d+\.\d+\n?$",
        "litestream": r"^0\.5\.17\n?$",
    }
    if product not in patterns or not isinstance(output, str) or not re.fullmatch(patterns[product], output):
        raise RuntimeError("unexpected binary version")
    return "0.33.11" if product == "trailbase" else "0.5.17"


def _binary_version_evidence(trail_output: str, litestream_output: str) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    versions = {
        "trailbase": validate_binary_version("trailbase", trail_output),
        "litestream": validate_binary_version("litestream", litestream_output),
    }
    build = re.search(r"^trail (v\S+)", trail_output)
    sqlite = re.search(r"(?m)^sqlite: (\d+\.\d+\.\d+)$", trail_output)
    if build is None or sqlite is None:
        raise RuntimeError("unexpected binary version")
    return versions, {
        "trailbase": {
            "reported": trail_output.rstrip("\n"),
            "build": build.group(1),
            "embedded_sqlite_version": sqlite.group(1),
        },
        "litestream": {"reported": litestream_output.rstrip("\n")},
    }


_PROVISION_SUMMARY_KEYS = {
    "status", "architecture", "installed_packages", "versions", "binary_versions",
    "archives", "executables", "services",
}
_POST_REBOOT_SUMMARY_KEYS = _PROVISION_SUMMARY_KEYS


def _validate_provision_summary(summary: Any) -> dict[str, Any]:
    """Validate the complete, pinned remote provisioning contract."""
    if not isinstance(summary, dict) or set(summary) != _PROVISION_SUMMARY_KEYS:
        raise RuntimeError("remote provisioning summary schema mismatch")
    machine = summary["architecture"]
    if summary["status"] != "PASS" or machine not in {"x86_64", "aarch64"}:
        raise RuntimeError("remote provisioning summary status or architecture mismatch")
    specs = {product: artifact_for(product, machine) for product in ("trailbase", "litestream")}
    packages = summary["installed_packages"]
    if (not isinstance(packages, list) or any(not isinstance(item, str) for item in packages)
            or packages != sorted(set(packages)) or packages != sorted(_REQUIRED_PACKAGES)):
        raise RuntimeError("remote provisioning package summary mismatch")
    if summary["versions"] != {product: spec.version for product, spec in specs.items()}:
        raise RuntimeError("remote provisioning version summary mismatch")
    if summary["archives"] != {product: spec.archive_sha256 for product, spec in specs.items()}:
        raise RuntimeError("remote provisioning archive summary mismatch")
    if summary["executables"] != {product: spec.executable_sha256 for product, spec in specs.items()}:
        raise RuntimeError("remote provisioning executable summary mismatch")
    reports = summary["binary_versions"]
    trail_report = reports.get("trailbase") if isinstance(reports, dict) else None
    trail_reported = trail_report.get("reported") if isinstance(trail_report, dict) else None
    trail_build = trail_report.get("build") if isinstance(trail_report, dict) else None
    sqlite_version = trail_report.get("embedded_sqlite_version") if isinstance(trail_report, dict) else None
    first_line = trail_reported.split("\n", 1)[0] if isinstance(trail_reported, str) else ""
    first_fields = first_line.split()
    reported_build = first_fields[1] if len(first_fields) == 3 and first_fields[0] == "trail" else ""
    if (not isinstance(reports, dict) or set(reports) != set(specs)
            or not isinstance(trail_report, dict)
            or set(trail_report) != {"reported", "build", "embedded_sqlite_version"}
            or trail_build != reported_build
            or not isinstance(trail_build, str)
            or not re.fullmatch(r"v0\.33\.11-[0-9]+-g[0-9a-f]{8}", trail_build)
            or not isinstance(sqlite_version, str)
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", sqlite_version)
            or not isinstance(trail_reported, str)
            or validate_binary_version("trailbase", trail_reported + "\n") != "0.33.11"
            or reports.get("litestream") != {"reported": "0.5.17"}):
        raise RuntimeError("remote provisioning binary version summary mismatch")
    services = summary["services"]
    if services != {unit: "masked-and-inactive" for unit in _WRITER_UNITS}:
        raise RuntimeError("remote provisioning service summary mismatch")
    return summary


def _validate_post_reboot_summary(summary: Any, initial: dict[str, Any]) -> None:
    if not isinstance(summary, dict) or set(summary) != _POST_REBOOT_SUMMARY_KEYS:
        raise RuntimeError("post-reboot provisioning summary schema mismatch")
    _validate_provision_summary(summary)
    for field in ("architecture", "installed_packages", "versions", "binary_versions", "archives", "executables", "services"):
        if summary[field] != initial[field]:
            raise RuntimeError(f"post-reboot {field} changed")


def validate_release_metadata(spec: Artifact, metadata: Any) -> None:
    expected_tag = "v" + spec.version
    if (not isinstance(metadata, dict) or metadata.get("tag_name") != expected_tag
            or metadata.get("draft") is not False or metadata.get("prerelease") is not False):
        raise RuntimeError("unexpected release metadata")
    assets = metadata.get("assets")
    if not isinstance(assets, list):
        raise RuntimeError("release assets are missing")
    matches = [asset for asset in assets if isinstance(asset, dict) and asset.get("name") == spec.filename]
    if len(matches) != 1:
        raise RuntimeError("release asset is missing or duplicated")
    asset = matches[0]
    if asset.get("digest") != "sha256:" + spec.archive_sha256 or asset.get("browser_download_url") != spec.url:
        raise RuntimeError("release asset identity or digest changed")


def published_checksum(text: str, filename: str) -> str:
    if not isinstance(text, str) or not _SAFE.fullmatch(filename):
        raise RuntimeError("invalid published checksum input")
    matches = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1] == filename and re.fullmatch(r"[0-9a-f]{64}", fields[0]):
            matches.append(fields[0])
    if len(matches) != 1:
        raise RuntimeError("published checksum is missing or duplicated")
    expected = {spec.filename: spec.archive_sha256 for key, spec in _ARTIFACTS.items() if key[0] == "litestream"}.get(filename)
    if expected is None or matches[0] != expected:
        raise RuntimeError("published checksum does not match pinned digest")
    return matches[0]


def _archive_executable(archive: Path, spec: Artifact) -> bytes:
    expected = set(spec.members)
    if len(expected) != len(spec.members) or spec.executable not in expected:
        raise RuntimeError("invalid pinned archive manifest")
    if spec.archive_kind == "zip":
        with zipfile.ZipFile(archive) as source:
            members = source.infolist()
            names = [member.filename for member in members]
            for member in members:
                mode = member.external_attr >> 16
                if not stat.S_ISREG(mode) or member.file_size > 128 * 1024 * 1024:
                    raise RuntimeError("unsafe ZIP member")
            if len(names) != len(set(names)) or set(names) != expected:
                raise RuntimeError("unexpected ZIP members")
            executable = source.read(spec.executable)
    elif spec.archive_kind == "tar.gz":
        with tarfile.open(archive, mode="r:gz") as source:
            members = source.getmembers()
            names = [member.name for member in members]
            if any(not member.isfile() or member.size > 128 * 1024 * 1024 for member in members):
                raise RuntimeError("unsafe tar member")
            if len(names) != len(set(names)) or set(names) != expected:
                raise RuntimeError("unexpected tar members")
            stream = source.extractfile(spec.executable)
            if stream is None:
                raise RuntimeError("missing archive executable")
            executable = stream.read()
    else:
        raise RuntimeError("unsupported archive kind")
    for name in names:
        pure = __import__("pathlib").PurePosixPath(name)
        if pure.is_absolute() or not pure.parts or any(part in ("", ".", "..") for part in pure.parts):
            raise RuntimeError("unsafe archive member path")
    if not executable or len(executable) > 128 * 1024 * 1024:
        raise RuntimeError("invalid archive executable")
    return executable


def extract_verified_artifact(archive: Path, spec: Artifact, destination: Path) -> None:
    archive = Path(archive)
    if not archive.is_file() or archive.is_symlink():
        raise RuntimeError("archive is not a regular file")
    if hashlib.sha256(archive.read_bytes()).hexdigest() != spec.archive_sha256:
        raise RuntimeError("archive checksum mismatch")
    executable = _archive_executable(archive, spec)
    if hashlib.sha256(executable).hexdigest() != spec.executable_sha256:
        raise RuntimeError("executable checksum mismatch")
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise RuntimeError("executable destination already exists")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = destination.parent / ("." + destination.name + ".tmp-" + uuid.uuid4().hex)
    try:
        with temporary.open("xb") as stream:
            stream.write(executable)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o700)
        os.link(temporary, destination, follow_symlinks=False)
    finally:
        temporary.unlink(missing_ok=True)


def _service_state(unit: str, *, run=subprocess.run) -> str:
    enabled = run(["systemctl", "is-enabled", unit], capture_output=True, text=True, check=False, timeout=30)
    active = run(["systemctl", "is-active", unit], capture_output=True, text=True, check=False, timeout=30)
    if enabled.returncode not in (0, 1) or enabled.stdout.strip() != "masked":
        raise RuntimeError(f"{unit} is not masked")
    if active.returncode != 3 or active.stdout.strip() != "inactive":
        raise RuntimeError(f"{unit} is not inactive")
    return "masked-and-inactive"


def mask_writer_services(service_dir: Path, *, run=subprocess.run) -> None:
    """Contain every writer before doing any package or network work.

    All commands are attempted even when a sibling fails so a partial stop or
    mask cannot leave an uncontained writer running.
    """
    service_dir = Path(service_dir)
    failures: list[str] = []
    for unit in _WRITER_UNITS:
        try:
            result = run(["systemctl", "stop", unit], capture_output=True, text=True, check=False, timeout=30)
            if result.returncode not in (0, 5):
                raise RuntimeError(f"returncode {result.returncode}")
        except Exception as exc:
            failures.append(f"stop:{unit}:{type(exc).__name__}")
    # Verify each stop before touching unit files, including units whose stop failed.
    for unit in _WRITER_UNITS:
        try:
            active = run(["systemctl", "is-active", unit], capture_output=True, text=True, check=False, timeout=30)
            if active.returncode != 3 or active.stdout.strip() != "inactive":
                raise RuntimeError("not inactive")
        except Exception as exc:
            failures.append(f"inactive:{unit}:{type(exc).__name__}")
    if not service_dir.is_dir() or service_dir.is_symlink():
        failures.append("mask:unsafe-systemd-directory")
    else:
        for unit in _WRITER_UNITS:
            try:
                path = service_dir / unit
                if path.is_symlink():
                    if os.readlink(path) != "/dev/null":
                        raise RuntimeError("unexpected symlink")
                elif path.exists():
                    raise RuntimeError("unit file already exists")
                else:
                    os.symlink("/dev/null", path)
            except Exception as exc:
                failures.append(f"mask:{unit}:{type(exc).__name__}")
    # Exactly one reload follows the complete mask attempt.
    try:
        result = run(["systemctl", "daemon-reload"], capture_output=True, text=True, check=False, timeout=30)
        if result.returncode:
            raise RuntimeError(f"returncode {result.returncode}")
    except Exception as exc:
        failures.append(f"reload:{type(exc).__name__}")
    for unit in _WRITER_UNITS:
        try:
            _service_state(unit, run=run)
        except Exception as exc:
            failures.append(f"verify:{unit}:{type(exc).__name__}")
    if failures:
        raise RuntimeError("writer containment failed: " + ", ".join(failures[:16]))


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
    result = ssh(node, ["stat", "-c", "%F\t%u\t%g\t%a\t%n", "--", path], check=False)
    if result.returncode:
        raise RuntimeError(f"remote path does not exist: {path}")
    fields = _stdout(result).strip().split("\t")
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
    for attempt in range(3):
        real = ssh(node, ["realpath", "-e", "--", path], check=False)
        if real.returncode == 0 and _stdout(real).strip() == path:
            return
        if attempt < 2:
            time.sleep(1)
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


def ssh(node: Node, argv: list[str], input: bytes | None = None, *, check: bool = True, timeout: float = SSH_TIMEOUT) -> subprocess.CompletedProcess:
    _validate_node_fields(node)
    if not argv:
        raise ValueError("remote command cannot be empty")
    command = " ".join(shlex.quote(str(arg)) for arg in argv)
    return subprocess.run(
        ["ssh", *_transport_options(), "--", node.ssh, command],
        input=input, capture_output=True, check=check, timeout=timeout,
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


def write_latest_storage_evidence_pointer(evidence: Path) -> Path:
    """Atomically publish only the latest local evidence path outside Git."""
    evidence = _absolute_no_symlinks(evidence)
    pointer = _absolute_no_symlinks(Path.home() / ".config" / "hat" / "m1-latest-storage-evidence")
    pointer.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _require_private_directory(pointer.parent, "storage pointer parent")
    temporary = pointer.parent / ("." + pointer.name + ".tmp-" + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, (str(evidence) + "\n").encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(temporary, pointer)
        pointer.chmod(0o600)
        directory_fd = os.open(pointer.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return pointer


def write_latest_fence_evidence_pointer(evidence: Path) -> Path:
    """Publish the latest fence evidence path in the private operator config."""
    evidence = _absolute_no_symlinks(evidence)
    pointer = _absolute_no_symlinks(Path.home() / ".config" / "hat" / "latest-fence-evidence")
    pointer.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _require_private_directory(pointer.parent, "fence pointer parent")
    temporary = pointer.parent / ("." + pointer.name + ".tmp-" + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, (str(evidence) + "\n").encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(temporary, pointer)
        pointer.chmod(0o600)
        directory_fd = os.open(pointer.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)
    return pointer


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


def _download_public(url: str, destination: Path, *, max_bytes: int) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "hat-qualification/1"})
    destination = Path(destination)
    try:
        with urllib.request.urlopen(request, timeout=60) as response, destination.open("xb") as stream:
            final = urllib.parse.urlparse(response.geturl())
            if (final.scheme != "https" or final.username is not None or final.password is not None
                    or final.hostname not in {"api.github.com", "github.com", "release-assets.githubusercontent.com"}):
                raise RuntimeError("download redirected to an untrusted URL")
            size = 0
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > max_bytes:
                    raise RuntimeError("download exceeds size limit")
                stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return hashlib.sha256(destination.read_bytes()).hexdigest()


def _release_api(spec: Artifact) -> str:
    repository = "trailbaseio/trailbase" if spec.product == "trailbase" else "benbjohnson/litestream"
    return f"https://api.github.com/repos/{repository}/releases/tags/v{spec.version}"


def _install_required_packages() -> list[str]:
    installed = set(_query_required_packages())
    needed = missing_packages(installed)
    if needed:
        environment = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
        subprocess.run(["apt-get", "update"], env=environment, capture_output=True, check=True, timeout=300)
        subprocess.run(
            ["apt-get", "install", "-y", "--no-install-recommends", *needed],
            env=environment, capture_output=True, check=True, timeout=300,
        )
        installed = set(_query_required_packages())
    if installed != set(_REQUIRED_PACKAGES):
        raise RuntimeError("required package installation did not complete")
    return sorted(installed)


def _trusted_remote_root(root: Path) -> Path:
    root = Path(root)
    expected_parent = Path("/var/lib/hat-qualification")
    if root.parent != expected_parent or not _RUN_ID.fullmatch(root.name):
        raise RuntimeError("invalid remote provisioning root")
    st = root.stat(follow_symlinks=False)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_gid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
        raise RuntimeError("untrusted remote provisioning root")
    if root.resolve(strict=True) != root:
        raise RuntimeError("remote provisioning root is not canonical")
    return root


def _checksums_asset(metadata: dict[str, Any]) -> tuple[str, str]:
    matches = [asset for asset in metadata.get("assets", [])
               if isinstance(asset, dict) and asset.get("name") == "checksums.txt"]
    url = "https://github.com/benbjohnson/litestream/releases/download/v0.5.17/checksums.txt"
    if len(matches) != 1 or matches[0].get("digest") != "sha256:" + _LITESTREAM_CHECKSUMS_SHA256 or matches[0].get("browser_download_url") != url:
        raise RuntimeError("published checksums asset identity or digest changed")
    return url, _LITESTREAM_CHECKSUMS_SHA256


def _remote_hash(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("remote artifact is not a regular file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _remote_verify(remote_root: Path) -> dict[str, Any]:
    root = _trusted_remote_root(remote_root)
    machine = platform.machine()
    specs = [artifact_for("trailbase", machine), artifact_for("litestream", machine)]
    binaries = root / "bin"
    downloads = root / "downloads"
    trail_output = subprocess.run([str(binaries / "trail"), "--version"], capture_output=True, text=True,
                                  check=True, timeout=30).stdout
    litestream_output = subprocess.run([str(binaries / "litestream"), "version"], capture_output=True,
                                       text=True, check=True, timeout=30).stdout
    versions, binary_versions = _binary_version_evidence(trail_output, litestream_output)
    services = {unit: _service_state(unit) for unit in _WRITER_UNITS}
    packages = _query_required_packages()
    if packages != sorted(_REQUIRED_PACKAGES):
        raise RuntimeError("required package state changed after reboot")
    return {"status": "PASS", "architecture": machine, "installed_packages": packages, "versions": versions,
            "binary_versions": binary_versions,
            "archives": {spec.product: _remote_hash(downloads / spec.filename) for spec in specs},
            "executables": {spec.product: _remote_hash(binaries / spec.executable) for spec in specs},
            "services": services}


def remote_provision(remote_root: Path) -> dict[str, Any]:
    if os.geteuid() != 0 or platform.system() != "Linux":
        raise RuntimeError("remote provisioning requires Linux root")
    root = _trusted_remote_root(remote_root)
    machine = platform.machine()
    specs = [artifact_for("trailbase", machine), artifact_for("litestream", machine)]

    # Fence writers before package manager, release metadata, or archive work.
    mask_writer_services(Path("/etc/systemd/system"))
    installed = _install_required_packages()

    downloads = root / "downloads"
    downloads.mkdir(mode=0o700)
    release_metadata: dict[str, dict[str, Any]] = {}
    for spec in specs:
        metadata_path = downloads / f"{spec.product}-release.json"
        _download_public(_release_api(spec), metadata_path, max_bytes=2 * 1024 * 1024)
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("invalid release metadata") from exc
        validate_release_metadata(spec, metadata)
        release_metadata[spec.product] = metadata

    checksums_url, checksums_digest = _checksums_asset(release_metadata["litestream"])
    checksums_path = downloads / "checksums.txt"
    if _download_public(checksums_url, checksums_path, max_bytes=128 * 1024) != checksums_digest:
        raise RuntimeError("published checksums file digest mismatch")
    checksums_text = checksums_path.read_text(encoding="ascii")

    for spec in specs:
        archive = downloads / spec.filename
        if _download_public(spec.url, archive, max_bytes=256 * 1024 * 1024) != spec.archive_sha256:
            raise RuntimeError("release archive digest mismatch")
        if spec.product == "litestream":
            published_checksum(checksums_text, spec.filename)

    binaries = root / "bin"
    for spec in specs:
        extract_verified_artifact(downloads / spec.filename, spec, binaries / spec.executable)

    trail_output = subprocess.run(
        [str(binaries / "trail"), "--version"], capture_output=True, text=True, check=True, timeout=30,
    ).stdout
    litestream_output = subprocess.run(
        [str(binaries / "litestream"), "version"], capture_output=True, text=True, check=True, timeout=30,
    ).stdout
    versions, binary_versions = _binary_version_evidence(trail_output, litestream_output)
    summary = {
        "status": "PASS", "architecture": machine, "installed_packages": sorted(installed),
        "versions": versions, "binary_versions": binary_versions,
        "archives": {spec.product: spec.archive_sha256 for spec in specs},
        "executables": {spec.product: spec.executable_sha256 for spec in specs},
        "services": {unit: "masked-and-inactive" for unit in _WRITER_UNITS},
    }
    return _validate_provision_summary(summary)


_BOUNDED_READ_SCRIPT = r'''import os, sys
fd = os.open(sys.argv[1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
with os.fdopen(fd, "rb") as source:
    sys.stdout.buffer.write(source.read(int(sys.argv[2])))
'''


def _copy_from_node(node: Node, source: str, destination: Path, *, max_bytes: int) -> None:
    if _REMOTE_ROOT is None:
        raise RuntimeError("remote copy context is not initialized")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
        raise ValueError("remote copy bound must be positive")
    confined_remote_path(_REMOTE_ROOT, source)
    kind, uid, gid, mode, name = _remote_stat(node, source)
    if kind != "regular file" or uid != 0 or gid != 0 or name != source or (mode & 0o022):
        raise RuntimeError("remote evidence file is unsafe")
    real = ssh(node, ["realpath", "-e", "--", source], check=False)
    if real.returncode or _stdout(real).strip() != source:
        raise RuntimeError("remote evidence file is not canonical")
    result = ssh(node, ["python3", "-c", _BOUNDED_READ_SCRIPT, source, str(max_bytes + 1)], check=False)
    if result.returncode or len(result.stdout) > max_bytes:
        raise RuntimeError("could not copy bounded remote evidence")
    destination = _absolute_no_symlinks(destination)
    _require_private_directory(destination.parent, "evidence destination parent")
    if destination.exists() or destination.is_symlink():
        raise RuntimeError("evidence destination already exists")
    temporary = destination.parent / ("." + destination.name + ".tmp-" + uuid.uuid4().hex)
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(result.stdout)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, destination, follow_symlinks=False)
        parent_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        temporary.unlink(missing_ok=True)


def _copy_m0_source(node: Node, context: RunContext, repository: Path) -> str:
    source_dir = repository / "experiments" / "m0"
    tracked = ("README.md", "run.py", "test_run.py")
    result = subprocess.run(
        ["git", "diff", "--quiet", "HEAD", "--", *[str(path.relative_to(repository)) for path in (source_dir / name for name in tracked)]],
        cwd=repository, capture_output=True, check=False, timeout=30,
    )
    if result.returncode:
        raise RuntimeError("M0 source differs from the committed baseline")
    remote_dir = context.remote_root + "/source/experiments/m0"
    for directory in (context.remote_root + "/source", context.remote_root + "/source/experiments", remote_dir):
        created = ssh(node, ["mkdir", "-m", "700", "--", directory], check=False)
        if created.returncode:
            raise RuntimeError("could not create remote M0 source directory")
    for name in tracked:
        scp_to(node, source_dir / name, remote_dir + "/" + name)
    return remote_dir


_M0_COLLECT_SCRIPT = r'''import hashlib, json, pathlib, tarfile, sys
root, output = map(pathlib.Path, sys.argv[1:])
RESULT_MAX = 8 * 1024 * 1024
LOG_MAX = 8 * 1024 * 1024
ARCHIVE_MAX = 128 * 1024 * 1024
def bounded_bytes(path, limit):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise RuntimeError("M0 evidence file exceeds bound")
    chunks = []
    with path.open("rb") as source:
        remaining = limit
        while remaining:
            chunk = source.read(min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    return b"".join(chunks)
def bounded_hash(path, limit):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise RuntimeError("M0 log exceeds bound")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
runs = [path for path in root.iterdir() if path.name.startswith("run-")]
if any(path.is_symlink() or not path.is_dir() for path in runs):
    raise RuntimeError("unsafe M0 run root")
evidence = {"run_count": len(runs), "result_present": False, "log_count": 0, "logs": []}
logs = []
def safe_relative(path, base):
    relative = path.relative_to(base)
    if not relative.parts or any(part in ("", ".", "..") for part in relative.parts):
        raise RuntimeError("unsafe log path")
    return pathlib.PurePosixPath(*relative.parts).as_posix()
if len(runs) == 1:
    run = runs[0]
    result_path = run / "result.json"
    if result_path.is_file() and not result_path.is_symlink():
        result_bytes = bounded_bytes(result_path, RESULT_MAX)
        (output / "m0-result.json").write_bytes(result_bytes)
        evidence.update({"result_present": True, "result_sha256": hashlib.sha256(result_bytes).hexdigest()})
        try:
            result = json.loads(result_bytes)
            if not isinstance(result, dict) or not isinstance(result.get("results", []), list):
                raise TypeError
            evidence.update({"result_status": result.get("status"), "repeat": result.get("repeat"),
                             "result_count": len(result.get("results", []))})
        except (UnicodeError, json.JSONDecodeError, TypeError):
            evidence["result_valid_json"] = False
    for path in sorted(run.rglob("*")):
        if path.is_symlink():
            raise RuntimeError("symlink in M0 logs")
        if path.is_file() and path.parent.name == "logs":
            relative = safe_relative(path, run)
            logs.append({"path": "logs/" + relative, "sha256": bounded_hash(path, LOG_MAX)})
    evidence["logs"] = logs
    evidence["log_count"] = len(logs)
with tarfile.open(output / "m0-logs.tar.gz", "x:gz") as archive:
    for item in logs:
        path = run / pathlib.PurePosixPath(item["path"][len("logs/"):])
        info = archive.gettarinfo(str(path), arcname=item["path"])
        if not info.isfile():
            raise RuntimeError("non-regular M0 log")
        if archive.tell() + path.stat().st_size > ARCHIVE_MAX:
            raise RuntimeError("M0 log archive exceeds bound")
        with path.open("rb") as source:
            archive.addfile(info, source)
if (output / "m0-logs.tar.gz").stat().st_size > ARCHIVE_MAX:
    raise RuntimeError("M0 log archive exceeds bound")
(output / "m0-evidence.json").write_text(json.dumps(evidence, sort_keys=True) + "\n")
'''


def _safe_archive_member(name: Any) -> bool:
    if not isinstance(name, str) or "\\" in name:
        return False
    path = __import__("pathlib").PurePosixPath(name)
    return (path.as_posix() == name and len(path.parts) >= 2 and path.parts[0] == "logs"
            and not path.is_absolute() and all(part not in ("", ".", "..") for part in path.parts))


def _validate_m0_log_archive(archive_path: Path, manifest: Any) -> bool:
    """Require a link-free archive whose members exactly match manifest hashes."""
    if not isinstance(manifest, dict) or not isinstance(manifest.get("logs"), list):
        return False
    expected: dict[str, str] = {}
    for item in manifest["logs"]:
        if (not isinstance(item, dict) or set(item) != {"path", "sha256"}
                or not _safe_archive_member(item["path"])
                or not isinstance(item["sha256"], str)
                or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None
                or item["path"] in expected):
            return False
        expected[item["path"]] = item["sha256"]
    if (type(manifest.get("log_count")) is not int or manifest.get("log_count") != len(expected)
            or not expected or not Path(archive_path).is_file() or Path(archive_path).is_symlink()):
        return False
    try:
        with tarfile.open(archive_path, "r:gz") as source:
            members = source.getmembers()
            names = [member.name for member in members]
            if (len(names) != len(set(names)) or set(names) != set(expected)
                    or any(not _safe_archive_member(member.name) or not member.isfile()
                           or member.issym() or member.islnk() or member.size < 0
                           or member.size > 128 * 1024 * 1024
                           for member in members)):
                return False
            for member in members:
                stream = source.extractfile(member)
                if stream is None or hashlib.sha256(stream.read(128 * 1024 * 1024 + 1)).hexdigest() != expected[member.name]:
                    return False
    except (OSError, tarfile.TarError):
        return False
    return True


def _validate_m0_aggregate(node: Node, expected_architecture: str, aggregate: Any,
                           manifest: Any, result_sha256: str, logs_archive: Path | None = None) -> bool:
    if node.name != "fm1" or not isinstance(aggregate, dict) or not isinstance(manifest, dict):
        return False
    try:
        trail_hash = artifact_for("trailbase", expected_architecture).executable_sha256
        litestream_hash = artifact_for("litestream", expected_architecture).executable_sha256
    except ValueError:
        return False
    expected_matrix = {(scenario, iteration) for iteration in range(1, 4)
                       for scenario in ("follow", "graceful", "crash", "lagged-crash")}
    expected_matrix.add(("guards", 1))
    results = aggregate.get("results")
    if not isinstance(results, list) or len(results) != len(expected_matrix):
        return False
    allowed_result_keys = {
        "scenario", "status", "iteration", "evidence", "initial_txid", "final_sync_txid", "selected_txid",
        "logical_comparison", "rows_per_business_db", "payload_bytes", "structural_check", "quiesce_wall_ns",
        "stop_evidence", "follow", "promotion_start_to_functional_ms", "quiesce_to_functional_ms",
        "baseline_auth", "promoted_writes", "logs_db", "epoch2", "normalized_follower_errors",
        "trail_signal_ns", "trail_exit_ns", "replicator_signal_ns", "replicator_exit_ns", "outcomes",
        "in_flight", "baseline", "signal_sent_ns", "exit_observed_ns", "auth", "controls",
    }
    if any(not isinstance(item, dict) or set(item) - allowed_result_keys
           or not isinstance(item.get("scenario"), str)
           or type(item.get("iteration")) is not int for item in results):
        return False
    actual_matrix = {(item["scenario"], item["iteration"]) for item in results}
    log_paths = {item.get("path") for item in manifest.get("logs", []) if isinstance(item, dict)}
    refs = []
    for item in results:
        evidence = item.get("evidence")
        ref = evidence.get("logs_ref") if isinstance(evidence, dict) else None
        if (not isinstance(ref, str) or not ref.startswith("logs/") or not ref.endswith("/")
                or not _safe_archive_member(ref[:-1]) or ref in refs
                or not any(isinstance(path, str) and path.startswith(ref) for path in log_paths)):
            return False
        refs.append(ref)
    if {path for path in log_paths if isinstance(path, str)} != {
            path for ref in refs for path in log_paths if isinstance(path, str) and path.startswith(ref)}:
        return False
    return (
        len(actual_matrix) == len(expected_matrix)
        and actual_matrix == expected_matrix
        and all(item.get("status") == "PASS" for item in results)
        and aggregate.get("scenario") == "all"
        and aggregate.get("status") == "PASS"
        and type(aggregate.get("repeat")) is int
        and aggregate.get("repeat") == 3
        and aggregate.get("platform") == {"system": "Linux", "machine": expected_architecture}
        and aggregate.get("trail_sha256") == trail_hash
        and aggregate.get("litestream_sha256") == litestream_hash
        and manifest.get("run_count") == 1
        and manifest.get("result_present") is True
        and manifest.get("result_sha256") == result_sha256
        and manifest.get("result_status") == "PASS"
        and type(manifest.get("repeat")) is int
        and manifest.get("repeat") == 3
        and type(manifest.get("result_count")) is int
        and manifest.get("result_count") == 13
        and type(manifest.get("log_count")) is int
        and manifest.get("log_count") > 0
        and logs_archive is not None
        and _validate_m0_log_archive(logs_archive, manifest)
    )


def _m0_scope_unit(context: RunContext) -> str:
    return "hat-m0-" + context.run_id.rsplit("-", 1)[1]


def _stop_m0_scope(node: Node, unit: str) -> None:
    stopped = ssh(node, ["systemctl", "stop", unit], check=False, timeout=120)
    reset = ssh(node, ["systemctl", "reset-failed", unit], check=False, timeout=120)
    if stopped.returncode not in (0, 5) or reset.returncode not in (0, 1, 5):
        raise RuntimeError("could not stop M0 scope")


def _run_m0_linux_parity(node: Node, context: RunContext, evidence: Path, local_root: Path,
                         repository: Path, expected_architecture: str) -> StorageStatus:
    m0 = _copy_m0_source(node, context, repository)
    work = _create_runtime_root(node, context)
    unit = _m0_scope_unit(context)
    workload = ["python3", m0 + "/run.py", "--trail", context.remote_root + "/bin/trail",
                "--litestream", context.remote_root + "/bin/litestream", "--work-root", work,
                "--scenario", "all", "--repeat", "3"]
    command = ["systemd-run", "--scope", "--unit=" + unit, "--collect", "--quiet", "--", *workload]
    termination = "completed"
    exit_code = None
    diagnostic: bytes | str = b""
    try:
        result = ssh(node, command, check=False, timeout=1200)
        exit_code = result.returncode
        diagnostic = result.stderr or b""
    except subprocess.TimeoutExpired as exc:
        termination = "timeout"
        diagnostic = exc.stderr or b""
    except (OSError, subprocess.SubprocessError) as exc:
        termination = type(exc).__name__
        diagnostic = getattr(exc, "stderr", b"") or b""

    failures = []
    abnormal = termination != "completed" or exit_code != 0
    if abnormal:
        diagnostic_bytes = diagnostic.encode("utf-8", errors="replace") if isinstance(diagnostic, str) else diagnostic
        failures.append("resource capability: no space left on device"
                        if b"No space left on device" in diagnostic_bytes else "workload did not complete")
        try:
            _stop_m0_scope(node, unit)
        except (OSError, subprocess.SubprocessError, RuntimeError):
            failures.append("M0 scope cleanup failed")
    local_manifest = local_root / "fm1-m0-evidence.json"
    local_logs = local_root / "fm1-m0-logs.tar.gz"
    local_result = local_root / "fm1-m0-result.json"
    manifest: dict[str, Any] = {}
    try:
        collected = ssh(node, ["python3", "-c", _M0_COLLECT_SCRIPT, work, context.remote_root], check=False)
        if collected.returncode:
            raise RuntimeError("remote evidence collection failed")
        _copy_from_node(node, context.remote_root + "/m0-evidence.json", local_manifest, max_bytes=1024 * 1024)
        _copy_from_node(node, context.remote_root + "/m0-logs.tar.gz", local_logs, max_bytes=128 * 1024 * 1024)
        manifest = json.loads(local_manifest.read_text(encoding="utf-8"))
        if manifest.get("result_present"):
            _copy_from_node(node, context.remote_root + "/m0-result.json", local_result, max_bytes=8 * 1024 * 1024)
    except (OSError, RuntimeError, ValueError, UnicodeError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        failures.append("evidence collection failed: " + type(exc).__name__)

    aggregate: dict[str, Any] = {}
    result_sha256 = ""
    if not _validate_m0_log_archive(local_logs, manifest):
        failures.append("copied logs are unsafe or incomplete")
    if local_result.is_file():
        try:
            result_bytes = local_result.read_bytes()
            result_sha256 = hashlib.sha256(result_bytes).hexdigest()
            aggregate = json.loads(result_bytes)
        except (OSError, UnicodeError, json.JSONDecodeError):
            failures.append("copied aggregate is invalid")
    complete = not failures and _validate_m0_aggregate(
        node, expected_architecture, aggregate, manifest, result_sha256, local_logs,
    )
    if not complete and not failures:
        failures.append("copied aggregate or logs are incomplete")
    status = StorageStatus.PASS if complete else StorageStatus.NO_GO
    event = {"event": "m0-linux-parity", "node": "fm1", "status": status.value, "repeat": 3,
             "termination": termination, "exit_code": exit_code, "failures": failures}
    if complete:
        event["coverage"] = {"results": 13, "logs": manifest["log_count"]}
    for name, path in (("partial_evidence_sha256", local_manifest), ("logs_sha256", local_logs),
                       ("result_sha256", local_result)):
        if path.is_file():
            event[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    append_evidence(evidence, event, repository)
    return status


def _create_runtime_root(node: Node, context: RunContext) -> str:
    base = "/run/hat-qualification"
    _verify_remote_directory(node, "/run")
    status = ssh(node, ["stat", "-c", "%F %u %g %a %n", "--", base], check=False)
    if status.returncode:
        absent = ssh(node, ["test", "!", "-e", base], check=False)
        dangling = ssh(node, ["test", "!", "-L", base], check=False)
        if absent.returncode or dangling.returncode or ssh(node, ["mkdir", "-m", "700", "--", base], check=False).returncode:
            raise RuntimeError("runtime qualification base is missing or unsafe")
    _verify_remote_directory(node, base, mode=0o700)
    root = base + "/" + context.run_id.rsplit("-", 1)[1]
    if ssh(node, ["test", "!", "-e", root], check=False).returncode or ssh(node, ["test", "!", "-L", root], check=False).returncode:
        raise RuntimeError("runtime M0 root already exists")
    if ssh(node, ["mkdir", "-m", "700", "--", root], check=False).returncode:
        raise RuntimeError("could not create runtime M0 root")
    _verify_remote_directory(node, root, mode=0o700)
    return root


def _preflight_boot_ids(evidence: Path, nodes: list[Node]) -> dict[str, str]:
    expected = {node.name for node in nodes}
    boots: dict[str, str] = {}
    for line in evidence.read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        if event.get("event") == "preflight" and isinstance(event.get("facts"), dict):
            name = event["facts"].get("node")
            boot = event["facts"].get("boot_id", "").strip()
            if name in boots or name not in expected or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot):
                raise RuntimeError("invalid preflight boot identity")
            boots[name] = boot
    if set(boots) != expected:
        raise RuntimeError("preflight boot identities are incomplete")
    return boots


def _require_live_identity(node: Node, boot_id: str) -> None:
    hostname = ssh(node, ["hostname"], check=False)
    boot = ssh(node, ["cat", "/proc/sys/kernel/random/boot_id"], check=False)
    if hostname.returncode or _stdout(hostname).strip() != node.hostname or boot.returncode or _stdout(boot).strip() != boot_id:
        raise RuntimeError("live node identity changed before reboot")


def _verify_reboot(node: Node, old_boot: str, *, timeout: float = 240.0) -> None:
    reboot = ssh(node, ["systemctl", "reboot"], check=False)
    if reboot.returncode not in (0, 255):
        raise RuntimeError("reboot request failed")
    deadline = time.monotonic() + timeout
    new_boot = ""
    while time.monotonic() < deadline:
        time.sleep(3)
        try:
            result = ssh(node, ["cat", "/proc/sys/kernel/random/boot_id"], check=False)
            candidate = _stdout(result).strip() if result.returncode == 0 else ""
        except (OSError, subprocess.SubprocessError):
            candidate = ""
        if candidate and candidate != old_boot:
            new_boot = candidate
            break
    if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", new_boot):
        raise RuntimeError("node did not return with a new boot identity")
    hostname = ssh(node, ["hostname"], check=False)
    if hostname.returncode or _stdout(hostname).strip() != node.hostname:
        raise RuntimeError("node hostname changed after reboot")
    for unit in _WRITER_UNITS:
        enabled = ssh(node, ["systemctl", "is-enabled", unit], check=False)
        active = ssh(node, ["systemctl", "is-active", unit], check=False)
        if (enabled.returncode not in (0, 1) or _stdout(enabled).strip() != "masked"
                or active.returncode != 3 or _stdout(active).strip() != "inactive"):
            raise RuntimeError("writer service mask did not survive reboot")
    return new_boot


def _append_provision_no_go(evidence: Path | None, repository: Path, *, stage: str, exc: BaseException) -> None:
    if evidence is None:
        return
    try:
        append_evidence(evidence, {"event": "provision", "status": "NO-GO", "stage": stage,
                                   "exception_type": type(exc).__name__}, repository)
    except Exception:
        pass


def _provision_workflow(nodes: list[Node], context: RunContext, evidence: Path, repository: Path, *, inventory_path: Path, linode_env: Path, fence_command: Path) -> StorageStatus:
    global _SSH_KNOWN_HOSTS, _REMOTE_ROOT
    _validate_prerequisites(nodes, inventory_path, linode_env, repository)
    local_root = _validate_local_context(context, repository)
    evidence = _validate_evidence_path(evidence, local_root, repository)
    stage = "transport-setup"
    try:
        with tempfile.TemporaryDirectory(prefix="hat-known-hosts-") as directory:
            _SSH_KNOWN_HOSTS = build_pinned_known_hosts(nodes, Path(directory) / "pins")
            _REMOTE_ROOT = context.remote_root
            coordinator = Path(__file__).resolve()
            architectures = {}
            summaries: dict[str, dict[str, Any]] = {}
            for node in nodes:
                stage = "provision:" + node.name
                _verify_remote_directory(node, context.remote_root, mode=0o700)
                remote_coordinator = context.remote_root + "/m1-run.py"
                scp_to(node, coordinator, remote_coordinator)
                result = ssh(node, ["python3", remote_coordinator, "__remote-provision", context.remote_root],
                             check=False, timeout=REMOTE_PROVISION_TIMEOUT)
                if result.returncode:
                    raise RuntimeError(f"provisioning failed for {node.name}")
                try:
                    summary = json.loads(_stdout(result))
                except (UnicodeError, json.JSONDecodeError) as exc:
                    raise RuntimeError("invalid remote provisioning result") from exc
                summary = _validate_provision_summary(summary)
                architectures[node.name] = summary["architecture"]
                summaries[node.name] = summary
                append_evidence(evidence, {"event": "provision", "node": node.name, **summary}, repository)

            stage = "reboot-preflight"
            boot_ids = _preflight_boot_ids(evidence, nodes)
            for node in nodes:
                stage = "reboot:" + node.name
                target = {"node": node.name, "instance_id": node.instance_id,
                          "provider_label": node.provider_label, "address": node.address,
                          "host_key": node.host_key}
                inspected = invoke_fence(fence_command, "inspect", target)
                provider = inspected.get("evidence", {})
                if not inspected.get("valid") or provider.get("state") != "running":
                    raise RuntimeError("provider identity/state is not confirmed before reboot")
                _require_live_identity(node, boot_ids[node.name])
                new_boot_id = _verify_reboot(node, boot_ids[node.name])
                post = ssh(node, ["python3", remote_coordinator, "__remote-verify", context.remote_root],
                           check=False, timeout=REMOTE_PROVISION_TIMEOUT)
                if post.returncode:
                    raise RuntimeError(f"post-reboot verification failed for {node.name}")
                try:
                    post_summary = json.loads(_stdout(post))
                except (UnicodeError, json.JSONDecodeError) as exc:
                    raise RuntimeError("invalid post-reboot verification result") from exc
                _validate_post_reboot_summary(post_summary, summaries[node.name])
                append_evidence(evidence, {"event": "reboot-mask-check", "node": node.name,
                                           "status": "PASS", "old_boot_id": boot_ids[node.name],
                                           "new_boot_id": new_boot_id,
                                           "services": post_summary["services"],
                                           "installed_packages": post_summary["installed_packages"],
                                           "versions": post_summary["versions"],
                                           "binary_versions": post_summary["binary_versions"],
                                           "archives": post_summary["archives"],
                                           "executables": post_summary["executables"]}, repository)

            stage = "m0-linux-parity"
            fm1 = next(node for node in nodes if node.name == "fm1")
            return _run_m0_linux_parity(fm1, context, evidence, local_root, repository, architectures["fm1"])
    except Exception as exc:
        _append_provision_no_go(evidence, repository, stage=stage, exc=exc)
        return StorageStatus.NO_GO
    finally:
        _SSH_KNOWN_HOSTS = None
        _REMOTE_ROOT = None


def provision(nodes: list[Node], context: RunContext, evidence: Path, repository: Path, *, inventory_path: Path, linode_env: Path, fence_command: Path) -> StorageStatus:
    try:
        return _provision_workflow(nodes, context, evidence, repository,
                                   inventory_path=inventory_path, linode_env=linode_env,
                                   fence_command=fence_command)
    except Exception as exc:
        _append_provision_no_go(evidence, repository, stage="provision", exc=exc)
        return StorageStatus.NO_GO


def _storage_matrix(nodes=None, context=None, evidence=None, repository=None, *, s3_env=None, cleanup=False) -> StorageStatus:
    """Collect the complete fresh-prefix matrix; capability mismatches produce NO-GO."""
    from concurrent.futures import ThreadPoolExecutor
    from xml.etree import ElementTree
    from s3 import client_from_env, header_value, quote_etag, Reconciliation
    if s3_env is None: raise ValueError("private S3 env is required")
    client = client_from_env(s3_env, repository)
    prefix = f"qualification/{context.run_id}/"
    failures: list[str] = []
    expected_objects: set[str] = set()
    success = {200, 201, 204}
    refused = {409, 412}

    def etag(result):
        return header_value(result[1], "etag")

    def check(condition, message):
        if not condition and message not in failures: failures.append(message)

    def record(name, result, request_body=b"", request_headers=None, method=None, object_key=None, **extra):
        status, headers, data = result
        if method is None or object_key is None:
            raise ValueError("storage evidence requires method and key")
        event = {"operation": name, "method": method, "key": object_key, "status": status,
            "request_id": header_value(headers, "x-amz-request-id") or header_value(headers, "x-request-id"),
            "etag": etag(result), "request_headers": dict(request_headers or {}),
            "request_payload_sha256": hashlib.sha256(request_body).hexdigest(),
            "response_payload_sha256": hashlib.sha256(data).hexdigest()}
        event.update(extra)
        append_evidence(evidence, event, repository)
        return result

    unconditional_key = prefix + "control/unconditional"
    unconditional_body = b"ordinary"
    unconditional = record("put-unconditional", client.put(unconditional_key, unconditional_body), unconditional_body, method="PUT", object_key=unconditional_key)
    unconditional_etag = etag(unconditional)
    unconditional_head = record("head-unconditional", client.head(unconditional_key), method="HEAD", object_key=unconditional_key)
    unconditional_get = record("get-unconditional", client.get(unconditional_key), unconditional_body, method="GET", object_key=unconditional_key)
    unconditional_hash = hashlib.sha256(unconditional_body).hexdigest()
    check(unconditional[0] in success and bool(unconditional_etag), "unconditional PUT failed")
    check(
        unconditional_head[0] == unconditional_get[0] == 200
        and etag(unconditional_head) == etag(unconditional_get) == unconditional_etag
        and hashlib.sha256(unconditional_head[2]).hexdigest() == hashlib.sha256(b"").hexdigest()
        and unconditional_get[2] == unconditional_body
        and hashlib.sha256(unconditional_get[2]).hexdigest() == unconditional_hash,
        "unconditional PUT GET/HEAD bytes, hash, or ETag mismatch",
    )
    append_evidence(evidence, {"operation": "unconditional-verification", "method": "GET/HEAD", "key": unconditional_key, "etag": unconditional_etag,
        "expected_payload_sha256": unconditional_hash, "head_payload_sha256": hashlib.sha256(unconditional_head[2]).hexdigest(),
        "get_payload_sha256": hashlib.sha256(unconditional_get[2]).hexdigest(), "valid": not failures}, repository)
    unconditional_delete = record("delete-unconditional", client.delete(unconditional_key), method="DELETE", object_key=unconditional_key)
    unconditional_absent_head = record("head-after-delete-unconditional", client.head(unconditional_key), method="HEAD", object_key=unconditional_key)
    unconditional_absent_get = record("get-after-delete-unconditional", client.get(unconditional_key), method="GET", object_key=unconditional_key)
    check(unconditional_delete[0] in success and unconditional_absent_head[0] == unconditional_absent_get[0] == 404,
        "unconditional DELETE failed")
    if unconditional_absent_get[0] == 200: expected_objects.add(unconditional_key)

    key = prefix + "control/object"
    created = record("put-create", client.put(key, b"one", if_none_match=True), b"one", request_headers={"If-None-Match": "*"}, method="PUT", object_key=key)
    original = etag(created)
    check(created[0] in success and bool(original), "conditional create failed")
    head = record("head-created", client.head(key), method="HEAD", object_key=key); got = record("get-created", client.get(key), method="GET", object_key=key)
    check(head[0] == got[0] == 200 and etag(head) == etag(got) == original and got[2] == b"one", "created object did not match bytes/ETag")
    refused_create = record("put-create-refused", client.put(key, b"other", if_none_match=True), b"other", request_headers={"If-None-Match": "*"}, method="PUT", object_key=key)
    check(refused_create[0] in refused, "existing conditional create was not refused")
    unchanged = record("get-after-create-refused", client.get(key), method="GET", object_key=key)
    check(unchanged[0] == 200 and etag(unchanged) == original and unchanged[2] == b"one", "refused create changed object")
    replaced = record("put-replace", client.put(key, b"two", etag=original), b"two", request_headers={"If-Match": quote_etag(original)}, method="PUT", object_key=key)
    current = etag(replaced)
    check(replaced[0] in success and bool(current), "current conditional replace failed")
    current_get = record("get-after-replace", client.get(key), method="GET", object_key=key)
    check(current_get[0] == 200 and etag(current_get) == current and current_get[2] == b"two", "replacement bytes/ETag mismatch")
    stale_replace = record("put-stale-refused", client.put(key, b"bad", etag=original), b"bad", request_headers={"If-Match": quote_etag(original)}, method="PUT", object_key=key)
    check(stale_replace[0] in refused, "stale conditional replace was not refused")
    after_stale_replace = record("get-after-stale-replace", client.get(key), method="GET", object_key=key)
    check(after_stale_replace[0] == 200 and etag(after_stale_replace) == current and after_stale_replace[2] == b"two", "stale replace changed replacement")
    expected_objects.add(key)

    missing_replace_key = prefix + "control/missing-replace"
    missing_replace = record("put-replace-missing", client.put(missing_replace_key, b"bad", etag='"missing"'), b"bad", request_headers={"If-Match": '"missing"'}, method="PUT", object_key=missing_replace_key)
    check(missing_replace[0] in {404, *refused}, "missing conditional replace was not refused")
    check(record("head-after-missing-replace", client.head(missing_replace_key), method="HEAD", object_key=missing_replace_key)[0] == 404, "missing conditional replace created object")

    stale_delete_key = prefix + "control/stale-delete"
    stale_created = record("put-stale-delete-seed", client.put(stale_delete_key, b"old", if_none_match=True), b"old", request_headers={"If-None-Match": "*"}, method="PUT", object_key=stale_delete_key)
    stale_old = etag(stale_created)
    stale_replaced = record("put-stale-delete-replace", client.put(stale_delete_key, b"replacement", etag=stale_old), b"replacement", request_headers={"If-Match": quote_etag(stale_old)}, method="PUT", object_key=stale_delete_key)
    stale_current = etag(stale_replaced)
    check(stale_created[0] in success and stale_replaced[0] in success and bool(stale_current), "stale-delete setup failed")
    stale_delete = record("delete-stale-refused", client.delete(stale_delete_key, etag=stale_old), request_headers={"If-Match": quote_etag(stale_old)}, method="DELETE", object_key=stale_delete_key)
    check(stale_delete[0] in refused, "stale conditional DELETE was not refused")
    stale_final_head = record("head-after-stale-delete", client.head(stale_delete_key), method="HEAD", object_key=stale_delete_key)
    stale_final_get = record("get-after-stale-delete", client.get(stale_delete_key), method="GET", object_key=stale_delete_key)
    check(stale_final_head[0] == stale_final_get[0] == 200 and etag(stale_final_head) == etag(stale_final_get) == stale_current and stale_final_get[2] == b"replacement", "stale conditional DELETE did not preserve replacement")
    if stale_final_get[0] == 200: expected_objects.add(stale_delete_key)

    missing_delete_key = prefix + "control/missing-delete"
    missing_delete = record("delete-missing", client.delete(missing_delete_key, etag='"missing"'), request_headers={"If-Match": '"missing"'}, method="DELETE", object_key=missing_delete_key)
    check(missing_delete[0] in {404, *refused}, "missing conditional DELETE was not refused")
    check(record("head-after-delete-missing", client.head(missing_delete_key), method="HEAD", object_key=missing_delete_key)[0] == 404, "missing object appeared after conditional DELETE")

    current_delete_key = prefix + "control/current-delete"
    delete_seed = record("put-current-delete-seed", client.put(current_delete_key, b"delete-me", if_none_match=True), b"delete-me", request_headers={"If-None-Match": "*"}, method="PUT", object_key=current_delete_key)
    delete_current = record("delete-current", client.delete(current_delete_key, etag=etag(delete_seed)), request_headers={"If-Match": quote_etag(etag(delete_seed))}, method="DELETE", object_key=current_delete_key)
    check(delete_seed[0] in success and delete_current[0] in success, "current conditional DELETE failed")
    check(record("head-after-delete-current", client.head(current_delete_key), method="HEAD", object_key=current_delete_key)[0] == 404, "current conditional DELETE left object")

    race_create_key = prefix + "race/create"
    create_bodies = (b"create-a", b"create-b")
    with ThreadPoolExecutor(max_workers=2) as pool:
        creates = list(pool.map(lambda body: client.put(race_create_key, body, if_none_match=True), create_bodies))
    for index, (result, body) in enumerate(zip(creates, create_bodies), 1): record(f"race-create-{index}", result, body, request_headers={"If-None-Match": "*"}, method="PUT", object_key=race_create_key)
    create_winners = [(result, body) for result, body in zip(creates, create_bodies) if result[0] in success]
    create_losers = [result for result in creates if result[0] not in success]
    create_final = record("race-create-final", client.get(race_create_key), method="GET", object_key=race_create_key)
    check(len(create_winners) == 1 and len(create_losers) == 1 and create_losers[0][0] in refused, "create race did not produce one winner and one expected refusal")
    if len(create_winners) == 1:
        winner, body = create_winners[0]
        lineage_ok = bool(etag(winner)) and create_final[0] == 200 and create_final[2] == body and etag(create_final) == etag(winner)
        append_evidence(evidence, {"operation": "race-create-lineage", "method": "PUT", "key": race_create_key, "winning_response_etag": etag(winner), "final_etag": etag(create_final), "winning_payload_sha256": hashlib.sha256(body).hexdigest(), "final_payload_sha256": hashlib.sha256(create_final[2]).hexdigest(), "valid": lineage_ok}, repository)
        check(lineage_ok, "create race ETag lineage mismatch")
    else:
        append_evidence(evidence, {"operation": "race-create-lineage", "valid": False}, repository)
    if create_final[0] == 200: expected_objects.add(race_create_key)

    race_replace_key = prefix + "race/replace"
    race_seed = record("race-replace-seed", client.put(race_replace_key, b"seed", if_none_match=True), b"seed", request_headers={"If-None-Match": "*"}, method="PUT", object_key=race_replace_key)
    replace_bodies = (b"replace-a", b"replace-b")
    with ThreadPoolExecutor(max_workers=2) as pool:
        replaces = list(pool.map(lambda body: client.put(race_replace_key, body, etag=etag(race_seed)), replace_bodies))
    for index, (result, body) in enumerate(zip(replaces, replace_bodies), 1): record(f"race-replace-{index}", result, body, request_headers={"If-Match": quote_etag(etag(race_seed))}, method="PUT", object_key=race_replace_key)
    replace_winners = [(result, body) for result, body in zip(replaces, replace_bodies) if result[0] in success]
    replace_losers = [result for result in replaces if result[0] not in success]
    replace_final = record("race-replace-final", client.get(race_replace_key), method="GET", object_key=race_replace_key)
    check(len(replace_winners) == 1 and len(replace_losers) == 1 and replace_losers[0][0] in refused, "replace race did not produce one winner and one expected refusal")
    if len(replace_winners) == 1:
        winner, body = replace_winners[0]
        lineage_ok = bool(etag(race_seed)) and bool(etag(winner)) and replace_final[0] == 200 and replace_final[2] == body and etag(replace_final) == etag(winner)
        append_evidence(evidence, {"operation": "race-replace-lineage", "method": "PUT", "key": race_replace_key, "seed_etag": etag(race_seed), "winning_response_etag": etag(winner), "final_etag": etag(replace_final), "winning_payload_sha256": hashlib.sha256(body).hexdigest(), "final_payload_sha256": hashlib.sha256(replace_final[2]).hexdigest(), "valid": lineage_ok}, repository)
        check(lineage_ok, "replace race ETag lineage mismatch")
    else:
        append_evidence(evidence, {"operation": "race-replace-lineage", "seed_etag": etag(race_seed), "valid": False}, repository)
    if replace_final[0] == 200: expected_objects.add(race_replace_key)

    uncertain_key, uncertain_body = prefix + "reconcile", b"uncertain-write"
    discarded = client.put_discarded(uncertain_key, uncertain_body, if_none_match=True)
    reconciliation = client.reconcile_put_detailed(uncertain_key, uncertain_body)
    append_evidence(evidence, {"operation": "discarded-response-reconciliation", "method": "PUT", "key": uncertain_key, "request_headers": {"If-None-Match": "*"}, "outcome": discarded.value,
        "result": reconciliation.outcome.value,
        "expected_payload_sha256": hashlib.sha256(uncertain_body).hexdigest(),
        "probes": [probe.__dict__ for probe in reconciliation.probes]}, repository)
    check(discarded is Reconciliation.UNKNOWN, "discarded response was not unknown")
    check(reconciliation.outcome in {Reconciliation.COMMITTED, Reconciliation.DISCARDED}, "discarded response remained unresolved")
    if reconciliation.outcome is Reconciliation.COMMITTED: expected_objects.add(uncertain_key)

    listed = record("list", client.list(prefix), method="GET", object_key=prefix)
    listed_keys: set[str] = set()
    if listed[0] == 200:
        try:
            root = ElementTree.fromstring(listed[2])
            listed_keys = {element.text for element in root.iter() if element.tag.rsplit("}", 1)[-1] == "Key" and element.text}
        except ElementTree.ParseError:
            pass
    append_evidence(evidence, {"operation": "list-verification", "method": "GET", "key": prefix, "prefix": prefix, "listed_keys": sorted(listed_keys), "expected_keys": sorted(expected_objects)}, repository)
    check(listed[0] == 200 and expected_objects.issubset(listed_keys) and all(key.startswith(prefix) for key in listed_keys), "LIST did not prove fresh-prefix objects")

    result = StorageStatus.PASS if not failures else StorageStatus.NO_GO
    accepted_pass = result is StorageStatus.PASS
    cleanup_keys = expected_objects | {key for key in listed_keys if key.startswith(prefix)}
    cleanup_performed = False
    if cleanup and accepted_pass:
        cleanup_performed = True
        for index, cleanup_key in enumerate(sorted(cleanup_keys), 1):
            deleted = record(f"cleanup-delete-{index}", client.delete(cleanup_key), method="DELETE", object_key=cleanup_key, key=cleanup_key)
            absent = record(f"cleanup-head-{index}", client.head(cleanup_key), method="HEAD", object_key=cleanup_key, key=cleanup_key)
            check(deleted[0] in success and absent[0] == 404, "fresh-prefix cleanup failed")
        result = StorageStatus.PASS if not failures else StorageStatus.NO_GO
    append_evidence(evidence, {"operation": "storage-cleanup", "requested": cleanup,
        "performed": cleanup_performed, "eligible": accepted_pass,
        "preserved": not cleanup_performed}, repository)
    append_evidence(evidence, {"operation": "storage-result", "result": result.value, "failures": failures}, repository)
    return result


def _fence_time(value: Any) -> datetime.datetime:
    if not isinstance(value, str):
        raise ValueError("missing fence timestamp")
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid fence timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("fence timestamp must include timezone")
    return parsed


def validate_fence_evidence(evidence: Any, target: dict[str, Any], action: str) -> bool:
    """Accept only one exact, completed provider observation; everything else is unknown."""
    if action not in {"inspect", "power-off", "power-on"} or not isinstance(evidence, dict):
        return False
    required = {"action", "target", "request", "completion", "state", "observations"}
    if set(evidence) != required or evidence["action"] != action or evidence["target"] != target:
        return False
    request = evidence["request"]
    completion = evidence["completion"]
    observations = evidence["observations"]
    if (not isinstance(request, dict) or set(request) != {"id", "time"} or
            not isinstance(request["id"], str) or not request["id"] or
            not isinstance(completion, dict) or set(completion) != {"time"} or
            not isinstance(observations, list) or not observations):
        return False
    try:
        request_time = _fence_time(request["time"])
        completion_time = _fence_time(completion["time"])
    except ValueError:
        return False
    now = datetime.datetime.now(datetime.timezone.utc)
    if completion_time < request_time or now - completion_time > datetime.timedelta(seconds=FENCE_MAX_AGE) or completion_time - now > datetime.timedelta(seconds=30):
        return False
    seen: set[tuple[str, str]] = set()
    previous = None
    for observation in observations:
        if not isinstance(observation, dict) or set(observation) != {"time", "state"}:
            return False
        if not isinstance(observation["state"], str):
            return False
        try:
            observed_at = _fence_time(observation["time"])
        except ValueError:
            return False
        if observed_at - now > datetime.timedelta(seconds=30):
            return False
        key = (observation["time"], observation["state"])
        if key in seen or (previous is not None and observed_at <= previous):
            return False
        seen.add(key)
        previous = observed_at
    terminal = {"power-off": "offline", "power-on": "running"}.get(action)
    return (terminal is None or evidence["state"] == terminal) and evidence["state"] == observations[-1]["state"] and previous >= completion_time


def promotion_allowed(evidence: Any, target: dict[str, Any]) -> bool:
    return validate_fence_evidence(evidence, target, "power-off")


def invoke_fence(command: Path, action: str, target: dict[str, Any], *, timeout: float = 60.0) -> dict[str, Any]:
    """Invoke the operator-owned executable without a shell or secret-bearing arguments."""
    if action not in {"inspect", "power-off", "power-on"} or not isinstance(target, dict) or not target:
        return {"valid": False, "reason": "invalid request"}
    try:
        command = _absolute_no_symlinks(command)
        parent = command.parent
        while True:
            st = parent.stat()
            trusted_sticky = stat.S_ISDIR(st.st_mode) and bool(st.st_mode & stat.S_ISVTX)
            if st.st_uid not in (0, os.getuid()) or ((st.st_mode & 0o022) and not trusted_sticky):
                return {"valid": False, "reason": "fence command parent is not trusted"}
            if parent == Path(parent.anchor):
                break
            parent = parent.parent
        if (command.is_symlink() or not command.is_file() or not os.access(command, os.X_OK)
                or command.stat().st_uid != os.getuid() or stat.S_IMODE(command.stat().st_mode) != 0o700
                or command.is_relative_to(Path(__file__).resolve().parents[2])):
            return {"valid": False, "reason": "fence command is not a private executable"}
        try:
            json.dumps(target, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            return {"valid": False, "reason": "invalid request"}
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix="hat-fence-", suffix=".json", delete=False) as target_file:
            json.dump(target, target_file, sort_keys=True, separators=(",", ":"))
            target_path = Path(target_file.name)
        os.chmod(target_path, 0o600)
        try:
            result = subprocess.run([str(command), action, str(target_path)], capture_output=True, timeout=timeout, check=False)
        finally:
            target_path.unlink(missing_ok=True)
        if result.returncode != 0:
            return {"valid": False, "reason": "fence command failed or returned non-single JSON"}
        try:
            stdout = result.stdout.decode("utf-8")
        except UnicodeDecodeError:
            return {"valid": False, "reason": "malformed fence evidence"}
        if not stdout.strip() or stdout.count("\n") > 1:
            return {"valid": False, "reason": "fence command failed or returned non-single JSON"}
        try:
            evidence = json.loads(stdout)
        except json.JSONDecodeError:
            return {"valid": False, "reason": "malformed fence evidence"}
        return {"valid": validate_fence_evidence(evidence, target, action), "evidence": evidence}
    except (OSError, subprocess.TimeoutExpired):
        return {"valid": False, "reason": "fence outcome unknown"}
    except Exception:
        return {"valid": False, "reason": "fence outcome unknown"}


def _target_digest(target: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(target, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _fence_coordinator_event(action: str, target: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    provider = result.get("evidence") if isinstance(result.get("evidence"), dict) else {}
    event: dict[str, Any] = {
        "operation": "fence-inspect",
        "action": action,
        "target_sha256": _target_digest(target),
        "target_match": provider.get("target") == target if "target" in provider else False,
        "valid": bool(result.get("valid")),
        "request": provider.get("request"),
        "completion": provider.get("completion"),
        "state": provider.get("state"),
        "observations": provider.get("observations"),
        "failure_reason": result.get("reason"),
        "result": "PASS" if result.get("valid") else "NO-GO",
    }
    return redact(event)


def storage(nodes=None, context=None, evidence=None, repository=None, *, s3_env=None, cleanup=False) -> StorageStatus:
    """Return a bounded NO-GO and preserve evidence when a provider operation raises."""
    try:
        return _storage_matrix(nodes, context, evidence, repository, s3_env=s3_env, cleanup=cleanup)
    except Exception as exc:
        failure = "storage operation raised before matrix completion"
        try:
            append_evidence(evidence, {"operation": "storage-error", "exception_type": type(exc).__name__, "failure": failure}, repository)
            append_evidence(evidence, {"operation": "storage-result", "result": StorageStatus.NO_GO.value, "failures": [failure]}, repository)
        except Exception:
            pass
        return StorageStatus.NO_GO


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] in {"__remote-provision", "__remote-verify"}:
        if len(argv) != 2:
            raise ValueError("remote provisioning requires one root")
        result = remote_provision(Path(argv[1])) if argv[0] == "__remote-provision" else _remote_verify(Path(argv[1]))
        print(json.dumps(result, sort_keys=True))
        return 0
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario", choices=["preflight", "init-remote", "provision", "storage", "fence-inspect"])
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--linode-env", type=Path)
    parser.add_argument("--s3-env", type=Path)
    parser.add_argument("--fence-command", type=Path)
    parser.add_argument("--cleanup", action="store_true", help="delete fresh-prefix objects only after a passing matrix")
    args = parser.parse_args(argv)
    repository = Path(__file__).resolve().parents[2]
    if args.scenario == "fence-inspect":
        if args.inventory is None or args.fence_command is None:
            parser.error("--inventory and --fence-command are required")
        context = new_run_context(args.work_root, repository)
        evidence = context.local_root / "evidence.jsonl"
        overall = True
        try:
            nodes = load_inventory(args.inventory, repository)
            for node in nodes:
                target = {"node": node.name, "instance_id": node.instance_id,
                          "provider_label": node.provider_label, "address": node.address,
                          "host_key": node.host_key}
                result = invoke_fence(args.fence_command, "inspect", target)
                append_evidence(evidence, _fence_coordinator_event("inspect", target, result), repository)
                if not result.get("valid"):
                    overall = False
                    print(f"fence inspect failed for {node.name}", file=sys.stderr)
                else:
                    print(f"fence inspect passed for {node.name}")
            append_evidence(evidence, {"operation": "fence-inspect-result", "result": "PASS" if overall else "NO-GO"}, repository)
        except Exception as exc:
            overall = False
            try:
                append_evidence(evidence, {"operation": "fence-inspect-error", "result": "NO-GO",
                                           "failure_reason": "coordinator failure", "exception_type": type(exc).__name__}, repository)
                append_evidence(evidence, {"operation": "fence-inspect-result", "result": "NO-GO"}, repository)
            except Exception:
                pass
        finally:
            write_latest_fence_evidence_pointer(evidence)
        return 0 if overall else 2
    if args.scenario == "storage":
        context = new_run_context(args.work_root, repository)
        evidence = context.local_root / "evidence.jsonl"
        try:
            result = storage(context=context, evidence=evidence, repository=repository, s3_env=args.s3_env, cleanup=args.cleanup)
        finally:
            write_latest_storage_evidence_pointer(evidence)
        print(f"storage {result.value}")
        return 0 if result is StorageStatus.PASS else 2
    if args.inventory is None or args.linode_env is None:
        parser.error("--inventory and --linode-env are required")
    if args.scenario == "provision" and args.fence_command is None:
        parser.error("provision requires --fence-command for pre-reboot identity confirmation")
    if args.scenario == "provision":
        context = None
        evidence = None
        try:
            nodes = load_inventory(args.inventory, repository)
            load_linode_env(args.linode_env, nodes, repository)
            context = new_run_context(args.work_root, repository)
            evidence = context.local_root / "evidence.jsonl"
            preflight(nodes, context, evidence, repository, inventory_path=args.inventory, linode_env=args.linode_env)
            init_remote(nodes, context, evidence, repository, inventory_path=args.inventory, linode_env=args.linode_env)
            result = provision(nodes, context, evidence, repository, inventory_path=args.inventory,
                               linode_env=args.linode_env, fence_command=args.fence_command)
        except Exception as exc:
            _append_provision_no_go(evidence, repository, stage="preflight/init", exc=exc)
            print("provision NO-GO")
            return 2
        if result is StorageStatus.NO_GO:
            print("provision NO-GO")
            return 2
        print(f"provision passed: {len(nodes)} nodes")
        return 0

    nodes = load_inventory(args.inventory, repository)
    load_linode_env(args.linode_env, nodes, repository)
    if args.scenario in {"preflight", "provision"}:
        context = new_run_context(args.work_root, repository)
        evidence = context.local_root / "evidence.jsonl"
        preflight(nodes, context, evidence, repository, inventory_path=args.inventory, linode_env=args.linode_env)
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
