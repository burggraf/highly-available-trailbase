#!/usr/bin/env python3
"""Local M0 process-safety harness."""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import shutil
from dataclasses import dataclass
from pathlib import Path


FIXTURE_USERNAME = "m0user"

OPS_SQL = """CREATE TABLE hat_ops (\n  id INTEGER PRIMARY KEY,\n  op_key TEXT NOT NULL UNIQUE,\n  payload TEXT NOT NULL\n) STRICT;\n"""

CONFIG_TEXTPROTO = """server { application_name: \"HAT M0\" site_url: \"http://localhost\" }\nauth { user_identifier: ONLY_USERNAME }\ndatabases: [{ name: \"aux\" }]\nrecord_apis: [{\n  name: \"main_ops\"\n  table_name: \"hat_ops\"\n  acl_authenticated: [CREATE, READ, UPDATE, DELETE, SCHEMA]\n}, {\n  name: \"aux_ops\"\n  table_name: \"aux.hat_ops\"\n  attached_databases: [\"aux\"]\n  acl_authenticated: [CREATE, READ, UPDATE, DELETE, SCHEMA]\n}]\njobs {\n  system_jobs: [\n    { id: BACKUP schedule: \"@daily\" disabled: true },\n    { id: HEARTBEAT schedule: \"17 * * * * * *\" disabled: true },\n    { id: LOG_CLEANER schedule: \"@hourly\" disabled: true },\n    { id: AUTH_CLEANER schedule: \"@hourly\" disabled: true },\n    { id: QUERY_OPTIMIZER schedule: \"@daily\" disabled: true },\n    { id: FILE_DELETIONS schedule: \"@hourly\" disabled: true },\n    { id: ANONYMOUS_CLEANER schedule: \"@daily\" disabled: true }\n  ]\n}\n"""


@dataclass
class OwnedProcess:
    process: subprocess.Popen
    role: str


def require_private_run_root(root: Path, repository: Path) -> Path:
    root = root.expanduser().absolute()
    repository = repository.expanduser().absolute()
    try:
        root.relative_to(repository)
    except ValueError:
        pass
    else:
        raise ValueError("run root must be outside the repository")
    if root.exists():
        if root.is_symlink() or not root.is_dir() or any(root.iterdir()):
            raise ValueError("run root must be a new empty directory")
    else:
        root.mkdir(mode=0o700, parents=True)
    root.chmod(0o700)
    return root


def normalize_txid(value: int | str) -> int:
    if isinstance(value, bool):
        raise ValueError("invalid txid")
    if isinstance(value, int):
        if value < 0:
            raise ValueError("invalid txid")
        return value
    text = value.strip().lower()
    if not text:
        raise ValueError("invalid txid")
    try:
        return int(text, 16)
    except ValueError as exc:
        raise ValueError("invalid txid") from exc


def read_txid_sidecar(path: Path) -> int:
    try:
        return normalize_txid(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"cannot read txid sidecar: {path}") from exc


def require_files(paths: list[Path]) -> None:
    missing = [str(path) for path in paths if not path.is_file() or path.is_symlink()]
    if missing:
        raise FileNotFoundError("required files missing: " + ", ".join(missing))


def parse_follower_line(line: str) -> dict[str, object]:
    stripped = line.strip()
    try:
        value = json.loads(stripped)
    except json.JSONDecodeError:
        value = {}
        if "level=ERROR" in stripped or "follow: error applying updates" in stripped:
            value["error"] = True
            value["message"] = stripped
        return value
    if not isinstance(value, dict):
        return {}
    if "txid" in value:
        value["txid"] = normalize_txid(value["txid"])
    return value


def promotion_error_gate(events: list[dict[str, object]]) -> None:
    if any(event.get("error") for event in events):
        raise RuntimeError("follower error gate failed")


def write_fixture(depot: Path) -> None:
    depot = depot.absolute()
    depot.mkdir(mode=0o700, parents=True, exist_ok=False)
    (depot / "migrations" / "main").mkdir(parents=True)
    (depot / "migrations" / "aux").mkdir(parents=True)
    (depot / "config.textproto").write_text(CONFIG_TEXTPROTO, encoding="utf-8")
    for database in ("main", "aux"):
        (depot / "migrations" / database / "U100__hat_ops.sql").write_text(OPS_SQL, encoding="utf-8")


def validate_inventory(paths: dict[str, Path]) -> dict[str, Path]:
    required = {"main", "session", "aux"}
    if set(paths) != required:
        raise ValueError(f"database inventory must be exactly {sorted(required)}")
    resolved = {name: path.expanduser().absolute() for name, path in paths.items()}
    if len(set(resolved.values())) != len(resolved):
        raise ValueError("database inventory contains aliased paths")
    return resolved


def parse_binary_versions(trail_output: str, litestream_output: str) -> dict[str, str]:
    trail_match = re.search(r"\bv(\d+\.\d+\.\d+)", trail_output)
    litestream_match = re.fullmatch(r"\s*(\d+\.\d+\.\d+)\s*", litestream_output)
    if not trail_match or not litestream_match:
        raise ValueError("unrecognized binary version output")
    return {"trail": trail_match.group(1), "litestream": litestream_match.group(1)}


def validate_binary_versions(expected: dict[str, str], actual: dict[str, str]) -> None:
    if expected != actual:
        raise ValueError(f"binary versions do not match: expected {expected}, got {actual}")


def require_stopped(children: list[OwnedProcess]) -> None:
    live = [child.role for child in children if child.process.poll() is None]
    if live:
        raise RuntimeError("cannot promote while processes are alive: " + ", ".join(live))


def stop_owned(children: list[OwnedProcess], timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    for child in children:
        if child.process.poll() is None:
            try:
                os.killpg(child.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    for child in children:
        remaining = max(0.0, deadline - time.monotonic())
        if child.process.poll() is None:
            try:
                child.process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(child.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.process.wait()


def free_loopback_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def http_request(method: str, url: str, body: dict | None = None, token: str | None = None) -> tuple[int, bytes]:
    headers = {"Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        response = urllib.request.urlopen(request, timeout=5)
    except urllib.error.HTTPError as exc:
        response = exc
    return response.status, response.read()


def http_json(method: str, url: str, body: dict | None = None, token: str | None = None) -> tuple[int, object]:
    status, raw = http_request(method, url, body, token)
    try:
        decoded = json.loads(raw) if raw else None
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"non-JSON response from {url}: {raw[:200]!r}") from exc
    return status, decoded


def wait_ready(base_url: str, child: OwnedProcess, timeout: float = 60) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if child.process.poll() is not None:
            raise RuntimeError(f"{child.role} exited before readiness: {child.process.returncode}")
        try:
            health, _ = http_request("GET", f"{base_url}/api/healthcheck")
            probe, _ = http_request("GET", f"{base_url}/api/records/v1/main_ops")
            if health == 200 and probe in (401, 403):
                return
        except (OSError, RuntimeError):
            pass
        time.sleep(0.1)
    raise RuntimeError(f"{child.role} readiness timed out")


def owned_process(argv: list[str], role: str, cwd: Path, log_path: Path) -> OwnedProcess:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    stream = log_path.open("w", encoding="utf-8")
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=stream,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        close_fds=True,
        env={"PATH": os.environ.get("PATH", ""), "PYTHONUNBUFFERED": "1"},
    )
    return OwnedProcess(process, role)


def run_fixture(trail: Path, litestream: Path, root: Path) -> int:
    actual_versions = parse_binary_versions(
        subprocess.run([str(trail), "--version"], capture_output=True, text=True, timeout=10, check=True).stdout,
        subprocess.run([str(litestream), "version"], capture_output=True, text=True, timeout=10, check=True).stdout,
    )
    validate_binary_versions({"trail": "0.33.11", "litestream": "0.5.17"}, actual_versions)
    depots = {name: root / name / "traildepot" for name in ("a", "b", "c")}
    for depot in depots.values():
        write_fixture(depot)
    username = FIXTURE_USERNAME
    password = "m0-local-only-password"
    port = free_loopback_port()
    base = f"http://127.0.0.1:{port}"
    child = owned_process(
        [str(trail), "--depot", str(depots["a"]), "run", "--address", f"127.0.0.1:{port}", "--stderr-logging"],
        "trail-a-bootstrap", root, root / "logs" / "trail-a-bootstrap.log",
    )
    try:
        wait_ready(base, child)
        status, registered = http_request("POST", f"{base}/api/auth/v1/register", {
            "username": username, "password": password, "password_repeat": password,
        })
        if status != 200 or registered != b"registered":
            raise RuntimeError(f"registration contract mismatch: status={status}, body={registered[:200]!r}")
    finally:
        stop_owned([child])
    require_stopped([child])
    secrets = depots["a"] / "secrets"
    if not secrets.is_dir():
        raise RuntimeError("TrailBase bootstrap did not create required secrets")
    for name in ("b", "c"):
        shutil.copytree(secrets, depots[name] / "secrets")
    child = owned_process(
        [str(trail), "--depot", str(depots["a"]), "run", "--address", f"127.0.0.1:{port}", "--stderr-logging"],
        "trail-a", root, root / "logs" / "trail-a.log",
    )
    try:
        wait_ready(base, child)
        status, login = http_json("POST", f"{base}/api/auth/v1/login", {"username": username, "password": password})
        if status != 200 or not isinstance(login, dict) or not login.get("auth_token") or not login.get("refresh_token"):
            raise RuntimeError(f"login contract mismatch: status={status}, body={login}")
        token = str(login["auth_token"])
        refresh = str(login["refresh_token"])
        status, second_login = http_json("POST", f"{base}/api/auth/v1/login", {"username": username, "password": password})
        if status != 200 or not isinstance(second_login, dict) or not second_login.get("refresh_token"):
            raise RuntimeError(f"second login contract mismatch: status={status}, body={second_login}")
        revoked_refresh = str(second_login["refresh_token"])
        status, logout_body = http_request("POST", f"{base}/api/auth/v1/logout", {"refresh_token": revoked_refresh})
        if status != 200 or logout_body:
            raise RuntimeError(f"logout contract mismatch: status={status}, body={logout_body[:200]!r}")
        status, _ = http_json("POST", f"{base}/api/auth/v1/refresh", {"refresh_token": revoked_refresh})
        if status == 200:
            raise RuntimeError("revoked refresh token remained valid")
        for api, row_id in (("main_ops", 900001), ("aux_ops", 900002)):
            status, created = http_json("POST", f"{base}/api/records/v1/{api}", {"id": row_id, "op_key": f"scratch-{api}", "payload": "create"}, token)
            if status not in (200, 201) or not isinstance(created, dict) or len(created.get("ids", [])) != 1:
                raise RuntimeError(f"record create contract mismatch for {api}: {status} {created}")
            returned_id = created["ids"][0]
            status, record = http_json("GET", f"{base}/api/records/v1/{api}/{returned_id}", token=token)
            if status != 200 or not isinstance(record, dict) or record.get("payload") != "create":
                raise RuntimeError(f"record read contract mismatch for {api}: {status} {record}")
            status, _ = http_json("PATCH", f"{base}/api/records/v1/{api}/{returned_id}", {"payload": "updated"}, token)
            if status not in (200, 204):
                raise RuntimeError(f"record patch contract mismatch for {api}: {status}")
            status, deleted = http_request("DELETE", f"{base}/api/records/v1/{api}/{returned_id}", token=token)
            if status != 200 or deleted != b"deleted":
                raise RuntimeError(f"record delete contract mismatch for {api}: {status} {deleted[:200]!r}")
            status, _ = http_json("GET", f"{base}/api/records/v1/{api}/{returned_id}", token=token)
            if status != 404:
                raise RuntimeError(f"deleted record remained for {api}: {status}")
        status, _ = http_json("POST", f"{base}/api/auth/v1/refresh", {"refresh_token": refresh})
        if status != 200:
            raise RuntimeError(f"retained refresh failed: {status}")
        status, _ = http_json("GET", f"{base}/api/records/v1/main_ops")
        if status not in (401, 403):
            raise RuntimeError(f"unauthenticated read unexpectedly allowed: {status}")
        require_files([depots["a"] / "data" / f"{name}.db" for name in ("main", "session", "aux")])
        if any((depots[name] / "data").exists() for name in ("b", "c")):
            raise RuntimeError("standby was initialized")
        version = subprocess.run([str(trail), "--version"], capture_output=True, text=True, timeout=10, check=True).stdout.splitlines()
        (root / "result.json").write_text(json.dumps({
            "scenario": "fixture",
            "status": "PASS",
            "trail_version": version,
            "databases": ["main", "session", "aux"],
            "auth": {"retained_refresh": "accepted", "revoked_refresh": "rejected"},
            "standbys_initialized": False,
        }, indent=2) + "\n")
    finally:
        stop_owned([child])
    return 0


def run_preflight(trail: Path, litestream: Path, root: Path) -> int:
    if not trail.is_file() or not os.access(trail, os.X_OK):
        raise RuntimeError(f"TrailBase executable is not runnable: {trail}")
    if not litestream.is_file() or not os.access(litestream, os.X_OK):
        raise RuntimeError(f"Litestream executable is not runnable: {litestream}")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    commands = [
        [str(trail), "--version"],
        [str(trail), "--help"],
        [str(trail), "run", "--help"],
        [str(trail), "user", "add", "--help"],
        [str(litestream), "version"],
        [str(litestream), "restore", "-h"],
        [str(litestream), "replicate", "-h"],
        [str(litestream), "sync", "-h"],
    ]
    results = []
    for argv in commands:
        completed = subprocess.run(argv, cwd=root, capture_output=True, text=True, timeout=30)
        results.append({"argv": argv, "returncode": completed.returncode,
                        "stdout": completed.stdout, "stderr": completed.stderr})
    (root / "preflight.json").write_text(json.dumps({
        "python": sys.version,
        "sqlite": __import__("sqlite3").sqlite_version,
        "commands": results,
    }, indent=2) + "\n", encoding="utf-8")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trail", type=Path)
    parser.add_argument("--litestream", type=Path)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--scenario", choices=["preflight", "fixture", "follow", "graceful", "crash", "lagged-crash", "guards", "all"], required=True)
    parser.add_argument("--repeat", type=int, default=1)
    args = parser.parse_args(argv)
    root = require_private_run_root(args.work_root / f"run-{time.time_ns()}", Path(__file__).resolve().parents[2])
    if args.scenario == "preflight":
        if not args.trail or not args.litestream:
            parser.error("preflight requires --trail and --litestream")
        return run_preflight(args.trail.absolute(), args.litestream.absolute(), root)
    if args.scenario == "fixture":
        if not args.trail or not args.litestream:
            parser.error("fixture requires --trail and --litestream")
        return run_fixture(args.trail.absolute(), args.litestream.absolute(), root)
    raise RuntimeError(f"scenario not implemented yet: {args.scenario}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        raise SystemExit(2)
