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
import sqlite3
import hashlib
import shlex
from dataclasses import dataclass
from pathlib import Path


FIXTURE_USERNAME = "m0user"

OPS_SQL = """CREATE TABLE hat_ops (\n  id INTEGER PRIMARY KEY,\n  op_key TEXT NOT NULL UNIQUE,\n  payload TEXT NOT NULL\n) STRICT;\n"""

CONFIG_TEXTPROTO = """server { application_name: \"HAT M0\" site_url: \"http://localhost\" }\nauth { user_identifier: ONLY_USERNAME }\ndatabases: [{ name: \"aux\" }]\nrecord_apis: [{\n  name: \"main_ops\"\n  table_name: \"hat_ops\"\n  acl_authenticated: [CREATE, READ, UPDATE, DELETE, SCHEMA]\n}, {\n  name: \"aux_ops\"\n  table_name: \"aux.hat_ops\"\n  attached_databases: [\"aux\"]\n  acl_authenticated: [CREATE, READ, UPDATE, DELETE, SCHEMA]\n}]\njobs {\n  system_jobs: [\n    { id: BACKUP schedule: \"@daily\" disabled: true },\n    { id: HEARTBEAT schedule: \"17 * * * * * *\" disabled: true },\n    { id: LOG_CLEANER schedule: \"@hourly\" disabled: true },\n    { id: AUTH_CLEANER schedule: \"@hourly\" disabled: true },\n    { id: QUERY_OPTIMIZER schedule: \"@daily\" disabled: true },\n    { id: FILE_DELETIONS schedule: \"@hourly\" disabled: true },\n    { id: ANONYMOUS_CLEANER schedule: \"@daily\" disabled: true }\n  ]\n}\n"""


class CorrectnessFailure(RuntimeError):
    pass


@dataclass
class OwnedProcess:
    process: subprocess.Popen
    role: str
    log_path: Path | None = None


def require_private_run_root(root: Path, repository: Path) -> Path:
    root = root.expanduser().resolve(strict=False)
    repository = repository.expanduser().resolve(strict=False)
    try:
        root.relative_to(repository)
    except ValueError:
        pass
    else:
        raise ValueError("run root must be outside the repository")
    if root.exists():
        raise ValueError("run root must not already exist")
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


def format_txid(value: int) -> str:
    if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("txid out of range")
    return f"{value:016x}"


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
    if not stripped:
        return {}
    try:
        value = json.loads(stripped)
    except json.JSONDecodeError:
        try:
            fields = dict(part.split("=", 1) for part in shlex.split(stripped) if "=" in part)
        except ValueError:
            return {"unrecognized": True, "message": stripped}
        if not {"level", "msg"}.issubset(fields):
            return {"unrecognized": True, "message": stripped}
        return {
            "level": fields["level"], "message": fields["msg"],
            "error": fields["level"].upper() == "ERROR" or "error applying updates" in fields["msg"],
        }
    if not isinstance(value, dict):
        return {"unrecognized": True, "message": stripped}
    if "txid" in value:
        value["txid"] = normalize_txid(value["txid"])
    value["error"] = str(value.get("level", "")).upper() == "ERROR" or bool(value.get("error"))
    return value


def promotion_error_gate(events: list[dict[str, object]]) -> None:
    if any(event.get("error") or event.get("unrecognized") for event in events):
        raise CorrectnessFailure("follower error gate failed")


def check_follower_log(child: OwnedProcess) -> None:
    if child.log_path and child.log_path.exists():
        events = [parse_follower_line(line) for line in child.log_path.read_text(errors="replace").splitlines()]
        promotion_error_gate(events)


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
    resolved = {name: path.expanduser().resolve(strict=False) for name, path in paths.items()}
    if len(set(resolved.values())) != len(resolved):
        raise ValueError("database inventory contains aliased paths")
    return paths


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
    return OwnedProcess(process, role, log_path)


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
        private_auth = root / "fixture-private.json"
        private_auth.write_text(json.dumps({"retained_refresh": refresh, "revoked_refresh": revoked_refresh}) + "\n")
        private_auth.chmod(0o600)
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


def write_litestream_config(root: Path, source: Path) -> tuple[Path, Path]:
    socket_path = root / "a.sock"
    if len(str(socket_path).encode()) >= 100:
        raise ValueError("Litestream socket path is too long")
    lines = [
        "socket:", "  enabled: true", f"  path: {json.dumps(str(socket_path))}", "  permissions: 0600",
        "retention:", "  enabled: false", "logging:", "  type: json", "dbs:",
    ]
    for name in ("main", "session", "aux"):
        database = source / f"{name}.db"
        lines.extend([
            f"  - path: {json.dumps(str(database))}",
            f"    meta-path: {json.dumps(str(root / 'meta' / 'e1' / name))}",
            "    replica:", "      type: file",
            f"      path: {json.dumps(str(root / 'backup' / 'e1' / name))}",
            "      sync-interval: 1s",
        ])
    path = root / "a.yml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path, socket_path


def sync_database(litestream: Path, socket_path: Path, database: Path) -> dict[str, object]:
    completed = subprocess.run(
        [str(litestream), "sync", "-socket", str(socket_path), "-wait", "-json", str(database)],
        capture_output=True, text=True, timeout=60,
    )
    if completed.returncode:
        raise RuntimeError(f"Litestream sync failed for {database.name}: {completed.stderr[-500:]}")
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"unrecognized Litestream sync output: {completed.stdout[-500:]}") from exc
    if not isinstance(result, dict) or "replica_txid" not in result:
        raise RuntimeError(f"Litestream sync omitted replica_txid: {result}")
    return result


def wait_for_path(path: Path, child: OwnedProcess, timeout: float = 60) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if child.process.poll() is not None:
            raise RuntimeError(f"{child.role} exited while waiting for {path}")
        if path.exists():
            return
        time.sleep(0.1)
    raise RuntimeError(f"timed out waiting for {path}")


def wait_for_txid(sidecar: Path, target: int, child: OwnedProcess, timeout: float = 60) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if child.process.poll() is not None:
            raise RuntimeError(f"{child.role} exited before txid {target:x}")
        check_follower_log(child)
        if sidecar.is_file():
            current = read_txid_sidecar(sidecar)
            if current >= target:
                return current
        time.sleep(0.1)
    raise RuntimeError(f"timed out waiting for {sidecar.name} to reach {target:x}")


def backup_inventory(path: Path) -> dict[str, str]:
    return {
        str(file.relative_to(path)): hashlib.sha256(file.read_bytes()).hexdigest()
        for file in sorted(path.rglob("*")) if file.is_file()
    }


def sqlite_rows(path: Path, tables: tuple[str, ...]) -> dict[str, object]:
    require_files([path])
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        connection.execute("PRAGMA ignore_check_constraints=ON")
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        if integrity != ("ok",):
            raise CorrectnessFailure(f"structural integrity failed for {path}: {integrity}")
        foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchall()
        if foreign_key_errors:
            raise CorrectnessFailure(f"foreign key check failed for {path}: {foreign_key_errors[:10]}")
        result: dict[str, object] = {
            "__schema__": connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_schema "
                "WHERE name NOT LIKE 'sqlite_%' AND name != '_litestream_lock' ORDER BY type, name"
            ).fetchall()
        }
        present = {row[0] for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
        for table in tables:
            if table not in present:
                raise RuntimeError(f"required table {table} missing from {path}")
            result[table] = connection.execute(f'SELECT * FROM "{table}" ORDER BY rowid').fetchall()
        return result
    finally:
        connection.close()


def run_follow(trail: Path, litestream: Path, root: Path) -> int:
    run_fixture(trail, litestream, root)
    depots = {name: root / name / "traildepot" for name in ("a", "b", "c")}
    source_data = depots["a"] / "data"
    paths = validate_inventory({name: source_data / f"{name}.db" for name in ("main", "session", "aux")})
    config, socket_path = write_litestream_config(root, source_data)
    port = free_loopback_port()
    base = f"http://127.0.0.1:{port}"
    trail_child: OwnedProcess | None = None
    replicator: OwnedProcess | None = None
    followers: list[OwnedProcess] = []
    initial: dict[str, int] = {}
    final: dict[str, int] = {}
    selected: dict[str, int] = {}
    try:
        trail_child = owned_process(
            [str(trail), "--depot", str(depots["a"]), "run", "--address", f"127.0.0.1:{port}", "--stderr-logging"],
            "trail-a", root, root / "logs" / "follow-trail-a.log",
        )
        replicator = owned_process(
            [str(litestream), "replicate", "-config", str(config)],
            "litestream-a", root, root / "logs" / "replicator-a.log",
        )
        wait_ready(base, trail_child)
        wait_for_path(socket_path, replicator)
        status, login = http_json("POST", f"{base}/api/auth/v1/login", {"username": FIXTURE_USERNAME, "password": "m0-local-only-password"})
        if status != 200 or not isinstance(login, dict):
            raise RuntimeError(f"follow login failed: {status} {login}")
        token = str(login["auth_token"])
        fixture_auth = json.loads((root / "fixture-private.json").read_text())
        baseline_retained_status, _ = http_json("POST", f"{base}/api/auth/v1/refresh", {"refresh_token": fixture_auth["retained_refresh"]})
        baseline_revoked_status, _ = http_json("POST", f"{base}/api/auth/v1/refresh", {"refresh_token": fixture_auth["revoked_refresh"]})
        if baseline_retained_status != 200 or baseline_revoked_status == 200:
            raise RuntimeError("pre-existing retained/revoked session state was not preserved")
        for name, database in paths.items():
            synced = sync_database(litestream, socket_path, database)
            initial[name] = normalize_txid(synced["replica_txid"])
        for name in ("main", "session", "aux"):
            output = depots["b"] / "data" / f"{name}.db"
            output.parent.mkdir(parents=True, exist_ok=True)
            child = owned_process(
                [str(litestream), "restore", "-f", "-follow-interval", "1s", "-o", str(output), (root / "backup" / "e1" / name).as_uri()],
                f"follower-b-{name}", root, root / "logs" / f"follower-b-{name}.log",
            )
            followers.append(child)
            initial[name] = wait_for_txid(output.with_name(output.name + "-txid"), initial[name], child)
        payload = "x" * 8192
        business_positions = {name: initial[name] for name in ("main", "aux")}
        follower_by_name = dict(zip(("main", "session", "aux"), followers))
        for start, end in ((1, 51), (51, 101)):
            for index in range(start, end):
                for api, prefix, offset in (("main_ops", "main", 0), ("aux_ops", "aux", 100000)):
                    row_id = offset + index
                    status, created = http_json("POST", f"{base}/api/records/v1/{api}", {
                        "id": row_id, "op_key": f"e1-{prefix}-{index:06d}", "payload": payload,
                    }, token)
                    if status not in (200, 201) or not isinstance(created, dict) or created.get("ids") != [str(row_id)]:
                        raise RuntimeError(f"measured write failed for {api}/{row_id}: {status} {created}")
            for name in ("main", "aux"):
                observed = normalize_txid(sync_database(litestream, socket_path, paths[name])["replica_txid"])
                if observed <= business_positions[name]:
                    raise RuntimeError(f"{name} did not advance after business batch")
                wait_for_txid(depots["b"] / "data" / f"{name}.db-txid", observed, follower_by_name[name])
                business_positions[name] = observed
        status, retained = http_json("POST", f"{base}/api/auth/v1/login", {"username": FIXTURE_USERNAME, "password": "m0-local-only-password"})
        status2, revoked = http_json("POST", f"{base}/api/auth/v1/login", {"username": FIXTURE_USERNAME, "password": "m0-local-only-password"})
        if status != 200 or status2 != 200 or not isinstance(retained, dict) or not isinstance(revoked, dict):
            raise RuntimeError("new session creation failed")
        session_first = sync_database(litestream, socket_path, paths["session"])
        session_first_txid = normalize_txid(session_first["replica_txid"])
        if session_first_txid <= initial["session"]:
            raise RuntimeError("session follower did not observe creation advancement")
        wait_for_txid(depots["b"] / "data" / "session.db-txid", session_first_txid, followers[1])
        logout_status, _ = http_request("POST", f"{base}/api/auth/v1/logout", {"refresh_token": revoked["refresh_token"]})
        retained_status, _ = http_json("POST", f"{base}/api/auth/v1/refresh", {"refresh_token": retained["refresh_token"]})
        revoked_status, _ = http_json("POST", f"{base}/api/auth/v1/refresh", {"refresh_token": revoked["refresh_token"]})
        if logout_status != 200 or retained_status != 200 or revoked_status == 200:
            raise RuntimeError("new retained/revoked session outcomes failed")
        session_second = sync_database(litestream, socket_path, paths["session"])
        session_second_txid = normalize_txid(session_second["replica_txid"])
        if session_second_txid <= session_first_txid:
            raise RuntimeError("session follower did not observe revocation advancement")
        for name, database in paths.items():
            synced = sync_database(litestream, socket_path, database)
            final[name] = normalize_txid(synced["replica_txid"])
            if final[name] <= initial[name]:
                raise RuntimeError(f"{name} did not advance beyond initial restore")
        if trail_child.process.poll() is not None:
            raise RuntimeError("TrailBase exited before intentional shutdown")
        stop_owned([trail_child])
        require_stopped([trail_child])
        for name, database in paths.items():
            synced = sync_database(litestream, socket_path, database)
            final[name] = normalize_txid(synced["replica_txid"])
        if replicator.process.poll() is not None:
            raise RuntimeError("replicator exited before intentional shutdown")
        stop_owned([replicator])
        require_stopped([replicator])
        inventory = backup_inventory(root / "backup" / "e1")
        oracle = root / "oracle" / "e1"
        oracle.mkdir(parents=True)
        for index, name in enumerate(("main", "session", "aux")):
            output = depots["b"] / "data" / f"{name}.db"
            dry_run = subprocess.run(
                [str(litestream), "restore", "-dry-run", "-json", "-o", str(oracle / f"{name}.db"), (root / "backup" / "e1" / name).as_uri()],
                capture_output=True, text=True, timeout=60,
            )
            if dry_run.returncode:
                raise RuntimeError(f"dry-run restore failed for {name}: {dry_run.stderr[-500:]}")
            try:
                plan = json.loads(dry_run.stdout)
                selected[name] = normalize_txid(plan["max_txid"])
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                raise RuntimeError(f"invalid dry-run restore plan for {name}: {dry_run.stdout[-500:]}") from exc
            if selected[name] < final[name]:
                raise RuntimeError(f"sealed history regressed for {name}")
            wait_for_txid(output.with_name(output.name + "-txid"), selected[name], followers[index])
            restored = subprocess.run(
                [str(litestream), "restore", "-txid", format_txid(selected[name]), "-o", str(oracle / f"{name}.db"), (root / "backup" / "e1" / name).as_uri()],
                capture_output=True, text=True, timeout=60,
            )
            if restored.returncode:
                raise RuntimeError(f"finite restore failed for {name}: {restored.stderr[-500:]}")
        if any(child.process.poll() is not None for child in followers):
            raise RuntimeError("follower exited before intentional shutdown")
        stop_owned(followers)
        require_stopped(followers)
        for name in ("main", "session", "aux"):
            lines = (root / "logs" / f"follower-b-{name}.log").read_text(errors="replace").splitlines()
            promotion_error_gate([parse_follower_line(line) for line in lines])
        follower_snapshots = {
            "main": sqlite_rows(depots["b"] / "data" / "main.db", ("hat_ops", "_user")),
            "session": sqlite_rows(depots["b"] / "data" / "session.db", ("_session",)),
            "aux": sqlite_rows(depots["b"] / "data" / "aux.db", ("hat_ops",)),
        }
        oracle_snapshots = {
            "main": sqlite_rows(oracle / "main.db", ("hat_ops", "_user")),
            "session": sqlite_rows(oracle / "session.db", ("_session",)),
            "aux": sqlite_rows(oracle / "aux.db", ("hat_ops",)),
        }
        comparisons = {name: follower_snapshots[name] == oracle_snapshots[name] for name in follower_snapshots}
        expected_operations = {
            name: [(f"e1-{name}-{index:06d}", payload) for index in range(1, 101)]
            for name in ("main", "aux")
        }
        for name in ("main", "aux"):
            rows = follower_snapshots[name]["hat_ops"]
            recovered = [(row[1], row[2]) for row in rows]
            if recovered != expected_operations[name]:
                raise CorrectnessFailure(f"{name} recovered operations do not match the independent manifest")
        if len(follower_snapshots["session"]["_session"]) != 3:
            raise CorrectnessFailure("retained/revoked session row outcome is incorrect")
        if not all(comparisons.values()):
            raise CorrectnessFailure(f"followed files differ logically from finite restores: {comparisons}")
        if backup_inventory(root / "backup" / "e1") != inventory:
            raise CorrectnessFailure("sealed e1 history changed")
        (root / "result.json").write_text(json.dumps({
            "scenario": "follow", "status": "PASS", "initial_txid": initial,
            "final_sync_txid": final, "selected_txid": selected,
            "logical_comparison": comparisons, "rows_per_business_db": 100,
            "payload_bytes": len(payload), "structural_check": "CHECK expressions not evaluated",
        }, indent=2) + "\n")
    finally:
        stop_owned([child for child in (trail_child, replicator, *followers) if child is not None])
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
        if completed.returncode != 0:
            raise RuntimeError(f"preflight command failed: {argv}: {completed.stderr[-500:]}")
    validate_binary_versions(
        {"trail": "0.33.11", "litestream": "0.5.17"},
        parse_binary_versions(results[0]["stdout"], results[4]["stdout"]),
    )
    (root / "preflight.json").write_text(json.dumps({
        "python": sys.version,
        "sqlite": sqlite3.sqlite_version,
        "platform": {"system": __import__("platform").system(), "machine": __import__("platform").machine()},
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
    if args.scenario == "follow":
        if not args.trail or not args.litestream:
            parser.error("follow requires --trail and --litestream")
        return run_follow(args.trail.absolute(), args.litestream.absolute(), root)
    raise RuntimeError(f"scenario not implemented yet: {args.scenario}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CorrectnessFailure as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        raise SystemExit(2)
