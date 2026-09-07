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
import threading
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


def outcomes(acknowledged: set[str], rejected: set[str], ambiguous: set[str], recovered: set[str], submitted: set[str]) -> dict[str, list[str]]:
    if (acknowledged & rejected or acknowledged & ambiguous or rejected & ambiguous
            or (acknowledged | rejected | ambiguous) != submitted):
        raise ValueError("outcome classes must partition submitted operations")
    return {
        "lost_acknowledged": sorted(acknowledged - recovered),
        "recovered_ambiguous": sorted(recovered & ambiguous),
        "recovered_rejected": sorted(recovered & rejected),
        "unexpected": sorted(recovered - submitted),
    }


def outcome_passes(result: dict[str, list[str]]) -> bool:
    return not result["recovered_rejected"] and not result["unexpected"]


def validate_epoch_paths(old: dict[str, Path], new: dict[str, Path]) -> None:
    if set(old) != set(new):
        raise ValueError("epoch database mappings differ")
    resolved = [path.resolve(strict=False) for path in (*old.values(), *new.values())]
    if len(set(resolved)) != len(resolved):
        raise ValueError("epoch paths must be unique and non-aliased")


def promote_candidate(children: list[OwnedProcess], databases: list[Path], start):
    require_stopped(children)
    require_files(databases)
    return start()


def require_stopped(children: list[OwnedProcess]) -> None:
    live = [child.role for child in children if child.process.poll() is None]
    if live:
        raise RuntimeError("cannot promote while processes are alive: " + ", ".join(live))


def kill_owned(child: OwnedProcess) -> tuple[int, int]:
    if child.process.poll() is not None:
        raise RuntimeError(f"{child.role} exited before fault injection")
    sent = time.monotonic_ns()
    os.killpg(child.process.pid, signal.SIGKILL)
    child.process.wait()
    return sent, time.monotonic_ns()


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


def write_litestream_config(root: Path, source: Path, epoch: str = "e1") -> tuple[Path, Path]:
    socket_path = root / f"{epoch}.sock"
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
            f"    meta-path: {json.dumps(str(root / 'meta' / epoch / name))}",
            "    replica:", "      type: file",
            f"      path: {json.dumps(str(root / 'backup' / epoch / name))}",
            "      sync-interval: 1s",
        ])
    path = root / f"{epoch}.yml"
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


def copy_for_inspection(source: Path, evidence_dir: Path) -> Path:
    require_files([source])
    evidence_dir.mkdir(parents=True, exist_ok=True)
    target = evidence_dir / source.name
    shutil.copy2(source, target)
    return target


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
        quiesce_wall_ns = time.time_ns()
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
        inspection_dir = root / "evidence" / "b-stopped-inspection"
        inspection_paths = {
            name: copy_for_inspection(depots["b"] / "data" / f"{name}.db", inspection_dir)
            for name in ("main", "session", "aux")
        }
        follower_snapshots = {
            "main": sqlite_rows(inspection_paths["main"], ("hat_ops", "_user")),
            "session": sqlite_rows(inspection_paths["session"], ("_session",)),
            "aux": sqlite_rows(inspection_paths["aux"], ("hat_ops",)),
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
            "quiesce_wall_ns": quiesce_wall_ns,
        }, indent=2) + "\n")
    finally:
        stop_owned([child for child in (trail_child, replicator, *followers) if child is not None])
    return 0


def rebuild_epoch2(trail: Path, litestream: Path, root: Path, writer_depot: Path, c_depot: Path,
                   writer: OwnedProcess, base: str, token: str) -> dict[str, object]:
    e1_inventory = backup_inventory(root / "backup" / "e1")
    source = writer_depot / "data"
    paths = validate_inventory({name: source / f"{name}.db" for name in ("main", "session", "aux")})
    old_paths = {name: root / "backup" / "e1" / name for name in paths}
    new_paths = {name: root / "backup" / "e2" / name for name in paths}
    validate_epoch_paths(old_paths, new_paths)
    config, socket_path = write_litestream_config(root, source, "e2")
    replicator: OwnedProcess | None = None
    followers: list[OwnedProcess] = []
    reseed_started = time.monotonic_ns()
    try:
        replicator = owned_process(
            [str(litestream), "replicate", "-config", str(config)],
            "litestream-b-e2", root, root / "logs" / "replicator-b-e2.log",
        )
        wait_for_path(socket_path, replicator)
        initial = {
            name: normalize_txid(sync_database(litestream, socket_path, database)["replica_txid"])
            for name, database in paths.items()
        }
        for name in ("main", "session", "aux"):
            output = c_depot / "data" / f"{name}.db"
            output.parent.mkdir(parents=True, exist_ok=True)
            child = owned_process(
                [str(litestream), "restore", "-f", "-follow-interval", "1s", "-o", str(output), (root / "backup" / "e2" / name).as_uri()],
                f"follower-c-{name}", root, root / "logs" / f"follower-c-{name}.log",
            )
            followers.append(child)
            initial[name] = wait_for_txid(output.with_name(output.name + "-txid"), initial[name], child)
        follower_by_name = dict(zip(("main", "session", "aux"), followers))
        progressed = {}
        for api, name, offset in (("main_ops", "main", 400000), ("aux_ops", "aux", 500000)):
            for index in range(1, 11):
                status, created = http_json("POST", f"{base}/api/records/v1/{api}", {
                    "id": offset + index, "op_key": f"e2-{name}-{index:06d}", "payload": "epoch-two",
                }, token)
                if status not in (200, 201) or not isinstance(created, dict):
                    raise RuntimeError(f"e2 write failed: {name}/{index}")
            progressed[name] = normalize_txid(sync_database(litestream, socket_path, paths[name])["replica_txid"])
            if progressed[name] <= initial[name]:
                raise RuntimeError(f"e2 {name} follower did not advance")
            wait_for_txid(c_depot / "data" / f"{name}.db-txid", progressed[name], follower_by_name[name])
        status, retained = http_json("POST", f"{base}/api/auth/v1/login", {"username": FIXTURE_USERNAME, "password": "m0-local-only-password"})
        status2, revoked = http_json("POST", f"{base}/api/auth/v1/login", {"username": FIXTURE_USERNAME, "password": "m0-local-only-password"})
        if status != 200 or status2 != 200 or not isinstance(retained, dict) or not isinstance(revoked, dict):
            raise RuntimeError("e2 session creation failed")
        session_created = normalize_txid(sync_database(litestream, socket_path, paths["session"])["replica_txid"])
        if session_created <= initial["session"]:
            raise RuntimeError("e2 session creation did not advance")
        wait_for_txid(c_depot / "data" / "session.db-txid", session_created, follower_by_name["session"])
        logout_status, _ = http_request("POST", f"{base}/api/auth/v1/logout", {"refresh_token": revoked["refresh_token"]})
        retained_status, _ = http_json("POST", f"{base}/api/auth/v1/refresh", {"refresh_token": retained["refresh_token"]})
        revoked_status, _ = http_json("POST", f"{base}/api/auth/v1/refresh", {"refresh_token": revoked["refresh_token"]})
        if logout_status != 200 or retained_status != 200 or revoked_status == 200:
            raise RuntimeError("e2 session revocation failed")
        session_revoked = normalize_txid(sync_database(litestream, socket_path, paths["session"])["replica_txid"])
        if session_revoked <= session_created:
            raise RuntimeError("e2 session revocation did not advance")
        if writer.process.poll() is not None:
            raise RuntimeError("promoted writer exited before e2 quiesce")
        stop_owned([writer])
        final = {
            name: normalize_txid(sync_database(litestream, socket_path, database)["replica_txid"])
            for name, database in paths.items()
        }
        if replicator.process.poll() is not None:
            raise RuntimeError("e2 replicator exited before intentional stop")
        stop_owned([replicator])
        selected = {}
        oracle = root / "oracle" / "e2"
        oracle.mkdir(parents=True)
        for name in ("main", "session", "aux"):
            dry = subprocess.run(
                [str(litestream), "restore", "-dry-run", "-json", "-o", str(oracle / f"{name}.db"), (root / "backup" / "e2" / name).as_uri()],
                capture_output=True, text=True, timeout=60, check=True,
            )
            selected[name] = normalize_txid(json.loads(dry.stdout)["max_txid"])
            follower = follower_by_name[name]
            wait_for_txid(c_depot / "data" / f"{name}.db-txid", selected[name], follower)
            restored = subprocess.run(
                [str(litestream), "restore", "-txid", format_txid(selected[name]), "-o", str(oracle / f"{name}.db"), (root / "backup" / "e2" / name).as_uri()],
                capture_output=True, text=True, timeout=60,
            )
            if restored.returncode:
                raise RuntimeError(f"e2 finite restore failed for {name}: {restored.stderr[-500:]}")
        stop_owned(followers)
        for child in followers:
            check_follower_log(child)
        inspection = root / "evidence" / "c-stopped-inspection"
        comparisons = {}
        table_map = {"main": ("hat_ops", "_user"), "session": ("_session",), "aux": ("hat_ops",)}
        for name in ("main", "session", "aux"):
            followed = sqlite_rows(copy_for_inspection(c_depot / "data" / f"{name}.db", inspection), table_map[name])
            restored = sqlite_rows(oracle / f"{name}.db", table_map[name])
            comparisons[name] = followed == restored
        if not all(comparisons.values()):
            raise CorrectnessFailure(f"e2 C follower differs from finite restore: {comparisons}")
        if backup_inventory(root / "backup" / "e1") != e1_inventory:
            raise CorrectnessFailure("e1 history changed while producing e2")
        return {
            "status": "PASS", "initial_txid": initial, "final_txid": final,
            "selected_txid": selected, "logical_comparison": comparisons,
            "reseed_ms": (time.monotonic_ns() - reseed_started) / 1_000_000,
            "retained_session": "present", "revoked_session": "absent",
        }
    finally:
        stop_owned([child for child in (replicator, *followers) if child is not None])


def run_graceful(trail: Path, litestream: Path, root: Path) -> int:
    run_follow(trail, litestream, root)
    follow_result = json.loads((root / "result.json").read_text())
    depot = root / "b" / "traildepot"
    databases = [depot / "data" / f"{name}.db" for name in ("main", "session", "aux")]
    evidence = root / "evidence" / "b-follow-sidecars"
    evidence.mkdir(parents=True)
    for database in databases:
        sidecar = database.with_name(database.name + "-txid")
        require_files([sidecar])
        shutil.move(sidecar, evidence / sidecar.name)
    unexpected = [
        str(path) for path in (depot / "data").iterdir()
        if path.name.endswith(("-wal", "-shm", "-journal"))
    ]
    if unexpected:
        raise CorrectnessFailure(f"unexpected journal sidecars block promotion: {unexpected}")
    port = free_loopback_port()
    base = f"http://127.0.0.1:{port}"
    start_ns = time.monotonic_ns()
    child = promote_candidate([], databases, lambda: owned_process(
        [str(trail), "--depot", str(depot), "run", "--address", f"127.0.0.1:{port}", "--stderr-logging"],
        "trail-b", root, root / "logs" / "trail-b.log",
    ))
    try:
        wait_ready(base, child)
        fixture_auth = json.loads((root / "fixture-private.json").read_text())
        retained_status, _ = http_json("POST", f"{base}/api/auth/v1/refresh", {"refresh_token": fixture_auth["retained_refresh"]})
        revoked_status, _ = http_json("POST", f"{base}/api/auth/v1/refresh", {"refresh_token": fixture_auth["revoked_refresh"]})
        if retained_status != 200 or revoked_status == 200:
            raise CorrectnessFailure("baseline auth outcome changed after promotion")
        status, login = http_json("POST", f"{base}/api/auth/v1/login", {"username": FIXTURE_USERNAME, "password": "m0-local-only-password"})
        if status != 200 or not isinstance(login, dict):
            raise CorrectnessFailure("promoted writer login failed")
        token = str(login["auth_token"])
        payload = "x" * 8192
        for api, name, offset in (("main_ops", "main", 0), ("aux_ops", "aux", 100000)):
            for index in range(1, 101):
                status, row = http_json("GET", f"{base}/api/records/v1/{api}/{offset + index}", token=token)
                if status != 200 or not isinstance(row, dict) or row.get("op_key") != f"e1-{name}-{index:06d}" or row.get("payload") != payload:
                    raise CorrectnessFailure(f"promoted API mismatch for {api}/{offset + index}")
            new_id = offset + 200001
            status, created = http_json("POST", f"{base}/api/records/v1/{api}", {
                "id": new_id, "op_key": f"promoted-{name}-000001", "payload": "promoted-write",
            }, token)
            if status not in (200, 201) or not isinstance(created, dict) or created.get("ids") != [str(new_id)]:
                raise CorrectnessFailure(f"promoted write failed for {api}")
        functional_ns = time.monotonic_ns()
        require_files([depot / "data" / "logs.db"])
        epoch2 = rebuild_epoch2(trail, litestream, root, depot, root / "c" / "traildepot", child, base, token)
        (root / "result.json").write_text(json.dumps({
            "scenario": "graceful", "status": "PASS", "follow": follow_result,
            "promotion_start_to_functional_ms": (functional_ns - start_ns) / 1_000_000,
            "quiesce_to_functional_ms": (time.time_ns() - follow_result["quiesce_wall_ns"]) / 1_000_000,
            "baseline_auth": {"retained": "accepted", "revoked": "rejected"},
            "promoted_writes": 2, "logs_db": "node-local-created", "epoch2": epoch2,
        }, indent=2) + "\n")
    finally:
        stop_owned([child])
    return 0


def append_ledger(path: Path, event: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def run_lagged_crash(trail: Path, litestream: Path, root: Path) -> int:
    run_follow(trail, litestream, root)
    baseline_result = json.loads((root / "result.json").read_text())
    sealed_inventory = backup_inventory(root / "backup" / "e1")
    a_depot = root / "a" / "traildepot"
    b_depot = root / "b" / "traildepot"
    port = free_loopback_port()
    base = f"http://127.0.0.1:{port}"
    a_child = owned_process(
        [str(trail), "--depot", str(a_depot), "run", "--address", f"127.0.0.1:{port}", "--stderr-logging"],
        "trail-a-lagged", root, root / "logs" / "trail-a-lagged.log",
    )
    late_refresh = ""
    ledger = root / "operations.jsonl"
    submitted = {name: set() for name in ("main", "aux")}
    acknowledged = {name: set() for name in ("main", "aux")}
    rejected = {name: set() for name in ("main", "aux")}
    try:
        wait_ready(base, a_child)
        status, login = http_json("POST", f"{base}/api/auth/v1/login", {"username": FIXTURE_USERNAME, "password": "m0-local-only-password"})
        if status != 200 or not isinstance(login, dict):
            raise RuntimeError("lagged writer login failed")
        token = str(login["auth_token"])
        for name in ("main", "aux"):
            submitted[name].update(f"e1-{name}-{index:06d}" for index in range(1, 101))
            acknowledged[name].update(submitted[name])
        for index in range(1, 11):
            for api, name, offset in (("main_ops", "main", 1000), ("aux_ops", "aux", 101000)):
                key = f"lagged-{name}-{index:06d}"
                submitted[name].add(key)
                started = time.monotonic_ns()
                status, created = http_json("POST", f"{base}/api/records/v1/{api}", {
                    "id": offset + index, "op_key": key, "payload": "unreplicated",
                }, token)
                completed = time.monotonic_ns()
                if status not in (200, 201) or not isinstance(created, dict):
                    raise RuntimeError(f"lagged write failed: {api}/{key}")
                acknowledged[name].add(key)
                append_ledger(ledger, {"db": name, "epoch": "e1", "op_key": key, "outcome": "acknowledged", "submit_ns": started, "complete_ns": completed})
        denied_key = "denied-main-000001"
        submitted["main"].add(denied_key)
        denied_status, _ = http_request("POST", f"{base}/api/records/v1/main_ops", {
            "id": 999999, "op_key": denied_key, "payload": "must-not-exist",
        })
        if denied_status not in (401, 403):
            raise RuntimeError(f"denied write returned unexpected status: {denied_status}")
        rejected["main"].add(denied_key)
        append_ledger(ledger, {"db": "main", "epoch": "e1", "op_key": denied_key, "outcome": "rejected"})
        late_status, late_login = http_json("POST", f"{base}/api/auth/v1/login", {"username": FIXTURE_USERNAME, "password": "m0-local-only-password"})
        if late_status != 200 or not isinstance(late_login, dict):
            raise RuntimeError("late login failed")
        late_refresh = str(late_login["refresh_token"])
        signal_sent_ns, exit_observed_ns = kill_owned(a_child)
    finally:
        stop_owned([a_child])
    if backup_inventory(root / "backup" / "e1") != sealed_inventory:
        raise CorrectnessFailure("sealed e1 changed during lagged crash")
    databases = [b_depot / "data" / f"{name}.db" for name in ("main", "session", "aux")]
    evidence = root / "evidence" / "lagged-follow-sidecars"
    evidence.mkdir(parents=True)
    for database in databases:
        sidecar = database.with_name(database.name + "-txid")
        require_files([sidecar])
        shutil.move(sidecar, evidence / sidecar.name)
    b_port = free_loopback_port()
    b_base = f"http://127.0.0.1:{b_port}"
    b_child = promote_candidate([], databases, lambda: owned_process(
        [str(trail), "--depot", str(b_depot), "run", "--address", f"127.0.0.1:{b_port}", "--stderr-logging"],
        "trail-b-lagged", root, root / "logs" / "trail-b-lagged.log",
    ))
    try:
        wait_ready(b_base, b_child)
        fixture_auth = json.loads((root / "fixture-private.json").read_text())
        baseline_retained, _ = http_json("POST", f"{b_base}/api/auth/v1/refresh", {"refresh_token": fixture_auth["retained_refresh"]})
        baseline_revoked, _ = http_json("POST", f"{b_base}/api/auth/v1/refresh", {"refresh_token": fixture_auth["revoked_refresh"]})
        late_status, _ = http_json("POST", f"{b_base}/api/auth/v1/refresh", {"refresh_token": late_refresh})
        if baseline_retained != 200 or baseline_revoked == 200 or late_status == 200:
            raise CorrectnessFailure("lagged auth outcomes are incorrect")
        status, login = http_json("POST", f"{b_base}/api/auth/v1/login", {"username": FIXTURE_USERNAME, "password": "m0-local-only-password"})
        if status != 200 or not isinstance(login, dict):
            raise CorrectnessFailure("recovered login failed")
        token = str(login["auth_token"])
        recovered = {"main": set(), "aux": set()}
        for api, name, baseline_offset, tail_offset in (
            ("main_ops", "main", 0, 1000), ("aux_ops", "aux", 100000, 101000),
        ):
            for index in range(1, 101):
                row_status, row = http_json("GET", f"{b_base}/api/records/v1/{api}/{baseline_offset + index}", token=token)
                if row_status != 200 or not isinstance(row, dict):
                    raise CorrectnessFailure(f"sealed baseline missing: {name}/{index}")
                recovered[name].add(str(row["op_key"]))
            for index in range(1, 11):
                row_status, _ = http_json("GET", f"{b_base}/api/records/v1/{api}/{tail_offset + index}", token=token)
                if row_status == 200:
                    recovered[name].add(f"lagged-{name}-{index:06d}")
            if name == "main":
                denied_status, _ = http_json("GET", f"{b_base}/api/records/v1/main_ops/999999", token=token)
                if denied_status == 200:
                    recovered[name].add(denied_key)
        measurements = {
            name: outcomes(acknowledged[name], rejected[name], set(), recovered[name], submitted[name])
            for name in ("main", "aux")
        }
        if any(len(measurements[name]["lost_acknowledged"]) != 10 for name in measurements):
            raise CorrectnessFailure(f"lagged loss detector did not find ten writes per DB: {measurements}")
        if not all(outcome_passes(value) for value in measurements.values()):
            raise CorrectnessFailure(f"invalid lagged recovered outcomes: {measurements}")
        epoch2 = rebuild_epoch2(trail, litestream, root, b_depot, root / "c" / "traildepot", b_child, b_base, token)
        (root / "result.json").write_text(json.dumps({
            "scenario": "lagged-crash", "status": "PASS", "baseline": baseline_result,
            "signal_sent_ns": signal_sent_ns, "exit_observed_ns": exit_observed_ns,
            "outcomes": measurements, "epoch2": epoch2,
            "auth": {"baseline_retained": "accepted", "baseline_revoked": "rejected", "late": "rejected"},
        }, indent=2) + "\n")
    finally:
        stop_owned([b_child])
    return 0


def run_crash(trail: Path, litestream: Path, root: Path) -> int:
    run_follow(trail, litestream, root)
    a_depot = root / "a" / "traildepot"
    d_depot = root / "crash-b" / "traildepot"
    write_fixture(d_depot)
    shutil.copytree(a_depot / "secrets", d_depot / "secrets")
    source = a_depot / "data"
    paths = validate_inventory({name: source / f"{name}.db" for name in ("main", "session", "aux")})
    config, socket_path = write_litestream_config(root, source, "crash-e1")
    port = free_loopback_port()
    base = f"http://127.0.0.1:{port}"
    children: list[OwnedProcess] = []
    followers: list[OwnedProcess] = []
    try:
        trail_child = owned_process(
            [str(trail), "--depot", str(a_depot), "run", "--address", f"127.0.0.1:{port}", "--stderr-logging"],
            "trail-a-crash", root, root / "logs" / "trail-a-crash.log",
        )
        children.append(trail_child)
        replicator = owned_process(
            [str(litestream), "replicate", "-config", str(config)],
            "litestream-a-crash", root, root / "logs" / "replicator-a-crash.log",
        )
        children.append(replicator)
        wait_ready(base, trail_child)
        wait_for_path(socket_path, replicator)
        initial = {}
        for name, database in paths.items():
            initial[name] = normalize_txid(sync_database(litestream, socket_path, database)["replica_txid"])
        for name in ("main", "session", "aux"):
            output = d_depot / "data" / f"{name}.db"
            output.parent.mkdir(parents=True, exist_ok=True)
            child = owned_process(
                [str(litestream), "restore", "-f", "-follow-interval", "1s", "-o", str(output), (root / "backup" / "crash-e1" / name).as_uri()],
                f"crash-follower-{name}", root, root / "logs" / f"crash-follower-{name}.log",
            )
            followers.append(child)
            wait_for_txid(output.with_name(output.name + "-txid"), initial[name], child)
        status, login = http_json("POST", f"{base}/api/auth/v1/login", {"username": FIXTURE_USERNAME, "password": "m0-local-only-password"})
        if status != 200 or not isinstance(login, dict):
            raise RuntimeError("crash writer login failed")
        token = str(login["auth_token"])
        submitted = {name: {f"e1-{name}-{index:06d}" for index in range(1, 101)} for name in ("main", "aux")}
        acknowledged = {name: set(values) for name, values in submitted.items()}
        ambiguous = {"main": set(), "aux": set()}
        for index in range(1, 6):
            for api, name, offset in (("main_ops", "main", 2000), ("aux_ops", "aux", 102000)):
                key = f"crash-{name}-{index:06d}"
                submitted[name].add(key)
                write_status, created = http_json("POST", f"{base}/api/records/v1/{api}", {
                    "id": offset + index, "op_key": key, "payload": "crash-tail",
                }, token)
                if write_status not in (200, 201) or not isinstance(created, dict):
                    raise RuntimeError(f"pre-crash write failed: {key}")
                acknowledged[name].add(key)
        in_flight_key = "crash-main-inflight"
        submitted["main"].add(in_flight_key)
        request_started = threading.Event()
        request_result: dict[str, object] = {}
        def issue_in_flight() -> None:
            request_started.set()
            try:
                request_result["status"], request_result["body"] = http_json("POST", f"{base}/api/records/v1/main_ops", {
                    "id": 888888, "op_key": in_flight_key, "payload": "z" * (8 * 1024 * 1024),
                }, token)
            except Exception as exc:
                request_result["error"] = repr(exc)
        request_thread = threading.Thread(target=issue_in_flight, daemon=True)
        request_thread.start()
        if not request_started.wait(timeout=5):
            raise RuntimeError("in-flight mutation did not start")
        trail_sent, trail_exited = kill_owned(trail_child)
        replica_sent, replica_exited = kill_owned(replicator)
        request_thread.join(timeout=10)
        if request_thread.is_alive():
            raise RuntimeError("in-flight mutation did not resolve")
        if request_result.get("status") in (200, 201):
            acknowledged["main"].add(in_flight_key)
        else:
            ambiguous["main"].add(in_flight_key)
        selected = {}
        oracle_probe = root / "oracle" / "crash-e1"
        oracle_probe.mkdir(parents=True)
        for name in ("main", "session", "aux"):
            dry = subprocess.run(
                [str(litestream), "restore", "-dry-run", "-json", "-o", str(oracle_probe / f"{name}.db"), (root / "backup" / "crash-e1" / name).as_uri()],
                capture_output=True, text=True, timeout=60, check=True,
            )
            selected[name] = normalize_txid(json.loads(dry.stdout)["max_txid"])
            follower = followers[("main", "session", "aux").index(name)]
            wait_for_txid(d_depot / "data" / f"{name}.db-txid", selected[name], follower)
        if any(child.process.poll() is not None for child in followers):
            raise RuntimeError("crash follower exited unexpectedly")
        stop_owned(followers)
        for child in followers:
            check_follower_log(child)
        evidence = root / "evidence" / "crash-follow-sidecars"
        evidence.mkdir(parents=True)
        databases = [d_depot / "data" / f"{name}.db" for name in ("main", "session", "aux")]
        for database in databases:
            sidecar = database.with_name(database.name + "-txid")
            shutil.move(sidecar, evidence / sidecar.name)
        b_port = free_loopback_port()
        b_base = f"http://127.0.0.1:{b_port}"
        b_child = promote_candidate(followers, databases, lambda: owned_process(
            [str(trail), "--depot", str(d_depot), "run", "--address", f"127.0.0.1:{b_port}", "--stderr-logging"],
            "trail-b-crash", root, root / "logs" / "trail-b-crash.log",
        ))
        children.append(b_child)
        wait_ready(b_base, b_child)
        fixture_auth = json.loads((root / "fixture-private.json").read_text())
        retained_status, _ = http_json("POST", f"{b_base}/api/auth/v1/refresh", {"refresh_token": fixture_auth["retained_refresh"]})
        revoked_status, _ = http_json("POST", f"{b_base}/api/auth/v1/refresh", {"refresh_token": fixture_auth["revoked_refresh"]})
        if retained_status != 200 or revoked_status == 200:
            raise CorrectnessFailure("baseline auth failed after crash")
        status, recovered_login = http_json("POST", f"{b_base}/api/auth/v1/login", {"username": FIXTURE_USERNAME, "password": "m0-local-only-password"})
        if status != 200 or not isinstance(recovered_login, dict):
            raise CorrectnessFailure("crash recovery login failed")
        recovered_token = str(recovered_login["auth_token"])
        recovered = {"main": set(), "aux": set()}
        for api, name, baseline_offset, tail_offset in (
            ("main_ops", "main", 0, 2000), ("aux_ops", "aux", 100000, 102000),
        ):
            for index in range(1, 101):
                row_status, row = http_json("GET", f"{b_base}/api/records/v1/{api}/{baseline_offset + index}", token=recovered_token)
                if row_status != 200 or not isinstance(row, dict):
                    raise CorrectnessFailure(f"sealed baseline lost after crash: {name}/{index}")
                recovered[name].add(str(row["op_key"]))
            for index in range(1, 6):
                row_status, row = http_json("GET", f"{b_base}/api/records/v1/{api}/{tail_offset + index}", token=recovered_token)
                if row_status == 200 and isinstance(row, dict):
                    recovered[name].add(str(row["op_key"]))
        row_status, row = http_json("GET", f"{b_base}/api/records/v1/main_ops/888888", token=recovered_token)
        if row_status == 200 and isinstance(row, dict):
            recovered["main"].add(str(row["op_key"]))
        measured = {
            name: outcomes(acknowledged[name], set(), ambiguous[name], recovered[name], submitted[name])
            for name in ("main", "aux")
        }
        if not all(outcome_passes(value) for value in measured.values()):
            raise CorrectnessFailure(f"crash outcome classification failed: {measured}")
        epoch2 = rebuild_epoch2(trail, litestream, root, d_depot, root / "c" / "traildepot", b_child, b_base, recovered_token)
        (root / "result.json").write_text(json.dumps({
            "scenario": "crash", "status": "PASS", "selected_txid": selected,
            "trail_signal_ns": trail_sent, "trail_exit_ns": trail_exited,
            "replicator_signal_ns": replica_sent, "replicator_exit_ns": replica_exited,
            "outcomes": measured, "in_flight": "acknowledged" if in_flight_key in acknowledged["main"] else "ambiguous",
            "epoch2": epoch2,
        }, indent=2) + "\n")
    finally:
        stop_owned([*children, *followers])
    return 0


def run_guards(trail: Path, litestream: Path, root: Path) -> int:
    run_follow(trail, litestream, root)
    source = root / "b" / "traildepot" / "data"
    guard_root = root / "evidence" / "guard-copies"
    shutil.copytree(source, guard_root)
    results: dict[str, str] = {}
    starts: list[str] = []
    def forbidden_start():
        starts.append("started")
        raise AssertionError("writable process must not start")

    live = owned_process(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        "guard-live-follower", root, root / "logs" / "guard-live.log",
    )
    try:
        try:
            promote_candidate([live], [guard_root / f"{name}.db" for name in ("main", "session", "aux")], forbidden_start)
        except RuntimeError:
            results["live_process"] = "refused"
        else:
            raise CorrectnessFailure("live-process promotion was not refused")
    finally:
        stop_owned([live])
    missing_dir = root / "evidence" / "guard-missing"
    shutil.copytree(source, missing_dir)
    (missing_dir / "session.db").unlink()
    try:
        promote_candidate([], [missing_dir / f"{name}.db" for name in ("main", "session", "aux")], forbidden_start)
    except FileNotFoundError:
        if (missing_dir / "session.db").exists():
            raise CorrectnessFailure("missing-file guard created the database")
        results["missing_database"] = "refused-preserved"
    else:
        raise CorrectnessFailure("missing database promotion was not refused")
    malformed_dir = root / "evidence" / "guard-malformed-txid"
    shutil.copytree(source, malformed_dir)
    (malformed_dir / "main.db-txid").write_text("malformed")
    try:
        read_txid_sidecar(malformed_dir / "main.db-txid")
    except ValueError:
        results["malformed_txid"] = "refused"
    else:
        raise CorrectnessFailure("malformed TXID was accepted")
    corrupt_dir = root / "evidence" / "guard-corrupt"
    shutil.copytree(source, corrupt_dir)
    corrupt = corrupt_dir / "main.db"
    corrupt.write_bytes(corrupt.read_bytes()[:100])
    try:
        sqlite_rows(corrupt, ("hat_ops",))
    except (CorrectnessFailure, sqlite3.DatabaseError):
        results["truncated_database"] = "refused"
    else:
        raise CorrectnessFailure("truncated database passed validation")
    try:
        validate_epoch_paths(
            {name: root / "backup" / "e1" / name for name in ("main", "session", "aux")},
            {name: root / "backup" / "e1" / name for name in ("main", "session", "aux")},
        )
    except ValueError:
        results["reused_epoch"] = "refused"
    else:
        raise CorrectnessFailure("reused epoch paths were accepted")
    exited = owned_process(
        [sys.executable, "-c", "pass"], "guard-exited-follower", root, root / "logs" / "guard-exited.log",
    )
    exited.process.wait(timeout=5)
    try:
        wait_for_txid(root / "never-created-txid", 1, exited, timeout=0.1)
    except RuntimeError:
        results["unexpected_exit"] = "refused"
    else:
        raise CorrectnessFailure("unexpected follower exit was accepted")
    stalled = owned_process(
        [sys.executable, "-c", "import time; time.sleep(30)"], "guard-stalled-follower", root, root / "logs" / "guard-stalled.log",
    )
    try:
        try:
            wait_for_txid(root / "never-created-txid", 1, stalled, timeout=0.1)
        except RuntimeError:
            results["catchup_timeout"] = "refused"
        else:
            raise CorrectnessFailure("catch-up timeout was accepted")
    finally:
        stop_owned([stalled])
    apply_error = parse_follower_line('time=2026-01-01T00:00:00Z level=ERROR msg="follow: error applying updates"')
    later_progress = parse_follower_line('time=2026-01-01T00:00:01Z level=INFO msg="follow: applied updates"')
    try:
        promotion_error_gate([apply_error, later_progress])
    except CorrectnessFailure:
        results["apply_error_then_progress"] = "refused"
    else:
        raise CorrectnessFailure("later progress cleared follower error")
    if starts:
        raise CorrectnessFailure("a refusal control invoked writable startup")
    (root / "result.json").write_text(json.dumps({"scenario": "guards", "status": "PASS", "controls": results}, indent=2) + "\n")
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
    if args.scenario == "graceful":
        if not args.trail or not args.litestream:
            parser.error("graceful requires --trail and --litestream")
        return run_graceful(args.trail.absolute(), args.litestream.absolute(), root)
    if args.scenario == "lagged-crash":
        if not args.trail or not args.litestream:
            parser.error("lagged-crash requires --trail and --litestream")
        return run_lagged_crash(args.trail.absolute(), args.litestream.absolute(), root)
    if args.scenario == "crash":
        if not args.trail or not args.litestream:
            parser.error("crash requires --trail and --litestream")
        return run_crash(args.trail.absolute(), args.litestream.absolute(), root)
    if args.scenario == "guards":
        if not args.trail or not args.litestream:
            parser.error("guards requires --trail and --litestream")
        return run_guards(args.trail.absolute(), args.litestream.absolute(), root)
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
