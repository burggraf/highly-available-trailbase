#!/usr/bin/env python3
"""Local M0 process-safety harness."""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


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
    if args.scenario == "preflight":
        if not args.trail or not args.litestream:
            parser.error("preflight requires --trail and --litestream")
        root = require_private_run_root(args.work_root / f"run-{time.time_ns()}", Path(__file__).resolve().parents[2])
        return run_preflight(args.trail.absolute(), args.litestream.absolute(), root)
    raise RuntimeError(f"scenario not implemented yet: {args.scenario}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        raise SystemExit(2)
