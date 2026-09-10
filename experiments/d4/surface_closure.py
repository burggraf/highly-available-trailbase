"""Strict, offline validation of the pinned TrailBase mutation-surface census."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

COMMIT = "f24291b894bb6c6696608e5f4c2f68666fe97686"
REQUIRED_ROUTE_KEYS = {"method", "path", "handler", "source", "condition", "classification", "effects", "secondary_effects"}
REQUIRED_SOURCE_KEYS = {"file", "sha256", "line", "contains"}
REQUIRED_SOURCE_FILE_KEYS = {"file", "sha256"}


class SurfaceError(ValueError):
    pass


def _keys(value: dict, expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise SurfaceError(f"{name}: expected keys {sorted(expected)}, got {sorted(value)}")


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        manifest = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SurfaceError(f"cannot load manifest: {exc}") from exc
    if not isinstance(manifest, dict):
        raise SurfaceError("manifest must be an object")
    validate_manifest(manifest)
    return manifest


def validate_manifest(manifest: dict[str, Any]) -> None:
    if set(manifest) != {"schema_version", "source", "source_files", "capabilities", "routes"}:
        raise SurfaceError("manifest has unexpected or missing top-level keys")
    if manifest["schema_version"] != 1:
        raise SurfaceError("unsupported schema")
    source = manifest["source"]
    if not isinstance(source, dict) or set(source) != {"name", "repo", "tag", "commit", "root", "provenance"}:
        raise SurfaceError("invalid source tag")
    if (source["name"], source["repo"], source["tag"], source["commit"]) != (
        "trailbase", "trailbaseio/trailbase", "v0.33.11", COMMIT
    ):
        raise SurfaceError("source is not the pinned TrailBase")
    provenance = source["provenance"]
    if not isinstance(provenance, dict) or set(provenance) != {"file", "sha256"}:
        raise SurfaceError("invalid provenance")
    if not isinstance(manifest["source_files"], list) or not manifest["source_files"]:
        raise SurfaceError("source file inventory is empty")
    for entry in manifest["source_files"]:
        if not isinstance(entry, dict):
            raise SurfaceError("invalid source file entry")
        _keys(entry, REQUIRED_SOURCE_FILE_KEYS, "source file")
        if not isinstance(entry["file"], str) or not isinstance(entry["sha256"], str):
            raise SurfaceError("invalid source file tag")
    if len({x["file"] for x in manifest["source_files"]}) != len(manifest["source_files"]):
        raise SurfaceError("duplicate source file")
    routes = manifest["routes"]
    if not isinstance(routes, list) or len(routes) != 82:
        raise SurfaceError("the census must contain exactly 82 routes")
    pairs = []
    for route in routes:
        if not isinstance(route, dict):
            raise SurfaceError("invalid route")
        _keys(route, REQUIRED_ROUTE_KEYS, "route")
        if route["method"] not in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}:
            raise SurfaceError("invalid method")
        if route["classification"] not in {"allow", "deny", "runtime_unknown"}:
            raise SurfaceError("invalid classification")
        if route["classification"] == "allow" and (route["method"], route["path"]) != ("POST", "/api/auth/v1/logout"):
            raise SurfaceError("allowlist contains a route outside auth logout")
        if not isinstance(route["source"], dict):
            raise SurfaceError("invalid route source")
        _keys(route["source"], REQUIRED_SOURCE_KEYS, "route source")
        pairs.append((route["method"], route["path"]))
    if len(set(pairs)) != len(pairs):
        raise SurfaceError("duplicate method/path pair")
    if ("DELETE", "/api/auth/v1/delete") not in set(pairs):
        raise SurfaceError("account delete route missing")
    if not isinstance(manifest["capabilities"], list) or not manifest["capabilities"]:
        raise SurfaceError("capability inventory is empty")
    for capability in manifest["capabilities"]:
        if not isinstance(capability, dict) or set(capability) != {"name", "class", "source_files"}:
            raise SurfaceError("invalid capability")


def verify_source(manifest: dict[str, Any], root: Path) -> None:
    validate_manifest(manifest)
    provenance = manifest["source"]["provenance"]
    p = root.parent / provenance["file"]
    if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest() != provenance["sha256"]:
        raise SurfaceError("provenance manifest missing or tampered")
    expected = {entry["file"]: entry["sha256"] for entry in manifest["source_files"]}
    for name, digest in expected.items():
        path = root / name
        if not path.is_file():
            raise SurfaceError(f"missing source: {name}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise SurfaceError(f"tampered source: {name}")
    for route in manifest["routes"]:
        tag = route["source"]
        path = root / tag["file"]
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != tag["sha256"]:
            raise SurfaceError(f"route source mismatch: {tag['file']}")
        lines = path.read_text().splitlines()
        if tag["line"] < 1 or tag["line"] > len(lines) or tag["contains"] not in lines[tag["line"] - 1]:
            raise SurfaceError(f"bad source anchor: {tag['file']}:{tag['line']}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("source_root", type=Path)
    args = parser.parse_args()
    verify_source(load_manifest(args.manifest), args.source_root)
    print("surface closure verified: 82 routes")
