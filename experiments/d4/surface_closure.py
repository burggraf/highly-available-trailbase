"""Strict, offline validation of the pinned TrailBase mutation-surface census."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

COMMIT = "f24291b894bb6c6696608e5f4c2f68666fe97686"
ALLOWED = {
    ("POST", "/api/records/v1/main_ops"): "main",
    ("POST", "/api/records/v1/aux_ops"): "aux",
    ("POST", "/api/auth/v1/logout"): "session",
}
REQUIRED_ROUTE_KEYS = {"method", "path", "handler", "source", "condition", "classification", "effects", "secondary_effects"}
REQUIRED_SOURCE_KEYS = {"file", "sha256", "line", "contains"}
REQUIRED_SOURCE_FILE_KEYS = {"file", "sha256", "anchors"}
REQUIRED_CAPABILITY_KEYS = {"name", "class", "source_files", "edges", "condition"}
REQUIRED_CLASSES = {"router", "conditional", "job", "dynamic_router", "listener", "direct_writer", "provider", "telemetry"}

class SurfaceError(ValueError):
    pass

def _keys(value: dict, expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise SurfaceError(f"{name}: expected keys {sorted(expected)}, got {sorted(value)}")

def load_manifest(path: Path | None = None) -> dict[str, Any]:
    path = path or Path(__file__).with_name("surface_manifest.json")
    try:
        manifest = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SurfaceError(f"cannot load manifest: {exc}") from exc
    if not isinstance(manifest, dict):
        raise SurfaceError("manifest must be an object")
    validate_manifest(manifest)
    return manifest

def validate_manifest(manifest: dict[str, Any]) -> None:
    if set(manifest) != {"schema_version", "source", "source_files", "capabilities", "unresolved_source_graph", "routes"}:
        raise SurfaceError("manifest has unexpected or missing top-level keys")
    if manifest["schema_version"] != 1 or manifest["unresolved_source_graph"]:
        raise SurfaceError("source graph is unresolved")
    source = manifest["source"]
    if not isinstance(source, dict) or set(source) != {"name", "repo", "tag", "commit", "root", "provenance"}:
        raise SurfaceError("invalid source tag")
    if (source["name"], source["repo"], source["tag"], source["commit"]) != ("trailbase", "trailbaseio/trailbase", "v0.33.11", COMMIT):
        raise SurfaceError("source is not the pinned TrailBase")
    provenance = source["provenance"]
    if not isinstance(provenance, dict) or set(provenance) != {"file", "sha256"}:
        raise SurfaceError("invalid provenance")
    entries = manifest["source_files"]
    if not isinstance(entries, list) or not entries:
        raise SurfaceError("source file inventory is empty")
    for entry in entries:
        if not isinstance(entry, dict):
            raise SurfaceError("invalid source file entry")
        _keys(entry, REQUIRED_SOURCE_FILE_KEYS, "source file")
        if not isinstance(entry["file"], str) or not isinstance(entry["sha256"], str) or not isinstance(entry["anchors"], list) or not entry["anchors"]:
            raise SurfaceError("invalid source file tag")
        for anchor in entry["anchors"]:
            if not isinstance(anchor, dict) or set(anchor) != {"line", "contains"} or not isinstance(anchor["line"], int) or not isinstance(anchor["contains"], str):
                raise SurfaceError("invalid source anchor")
    inventory = {x["file"] for x in entries}
    if len(inventory) != len(entries):
        raise SurfaceError("duplicate source file")
    routes = manifest["routes"]
    if not isinstance(routes, list) or len(routes) != 82:
        raise SurfaceError("the census must contain exactly 82 routes")
    pairs = []
    for route in routes:
        if not isinstance(route, dict):
            raise SurfaceError("invalid route")
        _keys(route, REQUIRED_ROUTE_KEYS, "route")
        if route["method"] not in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"} or route["classification"] not in {"allow", "deny", "runtime_unknown"}:
            raise SurfaceError("invalid route classification or method")
        pair = (route["method"], route["path"])
        if route["classification"] == "allow" and pair not in ALLOWED:
            raise SurfaceError("allowlist contains an unqualified route")
        if not isinstance(route["source"], dict):
            raise SurfaceError("invalid route source")
        _keys(route["source"], REQUIRED_SOURCE_KEYS, "route source")
        if route["source"]["file"] not in inventory:
            raise SurfaceError("route source absent from inventory")
        pairs.append(pair)
    if len(set(pairs)) != len(pairs) or ("DELETE", "/api/auth/v1/delete") not in set(pairs):
        raise SurfaceError("duplicate route or account delete route missing")
    if {p for p, r in zip(pairs, routes) if r["classification"] == "allow"} != set(ALLOWED):
        raise SurfaceError("allowlist must be exactly the three qualified controls")
    capabilities = manifest["capabilities"]
    if not isinstance(capabilities, list) or not capabilities:
        raise SurfaceError("capability inventory is empty")
    classes = set()
    for capability in capabilities:
        if not isinstance(capability, dict) or set(capability) != REQUIRED_CAPABILITY_KEYS:
            raise SurfaceError("invalid capability")
        if not isinstance(capability["source_files"], list) or not capability["source_files"] or not set(capability["source_files"]) <= inventory or not isinstance(capability["edges"], list) or not capability["condition"]:
            raise SurfaceError("incomplete capability graph")
        classes.add(capability["class"])
        for edge in capability["edges"]:
            if not isinstance(edge, str) or edge not in {c["name"] for c in capabilities}:
                raise SurfaceError("unresolved capability edge")
    if not REQUIRED_CLASSES <= classes:
        raise SurfaceError("capability graph is incomplete")

def validate_eligibility_input(manifest: dict[str, Any]) -> None:
    """Reject a census that is not resolved enough for native eligibility."""
    validate_manifest(manifest)
    if any(route["classification"] == "runtime_unknown" for route in manifest["routes"]):
        raise SurfaceError("runtime_unknown is not eligible")
    if manifest["unresolved_source_graph"]:
        raise SurfaceError("unresolved source graph is not eligible")


def verify_source(source_root: Path, provenance_path: Path, manifest: dict[str, Any]) -> None:
    validate_manifest(manifest)
    provenance = manifest["source"]["provenance"]
    if not provenance_path.is_file() or hashlib.sha256(provenance_path.read_bytes()).hexdigest() != provenance["sha256"]:
        raise SurfaceError("provenance manifest missing or tampered")
    try:
        recorded = json.loads(provenance_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise SurfaceError("invalid provenance manifest") from exc
    if recorded.get("tag") != manifest["source"]["tag"] or recorded.get("commit") != manifest["source"]["commit"]:
        raise SurfaceError("provenance tag or commit mismatch")
    if source_root.name != manifest["source"]["root"]:
        raise SurfaceError("source root does not match pinned source")
    expected = {entry["file"]: entry["sha256"] for entry in manifest["source_files"]}
    for name, digest in expected.items():
        path = source_root / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise SurfaceError(f"missing or tampered source: {name}")
        lines = path.read_text().splitlines()
        for anchor in next(x["anchors"] for x in manifest["source_files"] if x["file"] == name):
            if anchor["line"] < 1 or anchor["line"] > len(lines) or anchor["contains"] not in lines[anchor["line"] - 1]:
                raise SurfaceError(f"bad source anchor: {name}:{anchor['line']}")
    for route in manifest["routes"]:
        tag = route["source"]
        path = source_root / tag["file"]
        lines = path.read_text().splitlines()
        if tag["line"] < 1 or tag["line"] > len(lines) or tag["contains"] not in lines[tag["line"] - 1]:
            raise SurfaceError(f"bad source anchor: {tag['file']}:{tag['line']}")
    relevant = {p for p in source_root.rglob("*") if p.is_file() and any(x in p.name.lower() for x in ("router", "listener", "writer", "job", "bridge"))}
    extra = {str(p.relative_to(source_root)) for p in relevant} - set(expected)
    if extra:
        raise SurfaceError(f"extra relevant source: {sorted(extra)}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("source_root", type=Path)
    parser.add_argument("provenance", type=Path)
    args = parser.parse_args()
    verify_source(args.source_root, args.provenance, load_manifest(args.manifest))
    print("surface closure verified: 82 routes")
