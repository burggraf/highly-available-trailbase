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
SOURCE_SCOPES = ["crates/core/src", "crates/wasm-runtime-axum/src", "crates/wasm-runtime-common/src", "crates/wasm-runtime-guest/src", "crates/wasm-runtime-host/src"]
HEX64 = __import__('re').compile(r'^[0-9a-f]{64}$')
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
    if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "source", "source_scopes", "source_files", "capabilities", "unresolved_source_graph", "routes"}:
        raise SurfaceError("manifest has unexpected or missing top-level keys")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1 or not isinstance(manifest["unresolved_source_graph"], list) or manifest["unresolved_source_graph"]:
        raise SurfaceError("source graph is unresolved")
    if any(type(x) is not str or not x for x in manifest["unresolved_source_graph"]): raise SurfaceError("invalid source graph")
    if manifest["source_scopes"] != SOURCE_SCOPES or any(type(x) is not str for x in manifest["source_scopes"]): raise SurfaceError("invalid source scopes")
    source = manifest["source"]
    if not isinstance(source, dict) or set(source) != {"name", "repo", "tag", "commit", "root", "provenance"}:
        raise SurfaceError("invalid source tag")
    if any(type(source[k]) is not str or not source[k] for k in ("name","repo","tag","commit","root")) : raise SurfaceError("invalid source fields")
    if (source["name"], source["repo"], source["tag"], source["commit"]) != ("trailbase", "trailbaseio/trailbase", "v0.33.11", COMMIT):
        raise SurfaceError("source is not the pinned TrailBase")
    provenance = source["provenance"]
    if not isinstance(provenance, dict) or set(provenance) != {"file", "sha256"} or type(provenance.get("file")) is not str or not HEX64.fullmatch(provenance.get("sha256", "")): raise SurfaceError("invalid provenance")
    entries = manifest["source_files"]
    if not isinstance(entries, list) or not entries:
        raise SurfaceError("source file inventory is empty")
    for entry in entries:
        if not isinstance(entry, dict):
            raise SurfaceError("invalid source file entry")
        _keys(entry, REQUIRED_SOURCE_FILE_KEYS, "source file")
        if type(entry["file"]) is not str or not entry["file"].endswith('.rs') or not HEX64.fullmatch(entry["sha256"]) or not isinstance(entry["anchors"], list) or not entry["anchors"]:
            raise SurfaceError("invalid source file tag")
        for anchor in entry["anchors"]:
            if not isinstance(anchor, dict) or set(anchor) != {"line", "contains"} or type(anchor["line"]) is not int or anchor["line"] < 1 or type(anchor["contains"]) is not str or not anchor["contains"]:
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
        if type(route["method"]) is not str or type(route["path"]) is not str or not route["path"] or any(type(route[k]) is not str or not route[k] for k in ("handler","condition","classification")) or route["method"] not in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"} or route["classification"] not in {"allow", "deny", "runtime_unknown"} or not isinstance(route["effects"], list) or not isinstance(route["secondary_effects"], list) or any(type(x) is not str for x in route["effects"]+route["secondary_effects"]):
            raise SurfaceError("invalid route classification or method")
        pair = (route["method"], route["path"])
        if route["classification"] == "allow" and pair not in ALLOWED:
            raise SurfaceError("allowlist contains an unqualified route")
        if not isinstance(route["source"], dict):
            raise SurfaceError("invalid route source")
        _keys(route["source"], REQUIRED_SOURCE_KEYS, "route source")
        if type(route["source"]["file"]) is not str or not HEX64.fullmatch(route["source"]["sha256"]) or type(route["source"]["line"]) is not int or route["source"]["line"] < 1 or type(route["source"]["contains"]) is not str or not route["source"]["contains"]: raise SurfaceError("invalid route source")
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
    sources = recorded.get("sources")
    if not isinstance(sources, list) or len([x for x in sources if isinstance(x, dict) and x.get("name") == "trailbase"]) != 1: raise SurfaceError("invalid provenance sources")
    selected = [x for x in sources if x.get("name") == "trailbase"][0]
    if set(selected) != {"name","repo","tag","commit","url","archive_sha256","regular_files","expanded_bytes"} or (selected["name"],selected["repo"],selected["tag"],selected["commit"]) != ("trailbase","trailbaseio/trailbase","v0.33.11",COMMIT) or not HEX64.fullmatch(selected["archive_sha256"]): raise SurfaceError("invalid provenance identity")
    if selected["tag"] != manifest["source"]["tag"] or selected["commit"] != manifest["source"]["commit"]:
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
        if expected.get(tag["file"]) != tag["sha256"]: raise SurfaceError(f"route source digest mismatch: {tag['file']}")
        path = source_root / tag["file"]
        lines = path.read_text().splitlines()
        if tag["line"] < 1 or tag["line"] > len(lines) or tag["contains"] not in lines[tag["line"] - 1]:
            raise SurfaceError(f"bad source anchor: {tag['file']}:{tag['line']}")
    actual = {str(p.relative_to(source_root)) for scope in SOURCE_SCOPES for p in (source_root / scope).rglob('*.rs') if p.is_file()}
    if actual != set(expected):
        raise SurfaceError("source inventory does not exactly match configured scopes")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("source_root", type=Path)
    parser.add_argument("provenance", type=Path)
    args = parser.parse_args()
    verify_source(args.source_root, args.provenance, load_manifest(args.manifest))
    print("surface closure verified: 82 routes")
