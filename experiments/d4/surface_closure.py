"""Strict, offline validation of the pinned TrailBase mutation-surface census."""
from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path
from typing import Any

COMMIT = "f24291b894bb6c6696608e5f4c2f68666fe97686"
TRAILBASE = ("trailbase", "trailbaseio/trailbase", "v0.33.11", COMMIT)
LITESTREAM = ("litestream", "benbjohnson/litestream", "v0.5.17", "ccd326c175b583b5e82893a6078f06dcef5fba3f")
ALLOWED = {("POST", "/api/records/v1/main_ops"): "main", ("POST", "/api/records/v1/aux_ops"): "aux", ("POST", "/api/auth/v1/logout"): "session"}
TOP_LEVEL = {"schema_version", "source", "source_scopes", "source_files", "capabilities", "graph_accounting", "unresolved_source_graph", "routes", "section_counts", "debug_only_routes", "exact_allow_rules", "listener_route_instances"}
SAFE_PATH = re.compile(r"^(?!/)(?!$)(?!.*\\)(?!.*(?:^|/)\.{1,2}(?:/|$))[^\x00]+$")
SOURCE_SCOPES = ["crates/core/src", "crates/wasm-runtime-axum/src", "crates/wasm-runtime-common/src", "crates/wasm-runtime-guest/src", "crates/wasm-runtime-host/src"]
HEX64 = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_JOBS = ("Backup", "Heartbeat", "LogCleaner", "AuthCleaner", "QueryOptimizer", "FileDeletions")
REQUIRED_ROUTER_SOURCES = {
    "router:oauth": ("crates/core/src/auth/oauth/mod.rs", "oauth_router"),
    "router:transaction": ("crates/core/src/records/mod.rs", "enable_transactions"),
    "router:custom": ("crates/core/src/server/mod.rs", "custom_router"),
}

class SurfaceError(ValueError): pass

def _is_file(path: Path, name: str) -> bool:
    try:
        return path.is_file()
    except (OSError, UnicodeError, RuntimeError) as exc:
        raise SurfaceError(f"{name}: cannot inspect path") from exc

def _read_bytes(path: Path, name: str) -> bytes:
    try:
        return path.read_bytes()
    except (OSError, UnicodeError, RuntimeError) as exc:
        raise SurfaceError(f"{name}: cannot read bytes") from exc

def _read_text(path: Path, name: str) -> str:
    try:
        return path.read_text()
    except (OSError, UnicodeError, RuntimeError) as exc:
        raise SurfaceError(f"{name}: cannot read text") from exc

def _dict(v: Any, name: str) -> dict:
    if type(v) is not dict: raise SurfaceError(f"{name}: expected object")
    return v

def _list(v: Any, name: str) -> list:
    if type(v) is not list: raise SurfaceError(f"{name}: expected array")
    return v

def _str(v: Any, name: str, nonempty=True) -> str:
    if type(v) is not str or (nonempty and not v): raise SurfaceError(f"{name}: expected string")
    return v

def _keys(v: dict, expected: set[str], name: str) -> None:
    if set(v) != expected: raise SurfaceError(f"{name}: invalid keys")

def _hex(v: Any, name: str) -> None:
    if type(v) is not str or not HEX64.fullmatch(v): raise SurfaceError(f"{name}: invalid digest")

def load_manifest(path: Path | None = None) -> dict[str, Any]:
    if path is not None and not isinstance(path, Path): raise SurfaceError("manifest path must be a Path")
    try: manifest = json.loads((path or Path(__file__).with_name("surface_manifest.json")).read_text())
    except (OSError, UnicodeError, RuntimeError, json.JSONDecodeError) as exc: raise SurfaceError(f"cannot load manifest: {exc}") from exc
    validate_manifest(manifest)
    return manifest

def _source_tag(source: Any) -> None:
    source = _dict(source, "source")
    _keys(source, {"name","repo","tag","commit","root","provenance"}, "source")
    for k in ("name","repo","tag","commit","root"): _str(source[k], f"source.{k}")
    if tuple(source[k] for k in ("name","repo","tag","commit")) != TRAILBASE: raise SurfaceError("wrong TrailBase identity")
    p = _dict(source["provenance"], "provenance"); _keys(p, {"file","sha256"}, "provenance"); _str(p["file"], "provenance.file"); _safe_relative(p["file"], "provenance.file"); _hex(p["sha256"], "provenance.sha256")

def _safe_relative(value: str, name: str) -> None:
    if not SAFE_PATH.fullmatch(value): raise SurfaceError(f"{name}: unsafe relative path")

def _tagged_source(v: Any, name: str) -> None:
    v = _dict(v, name); _keys(v, {"file","sha256","line","contains"}, name)
    _str(v["file"], name); _safe_relative(v["file"], f"{name}.file"); _hex(v["sha256"], name)
    if type(v["line"]) is not int or v["line"] < 1: raise SurfaceError(f"{name}: invalid line")
    _str(v["contains"], name)

def validate_manifest(manifest: dict[str, Any]) -> None:
    m = _dict(manifest, "manifest")
    _keys(m, TOP_LEVEL, "manifest")
    if type(m["schema_version"]) is not int or m["schema_version"] != 1: raise SurfaceError("invalid schema version")
    _source_tag(m["source"])
    scopes = _list(m["source_scopes"], "source_scopes")
    if scopes != SOURCE_SCOPES or any(type(x) is not str or not x or not SAFE_PATH.fullmatch(x) for x in scopes): raise SurfaceError("invalid source scopes")
    unresolved = _list(m["unresolved_source_graph"], "unresolved_source_graph")
    if unresolved or any(type(x) is not str or not x for x in unresolved): raise SurfaceError("source graph is unresolved")
    inventory = {}
    for e in _list(m["source_files"], "source_files"):
        e = _dict(e, "source file"); _keys(e, {"file","sha256","anchors"}, "source file")
        _str(e["file"], "source file"); _safe_relative(e["file"], "source file"); _hex(e["sha256"], "source file.sha256"); anchors = _list(e["anchors"], "anchors")
        if not e["file"].endswith(".rs") or not anchors: raise SurfaceError("invalid source file")
        for a in anchors:
            a = _dict(a, "anchor"); _keys(a, {"line","contains"}, "anchor")
            if type(a["line"]) is not int or a["line"] < 1: raise SurfaceError("invalid anchor line")
            _str(a["contains"], "anchor.contains")
        if e["file"] in inventory: raise SurfaceError("duplicate source file")
        inventory[e["file"]] = e["sha256"]
    routes = _list(m["routes"], "routes")
    if len(routes) != 82: raise SurfaceError("the census must contain exactly 82 routes")
    pairs = set()
    for r in routes:
        r = _dict(r, "route"); _keys(r, {"method","path","handler","source","condition","classification","effects","secondary_effects","resolution","section"}, "route")
        for k in ("method","path","handler","condition","classification","resolution","section"): _str(r[k], f"route.{k}")
        if r["section"] not in {"records","auth","admin","server"} or r["method"] not in {"GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"} or r["classification"] not in {"allow","deny","runtime_unknown"} or r["resolution"] not in {"static","runtime_unknown"}: raise SurfaceError("invalid route values")
        effects, secondary = _list(r["effects"], "effects"), _list(r["secondary_effects"], "secondary_effects")
        if not effects or not secondary or any(type(x) is not str or not x for x in effects + secondary): raise SurfaceError("route effects must be concrete and nonempty")
        _tagged_source(r["source"], "route source")
        if r["source"]["file"] not in inventory or inventory[r["source"]["file"]] != r["source"]["sha256"]: raise SurfaceError("route source digest mismatch")
        pair = (r["method"], r["path"])
        if pair in pairs: raise SurfaceError("duplicate route")
        pairs.add(pair)
        if r["path"] in {"/api/records/v1/main_ops", "/api/records/v1/aux_ops"}: raise SurfaceError("synthetic policy path in upstream routes")
        if r["classification"] != "deny": raise SurfaceError("upstream routes must default deny")
        if r["path"] == "/api/healthcheck" and (r["method"], r["handler"], r["condition"], r["source"]["file"]) != ("GET", "healthcheck_handler", "always", "crates/core/src/server/mod.rs"): raise SurfaceError("invalid healthcheck route")
    if ("DELETE", "/api/auth/v1/delete") not in pairs: raise SurfaceError("account delete route missing")
    if m["section_counts"] != {"records":10,"auth":31,"admin":40,"server":1}: raise SurfaceError("section count mismatch")
    _validate_debug(m, inventory)
    _validate_listener(m, inventory)
    _validate_rules(m, routes)
    caps = _list(m["capabilities"], "capabilities"); names = set()
    for raw in caps:
        raw = _dict(raw, "capability")
        _keys(raw, {"name","class","source_files","edges","condition","resolution","source"}, "capability")
        _str(raw["name"], "capability.name")
        if raw["name"] in names: raise SurfaceError("duplicate capability")
        names.add(raw["name"])
    for c in caps:
        c = _dict(c, "capability"); _keys(c, {"name","class","source_files","edges","condition","resolution","source"}, "capability")
        _str(c["name"], "capability.name"); _str(c["class"], "capability.class"); _str(c["condition"], "capability.condition")
        _tagged_source(c["source"], "capability.source")
        if c["source"]["file"] not in inventory or c["source"]["sha256"] != inventory[c["source"]["file"]]: raise SurfaceError("capability source digest mismatch")
        if not any(a["line"] == c["source"]["line"] for e in m["source_files"] if e["file"] == c["source"]["file"] for a in e["anchors"]): raise SurfaceError("capability source anchor missing from inventory")
        sf = _list(c["source_files"], "capability.source_files")
        if not sf or any(type(x) is not str or x not in inventory for x in sf) or len(set(sf)) != len(sf): raise SurfaceError("invalid capability sources")
        edges = _list(c["edges"], "capability.edges")
        if any(type(x) is not str or x not in names for x in edges): raise SurfaceError("unknown capability edge")
        if c["class"] not in {"router","conditional","job","dynamic_router","listener","direct_writer","provider","telemetry","route"}: raise SurfaceError("invalid capability class")
        if c["resolution"] not in {"static","runtime_unknown"}: raise SurfaceError("invalid capability resolution")
    byname = {c["name"]: c for c in caps}
    if {n for n in byname if n.startswith("job:")} != {"job:" + n for n in REQUIRED_JOBS}: raise SurfaceError("registered job inventory mismatch")
    for name, (file, contains) in REQUIRED_ROUTER_SOURCES.items():
        source = byname[name]["source"]
        if source["file"] != file: raise SurfaceError("router source anchor mismatch")
    route_nodes = {f"route:{r['method']} {r['path']}": r for r in routes}
    if any(name not in byname or byname[name]["class"] != "route" for name in route_nodes): raise SurfaceError("each route requires a route capability")
    for name, r in route_nodes.items():
        node = byname[name]
        if node["source_files"] != [r["source"]["file"]] or node["condition"] != r["condition"] or node["source"] != r["source"]: raise SurfaceError("route capability metadata mismatch")
    debug_node_names = {f"route:{r['method']} {r['path']}" for r in m["debug_only_routes"]}
    if any(c["class"] == "route" and c["name"] not in route_nodes and c["name"] not in debug_node_names for c in caps): raise SurfaceError("unaccounted route capability")
    if len([c for c in caps if c["name"] == "root"]) != 1: raise SurfaceError("one root required")
    if any(c["name"] in c["edges"] for c in caps): raise SurfaceError("self edge")
    if any(len(c["edges"]) != len(set(c["edges"])) for c in caps): raise SurfaceError("duplicate edge")
    reachable = {"root"}
    while True:
        new = reachable | {e for n in reachable for e in byname[n]["edges"]}
        if new == reachable: break
        reachable = new
    if reachable != set(byname): raise SurfaceError("disconnected capability graph")
    accounting = _dict(m["graph_accounting"], "graph_accounting")
    expected = {"routers","conditional_arms","jobs","dynamic_points","listeners","writers","telemetry","routes","debug_routes"}
    _keys(accounting, expected, "graph_accounting")
    for k,v in accounting.items():
        vals = _list(v, f"accounting.{k}")
        if any(type(x) is not str or x not in byname for x in vals) or len(vals) != len(set(vals)): raise SurfaceError(f"invalid accounting.{k}")
    if set(accounting["routers"]) != {n for n,c in byname.items() if c["class"] == "router"} - {"root"}: raise SurfaceError("router accounting mismatch")
    expected_routes = {f"route:{r['method']} {r['path']}" for r in routes}
    debug_routes = {f"route:{r['method']} {r['path']}" for r in m["debug_only_routes"]}
    if set(accounting["debug_routes"]) != debug_routes: raise SurfaceError("debug route accounting mismatch")
    if set(accounting["routes"]) != expected_routes or len(accounting["routes"]) != len(route_nodes): raise SurfaceError("route accounting mismatch")
    if any(byname[n]["class"] != "route" for n in accounting["routes"]): raise SurfaceError("route accounting class mismatch")
    for key, classes in {"conditional_arms":{"conditional"}, "jobs":{"job"}, "dynamic_points":{"dynamic_router"}, "listeners":{"listener"}, "telemetry":{"telemetry"}}.items():
        if any(byname[n]["class"] not in classes for n in accounting[key]): raise SurfaceError(f"{key} class mismatch")
    if any(byname[n]["class"] not in {"direct_writer","provider"} for n in accounting["writers"]): raise SurfaceError("writer class mismatch")

def _validate_debug(m, inventory):
    debug = _list(m["debug_only_routes"], "debug_only_routes")
    if len(debug) != 1: raise SurfaceError("exactly one debug route required")
    r = debug[0]; _tagged_route(r, inventory, "debug route")
    if (r["method"], r["path"], r["handler"], r["condition"]) != ("GET", "/api/whoami", "whoami_handler", "cfg(debug_assertions)"): raise SurfaceError("invalid debug route")
    if r["source"]["file"] != "crates/core/src/server/mod.rs" or "/api/whoami" not in r["source"]["contains"]: raise SurfaceError("invalid debug route anchor")
    node = next((c for c in m["capabilities"] if c["name"] == "route:GET /api/whoami"), None)
    if node is None or node["class"] != "route" or node["condition"] != r["condition"]: raise SurfaceError("debug capability mismatch")

def _tagged_route(r, inventory, name):
    _dict(r, name); _keys(r, {"method","path","handler","source","condition","classification","effects","secondary_effects","resolution","section"}, name)
    _tagged_source(r["source"], name + ".source")
    if r["source"]["file"] not in inventory: raise SurfaceError(name + " source missing")

def _validate_listener(m, inventory):
    items = _list(m["listener_route_instances"], "listener_route_instances")
    if len(items) != 3: raise SurfaceError("listener route count")
    seen = set()
    for i, raw in enumerate(items):
        x = _dict(raw, "listener route"); _keys(x, {"method","path","handler","source","condition"}, "listener route")
        for k in ("method","path","handler","condition"): _str(x[k], "listener route." + k)
        _tagged_source(x["source"], "listener route.source")
        if x["source"]["file"] not in inventory: raise SurfaceError("listener source missing")
        if x["condition"] != "independent_admin_listener": raise SurfaceError("invalid listener condition")
        expected = {("POST", "/api/auth/v1/login", "login_handler"), ("GET", "/api/auth/v1/status", "login_status_handler"), ("GET", "/api/auth/v1/logout", "logout_handler")}
        if (x["method"], x["path"], x["handler"]) not in expected or x["source"]["file"] != "crates/core/src/auth/mod.rs": raise SurfaceError("invalid listener route")
        key = (x["method"],x["path"],x["handler"],x["source"]["file"],x["condition"])
        if key in seen: raise SurfaceError("duplicate listener route")
        seen.add(key)

def _validate_rules(m, routes):
    rules = _dict(m["exact_allow_rules"], "exact_allow_rules")
    if set(rules) != {"POST /api/records/v1/main_ops", "POST /api/records/v1/aux_ops", "POST /api/auth/v1/logout"}: raise SurfaceError("invalid exact allow rules")
    templates = {f"{r['method']} {r['path']}": r for r in routes}
    expected = {"POST /api/records/v1/main_ops": ("POST /api/records/v1/{name}", "main"), "POST /api/records/v1/aux_ops": ("POST /api/transaction/v1/execute", "aux"), "POST /api/auth/v1/logout": ("POST /api/auth/v1/logout", "session")}
    for key, (upstream, db) in expected.items():
        x = _dict(rules[key], "exact allow rule"); _keys(x, {"upstream","database"}, "exact allow rule")
        if x["upstream"] != upstream or x["database"] != db or upstream not in templates: raise SurfaceError("rule-to-template mismatch")

def bind_request(method: str, path: str, manifest: dict[str, Any]) -> str | None:
    validate_manifest(manifest)
    rule = manifest["exact_allow_rules"].get(f"{method} {path}")
    return None if rule is None else rule["database"]

def validate_eligibility_input(manifest):
    validate_manifest(manifest)
    if any(r["resolution"] == "runtime_unknown" or r["classification"] == "runtime_unknown" for r in manifest["routes"]): raise SurfaceError("runtime_unknown is not eligible")
    if any(c["resolution"] == "runtime_unknown" for c in manifest["capabilities"]): raise SurfaceError("runtime_unknown capability is not eligible")

def verify_source(source_root: Path, provenance_path: Path, manifest: dict[str, Any]) -> None:
    if not isinstance(source_root, Path) or not isinstance(provenance_path, Path): raise SurfaceError("source paths must be Paths")
    validate_manifest(manifest); p = manifest["source"]["provenance"]
    if not _is_file(provenance_path, "provenance") or hashlib.sha256(_read_bytes(provenance_path, "provenance")).hexdigest() != p["sha256"]: raise SurfaceError("provenance manifest missing or tampered")
    try: recorded = json.loads(_read_text(provenance_path, "provenance"))
    except (json.JSONDecodeError, TypeError, UnicodeError) as exc: raise SurfaceError("invalid provenance manifest") from exc
    recorded = _dict(recorded, "provenance"); _keys(recorded, {"sources"}, "provenance"); sources = _list(recorded["sources"], "sources")
    if len(sources) != 2: raise SurfaceError("provenance requires TrailBase and Litestream")
    seen = set()
    for s in sources:
        s = _dict(s, "provenance source"); _keys(s, {"name","repo","tag","commit","url","archive_sha256","regular_files","expanded_bytes"}, "provenance source")
        name = _str(s["name"], "provenance name")
        if name in seen: raise SurfaceError("duplicate provenance source")
        seen.add(name); identity = TRAILBASE if name == "trailbase" else LITESTREAM if name == "litestream" else None
        if identity is None or tuple(s[k] for k in ("name","repo","tag","commit")) != identity: raise SurfaceError("invalid provenance identity")
        _str(s["url"], "provenance url"); _hex(s["archive_sha256"], "archive digest")
        expected_url = f"https://codeload.github.com/{identity[1]}/tar.gz/{identity[3]}"
        expected_archive = {"trailbase":"78f694531b28e6f8eb7f600a6c4c63f37437b5e965a1a0a357c19dd5780fd852", "litestream":"cbfb487c66690679234ec46e28d03a2de60b795b7b4466f3444755fc4d39e7d8"}[name]
        if s["url"] != expected_url or s["archive_sha256"] != expected_archive: raise SurfaceError("un pinned archive provenance")
        if type(s["regular_files"]) is not int or s["regular_files"] <= 0 or type(s["expanded_bytes"]) is not int or s["expanded_bytes"] <= 0: raise SurfaceError("invalid provenance sizes")
    if seen != {"trailbase","litestream"}: raise SurfaceError("missing provenance source")
    if source_root.name != manifest["source"]["root"]: raise SurfaceError("source root mismatch")
    try:
        if not source_root.is_dir(): raise SurfaceError("source root is missing or not a directory")
    except (OSError, UnicodeError, RuntimeError) as exc:
        raise SurfaceError("source root cannot be inspected") from exc
    expected = {e["file"]: e for e in manifest["source_files"]}
    for name,e in expected.items():
        path=source_root/name
        if not _is_file(path, name) or hashlib.sha256(_read_bytes(path, name)).hexdigest()!=e["sha256"]: raise SurfaceError(f"missing or tampered source: {name}")
        lines=_read_text(path, name).splitlines()
        for a in e["anchors"]:
            if a["line"] > len(lines) or a["contains"] not in lines[a["line"]-1]: raise SurfaceError(f"bad source anchor: {name}")
    for r in manifest["routes"] + manifest["debug_only_routes"]:
        s=r["source"]; path=source_root/s["file"]; lines=_read_text(path, s["file"]).splitlines()
        if s["line"] > len(lines) or s["contains"] not in lines[s["line"]-1]: raise SurfaceError("bad route anchor")
    for r in manifest["listener_route_instances"]:
        s=r["source"]; path=source_root/s["file"]; lines=_read_text(path, s["file"]).splitlines()
        if s["line"] > len(lines) or s["contains"] not in lines[s["line"]-1]: raise SurfaceError("bad listener anchor")
    try:
        actual={str(x.relative_to(source_root)) for scope in SOURCE_SCOPES for x in (source_root/scope).rglob("*.rs") if _is_file(x, "source enumeration")}
    except (OSError, UnicodeError, RuntimeError, ValueError) as exc:
        raise SurfaceError("source enumeration failed") from exc
    if actual != set(expected): raise SurfaceError("source inventory does not exactly match configured scopes")

if __name__ == "__main__":
    import argparse
    ap=argparse.ArgumentParser(); ap.add_argument("manifest",type=Path); ap.add_argument("source_root",type=Path); ap.add_argument("provenance",type=Path); a=ap.parse_args()
    verify_source(a.source_root,a.provenance,load_manifest(a.manifest)); print("surface closure verified: 82 routes")
