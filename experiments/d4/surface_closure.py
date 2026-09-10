"""Strict, offline validation of the pinned TrailBase mutation-surface census."""
from __future__ import annotations
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any
from dataclasses import dataclass
from types import MappingProxyType
import math

COMMIT = "f24291b894bb6c6696608e5f4c2f68666fe97686"
TRAILBASE = ("trailbase", "trailbaseio/trailbase", "v0.33.11", COMMIT)
LITESTREAM = ("litestream", "benbjohnson/litestream", "v0.5.17", "ccd326c175b583b5e82893a6078f06dcef5fba3f")
ALLOWED = {("POST", "/api/records/v1/main_ops"): "main", ("POST", "/api/records/v1/aux_ops"): "aux", ("POST", "/api/auth/v1/logout"): "session"}
TOP_LEVEL = {"schema_version", "source", "source_scopes", "source_files", "capabilities", "graph_accounting", "unresolved_source_graph", "routes", "section_counts", "debug_only_routes", "exact_allow_rules", "listener_route_instances"}
SAFE_PATH = re.compile(r"^(?!/)(?!$)(?!.*\\)(?!.*(?:^|/)\.{1,2}(?:/|$))[^\x00]+$")
SOURCE_SCOPES = ["crates/core/src", "crates/wasm-runtime-axum/src", "crates/wasm-runtime-common/src", "crates/wasm-runtime-guest/src", "crates/wasm-runtime-host/src"]
PINNED_MANIFEST_SHA256 = "bb6854d24732fc192da5e7fc6fdc6a9b0927603900d91fe0727d6846c56488bf"
MAX_ARTIFACT_BYTES = 1024 * 1024
HEX64 = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_JOBS = ("Backup", "Heartbeat", "LogCleaner", "AuthCleaner", "QueryOptimizer", "FileDeletions")
REQUIRED_NON_ROUTE = {
    "router:server": ("router", "crates/core/src/server/mod.rs", 423, "OpenApiRouter::new()", "always; main assembly; enable_transactions read at :421"),
    "router:records": ("router", "crates/core/src/records/mod.rs", 35, "pub(crate) fn router", "always; transaction child conditional"),
    "router:transaction": ("router", "crates/core/src/records/mod.rs", 69, "transaction::record_transactions_handler", "config.server.enable_record_transactions() true"),
    "router:auth": ("router", "crates/core/src/auth/mod.rs", 49, "let mut router = OpenApiRouter::new()", "always; anonymous arms at :86-90; OTP arms at :93-97"),
    "router:oauth": ("router", "crates/core/src/auth/oauth/mod.rs", 20, "oauth_router", "always; merged by auth"),
    "router:admin": ("router", "crates/core/src/server/mod.rs", 385, "pub(crate) fn build_admin_router", "always when admin is built; independent or main placement decided :166-197"),
    "router:admin-auth": ("router", "crates/core/src/auth/mod.rs", 113, "pub(super) fn admin_auth_router", "only independent admin router"),
    "router:wasm": ("router", "crates/core/src/server/mod.rs", 142, "crate::wasm::install_routes_and_jobs", "compile feature wasm; runtime component(s) present; each returned router pushed"),
    "router:custom": ("router", "crates/core/src/server/mod.rs", 131, "custom_router.into_iter()", "ServerOptions.custom_router supplied"),
    "conditional:transactions-enabled": ("conditional", "crates/core/src/server/mod.rs", 421, "let enable_transactions", "config flag true"),
    "conditional:records-subscribe-sqlite": ("conditional", "crates/core/src/records/mod.rs", 59, "matches!(connection_type, ConnectionType::Sqlite)", "SQLite connection"),
    "conditional:auth-anonymous-signin": ("conditional", "crates/core/src/auth/mod.rs", 93, "if config.auth.enable_anonymous_signin()", "anonymous auth enabled"),
    "conditional:auth-otp-signin": ("conditional", "crates/core/src/auth/mod.rs", 101, "if config.auth.enable_otp_signin()", "OTP auth enabled"),
    "conditional:wasm-feature": ("conditional", "crates/core/src/server/mod.rs", 137, "#[cfg(feature = \"wasm\")]", "compile feature"),
    "conditional:independent-admin-listener": ("conditional", "crates/core/src/server/mod.rs", 166, "if let Some(admin_address)", "admin address differs from main"),
    "conditional:public-dir": ("conditional", "crates/core/src/server/mod.rs", 459, "if let Some(public_dir)", "public directory supplied"),
    "conditional:public-dir-spa": ("conditional", "crates/core/src/server/mod.rs", 469, "if public_dir_spa", "SPA option and public dir"),
    "conditional:auth-rate-limit": ("conditional", "crates/core/src/server/mod.rs", 157, "if !state.dev_mode()", "non-dev + configured positive limit"),
    "job:Backup": ("job", "crates/core/src/scheduler.rs", 285, "SystemJobId::Backup", "registry always constructs; disabled by default (:295), config can enable"),
    "job:Heartbeat": ("job", "crates/core/src/scheduler.rs", 316, "SystemJobId::Heartbeat", "enabled default"),
    "job:LogCleaner": ("job", "crates/core/src/scheduler.rs", 329, "SystemJobId::LogCleaner", "enabled default; config retention"),
    "job:AuthCleaner": ("job", "crates/core/src/scheduler.rs", 362, "SystemJobId::AuthCleaner", "enabled default"),
    "job:QueryOptimizer": ("job", "crates/core/src/scheduler.rs", 396, "SystemJobId::QueryOptimizer", "enabled default"),
    "job:FileDeletions": ("job", "crates/core/src/scheduler.rs", 421, "SystemJobId::FileDeletions", "enabled default; iterates main/configured DBs :440-464"),
    "dynamic:wasm-manifest": ("dynamic_router", "crates/core/src/wasm/mod.rs", 170, "install_routes_and_jobs::<AppState>", "wasm feature/runtime present"),
    "dynamic:custom-router": ("dynamic_router", "crates/core/src/server/mod.rs", 456, "merge(custom_router)", "custom router option supplied"),
    "listener:main": ("listener", "crates/core/src/server/mod.rs", 368, "start_listen(addr, router", "always main; UDS :719-737 or TCP :742-774"),
    "listener:admin": ("listener", "crates/core/src/server/mod.rs", 192, "Some((admin_address, admin_router))", "admin_address present and differs from main"),
    "writer:main-db": ("direct_writer", "crates/core/src/app_state.rs", 58, "conn", "always; main connection initialized by manager (connection.rs:121-150)"),
    "writer:session-db": ("direct_writer", "crates/core/src/connection.rs", 568, "pub fn init_session_db", "always"),
    "writer:logs-db": ("direct_writer", "crates/core/src/connection.rs", 542, "pub(super) fn init_logs_db", "always; one writer (num_threads: Some(1))"),
    "writer:sql-query": ("direct_writer", "crates/core/src/admin/mod.rs", 77, "routes!(query::query_handler)", "admin route capability; SQL query handler is HTTP route"),
    "writer:ddl": ("direct_writer", "crates/core/src/admin/mod.rs", 42, "table::create_index::create_index_handler", "admin capability"),
    "writer:config": ("direct_writer", "crates/core/src/admin/config/update_config.rs", 26, "update_config_handler", "admin capability; config update"),
    "writer:backup": ("direct_writer", "crates/core/src/admin/backup.rs", 52, "trigger_backup_handler", "admin capability; backup trigger"),
    "writer:restore": ("direct_writer", "crates/core/src/admin/backup.rs", 134, "restore_backup_handler", "admin capability; restore"),
    "writer:filesystem": ("direct_writer", "crates/core/src/admin/rows/read_files.rs", 40, "read_files_handler", "admin/files capability; file read/delete paths are handled here and record file code"),
    "writer:object-store": ("direct_writer", "crates/core/src/app_state.rs", 598, "build_objectstore", "S3 config present -> AWS object store :602-632; absent -> local uploads filesystem :634-636"),
    "writer:wasm": ("direct_writer", "crates/core/src/wasm/mod.rs", 130, "pub(crate) async fn install_routes_and_jobs", "wasm feature/runtime present; guest may expose routes/jobs and DB/file effects"),
    "provider:email-smtp": ("provider", "crates/core/src/email.rs", 329, "fn new_smtp", "valid email SMTP config"),
    "provider:email-sendmail": ("provider", "crates/core/src/email.rs", 368, "fn new_local", "SMTP config absent/invalid; fallback :392-397"),
    "provider:oauth-oidc": ("provider", "crates/core/src/auth/oauth/providers/mod.rs", 48, "oidc::OidcProvider::registry_entry(0)", "statically registered; instantiated only configured provider entry"),
    "provider:oauth-apple": ("provider", "crates/core/src/auth/oauth/providers/mod.rs", 50, "AppleOAuthProvider::registry_entry()", "static registry; configured entry"),
    "provider:oauth-discord": ("provider", "crates/core/src/auth/oauth/providers/mod.rs", 51, "DiscordOAuthProvider", "static registry; configured entry"),
    "provider:oauth-gitlab": ("provider", "crates/core/src/auth/oauth/providers/mod.rs", 52, "GitlabOAuthProvider", "static registry; configured entry"),
    "provider:oauth-github": ("provider", "crates/core/src/auth/oauth/providers/mod.rs", 53, "GithubOAuthProvider::registry_entry()", "static registry; configured entry"),
    "provider:oauth-google": ("provider", "crates/core/src/auth/oauth/providers/mod.rs", 54, "GoogleOAuthProvider", "static registry; configured entry"),
    "provider:oauth-facebook": ("provider", "crates/core/src/auth/oauth/providers/mod.rs", 55, "FacebookOAuthProvider", "static registry; configured entry"),
    "provider:oauth-microsoft": ("provider", "crates/core/src/auth/oauth/providers/mod.rs", 56, "MicrosoftOAuthProvider", "static registry; configured entry"),
    "provider:oauth-twitch": ("provider", "crates/core/src/auth/oauth/providers/mod.rs", 57, "TwitchOAuthProvider", "static registry; configured entry"),
    "provider:oauth-yandex": ("provider", "crates/core/src/auth/oauth/providers/mod.rs", 58, "YandexOAuthProvider", "static registry; configured entry"),
    "telemetry:logs": ("telemetry", "crates/core/src/logging.rs", 230, "pub fn new", "tracing/default layers installed; async writer :238-258; inserts _logs :306-318"),
}
EXPECTED_ACCOUNTING = {
    "routers": ["router:server","router:records","router:transaction","router:auth","router:oauth","router:admin","router:admin-auth","router:wasm","router:custom"],
    "conditional_arms": ["conditional:transactions-enabled","conditional:records-subscribe-sqlite","conditional:auth-anonymous-signin","conditional:auth-otp-signin","conditional:wasm-feature","conditional:independent-admin-listener","conditional:public-dir","conditional:public-dir-spa","conditional:auth-rate-limit"],
    "jobs": ["job:Backup","job:Heartbeat","job:LogCleaner","job:AuthCleaner","job:QueryOptimizer","job:FileDeletions"],
    "dynamic_points": ["dynamic:wasm-manifest","dynamic:custom-router"],
    "listeners": ["listener:main","listener:admin"],
    "writers": ["writer:main-db","writer:session-db","writer:logs-db","writer:sql-query","writer:ddl","writer:config","writer:backup","writer:restore","writer:filesystem","writer:object-store","writer:wasm"],
    "providers": ["provider:email-smtp","provider:email-sendmail","provider:oauth-oidc","provider:oauth-apple","provider:oauth-discord","provider:oauth-gitlab","provider:oauth-github","provider:oauth-google","provider:oauth-facebook","provider:oauth-microsoft","provider:oauth-twitch","provider:oauth-yandex"],
    "telemetry": ["telemetry:logs"],
}

EXPECTED_ROUTE_CONDITIONS = {
    ('GET', '/api/records/v1/{name}'): 'always',
    ('POST', '/api/records/v1/{name}'): 'always',
    ('POST', '/api/transaction/v1/execute'): 'config:transactions_enabled',
    ('GET', '/api/records/v1/{name}/{record}'): 'always',
    ('GET', '/api/records/v1/{name}/{record}/file/{column_name}'): 'always',
    ('GET', '/api/records/v1/{name}/{record}/files/{column_name}/{file_name}'): 'always',
    ('PATCH', '/api/records/v1/{name}/{record}'): 'always',
    ('GET', '/api/records/v1/{name}/schema'): 'always',
    ('DELETE', '/api/records/v1/{name}/{record}'): 'always',
    ('GET', '/api/records/v1/{name}/subscribe/{record}'): 'config:sqlite',
    ('GET', '/api/auth/v1/oauth/{provider}/callback'): 'always',
    ('POST', '/api/auth/v1/oauth/{provider}/callback'): 'always',
    ('GET', '/api/auth/v1/oauth/{provider}/login'): 'always',
    ('GET', '/api/auth/v1/oauth/providers'): 'always',
    ('GET', '/api/auth/v1/avatar/{b64_user_id}'): 'always',
    ('POST', '/api/auth/v1/avatar'): 'always',
    ('DELETE', '/api/auth/v1/avatar'): 'always',
    ('POST', '/api/auth/v1/change_username'): 'always',
    ('POST', '/api/auth/v1/otp/request'): 'config:otp_enabled',
    ('POST', '/api/auth/v1/otp/login'): 'config:otp_enabled',
    ('POST', '/api/auth/v1/token'): 'always',
    ('GET', '/api/auth/v1/verify_email/trigger'): 'always',
    ('GET', '/api/auth/v1/verify_email/confirm/{email_verification_token}'): 'always',
    ('POST', '/api/auth/v1/register'): 'always',
    ('POST', '/api/auth/v1/promote_anonymous'): 'config:anonymous_enabled',
    ('GET', '/api/auth/v1/totp/register'): 'always',
    ('POST', '/api/auth/v1/totp/confirm'): 'always',
    ('POST', '/api/auth/v1/totp/unregister'): 'always',
    ('DELETE', '/api/auth/v1/delete'): 'always',
    ('POST', '/api/auth/v1/change_password'): 'always',
    ('GET', '/api/auth/v1/logout'): 'always',
    ('POST', '/api/auth/v1/logout'): 'always',
    ('POST', '/api/auth/v1/login_anonymous'): 'config:anonymous_enabled',
    ('GET', '/api/auth/v1/status'): 'always',
    ('POST', '/api/auth/v1/login'): 'always',
    ('POST', '/api/auth/v1/login_mfa'): 'always',
    ('POST', '/api/auth/v1/change_email/request'): 'always',
    ('GET', '/api/auth/v1/change_email/confirm/{email_verification_code}'): 'always',
    ('POST', '/api/auth/v1/reset_password/request'): 'always',
    ('POST', '/api/auth/v1/reset_password/update'): 'always',
    ('POST', '/api/auth/v1/refresh'): 'always',
    ('GET', '/api/_admin/openapi.json'): 'always',
    ('POST', '/api/_admin/query'): 'always',
    ('GET', '/api/_admin/backups'): 'always',
    ('POST', '/api/_admin/backups/trigger'): 'always',
    ('DELETE', '/api/_admin/backups/delete'): 'always',
    ('PATCH', '/api/_admin/backups/restore'): 'always',
    ('GET', '/api/_admin/public_key'): 'always',
    ('POST', '/api/_admin/parse'): 'always',
    ('GET', '/api/_admin/info'): 'always',
    ('POST', '/api/_admin/mint'): 'always',
    ('POST', '/api/_admin/email/test'): 'always',
    ('GET', '/api/_admin/oauth_providers'): 'always',
    ('GET', '/api/_admin/wasm'): 'always',
    ('POST', '/api/_admin/wasm/install'): 'always',
    ('POST', '/api/_admin/wasm/uninstall'): 'always',
    ('GET', '/api/_admin/config'): 'always',
    ('POST', '/api/_admin/config'): 'always',
    ('GET', '/api/_admin/schema/{record_api_name}/schema.json'): 'always',
    ('GET', '/api/_admin/schema'): 'always',
    ('POST', '/api/_admin/user'): 'always',
    ('GET', '/api/_admin/user'): 'always',
    ('PATCH', '/api/_admin/user'): 'always',
    ('DELETE', '/api/_admin/user'): 'always',
    ('PATCH', '/api/_admin/table/{table_name}'): 'always',
    ('GET', '/api/_admin/table/{table_name}/rows'): 'always',
    ('GET', '/api/_admin/table/{table_name}/files'): 'always',
    ('DELETE', '/api/_admin/table/{table_name}'): 'always',
    ('DELETE', '/api/_admin/table/{table_name}/rows'): 'always',
    ('POST', '/api/_admin/table/{table_name}'): 'always',
    ('GET', '/api/_admin/logs/list'): 'always',
    ('GET', '/api/_admin/logs/stats'): 'always',
    ('PATCH', '/api/_admin/index'): 'always',
    ('POST', '/api/_admin/index'): 'always',
    ('DELETE', '/api/_admin/index'): 'always',
    ('GET', '/api/_admin/tables'): 'always',
    ('DELETE', '/api/_admin/table'): 'always',
    ('POST', '/api/_admin/table'): 'always',
    ('PATCH', '/api/_admin/table'): 'always',
    ('GET', '/api/_admin/jobs'): 'always',
    ('POST', '/api/_admin/job/run'): 'always',
    ('GET', '/api/healthcheck'): 'always',
}
class SurfaceError(ValueError): pass

@dataclass(frozen=True)
class ClosureRequest:
    method: bytes
    target: bytes
    headers: tuple[tuple[bytes, bytes], ...]
    body: bytes

    def __repr__(self) -> str:
        return f"ClosureRequest(method={self.method!r}, target={self.target!r}, headers=<redacted>, body=<redacted>)"

@dataclass(frozen=True)
class ValidatedRequest:
    method: bytes
    target: bytes
    headers: tuple[tuple[bytes, bytes], ...]
    body_sha256: str

@dataclass(frozen=True)
class Binding:
    operation_kind: str
    database: str
    validated_request: ValidatedRequest

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
    try:
        with open(path or Path(__file__).with_name("surface_manifest.json"), "rb") as stream:
            data = stream.read(MAX_ARTIFACT_BYTES + 1)
        if len(data) > MAX_ARTIFACT_BYTES:
            raise SurfaceError("manifest exceeds 1MiB")
        manifest = json.loads(data)
    except (OSError, UnicodeError, RuntimeError, json.JSONDecodeError) as exc:
        raise SurfaceError("cannot load manifest") from exc
    validate_manifest(manifest)
    return manifest

def _source_tag(source: Any) -> None:
    source = _dict(source, "source")
    _keys(source, {"name","repo","tag","commit","root","provenance"}, "source")
    for k in ("name","repo","tag","commit","root"): _str(source[k], f"source.{k}")
    if tuple(source[k] for k in ("name","repo","tag","commit")) != TRAILBASE: raise SurfaceError("wrong TrailBase identity")
    _safe_single_name(source["root"], "source.root")
    p = _dict(source["provenance"], "provenance"); _keys(p, {"file","sha256"}, "provenance"); _str(p["file"], "provenance.file"); _safe_single_name(p["file"], "provenance.file"); _hex(p["sha256"], "provenance.sha256")

def _safe_relative(value: str, name: str) -> None:
    if not SAFE_PATH.fullmatch(value): raise SurfaceError(f"{name}: unsafe relative path")

def _safe_single_name(value: str, name: str) -> None:
    _safe_relative(value, name)
    if "/" in value: raise SurfaceError(f"{name}: expected a single relative name")

def _manifest_sha256(manifest: dict[str, Any]) -> str:
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()

def _tagged_source(v: Any, name: str) -> None:
    v = _dict(v, name); _keys(v, {"file","sha256","line","contains"}, name)
    _str(v["file"], name); _safe_relative(v["file"], f"{name}.file"); _hex(v["sha256"], name)
    if type(v["line"]) is not int or v["line"] < 1: raise SurfaceError(f"{name}: invalid line")
    _str(v["contains"], name)

def _in_scope(file: str) -> bool:
    return any(file.startswith(scope + "/") for scope in SOURCE_SCOPES)

def _inventory_anchor(inventory: dict[str, dict], source: dict, name: str) -> None:
    entry = inventory.get(source["file"])
    if entry is None or source["sha256"] != entry["sha256"]:
        raise SurfaceError(f"{name}: source digest mismatch")
    if (source["line"], source["contains"]) not in {
        (a["line"], a["contains"]) for a in entry["anchors"]
    }:
        raise SurfaceError(f"{name}: source anchor mismatch")

def _validate_non_routes(caps: list[dict], inventory: dict[str, dict]) -> dict[str, dict]:
    byname = {c["name"]: c for c in caps}
    actual = {name for name, c in byname.items() if c["class"] != "route"}
    if actual != set(REQUIRED_NON_ROUTE):
        raise SurfaceError("non-route capability inventory mismatch")
    for name, expected in REQUIRED_NON_ROUTE.items():
        c = byname[name]
        cls, file, line, contains, condition = expected
        if c["class"] != cls or c["condition"] != condition or c["source_files"] != [file]:
            raise SurfaceError(f"{name}: audited metadata mismatch")
        source = c["source"]
        if (source["file"], source["line"], source["contains"]) != (file, line, contains):
            raise SurfaceError(f"{name}: audited source mismatch")
        _inventory_anchor(inventory, source, name)
    return byname

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
        _str(e["file"], "source file"); _safe_relative(e["file"], "source file")
        if not _in_scope(e["file"]): raise SurfaceError("source file outside configured scopes")
        _hex(e["sha256"], "source file.sha256"); anchors = _list(e["anchors"], "anchors")
        if not e["file"].endswith(".rs") or not anchors: raise SurfaceError("invalid source file")
        for a in anchors:
            a = _dict(a, "anchor"); _keys(a, {"line","contains"}, "anchor")
            if type(a["line"]) is not int or a["line"] < 1: raise SurfaceError("invalid anchor line")
            _str(a["contains"], "anchor.contains")
        if e["file"] in inventory: raise SurfaceError("duplicate source file")
        inventory[e["file"]] = e
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
        _inventory_anchor(inventory, r["source"], "route source")
        pair = (r["method"], r["path"])
        if pair in pairs: raise SurfaceError("duplicate route")
        pairs.add(pair)
        if r["path"] in {"/api/records/v1/main_ops", "/api/records/v1/aux_ops"}: raise SurfaceError("synthetic policy path in upstream routes")
        if r["classification"] != "deny": raise SurfaceError("upstream routes must default deny")
        if r["path"] == "/api/healthcheck" and (r["method"], r["handler"], r["condition"], r["source"]["file"]) != ("GET", "healthcheck_handler", "always", "crates/core/src/server/mod.rs"): raise SurfaceError("invalid healthcheck route")
    if pairs != set(EXPECTED_ROUTE_CONDITIONS): raise SurfaceError("route identity census mismatch")
    for r in routes:
        if EXPECTED_ROUTE_CONDITIONS[(r["method"], r["path"])] != r["condition"]: raise SurfaceError("route condition census mismatch")
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
        _inventory_anchor(inventory, c["source"], "capability.source")
        sf = _list(c["source_files"], "capability.source_files")
        if not sf or any(type(x) is not str or x not in inventory for x in sf) or len(set(sf)) != len(sf): raise SurfaceError("invalid capability sources")
        edges = _list(c["edges"], "capability.edges")
        if any(type(x) is not str or x not in names for x in edges): raise SurfaceError("unknown capability edge")
        if c["class"] not in {"router","conditional","job","dynamic_router","listener","direct_writer","provider","telemetry","route"}: raise SurfaceError("invalid capability class")
        if c["resolution"] not in {"static","runtime_unknown"}: raise SurfaceError("invalid capability resolution")
    byname = _validate_non_routes(caps, inventory)
    route_nodes = {f"route:{r['method']} {r['path']}": r for r in routes}
    if any(name not in byname or byname[name]["class"] != "route" for name in route_nodes): raise SurfaceError("each route requires a route capability")
    for name, r in route_nodes.items():
        node = byname[name]
        if node["source_files"] != [r["source"]["file"]] or node["condition"] != r["condition"] or node["source"] != r["source"]: raise SurfaceError("route capability metadata mismatch")
    debug_node_names = {f"route:{r['method']} {r['path']}" for r in m["debug_only_routes"]}
    if any(c["class"] == "route" and c["name"] not in route_nodes and c["name"] not in debug_node_names for c in caps): raise SurfaceError("unaccounted route capability")
    if any(c["name"] in c["edges"] for c in caps): raise SurfaceError("self edge")
    if any(len(c["edges"]) != len(set(c["edges"])) for c in caps): raise SurfaceError("duplicate edge")
    reachable = {"router:server"}
    while True:
        new = reachable | {e for n in reachable for e in byname[n]["edges"]}
        if new == reachable: break
        reachable = new
    if reachable != set(byname): raise SurfaceError("disconnected capability graph")
    accounting = _dict(m["graph_accounting"], "graph_accounting")
    _keys(accounting, set(EXPECTED_ACCOUNTING), "graph_accounting")
    if any(accounting[k] != v for k, v in EXPECTED_ACCOUNTING.items()): raise SurfaceError("source accounting mismatch")
    if _manifest_sha256(m) != PINNED_MANIFEST_SHA256: raise SurfaceError("manifest SHA-256 pin mismatch")

def _validate_debug(m, inventory):
    debug = _list(m["debug_only_routes"], "debug_only_routes")
    if len(debug) != 1: raise SurfaceError("exactly one debug route required")
    r = debug[0]; _tagged_route(r, inventory, "debug route")
    if (r["method"], r["path"], r["handler"], r["condition"]) != ("GET", "/api/whoami", "whoami_handler", "cfg(debug_assertions)"): raise SurfaceError("invalid debug route")
    if r["source"]["file"] != "crates/core/src/server/mod.rs" or "/api/whoami" not in r["source"]["contains"]: raise SurfaceError("invalid debug route anchor")
    _inventory_anchor(inventory, r["source"], "debug route source")
    node = next((c for c in m["capabilities"] if type(c) is dict and c.get("name") == "route:GET /api/whoami"), None)
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
        _inventory_anchor(inventory, x["source"], "listener source")
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
    expected = {"POST /api/records/v1/main_ops": ("POST /api/records/v1/{name}", "main"), "POST /api/records/v1/aux_ops": ("POST /api/records/v1/{name}", "aux"), "POST /api/auth/v1/logout": ("POST /api/auth/v1/logout", "session")}
    for key, (upstream, db) in expected.items():
        x = _dict(rules[key], "exact allow rule"); _keys(x, {"upstream","database"}, "exact allow rule")
        if x["upstream"] != upstream or x["database"] != db or upstream not in templates: raise SurfaceError("rule-to-template mismatch")

def _strict_json(body: bytes) -> object:
    if type(body) is not bytes or not body:
        raise SurfaceError("invalid JSON framing")
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out: raise SurfaceError("duplicate JSON key")
            out[key] = value
        return out
    def constant(value):
        raise SurfaceError("nonfinite JSON number")
    def parse():
        try:
            return json.loads(body.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
        except (UnicodeDecodeError, ValueError, SurfaceError):
            return None
    value = parse()
    if value is None:
        raise SurfaceError("invalid JSON")
    if type(value) is not dict: raise SurfaceError("JSON object required")
    return value

def bind_request(request: ClosureRequest, manifest: dict[str, Any]) -> Binding | None:
    validate_manifest(manifest)
    if type(request) is not ClosureRequest or type(request.method) is not bytes or type(request.target) is not bytes or type(request.headers) is not tuple or type(request.body) is not bytes:
        raise SurfaceError("request fields must be exact bytes")
    if request.method != b"POST" or len(request.body) > 1024 * 1024: raise SurfaceError("invalid method or body")
    target = request.target
    if not target.isascii() or not target.startswith(b"/api/") or any(c < 0x20 or c == 0x7f for c in target) or any(x in target for x in (b"?", b"#", b"%", b"\\")) or b"//" in target or any(part in (b".", b"..") for part in target.split(b"/")) or target.endswith(b"/"):
        raise SurfaceError("invalid target")
    if any(type(header) is not tuple or len(header) != 2 or type(header[0]) is not bytes or type(header[1]) is not bytes for header in request.headers):
        raise SurfaceError("invalid headers")
    allowed = {b"/api/records/v1/main_ops": ("create_record", "main"), b"/api/records/v1/aux_ops": ("create_record", "aux"), b"/api/auth/v1/logout": ("logout_session", "session")}
    if request.target not in allowed: return None
    kind, database = allowed[target]
    folded = [name.lower() for name, _ in request.headers]
    if len(set(folded)) != len(folded): raise SurfaceError("duplicate headers")
    content_types = [value for name, value in zip(folded, (v for _, v in request.headers)) if name == b"content-type"]
    if (len(content_types) != 1 or any(c < 0x20 or c == 0x7f for name, value in request.headers for c in name + value)
            or any(name != name.strip(b" \\t") for name, _ in request.headers) or content_types[0] != b"application/json"):
        raise SurfaceError("invalid content type")
    auth = [value for name, value in zip(folded, (v for _, v in request.headers)) if name == b"authorization"]
    if kind != "logout_session":
        if len(request.headers) != 2 or len(auth) != 1:
            raise SurfaceError("invalid authorization")
        token = auth[0][len(b"Bearer "): ] if auth[0].startswith(b"Bearer ") else b""
        if not re.fullmatch(rb"[A-Za-z0-9._~-]{1,4096}", token): raise SurfaceError("invalid authorization")
    elif len(request.headers) != 1:
        raise SurfaceError("invalid logout headers")
    obj = _strict_json(request.body)
    if kind == "logout_session":
        if set(obj) != {"refresh_token"} or type(obj["refresh_token"]) is not str or not re.fullmatch(r"[A-Za-z0-9]{86}", obj["refresh_token"]): raise SurfaceError("invalid logout body")
    else:
        if set(obj) != {"op_key", "payload"} or any(type(obj[k]) is not str or not 1 <= len(obj[k]) <= 1024 for k in obj): raise SurfaceError("invalid operation body")
    validated = ValidatedRequest(request.method, request.target,
                                 ((b"Content-Type", b"application/json"),),
                                 hashlib.sha256(request.body).hexdigest())
    return Binding(kind, database, validated)

def validate_eligibility_input(manifest):
    validate_manifest(manifest)
    if any(r["resolution"] == "runtime_unknown" or r["classification"] == "runtime_unknown" for r in manifest["routes"]): raise SurfaceError("runtime_unknown is not eligible")
    if any(c["resolution"] == "runtime_unknown" for c in manifest["capabilities"]): raise SurfaceError("runtime_unknown capability is not eligible")

def _open_at(root_fd: int, absolute: Path, name: str, directory: bool = False) -> int:
    # resolve is only canonical-input policy; trust is on held descriptors, each child O_NOFOLLOW.
    try:
        if not absolute.is_absolute() or absolute.resolve(strict=True) != absolute:
            raise SurfaceError(f"{name}: path must be canonical absolute path")
        fd = os.dup(root_fd)
        try:
            for part in absolute.parts[1:]:
                flags = os.O_RDONLY | os.O_NOFOLLOW | (os.O_DIRECTORY if directory or part != absolute.parts[-1] else 0)
                new_fd = os.open(part, flags, dir_fd=fd)
                os.close(fd); fd = new_fd
            mode = os.fstat(fd).st_mode
            if directory and not stat.S_ISDIR(mode): raise SurfaceError(f"{name}: not a directory")
            return fd
        except Exception:
            os.close(fd); raise
    except SurfaceError: raise
    except (OSError, UnicodeError, RuntimeError, ValueError) as exc: raise SurfaceError(f"{name}: cannot open canonical path") from exc

def _open_relative(fd: int, parts: tuple[str, ...], name: str) -> int:
    current = None
    try:
        current = os.dup(fd)
        for part in parts:
            child = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | (os.O_DIRECTORY if part != parts[-1] else 0), dir_fd=current)
            os.close(current); current = child
        return current
    except (OSError, UnicodeError, RuntimeError, ValueError) as exc:
        if current is not None:
            try: os.close(current)
            except OSError: pass
        raise SurfaceError(f"{name}: cannot open relative path") from exc

def _fd_bytes(fd: int, name: str, identity: tuple[int, int, int] | None = None, max_bytes: int | None = None) -> bytes:
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode): raise SurfaceError(f"{name}: not a regular file")
        if identity is not None and (st.st_dev, st.st_ino, st.st_size) != identity:
            raise SurfaceError(f"{name}: descriptor identity changed")
        if max_bytes is not None and st.st_size > max_bytes:
            raise SurfaceError(f"{name}: exceeds size limit")
        chunks = []
        total = 0
        while chunk := os.read(fd, min(1024 * 1024, (max_bytes - total + 1) if max_bytes is not None else 1024 * 1024)):
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise SurfaceError(f"{name}: exceeds size limit")
            chunks.append(chunk)
        data = b"".join(chunks)
        if identity is not None and len(data) != identity[2]:
            raise SurfaceError(f"{name}: descriptor size changed")
        return data
    except SurfaceError: raise
    except (OSError, UnicodeError, RuntimeError) as exc: raise SurfaceError(f"{name}: cannot read") from exc

def _snapshot_source_files(source_fd: int, held_fds: list[int]) -> dict[str, tuple[int, tuple[int, int, int]]]:
    snapshot = {}
    identities = set()
    pending = []
    try:
        for scope in SOURCE_SCOPES:
            directory = _open_relative(source_fd, tuple(scope.split("/")), "source enumeration")
            held_fds.append(directory)
            pending.append((directory, scope))
        while pending:
            directory, relative = pending.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    child_fd = None
                    try:
                        child_fd = os.open(entry.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
                        st = os.fstat(child_fd)
                        child_relative = f"{relative}/{entry.name}"
                        if stat.S_ISDIR(st.st_mode):
                            held_fds.append(child_fd)
                            pending.append((child_fd, child_relative))
                            child_fd = None
                        elif stat.S_ISREG(st.st_mode):
                            if entry.name.endswith(".rs"):
                                identity = (st.st_dev, st.st_ino, st.st_size)
                                if child_relative in snapshot or identity[:2] in identities:
                                    raise SurfaceError("duplicate source file")
                                held_fds.append(child_fd)
                                snapshot[child_relative] = (child_fd, identity)
                                identities.add(identity[:2])
                                child_fd = None
                        else:
                            raise SurfaceError("source enumeration found special file")
                    finally:
                        if child_fd is not None: os.close(child_fd)
        return snapshot
    except SurfaceError: raise
    except (OSError, UnicodeError, RuntimeError, ValueError) as exc:
        raise SurfaceError("source enumeration failed") from exc

def _cached_anchor(cache: dict[str, dict[str, Any]], source: dict, name: str) -> None:
    entry = cache.get(source["file"])
    if entry is None or source["sha256"] != entry["sha256"]:
        raise SurfaceError(f"{name}: source digest mismatch")
    lines = entry["lines"]
    if source["line"] > len(lines) or source["contains"] not in lines[source["line"] - 1]:
        raise SurfaceError(f"{name}: source anchor mismatch")

def verify_source(source_root: Path, provenance_path: Path, manifest: dict[str, Any]) -> None:
    if not isinstance(source_root, Path) or not isinstance(provenance_path, Path): raise SurfaceError("source paths must be Paths")
    validate_manifest(manifest)
    held_fds = []
    try:
        try:
            root_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        except (OSError, UnicodeError, RuntimeError) as exc:
            raise SurfaceError("cannot open OS root") from exc
        held_fds.append(root_fd)
        source_fd = _open_at(root_fd, source_root, "source root", True)
        held_fds.append(source_fd)
        provenance_fd = _open_at(root_fd, provenance_path, "provenance")
        held_fds.append(provenance_fd)

        p = manifest["source"]["provenance"]
        if provenance_path.name != p["file"]: raise SurfaceError("provenance path mismatch")
        try:
            if os.fstat(provenance_fd).st_size > MAX_ARTIFACT_BYTES:
                raise SurfaceError("provenance exceeds size limit")
        except OSError as exc:
            raise SurfaceError("provenance: cannot stat") from exc
        provenance_data = _fd_bytes(provenance_fd, "provenance", max_bytes=MAX_ARTIFACT_BYTES)
        if hashlib.sha256(provenance_data).hexdigest() != p["sha256"]: raise SurfaceError("provenance manifest missing or tampered")
        try: recorded = json.loads(provenance_data.decode("utf-8"))
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
            expected_sizes = {"trailbase": (1512, 17610038), "litestream": (294, 3796066)}
            if (s["regular_files"], s["expanded_bytes"]) != expected_sizes[name]: raise SurfaceError("invalid provenance sizes")
        if seen != {"trailbase","litestream"}: raise SurfaceError("missing provenance source")
        if source_root.name != manifest["source"]["root"]: raise SurfaceError("source root mismatch")

        expected = {e["file"]: e for e in manifest["source_files"]}
        snapshot = _snapshot_source_files(source_fd, held_fds)
        if set(snapshot) != set(expected): raise SurfaceError("source inventory does not exactly match configured scopes")

        cache = {}
        for name in sorted(snapshot):
            fd, identity = snapshot[name]
            data = _fd_bytes(fd, name, identity, MAX_ARTIFACT_BYTES)
            digest = hashlib.sha256(data).hexdigest()
            if digest != expected[name]["sha256"]: raise SurfaceError(f"missing or tampered source: {name}")
            try: lines = data.decode("utf-8").splitlines()
            except UnicodeError as exc: raise SurfaceError(f"{name}: cannot decode") from exc
            cache[name] = {"data": data, "sha256": digest, "lines": lines}
            for anchor in expected[name]["anchors"]:
                if anchor["line"] > len(lines) or anchor["contains"] not in lines[anchor["line"] - 1]:
                    raise SurfaceError(f"bad source anchor: {name}")

        for route in manifest["routes"] + manifest["debug_only_routes"]:
            _cached_anchor(cache, route["source"], "route source")
        for route in manifest["listener_route_instances"]:
            _cached_anchor(cache, route["source"], "listener source")
        for capability in manifest["capabilities"]:
            _cached_anchor(cache, capability["source"], "capability source")
    except SurfaceError: raise
    except (OSError, UnicodeError, RuntimeError) as exc: raise SurfaceError("source verification failed") from exc
    finally:
        for fd in reversed(held_fds):
            try: os.close(fd)
            except OSError: pass

if __name__ == "__main__":
    import argparse
    ap=argparse.ArgumentParser(); ap.add_argument("manifest",type=Path); ap.add_argument("source_root",type=Path); ap.add_argument("provenance",type=Path); a=ap.parse_args()
    verify_source(a.source_root,a.provenance,load_manifest(a.manifest)); print("surface closure verified: 82 routes")

# Task 3: pure-data attestation/quarantine contracts.
ATTESTATION_SCHEMA = "d4-attestation-1"
PHASE_SOCKET_SCHEMA = "d4-phase-socket-1"
_QUAR_SCHEMA = "d4-quarantine-1"

def _canonical_digest(value, omitted):
    body = {k: v for k, v in value.items() if k != omitted}
    return hashlib.sha256(json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8", "strict")).hexdigest()

def _walk_attestation(v, path="attestation"):
    if isinstance(v, float) and not math.isfinite(v): raise SurfaceError(f"{path}: nonfinite")
    if isinstance(v, dict):
        if len(v) > 16384: raise SurfaceError(f"{path}: too many keys")
        for k, x in v.items():
            if type(k) is not str or not k: raise SurfaceError(f"{path}: invalid key")
            _walk_attestation(x, f"{path}.{k}")
    elif isinstance(v, list):
        if len(v) > 4096: raise SurfaceError(f"{path}: too many items")
        for i, x in enumerate(v): _walk_attestation(x, f"{path}[{i}]")
    elif isinstance(v, str) and len(v.encode()) > 4096: raise SurfaceError(f"{path}: string limit")

@dataclass(frozen=True, slots=True)
class AttestationTrust:
    manager_receipt_path_sha256: str
    manager_receipt_sha256: str
    manager_pid: int
    collector_pid: int
    collector_parent_pid: int
    collector_source_sha256: str
    fixture_pid: int
    fixture_start_mono_ns: int
    service_uid: int
    service_groups: tuple[int, ...]
    manifest_sha256: str
    source_sha256: str
    source_root_sha256: str
    binary_path_sha256: str
    binary_sha256: str
    build_id: str
    config_sha256: str
    config_generation: int
    migration_sha256: str
    plugin_sha256: str
    sandbox_profile_sha256: str
    sandbox_profile_generation: int
    sandbox_root_sha256: str
    collection_ready_mono_ns: int
    collection_launched_mono_ns: int
    collection_deadline_mono_ns: int
    expected_argv: tuple[str, ...]
    expected_env: tuple[tuple[str, str], ...]
    positive_request_sha256: tuple[tuple[str, str], ...]
    condition_resolutions: tuple[tuple[str, str], ...]
    protected_paths: tuple[str, ...]
    logs_path: str
    manager_receipt_nonce: str
    evidence_inventory: tuple[tuple[str, str, str, int, str], ...]
    attestation_sha256: str

def _ao(v, keys, p):
    if type(v) is not dict or set(v) != set(keys): raise SurfaceError(f"{p}: keys")
    return v

def _ai(v, p, positive=False):
    if type(v) is not int or (positive and v <= 0): raise SurfaceError(f"{p}: integer")
    return v

def _bounded(v, p, low=0, high=(1 << 63) - 1):
    _ai(v, p)
    if not low <= v <= high: raise SurfaceError(f"{p}: out of range")
    return v

def _as(v, p, digest=False):
    if type(v) is not str or not v or len(v.encode()) > 4096: raise SurfaceError(f"{p}: string")
    if digest and not HEX64.fullmatch(v): raise SurfaceError(f"{p}: hash")
    return v

def _al(v, p, n=4096):
    if type(v) is not list or len(v) > n: raise SurfaceError(f"{p}: array")
    return v

def _au(xs, key, p):
    vals=[x[key] for x in xs]
    if len(vals) != len(set(vals)): raise SurfaceError(f"{p}: duplicate identity")

def _files(xs, p):
    _al(xs,p)
    for x in xs:
        _ao(x,("path","sha256"),p); _as(x["path"],p); _as(x["sha256"],p,True)
        if not SAFE_PATH.fullmatch(x["path"]): raise SurfaceError(f"{p}: unsafe path")
    _au(xs,"path",p)

@dataclass(frozen=True, slots=True)
class PhaseSocketTrust:
    """Externally observed facts used by the pure phase/socket validator."""
    manager_pid: int
    trailbase_pid: int
    opener_pid: int
    collector_pid: int
    trailbase_start: int
    opener_start: int
    collector_start: int
    manager_start: int
    evidence_inventory: tuple[tuple[str, str], ...]
    pre_nonce: str
    post_nonce: str
    manager_parent_pid: int = 0
    manager_parent_start: int = 0
    trailbase_parent_start: int = 0
    opener_parent_start: int = 0
    collector_parent_start: int = 0
    pre_window_start: int = 1
    pre_window_end: int = (1 << 63) - 1
    peer_uid: int = 0
    peer_groups: tuple[int, ...] = ()


def _phase_socket_error(condition: bool, message: str) -> None:
    if not condition:
        raise SurfaceError(message)


def _phase_secret_scan(value, path="phase"):
    if isinstance(value, dict):
        for key, child in value.items():
            if key not in {"peer_credentials"} and any(word in key.lower() for word in ("secret", "token", "password", "cookie", "credential")):
                raise SurfaceError(f"{path}: secret metadata")
            _phase_secret_scan(child, f"{path}.{key}")
    elif isinstance(value, list):
        for i, child in enumerate(value): _phase_secret_scan(child, f"{path}[{i}]")
    elif isinstance(value, str) and any(ord(c) >= 128 for c in value):
        raise SurfaceError(f"{path}: non-ascii text")


def _validate_phase_socket_attestation(attestation: dict[str, Any], trust: PhaseSocketTrust) -> MappingProxyType:
    """Validate Task 3 receipts without touching the process, socket, or filesystem APIs."""
    if type(attestation) is not dict or type(trust) is not PhaseSocketTrust:
        raise SurfaceError("phase/socket input")
    _walk_attestation(attestation)
    _phase_secret_scan(attestation)
    required = {"schema", "pre_send", "sandbox_probe", "post_send", "evidence", "binding"}
    _phase_socket_error(set(attestation) == required and attestation["schema"] == PHASE_SOCKET_SCHEMA, "phase/socket schema")
    pre = _ao(attestation["pre_send"], ("nonce", "started", "exited", "processes", "listener", "listening_fd", "opener_endpoint", "accepted_endpoint", "linkage", "peer_credentials", "raw_framing", "held", "client_to_server_bytes", "server_to_client_bytes", "prefetched_bytes", "peeked_bytes", "drained_bytes"), "pre_send")
    probe = _ao(attestation["sandbox_probe"], ("nonce", "started", "exited", "evidence_id"), "sandbox_probe")
    post = _ao(attestation["post_send"], ("nonce", "started", "exited", "window_start", "window_end", "binary", "config", "argv", "parent_pid", "parent_start", "evidence_id"), "post_send")
    binding = _ao(attestation["binding"], ("nonce", "evidence_id"), "binding")
    _phase_socket_error(pre["nonce"] == trust.pre_nonce and post["nonce"] == trust.post_nonce, "phase nonce trust")
    _phase_socket_error(len({pre["nonce"], probe["nonce"], post["nonce"]}) == 3, "phase nonce reuse")
    _phase_socket_error(pre["nonce"] != post["nonce"] and pre["nonce"] != probe["nonce"] and post["nonce"] != probe["nonce"], "phase nonce overlap")
    for item, name in ((pre, "pre_send"), (probe, "sandbox_probe"), (post, "post_send")):
        for key in ("started", "exited"):
            _bounded(item[key], f"{name}.{key}", 1)
        _phase_socket_error(item["started"] <= item["exited"], f"{name} lifecycle")
    _phase_socket_error(probe["exited"] <= pre["started"], "sandbox ordering")
    _phase_socket_error(pre["exited"] <= post["started"], "post-send ordering")
    _phase_socket_error(pre["held"] is True and all(pre[k] == 0 for k in ("client_to_server_bytes", "server_to_client_bytes", "prefetched_bytes", "peeked_bytes", "drained_bytes")), "application bytes before validation")
    _phase_socket_error(pre["started"] >= trust.pre_window_start and pre["exited"] <= trust.pre_window_end and post["started"] >= post["window_start"] and post["exited"] <= post["window_end"], "held observation window")
    processes = _al(pre["processes"], "pre_send.processes", 4)
    _phase_socket_error(len(processes) == 4, "process cardinality")
    by_role = {}
    for p in processes:
        _ao(p, ("role", "pid", "parent_pid", "parent_start", "start", "exe_sha256", "argv", "evidence_id"), "process")
        _phase_socket_error(p["role"] in {"manager", "trailbase", "opener", "collector"} and p["role"] not in by_role, "process roles")
        _bounded(p["pid"], "process pid", 1); _bounded(p["parent_pid"], "process parent"); _bounded(p["parent_start"], "process parent start"); _bounded(p["start"], "process start", 1)
        _as(p["exe_sha256"], "process executable", True); _al(p["argv"], "process argv", 64); _as(p["evidence_id"], "process evidence")
        by_role[p["role"]] = p
    _phase_socket_error(set(by_role) == {"manager", "trailbase", "opener", "collector"}, "process roles")
    _phase_socket_error(by_role["manager"]["pid"] == trust.manager_pid and by_role["manager"]["start"] == trust.manager_start and by_role["manager"]["parent_pid"] == trust.manager_parent_pid and by_role["manager"]["parent_start"] == trust.manager_parent_start, "manager identity")
    for role in ("trailbase", "opener", "collector"):
        _phase_socket_error(by_role[role]["pid"] == getattr(trust, role + "_pid") and by_role[role]["start"] == getattr(trust, role + "_start"), f"{role} identity")
        _phase_socket_error(by_role[role]["parent_pid"] == trust.manager_pid and by_role[role]["parent_start"] == trust.manager_start, f"{role} ancestry")
    _phase_socket_error(by_role["collector"]["pid"] != by_role["trailbase"]["pid"] and by_role["collector"]["pid"] != by_role["opener"]["pid"], "collector substitution")
    _phase_socket_error(all(p["evidence_id"] for p in by_role.values()), "process evidence")
    for key, label in (("listener", "listener pathname"), ("listening_fd", "listening fd"), ("opener_endpoint", "opener endpoint"), ("accepted_endpoint", "accepted endpoint")):
        endpoint_keys = {"listener": ("path", "owner_uid", "mode", "nlink", "device", "inode", "api", "observed_mono_ns", "evidence_id"), "listening_fd": ("fd", "pid", "device", "inode", "api", "observed_mono_ns", "evidence_id"), "opener_endpoint": ("direction", "pid", "start", "device", "inode", "api", "observed_mono_ns", "evidence_id"), "accepted_endpoint": ("direction", "pid", "start", "device", "inode", "api", "observed_mono_ns", "evidence_id")}[key]
        obj = _ao(pre[key], endpoint_keys, label)
        _bounded(obj["device"], label + " device", 1); _bounded(obj["inode"], label + " inode", 1); _as(obj["api"], label + " api"); _bounded(obj["observed_mono_ns"], label + " time", 1); _as(obj["evidence_id"], label + " evidence")
        if key == "listener":
            _absolute_path(obj["path"], label + " path"); _bounded(obj["owner_uid"], label + " owner", 0); _bounded(obj["mode"], label + " mode", 0); _bounded(obj["nlink"], label + " nlink", 1)
        if key == "listening_fd": _bounded(obj["fd"], label + " fd", 0); _bounded(obj["pid"], label + " pid", 1)
        if key in {"opener_endpoint", "accepted_endpoint"}:
            _phase_socket_error(obj["direction"] in {"client_to_server", "server_to_client"}, label + " direction"); _bounded(obj["pid"], label + " pid", 1); _bounded(obj["start"], label + " start", 1)
    _phase_socket_error(pre["listener"]["api"] != "synthetic" and pre["listening_fd"]["api"] != "synthetic" and pre["accepted_endpoint"]["api"] != "synthetic", "kernel linkage")
    _phase_socket_error(pre["linkage"]["listener_id"] == pre["linkage"]["accepted_id"] and pre["linkage"]["kernel_api"] and _bounded(pre["linkage"]["observed_mono_ns"], "linkage time", 1) >= pre["started"], "listener linkage")
    _phase_socket_error(pre["opener_endpoint"]["direction"] == "client_to_server" and pre["accepted_endpoint"]["direction"] == "server_to_client", "endpoint direction")
    peer = _ao(pre["peer_credentials"], ("uid", "gids", "api", "observed_mono_ns", "evidence_id"), "peer credentials")
    _bounded(peer["uid"], "peer uid", 0); _al(peer["gids"], "peer groups", 64)
    for gid in peer["gids"]: _bounded(gid, "peer gid", 0, (1 << 32) - 1)
    _phase_socket_error(peer["uid"] == trust.peer_uid and tuple(peer["gids"]) == trust.peer_groups and peer["api"] == "LOCAL_PEERCRED" and pre["started"] <= peer["observed_mono_ns"] <= pre["exited"], "peer credentials")
    framing = _ao(pre["raw_framing"], ("method", "target", "headers", "http_version", "host", "content_length", "transfer_encoding", "body_start", "body_end", "body_total", "body_sha256", "request_sha256", "connection_id", "connection_nonce", "phase_nonce", "evidence_id"), "raw framing")
    headers = _al(framing["headers"], "raw headers", 64)
    names = []
    for header in headers:
        _ao(header, ("name", "value"), "raw header"); _as(header["name"], "header name"); _as(header["value"], "header value")
        _phase_socket_error(all(ord(c) < 128 for c in header["name"] + header["value"]), "header ascii"); names.append(header["name"].lower())
    _phase_socket_error(len(names) == len(set(names)) and "transfer-encoding" not in names and "content-length" in names, "raw headers")
    _phase_socket_error(framing["phase_nonce"] == pre["nonce"] and framing["connection_nonce"] != pre["nonce"] and framing["http_version"] == "HTTP/1.1" and framing["transfer_encoding"] is None and type(framing["content_length"]) is int and framing["content_length"] == framing["body_total"] and framing["body_end"] - framing["body_start"] == framing["body_total"] and HEX64.fullmatch(framing["body_sha256"]) and HEX64.fullmatch(framing["request_sha256"]), "raw framing")
    _as(framing["connection_id"], "connection id"); _as(framing["connection_nonce"], "connection nonce")
    _phase_socket_error(binding["nonce"] == pre["nonce"], "binding phase")
    _phase_socket_error(post["parent_pid"] == trust.manager_pid and post["parent_start"] == trust.manager_start and post["started"] < post["exited"] and post["started"] > pre["exited"], "litestream parent")
    _phase_socket_error(post["started"] > pre["exited"], "litestream pre-send presence")
    _as(post["binary"], "litestream binary", True); _as(post["config"], "litestream config", True); _al(post["argv"], "litestream argv", 64)
    evidence_items = _al(attestation["evidence"], "evidence", 4096)
    for x in evidence_items:
        _ao(x, ("id", "path", "sha256", "size", "kind", "collector_source_sha256", "created_mono_ns", "phase"), "evidence")
        _as(x["id"], "evidence id"); _safe_relative(x["path"], "evidence path"); _as(x["sha256"], "evidence hash", True); _bounded(x["size"], "evidence size"); _as(x["kind"], "evidence kind"); _as(x["collector_source_sha256"], "collector source", True); _bounded(x["created_mono_ns"], "evidence time", 1); _as(x["phase"], "evidence phase")
    _phase_socket_error(len({x["id"] for x in evidence_items}) == len(evidence_items) and len({x["path"] for x in evidence_items}) == len(evidence_items), "evidence uniqueness")
    inventory = tuple(sorted((str(x["id"]), str(x["sha256"])) for x in evidence_items if type(x) is dict and "id" in x and "sha256" in x))
    _phase_socket_error(inventory == tuple(sorted(trust.evidence_inventory)), "evidence inventory")
    evidence_ids = {x["id"] for x in evidence_items}
    refs = [p["evidence_id"] for p in processes] + [pre[k]["evidence_id"] for k in ("listener", "listening_fd", "opener_endpoint", "accepted_endpoint")]
    refs += [framing["evidence_id"], probe["evidence_id"], post["evidence_id"], binding["evidence_id"]]
    _phase_socket_error(all(type(x) is str and x in evidence_ids for x in refs), "evidence reference")
    pre_refs = [p["evidence_id"] for p in processes] + [pre[k]["evidence_id"] for k in ("listener", "listening_fd", "opener_endpoint", "accepted_endpoint")] + [framing["evidence_id"], binding["evidence_id"]]
    _phase_socket_error(all(next(x for x in evidence_items if x["id"] == ref)["phase"] == "pre_send" for ref in pre_refs), "pre evidence phase")
    _phase_socket_error(next(x for x in evidence_items if x["id"] == probe["evidence_id"])["phase"] == "sandbox_probe", "sandbox evidence phase")
    _phase_socket_error(next(x for x in evidence_items if x["id"] == post["evidence_id"])["phase"] == "post_send", "post evidence phase")
    _phase_socket_error(sum(x["size"] for x in evidence_items) <= 268435456, "evidence total")
    _phase_socket_error(all(x["phase"] in {"pre_send", "sandbox_probe", "post_send"} for x in evidence_items), "evidence phase")
    canonical = _canonical_digest({"nonce": pre["nonce"], "connection_id": framing["connection_id"], "request_sha256": framing["request_sha256"]}, "_unused")
    return MappingProxyType({"status": "feasible", "phase_nonce": pre["nonce"], "binding": (framing["connection_id"], framing["request_sha256"]), "digest": canonical})


def validate_phase_socket_attestation(attestation: dict[str, Any], trust: PhaseSocketTrust) -> MappingProxyType:
    try:
        return _validate_phase_socket_attestation(attestation, trust)
    except SurfaceError:
        raise
    except Exception as exc:
        raise SurfaceError("malformed phase/socket attestation") from exc


def validate_attestation(attestation, manifest, trust):
    try:
        if type(attestation) is dict and attestation.get("schema") == PHASE_SOCKET_SCHEMA:
            return validate_phase_socket_attestation(attestation, trust)
        if type(trust) is not AttestationTrust or type(manifest) is not dict or type(attestation) is not dict: raise SurfaceError("attestation inputs")
        for name in ("manager_receipt_path_sha256","manager_receipt_sha256","collector_source_sha256","manifest_sha256","source_sha256","source_root_sha256","binary_path_sha256","binary_sha256","config_sha256","migration_sha256","plugin_sha256","sandbox_profile_sha256","sandbox_root_sha256"):
            _as(getattr(trust,name), "trust."+name, True)
        for name in ("manager_pid","collector_pid","collector_parent_pid","fixture_pid"):
            _bounded(getattr(trust,name), "trust."+name, 1)
        for name in ("fixture_start_mono_ns","collection_ready_mono_ns","collection_launched_mono_ns","collection_deadline_mono_ns"):
            _bounded(getattr(trust,name), "trust."+name)
        _bounded(trust.service_uid, "trust.service_uid", 0, (1 << 32) - 1)
        _bounded(trust.config_generation, "trust.config_generation", 0, (1 << 31) - 1)
        _bounded(trust.sandbox_profile_generation, "trust.sandbox_profile_generation", 0, (1 << 31) - 1)
        _as(trust.manager_receipt_nonce, "trust nonce")
        _as(trust.attestation_sha256, "trust.attestation_sha256", True)
        _as(trust.build_id, "trust.build_id")
        _as(trust.logs_path, "trust.logs_path")
        if not trust.logs_path.startswith("/"): raise SurfaceError("trust logs path")
        if (type(trust.service_groups) is not tuple or not trust.service_groups
                or any(type(x) is not int or not 0 <= x <= (1 << 32) - 1 for x in trust.service_groups)
                or type(trust.expected_argv) is not tuple or not trust.expected_argv
                or any(type(x) is not str or not x for x in trust.expected_argv)
                or type(trust.expected_env) is not tuple
                or any(type(x) is not tuple or len(x) != 2 or any(type(y) is not str for y in x) for x in trust.expected_env)
                or type(trust.positive_request_sha256) is not tuple
                or {x[0] for x in trust.positive_request_sha256 if type(x) is tuple and len(x) == 2} != {"create_main","create_aux","logout_session"}
                or len(trust.positive_request_sha256) != 3
                or any(type(x) is not tuple or len(x) != 2 or type(x[1]) is not str or not HEX64.fullmatch(x[1]) for x in trust.positive_request_sha256)
                or type(trust.condition_resolutions) is not tuple
                or any(type(x) is not tuple or len(x) != 2 or x[1] not in {"enabled","disabled","absent"} for x in trust.condition_resolutions)
                or len(dict(trust.condition_resolutions)) != len(trust.condition_resolutions)
                or set(dict(trust.condition_resolutions)) != ({r["condition"] for r in manifest["routes"] if r["condition"] != "always"} | {c["name"] for c in manifest["capabilities"] if c["class"] == "conditional"})
                or type(trust.protected_paths) is not tuple or not trust.protected_paths
                or any(type(x) is not str or not x.startswith("/") for x in trust.protected_paths)
                or type(trust.evidence_inventory) is not tuple
                or any(type(x) is not tuple or len(x) != 5 or type(x[0]) is not str or type(x[1]) is not str
                       or type(x[2]) is not str or not HEX64.fullmatch(x[2]) or type(x[3]) is not int
                       or x[3] < 0 or type(x[4]) is not str for x in trust.evidence_inventory)
                or len(trust.evidence_inventory) != len(set(trust.evidence_inventory))):
            raise SurfaceError("invalid trust collections")
        if not (0 <= trust.collection_ready_mono_ns <= trust.collection_launched_mono_ns < trust.collection_deadline_mono_ns): raise SurfaceError("trust window")
        validate_manifest(manifest)
        if _manifest_sha256(manifest) != trust.manifest_sha256: raise SurfaceError("manifest trust")
        raw=json.dumps(attestation, ensure_ascii=False, sort_keys=True, separators=(",",":"), allow_nan=False).encode("utf-8", "strict")
        if len(raw)>8*1024*1024: raise SurfaceError("attestation too large")
        _walk_attestation(attestation)
        top={"schema","collector","manager_receipt","source","binary","config","migration","plugin","sandbox","launch","window","descriptors","listeners","connections","listener_bindings","registrations","writable_probes","evidence","uncertainty","telemetry","attestation_sha256"}
        if set(attestation)!=top or attestation["schema"]!=ATTESTATION_SCHEMA: raise SurfaceError("schema")
        digest=attestation["attestation_sha256"]; _as(digest,"attestation_sha256",True)
        if _canonical_digest(attestation,"attestation_sha256") != digest or digest != trust.attestation_sha256: raise SurfaceError("attestation digest")
        c=_ao(attestation["collector"],("id","source_sha256","pid","parent_pid","started_wall","started_mono_ns","finished_wall","finished_mono_ns"),"collector")
        r=_ao(attestation["manager_receipt"],("path_sha256","receipt_sha256","nonce","manager_pid","collector_pid","collector_parent_pid","launched_mono_ns","exited_mono_ns"),"receipt")
        _as(c["id"], "collector.id"); _as(c["started_wall"], "collector.started_wall"); _as(c["finished_wall"], "collector.finished_wall")
        for k in ("source_sha256",): _as(c[k],k,True)
        for k in ("path_sha256","receipt_sha256"): _as(r[k],k,True)
        _as(r["nonce"], "receipt.nonce")
        for k in ("pid","parent_pid","started_mono_ns","finished_mono_ns"): _bounded(c[k],k,1)
        for k in ("manager_pid","collector_pid","collector_parent_pid","launched_mono_ns","exited_mono_ns"): _bounded(r[k],k,1)
        if (r["receipt_sha256"],r["path_sha256"],r["nonce"],r["manager_pid"],r["collector_pid"],r["collector_parent_pid"]) != (trust.manager_receipt_sha256,trust.manager_receipt_path_sha256,trust.manager_receipt_nonce,trust.manager_pid,trust.collector_pid,trust.collector_parent_pid): raise SurfaceError("receipt trust")
        if not (trust.collection_launched_mono_ns == r["launched_mono_ns"] <= c["started_mono_ns"] <= c["finished_mono_ns"] <= r["exited_mono_ns"] <= trust.collection_deadline_mono_ns): raise SurfaceError("receipt time")
        if (c["pid"],c["parent_pid"],c["source_sha256"]) != (trust.collector_pid,trust.collector_parent_pid,trust.collector_source_sha256): raise SurfaceError("collector trust")
        s=_ao(attestation["source"],("repo","tag","commit","sha256","root_sha256"),"source")
        if (s["repo"],s["tag"],s["commit"]) != TRAILBASE[1:]: raise SurfaceError("source pin")
        for k in ("sha256","root_sha256"): _as(s[k],k,True)
        if (s["sha256"],s["root_sha256"]) != (trust.source_sha256,trust.source_root_sha256): raise SurfaceError("source trust")
        b=_ao(attestation["binary"],("path_sha256","sha256","build_id"),"binary")
        for k in ("path_sha256","sha256"): _as(b[k],k,True)
        if (b["path_sha256"],b["sha256"],b["build_id"]) != (trust.binary_path_sha256,trust.binary_sha256,trust.build_id): raise SurfaceError("binary trust")
        cfg=_ao(attestation["config"],("sha256","generation","files"),"config"); mig=_ao(attestation["migration"],("sha256","files"),"migration"); plug=_ao(attestation["plugin"],("sha256","files","registrations"),"plugin")
        for x in (cfg,mig,plug): _as(x["sha256"],"artifact",True); _ai(x["generation"],"generation") if "generation" in x else None; _files(x["files"],"files")
        if type(plug["registrations"]) is not list or plug["registrations"]: raise SurfaceError("plugin registrations")
        if (cfg["sha256"],cfg["generation"],mig["sha256"],plug["sha256"]) != (trust.config_sha256,trust.config_generation,trust.migration_sha256,trust.plugin_sha256): raise SurfaceError("artifact trust")
        sb=_ao(attestation["sandbox"],("profile_sha256","profile_generation","identity_uid","identity_groups","root_sha256"),"sandbox")
        for k in ("profile_sha256","root_sha256"): _as(sb[k],k,True)
        _ai(sb["profile_generation"],"sandbox generation"); _ai(sb["identity_uid"],"sandbox uid",True); _al(sb["identity_groups"],"sandbox groups",64)
        if (sb["profile_sha256"],sb["profile_generation"],sb["root_sha256"],sb["identity_uid"],tuple(sb["identity_groups"])) != (trust.sandbox_profile_sha256,trust.sandbox_profile_generation,trust.sandbox_root_sha256,trust.service_uid,trust.service_groups): raise SurfaceError("sandbox trust")
        launch=_ao(attestation["launch"],("argv","env","process_tree","env_i"),"launch"); _al(launch["argv"],"argv",64); _al(launch["env"],"env",128)
        if launch["env_i"] is not True or tuple(launch["argv"]) != trust.expected_argv or tuple((x["name"],x["value"]) for x in launch["env"]) != trust.expected_env: raise SurfaceError("launch")
        for x in launch["argv"]: _as(x,"argv")
        for x in launch["env"]:
            _ao(x,("name","value"),"env"); _as(x["name"],"env name"); _as(x["value"],"env value")
            if any(word in x["name"].lower() for word in ("token","secret","password","credential","cookie")): raise SurfaceError("credential environment")
        _au(launch["env"],"name","env")
        tree=_al(launch["process_tree"],"tree",256); seen={}
        for x in tree:
            _ao(x,("pid","parent_pid","start_mono_ns","uid","gids","exe_sha256","argv","role"),"process"); _ai(x["pid"],"pid",True); _ai(x["parent_pid"],"parent"); _ai(x["start_mono_ns"],"process start",True); _ai(x["uid"],"uid"); _al(x["gids"],"gids",64); _as(x["exe_sha256"],"exe",True); _al(x["argv"],"process argv",64); _as(x["role"],"role"); seen[x["pid"]]=x
        if len(seen)!=len(tree) or not {"manager","trailbase","collector"} <= {x["role"] for x in tree}: raise SurfaceError("process tree")
        for x in tree:
            chain=set(); q=x["pid"]
            while q:
                if q in chain: raise SurfaceError("process cycle")
                chain.add(q); q=seen.get(q,{}).get("parent_pid",0)
                if q and q not in seen: raise SurfaceError("orphan process")
        w=_ao(attestation["window"],("ready_mono_ns","start_mono_ns","end_mono_ns","positive_controls"),"window")
        for k in ("ready_mono_ns","start_mono_ns","end_mono_ns"): _ai(w[k],k)
        if not (w["ready_mono_ns"] == trust.collection_ready_mono_ns <= w["start_mono_ns"] and trust.collection_launched_mono_ns <= w["start_mono_ns"] < w["end_mono_ns"] <= c["finished_mono_ns"] <= trust.collection_deadline_mono_ns and w["end_mono_ns"] - w["start_mono_ns"] <= 300_000_000_000): raise SurfaceError("window")
        _al(w["positive_controls"],"controls",64)
        u=_ao(attestation["uncertainty"],("unknown","missing","extra","stale","self_reported_only"),"uncertainty")
        if any(type(u[k]) is not list or u[k] for k in u): raise SurfaceError("uncertainty")
        _validate_attestation_nested(attestation,trust,seen,manifest)
        return MappingProxyType({"status":"feasible","listeners":tuple((x["id"],x["path"],x["inode"]) for x in attestation["listeners"])})
    except SurfaceError: raise
    except Exception as exc: raise SurfaceError("malformed attestation") from exc

def _absolute_path(value, name):
    _as(value, name)
    path = Path(value)
    if (not path.is_absolute() or str(path) != value or value.startswith("//")
            or os.path.normpath(value) != value or any(part in {".", ".."} for part in path.parts)):
        raise SurfaceError(f"{name}: canonical absolute path required")


def _validate_attestation_nested(a, trust, tree, manifest):
    specs = {
        "descriptors": ("pid fd cloexec owner_uid process_role type path inode device mode nlink source".split(), 256),
        "listeners": ("id pid role protocol sock_type path parent_ancestry uid mode device inode nlink source".split(), 2),
        "connections": ("id listener_id client_pid server_pid client_uid client_gids server_uid server_gids client_device client_inode server_device server_inode accepted_mono_ns peer_source bytes_before_validation evidence_id".split(), 64),
        "listener_bindings": ("listener_id inode device pid exe_sha256 argv observed_mono_ns source evidence_id".split(), 2),
        "writable_probes": ("path uid operation result errno evidence_id".split(), 256),
        "evidence": ("id path sha256 size kind collector_source_sha256 created_mono_ns".split(), 4096),
    }
    identities = {"descriptors": lambda x: (x["pid"], x["fd"]), "listeners": lambda x: x["id"],
                  "connections": lambda x: x["id"], "listener_bindings": lambda x: x["listener_id"],
                  "writable_probes": lambda x: x["path"], "evidence": lambda x: x["id"]}
    for group, (keys, limit) in specs.items():
        items = _al(a[group], group, limit)
        seen = set()
        for item in items:
            _ao(item, keys, group)
            ident = identities[group](item)
            if ident in seen: raise SurfaceError(f"{group}: duplicate identity")
            seen.add(ident)

    by_role = {}
    for proc in tree.values():
        if proc["role"] not in {"manager", "trailbase", "collector"} or proc["role"] in by_role: raise SurfaceError("process roles")
        for gid in proc["gids"]: _bounded(gid, "process gid", 0, (1 << 32) - 1)
        for arg in proc["argv"]: _as(arg, "process argv")
        _bounded(proc["pid"], "process pid", 1); _bounded(proc["parent_pid"], "process parent")
        _bounded(proc["uid"], "process uid", 0, (1 << 32) - 1)
        _bounded(proc["start_mono_ns"], "process start", 1)
        by_role[proc["role"]] = proc
    if set(by_role) != {"manager", "trailbase", "collector"}: raise SurfaceError("process roles")
    manager, fixture, collector = by_role["manager"], by_role["trailbase"], by_role["collector"]
    if (manager["pid"] != trust.manager_pid or manager["parent_pid"] != 0
            or fixture["pid"] != trust.fixture_pid or fixture["parent_pid"] != trust.manager_pid
            or fixture["start_mono_ns"] != trust.fixture_start_mono_ns
            or fixture["uid"] != trust.service_uid or tuple(fixture["gids"]) != trust.service_groups
            or fixture["exe_sha256"] != trust.binary_sha256 or tuple(fixture["argv"]) != trust.expected_argv
            or collector["pid"] != trust.collector_pid or collector["parent_pid"] != trust.collector_parent_pid
            or trust.collector_parent_pid != trust.manager_pid or collector["exe_sha256"] != trust.collector_source_sha256
            or collector["pid"] == fixture["pid"]): raise SurfaceError("trusted process tree mismatch")

    for descriptor in a["descriptors"]:
        _bounded(descriptor["pid"], "descriptor pid", 1)
        _bounded(descriptor["fd"], "descriptor fd", 0, 1_048_576)
        _bounded(descriptor["owner_uid"], "descriptor uid", 0, (1 << 32) - 1)
        _bounded(descriptor["inode"], "descriptor inode")
        _bounded(descriptor["device"], "descriptor device")
        _bounded(descriptor["mode"], "descriptor mode", 0, 0o7777)
        _bounded(descriptor["nlink"], "descriptor nlink", 1, (1 << 31) - 1)
        if type(descriptor["cloexec"]) is not bool or descriptor["source"] != "observed" or descriptor["type"] not in {"stdin","stdout","stderr","uds","file","pipe","other"}: raise SurfaceError("descriptor observation")
        proc = tree.get(descriptor["pid"])
        if proc is None or descriptor["process_role"] != proc["role"] or descriptor["owner_uid"] != proc["uid"]: raise SurfaceError("descriptor process")
        if descriptor["fd"] <= 2:
            if descriptor["type"] != ("stdin", "stdout", "stderr")[descriptor["fd"]]: raise SurfaceError("stdio descriptor")
        elif descriptor["cloexec"] is not True: raise SurfaceError("descriptor not cloexec")
        if descriptor["path"] is not None:
            _absolute_path(descriptor["path"], "descriptor.path")
            if proc["role"] != "trailbase" and descriptor["path"] in trust.protected_paths: raise SurfaceError("inherited protected descriptor")
        elif descriptor["type"] not in {"stdin","stdout","stderr","pipe","other"}: raise SurfaceError("descriptor path missing")
        if descriptor["fd"] > 2 and proc["role"] == "collector": raise SurfaceError("collector descriptor not allowlisted")
        if descriptor["fd"] > 2 and proc["role"] == "manager" and descriptor["type"] != "uds": raise SurfaceError("manager descriptor not allowlisted")
    expected_stdio = {(pid, fd) for pid in tree for fd in (0, 1, 2)}
    if not expected_stdio <= {(x["pid"], x["fd"]) for x in a["descriptors"]}: raise SurfaceError("stdio inventory incomplete")

    listeners = {x["id"]: x for x in a["listeners"]}
    if len(listeners) != 2 or {x["role"] for x in listeners.values()} != {"main", "admin"}: raise SurfaceError("listener roles")
    for listener in listeners.values():
        _as(listener["id"], "listener.id"); _absolute_path(listener["path"], "listener.path")
        _bounded(listener["pid"], "listener pid", 1); _bounded(listener["uid"], "listener uid", 0, (1 << 32) - 1)
        _bounded(listener["mode"], "listener mode", 1, 0o7777); _bounded(listener["device"], "listener device", 1)
        _bounded(listener["inode"], "listener inode", 1); _bounded(listener["nlink"], "listener nlink", 1, (1 << 31) - 1)
        if (listener["pid"] != trust.fixture_pid or listener["uid"] != trust.service_uid
                or listener["protocol"] != "AF_UNIX" or listener["sock_type"] != "SOCK_STREAM"
                or listener["source"] != "observed" or listener["mode"] != 0o600 or listener["nlink"] != 1): raise SurfaceError("listener identity")
        ancestry = _al(listener["parent_ancestry"], "listener ancestry", 32)
        if not ancestry: raise SurfaceError("listener ancestry")
        previous = None
        for parent in ancestry:
            _ao(parent, ("path","uid","mode","symlink"), "listener parent")
            _absolute_path(parent["path"], "listener parent.path")
            if parent["uid"] != trust.service_uid or parent["mode"] != 0o700 or parent["symlink"] is not False: raise SurfaceError("listener ancestry")
            if previous is not None and Path(parent["path"]).parent != Path(previous): raise SurfaceError("listener ancestry order")
            previous = parent["path"]
        if Path(listener["path"]).parent != Path(ancestry[-1]["path"]): raise SurfaceError("listener parent mismatch")
    if len({x["path"] for x in listeners.values()}) != 2 or len({(x["device"],x["inode"]) for x in listeners.values()}) != 2: raise SurfaceError("listener replacement")
    allowed_fixture_paths = set(trust.protected_paths) | {trust.logs_path} | {x["path"] for x in listeners.values()}
    if any(x["fd"] > 2 and x["process_role"] == "trailbase" and (x["path"] not in allowed_fixture_paths or x["type"] not in {"file","uds","pipe"}) for x in a["descriptors"]): raise SurfaceError("fixture descriptor not allowlisted")
    for listener in listeners.values():
        matches = [d for d in a["descriptors"] if d["pid"] == trust.fixture_pid and d["type"] == "uds"
                   and d["path"] == listener["path"] and d["inode"] == listener["inode"]
                   and d["device"] == listener["device"]]
        if len(matches) != 1: raise SurfaceError("listener descriptor binding")

    evidence = {}
    total = 0
    for item in a["evidence"]:
        _as(item["id"], "evidence.id"); _safe_relative(item["path"], "evidence.path"); _as(item["sha256"], "evidence.sha256", True)
        _bounded(item["size"], "evidence.size", 0, 268435456); _bounded(item["created_mono_ns"], "evidence.time")
        if item["kind"] not in {"absence","descriptor","socket","process","probe","receipt","registration","other"}: raise SurfaceError("evidence kind")
        if item["collector_source_sha256"] != trust.collector_source_sha256 or not (trust.collection_launched_mono_ns <= item["created_mono_ns"] <= trust.collection_deadline_mono_ns) or item["size"] > 268435456: raise SurfaceError("evidence trust")
        total += item["size"]
        if total > 268435456: raise SurfaceError("evidence total")
        evidence[item["id"]] = item
    if len(evidence) != len(a["evidence"]) or len({x["path"] for x in a["evidence"]}) != len(a["evidence"]): raise SurfaceError("duplicate evidence")
    observed_inventory = tuple(sorted((x["id"], x["path"], x["sha256"], x["size"], x["kind"]) for x in a["evidence"]))
    if observed_inventory != tuple(sorted(trust.evidence_inventory)): raise SurfaceError("evidence inventory trust")
    referenced = set()
    def evidence_ref(value, kinds=None):
        if type(value) is not str or value not in evidence: raise SurfaceError("missing evidence")
        if kinds is not None and evidence[value]["kind"] not in kinds: raise SurfaceError("wrong evidence kind")
        referenced.add(value)

    bindings = {x["listener_id"]: x for x in a["listener_bindings"]}
    if set(bindings) != set(listeners): raise SurfaceError("listener binding set")
    for listener_id, binding in bindings.items():
        listener = listeners[listener_id]
        for key in ("inode","device","pid","observed_mono_ns"): _bounded(binding[key], "binding integer", 1)
        _as(binding["exe_sha256"], "binding executable", True); _al(binding["argv"], "binding argv", 64)
        if (binding["source"] != "observed" or binding["inode"] != listener["inode"] or binding["device"] != listener["device"]
                or binding["pid"] != trust.fixture_pid or binding["exe_sha256"] != trust.binary_sha256
                or tuple(binding["argv"]) != trust.expected_argv or not (a["window"]["start_mono_ns"] <= binding["observed_mono_ns"] <= a["window"]["end_mono_ns"])): raise SurfaceError("listener binding")
        evidence_ref(binding["evidence_id"], {"socket"})

    connections = {x["id"]: x for x in a["connections"]}
    for connection in connections.values():
        _as(connection["id"], "connection.id"); _al(connection["client_gids"], "client gids", 64); _al(connection["server_gids"], "server gids", 64)
        for gid in connection["client_gids"] + connection["server_gids"]: _bounded(gid, "connection gid", 0, (1 << 32) - 1)
        for key in ("client_pid","server_pid","client_device","client_inode","server_device","server_inode","accepted_mono_ns"): _bounded(connection[key], "connection integer", 1)
        for key in ("client_uid","server_uid"): _bounded(connection[key], "connection uid", 0, (1 << 32) - 1)
        _bounded(connection["bytes_before_validation"], "connection bytes", 0, 0)
        listener = listeners.get(connection["listener_id"])
        if (listener is None or connection["client_pid"] != trust.manager_pid
                or tree[connection["client_pid"]]["role"] != "manager"
                or connection["server_pid"] != trust.fixture_pid or connection["server_uid"] != trust.service_uid
                or tuple(connection["server_gids"]) != trust.service_groups or connection["server_device"] != listener["device"] or connection["server_inode"] != listener["inode"]
                or connection["client_pid"] not in tree or connection["client_uid"] != tree[connection["client_pid"]]["uid"]
                or tuple(connection["client_gids"]) != tuple(tree[connection["client_pid"]]["gids"])
                or connection["peer_source"] != "LOCAL_PEERCRED" or connection["bytes_before_validation"] != 0
                or not (a["window"]["start_mono_ns"] <= connection["accepted_mono_ns"] <= a["window"]["end_mono_ns"])): raise SurfaceError("connection binding")
        peer_descriptors = [d for d in a["descriptors"] if d["pid"] == connection["client_pid"]
                            and d["inode"] == connection["client_inode"] and d["device"] == connection["client_device"]
                            and d["type"] == "uds" and d["path"] == listener["path"]]
        if len(peer_descriptors) != 1: raise SurfaceError("connection client descriptor")
        evidence_ref(connection["evidence_id"], {"socket"})

    manager_sockets = {(d["device"], d["inode"], d["path"]) for d in a["descriptors"] if d["pid"] == trust.manager_pid and d["fd"] > 2}
    connection_sockets = {(c["client_device"], c["client_inode"], listeners[c["listener_id"]]["path"]) for c in connections.values()}
    if manager_sockets != connection_sockets: raise SurfaceError("manager descriptor allowlist")

    controls = _al(a["window"]["positive_controls"], "controls", 3)
    if len(controls) != 3: raise SurfaceError("positive controls")
    expected_requests = dict(trust.positive_request_sha256)
    expected_kinds = set(expected_requests)
    for control in controls:
        _ao(control, ("kind","request_sha256","connection_id","start_mono_ns","end_mono_ns","evidence_id"), "control")
        _as(control["kind"], "control.kind"); _as(control["request_sha256"], "control.request_sha256", True)
        _ai(control["start_mono_ns"], "control.start"); _ai(control["end_mono_ns"], "control.end")
        if (control["request_sha256"] != expected_requests.get(control["kind"])
                or control["connection_id"] not in connections
                or listeners[connections[control["connection_id"]]["listener_id"]]["role"] != "main"
                or not (a["window"]["start_mono_ns"] <= control["start_mono_ns"] < control["end_mono_ns"] <= a["window"]["end_mono_ns"])): raise SurfaceError("control binding")
        evidence_ref(control["evidence_id"], {"socket"})
    if ({x["kind"] for x in controls} != expected_kinds
            or len({x["connection_id"] for x in controls}) != 3
            or set(connections) != {x["connection_id"] for x in controls}): raise SurfaceError("control kinds")

    for probe in a["writable_probes"]:
        _absolute_path(probe["path"], "probe.path"); _bounded(probe["uid"], "probe.uid", 0, (1 << 32) - 1); _bounded(probe["errno"], "probe.errno", 1, (1 << 31) - 1)
        if probe["uid"] != trust.service_uid or probe["operation"] not in {"create","append","rename","unlink","chmod"} or probe["result"] != "denied": raise SurfaceError("probe")
        evidence_ref(probe["evidence_id"], {"probe"})
    if {x["path"] for x in a["writable_probes"]} != set(trust.protected_paths): raise SurfaceError("protected probe coverage")

    regs = _ao(a["registrations"], ("jobs","plugins","routes","conditions","dynamic_absence"), "registrations")
    definitions = (("jobs", ("id","enabled","mutates","source_sha256","condition_id","evidence_id"), 256, lambda x: x["id"]),
                   ("plugins", ("id","enabled","sha256","kind","condition_id","evidence_id"), 256, lambda x: x["id"]),
                   ("routes", ("method","path","handler","enabled","source_sha256","condition_id","evidence_id"), 512, lambda x: (x["method"],x["path"])),
                   ("conditions", ("id","expression","resolution","observed_by","evidence_id"), 512, lambda x: x["id"]),
                   ("dynamic_absence", ("point_id","kind","source_sha256","query","expected_absent","observed_absent","evidence_id"), 256, lambda x: x["point_id"]))
    for name, keys, limit, identity in definitions:
        seen = set()
        for item in _al(regs[name], name, limit):
            _ao(item, keys, name); ident = identity(item)
            if ident in seen: raise SurfaceError(f"{name}: duplicate")
            seen.add(ident)
    if regs["plugins"]: raise SurfaceError("plugins enabled or present")
    expected_jobs = {"job:" + name for name in REQUIRED_JOBS}
    if {x["id"] for x in regs["jobs"]} != expected_jobs: raise SurfaceError("job set")
    for job in regs["jobs"]:
        if type(job["enabled"]) is not bool or type(job["mutates"]) is not bool or job["enabled"] or not job["mutates"]: raise SurfaceError("job state")
        _as(job["source_sha256"], "job source", True); _as(job["condition_id"], "job condition")
        capability = next(c for c in manifest["capabilities"] if c["name"] == job["id"])
        if job["source_sha256"] != capability["source"]["sha256"] or job["condition_id"] != "always": raise SurfaceError("job source")
        evidence_ref(job["evidence_id"], {"registration"})
    expected_routes = {(x["method"],x["path"]): x for x in manifest["routes"]}
    if {(x["method"],x["path"]) for x in regs["routes"]} != set(expected_routes): raise SurfaceError("route set")
    resolutions = dict(trust.condition_resolutions)
    for route in regs["routes"]:
        source = expected_routes[(route["method"],route["path"])]
        if (route["handler"] != source["handler"] or route["source_sha256"] != source["source"]["sha256"]
                or route["condition_id"] != source["condition"] or type(route["enabled"]) is not bool
                or route["enabled"] != (source["condition"] == "always" or resolutions.get(source["condition"]) == "enabled")): raise SurfaceError("route registration")
        evidence_ref(route["evidence_id"], {"registration"})
    conditions = {x["id"]: x for x in regs["conditions"]}
    if set(conditions) != set(resolutions): raise SurfaceError("condition set")
    for condition_id, resolution in resolutions.items():
        item = conditions[condition_id]
        _as(item["expression"], "condition expression")
        if item["resolution"] != resolution or item["observed_by"] not in {"collector","evidence"}: raise SurfaceError("condition resolution")
        evidence_ref(item["evidence_id"], {"registration","absence"})
    dynamic = {x["point_id"]: x for x in regs["dynamic_absence"]}
    expected_dynamic = {x["name"]: x for x in manifest["capabilities"] if x["class"] == "dynamic_router"}
    if set(dynamic) != set(expected_dynamic): raise SurfaceError("dynamic point set")
    for point_id, item in dynamic.items():
        _as(item["kind"], "dynamic kind"); _as(item["query"], "dynamic query")
        if (item["source_sha256"] != expected_dynamic[point_id]["source"]["sha256"] or item["expected_absent"] is not True
                or item["observed_absent"] is not True or "runtime_unknown" in item["query"]): raise SurfaceError("dynamic absence")
        evidence_ref(item["evidence_id"], {"absence"})

    telemetry = _ao(a["telemetry"], ("logs_only","readers","writers","scan_evidence_id"), "telemetry")
    if telemetry["logs_only"] is not True: raise SurfaceError("telemetry")
    evidence_ref(telemetry["scan_evidence_id"], {"other"})
    for kind in ("readers","writers"):
        for item in _al(telemetry[kind], "telemetry." + kind, 256):
            _ao(item, ("pid","operation","path","evidence_id"), "telemetry entry")
            _ai(item["pid"], "telemetry pid", True); _as(item["operation"], "telemetry operation"); _absolute_path(item["path"], "telemetry path")
            if (item["pid"] != trust.fixture_pid or item["path"] != trust.logs_path
                    or item["operation"] != ("read" if kind == "readers" else "write")): raise SurfaceError("telemetry path")
            evidence_ref(item["evidence_id"], {"descriptor","registration","other"})
    allowed_orphans = {item["id"] for item in a["evidence"] if item["kind"] == "receipt"}
    if set(evidence) - referenced - allowed_orphans: raise SurfaceError("orphan evidence")


def validate_quarantine(root, manifest):
    """Return a bounded read snapshot; Task5 owns terminal capture/future immutability."""
    required = {"schema", "root", "owner_uid", "disposition", "files", "file_count", "byte_total", "hash_algorithm", "manifest_sha256", "access_log"}
    fds = []
    def meta(st):
        return (st.st_dev, st.st_ino, st.st_uid, stat.S_IMODE(st.st_mode), st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns, stat.S_IFMT(st.st_mode))
    def stable(fd, before, name, regular=True):
        after = os.fstat(fd)
        if (not stat.S_ISREG(after.st_mode) if regular else False) or after.st_mode & stat.S_IFMT(after.st_mode) != before[-1] or meta(after) != before:
            raise SurfaceError(f"{name}: changed during validation")
    try:
        if not isinstance(root, Path) or type(manifest) is not dict or set(manifest) != required: raise SurfaceError("invalid quarantine manifest")
        if manifest["schema"] != _QUAR_SCHEMA or type(manifest["root"]) is not str: raise SurfaceError("quarantine root")
        canonical = os.path.realpath(os.path.abspath(os.fspath(root)))
        if manifest["root"] != canonical or len(canonical.encode()) > 4096: raise SurfaceError("quarantine root")
        uid = manifest["owner_uid"]
        if type(uid) is not int or uid <= 0 or manifest["disposition"] != "pending" or manifest["hash_algorithm"] != "sha256": raise SurfaceError("quarantine metadata")
        if type(manifest["manifest_sha256"]) is not str or not HEX64.fullmatch(manifest["manifest_sha256"]) or _canonical_digest(manifest, "manifest_sha256") != manifest["manifest_sha256"]: raise SurfaceError("manifest digest")
        files = manifest["files"]
        if type(files) is not list or len(files) > 16384 or type(manifest["file_count"]) is not int or manifest["file_count"] != len(files): raise SurfaceError("file count")
        if type(manifest["byte_total"]) is not int or not 0 <= manifest["byte_total"] <= 268435456: raise SurfaceError("quarantine size")
        names, declared, inodes = set(), {}, set()
        for x in files:
            if type(x) is not dict or set(x) != {"path","sha256","size","mode","nlink","kind"}: raise SurfaceError("invalid payload entry")
            path=x["path"]
            if type(path) is not str or not SAFE_PATH.fullmatch(path) or path.startswith("./") or path.endswith("/") or path in names or x["kind"] != "regular" or x["mode"] != 0o600 or x["nlink"] != 1 or type(x["size"]) is not int or not 0 <= x["size"] <= 268435456 or not HEX64.fullmatch(x["sha256"]): raise SurfaceError("invalid payload entry")
            names.add(path); declared[path]=x
        if sum(x["size"] for x in files) != manifest["byte_total"]: raise SurfaceError("byte total")
        parent_path=os.path.dirname(canonical); parent_pre=os.lstat(parent_path); root_pre=os.lstat(canonical)
        if not stat.S_ISDIR(parent_pre.st_mode) or not stat.S_ISDIR(root_pre.st_mode) or parent_pre.st_uid != uid or root_pre.st_uid != uid or stat.S_IMODE(parent_pre.st_mode) != 0o700 or stat.S_IMODE(root_pre.st_mode) != 0o700: raise SurfaceError("quarantine ancestry")
        parent_fd=os.open(parent_path, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); fds.append(parent_fd)
        root_fd=os.open(os.path.basename(canonical), os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW, dir_fd=parent_fd); fds.append(root_fd)
        if meta(os.fstat(parent_fd)) != meta(parent_pre) or meta(os.fstat(root_fd)) != meta(root_pre): raise SurfaceError("quarantine identity")
        log=manifest["access_log"]
        if type(log) is not str or not os.path.isabs(log) or os.path.dirname(log) != canonical or os.path.basename(log) == "manifest.json": raise SurfaceError("access log")
        controls={"manifest.json", os.path.basename(log)}
        if names & controls: raise SurfaceError("control declared as payload")
        expected_dirs={tuple(path.split("/")[:i]) for path in names|controls for i in range(1,len(path.split("/")))}
        seen=set(); entries=[]; directories=[]
        for name in controls:
            fd=os.open(name, os.O_RDONLY|os.O_NOFOLLOW, dir_fd=root_fd); fds.append(fd); pre=meta(os.fstat(fd))
            if pre[-1] != stat.S_IFREG or pre[2] != uid or pre[3] != 0o600 or pre[4] != 1: raise SurfaceError("control metadata")
            data=_fd_bytes(fd, "quarantine control", max_bytes=8*1024*1024)
            stable(fd,pre,"quarantine control")
            if name == "manifest.json":
                try: actual=_strict_json(data)
                except SurfaceError as exc: raise SurfaceError("control manifest") from exc
                if actual != manifest: raise SurfaceError("control manifest")
            seen.add(name); entries.append((name,pre[0],pre[1],pre[5],"control"))
        def walk(dfd,prefix=()):
            with os.scandir(dfd) as scan:
                for ent in scan:
                    name=ent.name
                    if not name or "/" in name or "\\" in name or "\x00" in name: raise SurfaceError("invalid entry")
                    rel=prefix+(name,); fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|getattr(os,"O_NONBLOCK",0),dir_fd=dfd); fds.append(fd); pre=meta(os.fstat(fd)); key="/".join(rel)
                    if pre[-1] == stat.S_IFDIR:
                        if pre[2]!=uid or pre[3]!=0o700 or rel not in expected_dirs: raise SurfaceError("directory metadata")
                        directories.append((fd, pre, key))
                        walk(fd,rel)
                    elif pre[-1] == stat.S_IFREG:
                        if key in controls:
                            if key in seen: continue
                            raise SurfaceError("control entry missing")
                        if key not in declared or key in seen or (pre[0],pre[1]) in inodes: raise SurfaceError("duplicate or undeclared entry")
                        x=declared[key]
                        if pre[2]!=uid or pre[3]!=0o600 or pre[4]!=1 or pre[5]!=x["size"]: raise SurfaceError("payload metadata")
                        data=_fd_bytes(fd,"quarantine payload",max_bytes=268435456); digest=hashlib.sha256(data).hexdigest(); stable(fd,pre,"quarantine payload")
                        if digest != x["sha256"]: raise SurfaceError("payload tamper")
                        seen.add(key); inodes.add((pre[0],pre[1])); entries.append((key,pre[0],pre[1],pre[5],digest))
                    else: raise SurfaceError("special entry")
        walk(root_fd)
        if seen != names|controls: raise SurfaceError("missing entry")
        for directory_fd, before, key in directories:
            stable(directory_fd, before, "quarantine directory " + key, regular=False)
        if meta(os.fstat(parent_fd)) != meta(parent_pre) or meta(os.fstat(root_fd)) != meta(root_pre): raise SurfaceError("quarantine identity")
        return MappingProxyType({"feasible":True,"root":canonical,"root_device":root_pre.st_dev,"root_inode":root_pre.st_ino,"file_count":len(files),"byte_total":manifest["byte_total"],"entries":tuple(entries)})
    except SurfaceError: raise
    except (OSError, ValueError, TypeError, UnicodeError) as exc: raise SurfaceError("quarantine validation failed") from exc
    finally:
        for fd in reversed(fds):
            try: os.close(fd)
            except OSError: pass
