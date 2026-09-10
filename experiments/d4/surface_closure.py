"""Strict, offline validation of the pinned TrailBase mutation-surface census."""
from __future__ import annotations
import hashlib
import json
import re
import stat
from pathlib import Path
from typing import Any

COMMIT = "f24291b894bb6c6696608e5f4c2f68666fe97686"
TRAILBASE = ("trailbase", "trailbaseio/trailbase", "v0.33.11", COMMIT)
LITESTREAM = ("litestream", "benbjohnson/litestream", "v0.5.17", "ccd326c175b583b5e82893a6078f06dcef5fba3f")
ALLOWED = {("POST", "/api/records/v1/main_ops"): "main", ("POST", "/api/records/v1/aux_ops"): "aux", ("POST", "/api/auth/v1/logout"): "session"}
TOP_LEVEL = {"schema_version", "source", "source_scopes", "source_files", "capabilities", "graph_accounting", "unresolved_source_graph", "routes", "section_counts", "debug_only_routes", "exact_allow_rules", "listener_route_instances"}
SAFE_PATH = re.compile(r"^(?!/)(?!$)(?!.*\\)(?!.*(?:^|/)\.{1,2}(?:/|$))[^\x00]+$")
SOURCE_SCOPES = ["crates/core/src", "crates/wasm-runtime-axum/src", "crates/wasm-runtime-common/src", "crates/wasm-runtime-guest/src", "crates/wasm-runtime-host/src"]
PINNED_SEMANTIC_FINGERPRINT = "6258275d38d9128f157778c72eed989dda99dd8642249fdf4e16427e847b8755"
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
    _safe_single_name(source["root"], "source.root")
    p = _dict(source["provenance"], "provenance"); _keys(p, {"file","sha256"}, "provenance"); _str(p["file"], "provenance.file"); _safe_single_name(p["file"], "provenance.file"); _hex(p["sha256"], "provenance.sha256")

def _safe_relative(value: str, name: str) -> None:
    if not SAFE_PATH.fullmatch(value): raise SurfaceError(f"{name}: unsafe relative path")

def _safe_single_name(value: str, name: str) -> None:
    _safe_relative(value, name)
    if "/" in value: raise SurfaceError(f"{name}: expected a single relative name")

def _regular_file(path: Path, name: str) -> bool:
    try:
        return not path.is_symlink() and stat.S_ISREG(path.stat().st_mode)
    except (OSError, UnicodeError, RuntimeError) as exc:
        raise SurfaceError(f"{name}: cannot inspect path") from exc

def _lstat(path: Path, name: str):
    try:
        return path.lstat()
    except (OSError, UnicodeError, RuntimeError) as exc:
        raise SurfaceError(f"{name}: cannot inspect path") from exc

def _source_path(source_root: Path, relative: str, name: str) -> tuple[Path, int]:
    path = source_root
    parts = Path(relative).parts
    for index, part in enumerate(parts):
        path /= part
        mode = _lstat(path, name).st_mode
        if stat.S_ISLNK(mode):
            raise SurfaceError(f"{name}: symlink is not allowed")
        if index < len(parts) - 1 and not stat.S_ISDIR(mode):
            raise SurfaceError(f"{name}: source path component is not a directory")
    return path, mode

def _semantic_fingerprint(manifest: dict[str, Any]) -> str:
    def normalized(value, path=()):
        if type(value) is dict:
            return {
                key: normalized(item, path + (key,))
                for key, item in value.items()
                if key != "sha256" and not (path == ("source",) and key in {"root", "provenance"})
            }
        if type(value) is list:
            return [normalized(item, path) for item in value]
        return value
    return hashlib.sha256(json.dumps(normalized(manifest), sort_keys=True, separators=(",", ":")).encode()).hexdigest()

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
    if _semantic_fingerprint(m) != PINNED_SEMANTIC_FINGERPRINT: raise SurfaceError("semantic fingerprint mismatch")

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
    if not _regular_file(provenance_path, "provenance") or hashlib.sha256(_read_bytes(provenance_path, "provenance")).hexdigest() != p["sha256"]: raise SurfaceError("provenance manifest missing or tampered")
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
    root_mode = _lstat(source_root, "source root").st_mode
    if stat.S_ISLNK(root_mode) or not stat.S_ISDIR(root_mode): raise SurfaceError("source root is missing or not a directory")
    expected = {e["file"]: e for e in manifest["source_files"]}
    for name,e in expected.items():
        path, mode = _source_path(source_root, name, name)
        if not stat.S_ISREG(mode) or hashlib.sha256(_read_bytes(path, name)).hexdigest()!=e["sha256"]: raise SurfaceError(f"missing or tampered source: {name}")
        lines=_read_text(path, name).splitlines()
        for a in e["anchors"]:
            if a["line"] > len(lines) or a["contains"] not in lines[a["line"]-1]: raise SurfaceError(f"bad source anchor: {name}")
    for r in manifest["routes"] + manifest["debug_only_routes"]:
        _inventory_anchor({k:v for k,v in expected.items()}, r["source"], "route source")
    for r in manifest["listener_route_instances"]:
        _inventory_anchor({k:v for k,v in expected.items()}, r["source"], "listener source")
    for c in manifest["capabilities"]:
        _inventory_anchor({k:v for k,v in expected.items()}, c["source"], "capability source")
    actual = set()
    for scope in SOURCE_SCOPES:
        directory, mode = _source_path(source_root, scope, "source enumeration")
        if not stat.S_ISDIR(mode): raise SurfaceError("source scope is not a directory")
        pending = [(directory, scope)]
        while pending:
            directory, relative = pending.pop()
            try:
                children = list(directory.iterdir())
            except (OSError, UnicodeError, RuntimeError) as exc:
                raise SurfaceError("source enumeration failed") from exc
            for child in children:
                child_relative = f"{relative}/{child.name}"
                _, child_mode = _source_path(source_root, child_relative, "source enumeration")
                if stat.S_ISDIR(child_mode): pending.append((child, child_relative))
                elif stat.S_ISREG(child_mode) and child.suffix == ".rs": actual.add(child_relative)
    if actual != set(expected): raise SurfaceError("source inventory does not exactly match configured scopes")

if __name__ == "__main__":
    import argparse
    ap=argparse.ArgumentParser(); ap.add_argument("manifest",type=Path); ap.add_argument("source_root",type=Path); ap.add_argument("provenance",type=Path); a=ap.parse_args()
    verify_source(a.source_root,a.provenance,load_manifest(a.manifest)); print("surface closure verified: 82 routes")
