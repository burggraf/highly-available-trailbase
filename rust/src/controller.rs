use crate::{
    auth::{AuthError, AuthStore},
    config::{Config, CONFIG_LIMIT},
    journal::{Journal, JournalError, OperationReceipt},
};
use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use getrandom::fill;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::net::TcpListener;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestartState {
    WaitingForController,
    WaitingForAuthorization,
    Authorized,
    BlockedUncertain,
}

pub struct RestartGuard {
    incarnation: String,
    state: RestartState,
}

impl RestartGuard {
    pub fn new(incarnation: &str) -> Self {
        Self {
            incarnation: incarnation.to_owned(),
            state: RestartState::WaitingForController,
        }
    }

    pub fn controller_reachable(&mut self) {
        if self.state == RestartState::WaitingForController {
            self.state = RestartState::WaitingForAuthorization;
        }
    }

    pub fn authorize(&mut self, incarnation: &str) -> bool {
        if self.state != RestartState::WaitingForAuthorization || incarnation != self.incarnation {
            return false;
        }
        self.state = RestartState::Authorized;
        true
    }

    pub fn block_uncertain(&mut self) {
        self.state = RestartState::BlockedUncertain;
    }

    pub fn state(&self) -> &RestartState {
        &self.state
    }
}

pub struct Controller {
    pub journal: Journal,
    pub auth: AuthStore,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionCommand {
    pub cluster_id: String,
    pub controller_node_id: String,
    pub request_id: String,
    pub operation_id: String,
    pub digest: String,
    pub kind: String,
    pub target_node_id: String,
    pub expected_generation: String,
    pub expected_role: String,
    pub expected_admission: String,
    pub accept_possible_loss: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionOutcome {
    Succeeded,
    FailedSafe,
    Uncertain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionAdapterError {
    Unavailable,
    Refused,
    Uncertain,
}

pub trait ActionAdapter: Send + Sync {
    fn available(&self) -> bool;
    fn execute(&self, command: &ActionCommand) -> Result<ActionOutcome, ActionAdapterError>;
}

struct UnavailableActionAdapter;

impl ActionAdapter for UnavailableActionAdapter {
    fn available(&self) -> bool {
        false
    }

    fn execute(&self, _command: &ActionCommand) -> Result<ActionOutcome, ActionAdapterError> {
        Err(ActionAdapterError::Unavailable)
    }
}

impl Controller {
    pub fn open(path: impl AsRef<std::path::Path>, owner: &str) -> Result<Self, JournalError> {
        let journal = Journal::open(path, owner)?;
        let mut auth = AuthStore::new();
        for (account, hash, enabled) in journal.accounts()? {
            auth.load_account(&account, &hash, enabled)
                .map_err(|_| JournalError::InvalidInput)?;
        }
        Ok(Self { journal, auth })
    }

    pub fn create_account(&mut self, account: &str, password: &str) -> Result<(), JournalError> {
        let mut candidate = AuthStore::new();
        candidate
            .create_account(account, password)
            .map_err(|_| JournalError::InvalidInput)?;
        let hash = candidate
            .password_hash(account)
            .ok_or(JournalError::InvalidInput)?
            .to_owned();
        self.journal.store_account(account, &hash, true)?;
        self.auth
            .load_account(account, &hash, true)
            .map_err(|_| JournalError::InvalidInput)
    }

    pub fn disable_account(&mut self, account: &str) -> Result<(), JournalError> {
        self.journal.set_account_enabled(account, false)?;
        self.auth
            .disable_account(account)
            .map_err(|_| JournalError::InvalidInput)
    }

    pub fn submit_operation(
        &mut self,
        request_id: &str,
        operation_id: &str,
        digest: &str,
    ) -> Result<OperationReceipt, JournalError> {
        self.journal.submit(request_id, operation_id, digest)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeView {
    pub id: String,
    pub endpoint: String,
    pub role: &'static str,
    pub health: &'static str,
    pub admission: &'static str,
    pub replication: &'static str,
    pub detail: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClusterView {
    pub cluster_id: String,
    pub controller_node_id: String,
    pub primary_node_id: String,
    pub route_generation: Option<String>,
    pub writer_epoch: Option<String>,
    pub nodes: Vec<NodeView>,
}

impl ClusterView {
    pub fn empty() -> Self {
        Self {
            cluster_id: "unknown".into(),
            controller_node_id: "unknown".into(),
            primary_node_id: "unknown".into(),
            route_generation: None,
            writer_epoch: None,
            nodes: Vec::new(),
        }
    }

    pub fn from_config(config: &Config) -> Self {
        Self {
            cluster_id: config.cluster_id().to_owned(),
            controller_node_id: config.controller_node_id().to_owned(),
            primary_node_id: config.primary_node_id().to_owned(),
            route_generation: None,
            writer_epoch: None,
            nodes: config
                .nodes()
                .iter()
                .map(|node| NodeView {
                    id: node.id().to_owned(),
                    endpoint: node.endpoint().to_owned(),
                    role: if node.id() == config.primary_node_id() {
                        "primary"
                    } else {
                        "standby"
                    },
                    health: "unknown",
                    admission: "unknown",
                    replication: "unknown",
                    detail: "Waiting for a live node observation",
                })
                .collect(),
        }
    }
}

#[derive(Clone)]
pub struct DashboardState {
    controller: Arc<Mutex<Controller>>,
    origin: Arc<str>,
    csrf: Arc<str>,
    cluster: Arc<ClusterView>,
    local_node_id: Option<Arc<str>>,
    adapter: Arc<dyn ActionAdapter>,
}

#[derive(Deserialize)]
struct LoginRequest {
    account: String,
    password: String,
}

#[derive(Deserialize)]
struct OperationRequest {
    request_id: String,
    operation_id: String,
    digest: String,
}

#[derive(Deserialize)]
struct ActionRequest {
    request_id: String,
    operation_id: String,
    kind: String,
    target_node_id: String,
    expected_generation: String,
    expected_role: String,
    expected_admission: String,
    accept_possible_loss: bool,
}

#[derive(Serialize)]
struct LoginResponse {
    csrf_token: String,
}

#[derive(Serialize)]
struct ActionAvailability {
    enabled: bool,
    authority: String,
    reason: &'static str,
}

#[derive(Serialize)]
struct StatusResponse {
    controller: &'static str,
    unfinished_operations: usize,
    cluster: ClusterView,
    actions: ActionAvailability,
}

pub fn dashboard(controller: Controller, origin: &str) -> Result<Router, JournalError> {
    dashboard_with_cluster(controller, origin, ClusterView::empty(), None)
}

pub fn dashboard_with_cluster(
    controller: Controller,
    origin: &str,
    cluster: ClusterView,
    local_node_id: Option<&str>,
) -> Result<Router, JournalError> {
    dashboard_with_cluster_and_adapter(
        controller,
        origin,
        cluster,
        local_node_id,
        Arc::new(UnavailableActionAdapter),
    )
}

pub fn dashboard_with_cluster_and_adapter(
    controller: Controller,
    origin: &str,
    cluster: ClusterView,
    local_node_id: Option<&str>,
    adapter: Arc<dyn ActionAdapter>,
) -> Result<Router, JournalError> {
    let mut csrf_bytes = [0u8; 32];
    fill(&mut csrf_bytes).map_err(|_| JournalError::InvalidInput)?;
    let csrf: String = csrf_bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let state = DashboardState {
        controller: Arc::new(Mutex::new(controller)),
        origin: Arc::from(origin.to_owned()),
        csrf: Arc::from(csrf),
        cluster: Arc::new(cluster),
        local_node_id: local_node_id.map(Arc::from),
        adapter,
    };
    Ok(Router::new()
        .route("/", get(index))
        .route("/app.css", get(app_css))
        .route("/app.js", get(app_js))
        .route("/favicon.ico", get(favicon))
        .route("/api/v1/login", post(login))
        .route("/api/v1/logout", post(logout))
        .route("/api/v1/status", get(status))
        .route("/api/v1/actions", post(action))
        .route("/api/v1/operations", post(operation))
        .with_state(state))
}

pub async fn serve_dashboard(
    listen: SocketAddr,
    controller: Controller,
    origin: &str,
) -> Result<(), String> {
    serve_dashboard_with_cluster(listen, controller, origin, ClusterView::empty(), None).await
}

pub async fn serve_dashboard_with_cluster(
    listen: SocketAddr,
    controller: Controller,
    origin: &str,
    cluster: ClusterView,
    local_node_id: Option<&str>,
) -> Result<(), String> {
    if !listen.ip().is_loopback() || !valid_local_origin(origin) {
        return Err("controller listener must be loopback with a local origin".to_string());
    }
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|_| "unable to bind controller")?;
    axum::serve(
        listener,
        dashboard_with_cluster(controller, origin, cluster, local_node_id)
            .map_err(|_| "invalid controller")?,
    )
    .await
    .map_err(|_| "controller stopped".to_string())
}

async fn index(State(state): State<DashboardState>, request: Request) -> Response<Body> {
    if !headers_bounded(request.headers()) || !host_matches(request.headers(), &state.origin) {
        return refused(StatusCode::BAD_REQUEST, "request refused");
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header("content-security-policy", "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        .header("x-content-type-options", "nosniff")
        .header("cache-control", "no-store")
        .body(Body::from(r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>HAT Control Center</title>
  <link rel="stylesheet" href="/app.css">
  <script src="/app.js" defer></script>
</head>
<body>
  <div class="app-shell">
    <header class="topbar">
      <a class="brand" href="/" aria-label="HAT Control Center home">
        <span class="brand-mark">H</span>
        <span><strong>HAT Control Center</strong><small>Single-writer cluster operations</small></span>
      </a>
      <div class="topbar-actions">
        <span id="connection-badge" class="badge badge-muted">Sign in required</span>
        <button class="button button-ghost" id="logout" type="button">Sign out</button>
      </div>
    </header>

    <main class="content">
      <section class="hero">
        <div>
          <p class="eyebrow">Operations center</p>
          <h1>Cluster overview</h1>
          <p class="lede">See which node is serving traffic, whether replicas are ready, and what the controller will allow next.</p>
        </div>
        <button class="button button-secondary" id="refresh-status" type="button">Refresh status</button>
      </section>

      <section class="login-panel panel" aria-labelledby="login-heading">
        <div>
          <p class="eyebrow">Operator access</p>
          <h2 id="login-heading">Sign in to manage the cluster</h2>
          <p class="muted">Read-only status is available after authentication. Actions always require a fresh server-side check.</p>
        </div>
        <form id="login" class="login-form">
          <label>Account<input id="account" name="account" autocomplete="username" required></label>
          <label>Password<input id="password" name="password" type="password" autocomplete="current-password" required></label>
          <button class="button button-primary" type="submit">Sign in</button>
        </form>
      </section>

      <p id="status" class="notice notice-info" role="status">Sign in to load live cluster status.</p>

      <section class="metric-grid" aria-label="Cluster summary">
        <article class="metric-card"><span class="metric-label">Cluster health</span><strong id="summary-health">Unknown</strong><span id="summary-health-detail" class="metric-detail">No live observations yet</span></article>
        <article class="metric-card"><span class="metric-label">Current primary</span><strong id="summary-primary">Unknown</strong><span id="summary-primary-detail" class="metric-detail">Route not published</span></article>
        <article class="metric-card"><span class="metric-label">Nodes</span><strong id="summary-nodes">0</strong><span id="summary-nodes-detail" class="metric-detail">Inventory unavailable</span></article>
        <article class="metric-card"><span class="metric-label">Open operations</span><strong id="summary-operations">—</strong><span id="summary-operations-detail" class="metric-detail">Sign in to inspect</span></article>
      </section>

      <section class="panel" aria-labelledby="nodes-heading">
        <div class="panel-heading"><div><p class="eyebrow">Inventory and observations</p><h2 id="nodes-heading">Nodes</h2></div><span id="cluster-id" class="mono muted">Cluster unavailable</span></div>
        <div id="node-grid" class="node-grid"><div class="empty-state">Sign in to load the node inventory.</div></div>
      </section>

      <div class="two-column">
        <section class="panel" aria-labelledby="actions-heading">
          <div class="panel-heading"><div><p class="eyebrow">Controlled mutations</p><h2 id="actions-heading">Operator actions</h2></div><span class="badge badge-warning">Confirmation required</span></div>
          <p id="action-notice" class="muted">The native node-action adapter is not connected. No button will simulate a transition.</p>
          <label class="field-label" for="action-target">Target node</label>
          <select id="action-target" class="select" disabled><option>Sign in to load nodes</option></select>
          <div class="action-grid">
            <button class="action-card action-danger" data-action="failover" type="button" disabled><span class="action-icon">↗</span><span><strong>Fail over</strong><small>Promote a confirmed standby</small></span></button>
            <button class="action-card" data-action="restart" type="button" disabled><span class="action-icon">↻</span><span><strong>Restart node</strong><small>Reconcile before reopening</small></span></button>
            <button class="action-card" data-action="shutdown" type="button" disabled><span class="action-icon">■</span><span><strong>Shut down</strong><small>Close admission first</small></span></button>
            <button class="action-card" data-action="rejoin" type="button" disabled><span class="action-icon">＋</span><span><strong>Rejoin node</strong><small>Reseed as a closed standby</small></span></button>
          </div>
        </section>

        <section class="panel" aria-labelledby="operations-heading">
          <div class="panel-heading"><div><p class="eyebrow">Durable control history</p><h2 id="operations-heading">Current operation</h2></div><span class="badge badge-muted">Controller journal</span></div>
          <div id="operation-state" class="empty-state"><strong>No operation selected</strong><span>Accepted operations will appear here with their target, phase, and uncertainty state.</span></div>
        </section>
      </div>
    </main>
  </div>
</body>
</html>"##))
        .unwrap()
}

const CSS: &str = r##"
:root { color-scheme: light; --ink:#18212f; --muted:#697386; --line:#e6eaf0; --surface:#fff; --page:#f6f8fb; --navy:#182b49; --blue:#2e67d1; --green:#18835b; --amber:#9a6612; --red:#bd3f4a; --shadow:0 12px 32px rgba(24,43,73,.08); font:15px/1.5 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
* { box-sizing:border-box; }
body { margin:0; background:var(--page); color:var(--ink); }
button, input, select { font:inherit; }
button { cursor:pointer; }
button:disabled { cursor:not-allowed; opacity:.52; }
.app-shell { min-height:100vh; }
.topbar { height:76px; display:flex; align-items:center; justify-content:space-between; padding:0 5vw; background:var(--navy); color:#fff; }
.brand { display:flex; align-items:center; gap:12px; color:#fff; text-decoration:none; }
.brand-mark { display:grid; place-items:center; width:36px; height:36px; border-radius:10px; background:#6ba4ff; color:var(--navy); font-size:21px; font-weight:800; }
.brand strong, .brand small { display:block; }
.brand strong { font-size:16px; letter-spacing:.01em; }
.brand small { color:#b9c7dc; font-size:12px; }
.topbar-actions { display:flex; align-items:center; gap:14px; }
.content { width:min(1180px, 90vw); margin:0 auto; padding:46px 0 72px; }
.hero { display:flex; align-items:flex-end; justify-content:space-between; gap:24px; margin-bottom:28px; }
.eyebrow { margin:0 0 6px; color:var(--blue); font-size:11px; font-weight:800; letter-spacing:.14em; text-transform:uppercase; }
h1, h2, p { margin-top:0; }
h1 { margin-bottom:8px; color:var(--navy); font-size:clamp(30px, 4vw, 48px); line-height:1.05; letter-spacing:-.04em; }
h2 { margin-bottom:5px; color:var(--navy); font-size:20px; letter-spacing:-.02em; }
.lede { max-width:650px; margin:0; color:var(--muted); font-size:17px; }
.panel, .metric-card { border:1px solid var(--line); border-radius:16px; background:var(--surface); box-shadow:var(--shadow); }
.panel { padding:24px; margin-bottom:22px; }
.panel-heading { display:flex; align-items:flex-start; justify-content:space-between; gap:16px; margin-bottom:20px; }
.muted, .metric-detail, .node-detail { color:var(--muted); }
.login-panel { display:flex; align-items:end; justify-content:space-between; gap:28px; }
.login-form { display:grid; grid-template-columns:150px 190px auto; align-items:end; gap:12px; min-width:min(100%, 520px); }
label, .field-label { display:grid; gap:6px; color:var(--muted); font-size:12px; font-weight:700; }
input, .select { width:100%; min-height:42px; border:1px solid #ced5e0; border-radius:9px; background:#fff; color:var(--ink); padding:9px 11px; outline:none; }
input:focus, .select:focus { border-color:var(--blue); box-shadow:0 0 0 3px rgba(46,103,209,.14); }
.button { display:inline-flex; align-items:center; justify-content:center; min-height:42px; border:1px solid transparent; border-radius:9px; padding:9px 16px; font-weight:750; transition:transform .15s, box-shadow .15s, background .15s; }
.button:hover:not(:disabled) { transform:translateY(-1px); box-shadow:0 5px 14px rgba(24,43,73,.14); }
.button-primary { background:var(--blue); color:#fff; }
.button-secondary { border-color:#cbd6e7; background:#fff; color:var(--navy); }
.button-ghost { min-height:34px; border-color:rgba(255,255,255,.25); background:transparent; color:#fff; padding:6px 12px; }
.notice { border-radius:10px; padding:12px 15px; margin:0 0 22px; border:1px solid; }
.notice-info { border-color:#c8dafb; background:#eef5ff; color:#24539d; }
.notice-success { border-color:#bfe8d5; background:#effaf4; color:#146340; }
.notice-danger { border-color:#f0c6cc; background:#fff2f3; color:#9f303d; }
.metric-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-bottom:22px; }
.metric-card { padding:20px; }
.metric-label { display:block; color:var(--muted); font-size:12px; font-weight:700; }
.metric-card strong { display:block; margin:5px 0 2px; color:var(--navy); font-size:24px; letter-spacing:-.03em; }
.metric-detail { display:block; font-size:12px; }
.node-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(250px,1fr)); gap:14px; }
.node-card { border:1px solid var(--line); border-radius:12px; padding:18px; background:#fbfcfe; }
.node-card-header { display:flex; align-items:center; justify-content:space-between; gap:10px; }
.node-card-header > div { display:flex; align-items:center; gap:9px; }
.node-dot { width:10px; height:10px; border-radius:50%; background:#aab3c2; box-shadow:0 0 0 4px #eef1f5; }
.node-healthy { background:var(--green); box-shadow:0 0 0 4px #ddf4e9; }
.node-stale { background:var(--amber); box-shadow:0 0 0 4px #fff0d3; }
.node-danger { background:var(--red); box-shadow:0 0 0 4px #ffe0e3; }
.role, .badge { display:inline-flex; align-items:center; border-radius:999px; padding:4px 9px; font-size:11px; font-weight:800; }
.role-primary { background:#e5efff; color:#2b5bb0; }
.role-standby { background:#edf0f5; color:#596579; }
.badge-success { background:#dff4e9; color:#146340; }
.badge-warning { background:#fff0d3; color:#87570d; }
.badge-danger { background:#ffe0e3; color:#9f303d; }
.badge-muted { background:rgba(255,255,255,.14); color:#d3ddec; }
.node-endpoint { margin:11px 0 15px; font-size:12px; }
.node-facts { display:grid; grid-template-columns:repeat(3,1fr); gap:8px; margin:0; }
.node-facts div { border-top:1px solid var(--line); padding-top:8px; }
.node-facts dt { color:var(--muted); font-size:11px; }
.node-facts dd { margin:2px 0 0; color:var(--ink); font-size:12px; font-weight:700; text-transform:capitalize; }
.node-detail { margin:14px 0 0; font-size:12px; }
.two-column { display:grid; grid-template-columns:1.15fr .85fr; gap:22px; }
.field-label { margin-bottom:7px; }
.action-grid { display:grid; grid-template-columns:repeat(2,1fr); gap:10px; margin-top:16px; }
.action-card { display:flex; align-items:center; gap:12px; min-height:72px; border:1px solid var(--line); border-radius:12px; background:#fff; color:var(--ink); padding:12px; text-align:left; }
.action-card:hover:not(:disabled) { border-color:#a9c5f6; background:#f7faff; }
.action-danger { border-color:#f0c6cc; }
.action-icon { display:grid; place-items:center; width:32px; height:32px; border-radius:9px; background:#edf3ff; color:var(--blue); font-size:19px; }
.action-danger .action-icon { background:#fff0f1; color:var(--red); }
.action-card strong, .action-card small { display:block; }
.action-card small { margin-top:2px; color:var(--muted); font-size:11px; }
.empty-state { display:grid; gap:4px; min-height:120px; place-content:center; border:1px dashed #ccd5e2; border-radius:11px; color:var(--muted); text-align:center; }
.empty-state strong { color:var(--navy); }
.mono { font-family:ui-monospace, SFMono-Regular, Menlo, monospace; }
@media (max-width:800px) { .topbar { padding:0 20px; } .content { width:min(100% - 32px, 640px); padding-top:28px; } .hero, .login-panel { align-items:stretch; flex-direction:column; } .login-form { grid-template-columns:1fr; min-width:0; } .metric-grid { grid-template-columns:repeat(2,1fr); } .two-column { grid-template-columns:1fr; } }
@media (max-width:480px) { .topbar { height:auto; align-items:flex-start; gap:16px; padding:18px 16px; } .topbar-actions { align-items:flex-end; flex-direction:column; gap:8px; } .content { width:calc(100% - 24px); } .panel { padding:17px; } .metric-grid { gap:8px; } .metric-card { padding:14px; } .metric-card strong { font-size:20px; } .action-grid { grid-template-columns:1fr; } }
"##;

async fn app_css(State(state): State<DashboardState>, request: Request) -> Response<Body> {
    if !headers_bounded(request.headers()) || !host_matches(request.headers(), &state.origin) {
        return refused(StatusCode::BAD_REQUEST, "request refused");
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/css; charset=utf-8")
        .header("cache-control", "no-store")
        .body(Body::from(CSS))
        .unwrap()
}

async fn favicon(State(state): State<DashboardState>, request: Request) -> Response<Body> {
    if !headers_bounded(request.headers()) || !host_matches(request.headers(), &state.origin) {
        return refused(StatusCode::BAD_REQUEST, "request refused");
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn app_js(State(state): State<DashboardState>, request: Request) -> Response<Body> {
    if !headers_bounded(request.headers()) || !host_matches(request.headers(), &state.origin) {
        return refused(StatusCode::BAD_REQUEST, "request refused");
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/javascript; charset=utf-8")
        .header("cache-control", "no-store")
        .body(Body::from(r#"(() => {
const $ = (id) => document.getElementById(id);
let csrf = '';
let snapshot = null;

const setNotice = (text, kind = 'info') => {
  const node = $('status');
  node.textContent = text;
  node.className = `notice notice-${kind}`;
};
const escapeHtml = (value) => String(value ?? '').replace(/[&<>'"]/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));
const label = (value) => String(value || 'unknown').replaceAll('_', ' ');

function renderCluster(data) {
  snapshot = data;
  const cluster = data.cluster || {};
  const nodes = cluster.nodes || [];
  const healthy = nodes.filter((node) => node.health === 'healthy').length;
  const unknown = nodes.filter((node) => node.health === 'unknown' || node.health === 'stale').length;
  $('summary-health').textContent = healthy === nodes.length && nodes.length ? 'Healthy' : unknown ? 'Needs attention' : 'Unknown';
  $('summary-health-detail').textContent = unknown ? `${unknown} node${unknown === 1 ? '' : 's'} need observation` : 'All observations current';
  $('summary-primary').textContent = cluster.primary_node_id || 'Unknown';
  $('summary-primary-detail').textContent = cluster.route_generation ? `Route generation ${cluster.route_generation}` : 'Route not published';
  $('summary-nodes').textContent = nodes.length;
  $('summary-nodes-detail').textContent = nodes.length ? 'Configured inventory' : 'Inventory unavailable';
  $('summary-operations').textContent = data.unfinished_operations ?? '—';
  $('summary-operations-detail').textContent = data.unfinished_operations ? 'Needs inspection' : 'No open operations';
  $('cluster-id').textContent = cluster.cluster_id || 'Cluster unavailable';
  $('connection-badge').textContent = data.controller === 'available' ? 'Controller connected' : 'Controller unavailable';
  $('connection-badge').className = `badge ${data.controller === 'available' ? 'badge-success' : 'badge-danger'}`;

  $('node-grid').innerHTML = nodes.length ? nodes.map((node) => `
    <article class=\"node-card\">
      <div class=\"node-card-header\"><div><span class=\"node-dot node-${escapeHtml(node.health)}\"></span><strong>${escapeHtml(node.id)}</strong></div><span class=\"role role-${escapeHtml(node.role)}\">${escapeHtml(node.role)}</span></div>
      <p class=\"node-endpoint mono\">${escapeHtml(node.endpoint)}</p>
      <dl class=\"node-facts\"><div><dt>Health</dt><dd>${escapeHtml(label(node.health))}</dd></div><div><dt>Admission</dt><dd>${escapeHtml(label(node.admission))}</dd></div><div><dt>Replication</dt><dd>${escapeHtml(label(node.replication))}</dd></div></dl>
      <p class=\"node-detail\">${escapeHtml(node.detail)}</p>
    </article>`).join('') : '<div class=\"empty-state\">No configured nodes.</div>';

  $('action-target').innerHTML = nodes.length ? nodes.map((node) => `<option value=\"${escapeHtml(node.id)}\">${escapeHtml(node.id)} · ${escapeHtml(node.role)}</option>`).join('') : '<option>No nodes available</option>';
  $('action-target').disabled = !data.actions?.enabled || !nodes.length;
  document.querySelectorAll('[data-action]').forEach((button) => { button.disabled = !data.actions?.enabled || !nodes.length; });
  $('action-notice').textContent = data.actions?.reason || 'No action status available.';
  $('operation-state').innerHTML = data.unfinished_operations ? '<strong>Open operations need inspection</strong><span>Use the controller journal before starting another mutation.</span>' : '<strong>No operation selected</strong><span>Accepted operations will appear here with their target, phase, and uncertainty state.</span>';
}

async function refresh() {
  const response = await fetch('/api/v1/status', { headers: {'Accept': 'application/json'} });
  if (response.status === 401) return setNotice('Sign in to load live cluster status.', 'info');
  if (!response.ok) return setNotice('The controller did not return a usable status.', 'danger');
  renderCluster(await response.json());
  setNotice('Status refreshed just now.', 'success');
}

$('login').addEventListener('submit', async (event) => {
  event.preventDefault();
  const response = await fetch('/api/v1/login', { method: 'POST', headers: {'Content-Type': 'application/json', 'Origin': location.origin}, body: JSON.stringify({account: $('account').value, password: $('password').value}) });
  if (!response.ok) return setNotice('Sign-in refused. Check the account and password.', 'danger');
  csrf = (await response.json()).csrf_token;
  await refresh();
});
$('refresh-status').addEventListener('click', refresh);
$('logout').addEventListener('click', async () => {
  if (csrf) await fetch('/api/v1/logout', { method: 'POST', headers: {'Origin': location.origin, 'X-CSRF-Token': csrf} });
  csrf = '';
  snapshot = null;
  $('connection-badge').textContent = 'Sign in required';
  $('connection-badge').className = 'badge badge-muted';
  setNotice('Signed out.', 'info');
});
document.querySelectorAll('[data-action]').forEach((button) => button.addEventListener('click', async () => {
  if (!snapshot || !csrf) return;
  const target = $('action-target').value;
  const kind = button.dataset.action;
  const node = (snapshot.cluster.nodes || []).find((item) => item.id === target);
  const phrase = kind === 'failover' ? 'This may lose recent writes. Continue?' : `Request ${kind} for ${target}?`;
  if (!window.confirm(phrase)) return;
  const response = await fetch('/api/v1/actions', { method: 'POST', headers: {'Content-Type': 'application/json', 'Origin': location.origin, 'X-CSRF-Token': csrf}, body: JSON.stringify({request_id: crypto.randomUUID(), operation_id: crypto.randomUUID(), kind, target_node_id: target, expected_generation: snapshot.cluster.route_generation || '0', expected_role: node?.role || '', expected_admission: node?.admission || '', accept_possible_loss: kind === 'failover'}) });
  const body = await response.text();
  setNotice(response.ok ? 'Operation accepted.' : body || 'Action refused.', response.ok ? 'success' : 'danger');
}));
})();"#))
        .unwrap()
}

async fn login(State(state): State<DashboardState>, request: Request) -> Response<Body> {
    if !headers_bounded(request.headers())
        || !json_origin_ok(request.headers(), &state.origin, true)
    {
        return refused(StatusCode::FORBIDDEN, "request refused");
    }
    let body = match bounded_json::<LoginRequest>(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let mut controller = state.controller.lock().unwrap();
    let token = match controller.auth.login(&body.account, &body.password) {
        Ok(token) => token,
        Err(AuthError::Refused | AuthError::Revoked | AuthError::InvalidInput) => {
            return refused(StatusCode::UNAUTHORIZED, "login failed")
        }
    };
    let mut response = Json(LoginResponse {
        csrf_token: state.csrf.to_string(),
    })
    .into_response();
    let cookie = format!("__Host-hat_session={token}; Secure; HttpOnly; SameSite=Strict; Path=/");
    response
        .headers_mut()
        .insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    response
}

async fn logout(State(state): State<DashboardState>, request: Request) -> Response<Body> {
    if !headers_bounded(request.headers())
        || !json_origin_ok(request.headers(), &state.origin, true)
        || request
            .headers()
            .get("x-csrf-token")
            .and_then(|value| value.to_str().ok())
            != Some(state.csrf.as_ref())
    {
        return refused(StatusCode::FORBIDDEN, "request refused");
    }
    let mut controller = state.controller.lock().unwrap();
    if authenticate(&mut controller, request.headers()).is_ok() {
        if let Some(token) = request
            .headers()
            .get(header::COOKIE)
            .and_then(|value| value.to_str().ok())
            .and_then(session_cookie)
        {
            controller.auth.logout(token);
        }
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "__Host-hat_session=; Max-Age=0; Secure; HttpOnly; SameSite=Strict; Path=/",
        ),
    );
    response
}

fn is_mutation_authority(state: &DashboardState) -> bool {
    state.local_node_id.as_deref() == Some(state.cluster.controller_node_id.as_str())
}

async fn status(State(state): State<DashboardState>, request: Request) -> Response<Body> {
    if !headers_bounded(request.headers()) || !host_matches(request.headers(), &state.origin) {
        return refused(StatusCode::BAD_REQUEST, "request refused");
    }
    let mut controller = state.controller.lock().unwrap();
    if authenticate(&mut controller, request.headers()).is_err() {
        return refused(StatusCode::UNAUTHORIZED, "authentication required");
    }
    let unfinished = match controller.journal.unfinished() {
        Ok(items) => items.len(),
        Err(_) => return refused(StatusCode::INTERNAL_SERVER_ERROR, "status unavailable"),
    };
    Json(StatusResponse {
        controller: "available",
        unfinished_operations: unfinished,
        cluster: (*state.cluster).clone(),
        actions: ActionAvailability {
            enabled: false,
            authority: state.cluster.controller_node_id.clone(),
            reason: if is_mutation_authority(&state) {
                "Native node-action adapter is not connected; actions are fail-closed."
            } else {
                "This dashboard is read-only; submit actions through the configured controller authority."
            },
        },
    })
    .into_response()
}

async fn action(State(state): State<DashboardState>, request: Request) -> Response<Body> {
    if !headers_bounded(request.headers())
        || !json_origin_ok(request.headers(), &state.origin, true)
    {
        return refused(StatusCode::FORBIDDEN, "request refused");
    }
    if request
        .headers()
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
        != Some(state.csrf.as_ref())
    {
        return refused(StatusCode::FORBIDDEN, "request refused");
    }
    let session = request.headers().clone();
    let body = match bounded_json::<ActionRequest>(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let mut controller = state.controller.lock().unwrap();
    if authenticate(&mut controller, &session).is_err() {
        return refused(StatusCode::UNAUTHORIZED, "authentication required");
    }
    if !valid_action_identity(&body.request_id) || !valid_action_identity(&body.operation_id) {
        return refused(StatusCode::BAD_REQUEST, "invalid action identity");
    }
    if !matches!(
        body.kind.as_str(),
        "failover" | "restart" | "shutdown" | "rejoin"
    ) || body.target_node_id.is_empty()
        || body.target_node_id.len() > 32
        || body.expected_generation.is_empty()
        || body.expected_role.is_empty()
        || body.expected_role.len() > 32
        || body.expected_admission.is_empty()
        || body.expected_admission.len() > 32
    {
        return refused(StatusCode::BAD_REQUEST, "invalid action");
    }
    let Some(target) = state
        .cluster
        .nodes
        .iter()
        .find(|node| node.id == body.target_node_id)
    else {
        return refused(StatusCode::BAD_REQUEST, "unknown target node");
    };
    if body.expected_role != target.role || body.expected_admission != target.admission {
        return refused(StatusCode::CONFLICT, "target state changed");
    }
    let current_generation = state.cluster.route_generation.as_deref().unwrap_or("0");
    if body.expected_generation != current_generation {
        return refused(StatusCode::CONFLICT, "stale route generation");
    }
    if body.kind == "failover" && !body.accept_possible_loss {
        return refused(StatusCode::CONFLICT, "possible loss must be accepted");
    }
    if !is_mutation_authority(&state) {
        return refused(
            StatusCode::SERVICE_UNAVAILABLE,
            "controller authority is configured elsewhere",
        );
    }
    let digest = action_digest(&state.cluster, &body);
    let failover = body.kind == "failover";
    match controller
        .journal
        .retained(&body.request_id, &body.operation_id, &digest, failover)
    {
        Ok(Some(receipt)) => return action_receipt(receipt, StatusCode::ACCEPTED),
        Ok(None) => {}
        Err(JournalError::Conflict | JournalError::PolicyConflict) => {
            return refused(StatusCode::CONFLICT, "request identity conflict")
        }
        Err(_) => return refused(StatusCode::INTERNAL_SERVER_ERROR, "operation unavailable"),
    }
    if !state.adapter.available() {
        return refused(
            StatusCode::SERVICE_UNAVAILABLE,
            "native action adapter unavailable",
        );
    }
    let receipt = match controller.journal.submit_with_policy(
        &body.request_id,
        &body.operation_id,
        &digest,
        failover,
    ) {
        Ok(receipt) => receipt,
        Err(JournalError::Conflict | JournalError::PolicyConflict) => {
            return refused(StatusCode::CONFLICT, "request identity conflict")
        }
        Err(JournalError::Uncertain) => {
            return refused(StatusCode::CONFLICT, "operation blocked by uncertainty")
        }
        Err(JournalError::InvalidInput) => {
            return refused(StatusCode::BAD_REQUEST, "invalid action")
        }
        Err(JournalError::AlreadyOwned | JournalError::Sql(_)) => {
            return refused(StatusCode::INTERNAL_SERVER_ERROR, "operation unavailable")
        }
    };
    let command = ActionCommand {
        cluster_id: state.cluster.cluster_id.clone(),
        controller_node_id: state.cluster.controller_node_id.clone(),
        request_id: body.request_id.clone(),
        operation_id: body.operation_id.clone(),
        digest,
        kind: body.kind.clone(),
        target_node_id: body.target_node_id.clone(),
        expected_generation: body.expected_generation.clone(),
        expected_role: body.expected_role.clone(),
        expected_admission: body.expected_admission.clone(),
        accept_possible_loss: body.accept_possible_loss,
    };
    let terminal_state = match state.adapter.execute(&command) {
        Ok(ActionOutcome::Succeeded) => "succeeded",
        Ok(ActionOutcome::FailedSafe) | Err(ActionAdapterError::Refused) => "failed_safe",
        Ok(ActionOutcome::Uncertain)
        | Err(ActionAdapterError::Unavailable | ActionAdapterError::Uncertain) => {
            "blocked_uncertain"
        }
    };
    if controller
        .journal
        .finish(&body.operation_id, terminal_state)
        .is_err()
    {
        let _ = controller.journal.block_uncertain(&body.operation_id);
        return refused(
            StatusCode::INTERNAL_SERVER_ERROR,
            "operation result unavailable",
        );
    }
    let mut settled = receipt;
    settled.state = terminal_state.to_owned();
    let status = if terminal_state == "blocked_uncertain" {
        StatusCode::CONFLICT
    } else {
        StatusCode::ACCEPTED
    };
    action_receipt(settled, status)
}

fn valid_action_identity(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn action_digest(cluster: &ClusterView, body: &ActionRequest) -> String {
    let canonical = serde_json::to_vec(&(
        "hat-action-v1",
        &cluster.cluster_id,
        &cluster.controller_node_id,
        &body.request_id,
        &body.operation_id,
        &body.kind,
        &body.target_node_id,
        &body.expected_generation,
        &body.expected_role,
        &body.expected_admission,
        body.accept_possible_loss,
    ))
    .expect("action digest fields are serializable");
    Sha256::digest(canonical)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn action_receipt(receipt: OperationReceipt, status: StatusCode) -> Response<Body> {
    let mut response = Json(receipt).into_response();
    *response.status_mut() = status;
    response
}

async fn operation(State(state): State<DashboardState>, request: Request) -> Response<Body> {
    if !headers_bounded(request.headers())
        || !json_origin_ok(request.headers(), &state.origin, true)
    {
        return refused(StatusCode::FORBIDDEN, "request refused");
    }
    let csrf = request
        .headers()
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok());
    if csrf != Some(state.csrf.as_ref()) {
        return refused(StatusCode::FORBIDDEN, "request refused");
    }
    let session = request.headers().clone();
    let body = match bounded_json::<OperationRequest>(request).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let mut controller = state.controller.lock().unwrap();
    if authenticate(&mut controller, &session).is_err() {
        return refused(StatusCode::UNAUTHORIZED, "authentication required");
    }
    if !is_mutation_authority(&state) {
        return refused(
            StatusCode::SERVICE_UNAVAILABLE,
            "controller authority is configured elsewhere",
        );
    }
    match controller.submit_operation(&body.request_id, &body.operation_id, &body.digest) {
        Ok(receipt) => {
            let mut response = Json(receipt).into_response();
            *response.status_mut() = StatusCode::ACCEPTED;
            response
        }
        Err(JournalError::Conflict) => refused(StatusCode::CONFLICT, "request identity conflict"),
        Err(_) => refused(StatusCode::BAD_REQUEST, "operation refused"),
    }
}

async fn bounded_json<T: for<'de> Deserialize<'de>>(request: Request) -> Result<T, Response<Body>> {
    if request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        != Some("application/json")
    {
        return Err(refused(StatusCode::UNSUPPORTED_MEDIA_TYPE, "JSON required"));
    }
    let bytes = axum::body::to_bytes(request.into_body(), CONFIG_LIMIT)
        .await
        .map_err(|_| refused(StatusCode::PAYLOAD_TOO_LARGE, "request too large"))?;
    serde_json::from_slice(&bytes).map_err(|_| refused(StatusCode::BAD_REQUEST, "invalid request"))
}

fn authenticate(controller: &mut Controller, headers: &HeaderMap) -> Result<String, AuthError> {
    let token = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(session_cookie)
        .ok_or(AuthError::Refused)?;
    controller.auth.authenticate(token)
}

fn headers_bounded(headers: &HeaderMap) -> bool {
    headers.len() <= 64
        && headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
            .sum::<usize>()
            <= 32 * 1024
        && headers
            .iter()
            .all(|(name, value)| name.as_str().len() <= 128 && value.as_bytes().len() <= 4096)
}

fn valid_local_origin(origin: &str) -> bool {
    let Some((scheme, host)) = origin.split_once("://") else {
        return false;
    };
    if scheme != "http" || host.is_empty() || host.contains('/') {
        return false;
    }
    let host = host
        .split(':')
        .next()
        .unwrap_or_default()
        .trim_matches(['[', ']']);
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}

fn host_matches(headers: &HeaderMap, origin: &str) -> bool {
    let Some(host) = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let expected_host = origin.split_once("://").map_or(origin, |(_, host)| host);
    host == expected_host && host.len() <= 256
}

fn session_cookie(cookies: &str) -> Option<&str> {
    if cookies.len() > 4096 {
        return None;
    }
    cookies
        .split(';')
        .find_map(|cookie| cookie.trim().strip_prefix("__Host-hat_session="))
}

fn json_origin_ok(headers: &HeaderMap, origin: &str, mutation: bool) -> bool {
    let origin_ok = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        == Some(origin);
    host_matches(headers, origin) && (!mutation || origin_ok)
}

fn refused(status: StatusCode, message: &'static str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("cache-control", "no-store")
        .body(Body::from(message))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_waits_for_controller_and_exact_incarnation_authorization() {
        let mut restart = RestartGuard::new("incarnation-a");
        assert!(!restart.authorize("incarnation-a"));
        restart.controller_reachable();
        assert!(!restart.authorize("incarnation-b"));
        assert!(restart.authorize("incarnation-a"));
        assert_eq!(restart.state(), &RestartState::Authorized);
        restart.block_uncertain();
        assert!(!restart.authorize("incarnation-a"));
    }

    #[test]
    fn action_digest_separates_identity_fields() {
        let cluster = ClusterView::empty();
        let base = ActionRequest {
            request_id: String::new(),
            operation_id: String::new(),
            kind: "restart".into(),
            target_node_id: "node-b".into(),
            expected_generation: "0".into(),
            expected_role: "standby".into(),
            expected_admission: "unknown".into(),
            accept_possible_loss: false,
        };
        let mut first = base;
        first.request_id = "a|b".into();
        first.operation_id = "c".into();
        let second = ActionRequest {
            request_id: "a".into(),
            operation_id: "b|c".into(),
            kind: "restart".into(),
            target_node_id: "node-b".into(),
            expected_generation: "0".into(),
            expected_role: "standby".into(),
            expected_admission: "unknown".into(),
            accept_possible_loss: false,
        };
        assert_ne!(
            action_digest(&cluster, &first),
            action_digest(&cluster, &second)
        );
    }
}
