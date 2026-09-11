use crate::{
    auth::{AuthError, AuthStore},
    config::CONFIG_LIMIT,
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

#[derive(Clone)]
pub struct DashboardState {
    controller: Arc<Mutex<Controller>>,
    origin: Arc<str>,
    csrf: Arc<str>,
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

#[derive(Serialize)]
struct LoginResponse {
    csrf_token: String,
}

#[derive(Serialize)]
struct StatusResponse {
    controller: &'static str,
    unfinished_operations: usize,
}

pub fn dashboard(controller: Controller, origin: &str) -> Result<Router, JournalError> {
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
    };
    Ok(Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/api/v1/login", post(login))
        .route("/api/v1/logout", post(logout))
        .route("/api/v1/status", get(status))
        .route("/api/v1/operations", post(operation))
        .with_state(state))
}

pub async fn serve_dashboard(
    listen: SocketAddr,
    controller: Controller,
    origin: &str,
) -> Result<(), String> {
    if !listen.ip().is_loopback() || !valid_local_origin(origin) {
        return Err("controller listener must be loopback with a local origin".to_string());
    }
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|_| "unable to bind controller")?;
    axum::serve(
        listener,
        dashboard(controller, origin).map_err(|_| "invalid controller")?,
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
        .header("content-security-policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        .header("x-content-type-options", "nosniff")
        .body(Body::from("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>HAT controller</title><script src=\"/app.js\" defer></script></head><body><main><h1>HAT controller</h1><p>Local controller dashboard.</p><form id=\"login\"><label for=\"account\">Account</label><input id=\"account\" name=\"account\" autocomplete=\"username\" required><label for=\"password\">Password</label><input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\" required><button type=\"submit\">Sign in</button></form><button type=\"button\" id=\"refresh-status\">Refresh status</button><button type=\"button\" id=\"logout\">Sign out</button><p id=\"status\" role=\"status\">Status requires sign-in.</p><form id=\"operation\"><label for=\"request-id\">Request ID</label><input id=\"request-id\" required><label for=\"operation-id\">Operation ID</label><input id=\"operation-id\" required><label for=\"digest\">Digest</label><input id=\"digest\" required><button type=\"submit\">Submit operation</button></form></main></body></html>"))
        .unwrap()
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
const status = (text) => { $('status').textContent = text; };
$('login').addEventListener('submit', async (event) => {
  event.preventDefault();
  const response = await fetch('/api/v1/login', { method: 'POST', headers: {'Content-Type': 'application/json', 'Origin': location.origin}, body: JSON.stringify({account: $('account').value, password: $('password').value}) });
  if (!response.ok) return status('Sign-in refused');
  csrf = (await response.json()).csrf_token;
  status('Signed in');
});
$('refresh-status').addEventListener('click', async () => {
  const response = await fetch('/api/v1/status');
  status(response.ok ? JSON.stringify(await response.json()) : 'Status unavailable');
});
$('operation').addEventListener('submit', async (event) => {
  event.preventDefault();
  const response = await fetch('/api/v1/operations', { method: 'POST', headers: {'Content-Type': 'application/json', 'Origin': location.origin, 'X-CSRF-Token': csrf}, body: JSON.stringify({request_id: $('request-id').value, operation_id: $('operation-id').value, digest: $('digest').value}) });
  status(response.ok ? 'Operation accepted' : 'Operation refused');
});
$('logout').addEventListener('click', async () => {
  await fetch('/api/v1/logout', { method: 'POST', headers: {'Origin': location.origin, 'X-CSRF-Token': csrf} });
  csrf = '';
  status('Signed out');
});
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
    })
    .into_response()
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
}
