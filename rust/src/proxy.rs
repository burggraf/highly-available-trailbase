use crate::config::Config;
use crate::routing::{RouteTable, SelectedTarget};
use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri},
    Router,
};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use serde::Deserialize;
use std::{net::SocketAddr, sync::Arc};

const INTERNAL_PATH: &str = "/__hat/internal";
const PEER_TOKEN_HEADER: &str = "x-hat-peer-token";
const TARGET_EPOCH_HEADER: &str = "x-hat-writer-epoch";
const PRIMARY_NODE_HEADER: &str = "x-hat-primary-node";
const PRIMARY_INCAR_HEADER: &str = "x-hat-primary-incarnation";
const INTERNAL_DISPATCH_HEADER: &str = "x-hat-internal-dispatch";
const ROUTING_HEADERS: [&str; 6] = [
    PEER_TOKEN_HEADER,
    TARGET_EPOCH_HEADER,
    PRIMARY_NODE_HEADER,
    PRIMARY_INCAR_HEADER,
    "x-hat-route-generation",
    INTERNAL_DISPATCH_HEADER,
];

#[derive(Deserialize)]
struct ProxyInput {
    config: serde_json::Value,
    route: Option<serde_json::Value>,
    peer_token: String,
}

#[derive(Clone)]
pub struct ProxyState {
    client: Client<HttpConnector, Body>,
    route: Arc<RouteTable>,
    peer_token: Arc<str>,
}

pub fn input(input: &str) -> Result<(Config, RouteTable, String), String> {
    if input.len() > crate::config::CONFIG_LIMIT {
        return Err("invalid proxy input".to_string());
    }
    crate::config::reject_duplicate_keys(input).map_err(|_| "invalid proxy input".to_string())?;
    let parsed: ProxyInput = serde_json::from_str(input).map_err(|_| "invalid proxy input")?;
    if parsed.peer_token.is_empty() || parsed.peer_token.len() > 256 {
        return Err("invalid proxy input".to_string());
    }
    let config_text = serde_json::to_string(&parsed.config).map_err(|_| "invalid proxy input")?;
    let config = Config::from_json(&config_text).map_err(|_| "invalid proxy input")?;
    let mut table = RouteTable::new(&config);
    if let Some(route) = parsed.route {
        let route_text = serde_json::to_string(&route).map_err(|_| "invalid proxy input")?;
        let route = crate::routing::Route::from_wire_json(&config, &route_text)
            .map_err(|_| "invalid proxy input")?;
        table.install(route).map_err(|_| "invalid proxy input")?;
    }
    Ok((config, table, parsed.peer_token))
}

pub fn router(route: RouteTable, peer_token: String) -> Router {
    let state = ProxyState {
        client: Client::builder(TokioExecutor::new())
            .retry_canceled_requests(false)
            .build_http(),
        route: Arc::new(route),
        peer_token: Arc::from(peer_token),
    };
    Router::new().fallback(proxy).with_state(state)
}

pub async fn serve(listen: SocketAddr, input: &str) -> Result<(), String> {
    let (_config, route, peer_token) = self::input(input)?;
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|_| "unable to bind proxy")?;
    axum::serve(listener, router(route, peer_token))
        .await
        .map_err(|_| "proxy stopped".to_string())
}

async fn proxy(State(state): State<ProxyState>, request: Request<Body>) -> Response<Body> {
    if request.uri().path() == INTERNAL_PATH || request.uri().path().starts_with("/__hat/internal/")
    {
        return forward_internal(state, request).await;
    }
    if ROUTING_HEADERS
        .iter()
        .any(|name| request.headers().contains_key(*name))
    {
        return refused(StatusCode::BAD_REQUEST, "untrusted routing headers");
    }
    forward(state, request).await
}

async fn forward_internal(state: ProxyState, mut request: Request<Body>) -> Response<Body> {
    let authorized = request
        .headers()
        .get(PEER_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        == Some(state.peer_token.as_ref());
    let epoch = request
        .headers()
        .get(TARGET_EPOCH_HEADER)
        .and_then(|value| value.to_str().ok());
    let expected_epoch = state
        .route
        .active()
        .map(|route| route.writer_epoch().to_string());
    let expected_node = state.route.active().map(|route| route.primary_node_id());
    let expected_incarnation = state
        .route
        .active()
        .map(|route| route.primary_incarnation());
    let node = request
        .headers()
        .get(PRIMARY_NODE_HEADER)
        .and_then(|value| value.to_str().ok());
    let incarnation = request
        .headers()
        .get(PRIMARY_INCAR_HEADER)
        .and_then(|value| value.to_str().ok());
    if !authorized
        || epoch != expected_epoch.as_deref()
        || node != expected_node
        || incarnation != expected_incarnation
    {
        return refused(StatusCode::UNAUTHORIZED, "unauthorized peer");
    }
    request.headers_mut().remove(PEER_TOKEN_HEADER);
    request.headers_mut().remove(TARGET_EPOCH_HEADER);
    request.headers_mut().remove(PRIMARY_NODE_HEADER);
    request.headers_mut().remove(PRIMARY_INCAR_HEADER);
    request.headers_mut().remove("x-hat-route-generation");
    request
        .headers_mut()
        .insert(INTERNAL_DISPATCH_HEADER, HeaderValue::from_static("true"));
    let suffix = request
        .uri()
        .path()
        .strip_prefix(INTERNAL_PATH)
        .unwrap_or("/");
    let suffix = if suffix.is_empty() { "/" } else { suffix };
    let path = match request.uri().query() {
        Some(query) => format!("{suffix}?{query}"),
        None => suffix.to_string(),
    };
    *request.uri_mut() = match path.parse() {
        Ok(uri) => uri,
        Err(_) => return refused(StatusCode::BAD_REQUEST, "invalid internal path"),
    };
    let target = match state.route.select(request.method().as_str(), &path) {
        Ok(target) => target,
        Err(_) => return refused(StatusCode::SERVICE_UNAVAILABLE, "no active route"),
    };
    forward_to(state.client.clone(), request, target).await
}

async fn forward(state: ProxyState, request: Request<Body>) -> Response<Body> {
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let target = match state.route.select(request.method().as_str(), path) {
        Ok(target) => target,
        Err(_) => return refused(StatusCode::SERVICE_UNAVAILABLE, "no active route"),
    };
    forward_to(state.client.clone(), request, target).await
}

async fn forward_to(
    client: Client<HttpConnector, Body>,
    mut request: Request<Body>,
    target: SelectedTarget,
) -> Response<Body> {
    let uri = match format!("{}{}", target.endpoint, request.uri()).parse::<Uri>() {
        Ok(uri) => uri,
        Err(_) => return refused(StatusCode::BAD_GATEWAY, "invalid upstream target"),
    };
    *request.uri_mut() = uri;
    strip_hop_by_hop(request.headers_mut());
    let response = match client.request(request).await {
        Ok(response) => response,
        Err(_) => return refused(StatusCode::BAD_GATEWAY, "upstream unavailable"),
    };
    let (mut parts, body) = response.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    Response::from_parts(parts, Body::new(body))
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let connection_names: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in connection_names {
        headers.remove(name);
    }
    for name in [
        header::CONNECTION,
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
        header::TE,
        header::TRAILER,
        header::TRANSFER_ENCODING,
        header::UPGRADE,
        header::HOST,
        HeaderName::from_static("keep-alive"),
    ] {
        headers.remove(name);
    }
}

fn refused(status: StatusCode, message: &'static str) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::from(message))
        .unwrap_or_else(|_| Response::new(Body::from("request refused")))
}
