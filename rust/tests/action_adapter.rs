use hat::controller::{
    dashboard_with_cluster_and_adapter, ActionAdapter, ActionAdapterError, ActionCommand,
    ActionOutcome, ClusterView, Controller, NodeView,
};
use std::{
    collections::VecDeque,
    io::{Read, Write},
    net::TcpStream,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

struct FakeAdapter {
    calls: Mutex<Vec<ActionCommand>>,
    outcomes: Mutex<VecDeque<Result<ActionOutcome, ActionAdapterError>>>,
}

impl FakeAdapter {
    fn new(outcomes: impl IntoIterator<Item = Result<ActionOutcome, ActionAdapterError>>) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            outcomes: Mutex::new(outcomes.into_iter().collect()),
        }
    }
}

impl ActionAdapter for FakeAdapter {
    fn available(&self) -> bool {
        true
    }

    fn execute(&self, command: &ActionCommand) -> Result<ActionOutcome, ActionAdapterError> {
        self.calls.lock().unwrap().push(command.clone());
        self.outcomes
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(ActionOutcome::Succeeded))
    }
}

fn temp_path() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("hat-action-adapter-{suffix}.db"))
}

fn cluster() -> ClusterView {
    ClusterView {
        cluster_id: "cluster-a".into(),
        controller_node_id: "node-a".into(),
        primary_node_id: "node-a".into(),
        route_generation: None,
        writer_epoch: None,
        nodes: vec![
            NodeView {
                id: "node-a".into(),
                endpoint: "http://node-a".into(),
                role: "primary",
                health: "unknown",
                admission: "unknown",
                replication: "unknown",
                detail: "test",
            },
            NodeView {
                id: "node-b".into(),
                endpoint: "http://node-b".into(),
                role: "standby",
                health: "unknown",
                admission: "unknown",
                replication: "unknown",
                detail: "test",
            },
        ],
    }
}

fn response(address: &str, request: String) -> String {
    let mut stream = TcpStream::connect(address).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).unwrap();
    String::from_utf8(bytes).unwrap()
}

fn login(address: &str, origin: &str) -> (String, String) {
    let body = r#"{"account":"operator","password":"a sufficiently long password"}"#;
    let login = response(
        address,
        format!(
            "POST /api/v1/login HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    );
    assert!(login.starts_with("HTTP/1.1 200"), "{login}");
    let cookie = login
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("set-cookie:"))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .split_once(':')
        .unwrap()
        .1
        .trim()
        .to_owned();
    let csrf = login
        .split("\"csrf_token\":\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    (cookie, csrf)
}

fn action(address: &str, origin: &str, cookie: &str, csrf: &str, body: &str) -> String {
    response(
        address,
        format!(
            "POST /api/v1/actions HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nCookie: {cookie}\r\nX-CSRF-Token: {csrf}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn action_adapter_binds_identity_replays_once_and_blocks_uncertainty() {
    let path = temp_path();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let origin = format!("http://{address}");
    let mut controller = Controller::open(&path, "node-a").unwrap();
    controller
        .create_account("operator", "a sufficiently long password")
        .unwrap();
    let adapter = Arc::new(FakeAdapter::new([
        Ok(ActionOutcome::Succeeded),
        Ok(ActionOutcome::FailedSafe),
        Ok(ActionOutcome::Uncertain),
    ]));
    let router = dashboard_with_cluster_and_adapter(
        controller,
        &origin,
        cluster(),
        Some("node-a"),
        adapter.clone(),
    )
    .unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    let (cookie, csrf) = login(&address, &origin);
    let first_body = r#"{"request_id":"request-1","operation_id":"operation-1","kind":"restart","target_node_id":"node-b","expected_generation":"0","expected_role":"standby","expected_admission":"unknown","accept_possible_loss":false}"#;
    let first = action(&address, &origin, &cookie, &csrf, first_body);
    assert!(first.starts_with("HTTP/1.1 202"), "{first}");
    assert!(first.contains("\"state\":\"succeeded\""), "{first}");

    let replay = action(&address, &origin, &cookie, &csrf, first_body);
    assert!(replay.starts_with("HTTP/1.1 202"), "{replay}");
    assert!(replay.contains("\"state\":\"succeeded\""), "{replay}");
    assert_eq!(adapter.calls.lock().unwrap().len(), 1);
    let command = adapter.calls.lock().unwrap().first().unwrap().clone();
    assert_eq!(command.cluster_id, "cluster-a");
    assert_eq!(command.controller_node_id, "node-a");
    assert_eq!(command.target_node_id, "node-b");
    assert_eq!(command.expected_role, "standby");
    assert_eq!(command.digest.len(), 64);

    let conflict_body = r#"{"request_id":"request-1","operation_id":"operation-1","kind":"shutdown","target_node_id":"node-b","expected_generation":"0","expected_role":"standby","expected_admission":"unknown","accept_possible_loss":false}"#;
    let conflict = action(&address, &origin, &cookie, &csrf, conflict_body);
    assert!(conflict.starts_with("HTTP/1.1 409"), "{conflict}");
    assert_eq!(adapter.calls.lock().unwrap().len(), 1);

    let failed_body = r#"{"request_id":"request-2","operation_id":"operation-2","kind":"restart","target_node_id":"node-b","expected_generation":"0","expected_role":"standby","expected_admission":"unknown","accept_possible_loss":false}"#;
    let failed = action(&address, &origin, &cookie, &csrf, failed_body);
    assert!(failed.starts_with("HTTP/1.1 202"), "{failed}");
    assert!(failed.contains("\"state\":\"failed_safe\""), "{failed}");
    assert_eq!(adapter.calls.lock().unwrap().len(), 2);

    let uncertain_body = r#"{"request_id":"request-3","operation_id":"operation-3","kind":"restart","target_node_id":"node-b","expected_generation":"0","expected_role":"standby","expected_admission":"unknown","accept_possible_loss":false}"#;
    let uncertain = action(&address, &origin, &cookie, &csrf, uncertain_body);
    assert!(uncertain.starts_with("HTTP/1.1 409"), "{uncertain}");
    assert!(uncertain.contains("blocked_uncertain"), "{uncertain}");
    assert_eq!(adapter.calls.lock().unwrap().len(), 3);

    let blocked_body = r#"{"request_id":"request-4","operation_id":"operation-4","kind":"restart","target_node_id":"node-b","expected_generation":"0","expected_role":"standby","expected_admission":"unknown","accept_possible_loss":false}"#;
    let blocked = action(&address, &origin, &cookie, &csrf, blocked_body);
    assert!(blocked.starts_with("HTTP/1.1 409"), "{blocked}");
    assert!(
        blocked.contains("operation blocked by uncertainty"),
        "{blocked}"
    );
    assert_eq!(adapter.calls.lock().unwrap().len(), 3);

    server.abort();
    let _ = server.await;
    drop(adapter);
    let _ = std::fs::remove_file(path);
}
