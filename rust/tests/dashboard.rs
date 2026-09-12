use hat::journal::Journal;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn free_addr() -> String {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string()
}

#[allow(clippy::zombie_processes)]
fn start_controller() -> (Child, String, std::path::PathBuf) {
    let address = free_addr();
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let journal = std::env::temp_dir().join(format!("hat-dashboard-{suffix}.db"));
    let origin = format!("http://{address}");
    let mut account = Command::new(env!("CARGO_BIN_EXE_hat"))
        .args([
            "controller",
            "account",
            "add",
            "--journal",
            journal.to_str().unwrap(),
            "--account",
            "operator",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    account
        .stdin
        .take()
        .unwrap()
        .write_all(b"a sufficiently long password\n")
        .unwrap();
    let account_output = account.wait_with_output().unwrap();
    assert!(
        account_output.status.success(),
        "account setup failed: {}",
        String::from_utf8_lossy(&account_output.stderr)
    );
    let child = Command::new(env!("CARGO_BIN_EXE_hat"))
        .args([
            "controller",
            "serve",
            "--listen",
            &address,
            "--journal",
            journal.to_str().unwrap(),
            "--origin",
            &origin,
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if TcpStream::connect(&address).is_ok() {
            return (child, address, journal);
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("controller did not listen");
}

#[test]
fn dashboard_serves_local_status_shell_and_refuses_unauthenticated_status() {
    let (mut child, address, journal) = start_controller();
    let origin = format!("http://{address}");
    let mut page = TcpStream::connect(&address).unwrap();
    page.write_all(
        format!("GET / HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .unwrap();
    let mut page_bytes = [0u8; 4096];
    let page_count = page.read(&mut page_bytes).unwrap_or(0);
    let page_response = String::from_utf8_lossy(&page_bytes[..page_count]);
    assert!(page_response.starts_with("HTTP/1.1 200"));
    assert!(page_response.contains("HAT Control Center"));
    assert!(page_response.contains("id=\"login\""));
    assert!(page_response.contains("/app.css"));
    assert!(page_response.contains("/app.js"));
    assert!(page_response
        .to_ascii_lowercase()
        .contains("content-security-policy"));

    let mut status = TcpStream::connect(&address).unwrap();
    status
        .write_all(
            format!("GET /api/v1/status HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .unwrap();
    let mut status_response = [0u8; 1024];
    let count = status.read(&mut status_response).unwrap_or(0);
    assert!(String::from_utf8_lossy(&status_response[..count]).starts_with("HTTP/1.1 401"));

    let mut login = TcpStream::connect(&address).unwrap();
    let login_body = br#"{"account":"operator","password":"a sufficiently long password"}"#;
    write_request(&mut login, &format!("POST /api/v1/login HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", login_body.len()), login_body);
    let login_response = read_response(&mut login);
    assert!(login_response.starts_with("HTTP/1.1 200"));
    let cookie = login_response
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("set-cookie:"))
        .unwrap()
        .trim()
        .to_owned();
    let cookie = cookie
        .strip_prefix("Set-Cookie: ")
        .or_else(|| cookie.strip_prefix("set-cookie: "))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let csrf = login_response
        .split("\"csrf_token\":\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();

    let mut authenticated = TcpStream::connect(&address).unwrap();
    authenticated.write_all(format!("GET /api/v1/status HTTP/1.1\r\nHost: {address}\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
    assert!(read_response(&mut authenticated).starts_with("HTTP/1.1 200"));

    let mut operation = TcpStream::connect(&address).unwrap();
    let operation_body =
        br#"{"request_id":"request-1","operation_id":"operation-1","digest":"digest-1"}"#;
    write_request(&mut operation, &format!("POST /api/v1/operations HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nCookie: {cookie}\r\nX-CSRF-Token: {csrf}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", operation_body.len()), operation_body);
    let operation_response = read_response(&mut operation);
    assert!(operation_response.starts_with("HTTP/1.1 503"));
    assert!(operation_response.contains("controller authority is configured elsewhere"));

    let _ = child.kill();
    let _ = child.wait();
    let mut recovery = Command::new(env!("CARGO_BIN_EXE_hat"))
        .args([
            "controller",
            "account",
            "add",
            "--journal",
            journal.to_str().unwrap(),
            "--account",
            "recovered",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    recovery
        .stdin
        .take()
        .unwrap()
        .write_all(b"another sufficiently long password\n")
        .unwrap();
    assert!(recovery.wait().unwrap().success());
    let _ = std::fs::remove_file(journal);
}

#[test]
fn dashboard_shows_cluster_overview_and_refuses_unavailable_native_actions() {
    let (mut child, address, journal) = start_controller_with_config();
    let origin = format!("http://{address}");

    let mut page = TcpStream::connect(&address).unwrap();
    page.write_all(
        format!("GET / HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .unwrap();
    let page_response = read_response(&mut page);
    assert!(page_response.starts_with("HTTP/1.1 200"));
    for text in [
        "Cluster overview",
        "Fail over",
        "Restart node",
        "Rejoin node",
    ] {
        assert!(page_response.contains(text), "missing {text}");
    }

    let mut login = TcpStream::connect(&address).unwrap();
    let login_body = br#"{"account":"operator","password":"a sufficiently long password"}"#;
    write_request(&mut login, &format!("POST /api/v1/login HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", login_body.len()), login_body);
    let login_response = read_response(&mut login);
    assert!(login_response.starts_with("HTTP/1.1 200"));
    let cookie = login_response
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
    let csrf = login_response
        .split("\"csrf_token\":\"")
        .nth(1)
        .unwrap()
        .split('\"')
        .next()
        .unwrap()
        .to_owned();

    let mut status = TcpStream::connect(&address).unwrap();
    status
        .write_all(
            format!("GET /api/v1/status HTTP/1.1\r\nHost: {address}\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .unwrap();
    let status_response = read_response(&mut status);
    assert!(status_response.starts_with("HTTP/1.1 200"));
    assert!(status_response.contains("\"nodes\""));
    assert!(status_response.contains("\"controller_node_id\":\"node-a\""));
    assert!(status_response.contains("\"authority\":\"node-a\""));
    assert!(status_response.contains("\"node-a\""));
    assert!(status_response.contains("\"unknown\""));
    assert!(status_response.contains("\"enabled\":false"));

    let mut operation = TcpStream::connect(&address).unwrap();
    let operation_body =
        br#"{"request_id":"request-1","operation_id":"operation-1","digest":"digest-1"}"#;
    write_request(&mut operation, &format!("POST /api/v1/operations HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nCookie: {cookie}\r\nX-CSRF-Token: {csrf}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", operation_body.len()), operation_body);
    assert!(read_response(&mut operation).starts_with("HTTP/1.1 202"));

    let mut duplicate = TcpStream::connect(&address).unwrap();
    write_request(&mut duplicate, &format!("POST /api/v1/operations HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nCookie: {cookie}\r\nX-CSRF-Token: {csrf}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", operation_body.len()), operation_body);
    let duplicate_response = read_response(&mut duplicate);
    assert!(duplicate_response.starts_with("HTTP/1.1 202"));
    assert!(duplicate_response.contains("operation-1"));

    let mut unknown_action = TcpStream::connect(&address).unwrap();
    let unknown_body = br#"{"request_id":"unknown-request","operation_id":"unknown-operation","kind":"restart","target_node_id":"node-z","expected_generation":"0","expected_role":"standby","expected_admission":"unknown","accept_possible_loss":false}"#;
    write_request(&mut unknown_action, &format!("POST /api/v1/actions HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nCookie: {cookie}\r\nX-CSRF-Token: {csrf}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", unknown_body.len()), unknown_body);
    let unknown_response = read_response(&mut unknown_action);
    assert!(unknown_response.starts_with("HTTP/1.1 400"));
    assert!(unknown_response.contains("unknown target node"));

    let mut missing_identity = TcpStream::connect(&address).unwrap();
    let missing_identity_body = br#"{"kind":"restart","target_node_id":"node-b","expected_generation":"0","expected_role":"standby","expected_admission":"unknown","accept_possible_loss":false}"#;
    write_request(&mut missing_identity, &format!("POST /api/v1/actions HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nCookie: {cookie}\r\nX-CSRF-Token: {csrf}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", missing_identity_body.len()), missing_identity_body);
    assert!(read_response(&mut missing_identity).starts_with("HTTP/1.1 400"));

    let mut stale_action = TcpStream::connect(&address).unwrap();
    let stale_body = br#"{"request_id":"stale-request","operation_id":"stale-operation","kind":"restart","target_node_id":"node-b","expected_generation":"1","expected_role":"standby","expected_admission":"unknown","accept_possible_loss":false}"#;
    write_request(&mut stale_action, &format!("POST /api/v1/actions HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nCookie: {cookie}\r\nX-CSRF-Token: {csrf}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", stale_body.len()), stale_body);
    let stale_response = read_response(&mut stale_action);
    assert!(stale_response.starts_with("HTTP/1.1 409"));
    assert!(stale_response.contains("stale route generation"));

    let mut action = TcpStream::connect(&address).unwrap();
    let action_body = br#"{"request_id":"action-request","operation_id":"action-operation","kind":"restart","target_node_id":"node-b","expected_generation":"0","expected_role":"standby","expected_admission":"unknown","accept_possible_loss":false}"#;
    write_request(&mut action, &format!("POST /api/v1/actions HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nCookie: {cookie}\r\nX-CSRF-Token: {csrf}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", action_body.len()), action_body);
    let action_response = read_response(&mut action);
    assert!(action_response.starts_with("HTTP/1.1 503"));
    assert!(action_response.contains("native action adapter unavailable"));

    let _ = child.kill();
    let _ = child.wait();
    let verify = Journal::open(&journal, "verify").unwrap();
    assert!(verify.receipt("action-request").unwrap().is_none());
    let _ = std::fs::remove_file(journal);
}

#[test]
fn configured_non_authority_refuses_durable_operations() {
    let (mut child, address, journal) = start_controller_with_config_as("node-b");
    let origin = format!("http://{address}");

    let mut login = TcpStream::connect(&address).unwrap();
    let login_body = br#"{"account":"operator","password":"a sufficiently long password"}"#;
    write_request(&mut login, &format!("POST /api/v1/login HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", login_body.len()), login_body);
    let login_response = read_response(&mut login);
    assert!(login_response.starts_with("HTTP/1.1 200"));
    let cookie = login_response
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
    let csrf = login_response
        .split("\"csrf_token\":\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();

    let mut operation = TcpStream::connect(&address).unwrap();
    let operation_body =
        br#"{"request_id":"read-only-request","operation_id":"read-only-operation","digest":"digest"}"#;
    write_request(&mut operation, &format!("POST /api/v1/operations HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nCookie: {cookie}\r\nX-CSRF-Token: {csrf}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", operation_body.len()), operation_body);
    let response = read_response(&mut operation);
    assert!(response.starts_with("HTTP/1.1 503"));
    assert!(response.contains("controller authority is configured elsewhere"));

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(journal);
}

fn start_controller_with_config() -> (Child, String, std::path::PathBuf) {
    start_controller_with_config_as("node-a")
}

fn start_controller_with_config_as(local_node_id: &str) -> (Child, String, std::path::PathBuf) {
    let address = free_addr();
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let journal = std::env::temp_dir().join(format!("hat-dashboard-cluster-{suffix}.db"));
    let config = std::env::temp_dir().join(format!("hat-dashboard-cluster-{suffix}.json"));
    std::fs::write(
        &config,
        r#"{
            "schema_version": 1,
            "cluster_id": "00000000-0000-4000-8000-000000000001",
            "primary": "node-a",
            "controller_node": "node-a",
            "state_dir": "/var/lib/hat/controller",
            "replica_reads": false,
            "required_databases": ["main", "session", "aux"],
            "nodes": [
                {"id": "node-a", "endpoint": "http://node-a.internal:4000", "data_dir": "/var/lib/hat/node-a"},
                {"id": "node-b", "endpoint": "http://node-b.internal:4000", "data_dir": "/var/lib/hat/node-b"}
            ]
        }"#,
    )
    .unwrap();
    let origin = format!("http://{address}");
    let mut account = Command::new(env!("CARGO_BIN_EXE_hat"))
        .args([
            "controller",
            "account",
            "add",
            "--journal",
            journal.to_str().unwrap(),
            "--account",
            "operator",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    account
        .stdin
        .take()
        .unwrap()
        .write_all(b"a sufficiently long password\n")
        .unwrap();
    let account_output = account.wait_with_output().unwrap();
    assert!(
        account_output.status.success(),
        "account setup failed: {}",
        String::from_utf8_lossy(&account_output.stderr)
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_hat"))
        .args([
            "controller",
            "serve",
            "--listen",
            &address,
            "--journal",
            journal.to_str().unwrap(),
            "--origin",
            &origin,
            "--config",
            config.to_str().unwrap(),
            "--node-id",
            local_node_id,
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if TcpStream::connect(&address).is_ok() {
            let _ = std::fs::remove_file(config);
            return (child, address, journal);
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("cluster controller did not listen");
}

fn write_request(stream: &mut TcpStream, headers: &str, body: &[u8]) {
    stream.write_all(headers.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
}

fn read_response(stream: &mut TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut bytes = [0u8; 8192];
    let count = stream.read(&mut bytes).unwrap_or(0);
    String::from_utf8_lossy(&bytes[..count]).into_owned()
}
