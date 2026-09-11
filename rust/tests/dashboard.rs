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
    assert!(account.wait().unwrap().success());
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
    assert!(page_response.contains("HAT controller"));
    assert!(page_response.contains("id=\"login\""));
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
    assert!(read_response(&mut operation).starts_with("HTTP/1.1 202"));

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
