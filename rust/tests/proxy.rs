use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex, MutexGuard, OnceLock},
    thread,
    time::Duration,
};

fn free_addr() -> String {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string()
}

fn bound_listener() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    (listener, address)
}

fn proxy_input(upstream: &str) -> String {
    format!(
        r#"{{"config":{{"schema_version":1,"cluster_id":"11111111-1111-4111-8111-111111111111","primary":"node-a","state_dir":"/var/lib/hat/state","replica_reads":false,"required_databases":["main","session"],"nodes":[{{"id":"node-a","endpoint":"http://{upstream}","data_dir":"/var/lib/hat/node-a"}}]}},"route":{{"schema_version":1,"cluster_id":"11111111-1111-4111-8111-111111111111","generation":"1","primary_node_id":"node-a","writer_epoch":"7","primary_incarnation":"22222222-2222-4222-8222-222222222222","release_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","config_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}},"peer_token":"test-peer-token"}}"#
    )
}

#[allow(clippy::zombie_processes)]
static PROXY_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

struct ProxyHandle {
    child: Child,
    _guard: MutexGuard<'static, ()>,
}

impl ProxyHandle {
    fn kill(&mut self) -> std::io::Result<()> {
        self.child.kill()
    }

    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.child.wait()
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[allow(clippy::zombie_processes)]
fn start_proxy_with_input(input: String) -> (ProxyHandle, String) {
    let guard = PROXY_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let listen = free_addr();
    let mut child = Command::new(env!("CARGO_BIN_EXE_hat"))
        .args(["proxy", "serve", "--listen", &listen])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    for _ in 0..100 {
        if TcpStream::connect(&listen).is_ok() {
            return (
                ProxyHandle {
                    child,
                    _guard: guard,
                },
                listen,
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    panic!("proxy did not listen at {listen}");
}

fn start_proxy(upstream: &str) -> (ProxyHandle, String) {
    start_proxy_with_input(proxy_input(upstream))
}

fn proxy_input_without_route(upstream: &str) -> String {
    let input = proxy_input(upstream);
    let route_start = input.find("\"route\":").unwrap();
    let peer_start = input[route_start..].find(",\"peer_token\"").unwrap() + route_start;
    format!(
        "{}\"route\":null{}",
        &input[..route_start],
        &input[peer_start..]
    )
}

#[test]
fn missing_route_refuses_at_the_proxy_boundary() {
    let (mut proxy, proxy_addr) = start_proxy_with_input(proxy_input_without_route(&free_addr()));
    let mut client = TcpStream::connect(proxy_addr).unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    let _ = proxy.kill();
    let _ = proxy.wait();
    assert!(response.starts_with("HTTP/1.1 503"));
}

#[test]
fn public_requests_with_routing_headers_are_refused() {
    let (mut proxy, proxy_addr) = start_proxy(&free_addr());
    let mut client = TcpStream::connect(proxy_addr).unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: public.example\r\nX-Hat-Route-Generation: 99\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = [0u8; 1024];
    let count = client.read(&mut response).unwrap_or(0);
    let response = String::from_utf8_lossy(&response[..count]);
    let _ = proxy.kill();
    let _ = proxy.wait();
    assert!(response.starts_with("HTTP/1.1 400"));
}

#[test]
fn internal_requests_require_peer_token_and_epoch() {
    let (mut proxy, proxy_addr) = start_proxy(&free_addr());
    let mut client = TcpStream::connect(proxy_addr).unwrap();
    client
        .write_all(b"GET /__hat/internal/api HTTP/1.1\r\nHost: peer\r\nX-Hat-Writer-Epoch: 7\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = [0u8; 1024];
    let count = client.read(&mut response).unwrap_or(0);
    let response = String::from_utf8_lossy(&response[..count]);
    let _ = proxy.kill();
    let _ = proxy.wait();
    assert!(response.starts_with("HTTP/1.1 401"));
}

#[test]
fn authorized_internal_requests_dispatch_without_a_proxy_loop() {
    let (listener, upstream_addr) = bound_listener();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0u8; 512];
        let _ = stream.read(&mut request);
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .unwrap();
    });
    let (mut proxy, proxy_addr) = start_proxy(&upstream_addr);
    let mut client = TcpStream::connect(proxy_addr).unwrap();
    client
        .write_all(b"GET /__hat/internal/api/items?x=1 HTTP/1.1\r\nHost: peer\r\nX-Hat-Peer-Token: test-peer-token\r\nX-Hat-Writer-Epoch: 7\r\nX-Hat-Primary-Node: node-a\r\nX-Hat-Primary-Incarnation: 22222222-2222-4222-8222-222222222222\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = [0u8; 1024];
    let count = client.read(&mut response).unwrap_or(0);
    let response = String::from_utf8_lossy(&response[..count]);
    server.join().unwrap();
    let _ = proxy.kill();
    let _ = proxy.wait();
    assert!(response.starts_with("HTTP/1.1 204"));
}

#[test]
fn proxy_preserves_redirect_error_and_streamed_response_statuses() {
    let (listener, upstream_addr) = bound_listener();
    let server = thread::spawn(move || {
        for response in [
            b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 4\r\nConnection: close\r\n\r\nfail".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\ndata: one\n\n".as_slice(),
        ] {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut request = [0u8; 512];
            let _ = stream.read(&mut request);
            stream.write_all(response).unwrap();
            if response.starts_with(b"HTTP/1.1 200") {
                thread::sleep(Duration::from_millis(25));
                stream.write_all(b"data: two\n\n").unwrap();
            }
        }
    });
    let (mut proxy, proxy_addr) = start_proxy(&upstream_addr);

    let mut redirect = TcpStream::connect(&proxy_addr).unwrap();
    redirect
        .write_all(b"GET /redirect HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut redirect_response = [0u8; 1024];
    let redirect_len = redirect.read(&mut redirect_response).unwrap_or(0);
    let redirect_response = String::from_utf8_lossy(&redirect_response[..redirect_len]);
    assert!(redirect_response.starts_with("HTTP/1.1 302"));
    assert!(redirect_response
        .to_ascii_lowercase()
        .contains("location: /next"));

    let mut error = TcpStream::connect(&proxy_addr).unwrap();
    error
        .write_all(b"GET /error HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut error_response = [0u8; 1024];
    let error_len = error.read(&mut error_response).unwrap_or(0);
    let error_response = String::from_utf8_lossy(&error_response[..error_len]);
    assert!(error_response.starts_with("HTTP/1.1 500"));
    assert!(error_response.ends_with("fail"));

    let mut stream = TcpStream::connect(&proxy_addr).unwrap();
    stream
        .write_all(b"GET /events HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n")
        .unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut stream_response = Vec::new();
    let mut buffer = [0u8; 1024];
    while !stream_response
        .windows(b"data: two\n\n".len())
        .any(|window| window == b"data: two\n\n")
    {
        let count: usize = stream.read(&mut buffer).unwrap_or_default();
        if count == 0 {
            break;
        }
        stream_response.extend_from_slice(&buffer[..count]);
    }
    let stream_response = String::from_utf8(stream_response).unwrap();
    assert!(stream_response.contains("data: one"));
    assert!(stream_response.contains("data: two"));

    server.join().unwrap();
    let _ = proxy.kill();
    let _ = proxy.wait();
}

#[test]
fn upstream_disconnect_is_not_retried() {
    let (listener, upstream_addr) = bound_listener();
    let requests = Arc::new(Mutex::new(0usize));
    let requests_seen = Arc::clone(&requests);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        *requests_seen.lock().unwrap() += 1;
        let mut request = [0u8; 512];
        let _ = stream.read(&mut request);
    });
    let (mut proxy, proxy_addr) = start_proxy(&upstream_addr);
    let mut client = TcpStream::connect(proxy_addr).unwrap();
    client
        .write_all(b"GET /disconnect HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = [0u8; 1024];
    let count = client.read(&mut response).unwrap_or(0);
    let response = String::from_utf8_lossy(&response[..count]);
    server.join().unwrap();
    let _ = proxy.kill();
    let _ = proxy.wait();
    assert!(response.starts_with("HTTP/1.1 502"));
    assert_eq!(*requests.lock().unwrap(), 1);
}

#[test]
fn stale_peer_identity_is_refused() {
    let (mut proxy, proxy_addr) = start_proxy(&free_addr());
    let mut client = TcpStream::connect(proxy_addr).unwrap();
    client
        .write_all(b"GET /__hat/internal/api HTTP/1.1\r\nHost: peer\r\nX-Hat-Peer-Token: test-peer-token\r\nX-Hat-Writer-Epoch: 7\r\nX-Hat-Primary-Node: node-old\r\nX-Hat-Primary-Incarnation: 22222222-2222-4222-8222-222222222222\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = [0u8; 1024];
    let count = client.read(&mut response).unwrap_or(0);
    let response = String::from_utf8_lossy(&response[..count]);
    let _ = proxy.kill();
    let _ = proxy.wait();
    assert!(response.starts_with("HTTP/1.1 401"));
}

#[test]
fn real_binary_forwards_body_headers_and_response_once() {
    let (listener, upstream_addr) = bound_listener();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_by_server = Arc::clone(&seen);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let count = stream.read(&mut buf).unwrap();
            if count == 0 {
                break;
            }
            request.extend_from_slice(&buf[..count]);
            let header_end = request.windows(4).position(|window| window == b"\r\n\r\n");
            let content_length = String::from_utf8_lossy(&request)
                .lines()
                .find_map(|line| {
                    line.strip_prefix("content-length: ")
                        .or_else(|| line.strip_prefix("Content-Length: "))
                })
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            if let Some(header_end) = header_end {
                if request.len() >= header_end + 4 + content_length {
                    break;
                }
            }
        }
        *seen_by_server.lock().unwrap() = request;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: X-Response-Hop\r\nX-Response-Hop: secret\r\nX-Upstream: yes\r\n\r\nhello")
            .unwrap();
    });

    let (mut proxy, proxy_addr) = start_proxy(&upstream_addr);
    let mut client = TcpStream::connect(proxy_addr).unwrap();
    client
        .write_all(
            b"POST /api/items?x=1 HTTP/1.1\r\nHost: public.example\r\nConnection: X-Request-Hop\r\nX-Request-Hop: secret\r\nContent-Length: 7\r\nCookie: sid=abc\r\nAuthorization: Bearer secret\r\nX-Test: preserved\r\n\r\npayload",
        )
        .unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    while !response.ends_with(b"hello") {
        let count = client.read(&mut buf).unwrap();
        assert!(count > 0, "proxy closed before the complete response");
        response.extend_from_slice(&buf[..count]);
    }
    server.join().unwrap();
    let _ = proxy.kill();
    let _ = proxy.wait();

    let request = String::from_utf8(seen.lock().unwrap().clone()).unwrap();
    assert!(request.starts_with("POST /api/items?x=1 HTTP/1.1\r\n"));
    assert!(request.contains("cookie: sid=abc\r\n") || request.contains("Cookie: sid=abc\r\n"));
    assert!(
        request.contains("authorization: Bearer secret\r\n")
            || request.contains("Authorization: Bearer secret\r\n")
    );
    assert!(request.ends_with("\r\n\r\npayload"));
    assert!(!request.contains("X-Request-Hop: secret"));
    let response = String::from_utf8(response).unwrap();
    assert!(response.contains("200 OK"));
    assert!(response.to_ascii_lowercase().contains("x-upstream: yes"));
    assert!(!response
        .to_ascii_lowercase()
        .contains("x-response-hop: secret"));
    assert!(response.ends_with("hello"));
}
