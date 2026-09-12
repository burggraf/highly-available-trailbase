use crate::{
    config::reject_duplicate_keys,
    controller::{ActionAdapterError, ActionOutcome},
    node_agent::{NodeActionCommand, NodeBoundaryError, NodeExecutor},
};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::{
    io::{ErrorKind, Read},
    os::unix::{
        fs::{FileTypeExt, MetadataExt},
        net::{UnixListener, UnixStream},
    },
    path::Path,
};

const SCHEMA_VERSION: u8 = 1;
const FRAME_LIMIT: usize = 16 * 1024;
const MIN_TOKEN: usize = 16;
const MAX_TOKEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    Io,
    InvalidToken,
    TooLarge,
    Truncated,
    TrailingBytes,
    InvalidFrame,
    InvalidEnvelope,
    UnsupportedSchema,
    Unauthorized,
    Command(NodeBoundaryError),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEnvelope {
    schema_version: u8,
    peer_token: String,
    command: String,
}

#[derive(Serialize)]
struct EncodedEnvelope<'a> {
    schema_version: u8,
    peer_token: &'a str,
    command: &'a str,
}

pub fn encode_frame(
    peer_token: &str,
    command: &NodeActionCommand,
) -> Result<Vec<u8>, TransportError> {
    if !valid_token(peer_token) {
        return Err(TransportError::InvalidToken);
    }
    let command_wire = command.to_wire_json();
    let command =
        NodeActionCommand::from_wire_json(&command_wire).map_err(TransportError::Command)?;
    let command_wire = command.to_wire_json();
    let envelope = serde_json::to_vec(&EncodedEnvelope {
        schema_version: SCHEMA_VERSION,
        peer_token,
        command: &command_wire,
    })
    .map_err(|_| TransportError::InvalidEnvelope)?;
    if envelope.len() > FRAME_LIMIT {
        return Err(TransportError::TooLarge);
    }
    let length = u32::try_from(envelope.len()).map_err(|_| TransportError::TooLarge)?;
    let mut frame = Vec::with_capacity(4 + envelope.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&envelope);
    Ok(frame)
}

pub fn decode_frame(
    frame: &[u8],
    expected_token: &str,
) -> Result<NodeActionCommand, TransportError> {
    if !valid_token(expected_token) {
        return Err(TransportError::InvalidToken);
    }
    if frame.len() < 4 {
        return Err(TransportError::Truncated);
    }
    let length = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if length > FRAME_LIMIT {
        return Err(TransportError::TooLarge);
    }
    let end = 4usize.checked_add(length).ok_or(TransportError::TooLarge)?;
    if frame.len() < end {
        return Err(TransportError::Truncated);
    }
    if frame.len() > end {
        return Err(TransportError::TrailingBytes);
    }
    let payload = &frame[4..end];
    let text = std::str::from_utf8(payload).map_err(|_| TransportError::InvalidFrame)?;
    reject_duplicate_keys(text).map_err(|_| TransportError::InvalidEnvelope)?;
    let envelope: WireEnvelope =
        serde_json::from_str(text).map_err(|_| TransportError::InvalidEnvelope)?;
    if envelope.schema_version != SCHEMA_VERSION {
        return Err(TransportError::UnsupportedSchema);
    }
    if !valid_token(&envelope.peer_token)
        || !constant_time_equal(&envelope.peer_token, expected_token)
    {
        return Err(TransportError::Unauthorized);
    }
    NodeActionCommand::from_wire_json(&envelope.command).map_err(TransportError::Command)
}

#[cfg(unix)]
pub struct LocalUnixListener {
    listener: UnixListener,
    path: std::path::PathBuf,
    expected_token: String,
    bound_device: u64,
    bound_inode: u64,
    closed: bool,
}

#[cfg(unix)]
impl LocalUnixListener {
    pub fn bind(path: &Path, expected_token: &str) -> Result<Self, TransportError> {
        if !valid_token(expected_token) {
            return Err(TransportError::InvalidToken);
        }
        let parent = path.parent().ok_or(TransportError::Io)?;
        let metadata = std::fs::symlink_metadata(parent).map_err(|_| TransportError::Io)?;
        if !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
            return Err(TransportError::Io);
        }
        let listener = UnixListener::bind(path).map_err(|_| TransportError::Io)?;
        let bound = std::fs::symlink_metadata(path).map_err(|_| TransportError::Io)?;
        if !bound.file_type().is_socket() {
            return Err(TransportError::Io);
        }
        Ok(Self {
            listener,
            path: path.to_path_buf(),
            expected_token: expected_token.to_owned(),
            bound_device: bound.dev(),
            bound_inode: bound.ino(),
            closed: false,
        })
    }

    pub fn receive(&self) -> Result<NodeActionCommand, TransportError> {
        let (mut stream, _) = self.listener.accept().map_err(|_| TransportError::Io)?;
        let frame = read_one_frame(&mut stream)?;
        decode_frame(&frame, &self.expected_token)
    }

    pub fn receive_and_execute(
        &self,
        executor: &dyn NodeExecutor,
    ) -> Result<ActionOutcome, LocalExecutionError> {
        let command = self.receive().map_err(LocalExecutionError::Transport)?;
        executor
            .execute(&command)
            .map_err(LocalExecutionError::Executor)
    }

    pub fn shutdown(mut self) -> Result<(), TransportError> {
        let result = self.cleanup();
        self.closed = true;
        result
    }

    fn cleanup(&self) -> Result<(), TransportError> {
        match std::fs::symlink_metadata(&self.path) {
            Ok(current)
                if current.file_type().is_socket()
                    && current.dev() == self.bound_device
                    && current.ino() == self.bound_inode =>
            {
                std::fs::remove_file(&self.path).map_err(|_| TransportError::Io)
            }
            _ => Err(TransportError::Io),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalExecutionError {
    Transport(TransportError),
    Executor(ActionAdapterError),
}

#[cfg(unix)]
impl Drop for LocalUnixListener {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.cleanup();
        }
    }
}

#[cfg(unix)]
pub fn receive_one(path: &Path, expected_token: &str) -> Result<NodeActionCommand, TransportError> {
    let listener = LocalUnixListener::bind(path, expected_token)?;
    let result = listener.receive();
    let cleanup = listener.shutdown();
    match (result, cleanup) {
        (Ok(command), Ok(())) => Ok(command),
        (Ok(_), Err(_)) | (Err(_), Err(_)) => Err(TransportError::Io),
        (Err(error), Ok(())) => Err(error),
    }
}

#[cfg(unix)]
fn read_one_frame(stream: &mut UnixStream) -> Result<Vec<u8>, TransportError> {
    let mut prefix = [0u8; 4];
    stream.read_exact(&mut prefix).map_err(|error| {
        if error.kind() == ErrorKind::UnexpectedEof {
            TransportError::Truncated
        } else {
            TransportError::Io
        }
    })?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > FRAME_LIMIT {
        return Err(TransportError::TooLarge);
    }
    let mut frame = Vec::with_capacity(4 + length);
    frame.extend_from_slice(&prefix);
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload).map_err(|error| {
        if error.kind() == ErrorKind::UnexpectedEof {
            TransportError::Truncated
        } else {
            TransportError::Io
        }
    })?;
    frame.extend_from_slice(&payload);
    stream
        .set_nonblocking(true)
        .map_err(|_| TransportError::Io)?;
    let mut trailing = [0u8; 1];
    match stream.read(&mut trailing) {
        Ok(0) => Ok(frame),
        Ok(_) => Err(TransportError::TrailingBytes),
        Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(frame),
        Err(_) => Err(TransportError::Io),
    }
}

fn valid_token(value: &str) -> bool {
    (MIN_TOKEN..=MAX_TOKEN).contains(&value.len())
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn constant_time_equal(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let length = left.len().max(right.len());
    let mut difference = u8::from(left.len() != right.len());
    for index in 0..length {
        difference |= left.get(index).copied().unwrap_or_default()
            ^ right.get(index).copied().unwrap_or_default();
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::ActionCommand;
    use crate::node_agent::NodeActionCommand;

    const TOKEN: &str = "peer-token-0123456789";
    const CLUSTER: &str = "00000000-0000-4000-8000-000000000001";
    const INCARNATION: &str = "00000000-0000-4000-8000-000000000002";

    fn command() -> NodeActionCommand {
        let mut command = ActionCommand {
            cluster_id: CLUSTER.into(),
            controller_node_id: "node-controller".into(),
            request_id: "request-1".into(),
            operation_id: "operation-1".into(),
            digest: String::new(),
            kind: "restart".into(),
            target_node_id: "node-a".into(),
            expected_generation: "3".into(),
            expected_role: "standby".into(),
            expected_admission: "closed".into(),
            accept_possible_loss: false,
        };
        command.digest = command.derived_digest();
        NodeActionCommand::from_controller(&command, INCARNATION).unwrap()
    }

    fn raw_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    #[cfg(unix)]
    fn private_socket_path(label: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("hat-task9h-{label}-{suffix}"));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("node.sock");
        (directory, path)
    }

    #[test]
    fn valid_frame_round_trips_and_wrong_token_refuses() {
        let frame = encode_frame(TOKEN, &command()).unwrap();
        assert_eq!(decode_frame(&frame, TOKEN).unwrap(), command());
        assert_eq!(
            decode_frame(&frame, "wrong-token-012345"),
            Err(TransportError::Unauthorized)
        );
    }

    #[test]
    fn framing_refuses_truncation_trailing_bytes_and_oversize() {
        let frame = encode_frame(TOKEN, &command()).unwrap();
        assert_eq!(
            decode_frame(&frame[..frame.len() - 1], TOKEN),
            Err(TransportError::Truncated)
        );
        let mut trailing = frame.clone();
        trailing.push(0);
        assert_eq!(
            decode_frame(&trailing, TOKEN),
            Err(TransportError::TrailingBytes)
        );
        assert_eq!(
            decode_frame(&[0xff; FRAME_LIMIT + 5], TOKEN),
            Err(TransportError::TooLarge)
        );
        assert_eq!(
            encode_frame("short", &command()),
            Err(TransportError::InvalidToken)
        );
    }

    #[test]
    fn envelope_and_nested_command_refusals_are_distinct() {
        let unsupported = raw_frame(
            br#"{"schema_version":2,"peer_token":"peer-token-0123456789","command":"{}"}"#,
        );
        assert_eq!(
            decode_frame(&unsupported, TOKEN),
            Err(TransportError::UnsupportedSchema)
        );
        let unknown = raw_frame(
            br#"{"schema_version":1,"peer_token":"peer-token-0123456789","command":"{}","extra":true}"#,
        );
        assert_eq!(
            decode_frame(&unknown, TOKEN),
            Err(TransportError::InvalidEnvelope)
        );
        let duplicate = raw_frame(
            br#"{"schema_version":1,"peer_token":"peer-token-0123456789","peer_token":"peer-token-0123456789","command":"{}"}"#,
        );
        assert_eq!(
            decode_frame(&duplicate, TOKEN),
            Err(TransportError::InvalidEnvelope)
        );
        let invalid_command = raw_frame(
            br#"{"schema_version":1,"peer_token":"peer-token-0123456789","command":"{}"}"#,
        );
        assert!(matches!(
            decode_frame(&invalid_command, TOKEN),
            Err(TransportError::Command(NodeBoundaryError::InvalidWire))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_transport_dispatches_to_injected_executor_once() {
        use std::{io::Write, os::unix::net::UnixStream, sync::Mutex, thread, time::Duration};

        struct RecordingExecutor {
            calls: Mutex<Vec<NodeActionCommand>>,
        }

        impl NodeExecutor for RecordingExecutor {
            fn execute(
                &self,
                command: &NodeActionCommand,
            ) -> Result<ActionOutcome, ActionAdapterError> {
                self.calls.lock().unwrap().push(command.clone());
                Ok(ActionOutcome::Succeeded)
            }
        }

        let (directory, path) = private_socket_path("exec");
        let listener = LocalUnixListener::bind(&path, TOKEN).unwrap();
        let client_path = path.clone();
        let client = thread::spawn(move || {
            let mut connected = None;
            for _ in 0..100 {
                match UnixStream::connect(&client_path) {
                    Ok(stream) => {
                        connected = Some(stream);
                        break;
                    }
                    Err(_) => thread::sleep(Duration::from_millis(5)),
                }
            }
            let mut stream = connected.expect("listener did not accept connections");
            stream
                .write_all(&encode_frame(TOKEN, &command()).unwrap())
                .unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
        });
        let executor = RecordingExecutor {
            calls: Mutex::new(Vec::new()),
        };
        assert_eq!(
            listener.receive_and_execute(&executor),
            Ok(ActionOutcome::Succeeded)
        );
        client.join().unwrap();
        assert_eq!(executor.calls.lock().unwrap().as_slice(), &[command()]);
        listener.shutdown().unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn transport_refusal_happens_before_executor_invocation() {
        use std::{
            io::Write,
            os::unix::net::UnixStream,
            sync::atomic::{AtomicUsize, Ordering},
            thread,
            time::Duration,
        };

        struct CountingExecutor(AtomicUsize);

        impl NodeExecutor for CountingExecutor {
            fn execute(
                &self,
                _command: &NodeActionCommand,
            ) -> Result<ActionOutcome, ActionAdapterError> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Ok(ActionOutcome::Succeeded)
            }
        }

        let (directory, path) = private_socket_path("auth");
        let listener = LocalUnixListener::bind(&path, TOKEN).unwrap();
        let client_path = path.clone();
        let client = thread::spawn(move || {
            let mut connected = None;
            for _ in 0..100 {
                match UnixStream::connect(&client_path) {
                    Ok(stream) => {
                        connected = Some(stream);
                        break;
                    }
                    Err(_) => thread::sleep(Duration::from_millis(5)),
                }
            }
            let mut stream = connected.expect("listener did not accept connections");
            stream
                .write_all(&encode_frame("wrong-token-012345", &command()).unwrap())
                .unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
        });
        let executor = CountingExecutor(AtomicUsize::new(0));
        assert_eq!(
            listener.receive_and_execute(&executor),
            Err(LocalExecutionError::Transport(TransportError::Unauthorized))
        );
        client.join().unwrap();
        assert_eq!(executor.0.load(Ordering::Relaxed), 0);
        listener.shutdown().unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn executor_uncertainty_is_preserved() {
        use std::{io::Write, os::unix::net::UnixStream, thread, time::Duration};

        struct UncertainExecutor;

        impl NodeExecutor for UncertainExecutor {
            fn execute(
                &self,
                _command: &NodeActionCommand,
            ) -> Result<ActionOutcome, ActionAdapterError> {
                Err(ActionAdapterError::Uncertain)
            }
        }

        let (directory, path) = private_socket_path("uncertain");
        let listener = LocalUnixListener::bind(&path, TOKEN).unwrap();
        let client_path = path.clone();
        let client = thread::spawn(move || {
            let mut connected = None;
            for _ in 0..100 {
                match UnixStream::connect(&client_path) {
                    Ok(stream) => {
                        connected = Some(stream);
                        break;
                    }
                    Err(_) => thread::sleep(Duration::from_millis(5)),
                }
            }
            let mut stream = connected.expect("listener did not accept connections");
            stream
                .write_all(&encode_frame(TOKEN, &command()).unwrap())
                .unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
        });
        assert_eq!(
            listener.receive_and_execute(&UncertainExecutor),
            Err(LocalExecutionError::Executor(ActionAdapterError::Uncertain))
        );
        client.join().unwrap();
        listener.shutdown().unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn persistent_listener_keeps_socket_until_explicit_shutdown() {
        use std::{io::Write, os::unix::net::UnixStream, thread, time::Duration};

        let (directory, path) = private_socket_path("p");
        let listener = LocalUnixListener::bind(&path, TOKEN).unwrap();
        assert!(matches!(
            LocalUnixListener::bind(&path, TOKEN),
            Err(TransportError::Io)
        ));
        let client_path = path.clone();
        let client = thread::spawn(move || {
            for _ in 0..2 {
                let mut connected = None;
                for _ in 0..100 {
                    match UnixStream::connect(&client_path) {
                        Ok(stream) => {
                            connected = Some(stream);
                            break;
                        }
                        Err(_) => thread::sleep(Duration::from_millis(5)),
                    }
                }
                let mut stream = connected.expect("listener did not accept connections");
                stream
                    .write_all(&encode_frame(TOKEN, &command()).unwrap())
                    .unwrap();
                stream.shutdown(std::net::Shutdown::Write).unwrap();
            }
        });
        assert_eq!(listener.receive().unwrap(), command());
        assert_eq!(listener.receive().unwrap(), command());
        assert!(path.exists(), "listener path disappeared before shutdown");
        client.join().unwrap();
        listener.shutdown().unwrap();
        assert!(!path.exists());
        let rebound = LocalUnixListener::bind(&path, TOKEN).unwrap();
        rebound.shutdown().unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn shutdown_refuses_a_replaced_socket_path() {
        let (directory, path) = private_socket_path("replace");
        let listener = LocalUnixListener::bind(&path, TOKEN).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        assert_eq!(listener.shutdown(), Err(TransportError::Io));
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn ephemeral_listener_accepts_one_frame_and_cleans_its_path() {
        use std::{io::Write, os::unix::net::UnixStream, thread, time::Duration};

        let (directory, path) = private_socket_path("valid");
        let server_path = path.clone();
        let server = thread::spawn(move || receive_one(&server_path, TOKEN));
        let mut connected = None;
        for _ in 0..100 {
            match UnixStream::connect(&path) {
                Ok(stream) => {
                    connected = Some(stream);
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(5)),
            }
        }
        let mut stream = connected.expect("ephemeral listener did not bind");
        stream
            .write_all(&encode_frame(TOKEN, &command()).unwrap())
            .unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(server.join().unwrap().unwrap(), command());
        assert!(!path.exists());
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn ephemeral_listener_does_not_wait_for_half_close() {
        use std::{io::Write, os::unix::net::UnixStream, sync::mpsc, thread, time::Duration};

        let (directory, path) = private_socket_path("no-half-close");
        let server_path = path.clone();
        let (sender, receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            sender.send(receive_one(&server_path, TOKEN)).unwrap();
        });
        let mut stream = None;
        for _ in 0..100 {
            match UnixStream::connect(&path) {
                Ok(candidate) => {
                    stream = Some(candidate);
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(5)),
            }
        }
        let mut stream = stream.expect("ephemeral listener did not bind");
        stream
            .write_all(&encode_frame(TOKEN, &command()).unwrap())
            .unwrap();
        let received = receiver.recv_timeout(Duration::from_millis(250));
        drop(stream);
        let _ = server.join();
        assert_eq!(received.unwrap().unwrap(), command());
        assert!(!path.exists());
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn ephemeral_listener_refuses_bad_frames_and_cleans_its_path() {
        use std::{io::Write, os::unix::net::UnixStream, thread, time::Duration};

        let mut trailing = encode_frame(TOKEN, &command()).unwrap();
        trailing.push(0);
        let cases: Vec<(&str, Vec<u8>, Result<NodeActionCommand, TransportError>)> = vec![
            (
                "wrong-token",
                encode_frame("wrong-token-012345", &command()).unwrap(),
                Err(TransportError::Unauthorized),
            ),
            ("truncated", vec![0, 0, 0], Err(TransportError::Truncated)),
            ("trailing", trailing, Err(TransportError::TrailingBytes)),
        ];
        for (label, frame, expected) in cases {
            let (directory, path) = private_socket_path(label);
            let server_path = path.clone();
            let server = thread::spawn(move || receive_one(&server_path, TOKEN));
            let mut stream = None;
            for _ in 0..100 {
                match UnixStream::connect(&path) {
                    Ok(candidate) => {
                        stream = Some(candidate);
                        break;
                    }
                    Err(_) => thread::sleep(Duration::from_millis(5)),
                }
            }
            let mut stream = stream.expect("ephemeral listener did not bind");
            stream.write_all(&frame).unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            assert_eq!(server.join().unwrap(), expected);
            assert!(!path.exists());
            std::fs::remove_dir(directory).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn ephemeral_listener_refuses_shared_parent() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::path::Path::new("/tmp").join(format!("hat-task9h-shared-{suffix}.sock"));
        assert_eq!(receive_one(&path, TOKEN), Err(TransportError::Io));
    }

    #[cfg(unix)]
    #[test]
    fn ephemeral_listener_does_not_remove_preexisting_paths() {
        let (directory, path) = private_socket_path("existing");
        std::fs::write(&path, b"keep").unwrap();
        assert_eq!(receive_one(&path, TOKEN), Err(TransportError::Io));
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unix_socket_pair_carries_one_bounded_frame() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;

        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let frame = encode_frame(TOKEN, &command()).unwrap();
        sender.write_all(&frame).unwrap();
        let mut prefix = [0u8; 4];
        receiver.read_exact(&mut prefix).unwrap();
        let length = u32::from_be_bytes(prefix) as usize;
        let mut payload = vec![0u8; length];
        receiver.read_exact(&mut payload).unwrap();
        let mut received = prefix.to_vec();
        received.extend_from_slice(&payload);
        assert_eq!(decode_frame(&received, TOKEN).unwrap(), command());
    }
}
