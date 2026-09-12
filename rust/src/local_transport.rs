use crate::{
    config::reject_duplicate_keys,
    node_agent::{NodeActionCommand, NodeBoundaryError},
};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::{io::Read, os::unix::net::UnixListener, path::Path};

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
pub fn receive_one(path: &Path, expected_token: &str) -> Result<NodeActionCommand, TransportError> {
    if !valid_token(expected_token) {
        return Err(TransportError::InvalidToken);
    }
    let listener = UnixListener::bind(path).map_err(|_| TransportError::Io)?;
    let result = (|| {
        let (mut stream, _) = listener.accept().map_err(|_| TransportError::Io)?;
        let mut frame = Vec::with_capacity(4);
        let mut buffer = [0u8; 1024];
        loop {
            let count = stream.read(&mut buffer).map_err(|_| TransportError::Io)?;
            if count == 0 {
                break;
            }
            if frame.len().saturating_add(count) > FRAME_LIMIT + 4 {
                return Err(TransportError::TooLarge);
            }
            frame.extend_from_slice(&buffer[..count]);
        }
        decode_frame(&frame, expected_token)
    })();
    let cleanup = std::fs::remove_file(path);
    match (result, cleanup) {
        (Err(error), _) => Err(error),
        (Ok(command), Ok(())) => Ok(command),
        (Ok(_), Err(_)) => Err(TransportError::Io),
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
    fn ephemeral_listener_accepts_one_frame_and_cleans_its_path() {
        use std::{
            io::Write,
            os::unix::net::UnixStream,
            thread,
            time::{Duration, SystemTime, UNIX_EPOCH},
        };

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("hat-task9h-{suffix}.sock"));
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
    }

    #[cfg(unix)]
    #[test]
    fn ephemeral_listener_does_not_remove_preexisting_paths() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("hat-task9h-existing-{suffix}.sock"));
        std::fs::write(&path, b"keep").unwrap();
        assert_eq!(receive_one(&path, TOKEN), Err(TransportError::Io));
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");
        std::fs::remove_file(path).unwrap();
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
