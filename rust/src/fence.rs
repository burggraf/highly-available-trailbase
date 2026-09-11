use crate::{config::is_uuid, journal::Journal};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

const MAX_INPUT: usize = 16 * 1024;
const MAX_OUTPUT: usize = 64 * 1024;
const MAX_TEXT: usize = 128;
const MAX_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FenceRequest {
    pub schema_version: u8,
    pub cluster_id: String,
    pub operation_id: String,
    pub action_id: String,
    pub target: String,
    pub expected_incarnation: String,
    pub evidence_nonce: String,
    pub kind: String,
    pub deadline_ms: u64,
}

impl FenceRequest {
    pub fn new(
        cluster_id: &str,
        operation_id: &str,
        action_id: &str,
        target: &str,
        expected_incarnation: &str,
        evidence_nonce: &str,
        kind: &str,
        deadline_ms: u64,
    ) -> Result<Self, FenceError> {
        let request = Self {
            schema_version: 1,
            cluster_id: cluster_id.to_owned(),
            operation_id: operation_id.to_owned(),
            action_id: action_id.to_owned(),
            target: target.to_owned(),
            expected_incarnation: expected_incarnation.to_owned(),
            evidence_nonce: evidence_nonce.to_owned(),
            kind: kind.to_owned(),
            deadline_ms,
        };
        validate_request(&request)?;
        Ok(request)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FenceResult {
    pub schema_version: u8,
    pub cluster_id: String,
    pub operation_id: String,
    pub action_id: String,
    pub target: String,
    pub incarnation: String,
    pub evidence_nonce: String,
    pub state: String,
    pub provider_request_id: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FenceError {
    InvalidInput,
    InvalidExecutable,
    Spawn,
    ProcessIo,
    TimedOut,
    OutputTooLarge,
    Exited,
    InvalidResponse,
    BindingMismatch,
    Uncertain,
    Journal,
}

pub struct FenceCommand {
    executable: PathBuf,
    credential_ref: String,
    timeout: Duration,
}

impl FenceCommand {
    pub fn new(
        path: impl AsRef<Path>,
        credential_ref: &str,
        timeout: Duration,
    ) -> Result<Self, FenceError> {
        let executable = path.as_ref().to_owned();
        if !safe_executable(&executable)
            || credential_ref.is_empty()
            || credential_ref.len() > MAX_TEXT
            || !credential_ref.bytes().all(|byte| byte.is_ascii_graphic())
            || timeout.is_zero()
            || timeout > MAX_TIMEOUT
        {
            return Err(FenceError::InvalidInput);
        }
        Ok(Self {
            executable,
            credential_ref: credential_ref.to_owned(),
            timeout,
        })
    }

    pub fn execute_with_journal(
        &self,
        request: &FenceRequest,
        journal: &mut Journal,
    ) -> Result<FenceResult, FenceError> {
        validate_request(request)?;
        let result = self.execute(request);
        if result
            .as_ref()
            .is_err_and(|error| !matches!(error, FenceError::InvalidInput | FenceError::Spawn))
        {
            journal
                .block_uncertain(&request.operation_id)
                .map_err(|_| FenceError::Journal)?;
        }
        result
    }

    pub fn execute(&self, request: &FenceRequest) -> Result<FenceResult, FenceError> {
        validate_request(request)?;
        let input = serde_json::to_vec(request).map_err(|_| FenceError::InvalidInput)?;
        if input.len() > MAX_INPUT {
            return Err(FenceError::InvalidInput);
        }
        let mut command = Command::new(&self.executable);
        command
            .env("HAT_FENCE_CREDENTIAL_REF", &self.credential_ref)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(unix)]
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().map_err(|_| FenceError::Spawn)?;
        let Some(mut stdin) = child.stdin.take() else {
            stop_process_group(&mut child);
            return Err(FenceError::ProcessIo);
        };
        let writer = thread::spawn(move || stdin.write_all(&input));
        let Some(mut stdout) = child.stdout.take() else {
            stop_process_group(&mut child);
            return Err(FenceError::ProcessIo);
        };
        let (output_sender, output_receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut output = Vec::new();
            let mut chunk = [0u8; 4096];
            let result = loop {
                let count = match stdout.read(&mut chunk) {
                    Ok(count) => count,
                    Err(_) => break Err(FenceError::ProcessIo),
                };
                if count == 0 {
                    break Ok(output);
                }
                output.extend_from_slice(&chunk[..count]);
                if output.len() > MAX_OUTPUT {
                    break Err(FenceError::OutputTooLarge);
                }
            };
            let _ = output_sender.send(result);
        });

        let deadline =
            Instant::now() + self.timeout.min(Duration::from_millis(request.deadline_ms));
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() >= deadline => {
                    stop_process_group(&mut child);
                    return Err(FenceError::TimedOut);
                }
                Ok(None) => thread::sleep(Duration::from_millis(2)),
                Err(_) => {
                    stop_process_group(&mut child);
                    return Err(FenceError::ProcessIo);
                }
            }
        };
        drop(writer);
        let remaining = deadline.saturating_duration_since(Instant::now());
        let output = match output_receiver.recv_timeout(remaining) {
            Ok(Ok(output)) => output,
            Ok(Err(error)) => {
                stop_process_group(&mut child);
                return Err(error);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                stop_process_group(&mut child);
                return Err(FenceError::TimedOut);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                stop_process_group(&mut child);
                return Err(FenceError::ProcessIo);
            }
        };
        stop_process_group(&mut child);
        if !status.success() {
            return Err(FenceError::Exited);
        }
        let result: FenceResult =
            serde_json::from_slice(&output).map_err(|_| FenceError::InvalidResponse)?;
        validate_result(request, &result)?;
        Ok(result)
    }
}

fn validate_request(request: &FenceRequest) -> Result<(), FenceError> {
    if request.schema_version != 1
        || !is_uuid(&request.cluster_id)
        || !is_uuid(&request.operation_id)
        || !is_uuid(&request.action_id)
        || !is_uuid(&request.expected_incarnation)
        || !is_uuid(&request.evidence_nonce)
        || !valid_text(&request.target)
        || !matches!(request.kind.as_str(), "fence" | "inspect")
        || !(1..=10_000).contains(&request.deadline_ms)
    {
        return Err(FenceError::InvalidInput);
    }
    Ok(())
}

fn validate_result(request: &FenceRequest, result: &FenceResult) -> Result<(), FenceError> {
    if result.schema_version != 1
        || result.cluster_id != request.cluster_id
        || result.operation_id != request.operation_id
        || result.action_id != request.action_id
        || result.target != request.target
        || result.incarnation != request.expected_incarnation
        || result.evidence_nonce != request.evidence_nonce
        || !valid_text(&result.provider_request_id)
    {
        return Err(FenceError::BindingMismatch);
    }
    let expected_state = if request.kind == "fence" {
        "fenced"
    } else {
        "inspected"
    };
    if result.state != expected_state {
        return Err(FenceError::Uncertain);
    }
    Ok(())
}

fn stop_process_group(child: &mut std::process::Child) {
    kill_process_group(child);
    let _ = child.wait();
}

fn kill_process_group(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        // SAFETY: the child created its own process group immediately before exec.
        let killed = unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) } == 0;
        if !killed {
            let _ = child.kill();
        }
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
}

fn safe_executable(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_rejects_non_absolute_executables() {
        assert!(matches!(
            FenceCommand::new("fake", "credential", Duration::from_secs(1)),
            Err(FenceError::InvalidInput)
        ));
    }
}
