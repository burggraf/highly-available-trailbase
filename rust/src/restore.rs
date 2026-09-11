use crate::config::{is_uuid, reject_duplicate_keys};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub const MAX_RESTORE_BYTES: usize = 16 * 1024 * 1024;
const MAX_TEXT: usize = 128;
const MAX_MANIFEST_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreRequest {
    pub cluster_id: String,
    pub database: String,
    pub history_id: String,
    pub position: u64,
    pub schema_digest: String,
    pub config_digest: String,
    pub key_version: String,
    pub application_marker: String,
    pub auth_marker: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReceipt {
    pub database: String,
    pub history_id: String,
    pub position: u64,
    pub bytes: usize,
    pub destination: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RestoreError {
    InvalidInput,
    MissingSource,
    UnsafePath,
    Manifest,
    HistoryMismatch,
    PositionMismatch,
    SchemaMismatch,
    ConfigMismatch,
    KeyMismatch,
    Corrupt,
    ApplicationValidation,
    AuthValidation,
    DestinationExists,
    Io,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureValidation {
    schema_version: u8,
    application_ok: bool,
    auth_ok: bool,
    application_schema_digest: String,
    application_config_digest: String,
    auth_key_version: String,
    application_marker: String,
    auth_marker: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreManifest {
    schema_version: u8,
    cluster_id: String,
    database: String,
    history_id: String,
    position: u64,
    schema_digest: String,
    config_digest: String,
    key_version: String,
    payload_bytes: usize,
    payload_sha256: String,
}

pub fn validate_and_restore(
    source: &Path,
    destination: &Path,
    request: &RestoreRequest,
) -> Result<RestoreReceipt, RestoreError> {
    validate_request(request)?;
    if !safe_directory(source) {
        return Err(RestoreError::MissingSource);
    }
    if destination.exists() {
        return Err(RestoreError::DestinationExists);
    }
    if !destination.is_absolute() || !safe_parent(destination) {
        return Err(RestoreError::UnsafePath);
    }
    let source_root = fs::canonicalize(source).map_err(|_| RestoreError::MissingSource)?;
    let destination_parent =
        fs::canonicalize(destination.parent().ok_or(RestoreError::UnsafePath)?)
            .map_err(|_| RestoreError::UnsafePath)?;
    if destination_parent.starts_with(&source_root) {
        return Err(RestoreError::UnsafePath);
    }

    let manifest_path = source.join("manifest.json");
    let payload_path = source.join("payload.bin");
    if !safe_file(&manifest_path) || !safe_file(&payload_path) {
        return Err(RestoreError::UnsafePath);
    }
    let manifest_bytes =
        read_bounded(&manifest_path, MAX_MANIFEST_BYTES).ok_or(RestoreError::Manifest)?;
    let manifest_text = std::str::from_utf8(&manifest_bytes).map_err(|_| RestoreError::Manifest)?;
    reject_duplicate_keys(manifest_text).map_err(|_| RestoreError::Manifest)?;
    let manifest: RestoreManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|_| RestoreError::Manifest)?;
    validate_manifest(&manifest, request)?;

    let payload = read_bounded(&payload_path, MAX_RESTORE_BYTES).ok_or(RestoreError::Corrupt)?;
    if payload.len() != manifest.payload_bytes || sha256(&payload) != manifest.payload_sha256 {
        return Err(RestoreError::Corrupt);
    }
    validate_fixture(&payload, request)?;

    fs::create_dir(destination).map_err(|_| RestoreError::Io)?;
    let result = write_destination(destination, &manifest_bytes, &payload);
    if result.is_err() {
        let _ = fs::remove_dir_all(destination);
        return Err(result.unwrap_err());
    }
    Ok(RestoreReceipt {
        database: manifest.database,
        history_id: manifest.history_id,
        position: manifest.position,
        bytes: payload.len(),
        destination: destination.to_owned(),
    })
}

fn validate_request(request: &RestoreRequest) -> Result<(), RestoreError> {
    if !is_uuid(&request.cluster_id)
        || !valid_text(&request.database)
        || !valid_text(&request.history_id)
        || !valid_text(&request.schema_digest)
        || !valid_text(&request.config_digest)
        || !valid_text(&request.key_version)
        || !valid_text(&request.application_marker)
        || !valid_text(&request.auth_marker)
    {
        return Err(RestoreError::InvalidInput);
    }
    Ok(())
}

fn validate_manifest(
    manifest: &RestoreManifest,
    request: &RestoreRequest,
) -> Result<(), RestoreError> {
    if manifest.schema_version != 1
        || manifest.cluster_id != request.cluster_id
        || manifest.database != request.database
        || !valid_text(&manifest.history_id)
        || !valid_text(&manifest.schema_digest)
        || !valid_text(&manifest.config_digest)
        || !valid_text(&manifest.key_version)
        || manifest.payload_bytes > MAX_RESTORE_BYTES
        || !valid_sha256(&manifest.payload_sha256)
    {
        return Err(RestoreError::Manifest);
    }
    if manifest.history_id != request.history_id {
        return Err(RestoreError::HistoryMismatch);
    }
    if manifest.position != request.position {
        return Err(RestoreError::PositionMismatch);
    }
    if manifest.schema_digest != request.schema_digest {
        return Err(RestoreError::SchemaMismatch);
    }
    if manifest.config_digest != request.config_digest {
        return Err(RestoreError::ConfigMismatch);
    }
    if manifest.key_version != request.key_version {
        return Err(RestoreError::KeyMismatch);
    }
    Ok(())
}

fn write_destination(
    destination: &Path,
    manifest: &[u8],
    payload: &[u8],
) -> Result<(), RestoreError> {
    let mut manifest_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination.join("manifest.json"))
        .map_err(|_| RestoreError::Io)?;
    manifest_file
        .write_all(manifest)
        .map_err(|_| RestoreError::Io)?;
    manifest_file.sync_all().map_err(|_| RestoreError::Io)?;
    let mut payload_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination.join("payload.bin"))
        .map_err(|_| RestoreError::Io)?;
    payload_file
        .write_all(payload)
        .map_err(|_| RestoreError::Io)?;
    payload_file.sync_all().map_err(|_| RestoreError::Io)?;
    File::open(destination)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| RestoreError::Io)
}

fn read_bounded(path: &Path, limit: usize) -> Option<Vec<u8>> {
    let mut file = open_input(path).ok()?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() <= limit).then_some(bytes)
}

#[cfg(unix)]
fn open_input(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_input(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

fn safe_directory(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
        .unwrap_or(false)
}

fn safe_file(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        .unwrap_or(false)
}

fn safe_parent(path: &Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    let Ok(metadata) = fs::symlink_metadata(parent) else {
        return false;
    };
    !metadata.file_type().is_symlink()
        && metadata.is_dir()
        && fs::canonicalize(parent).is_ok_and(|canonical| canonical.is_dir())
}

fn validate_fixture(payload: &[u8], request: &RestoreRequest) -> Result<(), RestoreError> {
    let text = std::str::from_utf8(payload).map_err(|_| RestoreError::ApplicationValidation)?;
    reject_duplicate_keys(text).map_err(|_| RestoreError::ApplicationValidation)?;
    let fixture: FixtureValidation =
        serde_json::from_slice(payload).map_err(|_| RestoreError::ApplicationValidation)?;
    if fixture.schema_version != 1
        || !fixture.application_ok
        || fixture.application_schema_digest != request.schema_digest
        || fixture.application_config_digest != request.config_digest
        || fixture.application_marker != request.application_marker
    {
        return Err(RestoreError::ApplicationValidation);
    }
    if !fixture.auth_ok
        || fixture.auth_key_version != request.key_version
        || fixture.auth_marker != request.auth_marker
    {
        return Err(RestoreError::AuthValidation);
    }
    Ok(())
}

fn valid_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn sha256(payload: &[u8]) -> String {
    Sha256::digest(payload)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uppercase_hashes_are_not_accepted() {
        assert!(!valid_sha256(&"A".repeat(64)));
    }
}
