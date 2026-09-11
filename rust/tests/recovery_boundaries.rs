use hat::{
    fence::{FenceCommand, FenceError, FenceRequest},
    journal::{Journal, JournalError},
    restore::{validate_and_restore, RestoreError, RestoreRequest},
};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const CLUSTER: &str = "11111111-1111-4111-8111-111111111111";
const OPERATION: &str = "22222222-2222-4222-8222-222222222222";
const ACTION: &str = "33333333-3333-4333-8333-333333333333";
const INCARNATION: &str = "44444444-4444-4444-8444-444444444444";
const EVIDENCE: &str = "55555555-5555-4555-8555-555555555555";

fn root(label: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("hat-task6-{label}-{suffix}"));
    fs::create_dir(&path).unwrap();
    path
}

fn request() -> RestoreRequest {
    RestoreRequest {
        cluster_id: CLUSTER.into(),
        database: "main".into(),
        history_id: "history-a".into(),
        position: 7,
        schema_digest: "schema-a".into(),
        config_digest: "config-a".into(),
        key_version: "key-a".into(),
        application_marker: "app-ok".into(),
        auth_marker: "auth-ok".into(),
    }
}

fn fixture_payload(application_ok: bool, auth_ok: bool, auth_marker: &str) -> Vec<u8> {
    format!(r#"{{"schema_version":1,"application_ok":{application_ok},"auth_ok":{auth_ok},"application_schema_digest":"schema-a","application_config_digest":"config-a","auth_key_version":"key-a","application_marker":"app-ok","auth_marker":"{auth_marker}"}}"#).into_bytes()
}

fn write_source(root: &Path, payload: &[u8]) {
    fs::write(root.join("payload.bin"), payload).unwrap();
    let hash = sha256(payload);
    fs::write(root.join("manifest.json"), format!(
        r#"{{"schema_version":1,"cluster_id":"{CLUSTER}","database":"main","history_id":"history-a","position":7,"schema_digest":"schema-a","config_digest":"config-a","key_version":"key-a","payload_bytes":{},"payload_sha256":"{}"}}"#,
        payload.len(), hash
    )).unwrap();
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn restore_refuses_missing_wrong_identity_corruption_and_failed_validation() {
    let root = root("restore-refuse");
    let source = root.join("source");
    fs::create_dir(&source).unwrap();
    write_source(&source, &fixture_payload(true, true, "auth-ok"));

    assert!(matches!(
        validate_and_restore(&root.join("missing"), &root.join("out"), &request()),
        Err(RestoreError::MissingSource)
    ));
    let mut wrong = request();
    wrong.history_id = "history-b".into();
    assert!(matches!(
        validate_and_restore(&source, &root.join("wrong"), &wrong),
        Err(RestoreError::HistoryMismatch)
    ));
    for (name, error) in [
        ("position", RestoreError::PositionMismatch),
        ("schema", RestoreError::SchemaMismatch),
        ("config", RestoreError::ConfigMismatch),
        ("key", RestoreError::KeyMismatch),
    ] {
        let mut mismatch = request();
        match name {
            "position" => mismatch.position += 1,
            "schema" => mismatch.schema_digest = "schema-b".into(),
            "config" => mismatch.config_digest = "config-b".into(),
            "key" => mismatch.key_version = "key-b".into(),
            _ => unreachable!(),
        }
        assert_eq!(
            validate_and_restore(&source, &root.join(name), &mismatch),
            Err(error)
        );
    }
    fs::write(source.join("payload.bin"), b"corrupt").unwrap();
    assert!(matches!(
        validate_and_restore(&source, &root.join("corrupt"), &request()),
        Err(RestoreError::Corrupt)
    ));
    write_source(&source, &fixture_payload(true, true, "auth-ok"));
    fs::write(source.join("manifest.json"), b"{\"schema_version\":1").unwrap();
    assert!(matches!(
        validate_and_restore(&source, &root.join("truncated"), &request()),
        Err(RestoreError::Manifest)
    ));
    let duplicate = String::from_utf8(fixture_payload(true, true, "auth-ok"))
        .unwrap()
        .replacen(
            "\"application_ok\":true,",
            "\"application_ok\":true,\"application_ok\":false,",
            1,
        );
    write_source(&source, duplicate.as_bytes());
    assert!(matches!(
        validate_and_restore(&source, &root.join("duplicate"), &request()),
        Err(RestoreError::ApplicationValidation)
    ));
    write_source(&source, &fixture_payload(false, true, "auth-ok"));
    assert!(matches!(
        validate_and_restore(&source, &root.join("application"), &request()),
        Err(RestoreError::ApplicationValidation)
    ));
    write_source(&source, &fixture_payload(true, true, "wrong-auth"));
    assert!(matches!(
        validate_and_restore(&source, &root.join("auth"), &request()),
        Err(RestoreError::AuthValidation)
    ));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn restore_copies_only_after_exact_validation_into_a_fresh_workspace() {
    let root = root("restore-success");
    let source = root.join("source");
    let destination = root.join("destination");
    fs::create_dir(&source).unwrap();
    write_source(&source, &fixture_payload(true, true, "auth-ok"));
    let receipt = validate_and_restore(&source, &destination, &request()).unwrap();
    assert_eq!(receipt.database, "main");
    assert_eq!(receipt.position, 7);
    assert_eq!(
        fs::read(destination.join("payload.bin")).unwrap(),
        fixture_payload(true, true, "auth-ok")
    );
    assert!(validate_and_restore(&source, &destination, &request()).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn restore_refuses_symlinked_source_files() {
    let root = root("restore-symlink");
    let source = root.join("source");
    fs::create_dir(&source).unwrap();
    write_source(&source, &fixture_payload(true, true, "auth-ok"));
    let payload = root.join("payload-real");
    fs::rename(source.join("payload.bin"), &payload).unwrap();
    std::os::unix::fs::symlink(&payload, source.join("payload.bin")).unwrap();
    assert!(matches!(
        validate_and_restore(&source, &root.join("out"), &request()),
        Err(RestoreError::UnsafePath)
    ));
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn fence_refuses_wrong_binding_and_timeout_without_claiming_fence() {
    let root = root("fence");
    let script = root.join("fake-fencer.sh");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '%s' '{}'\n",
            response("other-target", "fenced")
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&script).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    permissions.set_mode(0o700);
    fs::set_permissions(&script, permissions).unwrap();
    let command = FenceCommand::new(&script, "credential-ref", Duration::from_secs(2)).unwrap();
    let request = FenceRequest::new(
        CLUSTER,
        OPERATION,
        ACTION,
        "node-a",
        INCARNATION,
        EVIDENCE,
        "fence",
        2_000,
    )
    .unwrap();
    assert_eq!(command.execute(&request), Err(FenceError::BindingMismatch));
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '%s' '{}'\n",
            response_with_incarnation("node-a", "other-incarnation", "fenced")
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script, permissions).unwrap();
    assert_eq!(command.execute(&request), Err(FenceError::BindingMismatch));
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '%s' '{}'\n",
            response("node-a", "uncertain")
        ),
    )
    .unwrap();
    let mut permissions = fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script, permissions).unwrap();
    assert_eq!(command.execute(&request), Err(FenceError::Uncertain));

    fs::write(&script, "#!/bin/sh\nsleep 1\n").unwrap();
    let mut permissions = fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script, permissions).unwrap();
    let command = FenceCommand::new(&script, "credential-ref", Duration::from_millis(20)).unwrap();
    let started = std::time::Instant::now();
    assert_eq!(command.execute(&request), Err(FenceError::TimedOut));
    assert!(started.elapsed() < Duration::from_millis(500));

    fs::write(&script, "#!/bin/sh\n(sleep 1) &\nexit 0\n").unwrap();
    let mut permissions = fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script, permissions).unwrap();
    let command = FenceCommand::new(&script, "credential-ref", Duration::from_millis(40)).unwrap();
    let started = std::time::Instant::now();
    assert_eq!(command.execute(&request), Err(FenceError::TimedOut));
    assert!(started.elapsed() < Duration::from_millis(500));

    fs::write(&script, "#!/bin/sh\nhead -c 70000 /dev/zero\n").unwrap();
    let mut permissions = fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&script, permissions).unwrap();
    let command = FenceCommand::new(&script, "credential-ref", Duration::from_secs(1)).unwrap();
    assert_eq!(command.execute(&request), Err(FenceError::OutputTooLarge));

    let mut journal = Journal::open(root.join("journal.db"), "fence-test").unwrap();
    journal
        .submit("request-fence", OPERATION, "fence-digest")
        .unwrap();
    assert_eq!(
        command.execute_with_journal(&request, &mut journal),
        Err(FenceError::OutputTooLarge)
    );
    assert_eq!(
        journal.submit("new-request", "new-operation", "new-digest"),
        Err(JournalError::Uncertain)
    );
    assert_eq!(
        journal
            .submit("request-fence", OPERATION, "fence-digest")
            .unwrap()
            .state,
        "blocked_uncertain"
    );
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
fn response(target: &str, state: &str) -> String {
    response_with_incarnation(target, INCARNATION, state)
}

#[cfg(unix)]
fn response_with_incarnation(target: &str, incarnation: &str, state: &str) -> String {
    format!(
        r#"{{"schema_version":1,"cluster_id":"{CLUSTER}","operation_id":"{OPERATION}","action_id":"{ACTION}","target":"{target}","incarnation":"{incarnation}","evidence_nonce":"{EVIDENCE}","state":"{state}","provider_request_id":"provider-1"}}"#
    )
}
