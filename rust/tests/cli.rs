use std::process::{Command, Stdio};

const VALID_CONFIG: &str = r#"{
  "schema_version": 1,
  "cluster_id": "00000000-0000-4000-8000-000000000001",
  "primary": "node-a",
  "controller_node": "node-b",
  "state_dir": "/var/lib/hat/controller",
  "replica_reads": false,
  "required_databases": ["main", "session", "aux"],
  "nodes": [
    {"id": "node-a", "endpoint": "http://node-a.internal:4000", "data_dir": "/var/lib/hat/node-a"},
    {"id": "node-b", "endpoint": "http://node-b.internal:4000", "data_dir": "/var/lib/hat/node-b"}
  ]
}"#;

fn run(args: &[&str], input: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_hat"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start hat");
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(input)
            .expect("write stdin");
    }
    child.wait_with_output().expect("collect hat output")
}

#[test]
fn config_check_accepts_valid_stdin_without_opening_referenced_paths() {
    let output = run(&["config", "check"], VALID_CONFIG.as_bytes());

    assert!(output.status.success());
    assert_eq!(output.stdout, b"configuration valid\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn config_check_refuses_invalid_input_without_echoing_supplied_content() {
    let input = VALID_CONFIG.replace("node-a", "not a valid node SECRET-DO-NOT-ECHO");
    let output = run(&["config", "check"], input.as_bytes());

    assert_eq!(output.status.code(), Some(2));
    let combined = [output.stdout, output.stderr].concat();
    let text = String::from_utf8_lossy(&combined);
    assert!(!text.contains("SECRET-DO-NOT-ECHO"));
}

#[test]
fn doctor_accepts_schema_without_opening_paths_or_endpoints() {
    let output = run(&["doctor"], VALID_CONFIG.as_bytes());

    assert!(output.status.success());
    assert_eq!(output.stdout, b"doctor: configuration valid\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn doctor_refuses_invalid_input_without_echoing_content() {
    let input = VALID_CONFIG.replace("node-a", "not a valid node DO-NOT-ECHO");
    let output = run(&["doctor"], input.as_bytes());

    assert_eq!(output.status.code(), Some(2));
    let combined = [output.stdout, output.stderr].concat();
    assert!(!String::from_utf8_lossy(&combined).contains("DO-NOT-ECHO"));
}

#[test]
fn local_task9_artifacts_are_placeholder_only_and_not_installable() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("rust parent");
    let config = std::fs::read_to_string(root.join("deploy/v1/config.example.json")).unwrap();
    assert!(config.contains(".invalid"));
    assert!(!config.contains("password"));
    for name in ["hat-controller.service", "hat-node.service"] {
        let unit = std::fs::read_to_string(root.join("deploy/v1").join(name)).unwrap();
        assert!(!unit.lines().any(|line| line.trim() == "[Install]"));
        assert!(unit.contains("/usr/bin/false"));
    }
    let runbook = std::fs::read_to_string(root.join("docs/v1-runbook.md")).unwrap();
    assert!(runbook.contains("not authorized"));
}

#[test]
fn unknown_command_and_oversized_input_are_refused_without_echoing_content() {
    let unknown = run(&["config", "unknown"], VALID_CONFIG.as_bytes());
    assert_eq!(unknown.status.code(), Some(2));

    let input = format!("{}{}", VALID_CONFIG, "X".repeat(65 * 1024));
    let oversized = run(&["config", "check"], input.as_bytes());
    assert_eq!(oversized.status.code(), Some(2));
    let combined = [oversized.stdout, oversized.stderr].concat();
    assert!(!String::from_utf8_lossy(&combined).contains(&input));
}
