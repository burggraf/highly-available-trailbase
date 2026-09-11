use std::process::Command;

#[test]
fn node_status_command_is_recognized() {
    let output = Command::new(env!("CARGO_BIN_EXE_hat"))
        .args(["node", "status"])
        .output()
        .expect("run hat node status");
    assert!(
        !output.stderr.starts_with(b"usage:"),
        "node lifecycle command was not recognized: {:?}",
        output.stderr
    );
}
