use std::process::Command;

#[test]
fn controller_status_command_is_recognized() {
    let output = Command::new(env!("CARGO_BIN_EXE_hat"))
        .args(["controller", "status"])
        .output()
        .expect("run hat controller status");
    assert!(
        !output.stderr.starts_with(b"usage:"),
        "controller command was not recognized: {:?}",
        output.stderr
    );
}
