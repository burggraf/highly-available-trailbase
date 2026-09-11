# HAT V1 local artifact runbook

## Status and safety boundary

This runbook documents the local Task 9 artifact contract only. The files under `deploy/v1/` are refusal-safe templates, not an installed deployment. **Installation, enablement, service start, native tests, provider fencing, credentials, VPS access, public HTTPS, and disruptive actions are not authorized.** The templates intentionally have no systemd `[Install]` section and use `/usr/bin/false` until a separately approved disposable runtime replaces them.

The existing Python/deployment material is historical evidence. Do not copy its credentials, paths, units, or live commands into this contract.

## Local preflight

Run only from this repository:

```sh
cargo fmt --manifest-path rust/Cargo.toml --check
cargo test --manifest-path rust/Cargo.toml --locked
cargo clippy --manifest-path rust/Cargo.toml --all-targets -- -D warnings
cargo build --manifest-path rust/Cargo.toml --release --locked
cargo run --manifest-path rust/Cargo.toml -- doctor < deploy/v1/config.example.json
```

`hat doctor` reads one bounded configuration document from stdin, validates the same schema as `hat config check`, and prints a fixed result. It does not open `state_dir`, `data_dir`, database files, certificates, endpoints, or secrets; it does not start systemd or a network listener. The example uses `.invalid` hostnames and placeholder paths deliberately.

## Inputs required before any installation decision

A later owner-approved native/deployment stage must freeze all of these before touching a host:

- supported Linux distribution, systemd version, package paths, service users/groups, and filesystem ownership/mode policy;
- real protected controller/node directories and a disposable fixture root, never an existing HAT deployment;
- TLS certificate/key ownership and the exact dashboard/application origins; plaintext fallback is refused;
- private peer identity and an operator-supplied fence/inspect contract with late-effect settlement semantics;
- pinned TrailBase/Litestream binaries and an explicit application/database validation contract;
- rollback, journal backup/recovery, certificate renewal, and operator stop/reconcile procedures.

Do not infer any of these from the example JSON. Static config validation is not reachability, ownership, certificate, database, or fencing proof.

## Refusal boundaries

- Do not create `/etc/hat/v1/ENABLE-LOCAL-DISPOSABLE-FIXTURE` on a real host.
- Do not run `systemctl enable`, `systemctl start`, `systemctl daemon-reload`, or an equivalent installer from this repository.
- Do not replace `/usr/bin/false` in either unit until the runtime and fixture are separately approved and reviewed.
- Do not run `cargo test --ignored`, `rust/tests/native.rs`, a provider adapter, a fence command, or a public listener without the matching approval and disposable fixture.
- A valid config does not authorize a writer, route, restore, promotion, rejoin, or deployment.

The next authorized step is a new, explicitly scoped native/disposable qualification decision. This local artifact slice makes no deployment or production-readiness claim.
