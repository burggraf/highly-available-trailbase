# HAT Rust V1 — Task 2 partial

One Cargo package for the current [single-controller V1 plan](../docs/plans/2026-09-11-v1-manual-failover.md#execution-state-and-acceptance). Follow [AGENTS.md](../AGENTS.md) for development and acceptance.

## What actually works

From the repository root:

```sh
cargo build --manifest-path rust/Cargo.toml --locked
cargo test --manifest-path rust/Cargo.toml --locked
cargo test --manifest-path rust/Cargo.toml --locked routing
```

The built executable is `rust/target/debug/hat`. It currently runs an **empty `main()`**, produces no output, and does not validate input. There is no usable configuration-check CLI, forwarding proxy, listener, controller, writer activation, or failover command.

Unit code parses bounded JSON configuration and exercises primary-only selection plus missing-route, rollback, equal-generation conflict, and duplicate-install handling. Previous verification reported 14 unit tests (six routing); this is not Task 2 acceptance or native qualification.

## Draft schema, not a supported installation format

Current configuration fields: `schema_version`, `cluster_id`, `primary`, `state_dir`, `replica_reads`, `required_databases`, and `nodes` containing `id`, `endpoint`, `data_dir`. It requires version 1, false replica reads, and main/session inventory. These fields are not live writer authority.

Remaining Task 2 work includes finalizing bounded identity/endpoint/path rules, distinguishing lexical path checks from filesystem privacy checks, excluding local logs from replicated inventory, and validating route wire records. Current routes are public Rust structs with caller-supplied endpoints and numeric generations; they do not yet implement the contract's strict JSON/decimal-string route boundary. Do not use this draft against an installation or supply private credentials.

See the active plan for criterion status, retained failures, and the exact next step. No Python state migration is supported.
