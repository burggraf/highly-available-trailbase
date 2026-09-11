# HAT Rust V1 — Task 2

This package implements the inert Task 2 slice from the [single-controller V1 plan](../docs/plans/2026-09-11-v1-manual-failover.md#execution-state-and-acceptance): bounded configuration validation and in-memory primary-only route selection. It does not listen, connect, start a writer, persist routes, activate nodes, fail over, or inspect referenced files.

## Configuration checker

```sh
printf '%s\n' '<JSON configuration>' | cargo run --manifest-path rust/Cargo.toml -- config check
```

`hat config check` reads one UTF-8 JSON document from stdin, capped at 64 KiB. Success prints `configuration valid` and exits 0. Invalid UTF-8, oversized input, invalid configuration, missing input, and every other command/argument exit 2 with a fixed refusal message; supplied configuration content is not printed. The checker never opens `state_dir`, `data_dir`, database paths, endpoints, or secrets.

The exact version-1 configuration object is:

- `schema_version`: number `1`.
- `cluster_id`: lowercase canonical UUID string.
- `primary`: a node ID from `nodes`.
- `state_dir`: absolute lexical path under `/var/lib/hat` with no `.` or `..` component. This is a supported-location rule, not proof of ownership, mode, or symlink safety.
- `replica_reads`: exactly `false`; local replica reads are refused in V1.
- `required_databases`: one to 64 unique names, including `main` and `session`; `logs` is reserved for local controller logs and is refused.
- `nodes`: one to 64 entries with unique IDs, endpoints, and data directories. IDs are lowercase ASCII names up to 32 characters. Endpoints are explicit `http`/`https` host-and-port URLs without credentials, paths, queries, fragments, or invalid ports. Data directories use the same lexical `/var/lib/hat` rule.

Unknown fields, duplicate JSON keys (including nested objects), invalid identities/endpoints/paths, duplicate inventory, missing required databases, and oversized strings/document input are refused. Filesystem ownership, permissions, symlink state, database existence/schema, and endpoint reachability are installation/lifecycle checks deferred to later tasks.

## Route records

Routes are version-1 JSON records capped at 8 KiB with exactly these fields:

```json
{
  "schema_version": 1,
  "cluster_id": "...",
  "generation": "1",
  "primary_node_id": "node-a",
  "writer_epoch": "1",
  "primary_incarnation": "...",
  "release_digest": "<64 lowercase hex characters>",
  "config_digest": "<64 lowercase hex characters>"
}
```

Generations and writer epochs are canonical decimal strings compared numerically, including `u64::MAX`. UUIDs and lowercase SHA-256-shaped digests are validated. Route endpoints are never accepted from the wire: they are resolved from the validated static inventory. A configuration `primary` hint creates no authority by itself. `RouteTable` refuses missing routes, rollback, conflicting equal generations, wrong clusters, and inventory mismatches; an exact duplicate is idempotent. Every method/path selects the active primary, including auth, logout, SSE, admin, and unknown/custom requests.

## Local checks

```sh
cargo fmt --manifest-path rust/Cargo.toml --check
cargo test --manifest-path rust/Cargo.toml --locked
cargo clippy --manifest-path rust/Cargo.toml --all-targets -- -D warnings
cargo build --manifest-path rust/Cargo.toml --release --locked
git diff --check
```

This is not a proxy, controller, deployment, failover, or native qualification claim. Python `hat/`, historical deployment files, and private evidence remain untouched.
