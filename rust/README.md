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

## Local proxy slice (Task 3)

The binary also runs a local-only primary proxy:

```sh
printf '%s' '<proxy input envelope>' | cargo run --manifest-path rust/Cargo.toml -- \
  proxy serve --listen 127.0.0.1:18081
```

The envelope contains the already-validated `config`, an inventory-bound `route`, and a bounded test peer token. The route is required; configuration hints do not create authority. Public requests are streamed once to the active route target, preserve application headers/bodies/statuses, remove hop-by-hop headers, and never retry after an upstream failure. `GET`, `POST`, auth, SSE, admin, and unknown paths use the same primary target. `x-hat-*` routing headers from public clients are refused.

`/__hat/internal/<path>` is a separate local test boundary requiring the configured peer token and exact writer epoch; it strips those headers before forwarding and refuses unauthorized requests. This is not production TLS or peer-identity qualification. The proxy has no controller dependency, route persistence, activation, failover, deployment support, or native qualification.

## Local node/lifecycle slice (Task 4)

Task 4 adds process-local node lifecycle state and replication observations. Nodes start with closed admission and a fresh incarnation; activation requires an exact cluster/node/incarnation/writer-epoch grant. Restart closes admission and invalidates the prior grant. Owned fixture children are observed and reaped explicitly. Replication tracks only the declared application databases, prevents follower/uploader ownership overlap, and keeps process liveness, progress, age, errors, and recoverability separate. Unknown observations are not healthy.

`hat node status` reports the inert process-local starting state. This slice does not start TrailBase or Litestream, open configured data paths, use systemd, perform native restore, activate real writers, or claim deployment/process-group qualification.

## Local controller slice (Task 5, accepted locally)

The local controller now has a bundled SQLite journal with `foreign_keys=ON`, `synchronous=FULL`, one-owner locking, durable operation intent, exact duplicate receipts, conflict refusal, unfinished-operation reopen, Argon2id account/session primitives, incarnation-bound restart waiting, and a loopback-only dashboard shell/status boundary. `controller serve` requires explicit `--listen`, `--journal`, and `--origin` arguments. It does not create a default account.

This local slice is accepted against T5-AC1 through T5-AC5. It is not public HTTPS, production TLS, a deployment, a fencing/controller action system, a native restart workflow, or a VPS qualification. No actual VPS or external service has been used.

This is not a controller deployment, failover, or native qualification claim. Python `hat/`, historical deployment files, and private evidence remain untouched.

## Local restore/fence boundary (Task 6, accepted locally)

`restore` validates a bounded local fixture manifest and payload against exact cluster/database/history/position/schema/config/key identities, SHA-256 content, and explicit application/auth fixture checks. It copies only after validation into a fresh workspace, refuses source symlinks and destination reuse, and fsyncs the copied files. It does not open TrailBase/SQLite application databases or claim native restore validation.

`fence` defines a bounded executable adapter contract with exact operation/action/target/incarnation/evidence bindings, protected credential references outside argv/results, bounded JSON input/output, process-group cleanup on every post-spawn failure, and typed refusal for stale, uncertain, malformed, delayed, or lost responses. Unknown results mark a journal operation `blocked_uncertain`, which blocks new mutations until a later reconciliation stage. The default tests use disposable local fake executables only; no provider action, deployment, VPS, or live fencing is performed.

This local slice is accepted against T6-AC1 through T6-AC4. Its application/auth checks are fixture JSON validators, not TrailBase validation; filesystem checks are not a complete descriptor-relative anti-TOCTOU implementation.
