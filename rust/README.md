# HAT Rust V1 — local Tasks 2–9 subset

This package implements the accepted local slices from the [single-controller V1 plan](../docs/plans/2026-09-11-v1-manual-failover.md#execution-state-and-acceptance): bounded configuration validation, primary-only routing/proxying, fixture node/controller state, restore/fence boundaries, planned switchover, manual failover/reconciliation/reseed, refusal-safe Task 9 artifacts, the accepted local Task 9D action-adapter contract, the accepted local Task 9E node boundary contract, the accepted local Task 9F forwarding boundary, the accepted local Task 9G transport contract, the accepted local Task 9H ephemeral listener, the accepted local Task 9I persistent listener lifecycle, the accepted local Task 9J transport-to-injected-executor boundary, and the accepted local Task 9K response contract. It does not perform native TrailBase/Litestream work, provider fencing, installation, deployment, public traffic, or live qualification.

## Configuration checker

```sh
printf '%s\n' '<JSON configuration>' | cargo run --manifest-path rust/Cargo.toml -- config check
```

`hat config check` reads one UTF-8 JSON document from stdin, capped at 64 KiB. Success prints `configuration valid` and exits 0. Invalid UTF-8, oversized input, invalid configuration, missing input, and every other command/argument exit 2 with a fixed refusal message; supplied configuration content is not printed. The checker never opens `state_dir`, `data_dir`, database paths, endpoints, or secrets.

`hat doctor` uses the same bounded, pure schema check and prints `doctor: configuration valid` on success. It is a read-only preflight diagnostic, not a reachability check or permission to start a service.

The exact version-1 configuration object is:

- `schema_version`: number `1`.
- `cluster_id`: lowercase canonical UUID string.
- `primary`: a node ID from `nodes`.
- `controller_node`: the one configured node allowed to accept dashboard mutations; it must be a node ID from `nodes`.
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

## Local controller slice (Tasks 5, 9C, and 9D, accepted locally)

The local controller has a bundled SQLite journal with `foreign_keys=ON`, `synchronous=FULL`, one-owner locking, durable operation intent, exact duplicate receipts, conflict refusal, unfinished-operation reopen, Argon2id account/session primitives, and incarnation-bound restart waiting. Serve the dashboard with an explicit configuration and local identity:

```sh
hat controller serve --listen 127.0.0.1:18083 \
  --journal /var/lib/hat/controller.sqlite \
  --origin http://localhost:18083 \
  --config /etc/hat/config.json \
  --node-id fm3
```

`controller_node` in the validated config, not a `--read-only` toggle, determines which configured node is the mutation authority. A node with another identity serves authenticated read-only status; missing/unknown observations remain `unknown`, and action controls are disabled. Login, CSRF, Origin/Host, target identity, exact route-generation, role/admission confirmation, and possible-loss checks are bounded at the API. The native node-action adapter is intentionally absent: failover, restart, shutdown, and rejoin requests are refused with a clear reason and never simulated. Durable operation submissions replay the same receipt and non-authority dashboards refuse them.

This local slice is accepted against T5-AC1 through T5-AC5 and T9C-AC1 through T9C-AC5. Task 9D adds `ActionCommand`, bounded adapter outcomes, server-derived action digests, exact replay/conflict handling, and injected fake-adapter tests; the default server still uses an unavailable adapter and refuses before journal insertion. It is not public HTTPS, production TLS, remote forwarding, a deployment, a fencing/controller action system, a native restart workflow, or a VPS qualification. No real node action is claimed.

## Local node boundary (Task 9E, accepted locally)

Task 9E defines bounded version-1 JSON envelopes for a future controller-to-node action and a node observation. Duplicate keys, unknown fields, oversized input, unsupported schema, malformed identities, invalid digests/generations, unknown route generation, stale generation, and role/admission mismatches refuse. `NodeObservation::from_node` validates local state before constructing an observation. The command digest is derived from the same controller-authoritative fields used by Task 9D.

This is a library boundary only. It opens no listener, uses no transport, starts/stops no process, accesses no TrailBase/Litestream state, restores no data, fences no provider, publishes no route, and performs no remote or disruptive action. See `../docs/plans/2026-09-11-task9e-node-boundary-design.md`.

## Local forwarding boundary (Task 9F, accepted locally)

Task 9F provides `InMemoryNodeAdapter`, which converts a controller action into a `NodeActionCommand`, validates the selected observation, and calls only an injected executor. Unknown, stale, or mismatched observations refuse before invocation. The normal controller still uses an unavailable adapter; no transport or native executor is installed.

## Local authenticated transport (Task 9G through Task 9K accepted locally)

Task 9G frames the validated node command with a bounded length prefix and strict versioned JSON envelope. A printable per-channel token is checked with bounded constant-time comparison; wrong tokens, malformed frames, duplicate/unknown fields, oversized input, and invalid nested commands refuse. Task 9H exercises one temporary Unix listener request in a private mode-0700 parent, reads one declared-length frame without requiring peer half-close, and removes only the verified bound path. Task 9I wraps this in a library/test-only persistent local bind/receive/shutdown/rebind lifecycle. Task 9J connects valid transport only to a supplied injected executor, preserving refusal and uncertainty. Task 9K adds strict bounded outcome/refusal response frames; no production listener, TLS/mTLS, or remote/native action is configured.

## Local restore/fence boundary (Task 6, accepted locally)

`restore` validates a bounded local fixture manifest and payload against exact cluster/database/history/position/schema/config/key identities, SHA-256 content, and explicit application/auth fixture checks. It copies only after validation into a fresh workspace, refuses source symlinks and destination reuse, and fsyncs the copied files. It does not open TrailBase/SQLite application databases or claim native restore validation.

`fence` defines a bounded executable adapter contract with exact operation/action/target/incarnation/evidence bindings, protected credential references outside argv/results, bounded JSON input/output, process-group cleanup on every post-spawn failure, and typed refusal for stale, uncertain, malformed, delayed, or lost responses. Unknown results mark a journal operation `blocked_uncertain`, which blocks new mutations until a later reconciliation stage. The default tests use disposable local fake executables only; no provider action, deployment, VPS, or live fencing is performed.

This local slice is accepted against T6-AC1 through T6-AC4. Its application/auth checks are fixture JSON validators, not TrailBase validation; filesystem checks are not a complete descriptor-relative anti-TOCTOU implementation.

## Local planned switchover path (Task 7, accepted locally)

`PlannedSwitchover` exercises one in-memory/SQLite fixture handover: it closes old admission, stops the old mutator/uploader and candidate follower children, requires exact settled fence evidence, quarantines the old node, validates/restores a fresh candidate workspace, promotes and activates the candidate, then publishes one higher-generation route. Exact journal replay returns its retained receipt; uncertain restore, fence, and effect-boundary responses mark `blocked_uncertain` and refuse new mutations. Quarantine rejects stale exact activation grants, including after route-publication uncertainty.

The operation tests use disposable `sh` children and fixture JSON only. Route state is in-memory, fence evidence is supplied by the test boundary, and no real provider, TrailBase/Litestream process, deployment, VPS, public listener, distributed route rollout, failover, or rejoin is exercised.

## Local failover, reconciliation, and rejoin path (Task 8, accepted locally)

`ManualFailover` requires explicit possible-loss acceptance and settled fence identity, retaining `LossBound::Unknown` rather than inventing a loss estimate. It reuses the restore/activation/route path, durably binds the failover policy, refuses active/uncertain replay, and supports same-operation inspect/reconcile after journal and node-state reconstruction. Exact fence, candidate, route, quarantine, and child-containment observations are required before a blocked operation can complete; repeated reconciliation is idempotent.

`reseed_rejoin` validates a quarantined former primary, restores into a fresh directory, preserves the original source/history, and returns a closed standby. Both the former primary and the new standby refuse writable activation. This remains fixture-only; native/provider settlement, deployment, VPS, public HTTPS, live failover, and disruptive qualification are not claimed.

## Local Task 9 artifact/contract subset

`deploy/v1/config.example.json` uses `.invalid` endpoints and placeholder paths. The two `deploy/v1/*.service` files are contract-only refusal templates: they have no systemd `[Install]` section, require an explicit disposable-fixture marker, and execute `/usr/bin/false`. `docs/v1-runbook.md` records the local doctor/gate commands and the unresolved Linux, ownership, TLS, fencing, binary, and fixture inputs.

No service unit was installed/enabled/started, and no native test was run. A later, separately authorized bounded VPS probe used fresh remote TrailBase/Litestream roots and the checked-out Rust proxy through SSH tunnels; it did not use these refusal templates or qualify the Rust controller/node operation boundary. Evidence and limitations are in `docs/reports/v1-task9b-e2e.txt`. Replacing the refusal command or creating `rust/tests/native.rs` still requires an installable native runtime contract and separately reviewed fixture.
