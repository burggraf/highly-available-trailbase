# Feature request: read-only TrailBase mode for externally replicated SQLite databases

Would you consider adding a supported **read-only server mode** to TrailBase, allowing it to serve existing Record API reads from SQLite databases maintained by an external replication process?

Our immediate use case is Litestream continuous restore. We are not asking TrailBase to implement replication, leader election, failover, or write forwarding—only a safe read-only application-server mode.

## Use case

We are building a small, operator-managed deployment with:

- One writable TrailBase primary.
- One or more replicas maintained through object storage using `litestream restore -f`.
- A Rust proxy on each node.
- A single controller for monitoring and manually coordinated failover.

Initially, all application requests will be forwarded to the primary, with TrailBase stopped on replica nodes. If TrailBase gains a compatible read-only mode, we would enable a narrow allowlist of read requests against each local replica:

```text
Client → node proxy ── approved reads → local read-only TrailBase
                   └─ everything else → primary TrailBase

Primary SQLite → Litestream → object storage → Litestream restore -f
                                                        ↓
                                               replica SQLite files
```

Writes, authentication endpoints, administration, unknown/custom routes, and realtime subscriptions would continue going to the primary. Reads requiring read-after-write consistency would also use the primary. Replica reads would be explicitly eventually consistent, not linearizable.

The controller would not be in the ordinary request path. Its downtime would prevent administrative transitions, not interrupt forwarding to the existing primary.

## Why proxy-level filtering is insufficient

[Litestream's restore documentation](https://litestream.io/reference/restore/) states that a database maintained with `restore -f` should only be opened read-only by consumers.

Our source inspection of **TrailBase v0.33.11** found behavior that appears incompatible with this requirement:

- Database connections open read/write/create and configure WAL.
- Startup initializes or migrates application and session databases.
- Schema metadata construction can drop and recreate file-deletion triggers.
- Background jobs and runtime features can mutate databases or shared object storage independently of incoming API writes.

For reference, the inspected paths include:

- [`crates/extension/src/lib.rs`](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/extension/src/lib.rs)
- [`crates/core/src/connection.rs`](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/src/connection.rs)
- [`crates/core/src/app_state.rs`](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/src/app_state.rs)
- [`crates/core/src/schema_metadata.rs`](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/src/schema_metadata.rs)
- [`crates/core/src/scheduler.rs`](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/src/scheduler.rs)

These are version-specific source findings, not a claim about every release. Please correct us if an existing supported mode already addresses this.

## Requested behavior

### 1. Open replicated databases genuinely read-only

Apply read-only behavior to `main.db`, `session.db`, and every configured/attached application database used by the server—not just connections in the read pool.

In this mode, TrailBase should:

- Require existing databases with a compatible schema.
- Avoid creating databases, applying migrations, rebuilding triggers, running mutating optimization, or changing journal mode.
- Validate schema compatibility and fail clearly when a migration or other write is required.
- Never temporarily open replicated databases writable to complete initialization.

The intended contract is **no TrailBase-originated mutation of replicated database state**. Normal SQLite read locking and necessary coordination files are a separate matter; we are not requesting that every filesystem operation be prohibited.

### 2. Suppress mutation independently of the proxy

The server should reject unsupported mutating routes itself, even if a request bypasses or is misclassified by the proxy. HTTP method alone is insufficient: for example, the inspected version includes a mutating GET logout endpoint.

Mutating jobs and background work must also be disabled, including session cleanup, file-deletion processing, custom/WASM jobs, and runtime preference writes. Disabling custom routes and jobs entirely would be acceptable for an initial implementation.

Replica startup and reads must not cause uploads, deletions, email delivery, or other application-side external mutations.

### 3. Preserve ordinary read API behavior

The useful initial scope is existing Record API reads, with normal query handling, response formats, and access rules.

If supported, authenticated reads should validate existing credentials using provisioned signing material without creating or refreshing sessions. Unsupported authentication behavior should fail explicitly rather than silently write local state or weaken access checks.

We recognize that permissions and account state on an asynchronous replica can be stale. Our deployment would restrict eligible reads accordingly; this request does not assume immediate revocation consistency.

Replica nodes would receive compatible configuration, keys, migrations and runtime assets through deployment tooling. Missing state should produce an error rather than bootstrap a new identity or database.

### 4. Keep optional writable state separate

Node-local request logs are fine provided they do not mutate the replicated databases. An option to disable database-backed request logging would also be sufficient.

Read-only mode should not persist administrative configuration changes or generate replacement secrets as a side effect of starting the replica.

### 5. Support a database that changes externally

These are live, changing replicas, not immutable snapshots. The mode should use SQLite access compatible with the restore process's locking and update mechanism; `immutable=1` is not appropriate for a changing database.

We would like to qualify:

- Visibility of new data after a completed restore update and a new read transaction.
- Connection-pool behavior and long-running readers during catch-up.
- Behavior when restore pauses, fails or restarts.
- Schema/configuration cache behavior after externally applied schema changes.

Automatic schema-cache refresh is **not required for the first version**. A documented procedure that takes the replica out of service and restarts it after a controlled schema rollout would be acceptable, provided restart itself remains read-only.

We can help test this integration against pinned TrailBase/Litestream versions. We do not expect a read-only flag alone to guarantee compatibility with every external replication tool.

## Explicit non-goals

We are not requesting:

- Built-in replication, consensus, automatic promotion or cluster management.
- Transparent write forwarding by TrailBase.
- Zero data loss or synchronous replication.
- Atomic recovery across independently replicated database files.
- Realtime events generated from physical database replay.
- Exactly-once jobs or external side effects.
- An in-process transition from replica to primary.

For promotion, our tooling would fence the previous primary, stop the replica server and restore process, validate recovered state, then restart TrailBase in normal writable mode. Replication lag, routing eligibility, fencing and failover remain our responsibility.

## Suggested initial acceptance checks

A minimal useful implementation would demonstrate that:

1. A pre-provisioned replica starts and serves approved Record API reads without modifying replicated database state.
2. Missing databases or incompatible schemas cause clear startup failures, not initialization or migration.
3. Mutating requests and background work cannot modify replicated databases or application object storage.
4. Litestream follow can apply new data while reads run, with subsequent reads observing completed updates and without database corruption or persistent lock failure.
5. Restart and controlled schema-rollout behavior are documented and tested.

**Would this fit TrailBase's direction?** We would appreciate guidance on the smallest maintainable upstream implementation, any existing work we should follow, and whether you would welcome a focused PR or reproducible integration test. A CLI flag is one possible interface, but we have no preference about its name or implementation.
