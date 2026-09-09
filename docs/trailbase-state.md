# TrailBase state and application behavior

Baseline: [TrailBase v0.33.11](https://github.com/trailbaseio/trailbase/tree/v0.33.11). Findings below are from source inspection, not a running HA experiment. Source links are pinned to that tag.

## 1. Database inventory and ownership

The CLI selects the depot with `--depot`; default is `./traildepot/`. Actual paths come from [`data_dir.rs`](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/src/data_dir.rs#L15-L67).

| State | Exact path under depot | Proposed HAT ownership / recovery |
| --- | --- | --- |
| Main application/users | `data/main.db` | Required; primary writes; continuously restore on standbys |
| Sessions/auth codes/OTP | `data/session.db` (**singular**) | Required by default; primary writes; replicate separately; define cross-DB/auth recovery policy |
| HTTP logs | `data/logs.db` | Node-local writable; do not follow primary logs into it; optional separate node/generation backup |
| Attached application DB | `data/<name>.db` | Explicit inventory and per-DB prefix; required unless declared rebuildable with a tested recovery procedure |
| Potential queue state | `data/queue.db` | Accessor exists, no caller found in baseline; do not assume active queue support; detect future usage during qualification |

[`Config.databases` and `record_apis[].attached_databases`](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/proto/config.proto#L268-L275) define configured/attached names. [`connection.rs`](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/src/connection.rs#L513-L534) initializes/migrates an attached database before attaching it. Do not infer the entire mutable DB inventory from only active Record APIs.

The [built-in backup enumeration](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/src/backup.rs#L24-L52) includes main/logs/session plus databases referenced by Record API attachments, not necessarily every configured DB. HAT needs its own strict declared inventory and startup/runtime drift checks. Dynamically added/untracked DBs must block HA readiness until enrolled.

Do not live-copy `-wal`/`-shm` from another host alongside restored DBs. These are SQLite operational files, not independent replication streams. Preserve them with the old node's forensic directory and use the qualified restore/journal-transition path.

## 2. Read-only standby is currently a blocker

**An unmodified v0.33.11 executable is not a true read-only replica server.** Sending only reads does not meet Litestream follow's read-only-consumer requirement.

Evidence:

- [`ServerArgs`](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/cli/src/args.rs#L112-L163) has no general read-only mode.
- [`connect_sqlite`](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/extension/src/lib.rs#L28-L77) opens read/write/create, forces WAL, sets `synchronous=NORMAL`, and runs startup optimize. The connection manager has a similar [open path](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/src/connection.rs#L586-L603).
- The [executor](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/sqlite/src/sqlite/executor.rs#L68-L117) keeps a writer handle. Reader-pool `query_only` does not turn the server into a read-only process.
- [`AppState::init`](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/src/app_state.rs#L92-L131) opens/migrates logs, sessions and main before serving.
- The [migration runner](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/refinery/src/traits/async.rs#L155-L177) issues schema-history DDL even with no pending user migration.
- [Schema metadata construction](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/src/schema_metadata.rs#L147-L243) drops/recreates file-deletion triggers for file columns.

Therefore neither “disable cron,” “read-only API ACL,” nor “put a proxy in front” fixes startup or connection-level behavior. `--demo` is not a read-only mode. Making replica files writable to let initialization succeed is not a supported workaround for continuous follow.

**Decision gate:** explicitly test the proposed service-hot/read-replica mode before committing to it. The test must run the actual pinned TrailBase binary against continuously restored `main.db`, `session.db`, and every enrolled attached database, while exercising startup, ordinary reads, auth reads, schema/config loading, long-lived readers, background jobs, log writes, follower catch-up, restart, and restore interruption. Trace filesystem and SQLite writes, WAL/SHM changes, locks, restore errors, and logical divergence. A passing test must demonstrate that TrailBase never mutates follower business databases and does not disrupt Litestream follow. If the pinned binary or an approved upstream/patch-based mode cannot satisfy this, abandon service-hot/read-replica capability for this project and retain data-hot stopped-application standbys.

**Baseline proposal:** keep TrailBase stopped on data-hot standbys. To achieve service-hot/read replicas, seek an upstream mode that:

1. Opens main/session/attached DBs truly read-only and validates existence/schema without creating, migrating, optimizing, or converting journal mode.
2. Separates writable node logs and their WAL/SHM from followed business state.
3. Disables mutating routes, all relevant system/custom jobs, config writes, and runtime DB side effects.
4. Handles schema/ACL/runtime cache refresh without executing DDL.
5. Uses read access compatible with Litestream's locks, change visibility and failure behavior; no `immutable=1` shortcut.

An upstream release containing those capabilities would preserve the “latest executable” objective. A private patch/fork or snapshot-swapping read service is a separate design decision, not silently part of HAT.

The primary's `synchronous=NORMAL` also belongs in durability qualification: local power-loss durability is not equivalent to every HTTP acknowledgement being fsynced or remotely backed up.

## 3. Multi-database consistency

Litestream follows each file independently. Positions and restore timestamps are per history. A common lease, S3 endpoint, or matched polling interval does not give atomic replay across main/session/attached files. SQLite WAL itself does not provide crash-atomic transactions across attached files as a set.

Classify every DB and dependency:

- **Authoritative independent state:** can recover to its own position with explicitly accepted temporal skew.
- **Coupled authoritative state:** application correctness/security depends on a consistent cut; not supported for unplanned automatic failover until a protocol or restriction handles it.
- **Rebuildable derived state:** may be rebuilt only under an explicit validated procedure; absence is not silently tolerated.
- **Node-local state:** logs, caches; never merged into application truth automatically.

Proposed conservative v1 rule: keep tightly coupled business invariants in `main.db`; enroll attached DBs only with declared recovery semantics. Session DB remains mandatory by default, but recovery may need reauthentication/invalidation and validation against main. That policy is not yet approved.

A planned quiesced checkpoint can stop all mutators, flush every DB, and record a coherent application cut. For unplanned failure, possible future mechanisms include application transaction/outbox IDs and replay, or a last verified quiesced checkpoint at a larger RPO. A “minimum TXID” or “same timestamp” across DBs is not a solution. Tests must include a crash between related DB writes and between independent uploads.

## 4. Logs

[HTTP logging](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/src/logging.rs#L229-L350) writes `logs.db`. `--stderr-logging` does not disable SQLite logging. No separate log-DB-path flag was found; node depots naturally keep separate `data/logs.db` files. Any separate filesystem mount must also accommodate its sidecars.

Default: leave logs local and ship structured process logs to an existing collector if desired. If using Litestream for log history, use a separate log replication process/config and a unique cluster/node/log-generation destination, never the business-state prefix. Logs are not a promotion prerequisite unless a specific audit requirement says otherwise. Configure bounded disk/retention and avoid letting log exhaustion bring down the API unnoticed.

Cross-node analytics may aggregate exports with node/epoch/request identity and deduplication later. Log aggregation cannot reconstruct missing business transactions or provide a fencing/audit authority by itself.

## 5. Authentication and non-database secrets

Exact non-DB state:

| Path/config | HAT requirement |
| --- | --- |
| `config.textproto` | Provision the same approved logical configuration; distinguish primary/read-role overrides; reject unpropagated admin changes |
| `secrets/secrets.textproto` | Recoverable vault/secrets provisioning outside database backup |
| `secrets/keys/private_key.pem`, `public_key.pem` | Shared signing identity for promotable nodes; protect private key; coordinate rotation and token verification |
| `secrets/certs/cert.pem`, `key.pem` if native TLS used | Shared identity or per-node certificates as appropriate; manage expiration/rotation |
| `migrations/`, `wasm/`, static/runtime assets | Developer deploys compatible immutable release; HAT verifies fingerprints |
| `metadata.textproto` | TrailBase version metadata; preserve for diagnosis, validate compatibility rather than blindly copying old startup state |
| `uploads/` | Local default; prohibited for HAT application objects |

[JWT source](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/src/auth/jwt.rs#L278-L348) generates keys if missing; independent bootstrap would create incompatible token identities. Never let a standby invent new keys or an admin account because restored state is missing.

[Token extraction/refresh](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/src/auth/tokens.rs#L57-L94) shows valid JWT verification can be stateless. Login creates session state; [GET logout](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/src/auth/api/logout.rs#L22-L82) is mutating. OTP/auth-code/OAuth and account changes have additional writes. A password-auth toggle is not a universal auth-write disable switch.

Default all auth traffic to the primary. Test cookies, canonical public URL, OAuth callbacks, CSRF/CORS, refresh tokens, password/TOTP/email changes, logout and key rotation across failover. Stale user/ACL/session data and lost revocation commits can authorize access that should have been removed. A relogin policy alone does not restore a lost account-disable/ACL update or invalidate every existing JWT; any emergency revocation/key rotation needs an explicit supported design.

Source [`vault.rs`](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/src/config/vault.rs#L55-L63) derives secret environment names as `TRAIL_<UPPERCASE_FIELD_PATH>`; for example `TRAIL_SERVER_S3_STORAGE_CONFIG_SECRET_ACCESS_KEY`. Provision secrets through protected runtime mechanisms and verify exact handling; do not commit them in sample configs.

Rate limits, in-memory caches, counters and abuse protections may reset or multiply with replicas. Inventory/test their semantics rather than implying HA preserves them automatically.

## 6. Shared application objects

Require `server.s3_storage_config` with [fields](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/proto/config.proto#L157-L184): `endpoint`, `region`, `bucket_name`, `access_key`, `secret_access_key`. HAT backup storage and TrailBase application object storage are distinct configurations/credentials, even when they use the same provider.

[Object store construction](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/src/app_state.rs#L598-L636) chooses S3 when configured, otherwise local uploads, and constructs the store at startup. Do not assume live config reload rebuilds it.

All authorized primaries use the same application object namespace; optional readers get object-read permission only. But shared storage solves **distribution**, not transactional consistency:

- Upload succeeds, DB commit fails: orphan object/cleanup required.
- DB commit succeeds, response or replication is lost: ambiguous operation and metadata recovery gap.
- Object update/delete succeeds while a DB replica is stale: replica may reference a now-missing object.
- PITR restores old metadata after deletion: object must still be recoverable independently.

[Record write paths](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/src/records/write_queries.rs#L337-L381) can immediately delete old objects after DB mutation. Disabling the periodic cleanup job does **not** by itself establish a retention grace period. Choose and test a policy: immutable/version-addressable objects with compatible download/recovery, upstream deferred deletion, or restricted file mutation/PITR/read-offload support. Bucket versioning by itself does not make TrailBase's normal key lookup retrieve an old version.

[File-deletion queue schema](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/migrations/base/U2__file_deletions.sql) and [cleanup retry](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/src/records/files.rs#L254-L277) contain a source-visible `record_rowid` versus `record_row_id` mismatch. The retry insertion appears unable to restore failed deletions. Reproduce and resolve or mitigate this before relying on cleanup; no upstream issue was filed in this pass.

## 7. Jobs and other side effects

[System jobs](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/src/scheduler.rs#L285-L630) use `jobs.system_jobs[].{id,schedule,disabled,timeout}`. Baseline behavior found:

- `BACKUP`: daily, disabled by default; local backups do not replace HAT remote recovery.
- `HEARTBEAT`: enabled, no DB write in the inspected job.
- `LOG_CLEANER`: hourly, deletes local logs.
- `AUTH_CLEANER`: hourly, deletes session/auth-code/OTP state.
- `QUERY_OPTIMIZER`: daily, optimize on main.
- `FILE_DELETIONS`: hourly, mutates main/configured DB queues and shared objects.
- `ANONYMOUS_CLEANER`: implementation exists, but not included in the inspected registration list; recheck future releases.

[WASM component jobs](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/src/wasm/mod.rs#L166-L197) start separately from system-job overrides; runtime [shared preferences](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/wasm-runtime-host/src/prefs.rs#L45-L93) write main. Disabling system jobs does not disable all custom work.

All mutating jobs are primary-only, including work started before public readiness. An old writer fence must cover their processes and egress. Switchover must drain/stop them before the final checkpoint. Exactly-once email/webhook/payment execution is not supplied by SQLite backup: applications need idempotent operations, a transactional outbox where appropriate, and reconciliation of acknowledged external effects. Capturing an outbox asynchronously still has rollback/loss semantics to define.

## 8. Realtime

TrailBase uses SQLite [`preupdate_hook`](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/src/records/subscribe/hook.rs#L39-L107) and [in-memory subscription channels](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/src/records/subscribe/state.rs#L230-L275) on its writer connection. External physical page replay does not execute SQL on that connection and therefore does not produce equivalent realtime events.

Baseline: route subscriptions to the primary; configure ingress for SSE streaming (no buffering/caching and appropriate timeouts). On role change close old streams; clients reconnect, reauthenticate as needed, resubscribe and refetch authoritative state. No promise of gapless delivery, stable event cursors or replay. A client can have seen an event for a commit later lost during failover; refetch must tolerate rollback.

If durable replay is needed, design application event IDs/outbox and a replay protocol separately. Do not add a message broker simply to conceal the fact that file replication is not an event stream.

## 9. Schema, config and caches

[Connection metadata](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/src/connection.rs#L227-L251) and [RecordApi structures](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/src/records/record_api.rs#L135-L173) retain schema/ACL/column state. No external DB-file watcher was found. SQLite page-cache visibility does not imply TrailBase's higher-level metadata refreshes.

[SIGHUP handling](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/core/src/server/mod.rs#L869-L935) can reapply migrations, rebuild triggers, reload config, and write config/vault state. It is not a safe read-only cache-invalidation command.

Proposed rule: primary-only migrations and administrative config changes through a controlled release/config process. Replicas with mismatched schema/config/key/runtime artifacts become ineligible; restart/rebuild only through the qualified mode. Rollouts may temporarily disable promotion and read offload. A newer binary starting on an old DB can mutate schema before traffic arrives, so version checks must precede executable startup.

Asset distribution remains developer-owned, but configuration, secret continuity, and compatibility checks are essential HA correctness—not optional asset syncing.
