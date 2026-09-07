# Deployment and storage contract

Status: proposed setup requirements, **not runnable installation instructions**. Generic service setup, capability checks, and the HAT config schema will follow feasibility testing. Hosting-provider provisioning, SDKs, credentials, and integrations remain operator-owned and outside this repo. Do not provision infrastructure from these placeholders.

## 1. First supported environment

**Selected target: provider-independent cloud VMs/VPSs first.** No hosting provider is selected or required by this repo. Bare-metal and orchestrator-specific deployments are deferred.

Recommend Linux VMs with node-exclusive persistent SSD-backed volumes, an existing HA ingress, and an operator-supplied independent fence. Define required OS, filesystem/locking, network, and supervision capabilities without tying them to VM product names. Windows, shared/network SQLite filesystems, serverless scale-to-zero/overlapping replicas, and multi-region active/active are outside the first support envelope.

Minimum topology: one primary plus one standby on distinct failure domains. Three nodes improve maintenance flexibility and recovery capacity but do not alter asynchronous durability. Ingress, the fencing mechanism, credentials, time service, DNS, and object storage are dependencies to include in the availability model.

For automatic promotion, the operator-supplied fence must confirm that the exact previous node incarnation cannot mutate or resume as the old writer. Confirmed external power-off is one implementation, not a required hosting API. An accepted request, SSH failure, or load-balancer removal is not completion evidence. Unknown fencing outcomes block promotion. Any restarted/replacement node must enter fenced and rejoin through the normal reseed protocol; preserve old disks for forensic recovery where possible.

HAT will document and test the [provider-neutral fencing contract](architecture.md#application-fencing), not ship hosting SDKs or adapters. Operators supply any hosting-specific executable/configuration privately and validate hung-node behavior, completion evidence, delayed/duplicate requests, permissions, restart prevention, disk preservation, and latency before enabling automation. A VPS without a trustworthy fence can still support replication/testing, but automatic promotion stays disabled; manual promotion still requires confirmed isolation.

Use generic local fixtures first. Later integration tests can use operator-provided VPSs with private inventory and credentials; publish only sanitized results and capability assumptions, not hosting names, account IDs, VM IDs, addresses, or private integration code. Successful fixture tests are not proof of a production fence. S3/R2 storage compatibility remains in scope independently of hosting choice.

## 2. Every node

Provision:

- Unique cluster/node/boot identity; no shared cloned identity or automatic writable startup.
- Identical, pinned TrailBase and Litestream executables, platform/SQLite build information and checksums.
- Compatible application release, migrations, WASM/extensions, API configuration, auth settings, and secret/key versions. Hash secrets via version identifiers or protected manifests, never publish raw secrets.
- Separate local directories for current working DBs, follower TXID sidecars, Litestream working metadata, logs, quarantine, temporary restore, and supervisor state.
- Enough disk for DBs + WAL + replication metadata + snapshots + one clean restore + forensic retention. Limits must include log/backup growth.
- A dedicated unprivileged application identity and restricted supervisor/fencing credentials. Database follow needs write access; a read-only application process needs a separate permission boundary.
- Private/loopback TrailBase ports, restricted admin and IPC ports, TLS at ingress, authenticated operator/control access, monitoring endpoints on a management network.
- Clock synchronization with offset monitoring; actual suspend/clock-error behavior tested against the lease model.
- External secret injection, outbound connectivity to storage, required identity/email services, and the fence backend. No credentials in Git, process arguments, metrics labels, or public logs.

Illustrative local layout (HAT-controlled paths, not TrailBase defaults):

```text
/opt/hat/releases/<release-id>/              pinned binaries + app artifacts
/etc/hat/                                  non-secret policy/config references
/var/lib/hat/<cluster>/<node>/
  supervisor/                              local transition records
  active/<activation-id>/traildepot/        current writable or followed depot
  restore/<operation-id>/                   clean staging depot
  quarantine/<old-activation-id>/           preserved forensic state
  node-logs/                               node-specific log files/exports
/run/hat/                                  restricted IPC sockets/readiness state
```

The final directory layout must respect TrailBase's actual paths described in [state inventory](trailbase-state.md). Do not invent a `--read-only` or `--log-db-path` flag; use only verified options. Avoid live directory/symlink swaps under open SQLite connections.

## 3. Per-role process and access model

| Concern | Primary | Data-hot standby | Optional service-hot standby |
| --- | --- | --- | --- |
| HAT supervisor | Lease holder, process owner, writer readiness | Follows metadata, evaluates eligibility | Same, plus read eligibility |
| TrailBase | Writable only after fence/activation checks | Stopped | Qualified read-only DB mode; node log writable |
| Litestream | One `replicate` process for required DB set | One `restore -f` per required DB | Same followers; never outbound replicate these files |
| Logs | Local/node-specific stream | Supervisor/follower logs | Local TrailBase log DB; never incoming log replay |
| S3 backup permissions | Read/write only the owned epoch; retention as needed | Read/list approved history | Same |
| Object permissions | Required read/write/delete while authorized | None unless required for readiness | Read-only; enforce beyond HTTP routing |
| Jobs/admin/auth mutation | Authorized primary only | Off | Off; auth-sensitive traffic normally primary |
| Ingress | Write and default read target | No application traffic | Only approved stale-tolerant routes |

Backup writer credentials must not let a stale epoch overwrite the next epoch. Prefer scoped short-lived identities where supported. R2/S3 permission propagation and expiry must be measured; credentials are defense-in-depth, not the primary fence. If a provider cannot express desired prefix scoping, use bucket/account isolation or document the reduced security boundary and require an external fence; do not imply S3 IAM works unchanged on R2.

## 4. Storage separation

Logical layout (buckets may be separate security/retention boundaries rather than just prefixes):

```text
hat-control-<environment>/
  clusters/<cluster-id>/
    lease/lock.json
    activations/<activation-id>.json
    active.json                         # advisory unless validated against authority

hat-backups-<environment>/
  clusters/<cluster-id>/epochs/<activation-id>/db/<logical-db-id>/
    <Litestream-owned LTX/snapshot objects>
  clusters/<cluster-id>/checkpoints/<checkpoint-id>.json

hat-objects-<environment>/
  <TrailBase-managed application object namespace>

hat-logs-<environment>/
  clusters/<cluster-id>/nodes/<node-id>/<boot-or-log-generation>/
    <optional log DB backups or append-only log exports>
```

Do not insert HAT metadata into Litestream's internal LTX file layout. A HAT activation namespace wraps the configured backup path. Log generations prevent a rebuilt node's new log database from colliding with its previous backup history. Log aggregation is a separate optional consumer with deduplication, privacy, and retention policy—not another writer into replicated business DBs.

The activation/checkpoint record records the exact logical DB inventory, source epoch, per-DB positions/checksums, schema/config/release compatibility and recovery policy. It is not an atomic distributed DB snapshot. The `active.json` publication safety problem is detailed in [architecture](architecture.md).

## 5. S3-compatible storage checklist

For each configured storage endpoint (no account or vendor selection is needed now):

- Create private environment/cluster-scoped storage. Disable public access; enforce TLS; choose regions/jurisdiction and encryption policy.
- Use the direct S3 API endpoint. R2 uses the account-specific endpoint and provider-appropriate signing/region configuration; AWS uses its region/bucket configuration. Generate exact config only after testing the pinned SDK/binary.
- Qualify conditional create, replace, and release; ETag quoting, 409/412 handling, expiry takeover, unknown response outcomes, concurrent contenders, listing, range reads, multipart uploads and retry/throttle behavior.
- Keep control objects free of cache/CDN paths, automated lifecycle deletion, object retention locks that prevent renewal, and asynchronous failover endpoints. A missing lease object is not an instruction to form a second cluster.
- Separate application-object, control, backup, and log credentials/policies. Standby application code must not receive backup write or fencing authority.
- Scope AWS permissions as needed: bucket prefix listing; object GET/PUT; DELETE for retention/release; multipart permissions; KMS access if selected. Separate recovery/break-glass and independent retention roles from routine node roles.
- For R2, verify actual token scope/granularity rather than copying an AWS policy. Conditional-delete support is an open gate in [upstream findings](upstream-findings.md).
- Retain recovery history longer than maximum expected node outage + catch-up + rollback/incident investigation. Fine-grained L0 retention, snapshots and compaction determine reachable PITR precision.
- Never apply generic bucket expiry that deletes an active restore chain. Let one qualified mechanism own retention; test oldest supported restore and lagging follower recovery.
- Keep an independent protected recovery copy if ransomware/operator compromise is in scope. S3 versioning/object lock and R2 equivalents differ; immutable archives must be separate from mutable live lock/compaction objects. Versioning alone is not a proven restorable backup policy.
- Object retention must cover restored DB references. Destructive application object deletion/GC can make PITR DBs unusable even when database backups are intact.
- Account for request rates and cost: roughly `standbys × DBs / poll_interval` baseline polls, plus object lists/downloads/compaction/snapshots; measure rather than assuming free replication. Cross-region latency/egress and full epoch reseeds matter.

No real buckets, credentials, or cloud resources were created in this planning pass.

## 6. Litestream configuration boundary

This is a **source-verified shape with placeholders**, not a complete config. In v0.5.17 each DB uses singular `replica`:

```yaml
# Primary only; generated per activation after exclusive authorization.
# Credential injection, IPC, metrics, retention, and provider options omitted here.
dbs:
  - path: /var/lib/hat/ACTIVE_DEPOT/data/main.db
    replica:
      url: s3://BACKUP_BUCKET/clusters/CLUSTER/epochs/ACTIVATION/db/main
  - path: /var/lib/hat/ACTIVE_DEPOT/data/session.db
    replica:
      url: s3://BACKUP_BUCKET/clusters/CLUSTER/epochs/ACTIVATION/db/session
  - path: /var/lib/hat/ACTIVE_DEPOT/data/ATTACHED_NAME.db
    replica:
      url: s3://BACKUP_BUCKET/clusters/CLUSTER/epochs/ACTIVATION/db/ATTACHED_NAME
  # Repeat the attached entry for each enrolled DB; omit it if none exist.
  # Do not add incoming-replicated log DBs or independently invent lease: fields.
```

Illustrative standby command, with paths and credentials supplied by the supervisor:

```sh
litestream restore -f -follow-interval 1s \
  -o /var/lib/hat/FOLLOW_DEPOT/data/main.db \
  s3://BACKUP_BUCKET/clusters/CLUSTER/epochs/ACTIVATION/db/main
```

Repeat for each required file; promote the set, not individual processes. Use strict restore failure handling on existing clusters. `-if-db-not-exists` is not a freshness check; `-if-replica-exists` must not turn missing backups into silently empty application state. Do not use `-force` on live files. A nonzero or silent/retrying follower failure must withdraw eligibility, not launch TrailBase.

HAT configuration will declare: identities, database inventory/policies, binary/artifact fingerprints, storage/secret references, fencing target, lease timing, loss/downtime policy, required redundancy, readiness/routing and optional read allowlists. Exact syntax is intentionally deferred until the experiments establish what can be enforced.

## 7. Operating procedures to deliver

- Bootstrap a new cluster; add/reseed a standby; inspect readiness and lag.
- Planned switchover; unplanned fenced promotion; abort an incomplete activation.
- Quarantine and rejoin an old primary; preserve data for reconciliation.
- Recover after total cluster loss; restore a tested PITR/checkpoint and corresponding objects/keys.
- Rotate credentials and signing keys without silently breaking auth or restore access.
- Upgrade pinned binaries/config/schema: drain or use backward-compatible migrations, update standbys, disable promotion during incompatible skew, then switch safely. A database rollback may require restore, not just the old executable.
- Handle S3 outage, quota, disk exhaustion, follower gaps, corrupt metadata, fence unavailability, and observed clock drift.
- Inspect and expire old epochs/logs without deleting active recovery dependencies.

## 8. Observability contract

Expose role and activation; current authority/fence status; lease remaining conservative time and renewal failures; per-DB local/applied/remote position and source identity; last successful storage observation; replication age/bytes/gaps; inventory mismatch; disk/WAL growth; process/IPC status; schema/key/release fingerprints; ingress errors and SSE reconnects; promotion refusals; degraded redundancy; object cleanup failures.

Do not expose secrets or private auth/session contents. A TXID is a position within one history, not a wall clock; “seconds since latest DB write” cannot distinguish idle traffic from a stalled uploader without additional evidence. Alert on **unknown** freshness, not just threshold breaches.

Measure RPO using an external durable test ledger of sent/acknowledged operation IDs and recovered results. Measure RTO from client probes, including auth and streams. Avoid claiming availability percentages until repeated realistic failure/load drills establish them.
