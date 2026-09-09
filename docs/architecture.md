# Architecture and failover protocol

Status: proposed contract. No controller, protocol implementation, or fencing integration exists yet. Read with the [master plan](plans/2026-09-07-master-plan.md) and [issue register](work-register.md).

## 1. Topology and roles

```text
clients ──> existing HA ingress ──> current PRIMARY ──> shared application objects
                      │                    │                    (S3/R2)
                      │                    └─ Litestream replicate
                      │                               │
                      │                      epoch-scoped DB backups
                      │                            (S3/R2)
                      │                               │
                      └─ optional qualified reads <─ STANDBYs
                                                    restore -f per DB

HAT supervisors <──> one authoritative cluster lease / activation metadata
       │
       └──> independent deployment fence + node-local process supervision
```

HAT uses “standby” for a cluster node and “backup destination” for Litestream's `replica` setting; these are not the same thing.

- **Service-hot/read standby (eventual target):** databases continuously restored and TrailBase running in a strictly qualified read-only mode, with local writable logs. It serves only approved stale-tolerant reads.
- **Data-hot standby (fallback):** databases continuously restored; TrailBase not running. Use this mode until the service-hot read-only gate passes.
- **Primary:** sole authorized mutable TrailBase instance plus outbound Litestream for every required database.
- **Quarantined node:** no ingress, no outbound replication or mutating jobs; local state retained for diagnosis.

All TrailBase access goes through role-aware ingress/local gates. Bind raw application/admin ports to private or loopback interfaces; deny bypass. Removing a load-balancer target alone does not fence local jobs or in-flight requests.

## 2. Three separate problems

### Election

Select one candidate using conditional updates to a single cluster lease. Health probes only trigger suspicion; they do not confer leadership. Lease contention must use CAS, not “read expired, then unconditional write.” Candidate priority/backoff can prefer a healthy/fresh node, but only the lease decides who may attempt activation.

Litestream's S3 leaser is a reuse candidate, not a turnkey solution. An integrated lease lifecycle must acquire, renew, stop safely, and handle uncertain responses. No separate per-database leaders.

### Application fencing

A successful lease update does not revoke an old process's SQLite connection, S3 credentials, cron timer, or outbound HTTP request. SIGTERM from a suspended supervisor cannot be trusted to arrive on time. A process resuming after its lease expired must not resume writes under the old authority.

For automatic failover, require an **operator-supplied independent fence**. HAT defines the safety contract, not a hosting-provider API or adapter. Confirmed external power-off is one possible implementation; an alternative must provide equivalent protection for every mutation path. A network-only fence must cover more than incoming HTTP; a DB file local to the isolated host is still writable. Fence evidence must identify the exact old instance/boot incarnation and prevent its automatic restart.

Proposed minimal integration: invoke a trusted operator-configured executable, kept outside this repo, with structured target/operation data—not an interpolated shell command. Freeze the invocation/result format during execution planning. The contract must:

- Bind the request and completion evidence to the cluster, old node/boot/activation, and a unique operation identity; reject stale or mismatched evidence.
- Report success only after the old writer, replicator, and jobs cannot mutate or resume under old authority. “Request accepted” or a process exit code without the required evidence is insufficient.
- Bound waiting and handle retries/unknown outcomes idempotently; a timeout or missing integration keeps promotion blocked. Recheck current promotion authority before acting on completion.
- Prevent delayed retries from fencing a new incarnation or a safely rejoined node; the operator integration owns target mapping and lifecycle interlocks.

HAT trusts this privileged integration's completion evidence; it cannot infer physical isolation from a generic result alone. The repository will supply deterministic contract fixtures and failure tests, not provider-specific SDKs, cloud provisioning, or a vendor certification list. Operators validate the real mechanism privately before enabling automatic failover.

Local defense-in-depth: deny readiness early, stop the entire managed process group/cgroup, enforce bounded shutdown, and watchdog the supervisor. These measures help, but an arbitrary whole-host pause defeats a same-host watchdog. If fencing cannot be proved, do not activate another writer. Manual promotion follows the same rule.

External effects already accepted by third parties before fencing may finish afterward. HAT cannot retract them; idempotency/reconciliation remains an application responsibility.

### Backup-history protection

Even after ingress removal, an old Litestream can upload stale data. The proposed baseline allocates **a new HAT epoch and fresh backup prefixes for every leadership activation**, including a writer restart. Thus old uploads cannot overwrite a successor's backup stream. This contains damage; it does not replace application fencing.

A HAT epoch is not a Litestream TXID or lease generation. Do not use the built-in generation as a permanent fencing counter: releasing/deleting its lock allows a later acquisition to start at generation 1. Use non-reused activation identities, and a durable ordering/publishing protocol if any consumer requires monotonic tokens. Never compare TXIDs across databases or epochs.

## 3. Lease and discovery metadata

Proposed logical metadata (schema and exact update protocol belong to M0/M1):

- Cluster identity, schema version, node ID, boot ID, activation ID.
- Lease ownership, ETag, expiry, last confirmed renewal and request timing.
- Activation phase: preparing, ready, draining, fenced, failed.
- Parent epoch and per-DB source positions; inventory/release/config/key fingerprints.
- Backup prefix map, primary private address, readiness, fence receipt, promotion reason.

Use direct authenticated S3 APIs, not a CDN, cached public domain, or an asynchronously replicated secondary copy for coordination. CAS is per object, not a multi-object transaction.

**Publication is itself a safety gate:** a separate `active.json` is advisory unless readers validate its activation against current authoritative leadership. An expired holder must not be able to publish a stale route after takeover. Decide whether authority/activation belongs in one CAS-controlled object or requires a fenced publication service. Do not presume Litestream's stock `lock.json` contains this metadata or safely preserves added fields on renewal. Do not run two incompatible lease implementations against the same key.

Timeout response lost after S3 committed? Reconcile using ownership/operation identity and a fresh conditional read; do not blindly acquire, release, or retry an old transition. Malformed/missing metadata on an initialized cluster is an incident, not bootstrap permission.

Lease timing needs an explicit clock-drift and scheduling model. The current library uses wall time. Determine TTL, renewal interval, network deadlines, early-stop margin, maximum clock error, and takeover margin from that model and fault tests—not from the library's 30-second default. Local deadlines should be monotonic and conservatively based on request timing, with suspend/resume tested. Expired authority must require a new activation, never a late renewal followed by resumed service.

## 4. State machine

```text
UNINITIALIZED ──explicit bootstrap──> PREPARING ──checks──> PRIMARY
         │
         └──existing cluster──> RESTORING ──checks──> FOLLOWING
                                                       │
                                     suspect + eligible + lease
                                                       v
                                                   PREPARING
                                                       │
                                    fence + catch-up + new epoch
                                                       v
                                                    PRIMARY
                                                       │
                                      loss / drain / incompatibility
                                                       v
                                             DRAINING / FENCED
                                                       │
                                                 QUARANTINED
                                                       │
                                        explicit rejoin / clean reseed
                                                       v
                                                   RESTORING
```

Persist transitions locally and in authoritative cluster metadata as appropriate. Restarting a supervisor never trusts “I was primary” from a local file. Crash at any transition boundary must lead to recovery or fencing, not two writers. Keep liveness distinct from readiness: a following or fenced agent can be alive but not application-ready.

## 5. Bootstrap

1. Explicit operator bootstrap names a new cluster, inventory, initial node, release, secrets, storage, and policy. Deny bootstrap over an existing cluster identity.
2. Validate backend conditional operations and fencing setup. Block application ingress.
3. Establish exclusive cluster authority and the first activation namespace.
4. Initialize TrailBase once in a controlled environment; capture generated state/secrets. Apply intended migrations only here/on an authorized primary.
5. Start outbound replication for all required DBs and verify remotely restorable baseline data. Trails/logs excluded from required business-state readiness.
6. Publish readiness only after application checks and activation publication are safe.
7. Seed standbys from this activation. Fail initial HA readiness until the required redundancy is healthy, even if the primary API itself works.

## 6. Automatic promotion contract

Every numbered item is a precondition or step, not a presently working command sequence.

1. **Suspect, do not elect by ping.** Combine application checks, supervisor health, lease state, replication progress, and ingress observations. Allow a local application restart only under valid exclusive authority and a new controlled activation. An API crash and a host failure need different diagnosis.
2. **Check candidate eligibility.** Correct inventory/release/config/key versions, healthy disk, reachable storage/control plane, no unexplained replay errors, approved consistency policy, acceptable RPO evidence, and available fencing backend. Unknowns remove eligibility.
3. **Obtain exclusive promotion authority.** CAS acquisition under the chosen expiry/timing rules; renew throughout preparation. A live primary that keeps a valid lease cannot be displaced merely because a peer missed HTTP probes. Operator takeover must also coordinate fencing/authority safely.
4. **Fence the previous activation.** Confirm old writer, outbound replicator, jobs, and restart mechanisms are disabled for the exact old host incarnation. Record evidence. Account for outstanding storage requests before treating old backup history as sealed. If this cannot be proved, stop here.
5. **Choose a recoverable cut.** Inspect complete remote LTX history and durable checkpoints for every required DB after fencing. Determine recoverable positions and the loss/uncertainty budget. Never select “highest TXID node” without checking database and epoch identity or matching checksums/history. An old primary's unuploaded local WAL is incident evidence, not something to merge automatically.
6. **Drain and stop replica readers; catch up and stop followers.** Wait for processes to exit and release files. If following has errored, been interrupted during apply, or cannot reach the cut, rebuild from known remote history into a clean directory. Use explicit positions for a finite restore where appropriate; `-f` cannot combine with `-txid`.
7. **Validate the set.** Integrity/checksum/history checks, schema/inventory, application invariants, session policy, and no unexpected WAL/journal sidecars. A collection of individually valid DBs is not proof of a consistent multi-DB set. Reject unsupported skew.
8. **Prepare a new epoch.** Record parent lineage and source cut; switch outbound configs to new per-DB prefixes. Never copy stale Litestream replication working metadata from the old primary. Preserve forensic source copies; start fresh local replication state with controlled journal-mode transition.
9. **Start the writable application under authority.** No followers remain on these paths. Permit only approved startup migrations/jobs; avoid large migrations on the failover path. Start/verify outbound replication for every required DB, using existing process supervision where useful. Ensure the new epoch has a restorable baseline before advertising it to replacement followers or opening public ingress. Startup jobs are already mutation, so fencing must precede startup.
10. **Publish and route.** Recheck authority/readiness; safely publish the new activation. Ingress drains the old target and switches to the new primary; keep stale gates closed. Record achieved RPO/RTO and unknown/lost operations.
11. **Rebuild redundancy.** Other nodes withdraw stale reads, stop old-epoch followers, and seed from the new epoch. Epoch reseeding adds I/O and a reduced-redundancy window; measure it. Do not assume existing followers transparently switch lineage.

If preparation fails or authority is lost, stop every mutator immediately and leave ingress closed. Never roll back by restarting the old writer without a new safe activation. Preparation may have written state or triggered side effects; preserve its history for diagnosis.

## 7. Planned switchover

Block new mutations and drain active requests, uploads, transactions, and scheduled work. Stop/pause the application's mutating processes while Litestream remains available to capture committed WAL. Use the verified IPC `sync -wait` capability per DB and verify remote positions; record a common **quiesced** inventory checkpoint. A shared timestamp alone is not that checkpoint.

Then stop the old outbound replicator, confirm fencing/no restart, and transfer authority through the same activation protocol. Keep reads only where their consistency and shutdown semantics are proven. Failure to drain/flush changes this into an unplanned recovery with an explicit loss assessment; do not label it zero-loss.

## 8. Rejoin and disaster recovery

A returning primary boots fenced, not writable. Quarantine its databases, WAL/SHM, Litestream working files, config/version information, and logs. Report unreplicated/divergent data for manual reconciliation. Reseed a new working directory from the current activation; keep a fresh local log DB. It rejoins as a standby and never triggers automatic failback.

For cluster-wide loss or PITR: stop/fence every mutator first, choose an explicit recovery point and compatible DB set, restore required release/secrets and application objects, validate, then create a new activation. Backups must exist independently of node disks; credentials and encryption keys require separate recovery. Do not overwrite live database files or reuse a recovery namespace as a running primary prefix.

## 9. Routing and failure semantics

Default all API/auth/admin/custom routes, file mutations, and realtime to the primary. Use one existing HA load balancer/reverse proxy with role-aware readiness; DNS-only failover has client caching and connection limitations and is not the baseline. Protect the ingress/control plane from becoming the new single point of failure.

Read offloading is opt-in per tested endpoint. The intended steady state is that all standbys run TrailBase, but a separate read hostname or explicit route allowlist must send only approved stale-tolerant reads there. Preserve TLS, origin/cookie and CORS behavior if used. Enforce staleness limits and current-epoch checks. Mutations, auth/ACL/session-sensitive reads, jobs, admin paths, and read-after-write flows stay primary by default. Stickiness is an optimization, not a durability guarantee; future causal tokens must carry epoch and per-DB position semantics.

On demotion close existing long-lived streams/connections, not only readiness for new ones. Never automatically retry non-idempotent mutations after an ambiguous timeout. Clients may need to query operation status or retry with application idempotency keys. Return explicit unavailability while safety is uncertain.

## 10. Failure decisions

| Event | Required response |
| --- | --- |
| Primary loses S3/control connectivity but still serves clients | Withdraw write readiness and stop within the conservative lease deadline; no continued writes on stale authority |
| Standby loses S3 | Mark lag/eligibility unknown; no promotion; stale reads only under separately approved policy |
| Entire coordination service unavailable | No new leader; primary stops before authority becomes uncertain; availability is deliberately sacrificed |
| Supervisor crashes or host pauses | Local coupled shutdown where possible; successor still needs an independent fence |
| Ingress is partitioned or has a stale primary target | Old local gate/fence rejects traffic; routing alone must not be trusted |
| Lease renew succeeds but response is lost | Reconcile uncertain state; never assume extra lease time |
| Corrupt/truncated LTX, partial apply, pruned history, disk full | Withdraw affected replica, alert, restore cleanly or refuse promotion |
| One required DB lags or is missing | Whole candidate is ineligible unless its declared recovery policy explicitly permits that state |
| New primary fails before publishing | Recover/fence the incomplete activation; never infer readiness from existence of a lease |
| Failure domain or external dependency outage | Hosting-provider independence does not imply safe automatic takeover across independent coordination/storage authorities; such failover needs a separate protocol |
