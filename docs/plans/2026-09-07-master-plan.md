# HAT master plan

Date: 2026-09-07 · Status: initial design, not an execution plan

## 1. Objective and boundaries

Run the latest **qualified** TrailBase executable as one writable primary and one or more promotable standbys. Litestream continuously uploads primary database changes to S3/R2; standbys continuously restore them. Automate safe failover, not just process restart.

The user selected this policy during planning:

> Safety first: automatic promotion only with proven fencing and a defined data-loss budget; otherwise stop for operator review.

**Deployment target chosen:** cloud VMs first. Bare-metal and orchestrator-specific deployments are deferred.

These decisions approve the safety direction and deployment class, not a particular cloud provider/fencing backend, numeric RPO/RTO, or all design proposals below. Those remain open decisions.

In scope:

- Failure detection, cluster-wide leadership, fencing, promotion, switchover, and safe rejoin.
- Main, session, and declared attached databases; separate per-node logs.
- Storage objects, auth secrets, realtime connections, jobs, schema/config compatibility, routing, and observability.
- Recovery drills, failure injection, provider qualification, operating procedures, and eventual packaging.
- Optional read scaling, without treating HTTP GET as a read-only guarantee.

Out of scope initially:

- Multi-primary writes, merging divergent SQLite histories, transparent zero-loss failover.
- Replicating local uploaded files: S3/R2 object storage is required.
- Distributing application assets. Developers deploy identical releases; HAT should validate release/config fingerprints and later offer rollout checks.
- Building a new database, load balancer, object store, consensus service, or analytics platform.

## 2. Feasibility before implementation

[Upstream findings](../upstream-findings.md) distinguish source evidence from assumptions. The first gates are:

1. **Application fence:** establish how an old writer is made unable to write before a new writer starts, including process suspension and network partitions.
2. **Restore/promote correctness:** qualify `restore -f`, recovery after interrupted page application, all required DB files, and writable startup after following stops.
3. **Read-only TrailBase:** the current unmodified release opens files writable, forces WAL, and performs startup writes. Keep its process stopped on standbys; qualify a future upstream read-only capability before allowing service-hot/read replicas.
4. **Multi-file consistency:** define which data must recover together and how to detect or prevent unsafe skew, especially auth/session and attached DB dependencies.
5. **S3/R2 coordination:** test conditional operations on the actual provider. Litestream's leaser is not currently an integrated CLI supervisor.

Until these pass, HAT is an HA design experiment, not a production availability claim. A blocked service-hot replica does not block data-hot standby research.

## 3. Architecture alternatives

| Approach | Advantages | Costs / limits | Direction |
| --- | --- | --- | --- |
| S3 lease primitives + small HAT supervisor + deployment-native external fence | Reuses storage and Litestream; few moving parts | Lease integration is missing; clocks, uncertain requests, fencing API and outage coupling must be solved | Recommended first investigation |
| Existing consensus-backed coordinator + the same supervisor/fence | Preferable where etcd/Consul or an equivalent managed control plane already exists | Adds a dependency otherwise; election still does not fence SQLite or make backups synchronous | Keep as an alternative, not a second v1 backend |
| Synchronous/quorum database or replication architecture | Appropriate if acknowledged-write loss is forbidden | Changes the core TrailBase/Litestream premise; needs a separate compatibility evaluation | Revisit only if requirements demand it |

Within the chosen cloud-VM target, the proposed initial deployment is two or three Linux VMs in separate failure domains, an existing HA ingress service, one S3/R2 endpoint, and a cloud-control-plane fence that works independently of the guest OS and application process. Two nodes can coordinate through a single authoritative object-store lease; adding a third node does **not** magically create data quorum replication.

Start with data-hot standbys: restore processes stay running, but TrailBase is stopped. Add service-hot read replicas only after the read-only gate. This is an explicit reduction of initial scope, not a claim to have solved the requested hot application standby yet.

## 4. Proposed invariants

1. At most one authorized application writer, including auth, cron, custom handlers, admin, cleanup, and object mutations.
2. One cluster-wide lease covers the whole writable database set, never independent elections per DB.
3. An unfenced or uncertain old writer prevents promotion. Operator mode cannot bypass this invariant.
4. Restorers and TrailBase writers never operate concurrently on the same database file.
5. All required databases, release artifacts, config, and key versions must pass promotion checks.
6. Each leadership activation has a new HAT epoch and isolated backup namespace. Old history is quarantined, not merged.
7. A lease object, discovery record, elapsed timeout, and backup position are different kinds of evidence; none alone proves all the others.
8. Missing, inaccessible, or corrupt backups on an existing cluster are errors, never permission to initialize empty databases.
9. Read-offload eligibility is an explicit allowlist with staleness/security constraints. Default routing remains primary-only.
10. Recovery of a failed primary means rejoining as a freshly seeded standby, not automatic failback.

See the [proposed protocol](../architecture.md) for the sequence and its unresolved integration points.

## 5. Service and data guarantees

**RPO** is the amount of acknowledged application data that may be lost, not the configured upload interval. **RTO** is time until the chosen service is usable again, not time until a lease is obtained. Define separate write/API, read, auth, storage, and realtime recovery objectives.

Approximate critical path:

`RTO = detection + safe lease/fence completion + catch-up/validation + new backup activation + TrailBase startup + routing/reconnect`

Some operations can overlap; measurements must use the full client-visible path. Large DBs, migrations, busy readers, S3 throttling, and epoch reseeding affect the result.

No numeric budget is approved yet. Automatic failover must stay disabled until the operator specifies acceptable time/transaction loss, how uncertainty is handled, and required evidence. A quiet DB is not necessarily a stalled replicator, and a fresh object listing is not proof that the dead primary uploaded its last acknowledged commit. Use commit/backup watermarks and externally observed heartbeats with explicit uncertainty; unknown RPO requires review or refusal.

Even primary-only reads cannot guarantee that data survives subsequent failover. Applications needing durable business operations require idempotency and reconciliation; a future remote-durability acknowledgement barrier would need its own end-to-end protocol and tests.

## 6. Milestones and exit gates

| Stage | Deliverable | Exit condition |
| --- | --- | --- |
| M0: qualify the premise | Version-pinned experiments and compatibility report | Follow/recovery, writable startup, multi-DB policy, provider CAS, and chosen fencing assumptions demonstrated; limitations recorded |
| M1: recover safely by operator command | Minimal supervisor, single deployment backend, data-hot standbys, manual promotion/rejoin, primary-only ingress, runbooks | Repeated fence/promote/rejoin drills; no shared-prefix corruption; no unfenced override; recover all supported state |
| M2: automate bounded failover | Detection, eligibility/RPO policy, race-safe election, resumable transitions, alerts | Partition/suspension/process-crash tests pass; explicit RPO/RTO evidence; unknown states stop safely |
| M3: optional read scaling | Qualified read-only TrailBase mode, route allowlist, lag gates, auth restrictions | Hidden-write audit and concurrent-follow tests pass; stale/security behavior documented and tested |
| M4: operational hardening | S3 and R2 qualification, restore/PITR drills, upgrade checks, cost/load tests, packaging | Published support matrix and measured SLO envelope; second provider earns support through testing |
| Later | Realtime replay, durable jobs, richer rollout helpers, aggregated log analytics | Only when demanded by application requirements |

M1 is deliberately manual before M2 automation; the project goal remains automatic HA. Platform support and provider support may be narrower at each stage.

## 7. What HAT will build

A small supervisor around existing binaries, not a TrailBase fork by default. Its responsibilities are process ownership, role transitions, lease integration, readiness, epoch metadata, promotion checks, and operator actions. Reuse one established ingress and one proven external fence rather than designing pluggable frameworks first.

[Work register](../work-register.md) specifies components, dependencies, acceptance tests, and stable issue IDs. [Deployment contract](../deployment.md) specifies desired node and bucket setup; examples are illustrative, not installable configurations. [TrailBase state](../trailbase-state.md) enumerates state that database replication alone does not cover.

Execution planning comes after M0: choose implementation language/backend, turn each accepted work item into concrete files, tests, commands, and reviewable tasks. Do not scaffold an unvalidated production controller now.

## 8. Questions for the next discussion

Priority order:

1. **Cloud provider/fencing:** cloud VMs are selected. Which VM provider should we qualify first, and what confirmed power-off/termination and restart-prevention guarantees does its control plane provide?
2. **Loss and downtime:** what acknowledged-write loss is acceptable, and for which data? What write/API RTO is useful? Is operator review acceptable when loss cannot be bounded?
3. **Hotness:** is data-hot/process-stopped an acceptable first milestone while genuine read-only TrailBase support is established?
4. **Database semantics:** are attached DBs independently recoverable, or do transactions/workflows require cross-DB invariants? Can failover invalidate sessions and require reauthentication?
5. **Storage provider/region:** AWS S3 or Cloudflare R2, single-region or cross-region? This choice is separate from the VM provider. Coordination and backup availability are shared dependencies.
6. **Reads:** public eventually-consistent reads only, or auth-sensitive reads? Which maximum stale/revocation windows are acceptable?
7. **Side effects:** any cron, email, webhook, payment, queue, object deletion, or custom runtime handlers that need idempotency or durable replay?
8. **Project policy:** choose a license before distributing implementation; public visibility alone does not grant an open-source license.

None of these questions blocks publishing this initial master plan. Unanswered choices must remain visible rather than becoming accidental guarantees.
