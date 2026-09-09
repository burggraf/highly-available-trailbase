# Work and issue register

Status: planning backlog with one bounded local experiment completed. The [M0 local report](reports/m0-local-failover.md) is evidence only for its explicit scope; it does not close the broader issues below. IDs are stable document references, not GitHub issue numbers. Priorities: P0 = safety/feasibility blocker; P1 = required for a useful supported release; P2 = optional/later. “Proposed” is a decision to discuss, not an accepted implementation.

## 1. Concrete build inventory

Prefer one small supervisor executable plus generated config and tests. Choose its language after M0; Go may make reuse of Litestream's leaser straightforward, but that is not a decided dependency or a reason to reimplement TrailBase.

| Component | Exact responsibility / output | Reuse / boundaries |
| --- | --- | --- |
| Qualification harness | Launch pinned binaries against disposable DBs, storage endpoints and generic fencing fixtures; collect integrity, positions, process traces and client operation ledger | Local tests first; later private VPS deployment validation; sanitized evidence, no hosting-specific dependencies |
| Inventory/config validator | Discover declared DB files; validate required/optional policies, no path alias/collision, roles, versions, secrets references, object store and fence availability | Fail closed on undeclared mutable DBs; no speculative config framework |
| Node supervisor | Own subprocess groups; persist/reconcile state transitions; role readiness; no auto-primary restart | Existing OS service manager for lifetime; reuse Litestream subprocess functionality where proven |
| Coordination/activation integration | One lease; renewal deadlines; uncertain-outcome reconciliation; fresh epoch allocation; safe discovery publication | Reuse Litestream S3 primitives only where the full contract holds; one backend first |
| Fencing contract | Invoke a trusted operator-supplied executable for the exact old node/boot; validate completion evidence and fail closed | Generic contract/fixtures only; hosting-specific code and target mappings live outside the repo; no adapter framework |
| Replication lifecycle | Generate per-epoch configs; run one primary replicator / per-DB followers; collect progress, handle gaps and clean reseeds | Litestream remains responsible for SQLite backup format and transport |
| Promotion/recovery operations | Eligibility, fence, choose/validate recovery cut, stop followers, activate epoch, start writer, publish, reseed peers | Same safe path for manual and automatic operation; resumable, idempotent transitions |
| Ingress integration | Stable primary endpoint; role/epoch-aware health; demotion/drain; optional allowlisted read endpoint | Existing managed LB or established proxy, not a new HTTP implementation |
| Operator surface | Proposed actions: status, bootstrap, switchover, promote, quarantine, rejoin, restore, validate, diagnose | Names/API not frozen; authenticated audit trail; no unsafe force-promote escape hatch |
| Metrics/events | Per-DB history/lag, conservative lease state, eligibility reasons, process/disk health, measured RPO/RTO | Reuse Litestream metrics/IPC; additional HAT state only |
| Packaging/runbooks | Pinned artifacts, generic Linux VM setup, capability checks, secret handling, upgrades and disaster recovery | No hosting-provider provisioning or integrations; no pretend-ready deployment bundle before safety tests |
| Service-hot read-only TrailBase capability | Genuine read-only opens and initialization, no background mutations or WAL conversion, local writable logs, cache refresh strategy | Eventual requirement for every standby; prefer upstream contribution; no fork assumed; do not substitute route filtering |

## 2. Safety and replication issues

| ID | Priority / stage | Issue and current direction | Required evidence / done when |
| --- | --- | --- | --- |
| HAT-001 | P0 M0 | Pin current upstream binaries and embedded SQLite versions | Record checksums/platform/help; test exact pair; upstream changes invalidate qualification |
| HAT-002 | P0 M0 | Follow correctness under real SQLite access | Multi-page transactions, long-lived readers, DDL, cache invalidation, truncate/vacuum/page-size behavior, lock pressure all pass on target platform |
| HAT-003 | P0 M0–M3 | Read-only TrailBase is absent in baseline | Run actual-binary service-hot tests covering startup, reads, auth, jobs, logs, WAL/SHM, locks, follow/catch-up, restart and interrupted restore across all required DBs. Require zero business-DB writes and no Litestream interference. If the tests fail and no supported upstream/approved mode fixes them, abandon read replicas and retain data-hot fallback |
| HAT-004 | P0 M0 | Provider-neutral independent fencing contract | Fixtures cover confirmed isolation, no-op/failed/missing fence, timeout, stale evidence and delayed retries against a new incarnation; deployment validation required before automation; restarted nodes cannot mutate before safe rejoin |
| HAT-005 | P0 M0–M1 | Integrate S3 lease lifecycle; released CLI does not do it | Acquire/renew/loss/expiry/release and child shutdown proven; no undocumented `lease:` config |
| HAT-006 | P0 M0 | Time/lease safety model | Bound skew, renewal latency, scheduling and suspend behavior; unknown timing forces stop; late renew never revives an old activation |
| HAT-007 | P0 M0–M1 | Safe activation publication and epoch ordering | Concurrent candidates/stale publishers cannot advertise an unauthorized writer; missing lock/generation reset/ABA and lost responses tested |
| HAT-008 | P0 M0–M1 | Prevent shared backup-prefix corruption | New namespace each activation; stale/in-flight old upload cannot change successor data; restored lineage verified |
| HAT-009 | P0 M0 | RPO evidence and accepted loss budget | Owner approves policy; distinguish applied/remote/acknowledged positions and idle/stalled state; unknown loss blocks automatic promotion |
| HAT-010 | P0 M0 | Multi-DB recovery semantics | Inventory includes main/session/all attached DBs; document independent vs coupled state; skew tests reject unsupported combinations |
| HAT-011 | P0 M0–M1 | Clean follow-to-write handoff | All readers/followers stopped; valid file set; journal transition and fresh replication metadata; new remote baseline restorable before readiness |
| HAT-012 | P0 M0–M1 | Restore errors and interrupted page application | Kill mid-apply, truncated LTX, checksum failure, disk full, missing TXID, retention gap, and unbounded retry cannot yield eligible corrupt output |
| HAT-013 | P0 M1 | Strict bootstrap/missing-data distinction | Empty/missing backup, auth failure, timeout, wrong prefix and absent attached DB never create empty state in an existing cluster |
| HAT-014 | P0 M1 | Safe old-primary rejoin | Returns fenced, forensic copy preserved, no auto-failback or WAL merge; clean seed rejoins current epoch |
| HAT-015 | P0 M1–M2 | Resumable crash-safe transitions | Inject supervisor/process/host failure after every promotion/switchover step; reconciliation never creates a second mutator |
| HAT-016 | P0 M0/M4 | Actual S3/R2 coordination semantics | Test simultaneous CAS create/replace/release, stale ETags, 409/412, permission changes and lost responses; endpoints lacking required semantics cannot enable automation |
| HAT-017 | P1 M1 | Manual switchover and quiesced checkpoint | Drain all mutators; verify IPC sync and per-DB cut; successful restore with no acknowledged loss in the controlled drill |
| HAT-018 | P1 M2 | Failure detection and candidate selection | HTTP failure alone never elects; all-required-DB eligibility, preference/backoff, lease contention, cooldown and flapping tested |
| HAT-019 | P1 M1–M2 | Storage/control outage policy | Primary stops on authority uncertainty; no automatic second coordinator/provider fallback; degraded behavior documented |

## 3. TrailBase/application issues

| ID | Priority / stage | Issue and direction | Required evidence / done when |
| --- | --- | --- | --- |
| HAT-020 | P0 M0/M3 | Hidden writes and startup jobs | Trace migrations, trigger creation, optimize, auth, admin, system/WASM jobs, SIGHUP, preferences, checkpoints; readonly profile cannot mutate followed DBs |
| HAT-021 | P1 M1/M3 | Logs stay node-local | Never restore primary logs over a running replica's log DB; optional per-node/per-generation backup; correct local retention and disk limits |
| HAT-022 | P0 M0–M1 | Auth continuity and security rollback | Shared required keys/config; login/refresh/logout/OTP/OAuth tested across failover; stale revocation and lost auth changes have explicit fail-closed/relogin policy |
| HAT-023 | P0 M1 | Shared application object storage | Validate S3/R2 config; upload/download/update/delete across promotion; no local-only uploads or replica-side object mutation |
| HAT-024 | P1 M0–M1 | Object/DB transaction gap and deletion retention | Failed upload/DB commit and stale file reads recover or fail as specified; PITR references preserved; immediate deletion limitation resolved or support restricted |
| HAT-025 | P1 M1 | Realtime continuity is not replica page replay | Primary-only SSE; streams close on demotion; clients reconnect/resubscribe/refetch; missing/duplicate notifications explicitly tolerated |
| HAT-026 | P1 M1 | Cron/WASM/email/webhook side effects | Only authorized primary starts jobs; application idempotency/outbox/reconciliation for crash ambiguity; no exactly-once claim |
| HAT-027 | P1 M1–M3 | Schema/config/runtime cache consistency | App/DB/key fingerprint eligibility; primary-only migrations/admin config; cache refresh or restart on schema changes; no unsafe SIGHUP workaround |
| HAT-028 | P1 M3 | Endpoint-level read eligibility | Enumerate routes; GET auth/custom routes not presumed safe; tests show denied writes and acceptable stale ACL/session behavior |
| HAT-029 | P1 M3 | Read consistency/causality and failover rollback | Primary-only default; read-after-write policy; current-epoch lag bounds; causal tokens if actually needed; primary fallback behavior tested |
| HAT-030 | P2 Later | Durable realtime replay and job replay | Evaluate transactional event/outbox design only if apps need replay; physical backup is not a notification bus |
| HAT-031 | P2 Later | Log aggregation | Optional independent collector with unique node/generation/event IDs, dedupe, access controls and privacy retention |
| HAT-032 | P1 M0/M1 | File-deletion error path | Verify baseline schema/retry-column mismatch and deletion-before-retry behavior; resolve upstream or document mitigation and restrictions before relying on GC |

## 4. Operations, security and scale issues

| ID | Priority / stage | Issue and direction | Required evidence / done when |
| --- | --- | --- | --- |
| HAT-033 | P0 M1 | Bypass-proof access/process boundaries | Raw TrailBase/admin ports private; no sibling service starts writer; stale ingress and orphan process tests pass |
| HAT-034 | P1 M1 | Ingress HA and connection draining | Survives LB instance failure; rejects stale targets; SSE/HTTP keepalive/in-flight requests handled; no blind mutation retries |
| HAT-035 | P1 M1 | Secrets and credential scope/rotation | Distinct control, backup, objects/log access; scoped epochs where possible; key recovery and credential rollover drills; no leaked credentials |
| HAT-036 | P1 M1–M4 | Backup retention and independent recovery | Oldest advertised PITR/lagging follower restores; lifecycle cannot delete needed chain; protected recovery copy and key retention tested |
| HAT-037 | P1 M1–M4 | Node capacity and lag under load | Disk exhaustion, WAL growth, slow storage, long read locks, object throttling, many DBs/readers, large reseed all covered |
| HAT-038 | P1 M2–M4 | Observability and measured objectives | External acknowledged-operation ledger; publish loss/RTO and safety refusals; distinguish process alive from correct role/replication |
| HAT-039 | P1 M1/M4 | Upgrade/migration/rollback process | Homogeneous qualified releases; incompatible skew disables promotion; controlled migrations and restore rollback documented |
| HAT-040 | P1 M1/M4 | Total loss/PITR and object recovery | Full restoration to new nodes from remote data + secrets + artifacts + objects; no dependence on dead node disks |
| HAT-041 | P1 M4 | Fault domains and deployment capabilities | Failure matrix includes ingress, fence, S3/R2, time, identity and network dependencies; publish capability assumptions, not hosting-provider certification; independent-authority failover not implied |
| HAT-042 | P1 M4 | Replication cost/performance | Measure polling/list/GET/PUT, compaction, snapshots, per-epoch reseeds and egress; cost budget plus sustainable lag limits |
| HAT-043 | P2 Later | Asset-release assistance, not distribution | Optional manifest/hash verification and rollout preflight; developer retains deployment responsibility |
| HAT-044 | P1 M1 | Configuration/operator trust boundary | Validate names/paths/URLs, protect control API, audit privileged actions, reject conflicting inventories and unsafe force flags |
| HAT-045 | P1 Before distribution | Apache-2.0 selected by the owner; supply-chain work continues | Repo license recorded; M0 binary provenance/checksums documented; update/security process remains to be defined |
| HAT-046 | P2 Later | Multi-region or zero-RPO redesign | Separate ADR and proof if requirements exceed asynchronous single-authority architecture |
| HAT-047 | P1 M1 | Health/readiness contract | Separate agent liveness, primary write readiness, reader freshness and HA redundancy; safe alerts/restarts avoid promotion storms |
| HAT-048 | P1 M0 | Complete DB inventory, including latent/new state | Do not rely only on built-in backup inventory; detect future `queue.db`, runtime-opened DBs and attachments; undeclared mutable state fails qualification |

## 5. First experiments, in dependency order

**Completed bounded slice:** the [M0 local follow-to-writer plan](plans/2026-09-07-m0-local-failover-execution-plan.md) was executed on macOS ARM64; see the [sanitized report](reports/m0-local-failover.md) and [runnable harness](../experiments/m0/README.md). It supplies limited evidence for HAT-001, HAT-008, HAT-010, HAT-011, HAT-012, HAT-014, HAT-017, HAT-021 and HAT-022 without closing them. Linux, S3/R2, host failure, external fencing, interrupted page application and production behavior remain unqualified.

1. **Reproducible baseline:** retrieve binaries, checksums and `--help`; initialize an isolated TrailBase fixture with main/session/attached DBs, auth, file columns, migrations, jobs, and a custom mutating GET. Record actual files/SQLite versions and writes.
2. **Follower alone:** replicate and continuously restore each required DB. First qualify the safe data-hot mode with TrailBase stopped; then qualify service-hot mode with TrailBase running read-only. Verify positions, checksums, fresh/idle behavior, restart, missing history, genuine kill mid-apply, corruption, shrink, and large DB recovery.
3. **Read-only gate:** run the actual pinned TrailBase binary against actively followed databases. Test startup, ordinary reads, auth/session reads, long transactions, live schema changes, configured and custom jobs, restart, and interrupted restore while tracing filesystem/SQLite writes, WAL/SHM changes, locks, restore errors, and logical divergence. Never enable reads by making files writable to get past the test. If no supported mode passes, explicitly close the read-replica capability and keep TrailBase stopped on standbys.
4. **Storage gate:** run contention/failure tests against the intended AWS S3/R2 endpoint, not just an emulator. Verify conditional delete explicitly. No production bucket data.
5. **Fence gate:** first exercise the provider-neutral contract with deterministic fixtures: confirmed isolation, failed/no-op/missing fence, timeout, stale evidence, and delayed retries. Then privately validate the actual operator-supplied fence on disposable VPSs with a paused/partitioned old node, stale ingress, and delayed renewal. Resume/restart the old node after takeover; no unauthorized mutation or replication into new history may succeed. Mocks alone do not qualify a real fence.
6. **Recovery cut:** construct a main/session/attached workflow with dependent updates; crash between operations and uploads. Demonstrate the declared recovery policy, including auth fail-closed checks and unsupported-skew rejection.
7. **Integrated switchover/promotion:** quiesced flush, fence, final restore cut, new epoch, writable startup, baseline replication, route change, rejoin. Repeat with failure injected at each transition and with two simultaneous contenders.
8. **Application drill:** auth flows, file upload/update/delete, SSE reconnect, custom jobs and ambiguous non-idempotent request. Validate external ledger vs recovered state.

M0 results should be short reproducible reports: pinned versions, generic environment/capability assumptions, commands with placeholders, expected invariant, observed outcome, sanitized logs/artifacts, and go/no-go decision. Keep actual hosting identities, addresses, credentials and integration code in private operator inventory. Successful happy-path demos do not close failure-mode issues.

## 6. Execution-plan readiness

Provider-independent cloud VMs/VPSs are the selected first deployment target. Before writing a complete execution plan, define the fencing contract, coordination/storage capabilities, RPO/RTO and uncertainty policy, supported DB semantics, hotness/read scope, auth recovery, object-retention restrictions, implementation language, and licensing. Hosting-provider selection or certification is not a prerequisite or repository responsibility; validation of a particular deployment is an operator responsibility before enabling automation.

Then turn M1/M2 issues into small implementation tasks with concrete files, runnable tests, acceptance commands, and review checkpoints. M3 should remain blocked while HAT-002/HAT-003/HAT-020 are unresolved. Do not turn these tables into dozens of empty modules, config interfaces, or GitHub tickets before prioritizing the experiments.
