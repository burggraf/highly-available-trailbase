# V1 Single-Controller Manual Failover Implementation Plan

> **REQUIRED SUB-SKILL:** Use the executing-plans skill to implement this plan task-by-task.

**Goal:** Deliver a small Rust proxy/controller system with one TrailBase writer, continuously restored standbys, and safe operator-triggered switchover, failover and rejoin.

**Architecture:** A Rust proxy runs on every data node and forwards every application request to the current primary. One non-HA controller monitors nodes and serializes manual operations using a durable local journal; node agents supervise pinned TrailBase/Litestream executables. Standbys keep TrailBase stopped, while a separate request-routing function leaves a narrow extension point for future qualified, scoped replica reads.

**Tech Stack:** Rust, a single Cargo package/binary, Tokio and an established HTTP/TLS stack, SQLite for local control journals, separately pinned TrailBase and Litestream, Linux/systemd, S3-compatible backup storage. Select library families during Task 1; resolve/pin exact crates in the package lockfile as each slice needs them, beginning in Task 2. No Raft, coordination service or new replication engine.

**Status:** Owner-approved scope; proposed implementation details and acceptance plan. Written 2026-09-11. No implementation, deployment, paid infrastructure, live failover, commit or push is authorized by this document alone.

---

## Execution state and acceptance

This section is the authoritative restart tracker. Follow [AGENTS.md](../../AGENTS.md). The task descriptions below remain the roadmap; historical Python task numbers are unrelated to these V1 stages.

**Workflow approval:** owner selected “finish one explicitly authorized stage, including test/fix/review iterations; stop when its acceptance criteria pass” and allowed local checkpoint commits, with merge/push still requiring approval. This supersedes the default no-commit statement above only for task-owned local checkpoints. It does not authorize later stages or external effects.

| Stage | State | Acceptance/authorization |
| --- | --- | --- |
| Task 1 — contracts/prerequisites | in_progress | Owner architecture decisions captured; action/security/native gates still open. Not a blocker to the explicitly authorized inert Task 2 slice. |
| Task 2 — package/config/routing | accepted | Owner approved T2-AC1 through T2-AC7 in this session. Local inert implementation accepted at checkpoint `3d262a3`; no Task 3 or external effects started. |
| Task 3 — proxy/peer transport | accepted | Local-only criteria T3-AC1 through T3-AC5 passed on `main`; production TLS/peer identity, deployment, controller integration, and native qualification remain deferred. |
| Task 4 — lifecycle/replication | accepted | Local fixture-only criteria T4-AC1 through T4-AC5 passed on `main`; native TrailBase/Litestream, systemd, deployment, and live effects remain deferred. |
| Task 5 — controller/dashboard/restart | pending | Not authorized; action/security contracts must be approved first. |
| Task 6 — restore/fence boundary | pending | Not authorized; fake adapters do not authorize live fencing. |
| Task 7 — planned switchover | pending | Not authorized; Task 5/6 and fixture approval required. |
| Task 8 — failover/rejoin | pending | Not authorized; accepted Task 7 required. |
| Task 9 — deployment/native acceptance | pending | Not authorized; explicit disposable infrastructure and deployment approvals required. |
| Task 10 — fault/release qualification | pending | Not authorized; workload, attempt budget and soak approval required. |

### Task 2 completion contract — approved and accepted

Scope: inert configuration and route validation/selection only. No listener, network call, writer, child supervision, route persistence, activation, failover, or infrastructure operation. Durable route publication remains a later integration gate; this stage tests in-memory replacement without claiming crash durability or controller authenticity.

| ID | Observable acceptance requirement | Required evidence | Result |
| --- | --- | --- | --- |
| T2-AC1 | One package under `rust/`, locked dependencies, a real configuration-check command with documented input/exit semantics. Valid input succeeds; invalid input/arguments fail without leaking supplied content. | `docs/reports/v1-task2-red.txt`; `rust/tests/cli.rs`; `docs/reports/v1-task2-gates.txt` | pass — real binary, bounded stdin, unknown command and fixed refusal output |
| T2-AC2 | Exact config schema is documented and enforced: version, field/key uniqueness, size limits, UUID/name grammar, fixed inventory and known primary, endpoint rules, required main/session and declared aux; duplicates and local logs enrollment refused. Replica reads refused. | `rust/src/config.rs` tests; `rust/tests/cli.rs`; `rust/README.md` schema; gate log | pass — schema, duplicate/unknown fields, endpoint/name/path/database/refusal cases covered |
| T2-AC3 | Path rules are explicit and executable: reject unsafe/invalid paths; distinguish lexical validation from actual ownership/permission/symlink checks. No claim of private storage based only on a string prefix; never open referenced secrets/DBs. | `rust/src/config.rs` path tests; `rust/tests/cli.rs`; `rust/README.md` deferred-check statement | pass — lexical `/var/lib/hat` policy rejects relative/traversal/temporary paths; no filesystem access or privacy claim |
| T2-AC4 | Strict versioned route wire record binds cluster, primary node, writer epoch, incarnation and release/config digests. Generations use validated decimal strings with numeric comparison; endpoints are resolved only from validated inventory, never supplied by a route. Config hints alone cannot create active authority. | `rust/src/routing.rs` route-wire tests; `rust/README.md` route format; gate log | pass — private validated route fields, exact wire schema, u64 boundary, decimal parsing, duplicate/unknown/wrong-cluster/unknown-node refusal |
| T2-AC5 | GET, POST, GET logout, auth, SSE, admin, and unknown/custom requests all choose the active primary independently of forwarding. No route refuses as unavailable; no expiry on controller disconnect, retry or fallback. | `routing::tests::every_application_request_selects_the_active_primary`; `rust/README.md`; gate log | pass — selection is in-memory and method/path independent; no network/controller/retry/fallback behavior exists |
| T2-AC6 | Lower generation and conflicting equal generation refuse without altering active state; exact duplicate is idempotent; valid higher generation installs as one replacement. | `routing::tests::rollback_and_conflicting_equal_generation_leave_active_route_unchanged`; route-wire tests; gate log | pass — rollback/conflict preserve active route, exact duplicate is idempotent, and validated higher generation replaces once |
| T2-AC7 | Meaningful failing-first evidence, all local gates green, criterion-by-criterion review, accurate docs and restart handoff. | `docs/reports/v1-task2-red.txt`, `docs/reports/v1-task2-gates.txt`, `docs/reports/v1-task2-final-gates-3.txt`, fresh read-only review recorded below, checkpoint `3d262a3` | pass — behavioral RED retained; fmt/test/clippy/locked release/diff gates passed; docs and handoff updated |

`not_run` means the complete criterion has not been verified, not that no related code exists. Existing partial code is not grandfathered into acceptance. Before starting each later stage, expand its numbered requirements and Exit into the same ID/check/result table, get approval of scope/criteria, then execute without seeking approval for each routine local iteration. Native or external gates remain separate and cannot be marked passed by mocks.

### Restart handoff — Task 2 acceptance checkpoint

- **Location:** branch `hat-v1-task2`, worktree `.worktrees/v1-task2` relative to the main checkout; accepted source checkpoint `3d262a3`. No merge/push/deployment performed.
- **Current authorization:** Task 2 and the local-only Task 3 proxy slice are accepted on `main`. Task 4 and later stages remain unauthorized; no external effects are authorized.
- **Implemented:** Cargo package/lock, bounded `hat config check` stdin CLI, exact configuration validation, strict inventory-bound route wire records, primary-only in-memory selection, and route replacement/refusal guards. The binary never opens referenced paths or starts services.
- **Evidence:** `docs/reports/v1-task2-red.txt` retains behavioral CLI RED; `docs/reports/v1-task2-gates.txt` records fmt, 16-test package suite, clippy `-D warnings`, locked release build, and diff-check exits 0.
- **Retained failure history:** the initial real-binary CLI test failed 0/3 before implementation and is preserved in `docs/reports/v1-task2-red.txt`; a later review found missing epoch/incarnation/digest conflict assertions, which were added before final verification. No Python files were changed and no historical live/native harness was run.
- **Review disposition:** fresh read-only reviewer found the implementation security boundaries sound, identified stale docs and incomplete conflict coverage, and returned FAIL. The conflict coverage was corrected; root README, status, Rust README, and this handoff now describe the accepted binary. Filesystem ownership/permissions/symlink safety, database existence/schema, endpoint reachability, proxying, activation, persistence, and failover remain intentionally deferred.
- **Next safe action:** obtain separate authorization and expand the Task 4 acceptance table before implementing lifecycle/replication. Preserve the Task 3 local-only boundary; Task 4 and later stages remain unauthorized.
- **Processes:** no runtime services started by the Rust slice; the managed gate process exited 0 and no active processes remain.
- **Documentation verification:** `rust/README.md`, root `README.md`, `docs/status.md`, this plan, and retained reports match the source checkpoint; `git diff --check` passed after documentation edits. Fresh reviews: initial read-only `reviewer` run `6326f027-2d1e-47e7-80db-bc7ba6ce6e66` found stale docs and missing conflict coverage; follow-up `reviewer` run `5b149332-98f4-4c73-9f7b-7d8e5c6389ad` returned PASS after fixes. Reviewer commands were intentionally none; retained gate logs record independent local commands.
- **Integration:** source checkpoint `3d262a3`; this handoff/status documentation is the task-owned follow-up commit after that source checkpoint. Merge, push, deployment, and worktree deletion remain unapproved.

## 1. Decisions and scope

### Confirmed by the owner

- Rust proxy on every TrailBase data node.
- Exactly one primary; one or more continuously restored standbys.
- V1 forwards **all application requests** to the primary, including reads, authentication, administration, custom routes and realtime.
- TrailBase remains stopped on standbys.
- Preserve the ability to add explicitly scoped local replica reads after suitable TrailBase read-only support is implemented and qualified.
- One controller is acceptable. Its unavailability prevents promotion/configuration changes but must not interrupt otherwise healthy existing-primary traffic.
- Failover is manual. Recent acknowledged writes may be lost; take practical precautions to minimize loss and prevent overlapping writers.
- A browser dashboard is required in V1, directly accessible over public HTTPS with sign-in. Individual local operator accounts all have the same management permissions. CLI access is supplementary, not a replacement.
- Unattended recovery of the existing primary after node-agent restart or host reboot is required. The owner accepts waiting for a reachable controller and fresh authorization before automatically restarting the same primary. An already-running primary continues during controller downtime. This does not authorize automatic promotion of another node.
- The initial acceptance application may exclude custom jobs and uploaded-file mutation; test records, authentication, SSE and main/session/aux databases first.
- Linux version, fencing provider/mechanism and public front door remain pending. Use local fake adapters initially; do not infer deployment choices or access existing infrastructure.

The [V1 contract draft](../v1-contract.md) records these approved choices and proposes browser security, operation identity, durable-command and fencing contracts. Action-specific schemas and native qualification remain outstanding; do not describe Task 1 as a qualified implementation.

### Proposed defaults for this plan

- One supported Linux/systemd platform and filesystem profile first; fixed node inventory.
- Serve a small browser dashboard from the same controller binary, using the same operation API as the CLI. No separate frontend service.
- Clean Rust-native installation, not migration of the deployed Python state.
- One cluster-wide mutating operation at a time; no queue or generic force button.
- Independent external fencing for both handover and unplanned recovery in the initial supported path.
- Separate authenticated management and peer-proxy access from public application ingress.
- Implement the approved restart policy with initially closed application admission and fresh incarnation-bound controller authorization. The exact command/acceptance protocol still needs review and executable tests; no cached startup authority.
- Applications using custom jobs or shared-file mutation need an explicit supported recovery policy before onboarding, despite their exclusion from the initial fixture.

### Relationship to previous plans

For the next V1 delivery, this plan replaces the **three-controller/OpenRaft work** in [the earlier Rust architecture](2026-09-10-rust-ha-architecture-design.md). Preserve that document as a deferred direction, not a prerequisite or a mandate to scaffold consensus.

The existing Python `hat/`, `experiments/`, `tests/` and deployment remain unchanged executable references and historical evidence. Do not translate them line by line, import their private deployment state, weaken their strict-loss tests, or claim their previous checks qualify the Rust implementation.

## 2. What V1 must demonstrate

1. A client reaches a stable operator-supplied URL and can use real TrailBase records, authentication and SSE.
2. Requests arriving through any healthy node proxy reach the sole active primary.
3. Every declared required database is backed up and followed on standby nodes; status distinguishes health from mere process liveness.
4. Stopping the controller process does not interrupt application traffic or existing SSE streams. No promotion becomes possible while it is unavailable.
5. An operator can perform a planned switchover and an independently fenced unplanned failover.
6. Old primary data/history is preserved; the old node cannot return as writer and can be reseeded as a standby.
7. Interrupted actions retain their identity and uncertainty. Recovery inspects rather than blindly replays.
8. Operators can monitor nodes, initiate confirmed transitions and inspect/reconcile operations through an authenticated browser dashboard.
9. An unchanged current primary can recover unattended after restart, waiting for the controller when necessary, while former primaries and nodes with conflicting/uncertain actions cannot.

**Durability statement:** Failover uses validated recoverable database positions. Acknowledged writes not present in those positions may be lost. Unless independently established, report the loss amount/time window as unknown—not zero.

## 3. Minimal architecture

```text
                    operator dashboard / CLI
                              |
                     single controller
                      local SQLite journal
                              |
                   authenticated node commands
                              |
public front door --> node proxies/agents --> active primary agent --> TrailBase
                          |                         |
                    standby followers        Litestream uploader
                          ^                         |
                          +---- object storage <----+
```

The controller is **not** a per-request dependency, route lease server, or component of the public front door. Controller-process failure and loss of a whole co-located host are different failures: co-location does not make that host's proxy/application survive host loss.

### One binary, few processes

Proposed commands:

```text
hat node serve             proxy, private node API and child supervision
hat controller serve       monitoring and serialized operation coordinator
hat status                 human-readable or JSON status
hat switchover NODE         planned handover
hat failover NODE          explicit accepted-loss recovery
hat operation inspect ID   inspect progress and uncertainty
hat operation reconcile ID reconcile the same operation, never blind replay
hat rejoin NODE            quarantine/reseed a former primary
hat doctor                 read-only installation/configuration checks
```

CLI spelling is provisional. Serve the dashboard and operation API from the controller binary on an explicitly configured public HTTPS origin, with individual local operator accounts and equal management permissions. Implement password hashing, protected revocable sessions, CSRF/origin checks, login throttling, bounded resources and per-operator audit attribution before exposing it. No public registration or default credentials; propose account maintenance through a protected controller-local CLI. Use supplied TLS certificate/key files rather than building a certificate service. Node/controller transport remains separate, using established TLS with fixed, pre-provisioned peer identities and role authorization. Do not invent a distributed ACL or generic privileged executor.

The dashboard must show node roles, per-database replication observations, stale/unknown health, current route and pending operations. Provide planned switchover, explicit accepted-loss failover, operation inspection/reconciliation and rejoin. Confirmation binds the selected node and observed operation/generation; a stale page or lost browser response never creates a second operation. Start with static assets and a small amount of browser JavaScript; do not add a frontend framework unless required.

Run the node agent unprivileged, owning its TrailBase/Litestream children and data directories. Installation grants only required access. Systemd contains the entire process tree and kills remaining children before restarting the agent. A saved historical primary role is not fresh startup authority. Under the proposed protocol, a restarted node first closes application admission, then the controller may authorize unattended same-primary recovery after checking current authority and pending actions. Qualify process containment and restart authorization before enabling activation.

### Route handling

Persist controller-issued routes containing cluster identity, monotonically increasing route generation, primary node, writer epoch and target incarnation. Proxies install them atomically and reject rollback/conflicting same-generation updates. Restarts may reload routes for forwarding, but routes alone cannot start a writer.

Use one request-routing function separate from HTTP forwarding. In V1 it unconditionally selects the primary. Do not add GET/POST heuristics, replica-selection algorithms, or a generic policy language.

Forward to the primary's authenticated internal proxy endpoint, not an exposed raw TrailBase listener. That endpoint validates the expected primary identity/epoch against local active state and either dispatches locally or refuses; it never forwards again. Strip client-supplied internal routing headers. This prevents proxy loops and lets stale proxies fail closed.

Missing routes fail with service unavailable. A primary connection failure never triggers local promotion or fallback to another writable server. Controller disconnection does not expire a valid active route.

Future scoped reads will add an explicit endpoint allowlist and local-read eligibility checks at this one routing boundary. Until qualified support exists, configuration requesting local database reads must be rejected. The extension must retain primary reads for consistency-sensitive calls and keep writes/auth/admin/unknown routes/SSE on the primary by default.

### Application front door

An operator-supplied load balancer or equivalent routes clients to healthy proxies. HAT supplies readiness endpoints, not DNS/VRRP/cloud-LB management. Direct-node URLs can demonstrate forwarding, but do not qualify stable ingress failover. The front door must also work while the controller is unavailable.

## 4. Safety rules retained without consensus

- **One controller authority:** enforce a single controller process lock on its journal. Do not automatically start a replacement controller from a backup. Replacing its host requires disabling the old authority and reconciling node state and pending effects first.
- **One writer:** independent fencing must exclude the exact old primary, its jobs, object-store writes and writable restart. Health-check failure, route withdrawal and human confidence are not a fence.
- **Durable action identity:** persist intent before sending an action and persist node acceptance before execution. Bind cluster, operation, phase, target incarnation, epoch and parameters. Exact duplicates return recorded status; conflicting duplicates refuse.
- **Uncertainty blocks conflicting work:** a timeout/disconnect does not cancel an action. Keep the operation slot until effects are settled. Do not authorize a new activation, opposite action or rejoin while an earlier accepted/delayed action could still execute.
- **Local guards:** nodes reject wrong-boot, obsolete-epoch and out-of-order commands using durable local state. Startup has no writer admission; any unattended same-primary restart requires fresh authorization under the approved restart protocol. Management authentication alone is not permission to replay an old activation.
- **History isolation:** every promoted writer starts a new backup namespace. Never merge divergent databases or upload both writers into one history.
- **Restore ownership:** stop and confirm exit of every follower before opening restored files writable. Suspect files are retained and restored afresh into a separate directory.
- **No blind HTTP write retries:** a lost response may hide a committed write. Proxying does not provide exactly-once application operations.

Task 1 must freeze the small command/phase contract, including unattended same-primary restart, delayed command handling, browser access protection and controller-replacement refusal conditions. Automatic restart is a serialized mutating operation, not an exception around the journal or fencing guards. These rules are acceptance requirements, not a claim that prose alone constitutes a verified protocol.

## 5. Supported state and recovery policy

Inventory `main.db`, `session.db` and every configured/attached application database explicitly. Keep node-local `logs.db` separate. Enroll and verify compatible configuration, signing keys, migrations, runtime assets and secret-version references before starting TrailBase. Never bootstrap missing restored state into an empty application.

Each database has its own backup history and position. A recorded set of positions is **not automatically a transactionally consistent cross-database snapshot**. Planned recovery uses a quiesced, flushed set. Unplanned recovery requires a declared application policy for independent/skew-tolerant state, plus application/auth validation; workloads requiring an unavailable atomic cross-file cut are unsupported.

The initial fixture includes main, session and one auxiliary database, real login/refresh/revocation behavior, and records. Do not narrow it to a main-only demonstration.

Lost revocations, permissions and external side effects matter even when ordinary write loss is accepted. Relogin alone does not repair lost ACL changes or invalidate all JWTs. Applications requiring stronger semantics must supply a supported recovery procedure or be rejected from the V1 envelope.

Uploads must be external/shared or separately recoverable; database backup does not protect local files. Shared object storage alone does not make file deletion and restored metadata consistent. Start the acceptance fixture without file mutation/custom jobs; explicitly disclose this limit instead of silently promising universal TrailBase compatibility.

Monitor uploaded and restored positions within the same database/history, observation age, last successful progress/check, errors, disk space and child health. Idle databases are not unhealthy merely because their position has not advanced. Backup gaps and storage outages alarm; the initial async policy permits the existing primary to keep serving, with widening or unknown loss exposure. No claimed hard RPO without enforcement and measurement.

## 6. Transition sequences

### Planned switchover

1. Lock the operation, persist intent, validate identities/configuration and target eligibility.
2. Close application admission at the primary agent, including existing streams; stop/drain TrailBase and its mutators. Do not depend on every remote proxy receiving a maintenance update.
3. Flush each enrolled database through the pinned Litestream sync interface, record the quiesced position set, stop the uploader, and confirm old-primary fencing.
4. Catch up/freeze the candidate, or perform finite restore to the recorded positions. Stop all followers.
5. Validate exact restored positions, integrity, release/configuration and application/auth invariants. Use a separate finite restore as comparison; do not run writable validation on candidate files.
6. Reserve a fresh epoch/history, activate the candidate behind closed public admission, and establish a remotely restorable new baseline.
7. Persist and distribute the new route, open eligible primary admission and verify the stable endpoint. Partial proxy updates remain visible; stale proxies refuse or hit the fenced old target rather than loop.
8. Finish the handover with old-node quarantine recorded. Rejoin is a separate operation so an offline old host does not keep a successful handover indefinitely open.

### Unplanned failover

1. Persist explicit operator intent and possible-loss acceptance.
2. Independently fence the old primary; uncertain fencing stops here.
3. Inspect available history and candidate positions. Select and validate the latest usable per-database set permitted by the application policy; report missing/unknown observations honestly.
4. Restore/freeze and validate the candidate, then use the same activation, new-baseline and route-publication path as planned switchover.
5. Report selected positions, validation results and known loss/ambiguity. An absent complete client ledger is not evidence of zero loss and is not a hidden requirement to build a durability gate.

### Unattended same-primary restart — approved policy, protocol draft

1. Start the node agent/proxy without TrailBase writable admission; generate a fresh agent incarnation, including on a same-boot agent restart.
2. Ask the controller to reconcile the current writer identity and durable operation state. Do not treat a saved route or a locally remembered role as authority.
3. If this is still the current primary and no conflicting/uncertain action or fence is outstanding, serialize and journal a restart operation. Validate retained local database/history, release/configuration and process containment before issuing incarnation-bound authorization.
4. Restart the same primary without operator approval, validate readiness/replication and publish the route for its new incarnation. Same-history resume versus a fresh history after detected rollback must be qualified; do not choose blindly.
5. If the node is a former primary, keep it quarantined. If the controller is unreachable, wait and retry observation/authorization rather than execute a cached activation. Existing accepted actions are reconciled, not retried as fresh effects.

This is not automatic failover. The owner approved the controller-unavailable waiting rule; the detailed safety protocol must still be implemented and qualified.

### Rejoin and interruption

- Rejoining nodes start cold, with old data/history preserved. Settle any pending provider power action before reboot/reuse; never risk a delayed old fence hitting the new incarnation.
- Restore into a clean directory from the current primary's history, verify it, and start followers only. Never resume the former writer's divergent files.
- Controller restart loads the journal, observes nodes and exposes unfinished operations. Reconciliation may record an independently established completed result or continue a proven unexecuted next step. Unsettled outcomes remain blocked; no journal deletion or generic force override.
- SSE clients reconnect/resubscribe/refetch after a transition. Durable replay and gapless events are not promised.

## 7. Implementation tasks

### Working discipline

Use one Cargo package under `rust/`; add modules only when their task needs them. Proposed file names below are concrete starting points, not a requirement for factories/traits or one abstraction per file. Existing Python runtime and deploy files stay untouched.

For each behavioral slice: write a failing test, run that named test to confirm the intended failure, implement the minimum behavior, rerun it and the package suite, then review the diff. Integration tests must execute the real Rust entrypoint; mocked subprocess outputs are not native qualification. Commit reviewed increments only when authorized.

Common local checks once the package exists:

```sh
cargo fmt --manifest-path rust/Cargo.toml --check
cargo test --manifest-path rust/Cargo.toml
cargo clippy --manifest-path rust/Cargo.toml --all-targets -- -D warnings
cargo build --manifest-path rust/Cargo.toml --release --locked
git diff --check
```

All must exit zero before a milestone is described as locally passing. Use the process tool for long-running build/test/server commands. Keep native/fault checks explicit and separate from ordinary unit tests so default testing never touches real infrastructure.

### Task 1 — Freeze the narrow contract and native prerequisites

**Files:** create `docs/v1-contract.md`; reference `docs/trailbase-state.md`, `docs/upstream-findings.md`, `tests/fixtures/README.md`, `hat/control.py`, `hat/transition.py`, `hat/recovery.py` and their relevant tests.

1. Record the confirmed public HTTPS/local-account dashboard, controller-dependent unattended restart and initial-fixture requirements. Leave deployment choices explicitly pending; specify browser security and secret provisioning before enabling public access.
2. Specify exact configuration/command/result fields, limits, role authorization, local state transitions, route admission and restart behavior. Define durable intent/acceptance ordering and delayed-action rejection before implementing mutation, including the race between same-primary restart and a manually requested failover.
3. Define the operator-supplied fence adapter's action/inspection inputs and terminal evidence, exact target binding, response-loss settlement and restart containment. Missing provider guarantees block live promotion, not local fake-adapter work.
4. Resolve current Rust library documentation; choose one HTTP/TLS stack and SQLite binding. Pin compatible crate versions/features in Cargo.lock as the first package and later slices add them; no unused dependency scaffold in this documentation task. Retain the historical external binary baseline until explicitly requalified.
5. Define finite native restore, child-containment and follower-stop checks to run once the relevant Rust slices exist. Reuse existing observed semantics; no new all-purpose qualification harness.

**Exit:** a small reviewable contract, concrete pending deployment inputs and testable refusal cases. No consensus research or feature scaffolding. Timebox approximately one working day; unresolved external guarantees are explicit blockers rather than guessed contracts.

### Task 2 — Package, configuration and primary-only routing

**Execution: accepted at checkpoint `3d262a3`.** See [completion criteria and handoff](#execution-state-and-acceptance). Task 3 remains unauthorized.

**Files:** create `rust/Cargo.toml`, `rust/Cargo.lock`, `rust/src/main.rs`, `rust/src/config.rs`, `rust/src/routing.rs`; tests alongside modules.

1. Add a minimal binary and configuration check. Write negative cases for duplicate node IDs, unknown primary, invalid/private paths, missing required DB inventory, incompatible schema version and requested replica reads.
2. Test that GET, POST, GET logout, SSE subscription, admin and unknown/custom requests all select the configured primary.
3. Implement only primary routing; keep selection independent of forwarding. Test missing route, route rollback and conflicting equal generation refusal.

**Check:** `cargo test --manifest-path rust/Cargo.toml routing` and the package suite.

**Exit:** inert configuration/routing functionality; nothing can launch a writer or change a service.

### Restart handoff — Task 4 acceptance checkpoint

- **Location:** `main`; Task 2 and Task 3 remain in the current dirty source tree, with Task 4 fixture-only lifecycle/replication changes added locally.
- **Authorization:** Task 4 is accepted only for local fixture behavior. Task 5 and later stages remain unauthorized; no native TrailBase/Litestream, deployment, systemd, activation, failover, or external effects occurred.
- **Implemented:** closed node admission, exact incarnation-bound activation grants, multi-restart incarnation tombstones, bounded child ownership/reaping, admission closure on child stop, declared-database replication configuration, ownership exclusion, and separate unknown observations.
- **Evidence:** `docs/reports/v1-task4-red.txt`, `v1-task4-gates.txt`, `v1-task4-final-gates.txt`, and `v1-task4-review.txt`; final package run passed 32 tests and all required local gates.
- **Next safe action:** before Task 5, obtain separate authorization and expand its acceptance table. Preserve the local-only boundary and do not start native qualification from this handoff.
- **Processes:** no active Task 4 services; fixture children are reaped by tests.

### Task 3 completion contract — approved for local-only implementation

Scope: real local HTTP forwarding through the Rust binary, with a separate private peer entry point and bounded refusal behavior. No controller dependency, activation, persistence, failover, TLS deployment, or external/native effects. Local test certificates or an explicit test-only peer authenticator may be used; this slice must not claim production peer authentication or deployment qualification.

| ID | Observable acceptance requirement | Required evidence | Result |
| --- | --- | --- | --- |
| T3-AC1 | The real binary accepts public HTTP requests and forwards method, path/query, headers, cookies, authorization, request body, status, response headers, redirects, errors, and streamed response bytes once to the active primary. | `rust/tests/proxy.rs`; `docs/reports/v1-task3-final-gates.txt` | pass — real-binary loopback tests cover forwarding, redirect, error and SSE-style stream responses |
| T3-AC2 | Forwarding is bounded and streaming: request/response bodies are not eagerly buffered, management-style limits do not cap application streams, hop-by-hop headers are normalized, and upstream connection loss is returned without retry. | `rust/tests/proxy.rs`; final gate report | pass — bounded input, direct streaming bodies, single-attempt client, request/response hop-by-hop stripping, and disconnect/no-retry are covered; no stress/soak claim |


| T3-AC3 | Client-controlled routing headers cannot select a target; targets come only from the validated active route, missing/stale routes refuse, and controller absence does not interrupt an already configured route. | routing/proxy integration tests | pass — public routing headers refuse, validated route is required for normal startup, missing route returns service unavailable, and no controller dependency exists |
| T3-AC4 | A distinct internal peer endpoint accepts only the configured authenticated peer boundary, rejects unauthorized peers and forged internal headers, dispatches locally without proxy loops, and does not log credentials or bodies. | private-peer refusal/loop tests; no live TLS claim | pass for local-only boundary — exact token/epoch/node/incarnation checks and dispatch guard tested; bearer token/plain HTTP are explicitly not production authentication |
| T3-AC5 | Meaningful failing-first real-boundary evidence, full Rust gates, diff review, and updated usage/handoff documentation are retained. | `docs/reports/v1-task3-red.txt`, `docs/reports/v1-task3-gates.txt`, `docs/reports/v1-task3-final-gates.txt`, `docs/reports/v1-task3-review.txt`, fresh review | pass — RED, 24-test final suite, all gates, review findings/fixes, and docs are retained |

Approved scope reference: owner authorization in this session. This local slice does not authorize public deployment, certificate/account creation, live services, native qualification, or claiming production-grade peer authentication.

### Task 3 — Streaming proxy and authenticated peer transport

**Files:** create `rust/src/proxy.rs`, `rust/tests/proxy.rs`; extend configuration/routing/main.

1. Start test upstreams and exercise real request bodies, cookies, Authorization, errors, redirects, uploads, streaming responses and disconnects through the actual binary.
2. Implement public forwarding and a distinct authenticated internal endpoint; normalize hop-by-hop headers, preserve HTTP semantics and trusted public-origin handling, impose bounded resources/backpressure, and never log credentials/bodies.
3. Test forged routing headers, unauthorized peers, stale target epoch, forwarding loops, connection loss after upstream commit and SSE delivery without buffering. Do not retry application requests after uncertain forwarding.
4. Verify controller disconnection cannot affect forwarding. Admission must be local; initially test it with inert controlled state until node activation exists.

**Check:** `cargo test --manifest-path rust/Cargo.toml --test proxy`.

**Exit:** a real forwarding demo, including SSE. No failover claim yet. Qualify WebSocket upgrades if a declared application needs them; SSE support alone is not WebSocket support.

### Task 4 completion contract — approved for local fixture-only implementation

Scope: node admission state, incarnation-bound activation, bounded child ownership, and per-database replication observations using temporary loopback/process fixtures. No TrailBase/Litestream execution, native restore, systemd, deployment, activation of real writers, or external effects. Native checks remain Task 9-gated.

| ID | Observable acceptance requirement | Required evidence | Result |
| --- | --- | --- | --- |
| T4-AC1 | A node starts with a fresh incarnation and closed application admission; only an exact cluster/node/incarnation/writer-epoch activation grant can open it. Restart creates a new incarnation and closes admission; stale/wrong grants refuse. | `rust/src/node.rs` lifecycle tests; `rust/tests/node.rs`; Task 4 reports | pass — exact grants, closed startup, multi-restart invalidation, same-incarnation and reused-incarnation refusal |
| T4-AC2 | Owned child processes are bounded and reaped; child exit/crash is observable, stop closes admission, and no second follower/uploader ownership can be acquired concurrently. | `rust/src/node.rs` child tests; `rust/src/replication.rs` ownership tests; final gates | pass — two-child bound, explicit/drop reaping, exit observation, admission closure, and ownership exclusion |
| T4-AC3 | Replication configuration is derived only from the declared required database inventory, excludes local `logs`, and distinguishes primary versus stopped-standby role without starting TrailBase/Litestream. | `rust/src/replication.rs` config tests; final gates | pass — declared inventory and role only; native services were not started |
| T4-AC4 | Per-database observations separately report process liveness, progress position/age, errors, and recoverability; missing/unknown observations are not converted into healthy state. | `rust/src/replication.rs` observation tests; final gates | pass — fields remain separate and unknown is unhealthy |
| T4-AC5 | Meaningful failing-first evidence, full Rust gates, read-only review, and updated usage/handoff documentation are retained. | `docs/reports/v1-task4-red.txt`, `v1-task4-gates.txt`, `v1-task4-final-gates.txt`, `v1-task4-review.txt`, plan handoff | pass — RED, 32 tests, all gates, final review, fixes, and docs retained |

Approved scope reference: owner authorization in this session. This fixture-only slice does not authorize native TrailBase/Litestream checks, systemd, deployment, live services, activation, failover, or external effects.

### Task 4 — Node lifecycle and continuous replication

**Files:** create `rust/src/node.rs`, `rust/src/replication.rs`, `rust/tests/node.rs`; later native checks in `rust/tests/native.rs`.

1. Test admission-closed startup, wrong-incarnation activation refusal, no simultaneous follower/uploader ownership, child crash and orphan containment using temporary unprivileged fixtures. Old activation grants must not survive an agent restart on the same host boot.
2. Implement supervision, protected state paths and exact declared-DB Litestream configurations. TrailBase listens only on protected local interfaces and never runs on a standby.
3. Add per-DB position/health observations using pinned machine-readable interfaces where available. Treat process liveness, progress and recoverability as separate facts.
4. Run explicit native checks for initial restore, interrupted follow, orderly follower stop and Linux service restart containment. Do not open suspect follow files writable to investigate them.

**Check:** `cargo test --manifest-path rust/Cargo.toml --test node`; separately approved native test invocation from Task 9.

**Exit:** one isolated primary and one stopped-TrailBase standby with visible replication. Automatic writer activation is still unavailable.

### Task 5 — Single controller, monitoring and durable actions

**Files:** create `rust/src/controller.rs`, `rust/src/journal.rs`, `rust/src/auth.rs`, `rust/tests/controller.rs`, `rust/ui/index.html`, `rust/ui/app.js`, `rust/ui/style.css`, `rust/tests/dashboard.rs`; extend node/main. Embed assets in the same binary.

1. Test one process/operation lock, durable intent before send, node acceptance before effect, exact duplicate results, conflicting duplicates and restart with an unfinished phase.
2. Implement the contract with local SQLite transactions/durability settings and bounded authenticated commands. Route state does not expire merely because the controller disappears.
3. Add shared dashboard/CLI status with roles, positions, observation ages, active operation and refusal reasons. Serialize mutations, not status requests or steady replication.
4. Build the public HTTPS dashboard and local-account/session implementation against that same API. Test TLS-only startup, no default/public-registration account, password-hash verification, login throttling, bounded hash concurrency, secure session cookies, expiration/revocation, unauthenticated refusal, CSRF/origin checks, escaped untrusted status text, stale-page conflicts, double clicks, operation receipt after response loss and accessible controls. Browser refresh/disconnection must not cancel or duplicate accepted work; a blocked transition must not prevent local account disable/session revocation.
5. Kill/restart the controller before/after simulated action acceptance and response loss. Test delayed old commands, node reboot and permanent blocked-uncertain state until evidence settles effects.
6. Implement the approved unattended same-primary restart protocol. Test agent restart, host reboot, controller unavailability, a former primary returning after failover, a restart racing manual failover, and delayed authorization after a newer incarnation. Never bypass operation serialization.

**Check:** `cargo test --manifest-path rust/Cargo.toml --test controller` and `cargo test --manifest-path rust/Cargo.toml --test dashboard`; exercise the actual dashboard in a browser once available.

**Exit:** browser monitoring, protected operation submission and reliable restart/action orchestration with local fixtures. No provider power actions yet.

### Task 6 — Restore validation and fencing boundary

**Files:** create `rust/src/restore.rs`, `rust/src/fence.rs`, `rust/tests/recovery_boundaries.rs`.

1. Test missing DB, wrong history/position, schema/config/key mismatch, corrupt/truncated restore and failed application/auth validation. Compare positions only within their database/history.
2. Implement fresh finite restore and integrity/application checks in isolated workspaces. Candidate validation must not start a mutating TrailBase against the future writer files; any real TrailBase validation runs on a separate copy with external effects contained.
3. Implement one executable fencing adapter contract with bounded input/output and protected credentials; use a fake adapter in default tests.
4. Test wrong target/incarnation, stale evidence, timeout, accepted action with lost response, and a delayed provider effect. Unknown results block activation and node reuse; negative reachability is supplementary evidence only.

**Check:** `cargo test --manifest-path rust/Cargo.toml --test recovery_boundaries`.

**Exit:** restore/fence refusals are executable. Live qualification remains blocked unless the actual provider contract and deployment authorization are available.

### Task 7 — Planned switchover, one vertical path

**Files:** create `rust/src/operations.rs`, `rust/tests/operations.rs`; extend controller/node/restore/proxy as needed.

1. Write the planned sequence test and an invariant asserting no old mutator or candidate follower remains when candidate writable startup occurs.
2. Implement the sequence in Section 6, sharing no more abstraction than the actual activation/route-publication helpers need.
3. Inject failures at each effect boundary, including successful effects with lost responses. Confirm closed admission or fenced old writer, retained intent and no blind replay.
4. Test partial route distribution and controller loss after new-primary activation. Restore service only by reconciling the existing operation, never by automatically reviving the old writer.

**Check:** `cargo test --manifest-path rust/Cargo.toml --test operations switchover`.

**Exit:** a disposable planned handover preserves the quiesced test ledger and changes writer through the same URL. It must finish cleanly at least once before adding more machinery.

### Task 8 — Manual failover, reconciliation and clean rejoin

**Files:** extend `rust/src/operations.rs`, `rust/tests/operations.rs`, `rust/src/main.rs`.

1. Test failover refusal without confirmed fencing, explicit possible-loss acceptance, allowed lost test writes, and unknown rather than invented loss bounds.
2. Implement unplanned recovery through the existing restore/activation path. Do not carry over the Python strict-zero-known-loss guard as an accidental V1 requirement; leave that Python guard unchanged.
3. Implement same-operation inspect/reconcile with the narrow contract; test controller/node crash, delayed activation and unresolved effects blocking conflicting operations.
4. Test and implement quarantine/reseed/rejoin into a new directory. Preserve original files/history and ensure booted former primaries cannot serve writable or upload stale data.

**Check:** `cargo test --manifest-path rust/Cargo.toml --test operations`.

**Exit:** a disposable failover/rejoin demonstration reports observed loss honestly and returns to one writer plus healthy standbys.

### Task 9 — Installable disposable deployment and native acceptance

**Files:** create `deploy/v1/hat-node.service`, `deploy/v1/hat-controller.service`, `deploy/v1/config.example.json`, `docs/v1-runbook.md`, `rust/tests/native.rs`. Keep the old demo units/configuration untouched.

1. Provide manual, deterministic installation steps, protected identities/secrets, directory ownership, network restrictions and read-only `hat doctor`. Do not build a cloud provisioner.
2. Test clean installation, initial activation, unattended current-primary restart, former-primary quarantine, process-tree cleanup, browser access protection, certificate expiry/refusal and manual renewal on the chosen platform.
3. Implement explicit ignored native tests using only a supplied disposable fixture. Require an explicit opt-in and refuse non-disposable paths/targets; default `cargo test` never powers hosts or touches the existing deployment.
4. Verify records/auth/SSE through every proxy and the chosen stable front door; stop the controller during ordinary traffic and active SSE.
5. Document controller backup/recovery: stop or fence old controller authority, inspect durable node state, preserve pending operations, and refuse recovery when authority/history cannot be reconstructed. Restoring a stale journal is not permission to act.
6. Document maintenance upgrade/rollback. Do not promise rolling upgrades; an old binary must refuse incompatible journals/configuration, and schema-changing application rollback requires an explicit recovery path.

**Explicit native command, only after fixture approval:**

```sh
HAT_V1_DISPOSABLE_CONFIG=/absolute/path/to/approved-fixture.json \
  cargo test --manifest-path rust/Cargo.toml --test native -- --ignored --test-threads=1
```

**Exit:** a repeatable installation and runbook, not a collection of manually repaired live commands.

### Task 10 — Fault qualification and release decision

**Files:** extend `rust/tests/native.rs`; create `docs/reports/v1-manual-failover.md`; update `docs/v1-runbook.md`, `README.md` and `docs/status.md` with observed results only.

Run the matrix below on explicitly approved disposable infrastructure. Use independent client records of submissions/responses to measure the fixture, without claiming complete coverage of arbitrary client acknowledgements. Preserve every failed run and partial transition. After two failed integrated attempts at a milestone, stop for a focused diagnosis/owner decision rather than restarting the whole exercise indefinitely.

| Scenario | Required outcome |
| --- | --- |
| Controller process stopped during normal traffic/SSE | Existing-primary traffic and streams continue; no administrative mutation proceeds |
| Controller restart at every transition boundary | Inspect/reconcile same operation; no duplicate unsafe effect |
| Concurrent operator commands | One accepted mutation; others rejected, not queued |
| Old primary partitioned or paused but potentially alive | No promotion until independently fenced; resumed old node cannot overlap |
| Fence response lost or action delayed | Uncertainty retained; no candidate activation/reuse until settled |
| Primary fails with healthy backups | Validated recovery, explicit loss/ambiguity report, one new writer |
| Lagging/corrupt/incomplete candidate | Catch-up/fresh restore or refusal, never unchecked activation |
| Storage unavailable or disk full | Truthful degradation; no false backup health or fabricated recoverability |
| Partial route rollout / stale proxy restart | Correct new route or explicit failure; no loop or alternate writer |
| Current primary agent/host restarts | Unattended recovery under the approved authorization protocol; no cached grant reuse |
| Restart races failover / controller unavailable during restart | Serialized resolution or safe waiting under the approved policy; never two writers |
| Former primary/agent reboots | Cold quarantine, no writable startup, clean reseed only |
| Dashboard reload, double submission, stale page or unauthorized request | Same-operation receipt or refusal; no duplicate action or access bypass |
| Expired/wrong management identity | Refusal; no insecure transport fallback |
| Failed install/upgrade | Recoverable documented state, no mixed-schema silent startup |

Complete at least three integrated switchover/failover/rejoin cycles, including a failure that is not merely a graceful primary shutdown. Measure client-observed outage, restore/startup costs and replication behavior under a declared workload; operator response time is part of real failover downtime. Agree a bounded pilot soak duration before running it (proposed 24–48 hours).

**Exit:** publish a support envelope, actual observations, limitations and open blockers. A passing unit suite is not production qualification. If stable ingress or the provider fencing contract remains unqualified, label the result a local/disposable prototype rather than a supported HA release.

## 8. Milestones and effort estimates

Estimates are cumulative focused engineering time for one supported environment, not guaranteed elapsed delivery dates. Provider access, approvals, bug discovery and soak time can extend the schedule.

| Checkpoint | Observable result | Rough cumulative effort |
| --- | --- | --- |
| M1 | Rust forwarding demo, node replication/status, happy-path disposable manual promotion | 3–5 working days for a narrow demonstration, not all safety gates |
| M2 | Dashboard MVP with durable operations, unattended same-primary recovery, fenced transitions, validation and rejoin | Provisionally 3–4 weeks |
| M3 | Installable operational pilot with native fault checks and runbooks | Provisionally 5–7 weeks |

The original 2–3/4–6 week estimates excluded a dashboard and used operator-controlled cold restart. The revised ranges allow roughly one additional week, subject to restart/access design. Unattended restart without a reachable controller is not included and needs a separate safety design if required.

Do not meet a timebox by skipping fencing, validation, authentication or uncertain-action handling. Show the last working milestone and the exact blocker. Review after M1 before expanding scope.

## 9. Deferred work

- Raft, replicated controllers, leases, elections and automatic promotion.
- Read-only TrailBase implementation and local scoped reads; see [the maintainer request](../trailbase-read-only-mode-request.md). Later acceptance must cover database locking, startup writes, schema refresh, stale authorization and replica freshness before routing any request locally.
- Zero-loss acknowledgement gates, D4 instrumentation and durable realtime replay.
- Dynamic membership, automatic discovery and online certificate/ACL services. The browser dashboard is now explicitly in scope.
- Generic cloud provisioning, DNS/load-balancer automation and universal fencing adapters.
- In-place import of Python journals/deployment state and universal support for arbitrary custom jobs/uploads.

## 10. First execution checkpoint

The restart availability policy and public dashboard/local-account access model are approved. Review the proposed bounded security/action contracts and freeze each slice's exact schemas before implementing it. Platform/fencing/front-door choices remain pending by owner decision; use local fixtures and fake adapters, and block live qualification until those inputs are supplied. Start with inert configuration and primary-only routing, then demonstrate the real proxy and proceed vertically. No public listener or action-capable runtime is implied by an inert slice.

This plan does not authorize modifications to the existing VPS deployment, inspection of private credentials, power actions, changing its accepted-loss policy, deletion of retained data, or additional infrastructure spending. Those require explicit scoped approval.
