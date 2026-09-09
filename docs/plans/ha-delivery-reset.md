# HAT: Working HA Delivery Reset — Proposed Implementation Plan

> **REQUIRED SUB-SKILL:** Use the executing-plans skill to implement this plan task-by-task.

**Goal:** Deliver TrailBase through one stable endpoint, with one active writer, a recoverable standby, safe operator-controlled failover and rejoin, then automatic failover.

**Architecture:** Keep pinned TrailBase and Litestream; the eventual target is TrailBase running on every standby in a strictly qualified read-only mode. Until that mode is proven, use stopped TrailBase as the safe fallback. Use IDrive e2 only for database backup transport, independently completed power fencing for writer exclusion, and an existing consensus service for the later automatic control plane. Ship a persistent manual recovery prototype before adding election.

**Tech Stack:** TrailBase v0.33.11, Litestream v0.5.17, Ubuntu/systemd, Python standard library for the first operational commands, HAProxy for prototype ingress. Proposed later automatic coordinator: a three-member etcd cluster, with version/resource qualification before installation. Private fencing adapter remains operator-owned.

**Status:** Proposed reset for owner approval. No deployment, package installation, credential-policy change, or live test is authorized merely by this document. Existing safety and evidence-preservation rules remain binding. Work on main; do not push until owner review.

---

## 1. What we are actually building

The observable product is:

1. A client uses the same URL to create and read records and authenticate.
2. One node is the only TrailBase writer. Other nodes continuously restore the databases and, once the read-only gate passes, run TrailBase as read replicas; stopped TrailBase remains the fallback.
3. An operator can move service to the standby without changing the client URL.
4. After actual loss of the writer, confirmed external fencing permits recovery on the standby.
5. The former writer cannot start writable on reboot; it rejoins only through a new clean restore.
6. Eventually the same transition runs automatically under exclusive cluster authority and an explicit loss policy.

A process restart, successful backup, test count, or collection of reports is not this product. A manual recovery prototype is useful but is not automatic HA. A single demo proxy is not highly available ingress.

## 2. Evidence reviewed and current state

Review baseline: repository HEAD `ee6e468`. This commit's final independent review was interrupted; it is not accepted solely because it is committed.

Reviewed README, master plan, architecture, deployment, TrailBase state, upstream findings, work register, qualification design, result reports, Task5 implementation/call paths, and test structure. Read private Task5 JSONL summaries without publishing their raw contents.

| Finding | Evidence strength | Decision |
| --- | --- | --- |
| Local follow-to-writer promotion, fresh epochs, and reseed can work | M0 macOS/local-file report passed the specified matrix | Reuse the validated semantics and fixture; not proof of Linux/S3 HA |
| Acknowledged writes can be lost | Observed natural and deliberately lagged M0 crashes | No zero-RPO promise; measure loss against an external client ledger |
| Stock TrailBase is not a read-only follower server | Pinned source inspection, writable startup behavior | Service-hot read replicas remain gated on a real read-only mode; data-hot stopped-app standby is the fallback |
| All required DBs need independent replication plus application checks | main/session/aux fixture and pinned state inventory | Retain all three; do not replace the workload with a main-only demo |
| IDrive e2 cannot serve as our CAS/lease authority | Conditional-delete and concurrent-replace failures in live storage matrix | Remove S3 election from the delivery path; no workaround protocol |
| IDrive basic object operations and initial replication work | Storage probes and partial Task5 runs | Keep as backup transport provisionally, not a qualified HA transport yet |
| Linux installation and boot containment work | Provisioning checks passed on three Ubuntu nodes | Reuse provisioned binaries/hosts; do not reprovision before every test |
| Full Linux parity did not qualify | Required aggregate missing | Preserve its NO-GO/incomplete status; not evidence that Linux or 1 GB is impossible |
| Fencing contract and non-destructive inspection exist | Contract tests and private inspection | Real power-off, promotion, and restart drill still required |
| Task5 never completed remote promotion | 13 available private Task5 evidence directories: zero e1 comparison or e2 comparison events, zero full-flow PASS; one recorded e1 cut event | Unqualified due to harness failures, not provider-level HA NO-GO |
| There is no runnable HAT service or ingress deployment | Tracked files are documents and experiments | Stop treating qualification progress as product delivery |

The existing experiment Python files total approximately 9,000 lines, including tests; M1 run.py alone is approximately 4,400 lines. This is evidence of misplaced implementation effort, not product maturity.

## 3. Why execution failed

- The original master plan's manual-recovery milestone was displaced by a large prerequisite qualification exercise.
- Provisioning, orchestration, metadata parsing, credentials, cleanup and result formatting were coupled into one fresh-run lifecycle. A reporting defect aborted useful replication work and triggered complicated cleanup.
- Tests often mocked SSH responses or extracted fragments rather than executing the deployed program in a clean Linux environment. Missing definitions, integer/string contracts and GNU tool behavior escaped reviews.
- Real error output was discarded early; diagnoses were sometimes inferred rather than established. A later successful SSH/SCP command does not prove why the earlier command failed.
- Independent reviews caught real security defects, but I repeatedly opened new implementation/review loops without a delivery checkpoint or retry budget.
- Status was reported as task numbers and PASS/NO-GO rather than a URL, working command, exact broken transition, and remaining product gap.

Fix the execution model, not just the latest exception.

## 4. Architecture decision

### Recommended: asynchronous active/passive TrailBase

Keep the basic TrailBase/Litestream premise. Separate data transport, authority, fencing and routing:

- **Data:** Litestream to epoch-isolated S3 prefixes; standby follows main/session/aux; fresh finite restore remains the independent oracle and fallback for suspect follower state.
- **Authority, first prototype:** one designated controller on the third node, operator commands only, one locked persistent transition journal. No peer elections or automatic controller failover. A lost controller prevents new transitions; it does not authorize another controller.
- **Authority, automation:** use one established consensus backend (proposed etcd), not S3 and not a custom consensus protocol. Lease acquisition is still not a physical fence.
- **Fence:** independent power-off of the exact previous writer plus independent unreachability and restart containment. Unknown outcome means no activation.
- **Ingress:** an existing proxy for the demo; redundant/managed ingress before claiming service HA. Raw app/admin access remains private and cannot bypass role restrictions.

Prototype topology: node A active writer, node B standby, node C controller/demo ingress/client probes. C is an explicitly acknowledged prototype single point of failure. Later, three control-plane members may run across these hosts if measured capacity permits; control-plane failure domains and ingress HA must be addressed separately.

### Alternatives considered

1. Continue qualifying a custom S3 election protocol: rejected. e2 has failed the required primitives; this would create a new distributed-systems project.
2. Replace Litestream with a different SQLite replication layer: reserve as a focused fallback if direct binary tests establish a real replication/promotion incompatibility. It would require renewed TrailBase, multi-DB, filesystem and durability qualification; it is not an assumed shortcut.
3. Redesign around synchronous durability: required if acknowledged-write loss is unacceptable. This would change the current premise, not be a hidden promise of this plan.

## 5. Explicit first-release envelope

The first demo is a disposable application using the existing three-DB fixture and real TrailBase auth. No reduction of the old fixture/repetitions/acceptance conditions is allowed to label old qualification PASS. Incremental demo checks are new milestones, not substitutes for that qualification.

- Main and session remain mandatory; aux remains in the demo. Arbitrarily coupled attached-DB workloads are not automatically supported.
- Planned switchover stops every mutator, flushes all DBs, and records a quiesced cut. Unplanned recovery cannot claim an atomic cross-file cut.
- Shared signing/config identity is required. Lost account revocations, ACL changes and sessions remain security-relevant; relogin alone is not a complete remedy.
- No local uploaded-file HA claim. A subsequent application acceptance check must cover shared object storage and explicit update/delete limitations.
- Custom jobs and external side effects are disabled in the first demo; enabling them requires primary-only and idempotency/reconciliation checks.
- SSE reconnect/refetch is supported only after tested; gapless replay is not promised.
- Automatic promotion is off by default. Production automatic recovery requires an approved loss/uncertainty and multi-DB/auth policy. Backup age alone cannot prove a bound on lost acknowledgements.

## 6. Deliverables and sequence

Timeboxes below are **active-work review limits**, not guarantees of completion. Exceeding one requires a concrete blocker and owner decision; it does not authorize silent extra days.

### D0 — Establish a safe, comprehensible baseline

**Review limit:** one hour of active work.

**Outputs:** `docs/status.md`, a read-only private node inventory, and a current-branch validation result.

- Verify current processes, writer services and previously known credential remnants using pinned SSH. Do not assume a prior cleanup PASS proves current state.
- Preserve historical roots, databases, S3 prefixes and logs. Do not mass-clean disks.
- Record latest commit as reviewed/unreviewed, current test results, usable components, and exact uncompleted gates.
- Freeze experiments/m1 as qualification evidence. No whole-file refactor and no attempt to make every old experiment green before product work.
- Keep a single status table: delivered, currently building, blocker, next demonstration.

**Done:** owner can see exactly what exists; no active unsafe writer/credential remnant is ignored. An unresolved safety issue blocks deployment, not another evidence-accounting expansion.

### D1 — Leave a working application and standby running

**Review limit:** four hours of active work; show partial working service sooner if possible.

**Proposed files:** `hat/node.py`, `deploy/hat-node.service`, `deploy/haproxy.cfg`, `tests/test_node.py`, `tests/demo_smoke.py`, `docs/runbook.md`. Create only files actually needed.

- Install one small real node-side program; do not construct Python source strings. Run that same program in tests and on Ubuntu.
- Reuse pinned artifact/config/TXID/validation knowledge from M0/M1 without importing the 4,400-line experiment as the operational controller.
- Use systemd for process lifetime and a short runtime socket path. No autonomous writable boot; HAT alone activates the writer.
- Deploy the three-DB demo once, then keep the setup for subsequent commands. Separate install/setup from transitions and from explicit decommissioning.
- Serve real create/read/login through a stable demo URL. Run replication on A and followers on B; run TrailBase on B only if the qualified read-only mode is available, otherwise keep it stopped.
- `hat status` shows role, epoch, per-DB positions, replication health and refusal reasons.
- Independently restore the published baseline and check fixture data/auth. Never infer readiness from process liveness alone.

**Done:** the owner can use the URL, see records/auth work, and see B catching up. This is not yet failover or ingress HA.

**Credential policy proposed for approval:** provision demo secrets once in protected runtime/config locations for the live deployment, not scattered per experiment. They remain only while that deployment is intentionally running; failed transitional copies and decommissioned credentials are scrubbed. No broad new credential access or automatic deletion of evidence.

### D2 — One command performs a safe planned switchover

**Review limit:** four hours after D1.

**Proposed files:** `hat/control.py`, `tests/test_transitions.py`; extend the same runbook and demo client.

- Use a local controller lock and durable operation journal to permit one manual transition at a time. Persist intent before mutation. Restart must reconcile or refuse an unfinished operation; never assume a timed-out command did nothing.
- Implement `hat switchover B`: close ingress readiness, drain/stop TrailBase and jobs, sync every DB, record cut, stop old uploader, confirm external fence/no restart, catch up/stop followers, validate all required files.
- Compare frozen candidate copies with an independent finite restore and client operation ledger. Use fresh restore if follower state is uncertain; do not silently skip comparison.
- Start B under a new epoch with new Litestream metadata, verify a remotely restorable baseline, then switch ingress and prove HTTP/auth work.
- Fence failure, missing DB, mismatched keys/release, live follower, lost authority or invalid restore prevents startup/routing. No force flag.

**Done:** client keeps the same URL; the actual writer moves A to B; all acknowledged writes before the quiesced cut remain; old writer stays stopped; new writes are backed up in e2. Leave B serving for inspection.

### D3 — Recover from a powered-off writer and rejoin it safely

**Delivered 2026-09-09 with explicit reconciliation:** A is again the healthy writer at the unchanged URL; B is a healthy same-epoch standby. Protected data/auth, acknowledged traffic accounting, independently restored post-rejoin writes, native followers and retained originals passed. The first boot validation rejected normal absent activation authority; a narrowly guarded reconciliation completed the same operation without another power-on. See [D3 execution record](2026-09-08-d3-recovery.md) and [current status](../status.md). This does not authorize automatic-control work or claim a clean one-shot/abrupt-power-loss demonstration.

**Review limit:** four hours after D2; actual disruptive step requires explicit approval for the selected deployment.

- While the demo client records submitted/acknowledged operations externally, power off the active node through the private fence integration.
- `hat recover A` uses the same transition path, exact fence evidence, explicit recovery cut and declared uncertainty policy. Do not relabel crash recovery as zero-loss planned switchover.
- Report recovered, lost and ambiguous operation IDs, plus client-observed downtime.
- Power the old node on. Prove it boots quarantined, cannot become writable automatically, and does not upload into the new epoch.
- `hat rejoin B` retains old state and restores into a new working directory from the current epoch.

**Done:** the same URL recovers after host loss, one writer remains, loss is measured honestly, and redundancy is restored. This is a usable **operator-controlled recovery release**, not automatic HA.

If this cannot complete within the review budget, deliver D1/D2 plus the exact blocked transition. Do not resume qualification churn.

### D4 — Automate the already-working transition

**Start only after D3 demonstrated.** Produce a bounded implementation task list at that point; do not scaffold speculative backends now.

- Add one established quorum coordinator (recommended etcd) and use the existing transition code, not a separate automatic promotion implementation.
- Qualify the pinned coordinator and available RAM/disk/CPU; use an official supported client interface rather than custom Raft or a new S3 lease algorithm.
- One authoritative activation/transition record, lease lifecycle, stale-controller rejection and boot incarnation binding.
- All candidates coordinate before fencing. Delayed actions must not target a new incarnation. On authority loss withdraw readiness and stop mutators; whole-host pauses still require external fencing before a successor starts.
- Replace the single demo proxy/control failure point with qualified HA ingress and quorum-controlled operation.
- Approve numeric loss/downtime policy and application consistency restrictions. Unknown loss fails closed unless an explicitly approved workload policy permits that uncertainty.

**Done:** automatic recovery survives one node loss; concurrent candidates cannot activate two writers; old node resume/reboot is safe; control-quorum loss, fence uncertainty, missing backups and ingress faults produce the documented refusal/degraded behavior. Measure RTO; a prototype target of two minutes is a proposed objective, not an SLO claim.

### D5 — Qualify a supported release, not every possible application

- Repeat the integrated failover/rejoin drill three times, preserving each result.
- Run bounded cases for node pause/partition, concurrent commands, controller crash during promotion, fence failure, restore error, one missing required DB, and storage outage.
- Test supported auth continuity/revocation semantics, shared-object upload/download and declared update/delete restrictions, SSE reconnect, and version/config mismatch.
- Publish one install/runbook, one supported-workload statement, real RPO/RTO observations, dependency failure behavior and unresolved limitations.
- Only then advertise the supported configuration as HA. Read replicas are an intended release capability, but remain disabled until the read-only gate passes. Keep generic providers, zero-loss replication, multi-region and broad feature coverage out of this release.

## 7. Test and delivery discipline

For each D1–D3 behavior:

1. Write the smallest failing behavioral test.
2. Implement the operational path.
3. Execute the installed entrypoint in a clean Ubuntu environment with real binaries/systemd as relevant. No AST-extracted function or mocked subprocess result is sufficient integration evidence.
4. Run affected tests and the existing direct regression suites without weakening expectations:
   - `python3 experiments/m0/test_run.py -q`
   - `python3 experiments/m1/test_run.py -q`
   - `python3 experiments/m1/test_s3.py -q`
5. Obtain separate bounded spec and quality/safety reviews at the deliverable boundary.
6. Demonstrate the URL/command and leave the useful deployment available.

One writer per checkout. Parent owns the integration path and live actions. No automatic chain of implementation agents. A reviewer identifies concrete correctness/safety defects; speculative future capabilities go to the backlog, not the critical path.

A live failure must leave: failed command/stage, return code, protected raw stderr/logs, expected versus observed state, credential/process safety status, and the next falsifiable check. Distinguish harness, transport, data-integrity, fencing, and reporting failures.

No blind whole-run retry. One focused diagnostic is allowed to establish a cause. After two failed integrated attempts at the same deliverable, stop, show evidence and choose a smaller diagnostic or architecture change with the owner. Do not silently increase the budget.

Unknown logs or malformed metadata remain fail-closed where currently required; do not wave away errors as harmless. Stop extending ad hoc log parsers one record at a time: use pinned real log fixtures and deployed-program tests, plus actual process/backup/data checks.

## 8. First next action after approval

Execute D0, then build D1. Do **not** launch the old `cross-host` scenario again merely because a review passed. The next demonstration must be a persistent working TrailBase URL with a visible standby, followed by a real switchover command.

This reset does not retroactively qualify M1, erase failed evidence, or declare the latest unreviewed commit safe. It changes the next deliverable from another experiment result to a usable piece of HAT.

## 9. Fresh-session handoff

This document is sufficient to begin D0 and guide the D1–D3 delivery sequence. It is not a complete production/automatic-HA implementation specification: D4 explicitly requires its own bounded task list after the manual recovery demonstration. Do not interpret that as permission to restart broad architecture research before D1.

- Repository: `/Users/markb/dev/hat`; work directly on `main`. Review baseline was `ee6e468`; inspect actual HEAD and working changes before proceeding. Do not reset the checkout or discard work.
- This plan was written after stopping the old workflow. Verify current process/subagent status rather than assuming nothing is running.
- Private inventory: `~/.config/hat/m1-inventory.json`.
- Private backup configuration: `~/.config/hat/m1-idrivee2.env`.
- Private fencing configuration and adapter: `~/.config/hat/m1-linode.env`, `~/.config/hat/m1-fence-linode`.
- Prior evidence: `~/.config/hat/m1-task5-live-runs` and `~/.config/hat/m1-provision-runs`. Read privately; never publish credentials, infrastructure identifiers or raw logs. No historical deletion is authorized.
- Do not resume any old `/tmp/hat-m1-*.js` workflow or automatically rerun `experiments/m1/run.py cross-host`.
- Before D1 live deployment, confirm the demo endpoint and approval for the proposed installation/persistent protected credential arrangement. Before D3, obtain the exact disruptive-test approval. These are deployment approvals, not reasons to expand the technical scope.
- First checkpoint: D0 status and safety inventory; next visible deliverable: the persistent D1 URL and standby status. No push until owner review.
