# D4 — quorum-controlled recovery: design proposal

Status: **staged approach approved; isolated qualification starting**. Owner approved strict fail-closed loss policy and then the recommended safety-first path on 2026-09-09. The first executable slice is `2026-09-09-d4-coordination-plan.md`. Numeric timings, live rollout and automatic mutating capabilities remain gated. No deployment changes or live fault drills are authorized by this document.

Baseline: `a46bd289ce3465e890ce3b90101ec9febbff1337`, clean checkout when planning began. A is the last verified healthy writer; B the healthy same-epoch standby. Preserve the existing private URL and all D0–D3 evidence. This proposal does not qualify HA or supersede the delivery reset's review limits.

## 1. D3 review: what can actually be reused

Delivered evidence:

- Protected baseline: 14 records and six historical auth cases.
- Provider-mediated B shutdown; may flush gracefully, not abrupt physical power loss.
- 51 acknowledged fault writes recovered; zero acknowledged missing; 87 uncertain absences remain ambiguous.
- Old-epoch cut 25/5/22; distinct new-epoch baseline 1/1/1. Post-rejoin writes/auth independently restored at 5/6/5; B reached that same cut.
- Approximately 68.35 seconds between successful observer samples, not a general RTO or a two-minute guarantee.
- B rebooted safely without `/run` authority. A controller guard incorrectly required stale rather than absent authority. The first node rejoin did not run until an explicit, one-shot reconciliation verified the retained boot evidence and fresh state.
- Local/Ubuntu current tests passed. The frozen M1 pathname-redaction flake was preserved, deterministically diagnosed, and followed by a separately recorded passing unmodified run. Do not call either the drill or publication verification clean one-shot execution.

Reusable code: `hat/transition.py` node actions and cold-state validation; `hat/recovery.py` finite-cut, protected-image and fault-accounting checks; `hat/control.py::ControlIO` pinned RPC, provider evidence, oracle and ingress mechanisms. Reuse these implementations rather than another promotion engine.

Not automatic-ready:

1. `Journal.check_authority()` checks local lock/filesystem identity, not quorum authority. Copying its SQLite file to another controller would not make a distributed lock.
2. The fixed direction currently selects the phase plan: A→B means planned D2; B→A means recovery D3. Automatic recovery must support either actual writer without silently invoking planned quiescence after a crash.
3. Recovery inputs include a C-local, closed fault ledger and stopped producer. General service traffic does not provide that proof, especially when C is lost.
4. Activation records are boot-bound but not continuously lease-bound. Readiness withdrawal alone would leave direct/background mutators possible.
5. Provider identity identifies a VM, not a guest boot. Checking authority before/after an API call cannot retract a delayed accepted power request.
6. C hosts the journal, credentials, oracle and sole ingress/access path. Electing another controller without making its prerequisites available would accomplish nothing.

## 2. Approved loss policy

**Zero acknowledged-write loss is required for automatic promotion. Unknown preservation means no promotion and operator review, even at the cost of availability.**

This is a decision rule, not a claim that asynchronous Litestream replication already supplies zero RPO. A recent backup timestamp, caught-up status, or absence of missing entries in an incomplete ledger cannot prove it.

The protected set includes acknowledged data mutations and security changes: revocation, logout, account/access changes and supported configuration identity. Restoring older auth state must not silently reinstate revoked access. Keep uploads, arbitrary jobs, unqualified update/delete semantics, read replicas and cross-database transactional guarantees out of the initial supported workload.

Two honest paths remain:

- Known protected boundary with **all mutation admission closed** and no unaccounted subsequent mutations: eligible for automatic recovery if all other proofs pass. Closing only Record POST requests is insufficient; auth/admin/background mutation paths must also be accounted for or excluded.
- Active-write crash: refuse unless a separately qualified acknowledgement/durability mechanism establishes preservation. A shared acknowledgement log alone is not enough when the selected database image lacks those writes. Do not add a home-grown replay log as an incidental D4 shortcut.

Therefore the first safety milestone may automate detection/refusal and recovery of a provably protected boundary without meeting the full active-write automatic-recovery objective. Label that limitation explicitly. If the required proof cannot be supplied by native capabilities, return to the owner with the architectural cost rather than weaken this policy.

## 3. Approaches and recommendation

1. **Recommended: safety-first staged adoption.** Qualify one established quorum service and the dangerous effect boundaries first; run observation-only decisions before enabling any mutating automatic action. Keep existing manual deployment useful throughout. Some crash cases deliberately remain unavailable.
2. **Full automatic package in one increment.** Implement acknowledgement durability, distributed transitions, ingress and recovery together. It targets broader availability sooner but multiplies unqualified interactions and obscures failures. Not recommended.
3. **Remain manual.** Lowest change risk; retain D3 as the release and defer automation. Honest, but does not deliver D4.

No custom consensus, S3 lease algorithm, backend plug-in framework, Kubernetes deployment, generic force/resume facility, or automatic failback.

## 4. Proposed authority and operation model

- Three etcd voting members, provisionally one per A/B/C, tolerate one member loss while two remain communicating. This placement is conditional on measured RAM/CPU/disk/fsync headroom; it is not qualified on the current VPSs yet.
- Pin one supported release and an official client interface. Qualify official `etcdctl` v3 versus the maintained v3 client against the required transaction/lease behavior; choose one, not a compatibility layer. Do not pin a release merely because Context7 indexed its documentation.
- Use authenticated TLS, restricted key namespace, least-privilege runtime identities and protected credential distribution. Confirm membership/cluster identity; snapshot restore or cluster replacement requires explicit maintenance, not automatic adoption of reset revisions.
- One persistent authoritative activation/transition record describes deployment generation, operation kind, writer, source/target boot incarnations, epoch, current phase and evidence references. Conditional updates compare the observed revision and owner identity.
- A lease-backed owner claim controls who may advance that record. Lease expiry must not delete pending effects, active-writer history or uncertainty. Local SQLite/logs remain retained audit artifacts, not a competing source of authority.
- Watches are notification hints, not permission to act. Decision/action gates require fresh authoritative validation; gaps, disconnects and compaction trigger revalidation or refusal.
- Before each external effect: commit its exact intent under the current owner. Afterward: verify the actual result and conditionally commit evidence. Loss of authority prevents further effects and publication of success.
- Small proof records are quorum-available. Larger private immutable evidence must survive loss of the initiating controller, using an explicitly addressed, hash-verified existing storage path. Publish evidence before marking its phase done; retain orphan artifacts. No secrets in public records or credentials in process arguments.

Refactor operation kind away from source/target direction with compatibility tests for the existing D2/D3 history. Both manual and automatic entrypoints must use the same authority-aware transition path once a deployment adopts D4. Legacy local-only commands must not remain an activation bypass.

## 5. Fencing, uncertain effects and node behavior

All candidates must acquire coordinated authority before fencing. A negative health probe is suspicion, not proof that a writer has stopped.

Before successor activation, externally fence every incarnation that may still execute as writer, including an uncertain candidate activation—not merely the last acknowledged writer. Validate exact provider identity and fresh terminal observations. A paused host cannot be made safe by assuming its local watchdog ran.

**Blocking qualification:** demonstrate what a provider request ID/terminal result actually guarantees. The D3 receipt alone is not a conditional fence against a guest incarnation. A check immediately before submission still leaves a race.

Persist outstanding power intent beyond controller lease expiry. Do not repeat it, boot/reuse its target, or authorize that target as a later writer until delayed effects are conclusively settled. If the adapter/provider cannot establish that an old action can no longer arrive, leave the affected incarnation quarantined and refuse automation. Do not invent a cancellable-request guarantee.

Node action admission checks current deployment/operation/lease generation and actual guest boot. A lease-aware local guard withdraws readiness and stops TrailBase and writer uploaders when authority cannot be confirmed. Bounded local checks must be tested under ordinary scheduling, but are not a whole-host-pause safety proof. Reboot starts quarantined; `/run` absence is expected. No boot, old command or stale route may independently recreate writer authority.

Uncertain activation or fencing is a durable stopped checkpoint, not a catch-all retry case. Automatic cold rejoin can be considered only after its boot and pending-effect obligations are settled; otherwise rejoin stays manual. No automatic failback is needed for D4.

## 6. Detection, timing and ingress

Health probes nominate a suspect; quorum ownership, policy proof and external fencing authorize recovery. A partitioned minority must not promote itself. Loss of quorum withdraws write readiness and stops mutators under the qualified local guard, rather than keeping an unverified writer available.

The reset's **120-second recovery target remains a proposed objective**, not an SLO or a deadline permitting unsafe promotion. Select numeric lease, renewal, RPC, stop and detection bounds only after measuring the pinned client, VM scheduling and provider behavior. Specify how stale responses, long pauses and clock changes are rejected; a lease TTL is not a synchronous shutdown guarantee.

For the existing private demonstration, proposed ingress is native proxy instances on multiple VPSs, selected through independent pinned access paths from a fixed workstation listener. Route only to the quorum-authorized, boot/epoch-bound ready writer; status-green alone is insufficient. Native backend failover must not replay uncertain mutations.

The operator workstation remains the client/access boundary, not a qualified HA public endpoint. Losing C must not require its SSH tunnel, oracle or credentials to recover. A production endpoint would require a separately approved ingress/topology choice; do not introduce paid infrastructure, a public listener, or assume floating-IP support. DNS round-robin alone is not the safety or availability design.

## 7. Bounded implementation candidates — gated, not authorized tasks

| Slice | Concrete output | Exit evidence / stop condition |
|---|---|---|
| 0. Resolve contracts | Supported workload, strict ACK proof source, supported etcd/client pin, resource and ingress topology decision | Refuse active-write automation if preservation cannot be proven; no live installation |
| 1. Qualify authority | Real three-member disposable cluster; transactions, leases, TLS and stale-owner tests | One member loss works; minority/quorum loss, reconnect and ambiguous transaction results refuse safely |
| 2. Qualify effect admission | Durable pending-effect lifecycle and node lease/boot admission using existing actions | Delayed power/activation cannot affect a reused incarnation; if provider contract cannot prove this, stop |
| 3. Reuse transitions | Explicit operation kind, quorum-backed phase commits, controller-independent evidence/prerequisites | D2/D3 history preserved; either writer direction tested; no local-only bypass or duplicate side effects |
| 4. Qualify ingress | Redundant native routes/access paths with fixed private URL | C loss, stale route, partition and reconnect do not admit writes to an unauthorized host |
| 5. Observation-only controller | Decisions/refusals over captured and synthetic failures, no power/activation capability | Strict policy handles missing ACK/backup/auth evidence; action requests remain disabled |
| 6. Owner-approved integrated demonstration | One bounded single-VPS-loss case using the installed entrypoints | Either verified recovery under strict policy or honest safe refusal; preserve evidence and leave useful deployment |

Slices 1–5 require smallest failing behavioral checks, real installed-component validation where relevant, and bounded independent spec and safety review before enabling actions. Do not replace deployment evidence with mocked subprocess success. Set an explicit active-work checkpoint before implementation; the historical D3 extension is not a new D4 budget. Retain the reset's stop after two failed integrated attempts, with no blind whole-run retry.

## 8. Acceptance matrix

- Either A or B as actual writer; simultaneous contenders: at most one activation, no conflicting power actions.
- Source host loss with a proven protected boundary: fence, finite independently verified restore, fresh epoch, unchanged URL and remotely restored new writes.
- Source host loss with unproven acknowledged data/auth: no promotion; durable reason and operator checkpoint.
- C/controller loss: surviving controllers have authority, credentials, evidence and oracle capacity; ingress remains usable without C.
- Controller crash before/after every mutating phase boundary: no implicit effect replay; uncertain intent survives ownership change.
- Lease expiry, quorum loss, asymmetric partition, delayed response, process/host pause and old guest reboot: no overlapping writers or stale activation.
- Accepted-but-delayed fence, changed boot, reused VM identity and malformed receipt: no unsafe reactivation; unresolved effects remain quarantined.
- Missing required DB, corrupt/behind backup, unavailable object store, wrong binaries/support or unsafe auth rollback: no activation.
- Stale ingress, backend failure and ambiguous client response: no unauthorized routing or blind request retry.
- Final accounting uses actual submitted/acknowledged/uncertain outcomes, same-epoch comparisons and independently restored data/auth; it does not infer zero loss from process health.

D4 is not complete until the promised single-node-loss case genuinely recovers automatically under the approved policy and C is no longer its service-side single point of failure. A safe refusal is a successful safety test, not a successful automatic-recovery demonstration. D5 remains the separate repeated-release qualification gate.

## References

- `docs/plans/ha-delivery-reset.md`, D4/D5 and delivery discipline.
- `docs/plans/2026-09-08-d3-recovery.md`; `docs/status.md`; `docs/runbook.md`.
- Official etcd API documentation reviewed through Context7: https://etcd.io/docs/v3.7/learning/api/ and https://etcd.io/docs/v3.7/dev-guide/api_reference_v3/ — API concepts only, not a selected release pin or deployment qualification.
