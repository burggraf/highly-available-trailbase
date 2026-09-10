# D0–D3 operational-readiness audit findings

## Scope and claim rules

This is a repository-only source audit. It did not read private evidence, contact A/B/C or a provider, open the demo, or execute an operator command. A/B/C are the public logical labels already used by the repository; no private endpoint, operation ID, credential, or evidence content appears below.

A command is **read-only** only when the complete checked-in command path does not intentionally change application, service, provider, configuration, journal, or evidence state. “Mutating (evidence only)” means the remote request is observational but the command creates local durable evidence. Historical/live statements are recorded separately from source/test claims: repository code and tests establish behavior, not present deployment state.

The finding classes used below are exactly: `correct now`, `documentation correction`, `contract missing`, `operational qualification missing`, and `out of scope`.

## Task4 verification checkpoint — clean `f781f0e`

The parent ran final verification once at clean `f781f0e` and did not rerun it. D4 unittest discovery ran **113 tests: 112 passed and one ERROR** in `test_native_adapter.NativeAdapterTests.test_default_command_timeout_stops_descendant_process_group`; `experiments/d4/native_adapter.py::_stop_group` encountered macOS `PermissionError: [Errno 1] Operation not permitted` from `os.killpg(process.pid, 0)`. This is a known recurring **macOS cleanup-observation uncertainty**, not a product regression. Earlier passing runs do not clear it, and it prevents a clean one-shot verification claim. Runtime discovery separately ran **107 tests OK**, with expected parser stderr and SQLite `ResourceWarning`s. `git diff --check`, the exact changed-path allowlist, and clean-worktree checks passed.

This is a documentation-only record: no code/test changes, diagnosis, or fix were made. D4 stock-runtime infeasibility remains in force; Task 2 and Task 3 blocker dispositions are unchanged. The checkpoint records the observed result and does not convert it into a clean pass.

## Exact documentation corrections

- The runbook now states the current envelope is manual D0–D3 only, D4 is infeasible on the stock runtime, and automatic HA is not provided.
- Its OBSERVATION checklist is limited to existing demo/status surfaces and explicitly treats the private `connect_demo.py` helper and installed `hat` aliases as not repository-verified.
- Restore verification is explicitly not non-disruptive: source review/preparation is separated from authorized actions that create files, processes, sessions, or application requests. The manual drill gate requires fresh authorization, stop conditions, no blind retry, escalation, timeout uncertainty, and evidence retention.
- `hat ingress-check` is read-only admission: incomplete verified-D3 serving/rejoin-tail requires the maintenance marker, valid D3 proof, retained route writer/epoch, and matching route hash, without permit/boot/PID. `route_pending` requires the exact phase prefix, maintenance/no failure, D3 proof as applicable, and permit operation/current boot/PID/birth/config hash; `verify_pending` additionally validates recorded route writer/epoch/config facts. `reconcile_existing` is service-changing because it may create/remove control metadata and stop/start ingress. `inspect-cold` and `inspect-frozen` are non-service-changing but may create dispatcher control metadata, so neither is strictly read-only.
- Restore verification acceptance now requires the explicitly approved integrity, authentication/session, record/membership, exact restore-position/proof checks to complete with all expected evidence retained; missing, mismatched, or uncertain checks refuse acceptance and escalate, with no rerun substitution. No objective unified manifest/schema binds those checks to restore class, source/target/epoch/position, and evidence, so this is a stop boundary—not authorization for a new restore (`contract missing`).
- Completed `ingress_allowed`/`reconcile_existing` bind the current config hash but do not require exact route writer/epoch/key-set identity; they are not fully route-authority qualified and must not be exercised until separate code design/tests (`contract missing`). Private/publication boundaries are historical operational facts, not repository access-control claims.

These are documentation corrections only; no private helper, alias, endpoint, evidence, or command was executed by this audit.

## Operator command inventory

### Runbook and controller commands

| Command | Class | Exact authority and preconditions | Durable intent, replay, and failure evidence | Repository support | Finding |
| --- | --- | --- | --- | --- | --- |
| `python3 …/connect_demo.py` | Mutating (workstation process/tunnel) | Private script, pinned SSH material, and free loopback port according to the runbook; the script is not in this repository, so its exact checks are unavailable. | Not established in repository; terminal exit/output is the only specified failure surface. Repeating can create another tunnel attempt. | `docs/runbook.md` only | `contract missing` |
| `hat status` on A/B | Read-only at the checked-in target (`node.py status`) | Local node status listener must answer; installed `hat` alias mapping is a live/deployment fact not represented in repository files. | No intent. Safe to repeat as an observation. Failure is exit/stderr; the command itself retains no evidence. | `hat/node.py::{main,public_status}`; `tests/test_node.py` | `correct now` |
| `systemctl status hat-demo.service` | Read-only | Local systemd access and the named installed unit. It reports service state, not replica freshness or promotion authority. | No intent. Safe to repeat. Failure/output is terminal-only unless separately retained. | `deploy/hat-demo.service`; `docs/runbook.md` | `correct now` |
| `python3 tests/test_node.py -q` | Mutating (local fixture/process state only) | Repository checkout and Python; `HAT_NODE_ENTRY`, if set, changes the inspected entrypoint. | No operational intent. Tests create temporary files/processes and clean them up. Rerunnable; stdout/stderr is not retained automatically. | `tests/test_node.py`; `hat/node.py` | `correct now` |
| `python3 tests/test_ingress.py -q` | Read-only against tracked configuration | Repository checkout and Python; reads the HAProxy configuration. | No operational intent. Rerunnable; stdout/stderr is not retained automatically. | `tests/test_ingress.py`; `deploy/haproxy.cfg` | `correct now` |
| `python3 tests/demo_smoke.py --base … --credentials … --ledger NEW` | Mutating (auth, main/aux records, and evidence) | Explicit base URL, credential JSON, and a new ledger path; optional registration is off in the runbook. | Ledger is exclusive-created mode 0600; each retained frame is flushed and fsynced. Same-path replay refuses, but a new path repeats real login/logout and writes. Assertion/HTTP failure leaves traceback plus a possibly partial ledger. | `tests/demo_smoke.py`; `tests/test_demo_smoke.py`; `tests/test_ingress.py` | `correct now` |
| `hat switchover B` | Mutating | Root; private controller config bound to controller hostname; exact target B; no unfinished journal operation/maintenance; A healthy writer, B healthy standby, matching epoch/release/support; pinned provider target; valid current route, credentials/history, and oracle identity. Before beginning a new operation, `switchover` invokes `reconcile_existing` under the controller journal lock. | SQLite operation and each phase intent commit before effects. Failure leaves pending intent, protected command intent/stdout/stderr/outcome, and `failure.json`; ingress is closed after a touched failure. An unfinished replay/new operation refuses; an exact completed D2 operation performs only bounded maintenance reconciliation and starts no new promotion. | `hat/control.py::{main,switchover,reconcile_existing,Journal,ControlIO}`; `tests/test_transitions.py`; `tests/test_control_io.py`; `tests/test_transition_guards.py` | `correct now` |
| `hat/control.py::reconcile_existing` (switchover preflight) | Mutating/service-changing | Root controller journal must be locked. With an unfinished operation it checks the maintenance marker and verified D3 serving state; otherwise it creates the maintenance marker if absent and stops ingress. With a completed operation it requires the latest route target/config hash to match, and if maintenance exists it must be the exact operation marker before removal. | It is not a new-operation retry: it either refuses an unfinished boundary after preserving/closing maintenance, or removes the exact completed marker and lets `switchover` start ingress. Stop/start ingress and marker creation/removal are failure evidence only through their return/error and durable marker/journal state; no separate operation intent is created by this helper. | `hat/control.py::reconcile_existing`; `tests/test_transitions.py::test_completed_crash_reconciles_exact_marker_without_new_operation`; `tests/test_transitions.py::test_route_crash_denies_restart_and_reconciles_ingress_before_refusal`; `tests/test_recovery_guards.py::test_verified_d3_pause_and_failed_rejoin_keep_exact_a_route`; `tests/test_recovery_guards.py::test_d3_gate_recognizes_each_post_verification_rejoin_tail_boundary` | `correct now` |
| `hat reconcile-compare OPERATION` | Mutating | Root/controller config; one 32-hex operation at the exact pending D2 compare boundary; matching source epoch and maintenance marker; retained compare failure; unused one-shot reconciliation marker; unchanged frozen state/cut, release/support, and fresh offline fence inspection. | Writes a one-shot reconciliation marker, reruns the oracle, archives the original failure, appends compare completion, then continues activation/baseline/route/verification. Any later failure is retained separately. It cannot replay the command or earlier phases; `switchover` calls `reconcile_existing` before this boundary is entered. | `hat/control.py::{main,switchover,reconcile_existing,Journal.accept_comparison}`; `tests/test_transitions.py` | `correct now` |
| `hat reconcile-verify OPERATION` | Mutating | Root/controller config; exact pending D2 verify boundary; exact maintenance marker; retained `verify`/`URLError` failure; no new-write ledger; unused verification marker; unchanged offline fence, B boot/epoch/health, route hash, baseline, and oracle identity. | Writes one-shot intent, closes/starts ingress, archives the original failure, performs real verification writes and independent restore, and appends verify completion. Repeat refuses; later failure is retained separately. `switchover` invokes `reconcile_existing` before a new operation, while this command handles only the exact verification boundary. | `hat/control.py::{main,switchover,reconcile_existing,Journal.accept_verification}`; `tests/test_transitions.py`; `tests/test_demo_smoke.py` | `correct now` |
| `hat ingress-check` | Read-only | Root; no extra arguments. The implemented `hat/control.py::ingress_allowed` branches are distinct: **(1) completed operation** requires maintenance absent and completed route evidence whose config hash equals the current ingress; it does not read/require a route permit, current boot, or PID. **(2) incomplete verified D3 post-verification/rejoin-tail** is accepted first through `_d3_serving_state`, requiring the maintenance marker plus valid complete D3 proof, the retained route writer/epoch, and matching current route hash; this branch does not require a permit, current boot, or PID. **(3) incomplete D3 `route_pending`/`verify_pending`** requires the exact journal prefix, maintenance marker, and no failure; it then requires the route permit’s operation/current boot/PID/birth and matching config hash (and, for `verify_pending`, matching recorded route facts). | No intent or retained result; exit 0/1 is the evidence unless the invoking service retains it. Safe to repeat as a gate. | `hat/control.py::{main,ingress_allowed,_d3_serving_state}` completed branch, D3 serving branch, and `route_pending`/`verify_pending` branches; `tests/test_transitions.py::test_completed_crash_reconciles_exact_marker_without_new_operation`; `tests/test_recovery_guards.py::test_d3_gate_recognizes_each_post_verification_rejoin_tail_boundary`; `tests/test_rejoin_driver.py::test_ingress_check_rejects_extra_argument_before_dispatch` | `correct now` |
| `hat recover A` | Mutating | Root/controller config and exact target A; completed B-writer journal plus matching route; exact private recovery-input shape; bounded owned protected baseline/history/fault artifacts; D2-bound source boot; independently dead producer; cold A identity; B provider-offline inspection; oracle/support identity. | Seals the fault ledger before reserving a new operation. Each of ten recovery phases has committed intent/result. Failure retains `failure.json`, command records, and closes ingress. There is no resume/retry/force path; success deliberately pauses before rejoin. Nonempty acknowledged-loss classification refuses before activation. | `hat/recovery.py::{_load_input,recover,_fault_outcomes}`; `hat/control.py::{Journal,current_writer}`; `tests/test_recover_driver.py`; `tests/test_recovery.py`; `tests/test_recovery_guards.py` | `correct now` |
| `hat rejoin B OPERATION` | Mutating | Root/controller config; exact target B and 32-hex operation; exact unused D3 boundary with ten completed phases, valid D3 proof/current A route, no failure, retained boot/config evidence, and unchanged writer identity. | Uses existing journal phases. First invocation commits `rejoin_boot` intent before provider power-on; then commits node rejoin and redundancy verification. Any failure retains `failure.json`; repeat refuses rather than issuing another power action. | `hat/control.py::{main,rejoin,Journal.continue_rejoin}`; `tests/test_rejoin_driver.py`; `tests/test_recovery_guards.py`; `tests/test_rejoin_native_boundaries.py` | `correct now` |
| `hat reconcile-rejoin-boot OPERATION` | Mutating | Root/controller config; one 32-hex operation at exact pending `rejoin_boot`; exact retained failure; exactly one successful original power-on and one matching cold response with command provenance; pinned B target; no prior reconciliation marker; unchanged A route. | Writes a one-shot marker before fresh A/node/provider observations, performs provider **inspect** (not another power action), appends boot completion, archives failure, then executes node rejoin and verification under the same lock. Repeat refuses. | `hat/control.py::{main,reconcile_rejoin_boot,rejoin}`; `tests/test_rejoin_boot_reconciliation.py`; `tests/test_rejoin_driver.py` | `correct now` |

The runbook’s “provider inspect only” is correctly scoped by its next sentence, which says the command executes node rejoin. The overall command remains disruptive/mutating.

### Node and D3 client CLIs

| Command | Class | Exact authority and preconditions | Durable intent, replay, and failure evidence | Repository support | Finding |
| --- | --- | --- | --- | --- | --- |
| `node.py status [--config …]` | Read-only | The config option is parsed but status does not load it; local status HTTP must answer. | No intent; repeatable. Exit/stderr only. | `hat/node.py::main`; `tests/test_node.py` | `correct now` |
| `node.py serve [--config …]` | Mutating | Valid root-owned fixed config/binaries/support and exclusive node lock; writer additionally needs exact role/epoch/current-boot authority and valid databases; standby requires empty data. | No separate operation intent. It creates runtime directory/lock/logs and starts writer/uploader or followers. Concurrent replay is lock-refused; standby restart with existing data refuses. Protected process logs and exit/stderr are failure evidence. | `hat/node.py::{main,serve,load_config}`; `tests/test_node.py`; `tests/test_native_standby_contract.py` | `correct now` |
| `node.py activate [--config …]` | Mutating | Root; configured role must already be writer; valid fixed config; activation path must not exist. It has no controller operation/owner/revision input. | Exclusive-creates and fsyncs current-boot authority, then starts the service. Replay refuses because authority exists, but there is no surrounding durable operation intent in this CLI; a service-start failure leaves the authority file and reports exit/stderr. | `hat/node.py::{main,activate}`; `tests/test_node.py` | `contract missing` |
| `client.py produce --token-ledger … --output … --source-epoch … [limits/base]` | Mutating (main/aux writes and evidence) | Existing private 0600 token ledger under an owned 0700 directory; valid source epoch; loopback-only HTTP base; duration 0–120s, interval 0.1–5s, at most 1000 submissions. | Output is exclusive-created 0600. Start/submission/outcome/stop frames are flushed and fsynced. It never retries a request; transport/5xx/invalid success is uncertain. Same output refuses. A crash after response but before acknowledgement fsync can leave an incomplete ledger. | `hat/client.py::{produce,read_closed_ledger}`; `tests/test_fault_client.py`; `tests/test_fault_client_security.py` | `contract missing` |
| `client.py observe --output … [limits/base/timeout]` | Mutating (evidence only; GET-only remotely) | New output under owned 0700 directory; loopback-only HTTP base; duration 0–600s, interval 0.1–5s, timeout 0–5s. Anonymous 401/403 is the only “available” observation. | Output is exclusive-created 0600 and every frame is fsynced. No request retry; repeat requires a new output. Errors and censored windows are retained, not converted to downtime or cancellation proof. | `hat/client.py::observe`; `tests/test_fault_client_security.py` | `correct now` |

`node.py activate` and `client.py produce` expose different contract gaps. Root-only activation is intentionally manual but has no common operation authority, while the producer covers only its generated main/aux creates and cannot prove a complete acknowledgement ledger across a crash. These are not reasons to weaken their existing fail-closed checks. `recovery.py` has no standalone parser; its only operator CLI surface is `hat recover A` through `control.py`.

### Forced node dispatcher actions

`transition.py local|remote` is root-only. Remote mode additionally requires the forced command `hat-node`. Every request has exactly `action`, a 32-hex `operation`, configured `epoch`, current `boot_id` (except `probe`/`inspect-cold` may use null), and an exact action payload. Role constraints are enforced. For ordinary mutations, the dispatcher exclusive-writes `STATE/OPERATION/ACTION.json` with `status=intent` before the effect and replaces it with `status=done` afterward; the existing record prohibits replay. Controller-side `ControlIO` separately retains command intent/stdout/stderr/outcome, with timeout marked uncertain. Common validation is covered by `hat/transition.py::{main,validate_request}` and `tests/test_transition_guards.py`.

| Action | Class | Additional precondition/input | Intent, replay, failure evidence | Supporting tests | Finding |
| --- | --- | --- | --- | --- | --- |
| `probe` | Read-only | Healthy local node; static/disabled node service, restart=no, legacy writable units masked. | Bypasses node action records; repeatable; exit/stderr only at node, controller command record remotely. | `tests/test_control_io.py`; `tests/test_recover_driver.py` | `correct now` |
| `inspect-cold` | Non-service-changing; may create control metadata (not strictly read-only) | Cold cgroup, no known mutator, safe service policy, absent/stale authority, matching cold config. | No action record, but the full dispatcher may create `STATE` and `STATE/lock`; repeatable only after that metadata exists safely. | `tests/test_recovery_node.py`; `tests/test_rejoin_native_boundaries.py` | `documentation correction` |
| `inspect-frozen` | Non-service-changing; may create control metadata (not strictly read-only) | Standby role/current boot; completed bound freeze record; no later restore/prepare/activate; unchanged frozen logical signature. | No action record, but dispatcher may create/open control metadata. Repeats the check; exit/stderr plus controller command record. | `tests/test_transition_guards.py`; `tests/test_transitions.py` | `documentation correction` |
| `quiesce` | Mutating | Writer role/current boot; healthy writer; current authority; exact empty payload. | Action intent precedes signal. Stops TrailBase, proves mutators stopped, syncs all DBs, stops uploader, retains/revokes activation. No replay. | `tests/test_node.py`; `tests/test_transition_guards.py` | `correct now` |
| `freeze` | Mutating | Standby/current boot; complete positive cut; healthy same-epoch follower caught up to cut. | Intent precedes service stop and SQLite copies. No replay; subprocess output is retained. | `tests/test_transition_guards.py`; `tests/test_transitions.py` | `correct now` |
| `restore` | Mutating | Standby/current boot; same complete cut as a completed freeze; empty cgroup; unused fresh-restore workspace. | Intent precedes finite restore; rejected follower is retained. No replay. | `tests/test_transition_guards.py`; `tests/test_transitions.py` | `correct now` |
| `prepare` | Mutating | Standby/current boot; reserved epoch exactly `d1-OPERATION`; three signatures and fence digest; completed matching freeze/restore or recovery restore; no authority/processes. | Intent precedes retaining/replacing data, metadata, config, and replica prefix. No replay. | `tests/test_recovery_node_regressions.py`; `tests/test_native_standby_contract.py` | `correct now` |
| `activate` | Mutating | Writer/current boot; empty cgroup; completed same-operation prepare, matching signature and boot. | Dispatcher intent precedes boot-bound authority creation/service start. No replay; node/controller outputs retained. | `tests/test_recover_driver.py`; `tests/test_node.py` | `correct now` |
| `prepare-recovery` | Mutating | Writer/current boot; cold-safe absent/stale authority; distinct valid source epoch. | Intent precedes retaining config/replica and rewriting role to standby/source epoch. No replay. | `tests/test_recovery_node.py`; `tests/test_recovery_node_regressions.py` | `correct now` |
| `restore-recovery` | Mutating | Standby/current boot; complete cut and fence digest; completed bound recovery preparation. | Intent precedes finite restore into an unused workspace. No replay. | `tests/test_recovery_node.py`; `tests/test_recovery_node_regressions.py` | `correct now` |
| `rejoin` | Mutating | Writer/current boot in cold quarantine; reserved new epoch exactly `d1-OPERATION`; absent/stale authority; unchanged boot/config/replica identity. | Intent precedes retaining authority/config/replica/data/metadata, creating empty data, rewriting standby epoch, and starting followers. No replay. | `tests/test_rejoin_native_boundaries.py`; `tests/test_recovery_node_regressions.py`; `tests/test_native_standby_contract.py` | `correct now` |

The source-level `inspect_cold()` function is observational, but the installed dispatcher envelope is not guaranteed filesystem-read-only because it creates/opens control metadata before dispatch. Documentation and future checklists should call it “non-service-changing inspection” rather than “read-only command” unless the metadata precondition is explicitly established. The same qualification applies to `inspect-frozen`.

## Unresolved assumptions (blockers)

- **BLOCKER — live observation:** present A/B/C service state, installed aliases, SSH/tunnel behavior, and private helper behavior are not repository-verifiable; no current-state claim is established here.
- **BLOCKER — restore/drill authorization:** restore verification and D2/D3 drills require a fresh owner authorization, bounded scope/timeout, and an evidence destination; source review alone cannot establish operational readiness.
- **BLOCKER — qualification:** D4 on the stock runtime, automatic HA, abrupt physical-loss behavior, sustained capacity, and physical fault-domain redundancy remain unqualified; the runbook makes no such claim.

## Prioritized operational risk register

This register is repository-only. “Current evidence” means checked-in source, tests, and documented historical boundaries; it is not a current-live observation. Source-level gaps are not evidence that the historical or documented deployment is presently unsafe or experiencing an incident. Every live or mutating step requires the approval stated in its entry. **P0** means a gap that must be resolved before any future exercise or acceptance because it gates admission or evidence interpretation. **P1** means prerequisite contract or qualification work; it is not an immediate exercise gate unless its entry explicitly says so.

### P0 — completed ingress route identity/key-set admission, newly found (`contract missing`)

- **Current evidence:** `ingress_allowed` and `reconcile_existing` bind the current config hash, but the completed branch does not require exact route writer/epoch/key-set identity; the gap is also recorded in the route checks above.
- **Why it matters:** a valid-looking route can outlive or point at the wrong authority, allowing stale or incorrectly keyed service exposure.
- **Next repository-only step:** write the route-authority contract and threat cases, including writer, epoch, key-set, permit, boot/PID, and failure-boundary bindings; add design-level acceptance criteria before implementation.
- **Explicit approval:** owner approval for any implementation, installed change, route opening, ingress restart, request, or live observation.

### P0 — unified restore acceptance manifest/schema (`contract missing`)

- **Current evidence:** the runbook requires integrity, auth/session, records/membership, and exact restore-position/proof checks, but no objective manifest binds checks to restore class, source/target/epoch/position, and retained evidence.
- **Why it matters:** a partial or mismatched restore can be accepted as complete, or evidence from one restore can be substituted for another.
- **Next repository-only step:** define a versioned manifest/schema and deterministic refusal rules for each restore class; review it against preserved D2/D3 evidence without performing a restore.
- **Explicit approval:** owner approval for implementation or any restore, application request, process start, file creation, or live/mutating drill.

### P1 — complete acknowledged-mutation coverage and client-ledger crash window (`contract missing`)

- **Current evidence:** `hat/client.py::produce` covers generated main/aux creates only; the external ledger is fsynced after response handling, leaving a crash window, and all auth/data mutation paths are not covered.
- **Why it matters:** an acknowledged mutation may be absent from the recoverable image or unclassified after a client crash, undermining loss refusal and recovery acceptance.
- **Next repository-only step:** inventory every mutation path and specify receipt/ledger ordering, crash states, and proof requirements; add read-only contract tests/specs only.
- **Explicit approval:** owner approval for client/controller changes, generated or real mutations, restore, replay, or live observation.

### P1 — authoritative provider accepted-request, late-effect, and incarnation settlement (`contract missing`)

- **Current evidence:** `ControlIO.command` preserves timeout as uncertain; local/provider request identifiers do not establish accepted-request identity, cancellation, late-effect settlement, or protection against a reused guest incarnation.
- **Why it matters:** a timed-out power or control effect can arrive after authority changes and affect the wrong incarnation; retrying can duplicate an effect.
- **Next repository-only step:** document the required provider receipt/operation/incarnation contract and refusal matrix, using only pinned repository interfaces and historical evidence.
- **Explicit approval:** owner/provider authorization for any provider API call, power/action request, polling against private infrastructure, or implementation of the adapter.

### P1 — common authority-aware admission, including direct node activation (`contract missing`)

- **Current evidence:** controller paths bind operation/epoch/boot, but `node.py activate` accepts root plus fixed writer config and no distributed owner/revision/action identity; existing dispatcher validation does not close that bypass.
- **Why it matters:** one mutation path can activate outside the common stale-owner and replay protections.
- **Next repository-only step:** define one authority/revision/action envelope and apply it to controller, dispatcher, and direct activation paths; enumerate stale and duplicate refusal cases.
- **Explicit approval:** owner approval for implementation, installed activation changes, service starts/stops, activation, routing, or live drills.

### P1 — C/ingress single points of failure (`operational qualification missing`)

- **Current evidence:** repository docs and deployment configuration describe one C ingress path; tests do not establish redundant ingress or a failure-domain handoff. Historical D2/D3 evidence is explicitly not a current-live claim.
- **Why it matters:** loss or partition of C can make healthy node state unreachable and can prevent safe admission/verification.
- **Next repository-only step:** specify ingress authority and failure-domain requirements, then design a repository-only observation checklist and evidence schema; do not execute it.
- **Explicit approval:** owner approval for any tunnel, ingress reload/restart, network fault, request, or other live observation/mutation.

### P1 — sustained capacity and physical fault-domain qualification (`operational qualification missing`)

- **Current evidence:** short historical shared-VM samples and fixture/unit tests do not establish sustained resource headroom, host pause behavior, abrupt loss, or physical fault-domain separation.
- **Why it matters:** overload or correlated host failure can invalidate timing, durability, and availability assumptions used by recovery.
- **Next repository-only step:** define workload, duration, resource, pause, and physical-domain acceptance criteria plus a read-only evidence plan; no capacity run or provisioning.
- **Explicit approval:** owner approval for load, pause/fault injection, provider operations, new resources/spending, or any mutating qualification.

### P1 — certificate rotation and admin revocation (`operational qualification missing`)

- **Current evidence:** the audit records TLS/RBAC boundaries, but no repository evidence proves rotation, expiry overlap, revocation, or removal of administrator access across all channels; existing TLS channels may retain RPC access after expiry.
- **Why it matters:** stale credentials or certificates can preserve control after intended revocation, or rotation can strand recovery and ingress.
- **Next repository-only step:** specify channel-by-channel rotation/revocation contracts, expiry behavior, and rollback/refusal tests using fixtures only.
- **Explicit approval:** owner approval for credential/certificate changes, service reload/restart, access revocation, or private/live verification.

### C — private tunnel and installed-alias unverifiability (`contract missing`)

- **Current evidence:** `connect_demo.py`, installed `hat` aliases, SSH material, and present tunnel/process state are outside the repository-only audit; runbook wording correctly labels them unverifiable here.
- **Why it matters:** an alias or tunnel can target the wrong host/service, and repository tests cannot establish the actual access boundary.
- **Next repository-only step:** document the expected alias/tunnel contract and a sanitized, read-only verification artifact format; do not copy private values or execute the helper.
- **Explicit approval:** owner approval for opening a tunnel, using private credentials/endpoints, contacting A/B/C, or any request through the tunnel.

### Sequencing and scope boundary

The next work order is: **(1) documentation corrections (done), (2) read-only contract/design work, (3) separately authorized observations, and (4) reviewed implementation and live drills**. D4 stock-runtime scope remains closed. Forking or instrumenting the stock runtime is a new decision, not an implied follow-up or authorization. Historical D2/D3 evidence remains preserved below and is not relabeled as current-live evidence. This register adds no new current-live observation.

## Runbook/status comparison and prioritized findings

| Finding | Comparison and evidence | Class |
| --- | --- | --- |
| Manual D0–D3 only; no election, promotion-ready signal, automatic restart, or automatic failover | Runbook and status agree with `hat/node.py::{public_status,main}`, `hat/control.py::main`, and `tests/test_node.py`; no `promote` or force option exists. | `correct now` |
| Status is an observation, not freshness/RPO/promotion proof | Runbook wording matches `hat/node.py::public_status`, which always emits `promotion_ready=false` and bounds only sampled health; covered by `tests/test_node.py`. | `correct now` |
| Interrupted operations retain intent and refuse blind replay | Runbook/status match `hat/control.py::Journal`, `hat/transition.py::main`, `tests/test_transitions.py`, and `tests/test_recover_driver.py`. A timeout remains uncertain in `hat/control.py::ControlIO.command`; it is not cancellation proof. | `correct now` |
| D3 recovery rejects known acknowledged losses but is not complete ACK coverage | The current guard in `hat/recovery.py::_fault_outcomes` rejects a nonempty `lost` list and `tests/test_recover_driver.py` verifies no activation/routing/replay. Status correctly says the external ledger is not on every mutation path and may crash after response before fsync; `hat/client.py::produce` confirms that ordering. | `contract missing` |
| Common authority-aware admission is absent | Controller requests bind operation/epoch/boot, but direct `node.py activate` accepts only root plus fixed writer config, and the local dispatcher trusts root-shaped requests. `docs/status.md` correctly records this as a remaining gate. | `contract missing` |
| Completed ingress route authority is incomplete | Completed `ingress_allowed`/`reconcile_existing` bind the current config hash but do not require exact route writer/epoch/key-set identity. Do not treat completed admission/reconciliation as fully qualified or exercise it until separate code design/tests. | `contract missing` |
| Unified restore acceptance contract is absent | No objective manifest/schema enumerates required checks per restore class or binds source/target/epoch/position/evidence. The runbook checklist is a stop boundary, not authorization to conduct or accept a new restore. | `contract missing` |
| `reconcile-rejoin-boot` is not an inspect-only command | Runbook correctly scopes “provider inspect only” to provider action and immediately says node rejoin follows. `hat/control.py::reconcile_rejoin_boot` writes a marker, archives failure, invokes node cold inspection, and calls `rejoin`; `tests/test_rejoin_boot_reconciliation.py` verifies rejoin occurs once without another power action. | `correct now` |
| Cold/frozen dispatcher inspections are not strictly filesystem-read-only | `hat/transition.py::main` may create the state directory and lock before either inspection. `tests/test_recovery_node.py` proves only the inner `inspect_cold()` function does not alter inspected authority/config. | `documentation correction` |
| Private tunnel helper and installed aliases are not repository-verifiable | Runbook describes the helper and installed `hat` links, but their private/installed content is outside this audit. Checked-in target behavior can be reviewed; exact installed mapping, SSH behavior, and present process state cannot. | `contract missing` |
| Clean one-shot D2/D3, abrupt physical loss, sustained capacity, physical fault domains, certificate rotation/revocation, and C redundancy remain unqualified | Runbook/status already preserve these limits. Unit/fake-I/O checks in `tests/` establish code contracts, not these operating properties. | `operational qualification missing` |
| Automatic HA, D4 admission, and production-readiness claims | Both documents explicitly withhold them; D4 stock-runtime infeasibility is outside this D0–D3 command audit. | `out of scope` |

## Historical/live-only claims

The following are documentary records, not revalidated conclusions of this audit:

- the current A-writer/B-standby/C-ingress state and installed hashes/processes;
- completed D2/D3 operations, measured positions/write counts/observation window, and retained provider/oracle evidence;
- prior live, Ubuntu, publication, and private full-suite results;
- private credential permissions, provider permissions, host identity, and protected evidence retention.

`docs/runbook.md` presents the latest operating snapshot and `docs/status.md` explicitly labels older checkpoints historical. Nothing in this repository-only audit promotes those records into fresh live evidence. A current-state claim requires a separately authorized observation and retained result; a recovery/ACK acceptance claim requires a separately authorized restore/drill, not a status probe.

## Self-review disposition

- Positive implementation claims above cite checked-in source and test paths.
- Live/historical claims are isolated and not asserted as current observations.
- Mutating commands include evidence-only and dispatcher-metadata mutation; no restore, smoke, activation, reconciliation, or rejoin path is labeled read-only.
- No private identifier, endpoint, credential value, raw evidence, or secret was copied into this document.
