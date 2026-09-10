# Private manual demo runbook

**Current state: A serves the unchanged private URL as the healthy writer; B is a healthy same-epoch standby with three native followers and no TrailBase. D3 powered-off-writer recovery and cold rejoin completed with explicit boot-evidence reconciliation. Fresh post-rejoin writes and historical auth were independently restored. See [status](status.md) for retained failures, uncertainty accounting and limits. No D4 or automatic-control work is authorized by this runbook.**

This is a persistent disposable **manual recovery demo, not automatic HA**. D1, reconciled D2 and reconciled D3 have real HTTP/auth and independent restore proof. A clean one-shot handover/recovery has not been demonstrated. Unchanged legacy tests have historical intermittent failures, retained below. Provider shutdown may flush gracefully; abrupt physical power loss and production readiness are not qualified.

## Current operating envelope and safety checklist

- **Envelope:** manual D0–D3 only. D4 is infeasible on the stock runtime; no automatic HA, election, promotion, or failover is provided.
- **OBSERVATION (non-disruptive):** use only the existing demo page, `docs/status.md`, `hat status` on A/B, and `systemctl status hat-demo.service` already described below. Record the observed time, role/epoch, positions, health/refusal text, and command output; these are observations, not freshness/RPO or promotion proof. The private `connect_demo.py` helper and installed `hat` aliases are not repository-verified, so do not infer their exact behavior from this checkout.
- **Restore verification (not non-disruptive):**
  - Preparation/read-only source review: confirm the approved cut, epoch, source/target identities, protected baseline, oracle/support identity, route and auth prerequisites, and an unused evidence/workspace path. Review the existing restore procedure and its guards; do not treat this review as a restore.
  - Actions requiring fresh explicit authorization: any restore or integrity check that creates files, starts/stops processes, opens sessions, or sends application requests (including auth, writes, or restore reads). These actions are service/evidence mutations, not observations.
  - **Acceptance:** accept restore verification only when the explicitly approved required integrity, authentication/session, record/membership, exact restore-position/proof checks are complete and all expected evidence is retained. Any missing, mismatched, or uncertain check refuses acceptance and escalates; a rerun is not a substitute.
- **Manual drill gate:** before any D2/D3 drill, obtain fresh explicit authorization naming the operation, target, scope, cut, timeout, and evidence destination. Stop on any precondition mismatch, refusal, unexpected state, failed guard, timeout, or ambiguous result; a timeout is uncertain completion, not permission to retry. Do not blindly retry or reactivate. Preserve logs/ledgers and escalate to the owner for a bounded decision; retain successful and failed evidence.
- **Blockers:** completed ingress admission/reconciliation binds the current config hash but does not require exact route writer/epoch/key-set identity; do not treat it as fully route-authority qualified or exercise it until separate code design/tests. No objective unified restore acceptance manifest/schema enumerates required checks and source/target/epoch/position/evidence bindings; this checklist is a stop boundary, not authorization to conduct or accept a new restore.

Restore/source-review details and the historical evidence remain in [Checks and delivery evidence](#checks-and-delivery-evidence), [D2](#d2-controller-and-interrupted-operation-boundary), and [D3](#d3-commands-and-completed-recovery).

## Access the running demo

Open **http://127.0.0.1:18080/** on the operator workstation. The current Pi-managed `d1-private-demo-access` process keeps an SSH tunnel to C's loopback HAProxy listener open. The UI shows A/B role, epoch, per-database positions, observation time and refusal reasons.

Login credentials are in the protected local file `~/.config/hat/d1-deployment/demo-login.json` (username `hatdemo`). Do not paste the password into shared reports. The page can authenticate, create and read records in both main and aux. Tokens remain in page memory, not local storage. The HTTP smoke check additionally tests retained/revoked session behavior.

If the workstation tunnel closes, restart it (only when port 18080 is free):

```sh
python3 ~/.config/hat/d1-deployment/connect_demo.py
```

Closing this tunnel does not stop the server deployment. Do not expose a public listener to work around an access problem. C is explicitly a prototype single point of failure.

## Installed layout and commands

On A and B:

- `/opt/hat-demo/node.py`: the same program tested locally and on Ubuntu.
- `/opt/hat-demo/bin/{trail,litestream}`: pinned v0.33.11/v0.5.17 executables copied from previously provisioned artifacts after SHA-256 checks.
- `/etc/hat-demo/node.json`: root-owned fixed role, epoch, hostname, binary and application-support fingerprints; bootstrap is now false.
- `/etc/hat-demo/litestream.yml`: three independent DB prefixes in a new demo epoch, separate from qualification history; short socket `/run/hat-demo/ls.sock`.
- `/etc/hat-demo/backup.env`: root-readable persistent backup credentials, loaded by systemd, not command arguments. The original backup credential's access scope is unchanged; no separate read-only standby key was provisioned. It is transport access, not election authority.
- `/var/lib/hat-demo/depot`: live writer on A and clean same-epoch follower data on B. Original data and metadata are retained in operation-tagged sibling directories. Signing/config identity and protected historical auth were preserved through recovery.
- `/var/lib/hat-demo/logs`: protected process logs, preserved across restarts. Retention is disabled in this short-lived demo; disk growth needs operator attention. This is not a production retention policy.

Read status over existing pinned SSH access on A or B:

```sh
hat status
systemctl status hat-demo.service
```

Node status is a transport observation, not a freshness/RPO guarantee. Compare A's published positions and B's applied positions only within the same epoch. A live process alone is never a promotion-readiness signal; `promotion_ready` is always false. Unknown/error logs latch a refusal for the process lifetime; inspect the protected logs rather than clearing the refusal blindly.

`hat-demo.service` runs as an unprivileged dedicated user, owns its children through a systemd control group, has no automatic restart and is deliberately not enabled on boot. Writer startup additionally requires a root-owned activation record matching the current boot and fixed epoch in `/run/hat-demo-activation.json`. A reboot removes that record. `activate` can only authorize the configured writer; it does not change a standby's role.

Startup checks require real nonempty regular databases, valid SQLite headers/structure and the required fixture schema. Bootstrap only accepts an actually empty directory. Runtime checks refuse missing/replaced database objects. The support manifest must contain the fixed config, migrations and signing-key anchors; empty, escaping or symlinked manifests are rejected.

Do not restart the standby against existing files: it intentionally refuses. The implemented cold rejoin is restricted to the exact verified D3 operation boundary; it is not a generic restart/resume mechanism. Do not clear directories or delete a failed follower's files to make startup pass. Do not run `activate` again or remove activation records as a retry mechanism.

On C, `hat-ingress.service` and `hat-tunnel-{a,b}.service` are enabled. HAProxy binds only `127.0.0.1:18080`; application and node-status connections use pinned SSH tunnels. Tunnel keys use dedicated non-shell accounts restricted to local forwarding and exact loopback destination ports. Raw TrailBase/admin access stays private. Ingress exposes only the demo page, A/B status, selected auth endpoints and main/aux Record APIs; registration/admin are not exposed by the proxy. Private deployment/publication boundaries are historical operational facts, not repository access-control guarantees.

## Checks and delivery evidence

```sh
python3 tests/test_node.py -q
python3 tests/test_ingress.py -q
python3 tests/demo_smoke.py --base http://127.0.0.1:18080 \
  --credentials ~/.config/hat/d1-deployment/demo-login.json \
  --ledger ~/.config/hat/d1-deployment/CHOOSE-A-NEW-LEDGER.jsonl
```

The smoke check performs real writes and login/logout; each new ledger is exclusive-created and private. Preserve it for external acknowledgement comparison. Do not run checks repeatedly just to clear a failure.

The first writer health refusal was caused by an incomplete new log parser: pinned compaction records and the explicitly disabled-retention warning were rejected. A sanitized real log fixture now covers those records; the focused correction passed on macOS and Ubuntu. The resumed deployment then showed B reaching A's selected positions and passed the HTTP/auth smoke through the stable URL.

A subsequent refusal on A stopped the initial independent-restore check before any restore ran. The two-failure budget was honored. The owner then explicitly approved one bounded diagnostic and justified targeted fix.

The captured record was INFO `l0 retention enforced`, with `deleted_count` and `max_l1_txid`. Pinned v0.5.17 `db.go` confirms that local L0 cleanup still runs with remote retention disabled. A real fixture and strict event-specific field/type check now cover it; ERROR records, malformed TXIDs, unknown fields and unrelated warnings still fail closed. Full captured A/B replication-log replay and eight node tests passed. Only A was restarted to apply the correction; B's files/followers stayed intact.

C's `/etc/hat-oracle`, `/opt/hat-oracle`, and `/var/lib/hat-oracle` contain the protected independent oracle. `tests/restore_baseline.py` passed with the real pinned binaries on Ubuntu: finite restore at main=10/session=8/aux=8, all three integrity/foreign-key checks, restored main/aux acknowledgement-ledger reads, shared signing identity, retained refresh acceptance and revoked refresh rejection. Its isolated TrailBase was stopped, and no TrailBase runs on B or C. The source writer and standby were left running throughout the oracle.

Protected proof: `~/.config/hat/d1-deployment/finite-restore-result.json`, `resumed-url-smoke.jsonl`, and the raw command logs in that directory. This is a D1 baseline check, not crash recovery or a claim of atomic multi-DB recovery. Do not run the private one-time installation scripts again against existing state.

## Historical D1 review corrections and validation

Both independent reviews completed with concrete findings, which the parent verified and fixed. The installed program now uses explicit pinned log message/field/type schemas, enforces database object/schema and runtime identity checks, and requires the fixed support identity anchors. HAProxy matches exact main/aux collection boundaries rather than sibling-name prefixes. The 11 node regressions pass locally and on Ubuntu; the ingress boundary regression and live denial checks pass.

To run the consolidated correction on B, its followers were stopped and the old data directory retained at `/var/lib/hat-demo/follow-before-review`. Fresh followers restored the same epoch into the normal data path. No database/history was deleted, and this is not a general rejoin command. A/B code and C config fingerprints were checked against this checkout.

Final live verification: all three published histories advanced (15/12/11 → 16/13/13 for main/session/aux), B reached the selected cut, and a new independent finite restore at 16/13/13 passed real records and retained/revoked auth. C's isolated oracle stopped; A/B remain running. Protected proof is in `delivery-status.json`, `final-catchup.json`, `final-url-smoke.jsonl` and `final-all-oracle-results.txt` in the private deployment directory.

Publication validation: **242 passed, 1 failed**. The unchanged M0 SIGKILL-required test missed its expected exception; its fixed 50 ms startup wait has no child-readiness handshake. One focused rerun passed. Evidence: `publish-1788892956602181000` in the private deployment directory. No experiment code was changed; no clean full-suite publication result is claimed.

Earlier precommit tests: **all 243 passed** (`precommit-1788892357065034000` in the private deployment directory). The preceding final-delivery runs had **242 passed, 1 failed**. The unchanged M1 `test_cross_host_early_failure_records_each_node_without_unbound_state` compares an unredacted temporary path with evidence where a previously registered dummy secret `x` was scrubbed. One test-only rerun reproduced it. Both failed logs are preserved; the frozen experiment was not edited or weakened. This test-isolation residual does not invalidate the independent D1 live checks. That earlier full suite passed, but the intermittent defect remains unfixed.

## D2 controller and interrupted-operation boundary

C's `/usr/local/bin/hat` points to `/opt/hat-control/control.py`. The original `hat switchover B` operation is now complete; do not initiate another promotion or manually manipulate its journal. `/var/lib/hat-control/journal.db` retains committed phase intents/results. The dedicated controller SSH key permits only the node dispatcher, with boot/epoch/operation guards; arbitrary commands are rejected. C's private provider credential is root-only and its original provider permissions are unchanged. Actual completed fencing and provider-observed identity/DNS checks passed in the first attempt.

The first command stopped after fencing A and freezing B: a private umask reduced the oracle parent to 0700. Explicit chmod and installed/unprivileged oracle checks verified the correction. The owner then authorized `hat reconcile-compare <operation>`, which accepts only the exact pending comparison boundary and does not replay earlier phases. It rechecks the fence and frozen state, reruns the oracle, preserves the original failure, and appends comparison completion in the existing journal/epoch.

That continuation passed comparison, B activation, fresh-epoch baseline restore and routing, but failed on the first final HTTP request with connection refused. Ingress closed and work stopped at the two-attempt limit. The owner explicitly approved one additional bounded readiness diagnosis/fix and verification-only completion.

An isolated real test proved the service's default `Type=simple` returned before HAProxy was listening. C now installs `deploy/hat-ingress-readiness.conf` at `/etc/systemd/system/hat-ingress.service.d/20-readiness.conf`: `Type=notify`, `NotifyAccess=all`, using the existing `haproxy -Ws` command. Keep the separate `10-maintenance.conf` gate; never replace it with a readiness workaround.

The restricted `hat reconcile-verify <operation>` accepted only the original pending verification prefix, pre-write HTTP failure and absent new-write ledger. It revalidated fencing, B's boot/epoch/health, route hash and baseline, independently rechecked the baseline, archived the second failure and used native readiness before the original verification. All auth/records, new writes and independent fresh-write restore checks passed. The same journal now has all ten phases complete and maintenance removed. Both failures and continuation evidence are retained. Neither reconciliation command is a generic retry/force mechanism or applicable to arbitrary future failures.

Ingress startup executes `hat ingress-check`: this is a read-only admission check and does not itself change service state. Its four incomplete/completed branches are: (1) completed operation, requiring maintenance absent and completed route evidence with the exact writer, epoch, key set, and current ingress config hash; (2) incomplete verified-D3 rejoin-tail, requiring the maintenance marker, valid D3 proof, retained route writer/epoch, and matching route hash, without permit/boot/PID; (3) incomplete D3 `route_pending`/`verify_pending`, requiring the exact D3 phase prefix, maintenance/no failure, D3 proof as applicable, and permit operation/current boot/PID/birth/config hash, with `verify_pending` additionally validating recorded route writer/epoch/config facts; and (4) incomplete D2 `route_pending`, requiring the exact ordered D2 phase prefix through `baseline|done` followed by `route|intent`, empty intent evidence, maintenance operation identity, no failure, and permit operation/current boot/PID/birth/config hash. Completed-operation maintenance reconciliation is accepted only for the latest completed target B and requires the exact route writer, epoch, key set, and current ingress hash; completed D3 target A refuses. `reconcile_existing` is service-changing because it may create/remove maintenance metadata and stop/start ingress under the journal lock. Neither case provides automatic failover or general recovery. These are checked-in source/test contracts, not fully qualified live route authority.

A/B's `transition.py` performs quiesce, freeze, finite-restore fallback, prepare and activate under root-only operation records. `inspect-cold` and `inspect-frozen` are non-service-changing inspections, but their dispatcher envelope may create control metadata; they are not strictly read-only. Rejected follower data and prior epoch data/metadata are retained. Preparation copies only the three validated databases, not follower sidecars. Do not invoke these phases manually or reactivate A. D3/rejoin still needs its separate disruptive-test approval.

## D3 commands and completed recovery

C's root-only commands are deliberately narrow:

- `hat recover A`: consume the exact private `/etc/hat-control/recovery-input.json`, completed B authority, protected baseline, sealed fault ledger and real producer-death evidence. Verify B offline, independently restore a selected old-epoch cut, then activate/verify A in a reserved fresh epoch. This command does not initiate the fault.
- `hat rejoin B <operation>`: only at the unused verified A-serving boundary. Verify A, boot B into quarantine, bind its actual new guest boot, retain original files, start clean followers and verify same-epoch catch-up. No blind retry.
- `hat reconcile-rejoin-boot <operation>`: only the exact retained pending boot intent/failure with unique successful original power-on/cold command evidence. A durable one-shot marker precedes fresh node/provider checks. It performs **provider inspect only**, requires the identical safe cold guest, archives the failure, and executes the first node rejoin under the same controller lock. It is not a generic resume/force command.

The completed operation is `59f3e121806a43dfb2326fb0d2a62eba`; all three commands now refuse reuse of that boundary. Do not rerun the private drill/install scripts. A normal reboot removes `/run` activation authority; safe cold inspection permits absent or validated stale authority, never current authority or live mutators.

Measured result: 51 acknowledged fault writes recovered, 0 acknowledged missing, 87 unacknowledged absences ambiguous; protected records/auth passed. The observer brackets approximately 68.35 seconds between successful observations. Final fresh-epoch restore and B catch-up both reached main/session/aux **5/6/5**. Preserve original ledgers, unsuccessful attempts, archived failure and reconciliation evidence. No lossless/general RPO or universal RTO promise follows from this sample.

## Evidence and limits

Protected local commands, raw stdout/stderr, configuration and client ledgers: `~/.config/hat/d1-deployment/`. Original qualification roots/prefixes/logs are unchanged. A later decommission must explicitly identify only the new deployment's services, paths and credentials; there is no automatic cleanup command.

No uploaded-file HA, custom jobs, gapless SSE, automatic election or cross-file atomic recovery promise. Asynchronous replication can lose acknowledged writes. The D2 handover completed with explicit recovery checkpoints, not a clean one-shot run. D3 recovery and redundancy restoration completed with explicit reconciliation, not a one-shot run. URL availability is not proof that failover is safe.
