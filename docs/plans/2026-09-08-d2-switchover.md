# D2 Planned Switchover Implementation Plan

> **REQUIRED SUB-SKILL:** Use the executing-plans skill to implement this plan task-by-task.

**Goal:** `hat switchover B` moves the running three-database demo from A to B through the existing private URL, without losing acknowledged pre-cut operations.

**Architecture:** C is the only manual controller. A local OS lock serializes commands; a SQLite journal commits intent before each external action. An interrupted operation refuses automatic retry. Node-side commands own process shutdown and filesystem changes; the controller never fabricates remote Python source. Completed external fencing precedes candidate startup, and a remotely restorable fresh-epoch baseline precedes routing.

**Tech Stack:** Python standard library, existing pinned TrailBase/Litestream, systemd, HAProxy, pinned SSH, operator-owned private fencing adapter.

Work on `main` as requested. D1 publication is `e692e51`. Keep experiments frozen, preserve every source/follower/oracle directory, and retain private operational outputs outside Git. Four-hour active-work review limit; stop after two failed integrated attempts. No D3 power-loss/rejoin test is authorized by D2.

## Owner-authorized reconciliation addendum

After the first integrated attempt stopped at oracle directory permissions, the owner explicitly approved one bounded reconciliation of the existing operation. A is fenced and B frozen; the corrected isolated same-cut oracle passed. `hat reconcile-compare <operation>` accepts only the exact journal prefix ending in the original comparison intent. It records reconciliation intent, rechecks completed fencing/current provider identity and unreachability, inspects B's boot-bound unchanged frozen state, and reruns the independent oracle. Only matching cut/signatures/auth evidence can append comparison completion. Original intents, epoch and archived failure remain; prior phases are never replayed. Activation/baseline/routing/verification then use the original guards. There is no general resume or force bypass. This continuation is the second integrated attempt; the two-failure stop remains in effect.

### Additional owner-authorized verification-only continuation

After the second attempt reached routing but failed on its first HTTP verification request, the owner explicitly approved one bounded readiness diagnosis/fix and verification completion. Isolated real HAProxy/systemd tests reproduced `Type=simple` returning before the listener and verified `Type=notify` returning after HTTP readiness. Install `deploy/hat-ingress-readiness.conf` as C's `20-readiness.conf` drop-in; retain the maintenance gate.

`hat reconcile-verify <operation>` accepts only the exact original pending verification prefix, the pre-write URLError failure, and no existing new-write ledger. It records one exclusive continuation intent, rechecks A's fence, B's boot/epoch/health, route hash and baseline evidence, independently rechecks the baseline, preserves the failure, then starts the approved route using a fresh boot/live-owner permit and native readiness. It performs the original auth/new-write/finite-restore checks before appending verification completion. No prior phase is replayed or overwritten. Any failure stops this additional allowance; no further attempt is implicit.

## Prerequisites and decisions

- The owner approved installing the existing private adapter/provider credential on C with root-only access. The adapter allowlist is not narrower provider-token permissions.
- Provisioning performs only read-only provider inspection. Match actual provider-returned identity to the pinned target, not just the adapter's echoed request. Before a power action, this check must happen again.
- Existing C SSH keys permit forwarding only. Add a dedicated controller key restricted to a fixed node-command dispatcher; do not copy the workstation's personal SSH key or give application processes fencing credentials.
- Existing node supervision stops all children together. D2 needs a distinct graceful TrailBase stop while its uploader stays alive to sync every database; SIGKILL or uncertain shutdown cannot produce a planned cut.
- Existing proxy and page are A-specific. B needs a private application tunnel; the page must no longer claim A is always the writer. Close application ingress durably throughout transition and after an interrupted controller restart.

## Batch 1 — durable local authority (no live power action)

Files: create `hat/control.py`, `tests/test_transitions.py`.

1. Write failing direct tests for exclusive ownership, persisted intent visible before an action, interrupted action refusal on reopen, refusal of phase skipping/retry, and unsafe journal paths.
2. Run `python3 tests/test_transitions.py -v`; verify the missing implementation fails.
3. Implement one controller journal using `fcntl.flock` and SQLite `synchronous=FULL`, with append-only step evidence and fresh operation/epoch IDs. Keep one unfinished operation; there is no force/resume bypass.
4. Execute the tests against the actual module locally and against its installed copy on C in isolated temporary directories. Tests must not touch live controller state or call a provider.

## Batch 2 — node transition primitives

Files: extend `hat/node.py`, `tests/test_node.py`, `deploy/hat-demo.service` only as required.

1. Add failing tests for graceful mutator stop before all-DB sync; premature child exit, forced kill and missing sync positions refuse a cut.
2. Implement fixed commands for quiesce/cut, uploader stop, follower stop/freeze and candidate preparation. Bind every request to configured node, source epoch, current boot and operation ID. Persist node intent before mutation; uncertain replay refuses.
3. Preserve old data/sidecars/config/activation evidence in operation-specific protected paths. Never reuse source or follower metadata for the new uploader.
4. Test missing DBs, keys/version mismatch, a live follower, stale authority and any failed validation preventing activation. Use the existing database/support validation rather than a second schema implementation.

## Batch 3 — one operational controller path

Files: extend `hat/control.py`, `tests/test_transitions.py`, `tests/restore_baseline.py`, `tests/demo_smoke.py`, `deploy/haproxy.cfg`, `deploy/index.html`.

1. Wire fixed phases: preflight → close ingress → quiesce/cut and stop uploader → completed fence → freeze candidate → compare → fresh-epoch activation → remote baseline → route → HTTP/auth verification.
2. Persist intent before each external command and completion only after validating its result. Capture bounded private stdout/stderr and exit code. Timeout is uncertainty, never success or automatic retry.
3. Validate exact fence target, operation/time ordering and terminal provider observation, independently check unreachability, and verify reboot containment established before fencing.
4. Compare all frozen candidate databases logically with independent finite restores at the recorded cut; validate schema, identity, integrity and the external acknowledgement ledger. Run auth tests only on isolated copies, not the candidate before activation. If candidate state is uncertain, retain it and use validated fresh restores rather than bypassing the comparison.
5. Activate B with a fresh epoch and metadata. Independently restore its published baseline before routing. Verify every pre-cut acknowledgement and retained/revoked auth through the unchanged URL; make and back up fresh writes.

## Batch 4 — bounded installed validation and delivery

1. Run installed entrypoint tests with real Ubuntu/systemd/binaries. Local mocks are not integration evidence.
2. Run node/ingress/transition tests and the three existing direct regression suites without modifying frozen expectations. Retain and report intermittent legacy failures separately.
3. Obtain separate bounded spec and safety reviews. Parent owns all integration and live mutations; no automatic agent implementation chain.
4. Perform one planned A-to-B transition after the pre-transition gates pass. Preserve the failed stage and deployment safety state if anything fails. Do not rerun the whole command against unfinished state.
5. Leave B serving the same URL, A fenced, new writes remotely restorable; update `docs/status.md` and `docs/runbook.md` with proof and limitations. Redundancy restoration and the explicitly approved disruptive recovery drill belong to D3, not this milestone.
