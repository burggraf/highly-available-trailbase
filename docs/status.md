# HAT delivery status

D0 checkpoint: 2026-09-08 UTC. Delivery direction approved by owner; work stays on `main`. The [delivery reset](plans/ha-delivery-reset.md) governs next work, not the old qualification sequence.

| Delivered | Currently building | Blocker | Next demonstration |
| --- | --- | --- | --- |
| D0 and D1: persistent private URL, real auth/records, visible three-DB standby, independent finite restore/auth proof | D1 handoff; D2 not started | No live D1 blocker; intermittent legacy test defects remain (details below) | Owner inspection of the running demo; next delivery milestone is planned switchover |

## D1 delivered demo (current)

Final live gates passed against the updated installed code. A/B source hashes and C's ingress config match this checkout. Final selected positions advanced in all three histories, from main=15/session=12/aux=11 to main=16/session=13/aux=13; B reached that cut. A second independent finite restore at that cut passed integrity, ledger reads and retained/revoked auth checks on C, then stopped. Latest A/B status: main=17/session=14/aux=13, no refusals, TrailBase only on A. Protected final evidence: `delivery-status.json`, `final-catchup.json`, `final-all-oracle-results.txt`, and `final-url-smoke.jsonl` under `~/.config/hat/d1-deployment/`.

**Publication validation: 242 passed, 1 failed.** The unchanged M0 `test_graceful_stop_fails_if_sigkill_is_required` failed its expected-exception assertion; its child gets only a 50 ms sleep to install a signal handler, without a readiness handshake. One focused rerun passed (1 test). This supports a timing-sensitive test diagnosis, not a clean full-suite result. Raw suite evidence: `~/.config/hat/d1-deployment/publish-1788892956602181000/`. No experiment code was changed. D1 node/ingress and M1/S3 suites passed in that publication run.

**Earlier precommit regression status: all 243 passed**, with protected evidence in `~/.config/hat/d1-deployment/precommit-1788892357065034000/`. The known intermittent defect below is not fixed or erased by this successful run.

The preceding final-delivery checks had **242 passed, 1 failed**. All 11 new node checks pass locally and on installed Ubuntu entrypoints; the ingress boundary test, 39 M0 tests and 11 S3 tests pass. Of 181 unchanged M1 tests, `test_cross_host_early_failure_records_each_node_without_unbound_state` failed at line 2324 because an earlier dummy secret `x` is redacted inside a random temporary path. The one test-only confirmation rerun reproduced the same path-sensitive failure with a different temporary name. Both logs are preserved (`final-experiments_m1_test_run.py.log`, `confirmed-experiments_m1_test_run.py.log`). No expectation weakening or experiment edit was made. The subsequent full precommit validation passed after the owner authorized publication. This unchanged experiment/test-isolation defect is recorded as a nonblocking D1 residual, not a clean full-regression PASS or acceptance of `ee6e468`.

### Review dispositions

Separate spec and safety reviews returned concrete blocking findings; parent verified and fixed each, then validated the exact deployed source. No independent clean re-review is claimed.

| Finding | Disposition and evidence |
| --- | --- |
| Unknown INFO/DEBUG messages accepted | Fixed: explicit pinned per-message field/type schemas; unknown-message regressions and complete captured A/B log replay pass. |
| Proxy collection prefix overmatch | Fixed: exact collection-boundary regex; regression and live denied-path checks pass; HAProxy config validation/reload succeeded. |
| DB names accepted without valid DB objects | Fixed: regular/nonempty files, no symlinks, SQLite headers/structure/required fixture schema, truly empty bootstrap, and runtime inode/type checks. Temporary-directory regressions and real writer startup pass. |
| Optional/unconfined support identity manifest | Fixed: exact D1 config/migration/key anchors, confined non-symlink regular files and fingerprints. Empty/missing/traversing/symlinked manifests are rejected; installed entrypoints pass. |

Both nodes now run the consolidated correction. B's old followed directory was preserved at `/var/lib/hat-demo/follow-before-review` after stopping its followers; a fresh directory follows the same existing epoch. No old roots, DBs, S3 prefixes or logs were deleted. This one operator-managed software-update restore is not a shipped rejoin command.

### Historical D1 checkpoints

- Working URL: **http://127.0.0.1:18080/** through the workstation's managed SSH tunnel to C. Opened in Chrome and its visible writer/standby status inspected. Access and credentials: [runbook](runbook.md).
- A: one real TrailBase writer plus Litestream uploader; B: three Litestream followers, TrailBase stopped; C: persistent loopback HAProxy with restricted pinned tunnels. All use the existing demo hosts, with fresh protected deployment paths/identity and a separate backup epoch.
- Real HTTP smoke through C passed: login, revoked refresh rejection, main+aux create/read, anonymous access denial. External private acknowledgement ledger: `~/.config/hat/d1-deployment/url-smoke.jsonl`.
- Node tests initially failed for the missing entrypoint, then passed locally and against the installed Ubuntu entrypoint. A real missing-activation startup check refused writable startup. Writer services have no automatic restart or boot enablement, and activation is boot/epoch-bound. This is not a reboot or power-fence drill.
- First integration failure: A's new log parser rejected known pinned compaction records and the configured retention warning. Captured real log fixtures, added a failing regression, then applied the focused pinned-contract correction. Seven node checks passed locally/on Ubuntu; B subsequently reached A's selected positions.
- Second integration failure: writer log refusal reappeared; `check_restore.py` exited 1 at its writer-health assertion before any restore. Work stopped at the two-failure budget. The owner then approved one bounded diagnostic and justified targeted fix.
- Diagnostic established the omitted INFO `l0 retention enforced` schema using captured logs and pinned v0.5.17 `db.go`. Local L0 cleanup continues with remote retention disabled. Added the real record to the pinned fixture and strict message-specific field/type validation. Replayed complete captured A/B replication logs with no rejected records; eight node tests passed locally and on Ubuntu. Unknown/error logs remain fail-closed.
- Focused resumption updated the installed entrypoint, restarted only A, passed a fresh stable-URL smoke and completed the independent finite three-DB restore/auth oracle on C. Selected positions: main=10/session=8/aux=8. All integrity/foreign-key checks, ledger record reads, shared signing identity, retained refresh acceptance and revoked refresh rejection passed. Oracle stopped; no TrailBase on B or C. Protected result: `~/.config/hat/d1-deployment/finite-restore-result.json` and `resumed-url-smoke.jsonl`.
- Deployment remains available. Matching observed A/B TXIDs alone are not a backup-freshness, RPO, or promotion-readiness claim. `promotion_ready` remains false.
- Raw commands, stderr, log archives, credentials and results remain protected under `~/.config/hat/d1-deployment/`. C's protected oracle setup is retained but not running. Nothing historical was deleted. No old qualification workflows or remote reprovisioning were run.
- Fresh checkpoint `1788889974840323000` under the private deployment evidence directory captured raw logs and current safety state. A/B positions were main=7, session=6, aux=6; A refused log health, B reported no refusal. No TrailBase process on B or C. All 238 direct checks passed (7 node + 39 M0 + 181 M1 + 11 S3); these are not the independent-restore gate.
- Post-fix checkpoint `1788890603158100000`: A/B main=11, session=9, aux=9 with no refusals; no TrailBase on B/C. All 239 direct checks passed (8 node + 231 legacy). Protected snapshots and validation logs retained beside the earlier failed checkpoint.
- Separate bounded read-only reviews use run `55b09a25-f112-425a-9df9-e36bba33a314`. Spec child `d67197f4-684c-454e-a5dc-2fd639aad23d` aborted with `Request was aborted`, not a verdict. Preserved the dirty `main`/`ee6e468` checkpoint (no worktree) under `review-abort-*`, then revived the same review protocol as `dd5ae235-516d-4dc3-968c-beb6646c0e8b`. Safety child `a00e65cb-3b9e-4f9f-b963-2471d61cdb88` also ended with `Request was aborted`; preserved `safety-review-abort-*` and recovered its final report through same-protocol run `ef0cfc29-cfb6-4805-be5b-0764752181bd`. Both final review artifacts were delivered; parent dispositions are above. Parent owned edits/live actions; no CLI fallback or old qualification runner was used.
- D1's live HTTP/auth, standby, independent restore and review-fix deployment gates are delivered. D2/D3 have not started. The current legacy regression limitation is recorded above; no further routine deployment approval is needed.

## D0 checkout and validation

- HEAD: `ee6e468` (`harden Task5 retained evidence accounting`). Its interrupted independent review remains **uncompleted**; passing regressions do not accept the commit as safety-reviewed.
- Starting checkout: `main`, no tracked changes; owner-provided `docs/plans/ha-delivery-reset.md` untracked. This checkpoint adds only this status document. No commit, push, reset, or historical deletion performed.
- Direct regressions, all exit 0: `python3 experiments/m0/test_run.py -q` (39 tests), `python3 experiments/m1/test_run.py -q` (181), `python3 experiments/m1/test_s3.py -q` (11). Total: 231 tests.
- Protected validation logs: `~/.config/hat/d0-validation/20260908T155504Z/`.
- No active managed process/subagent runs at initial inspection; local process-name inspection found no TrailBase/Litestream or old Python/SSH runner. New D0 collectors and tests have finished.
- `experiments/m1` is frozen qualification evidence. No old workflow, `cross-host`, provisioning, storage mutation, fencing, or qualification retry was launched.

## Historical D0 node safety (before D1 deployment)

Private read-only snapshot: `~/.config/hat/d0-inventory/20260908T155653Z/`. Inventory ordering maps A/B/C to the three existing private inventory entries. All three SSH host keys matched inventory pins and all hostnames matched. Collection ran as root, exited 0 on every node, and reported no filesystem scan errors.

- A/B/C: no TrailBase, Litestream, HAT or HAProxy process found. Both `hat-trailbase.service` and `hat-litestream.service` are masked/inactive with MainPID 0. Observed listeners are SSH and local DNS only; no application endpoint exists.
- Each node has about 961 MiB RAM, about 646–656 MiB available at collection, and 17–18 GiB free disk. These are capacity observations, not workload qualification.
- Retained binary candidates exist on all three nodes; SHA-256 inventories are private. Verify a selected pair against the pinned artifact records before reuse. No reprovisioning performed.
- Historical sensitive/support candidates: A has 48 secret directories containing 48 nonempty files, 48 TrailBase configs, 13 fixture-private manifests, 14 replication YAML configs, and 3 old remote control scripts. B and C each retain 1 old remote control script. No `.env` files were found in the inspected trees.
- A focused second read-only check found **all 128 candidates behind root-owned mode-0700 ancestors, with no symlink in their ancestor chains**. They are not active deployment credentials. Historical auth material is still present; do not call prior cleanup globally complete or reuse these secrets in D1. Preserve the protected history; use fresh demo identity in a separate deployment root. No files were scrubbed or permissions changed remotely.
- Scope: process metadata, listeners, systemd state, and filenames/permissions under qualification/deployment roots plus HAT-named trees under `/tmp` and `/root`. This is not a whole-disk secret-content audit, credential-validity check, or provider power-fence proof. Raw results and identifiers remain private.

The first local collector failed before SSH (exit 1): `inspect.py` shadowed Python's standard-library `inspect`, causing a circular import through `dataclasses`. Its raw traceback is preserved at `~/.config/hat/d0-inventory/initial-local-import-failure.log`. Renaming the collector resolved that exact cause; the corrected collection and focused protection check exited 0. No remote mutation occurred in any D0 collection.

## Reuse and uncompleted gates

Reuse the pinned TrailBase v0.33.11/Litestream v0.5.17 artifacts, three-DB/auth fixture, established config/TXID/finite-restore knowledge, existing hosts and boot containment. Do not import the experiment controller as the operational service.

At D0 all D1 gates were uncompleted. The current partial delivery above now provides the node entrypoint/systemd integration, stable private ingress, live create/read/auth and visible per-DB standby observations. Independent finite restore with fixture/auth validation and bounded review dispositions have now completed; current regression limitations are recorded above.

D2 planned switchover, D3 completed physical fencing/recovery/rejoin and loss measurement, automatic control plane, HA ingress, and supported-release qualification remain undelivered. Old Linux parity is incomplete/NO-GO, storage election is rejected, and Task5 remains unqualified. None of these statuses is relabeled by D0's passing tests.

## Deployment approval checkpoint

After the form timed out, the owner explicitly authorized necessary work on all three demo servers, including D1 installation and protected persistent credentials. No additional routine D1 deployment approval is needed. The owner subsequently authorized committing and pushing the D1 checkpoint. Evidence-preservation and delivery-scope constraints remain unchanged.

Authorized D1 deployment now uses the existing A/B/C, only needed packages/services, protected persistent demo secrets and C's loopback proxy through `http://127.0.0.1:18080`. Raw app/admin access stays private; no new public listener or DNS was introduced. C is a prototype single point of failure. Writer startup remains operator-controlled, never autonomous on boot.

Historical material remains protected and untouched. Any needed change to that policy requires owner approval. D3's exact disruptive-test approval is separate and has not been requested or granted. No automatic failover work starts before D3.
