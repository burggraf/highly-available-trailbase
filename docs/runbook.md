# D1 private demo runbook

D1 is delivered as a persistent disposable demo, **not HA**. Real HTTP/auth, three-DB catch-up, independent finite restore/auth and the deployed review corrections have passed. Unchanged legacy regression tests have intermittent failures, documented below. No failover, rejoin, automatic recovery or production readiness is claimed.

## Use the running demo

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
- `/var/lib/hat-demo/depot`: live writer on A, continuously restored files on B. Both have the same new demo signing/config identity. Historical auth material was not reused.
- `/var/lib/hat-demo/logs`: protected process logs, preserved across restarts. Retention is disabled in this short-lived demo; disk growth needs operator attention. This is not a production retention policy.

Read status over existing pinned SSH access:

```sh
hat status
systemctl status hat-demo.service
```

Node status is a transport observation, not a freshness/RPO guarantee. Compare A's published positions and B's applied positions only within the same epoch. A live process alone is never a promotion-readiness signal; `promotion_ready` is always false. Unknown/error logs latch a refusal for the process lifetime; inspect the protected logs rather than clearing the refusal blindly.

`hat-demo.service` runs as an unprivileged dedicated user, owns its children through a systemd control group, has no automatic restart and is deliberately not enabled on boot. Writer startup additionally requires a root-owned activation record matching the current boot and fixed epoch in `/run/hat-demo-activation.json`. A reboot removes that record. `activate` can only authorize the configured writer; it cannot promote B.

Startup checks require real nonempty regular databases, valid SQLite headers/structure and the required fixture schema. Bootstrap only accepts an actually empty directory. Runtime checks refuse missing/replaced database objects. The support manifest must contain the fixed config, migrations and signing-key anchors; empty, escaping or symlinked manifests are rejected.

Do not restart the standby against existing files: it intentionally refuses, pending a later explicit clean rejoin implementation. Do not clear directories or delete a failed follower's files to make startup pass. Do not run `activate` again or remove activation records as a retry mechanism.

On C, `hat-ingress.service` and `hat-tunnel-{a,b}.service` are enabled. HAProxy binds only `127.0.0.1:18080`; application and node-status connections use pinned SSH tunnels. Tunnel keys use dedicated non-shell accounts restricted to local forwarding and exact loopback destination ports. Raw TrailBase/admin access stays private. Ingress exposes only the demo page, A/B status, selected auth endpoints and main/aux Record APIs; registration/admin are not exposed by the proxy.

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

## Final review corrections and validation

Both independent reviews completed with concrete findings, which the parent verified and fixed. The installed program now uses explicit pinned log message/field/type schemas, enforces database object/schema and runtime identity checks, and requires the fixed support identity anchors. HAProxy matches exact main/aux collection boundaries rather than sibling-name prefixes. The 11 node regressions pass locally and on Ubuntu; the ingress boundary regression and live denial checks pass.

To run the consolidated correction on B, its followers were stopped and the old data directory retained at `/var/lib/hat-demo/follow-before-review`. Fresh followers restored the same epoch into the normal data path. No database/history was deleted, and this is not a general rejoin command. A/B code and C config fingerprints were checked against this checkout.

Final live verification: all three published histories advanced (15/12/11 → 16/13/13 for main/session/aux), B reached the selected cut, and a new independent finite restore at 16/13/13 passed real records and retained/revoked auth. C's isolated oracle stopped; A/B remain running. Protected proof is in `delivery-status.json`, `final-catchup.json`, `final-url-smoke.jsonl` and `final-all-oracle-results.txt` in the private deployment directory.

Publication validation: **242 passed, 1 failed**. The unchanged M0 SIGKILL-required test missed its expected exception; its fixed 50 ms startup wait has no child-readiness handshake. One focused rerun passed. Evidence: `publish-1788892956602181000` in the private deployment directory. No experiment code was changed; no clean full-suite publication result is claimed.

Earlier precommit tests: **all 243 passed** (`precommit-1788892357065034000` in the private deployment directory). The preceding final-delivery runs had **242 passed, 1 failed**. The unchanged M1 `test_cross_host_early_failure_records_each_node_without_unbound_state` compares an unredacted temporary path with evidence where a previously registered dummy secret `x` was scrubbed. One test-only rerun reproduced it. Both failed logs are preserved; the frozen experiment was not edited or weakened. This test-isolation residual does not invalidate the independent D1 live checks. That earlier full suite passed, but the intermittent defect remains unfixed.

## Evidence and limits

Protected local commands, raw stdout/stderr, configuration and client ledgers: `~/.config/hat/d1-deployment/`. Original qualification roots/prefixes/logs are unchanged. A later decommission must explicitly identify only the new deployment's services, paths and credentials; there is no automatic cleanup command.

No uploaded-file HA, custom jobs, gapless SSE, automatic election or cross-file atomic recovery promise. Asynchronous replication can lose acknowledged writes. D2/D3 and their safety checks remain separate future work. Do not use the working URL as proof that failover is safe.
