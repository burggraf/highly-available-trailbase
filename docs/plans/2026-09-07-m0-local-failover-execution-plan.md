# M0 Local Follow-to-Writer Experiment Implementation Plan

> **REQUIRED SUB-SKILL:** Use the executing-plans skill to implement this plan task-by-task.

**Goal:** Determine whether unmodified TrailBase and Litestream binaries can maintain a data-hot standby, promote its followed database set safely after the local primary processes stop, and replicate the promoted state into a fresh history.

**Architecture:** One Python standard-library harness owns isolated primary, standby, and replacement-standby directories and their subprocesses on one machine. Litestream uses a local-file backup destination; TrailBase stays stopped on followers until promotion. An external-to-the-application operation ledger and independent finite restores provide the correctness oracle.

**Tech Stack:** Python 3.11+ standard library (`subprocess`, `unittest`, `urllib`, `sqlite3`, `hashlib`, `json`, `pathlib`); pinned TrailBase and Litestream release executables; `gh` for initial artifact retrieval. No package installation, containers, hosting SDKs, S3 account, custom SQLite build, or HA controller.

---

Status: **execution plan only; experiment not implemented or run.** Created 2026-09-07.

## 1. Scope and limits

This is a bounded subset of the [master plan](2026-09-07-master-plan.md), not all of M0 and not a production deployment. Read [upstream findings](../upstream-findings.md), [state inventory](../trailbase-state.md), and the [promotion protocol](../architecture.md) before implementing.

It supplies evidence for HAT-001, HAT-008, HAT-010, HAT-011, HAT-012, HAT-014, HAT-017, HAT-021 and HAT-022 **only to the extent explicitly tested below**. Do not close those broader issues wholesale.

### Included

- Main, session, and one attached database; node-local logs.
- Record CRUD, append-only measurement writes, login/session refresh and logout.
- Initial restore, ongoing following, controlled shutdown, abrupt process loss, and deliberately unreplicated writes.
- Promotion of the actual followed files; separate one-shot restores for comparison.
- A new backup epoch after promotion and a freshly restored third node.
- Process/file ownership guards, strict required-file handling, and a corrupt-candidate refusal check.

### Explicitly excluded

- Zero-RPO acknowledgement barriers; zero-downtime or zero-RTO claims.
- Automatic election, distributed leases, external fencing implementation, ingress switching, provider selection or provisioning.
- Host/disk/power failure, network partitions, S3/R2 semantics, remote storage durability, production RPO/RTO certification.
- Read-serving TrailBase replicas, live schema changes, heavy-load/long-reader tests, arbitrary mid-page follower crashes, exhaustive retention/compaction faults.
- File uploads, realtime, WASM, external jobs, email, OAuth, and cross-DB transactional guarantees.

There are **no file-upload columns or requests** in this fixture. TrailBase may create its unused local `uploads/` directory; that is a laboratory-only exception to the production S3/R2 storage requirement, not validation of local file storage for HAT.

Local `SIGKILL` plus `wait()` proves these owned processes exited. It does **not** demonstrate a production fence or loss of the host page cache. The file backup shares the same physical host; it is an API/lifecycle surrogate, not an independent durability domain.

## 2. Files and deliverables

Create during execution, not while reviewing this plan:

| File | Purpose |
| --- | --- |
| `experiments/m0/run.py` | Single CLI harness; fixture/config literals, process ownership, scenarios, assertions, private artifacts |
| `experiments/m0/test_run.py` | Small standard-library test suite for the harness's dangerous guards and measurement logic |
| `experiments/m0/README.md` | Prerequisites, exact pinned-artifact retrieval, commands, limitations and result interpretation |
| `docs/reports/m0-local-failover.md` | Manually reviewed, sanitized result report; initially “not run,” never invented results |

Modify `README.md` to link the runnable experiment once it exists, and `docs/work-register.md` to link actual evidence without claiming untested issues are solved. No other production modules or dependency manifests are needed.

Generate SQL migrations and textproto/YAML fixtures from small literals in `run.py`; do not introduce a template library or one file per helper. Keep all binaries, DBs, keys, tokens, raw logs and results in a newly created private directory **outside the checkout**. Do not commit them, even if they contain only synthetic application data.

Suggested run layout:

```text
$WORK/                              # new private directory, mode 0700
  artifacts/                       # downloaded archives/binaries + provenance
  run-<unique-id>/
    a/traildepot/                  # initial writer
    b/traildepot/                  # actual followed candidate, then writer
    c/traildepot/                  # replacement standby for epoch e2
    backup/e1/{main,session,aux}/
    backup/e2/{main,session,aux}/
    meta/{e1,e2}/{main,session,aux}/
    oracle/{e1,e2}/                # finite restores from sealed backup history
    evidence/                     # frozen pre-start copies and sidecar inventory
    logs/                         # child stdout/stderr, private
    commands.jsonl                # redacted command/lifecycle events
    operations.jsonl              # fsynced client-observed operation ledger
    result.json                   # private machine-readable results
```

Use a short private socket path under the run directory; check the platform's Unix-socket path limit. Use absolute paths, `Path.as_uri()` for file URLs, and JSON-quoted strings in generated YAML. Reject a run root inside the repo, symlinks to someone else's data, existing populated output directories, and path aliases between nodes/epochs.

## 3. Executable baseline and commands

Rechecked release metadata when writing this plan: TrailBase **v0.33.11**, Litestream **v0.5.17**. Pin this pair for the initial series; if a newer release is chosen before execution, update provenance and revalidate every command/schema before collecting results. Never upgrade midway through a series.

### Artifact preparation

Use a clean implementation branch and the worktree setup skill if isolation is needed. In the implementation checkout:

```sh
WORK=$(mktemp -d /tmp/hat-m0.XXXXXX)
chmod 700 "$WORK"
mkdir "$WORK/artifacts"
```

Select matching release archives:

| Host | TrailBase archive | Litestream archive |
| --- | --- | --- |
| Linux x86_64 | `trailbase_v0.33.11_x86_64_linux.zip` | `litestream-0.5.17-linux-x86_64.tar.gz` |
| Linux ARM64 | `trailbase_v0.33.11_aarch64_linux.zip` | `litestream-0.5.17-linux-arm64.tar.gz` |
| macOS ARM64 | `trailbase_v0.33.11_aarch64_apple_darwin.zip` | `litestream-0.5.17-darwin-arm64.tar.gz` |
| macOS x86_64 | `trailbase_v0.33.11_x86_64_apple_darwin.zip` | `litestream-0.5.17-darwin-x86_64.tar.gz` |

Example retrieval for Linux x86_64 (choose the matching row, not emulation):

```sh
gh release download v0.33.11 --repo trailbaseio/trailbase \
  --pattern trailbase_v0.33.11_x86_64_linux.zip --dir "$WORK/artifacts"
gh release download v0.5.17 --repo benbjohnson/litestream \
  --pattern litestream-0.5.17-linux-x86_64.tar.gz \
  --pattern checksums.txt --dir "$WORK/artifacts"
```

Record release asset names/URLs/digests from the GitHub API; compare downloaded SHA-256 with the published digest/checksum **before extraction/execution**. Record hashes of the extracted executables too. A locally computed hash alone is not upstream authenticity evidence. Inspect archive contents and extract only under the private artifact directory; no global installation or `sudo`.

Pass explicit executable paths to the harness. Record `trail --version`, `trail --help`, `trail run --help`, `trail user add --help`, `litestream version`, `litestream restore -h`, `litestream replicate -h`, and `litestream sync -h`; distinguish expected help exit codes from execution failures. Record OS/architecture, Python version and `sqlite3.sqlite_version`. Obtain TrailBase's SQLite version through its supported admin query route if available, otherwise record **unknown**, not Python's version as a substitute. Unavailable native libraries are a preflight blocker, not permission to replace the released binary silently.

macOS runs are useful development evidence; only Linux runs speak to the first planned deployment OS. Neither is a cloud-provider qualification.

### Planned harness CLI

```sh
python3 -m unittest discover -s experiments/m0 -p 'test_run.py' -v

python3 experiments/m0/run.py --trail "$TRAIL" --litestream "$LITESTREAM" \
  --work-root "$WORK" --scenario preflight

python3 experiments/m0/run.py --trail "$TRAIL" --litestream "$LITESTREAM" \
  --work-root "$WORK" --scenario all --repeat 3
```

`TRAIL` and `LITESTREAM` are absolute paths assigned after verified extraction. Each invocation creates a new `run-<unique-id>`; no implicit resume or destructive cleanup. `--scenario` supports `preflight`, `fixture`, `follow`, `graceful`, `crash`, `lagged-crash`, `guards`, and `all`. `all` runs the three promotion scenarios and follow check `--repeat` times with fresh directories, and guard checks once. Setup phases run as needed per scenario, not against leftover state.

Exit codes: **0** all requested checks met, **1** assertion/correctness failure, **2** environment/upstream capability blocker. Expected data loss in an asynchronous scenario is not automatically a failed experiment; lost *sealed-baseline* writes, corruption, or an unclassified result is.

In Pi, run long harness commands using the process tool; the harness owns its subprocesses. Do not shell-background binaries or use sleeps as proof of readiness. Use bounded condition-based waits inside the harness (initial budget: 60 seconds per readiness/catch-up phase, 10 seconds for graceful stop); report timeout evidence rather than repeatedly increasing limits. These are test budgets, not proposed HA SLOs.

## 4. Fixture contract

### Databases and migrations

Create these migrations under both A and B's approved fixture configuration; B's migration files are provisioned assets, not executed until promotion:

- `<depot>/migrations/main/U100__hat_ops.sql`
- `<depot>/migrations/aux/U100__hat_ops.sql`

Both contain:

```sql
CREATE TABLE hat_ops (
  id INTEGER PRIMARY KEY,
  op_key TEXT NOT NULL UNIQUE,
  payload TEXT NOT NULL
) STRICT;
```

`main` and `aux` are independent append-only ledgers for loss measurement; do not pretend one paired HTTP write is an atomic cross-DB transaction. Reserve a separate scratch ID for CRUD tests, and exclude it from append-only loss counts. Use client-generated stable `op_key` values such as `e1-main-000001`; validate payloads, not just row counts.

Minimal source-verified textproto shape:

```textproto
server { site_url: "http://localhost" }
databases: [{ name: "aux" }]
record_apis: [{
  name: "main_ops"
  table_name: "hat_ops"
  acl_authenticated: [CREATE, READ, UPDATE, DELETE, SCHEMA]
}, {
  name: "aux_ops"
  table_name: "aux.hat_ops"
  attached_databases: ["aux"]
  acl_authenticated: [CREATE, READ, UPDATE, DELETE, SCHEMA]
}]
jobs {
  system_jobs: [
    { id: BACKUP disabled: true },
    { id: HEARTBEAT disabled: true },
    { id: LOG_CLEANER disabled: true },
    { id: AUTH_CLEANER disabled: true },
    { id: QUERY_OPTIMIZER disabled: true },
    { id: FILE_DELETIONS disabled: true },
    { id: ANONYMOUS_CLEANER disabled: true }
  ]
}
```

No WASM directory contents, external email/OAuth setup, public assets, subscriptions, or file columns. Disabled jobs keep the recovery cut measurable; they do not prove a production read-only mode. Force attached initialization by exercising `aux_ops` before configuring replication; verify `data/aux.db` actually exists.

Initialize only A. Use `trail --depot <A> user add m0-user@example.invalid <synthetic-password>` while its server is stopped, then run `trail --depot <A> run --address 127.0.0.1:<port>`. The password argument is synthetic but keep it and tokens out of public command logs. Capture normalized config and generated keys; provision frozen config, migrations and required `secrets/` into B/C **before failure injection**, not by borrowing A's disk during recovery. Never independently initialize B/C or copy A's `data/`, `backups/`, or Litestream metadata into them. Allow each node to create its own logs and version metadata at writable startup.

Bind to loopback only. Use one free port per node, detect bind collisions, and fail/retry only allocation—not another process's port. Check `/api/healthcheck` plus an actual expected API response; an open port is not sufficient.

### HTTP operations

Use `urllib.request`/`urllib.error` with explicit timeouts, JSON content type, and full response-body validation. Never blindly retry a mutation after an ambiguous timeout.

- `POST /api/auth/v1/login` with `{"email":"m0-user@example.invalid","password":"..."}`; save `auth_token`, `refresh_token`, `csrf_token` privately.
- `Authorization: Bearer <auth_token>` for protected records.
- `POST /api/records/v1/{main_ops|aux_ops}` with explicit `id`, `op_key`, `payload`; require one returned `ids` element and verify the record through GET.
- `GET`, `PATCH`, `DELETE /api/records/v1/{api}/{returned-id}` for the scratch-row CRUD check; deletion must result in absence.
- `POST /api/auth/v1/refresh` with `{"refresh_token":"..."}`; use this to prove session recovery, since JWT verification alone can be stateless.
- `POST /api/auth/v1/logout` with a second session's refresh token; confirm that token no longer refreshes before taking the baseline.

Use one retained and one revoked session. Record their expected outcomes without publishing token values. Under crash testing a late, unreplicated session may be lost; label that separately from the preserved baseline. Read measured records by individual ID, or explicitly paginate—never compare only the first default list page.

Source anchors: [attached API fixture](https://github.com/trailbaseio/trailbase/blob/v0.33.11/client/testfixture/config.textproto), [user CLI](https://github.com/trailbaseio/trailbase/blob/v0.33.11/crates/cli/src/args.rs#L218-L271), [auth endpoints](https://github.com/trailbaseio/trailbase/tree/v0.33.11/crates/core/src/auth/api). Exact behavior still gets an executable smoke check; a mismatch is reported, not hidden by directly editing auth tables.

### Litestream shape

Generate one A replicator config and one later B replicator config. This example is a template; replace paths, and repeat the DB entry for `session` and `aux`:

```yaml
socket:
  enabled: true
  path: "/ABS/RUN/a.sock"
  permissions: 0600
retention:
  enabled: false
logging:
  type: json
dbs:
  - path: "/ABS/RUN/a/traildepot/data/main.db"
    meta-path: "/ABS/RUN/meta/e1/main"
    replica:
      type: file
      path: "/ABS/RUN/backup/e1/main"
      sync-interval: 1s
```

No log database entry, `-exec` child, auto-recovery mode, or imaginary `lease:` field. The harness owns TrailBase and Litestream separately so it can stop the writer while leaving replication available for a controlled flush. Disabled retention preserves evidence during short experiments; still inventory compaction artifacts and seal history only after the replicator exits.

Commands issued by the harness as argument arrays:

```sh
litestream replicate -config /ABS/RUN/a.yml
litestream sync -socket /ABS/RUN/a.sock -wait -json /ABS/RUN/a/traildepot/data/main.db
litestream restore -f -follow-interval 1s \
  -o /ABS/RUN/b/traildepot/data/main.db file:///ABS/RUN/backup/e1/main
litestream restore -dry-run -json \
  -o /ABS/RUN/oracle/e1/main.db file:///ABS/RUN/backup/e1/main
litestream restore -txid HEX_TXID \
  -o /ABS/RUN/oracle/e1/main.db file:///ABS/RUN/backup/e1/main
```

Repeat independently per required DB. IPC CLI `txid`/`replica_txid` are JSON numbers; follow `main.db-txid` and restore plan positions use hexadecimal strings. Parse explicitly; do not compare strings lexically or positions across different DBs/epochs. Source: [sync CLI](https://github.com/benbjohnson/litestream/blob/v0.5.17/cmd/litestream/sync.go), [TXID sidecars](https://github.com/benbjohnson/litestream/blob/v0.5.17/replica.go#L1714-L1772), [config example](https://github.com/benbjohnson/litestream/blob/v0.5.17/etc/litestream.yml).

## 5. Safety, evidence and validation contract

### Process ownership

Use `Popen(argv, start_new_session=True, ...)` with `cwd` inside the private run directory, private output files and a minimal child environment; do not inherit unrelated service/storage credentials. Track each owned process handle and role in memory. Never use `pkill`, PID discovery by name, or a PID from an old run manifest. Cleanup in `finally`: signal only owned groups, bounded wait, escalate to SIGKILL as needed, and reap them. A graceful scenario that needed escalation is **not** a successful graceful trial.

Before starting B writable, require A's TrailBase and replicator and **all B follower processes** to have exited and been reaped. Before starting C writable in any future work, apply the same rule; this experiment never starts C's TrailBase. Refuse unknown ownership. Unexpected child exit fails the phase even if another health probe succeeds.

Preserve failed-run files. Do not install an automatic “delete and retry” cleanup path. Missing data, mismatched history, or integrity failures cannot fall through to TrailBase initialization.

### Follower error gate

Read each follower's captured stdout/stderr incrementally while waiting and drain it fully after exit, preserving raw lines and normalized error events with node/DB/epoch identity. In v0.5.17 restore initializes **text** logging even with `-json`; the primary replicator's JSON logging setting does not change follower logs. Parse the pinned text severity/message fields, including `level=ERROR` and `follow: error applying updates`, and recognize command-level stderr failures. Do not infer health from TXID progress alone.

Any unexplained apply/decoder/storage error makes a positive scenario fail or block, even if the process stays alive, later catches up, and final comparisons match. An unrecognized log format is an instrumentation blocker, not permission to ignore errors. Add parser fixtures and a negative control where an error is followed by successful progress; promotion must remain refused. Expected injected failures pass only their named negative test and remain recorded as errors.

### Client ledger and outcome calculation

For each attempt record DB, epoch, operation key, intended payload hash, monotonic submit/completion times, response status, and outcome (`acknowledged`, `rejected`, `ambiguous`). Classify as rejected only when the fixture's verified endpoint semantics establish no mutation, such as authorization rejection before execution. Timeouts, broken responses, and potentially post-commit server errors are ambiguous—not automatically rejected because they are non-2xx. Resolve every submitted operation into exactly one class before reporting. Flush and `fsync` the JSONL ledger after each completed observation. It is outside A/B and survives the child-process failures being tested; it does not survive a real host loss by design.

Measure per DB using operation keys:

```python
def outcomes(acknowledged, rejected, ambiguous, recovered, submitted):
    if (acknowledged & rejected or acknowledged & ambiguous or rejected & ambiguous
            or (acknowledged | rejected | ambiguous) != submitted):
        raise ValueError("outcome classes must partition submitted operations")
    return {
        "lost_acknowledged": sorted(acknowledged - recovered),
        "recovered_ambiguous": sorted(recovered & ambiguous),
        "recovered_rejected": sorted(recovered & rejected),
        "unexpected": sorted(recovered - submitted),
    }
```

Recovered ambiguous operations are possible after timeout; never call them duplicates or corruption merely because no response arrived. Validate payload equality separately and fail on recovered rejected operations or unexpected operations. For append-only fixtures, any loss within the known sealed baseline is a failure. Natural crashes may lose zero or more later acknowledged operations; record counts and IDs without inventing a time-based RPO bound from the polling interval.

### Sealed-history oracle

Once A's replicator has exited, record a sorted hash inventory of `backup/e1/`. Run `restore -dry-run -json` per DB to select the final reachable position; perform a finite restore at that exact position into `oracle/e1/`. No process may write that prefix afterward. Never use A's surviving DB/WAL as the recovery source in crash scenarios.

Followers must reach the selected final position before shutdown. After they exit, compare their actual files with the independent finite restores **logically**, not by DB-file hash: follow rewrites header counters/journal mode. Check table/schema inventory, fixture records including payloads, user/session rows and main/session user references. Exclude documented Litestream bookkeeping and node-local logs from business-data equality, not application tables. Keep raw auth-row comparisons private and publish only match/mismatch/counts.

Use SQLite `mode=ro`, short-lived connections, no `immutable=1`, and only on stopped outputs for this experiment. Check required files first so Python/TrailBase cannot create them. Save pristine candidate files/sidecars before inspection and before writable startup; diff file inventories afterward to identify startup side effects.

**Custom CHECK-function caveat:** ordinary Python SQLite cannot evaluate TrailBase's `is_uuid`, `is_email`, or `jsonschema` CHECK expressions. Perform structural `PRAGMA integrity_check` with connection-local `PRAGMA ignore_check_constraints=ON`, and label it **structural check, application CHECK expressions not evaluated**. Keep `foreign_key_check`, exact fixture/user/session comparisons, and subsequent real TrailBase API/auth checks as separate evidence. Do not stub UDFs, edit the schema, or claim a full TrailBase-aware constraint audit. If missing collations/functions still prevent structural validation, stop as a validator blocker rather than suppressing more checks. No such PRAGMA is applied to the running application.

The actual followed candidate must pass; silently promoting a fresh finite restore instead would evade the central experiment. Clean reseeding is demonstrated separately for C or an explicitly invalid candidate, not used to hide a normal-path mismatch.

## 6. Implementation tasks

Each task has a short red/green loop and a checkpoint. The larger end-to-end runs follow the passing guard tests; do not attempt every scenario in the first implementation step.

### Task 1: Own the run directory and child processes

**Files:** create `experiments/m0/run.py`, `experiments/m0/test_run.py`.

1. Write failing tests that an existing/non-private/aliased run path is rejected, only owned processes can be stopped, and promotion refuses any live source/follower. Use short Python child processes and `unittest.mock` where no real process is needed.
2. Run `python3 -m unittest discover -s experiments/m0 -p 'test_run.py' -v`; confirm failures are missing/incorrect behavior, not import-path mistakes.
3. Implement the minimal directory/argv/process-group helpers, bounded waits, cleanup, and `require_stopped(children)`; no persistent daemon or state-machine framework. Add `--scenario preflight` to capture binary provenance/help under the private root.
4. Rerun tests and preflight with verified binaries; verify cleanup by process-handle completion, not just a closed port. Inject one timeout and verify files/logs survive while children do not.
5. Commit only the two source files: `git commit -m "test: add isolated M0 process harness"` after explicit `git add` and `git diff --cached --check`.

**Checkpoint:** no experiment can overwrite a real depot or leave an untracked writer running; unsupported binary/host fails preflight clearly.

### Task 2: Build the real three-database fixture

**Files:** modify `experiments/m0/run.py`, `experiments/m0/test_run.py`.

1. Add failing checks for exactly `main.db`, `session.db`, `aux.db` in the replication inventory; reject `logs.db`, duplicate resolved paths, and mismatched binary versions. Confirm red with the same unittest command.
2. Implement the SQL/textproto literals above, A-only bootstrap, frozen non-DB provisioning, loopback startup, HTTP helper and fixture scenario.
3. Run `--scenario fixture`: scratch-row CRUD through both APIs; unauthenticated reads denied; retained session refresh succeeds; revoked session refresh fails; all three DB files exist. Capture A's SQLite/version and startup-side-effect observations.
4. Ensure B/C have no initialized application DB or running TrailBase. A must exit cleanly at scenario end. Rerun unit tests.
5. Commit: `git commit -m "test: add TrailBase main session and attached DB fixture"`.

**Checkpoint:** source-verified commands work with the actual binaries. If any fail, report the exact mismatch before changing the fixture contract; do not replace HTTP auth with SQL inserts.

### Task 3: Follow and compare against a finite restore

**Files:** modify `experiments/m0/run.py`, `experiments/m0/test_run.py`.

1. Add failing tests for decimal/hex position normalization, missing/malformed TXID sidecars, required-file checks before opening SQLite, and follower error parsing. Include an apply-error log followed by successful TXID progress; it must still reject promotion. Confirm red.
2. Implement file-backend configs, one replicator for the required set, three B followers, and a bounded wait on per-DB TXID progress, process health and the follower error gate. No SQLite readers on live followed files in this first experiment.
3. Run `--scenario follow`: record each follower's initial position, then write two business-row batches with explicit sync observations after each. After the initial session restore, create two new sessions, sync `session.db`, and require its follower TXID to advance. Retain one new session, revoke the other, sync again and require another session TXID advance; do not collapse creation/revocation into one observed batch. Both business DBs must also advance beyond their initial positions. Use 100 measured rows per business DB by default with 8 KiB payloads to cross page boundaries. An initial restore alone cannot pass for any required DB.
4. Stop A's TrailBase, flush all DBs while its replicator remains alive, then stop the replicator. Seal e1 and create the finite-restored oracle. Wait for B's final positions, stop/reap its followers, drain/check their logs, and perform the validation contract above. Require both pre-existing and newly retained/revoked session states and exact business rows to match; verify the newly retained session is present and the newly revoked session is absent.
5. Rerun tests; commit: `git commit -m "test: verify continuous follow against sealed restore history"`.

**Checkpoint:** no silent follower apply errors, unexplained stalls, missing history, or logical mismatch. Explicit sync is a laboratory observation/checkpoint, not a per-request durability barrier.

### Task 4: Promote the actual followed files after graceful shutdown

**Files:** modify `experiments/m0/run.py`, `experiments/m0/test_run.py`.

1. Add a failing test that promotion with a missing `session.db` or live follower invokes no TrailBase start command. Add a test that the new replica prefix/meta path differs from e1. Confirm red.
2. Implement `--scenario graceful` using Task 3's sealed handoff: stop all application traffic, stop A cleanly, final per-DB sync, stop replicator, follow to final cut, stop followers, validate and preserve evidence. Escalation to SIGKILL makes this trial fail its graceful classification.
3. Archive B's follow `*-txid` files after recording their positions; do not replay or copy foreign WAL/SHM or outbound replication metadata. Verify no unexpected journal sidecars; any anomaly blocks normal promotion. Start B writable with the frozen fixture/keys. Its normal writable startup may change schema bookkeeping/journal mode; record those changes, not byte equality.
4. Confirm **every** acknowledged fixture operation survived, both APIs read correctly, the old retained refresh token works, the revoked refresh token still fails, and B creates/writes its own `logs.db`. Then write fresh records through B. Measure B start-to-functional-API time and full quiesce-to-functional-API interruption separately.
5. Rerun tests; commit: `git commit -m "test: exercise graceful promotion of followed TrailBase state"`.

**Checkpoint:** this proves controlled local switchover only. No standby was running writable before A stopped, and no fresh oracle DB was substituted for B.

### Task 5: Measure abrupt and deliberately lagged recovery

**Files:** modify `experiments/m0/run.py`, `experiments/m0/test_run.py`.

1. Write and run these failing measurement tests before implementing the outcome helper; also test that invalid/overlapping outcome classes raise `ValueError`:

```python
import unittest
from run import outcomes

class OutcomeTests(unittest.TestCase):
    def test_acknowledged_and_ambiguous_are_distinct(self):
        result = outcomes({"a", "b"}, set(), {"c"}, {"a", "c"}, {"a", "b", "c"})
        self.assertEqual(result["lost_acknowledged"], ["b"])
        self.assertEqual(result["recovered_ambiguous"], ["c"])
        self.assertEqual(result["recovered_rejected"], [])
        self.assertEqual(result["unexpected"], [])

    def test_recovered_rejection_is_not_ambiguous(self):
        result = outcomes(set(), {"denied"}, set(), {"denied"}, {"denied"})
        self.assertEqual(result["recovered_rejected"], ["denied"])
        self.assertEqual(result["recovered_ambiguous"], [])
```

2. Implement the ledger/outcome contract and a known replicated baseline shared by both scenarios. Establish retained/revoked session outcomes before that baseline; do not depend on late unreplicated auth state to validate recovered records.
3. Implement `--scenario crash`: while sequential HTTP writes are active, SIGKILL A's TrailBase and replicator without a final sync/graceful shutdown. Record signal-send and observed-exit times separately—the two processes do not disappear atomically. Stop issuing new requests, resolve/log the in-flight request, reap both processes, and never restart the old replicator. Follow to the now-sealed backup cut and promote B as above.
4. Implement `--scenario lagged-crash`: establish/flush a baseline, stop A's replicator cleanly and verify e1 is sealed, then acknowledge 10 additional records per business DB plus one new login while TrailBase still runs. SIGKILL TrailBase. Recover solely from e1. Require the baseline to survive and the deliberately unreplicated tail to be absent; the late refresh token must fail, while the baseline retained/revoked outcomes remain intact.
5. For each scenario classify acknowledged loss, recovered ambiguous writes, recovered rejected writes, payload mismatch, per-DB skew and auth results. A nonempty `recovered_rejected` or `unexpected` result fails the scenario; add an aggregation test proving these cannot yield PASS. Include an actual denied record insertion with a unique operation key and verify it is absent after recovery. Natural crashes with no loss are valid observations, not evidence of zero-RPO. The lagged scenario must demonstrate that the loss detector can actually see missing acknowledged writes. Rerun unit tests.
6. Commit: `git commit -m "test: measure acknowledged-write loss in local crash recovery"`.

**Checkpoint:** A's surviving files are never a recovery source; loss stays confined to after the sealed baseline; corruption or unexpected records fail. This is a tail-loss fixture, not a validated production loss budget.

### Task 6: Establish epoch e2 and rebuild redundancy

**Files:** modify `experiments/m0/run.py`, `experiments/m0/test_run.py`.

1. Add a failing test that a replica destination equal to e1 or another DB's path is rejected; include path/symlink alias checks, not just string inequality. Confirm red.
2. Extend every promotion scenario to start B's outbound replication into fresh `backup/e2/<db>` and `meta/e2/<db>` paths. Never reuse A's metadata; e1 remains sealed and hash-inventoried.
3. Explicitly sync B's new writes, then start C's three followers from e2 and record their initial positions. After that initial restore, write another business batch and create two fresh sessions on B. Sync and require progress for all three C followers. Revoke one of these sessions, retain the other, sync `session.db` again and require another session TXID advance. Apply the same follower error gate as for B. C's TrailBase stays stopped.
4. Quiesce/stop B, finish replication, seal e2, stop C followers, drain/check their logs, and compare C with finite e2 restores and B's expected recovered-plus-new business/session state. The newly retained session must be present and the newly revoked session absent; initial-only session restoration cannot pass. Lost e1 tail must not reappear. Verify e1's hash inventory did not change; record e2 startup/internal bookkeeping separately from application records.
5. Rerun unit tests; commit: `git commit -m "test: reseed a standby from the promoted writer epoch"`.

**Checkpoint:** a new writer can produce independently restorable history; not merely answer one request after promotion. Measure reseed duration separately from client-visible interruption.

### Task 7: Prove refusal paths without hiding failures

**Files:** modify `experiments/m0/run.py`, `experiments/m0/test_run.py`.

1. Add failing tests for each guard in the table below; confirm red, then implement the minimal refusal behavior.
2. Run `--scenario guards` on disposable copies of stopped, known-good candidates. No destructive modification of the positive scenario's evidence is allowed.

| Injected condition | Required result |
| --- | --- |
| Source writer/replicator or any candidate follower still alive | Promotion refused; no writable TrailBase spawned |
| Required DB absent/empty | Refused before SQLite/TrailBase can create it; missing-file condition preserved |
| Missing/malformed follow TXID | Refused as a follow candidate; no blind resume or inferred freshness |
| Deliberately truncated candidate DB | Structural/logical validation fails; no writable start |
| Reused backup/meta prefix or mismatched DB/epoch mapping | Refused before starting replication |
| Expected follower process exits or catch-up deadline expires | Clear failure/blocker with its logs; no promotion by timeout |
| Apply-error log followed by later successful progress/equality | Error gate stays failed; no promotion, raw and normalized evidence preserved |

3. A separately requested clean reseed of an invalid candidate may succeed from the sealed backup, but retain the refusal evidence and label it **reseed**, not successful promotion of the corrupt follower. Never auto-retry a positive-path integrity failure this way.
4. Confirm no required-file guard has been weakened by `-force`, `-if-db-not-exists`, `-if-replica-exists`, permissive exception handling, or a fallback empty bootstrap. Rerun unit tests and a graceful scenario.
5. Commit: `git commit -m "test: reject unsafe M0 promotion candidates"`.

**Checkpoint:** the harness demonstrates negative controls as well as happy paths. It does not yet test genuinely interrupted multi-page follower apply or production fencing.

### Task 8: Repeat, review evidence, and publish the decision

**Files:** create `experiments/m0/README.md`, `docs/reports/m0-local-failover.md`; modify `README.md`, `docs/work-register.md`.

1. Run the full unittest command, then `--scenario all --repeat 3` against the same pinned pair. Every repetition uses a fresh run/subdirectory set. Capture outcomes for follow, graceful, natural crash, lagged crash, all e2 reseeds, and guard controls.
2. Inspect every failure/blocker and unexpected child exit before summarizing. Record the actual repeat count, hashes, platform, fixture sizes, polling/sync settings, timeouts, and whether structural validation excluded CHECK expressions. No statistical SLA from three trials.
3. Produce `result.json` with per-scenario status; source/follower stop evidence; per-DB/epoch initial/selected/applied positions; integrity and logical comparisons; acknowledged/rejected/ambiguous and recovered/lost/recovered-rejected counts; auth outcomes; log isolation; timing breakdowns; normalized follower errors and private artifact references. Never put tokens, password hashes, keys or raw user/session rows in public results.
4. Write the sanitized report using the decision table below. Publish source-controlled fixture reproduction and placeholder commands, not local hostnames/paths, accounts, binary archives or private runtime data. Link the report and mark only the exact tested scope of each issue.
5. Verify all owned processes exited, `git diff --check` passes, local Markdown links resolve, and staged files contain no generated DB/key/log artifacts. Resolve HAT-045 (license choice) with the owner before publishing implementation code; do not choose a license silently. Review the diff, commit `test: document M0 local follow and promotion results`, and push only after that decision and after the result summary matches the evidence.

## 7. Acceptance and go/no-go decision

| Finding | Decision |
| --- | --- |
| Planned cut restores exactly; actual followed files promote; baseline auth/log behavior is correct; e2 follows/restores; refusal controls work | **GO for next experiments only:** test real S3-compatible transport and operator-supplied fencing privately |
| Normal following/promoting corrupts data, loses a sealed baseline write, mixes histories, or requires concurrent writable access to followed files | **NO-GO for this lifecycle:** retain evidence, isolate root cause, consider an upstream fix/design revision |
| Missing binary support, command mismatch, missing validator functionality, unexplained timeout, or an untested mandatory scenario | **BLOCKED/INCOMPLETE:** no success claim or silent workaround |
| Only the controlled post-baseline tail is lost in abrupt recovery | Expected asynchronous behavior; report it, no automatic loss-budget approval |
| All tests pass on local file storage | No claim about S3/R2 CAS, external fencing, arbitrary multi-DB consistency, service-hot replicas, zero-RPO, zero-RTO, or production HA |

All required scenarios must complete or be explicitly marked blocked; zero-loss graceful switchover is a test outcome, not the deferred zero-RPO feature. Recovery timestamps start at harness fault/quiesce actions, not at a production failure detector; report this distinction.

## 8. Execution handoff

Execute tasks sequentially: they share one harness and build on verified behavior. Do not parallelize writers or run multiple experiments against one directory. Review at Tasks 3, 4 and 8; stop when evidence contradicts the lifecycle rather than building more controller code around it.

Available execution approaches after approval:

1. **Same session:** task-by-task implementation with focused review checkpoints; use subagent-driven-development if delegating implementation.
2. **Separate session:** open this repo/worktree and use executing-plans, returning at the checkpoints above.

This plan authorizes no VPS access, cloud resources, provider integrations, production credentials, or production changes. Those require a later, separately scoped experiment.
