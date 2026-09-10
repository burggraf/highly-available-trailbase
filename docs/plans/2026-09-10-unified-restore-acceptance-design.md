# Unified Restore Acceptance Design

## Purpose

Replace scattered D2/D3 restore-success conventions with one versioned, exact request/result contract. A future restore is accepted only when the controller's expected operation, phase, transition, epoch, positions, input identities, fixed check profile, and independent oracle result agree.

This is repository source/test work only. It does not authorize a restore, deployment, live verification, promotion, routing, reconciliation, or automatic HA.

## Scope

The contract covers every future controller-driven independent finite restore through `ControlIO.oracle` and `tests/restore_baseline.py`:

- D2 comparison and reconciled comparison at the source epoch;
- D2/D3 protected baseline and D2 verification-baseline at the new epoch;
- D2/D3 fresh-write proof at the new epoch;
- D3 recovery comparison with exhaustive fault classification and zero acknowledged loss.

Historical D1 evidence remains historical. Standalone D1 diagnostics are not accepted as D2/D3 operation evidence without an operation-bound request.

## Versioned operation migration

Add an `operations.restore_contract` discriminator to the controller journal. Opening an exact legacy journal transactionally adds the column with `legacy` for existing rows. New `Journal.begin` rows use `hat-restore-acceptance-1`. Any unknown value refuses.

Migration rules are fail-closed:

- completed legacy rows remain readable only by the explicitly named completed-authority paths: `current_writer`, completed `ingress_allowed`, and completed target-B `reconcile_existing` with its exact route/maintenance restrictions;
- a legacy completed row may be the source authority for a newly begun operation, whose new row uses `hat-restore-acceptance-1`;
- `_d3_serving_state`, `Journal.step`, `Journal._boundary`, `comparison_boundary`, `verification_boundary`, `accept_comparison`, `accept_verification`, `continue_rejoin`, and `finish` require the new contract for every unfinished operation;
- `reconcile_existing` closes ingress and refuses every unfinished legacy operation before continuation; no unfinished legacy state can activate, route, reconcile, or finish;
- `Journal.__enter__`, `begin`, every operations-table query, and the read-only `ingress_allowed` connection explicitly select/validate the contract column; unknown/mixed table layouts or values refuse;
- new-contract operations never accept a legacy report shape, and no compatibility adapter manufactures new-schema evidence from a legacy report.

The migration transaction first verifies the exact legacy column/index/table shape, adds the contract column with `legacy` for existing rows, validates every row, and commits. New-schema opening verifies the exact new shape. Crash-interruption tests reopen before migration, after the schema change but before commit, and after commit; only the exact recognized old or new shape is accepted.

## Fixed phase matrix

The controller derives profile and epoch from the locked journal operation. Callers do not supply or downgrade them.

| Direction | Phase | Fault input | Profile | Epoch |
| --- | --- | --- | --- | --- |
| A→B | `compare`, `reconciled-compare` | forbidden | `comparison` | `source_epoch` |
| A→B | `baseline`, `verification-baseline` | forbidden | `baseline` | `new_epoch` |
| A→B | `new-writes` | forbidden | `fresh-writes` | `new_epoch` |
| B→A | `compare` | required | `recovery-comparison` | `source_epoch` |
| B→A | `baseline` | forbidden | `baseline` | `new_epoch` |
| B→A | `new-writes` | forbidden | `fresh-writes` | `new_epoch` |

Every other phase × direction × fault combination refuses before creating files or starting the oracle. `new-writes` binds the exclusive fresh-write ledger. `verification-baseline` has baseline obligations. D3 does not accept reconciled comparison or verification-baseline through this generic boundary.

## Canonical acceptance request

Before starting the oracle, the controller builds an exact object:

```json
{
  "schema": "hat-restore-acceptance-1",
  "operation": "<32 lowercase hex>",
  "phase": "<fixed supported phase>",
  "source": "A|B",
  "target": "A|B",
  "epoch": "d1-...",
  "positions": {"main": 1, "session": 1, "aux": 1},
  "profile": "comparison|recovery-comparison|baseline|fresh-writes",
  "inputs": {
    "replica_config_sha256": "<64 lowercase hex>",
    "ledger_sha256": "<64 lowercase hex>",
    "restore_points": {
      "main": {"source": "/var/lib/hat-demo/depot/data/main.db", "position": 1},
      "session": {"source": "/var/lib/hat-demo/depot/data/session.db", "position": 1},
      "aux": {"source": "/var/lib/hat-demo/depot/data/aux.db", "position": 1}
    },
    "support": {"<fixed support path>": "<64 lowercase hex>"},
    "binaries": {"trail": "<64 lowercase hex>", "litestream": "<64 lowercase hex>"}
  }
}
```

For `recovery-comparison`, `inputs` additionally and exactly contains:

```json
{
  "fault_ledger_sha256": "<64 lowercase hex>",
  "fault_operations_sha256": "<hash of canonical sorted submitted api/op_key list>",
  "fault_operation_count": 1
}
```

The operation list contains identifiers only, never payloads. All hashes use raw bytes except `fault_operations_sha256`, which hashes canonical JSON (`sort_keys=True`, compact separators, UTF-8, no NaN).

The entire request is serialized the same canonical way. The request SHA-256 is over those exact bytes. The validator rejects noncanonical bytes, duplicate keys, unknown/missing fields, booleans as integers, invalid identifiers/epochs/hashes, incomplete database/support/binary sets, unsupported matrix combinations, wrong derived epoch/profile, and fault fields outside recovery comparison.

## Input identity and file handling

The identities refer to the exact inputs exposed to the oracle:

- byte-for-byte copied `replica.yml` and selected ledger raw bytes, including encoding and final newlines;
- exact logical Litestream restore points `(source path, TXID)` for all three databases;
- the fixed five-key non-bootstrap support set (`config.textproto`, both fixed `U100__hat_ops.sql` migrations, and the private/public signing keys) and exact two-key binary set (`trail`, `litestream`), each with raw-file SHA-256;
- the byte-for-byte sealed copied fault ledger for recovery comparison.

A remote Litestream source path is not falsely claimed to have a local immutable file hash. Its identity is the exact replica-config hash, request epoch, fixed database source path, and selected TXID. Acceptance binds the resulting restored file through its raw SHA-256, `logical_signature`, ledger/auth checks, and candidate/oracle signature equality.

Before any directory or file creation, a pure `derive_restore_profile(operation, phase, has_fault)` validates the exact matrix and returns the profile/epoch. Only then may the controller read inputs. It opens source inputs descriptor-relatively beneath pre-opened trusted root descriptors, rejects symlink components, and records `(st_dev, st_ino, st_mode, st_uid, st_gid, st_nlink, st_size)` plus SHA-256. It copies with binary reads/writes only, fsyncs each exclusive-created file and its containing directory, then verifies destination bytes/hash and rechecks source identity/hash. Newline or encoding conversion is a mismatch.

Directory traversal uses component-by-component `os.open(..., dir_fd=parent_fd, O_DIRECTORY|O_NOFOLLOW)` from a trusted root descriptor; files use `dir_fd` plus `O_NOFOLLOW`. Open descriptors remain held through validation/copy. External commands necessarily receive paths, so every ancestor and file identity is rechecked after command completion. Root compromise or a malicious process with root write authority is outside this local ownership trust model; replacement by the unprivileged oracle or other users is in scope and refuses.

The controller writes canonical request bytes durably under the operation work directory, then writes an identical oracle-readable copy. Secret-bearing config/ledger inputs are root-owned, oracle-group-readable `0640` regular single-link files beneath root-owned non-group-writable ancestry; the hash-only request is the same. The sealed fault copy and result are oracle-owned `0600`. No file is world-accessible.

The oracle independently uses the same descriptor-relative bounded reader, validates actual hashes/key sets/restore points and all three replica epoch paths against `request.epoch`, and rechecks identities after use. It replaces every security-relevant `assert` with explicit exceptions.

The oracle exclusive-creates canonical result bytes at mode `0600`, fsyncs file and directory, and never prints result or secret-bearing parse data. After command completion, the controller reads the result descriptor-relatively, verifies owner/mode/link/identity, validates it, rechecks request/input identities, and durably retains the exact bytes in the operation work directory before returning. A crash at any request copy/fsync, command, result fsync/read, retained-result fsync, or journal-commit boundary leaves refusal or a pending intent—never inferred acceptance.

## Exact oracle result

The result embeds the complete safe request so later journal validation is self-contained:

```json
{
  "schema": "hat-restore-acceptance-1",
  "request": {"...": "<exact request object>"},
  "request_sha256": "<hash of canonical request>",
  "databases": {
    "main": {"position": 1, "sha256": "...", "integrity": "PASS", "foreign_keys": "PASS"},
    "session": {"position": 1, "sha256": "...", "integrity": "PASS", "foreign_keys": "PASS"},
    "aux": {"position": 1, "sha256": "...", "integrity": "PASS", "foreign_keys": "PASS"}
  },
  "signature": {"main": "...", "session": "...", "aux": "..."},
  "checks": {"records": "PASS", "authentication": "PASS"}
}
```

For `recovery-comparison`, `checks` additionally and exactly contains:

```json
{
  "fault_outcomes": {
    "recovered": [],
    "lost": [],
    "ambiguous": [],
    "unacknowledged_recovered": [],
    "rejected": []
  },
  "acknowledged_loss": "NONE"
}
```

The sealed fault ledger is the sole source of truth. Both controller and oracle independently parse its complete closed event stream, derive the exact sorted JSON array of submitted identifier strings (`"main_ops/<op_key>"` or `"aux_ops/<op_key>"`), and require its count/hash to equal the request. The result's five categories must flatten to that same array/count/hash with no overlap or omission. Semantics remain exact: acknowledged present→`recovered`, acknowledged absent→`lost`; rejected must be absent→`rejected`; uncertain/no outcome present→`unacknowledged_recovered`; uncertain/no outcome absent→`ambiguous`. Zero submissions require five empty lists, count zero, and the canonical empty-array hash. `lost` must be empty and `acknowledged_loss` must be literal `NONE`.

The independent oracle calls this authoritative pure validator before emitting the result. The controller calls it again against the sealed ledger before returning, and later journal validation checks the self-contained request count/hash against the five result categories. No caller can accept recovery comparison without all three equalities.

For all profiles, the result keys are exactly `schema`, `request`, `request_sha256`, `databases`, `signature`, and `checks`; `request` is the complete exact request object, not a summary. `databases` has exactly `main`, `session`, and `aux`; each value has exactly `position`, `sha256`, `integrity`, and `foreign_keys`. Its position equals both `request.positions[db]` and `request.inputs.restore_points[db].position`; `sha256` is the lowercase SHA-256 of the exact restored database bytes read from a retained descriptor; and the two outcomes are literal `PASS` after explicit SQLite `PRAGMA integrity_check == ('ok',)` and empty `PRAGMA foreign_key_check`.

`signature` is exactly the three lowercase 64-hex values returned by `transition.logical_signature(data)`: after `node.validate_databases`, hash `repr` of schema rows ordered by type/name, then each table name ordered by name and every `repr(row)` sorted and newline-delimited, with the existing 64-MiB bound. The oracle computes it; controller comparison binds it to candidate state where required.

Exact validation requires canonical schema/request hashing, exact request keys and derived matrix, exact database key set/positions, integer (not boolean) equality, valid hashes/signatures, per-database PASS outcomes, exact profile-specific check keys, and records/authentication `PASS`. The old `auth_and_records` field, `integrity: "ok"`, truthy values, missing checks, and extra fault fields refuse everywhere for new operations.

## Coordinated consumer replacement

The new shape replaces legacy consumption together:

1. `ControlIO.oracle` constructs, writes, passes, reads, validates, and retains request/result evidence.
2. `tests/restore_baseline.py` requires `--acceptance-request`; it validates actual inputs before restore and emits only the exact new result.
3. D2 comparison/reconciliation, baseline, and new-write call sites consume `result.request.positions`, `result.signature`, and exact validated checks. The `verification-baseline` result is not discarded: it is embedded as `baseline_recheck` in the subsequent verification result and validated/stored by `Journal.accept_verification` before reconciliation completion.
4. D3 comparison, baseline, and new-write call sites do the same. The D3 baseline request is constructed with `new_epoch`; the oracle-emitted result embeds that request. The current post-oracle `dict(report, epoch=...)` injection is removed and regression-tested as forbidden.
5. `Journal.accept_comparison`, `Journal.accept_verification`, `_validate_d3_proof`, and D3 continuation require the operation's new contract and exact schema-bound reports. Legacy unfinished evidence and every old shortcut field refuse.
6. Fake I/O and fixtures emit real schema-valid request/result objects; no permissive fake may retain `auth_and_records` as a shortcut.

Existing stronger checks remain: candidate/oracle signatures match, report positions match selected or observed positions, fresh-write positions advance beyond the baseline, and route/activation checks remain independent. A manifest by itself never activates or routes.

## Data and exception handling

Requests/results contain hashes, identifiers, positions, and structural outcomes only. They never contain tokens, credentials, record payloads, database/WAL bytes, request bodies, or raw logs. Existing private ledgers, databases, and command logs remain outside Git. Parser and subprocess errors use bounded generic messages; secret-bearing exception text or stderr is not placed in journal evidence.

## Failure behavior

Unavailable, malformed, stale, mismatched, partial, duplicate-key, unknown-field, noncanonical, timeout, or uncertain evidence refuses the phase. Existing intent/failure evidence remains retained. No previous action is replayed, no later passing check substitutes for a failure, and no legacy report is upgraded by assertion.

## Test requirements

Failing-first tests cover:

- every missing/extra/duplicate request and result field;
- booleans in integer positions/counts;
- all unsupported phase/profile/direction/fault combinations;
- wrong derived epoch, source/target, operation, profile, request hash, or canonical bytes;
- altered config/ledger/fault/support/binary inputs, byte/newline/encoding changes during copy, unsafe/replaced files, source-path replacement, and unchanged-path identity changes;
- missing database, position mismatch, stale restored-byte hash/signature, canonical signature derivation, `ok` versus `PASS`, and missing foreign-key result;
- fault fields on non-recovery profiles, malformed/overlapping/incomplete classifications, equality of sealed-ledger/request/result submitted sets, zero-submission semantics, wrong count/hash, and nonempty acknowledged loss;
- exact old/new journal schema migration; crash before/inside/after migration commit; every named operations-table reader; completed-legacy authority/reconciliation behavior; unfinished-legacy refusal; new-operation schema selection;
- every production call site and fake using the new shape, ignored `verification-baseline` refusal, and forbidden D3 post-oracle epoch injection;
- pure matrix rejection before zero artifact creation or command intent for every unsupported combination;
- descriptor-parent, request, input, and result replacement races within the unprivileged threat model;
- refusal before activation, ingress start, route change, or reconciliation completion;
- injected crashes before/after every request/result file fsync, directory fsync, retained-result fsync, and journal commit, proving no acceptance from partial evidence.

Focused contract tests precede implementation. Then run runtime and D4 suites once, preserving any failure without rerun substitution.

## Implementation order

1. Add pure canonical request/profile/fault/result validators and red mutation tests.
2. Add journal contract migration and legacy/new boundary tests.
3. Replace oracle CLI input/output and protected file handling.
4. Replace every production consumer and fake in one migration commit sequence; no mixed acceptance state is considered releasable.
5. Update operational documentation only after exact-SHA specification and safety review.

## What this closes—and does not

This closes the repository P0 only when all future operation paths reject legacy evidence and the exact request/result contract is tested and reviewed. It does not prove deployment, fresh-validate historical restores, or close complete ACK coverage, asynchronous durability, D4 stock-runtime observability, provider late effects, distributed authority, ingress/controller availability, capacity, fault domains, certificate lifecycle, or production readiness.
