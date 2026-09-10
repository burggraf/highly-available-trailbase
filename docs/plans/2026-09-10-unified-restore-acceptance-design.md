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

- completed legacy rows remain readable for historical/current writer and exact route authority only;
- a legacy completed row may be the source authority for a newly begun operation, whose new row uses `hat-restore-acceptance-1`;
- unfinished legacy operations cannot accept a restore result, reconcile comparison/verification, continue D3 rejoin, activate, or route under the new code; they require a separately designed, evidence-specific migration;
- new-contract operations never accept a legacy report shape;
- no compatibility adapter manufactures new-schema evidence from a legacy report.

Journal schema migration, every production consumer, test fixture, and fake oracle change together. A crash during schema migration must leave either the recognized old schema or recognized new schema; any other table shape refuses.

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
    "restore_sources": {
      "main": "/var/lib/hat-demo/depot/data/main.db",
      "session": "/var/lib/hat-demo/depot/data/session.db",
      "aux": "/var/lib/hat-demo/depot/data/aux.db"
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

- copied `replica.yml` and selected ledger raw bytes;
- fixed restore source paths;
- the fixed installed support tree and `trail`/`litestream` binaries;
- the sealed copied fault ledger for recovery comparison.

The controller validates and hashes those inputs, writes the canonical request durably under the operation work directory, then writes the identical oracle-readable copy. Files are exclusive-created, regular, singly linked, non-world-accessible, and in root-owned/non-writable ancestry. Secret-bearing config/ledger inputs remain only as protected oracle inputs; the request contains hashes, not their bodies. File and containing-directory fsync completes before `systemd-run`.

The oracle independently opens bounded inputs without following symlinks, validates ownership/mode/link count and hashes, validates all three replica epoch paths against `request.epoch`, and checks the fixed support/binary/restore-source identities. It retains file descriptor identity and rechecks identity/hash after use. Any replacement or mismatch refuses.

The oracle writes its result by exclusive create with mode `0600`, fsyncs file and directory, and never prints result or secret-bearing parse data to stdout/stderr. After command completion, the controller reads it bounded with `O_NOFOLLOW`, verifies regular-file/owner/mode/link identity, validates it, and durably retains the exact canonical result in the operation work directory before returning it. A crash before journal completion leaves a pending intent and retained evidence, never inferred acceptance.

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

The independent oracle calls one authoritative fault validator before emitting the result. The controller and later journal validator call the same pure validator again. It requires five exact categories, valid unique identifiers, flattened count and canonical identifier hash equal to the request, exhaustive non-overlap, an empty `lost` category, and `acknowledged_loss == "NONE"`. No caller can accept a recovery-comparison result without that validation.

For all profiles, exact result validation requires canonical schema/request hashing, exact request keys and derived matrix, exact database key set and positions, integer position equality, valid SHA-256 and logical signatures, per-database `PASS` integrity/foreign-key outcomes, exact profile-specific check keys, and records/authentication `PASS`. `"ok"`, truthy values, missing checks, and extra fault fields refuse.

## Coordinated consumer replacement

The new shape replaces legacy consumption together:

1. `ControlIO.oracle` constructs, writes, passes, reads, validates, and retains request/result evidence.
2. `tests/restore_baseline.py` requires `--acceptance-request`; it validates actual inputs before restore and emits only the exact new result.
3. D2 comparison/reconciliation, baseline, verification-baseline, and new-write call sites consume `result.request.positions`, `result.signature`, and exact validated checks.
4. D3 comparison, baseline, and new-write call sites do the same; no epoch is injected after oracle return.
5. `Journal.accept_comparison`, `Journal.accept_verification`, `_validate_d3_proof`, and D3 continuation require the operation's new contract and exact schema-bound reports. Legacy unfinished evidence refuses.
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
- altered config/ledger/fault/support/binary inputs and unsafe/replaced files;
- missing database, position mismatch, stale hash/signature, `ok` versus `PASS`, missing foreign-key result;
- fault fields on non-recovery profiles, malformed/overlapping/incomplete classifications, wrong identifier count/hash, and nonempty acknowledged loss;
- exact old/new journal schema migration, completed-legacy read-only authority, unfinished-legacy refusal, and new-operation schema selection;
- every production call site and fake using the new shape;
- refusal before activation, ingress start, route change, or reconciliation completion;
- durable request-before-command and result-before-journal ordering.

Focused contract tests precede implementation. Then run runtime and D4 suites once, preserving any failure without rerun substitution.

## Implementation order

1. Add pure canonical request/profile/fault/result validators and red mutation tests.
2. Add journal contract migration and legacy/new boundary tests.
3. Replace oracle CLI input/output and protected file handling.
4. Replace every production consumer and fake in one migration commit sequence; no mixed acceptance state is considered releasable.
5. Update operational documentation only after exact-SHA specification and safety review.

## What this closes—and does not

This closes the repository P0 only when all future operation paths reject legacy evidence and the exact request/result contract is tested and reviewed. It does not prove deployment, fresh-validate historical restores, or close complete ACK coverage, asynchronous durability, D4 stock-runtime observability, provider late effects, distributed authority, ingress/controller availability, capacity, fault domains, certificate lifecycle, or production readiness.
