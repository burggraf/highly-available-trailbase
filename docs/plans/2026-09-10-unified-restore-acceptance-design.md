# Unified Restore Acceptance Design

## Purpose

Replace scattered D2/D3 restore-success conventions with one versioned, exact request/result contract. A restore is accepted only when the controller's expected operation, phase, transition, epoch, positions, input identities, and fixed check profile are all bound to the independent oracle result.

This is repository source/test work only. It does not authorize a restore, deployment, live verification, promotion, routing, reconciliation, or automatic HA.

## Scope

The contract covers future controller-driven D2/D3 independent finite restores performed through `ControlIO.oracle` and `tests/restore_baseline.py`:

- comparison or reconciled comparison at the source epoch;
- protected baseline and verification-baseline at the new epoch;
- fresh-write proof at the new epoch;
- D3 recovery comparison with exhaustive fault classification and zero acknowledged loss.

Historical D1 evidence remains historical. A standalone D1 invocation may use the oracle for diagnostics, but it is not accepted as a D2/D3 operation without an operation-bound request.

## Version and profiles

The exact version is `hat-restore-acceptance-1`. The caller does not choose arbitrary checks. The phase and operation direction select one fixed profile:

| Phase | Restored epoch | Fixed obligations |
| --- | --- | --- |
| `compare`, `reconciled-compare` | `source_epoch` | all three exact positions; per-DB restore identity, SHA-256, SQLite integrity and foreign-key checks; logical signatures; protected main/aux records; retained/revoked authentication |
| D3 `compare` with fault ledger | `source_epoch` | comparison obligations plus exhaustive non-overlapping fault classification and an empty acknowledged-loss set |
| `baseline`, `verification-baseline` | `new_epoch` | all three exact positions and comparison integrity/records/auth obligations |
| `new-writes` | `new_epoch` | all three exact positions and comparison obligations against the exclusive fresh-write ledger |

Unsupported phase/direction/fault combinations refuse. Required checks cannot be omitted or downgraded by the caller.

## Acceptance request

Before invoking the oracle, the controller durably writes one private exact JSON request containing only bounded identities, never ledger credentials or record bodies:

```json
{
  "schema": "hat-restore-acceptance-1",
  "operation": "<32 lowercase hex>",
  "phase": "<fixed supported phase>",
  "source": "A|B",
  "target": "A|B",
  "epoch": "d1-...",
  "positions": {"main": 1, "session": 1, "aux": 1},
  "inputs": {
    "replica_config_sha256": "<64 lowercase hex>",
    "ledger_sha256": "<64 lowercase hex>",
    "support": {"<fixed support path>": "<64 lowercase hex>"},
    "binaries": {"trail": "<64 lowercase hex>", "litestream": "<64 lowercase hex>"}
  },
  "profile": "comparison|recovery-comparison|baseline|fresh-writes"
}
```

`inputs` includes `fault_ledger_sha256` exactly for `recovery-comparison`. The controller derives profile and epoch from the journaled operation and phase; callers cannot supply them. Input hashes are computed from the exact files copied or exposed to the oracle. The request is passed as a private file and retained with the operation evidence.

The request validator rejects duplicate JSON keys, unknown or missing fields, booleans as integers, invalid operation/epoch/hash formats, incomplete database sets, unsupported phases/profiles, phase/profile/direction disagreement, and fault identity in any non-recovery profile.

## Oracle result

The oracle validates the request against the actual config, positions, ledger, support tree, binaries, and optional sealed fault ledger before restoring. It emits an exact result:

```json
{
  "schema": "hat-restore-acceptance-1",
  "request_sha256": "<hash of canonical request>",
  "operation": "<same operation>",
  "phase": "<same phase>",
  "source": "<same source>",
  "target": "<same target>",
  "epoch": "<same epoch>",
  "positions": {"main": 1, "session": 1, "aux": 1},
  "databases": {
    "main": {"position": 1, "sha256": "...", "integrity": "PASS", "foreign_keys": "PASS"},
    "session": {"position": 1, "sha256": "...", "integrity": "PASS", "foreign_keys": "PASS"},
    "aux": {"position": 1, "sha256": "...", "integrity": "PASS", "foreign_keys": "PASS"}
  },
  "signature": {"main": "...", "session": "...", "aux": "..."},
  "checks": {"records": "PASS", "authentication": "PASS"},
  "profile": "<same derived profile>"
}
```

For `recovery-comparison`, `checks` additionally contains the exact exhaustive `fault_outcomes` object and `acknowledged_loss: "NONE"`. Other profiles reject those fields.

The result validator requires exact keys, exact request bindings, canonical-request hash equality, exact per-database positions, valid hashes/signatures, all fixed PASS values, exhaustive fault membership, and zero acknowledged loss. Existing stronger comparisons remain: candidate/oracle signatures must match, baseline/new-write positions must match observed writer positions, and fresh writes must advance beyond the recorded baseline.

## Data and secret handling

The manifest contains hashes and structural outcomes only. It never includes tokens, credentials, request bodies, record payloads, database/WAL bytes, or raw logs. Existing private ledger, database, and log files remain outside Git. Parse errors must not retain secret-bearing exception content in journal evidence.

## Failure behavior

Any unavailable, malformed, stale, mismatched, partial, duplicate-key, unknown-field, timeout, or uncertain request/result refuses the restore phase. Existing journal intent and failure evidence remain retained. No prior action is replayed, no acceptance is inferred from later checks, and no route or activation is authorized by a manifest alone.

## Implementation shape

Keep the contract small:

1. Add pure request construction/validation and result validation helpers beside the existing recovery proof validators in `hat/recovery.py`.
2. Make `ControlIO.oracle` derive and durably write the request, pass it to the oracle, and validate the returned exact result.
3. Make `tests/restore_baseline.py` validate actual inputs against the request and emit the exact result.
4. Update D2/D3 call-site validation to consume the unified result without weakening existing phase-specific comparisons.
5. Add focused mutation tests for every field/binding/profile and integration tests proving refusal occurs before activation/routing.

No signing framework, configurable policy language, compatibility mode, or second schema version is added.

## What this closes—and does not

This closes the repository P0 that no objective operation-bound restore acceptance schema existed. It does not prove the currently deployed oracle uses the schema, does not fresh-validate historical restores, and does not close complete ACK coverage, asynchronous durability, D4 stock-runtime observability, provider late effects, distributed authority, ingress/controller availability, capacity, fault domains, certificate lifecycle, or production readiness.
