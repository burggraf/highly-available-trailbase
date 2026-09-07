# M0 local follow-to-writer experiment report

Date: 2026-09-07

Decision: **GO for next experiments only**

## Scope

This report covers the bounded local experiment in [`../plans/2026-09-07-m0-local-failover-execution-plan.md`](../plans/2026-09-07-m0-local-failover-execution-plan.md). It does not close the broader HAT issues or qualify production HA.

## Environment and provenance

- Host: macOS ARM64
- Python: 3.14.3
- Python SQLite: 3.53.4
- TrailBase: v0.33.11, embedded SQLite 3.53.2
- Litestream: v0.5.17
- Transport: local file backend on one physical host
- Follow interval: 1 second
- Readiness/catch-up budget: 60 seconds
- Graceful-stop budget: 10 seconds
- Business fixture: 100 rows per database, 8 KiB payloads
- Required databases: `main`, `session`, `aux`
- Repetitions: 3 fresh runs per positive scenario; guards once

Release archives and executables matched published/GitHub SHA-256 evidence. Exact hashes and retrieval commands are in [`../../experiments/m0/README.md`](../../experiments/m0/README.md).

## Results

All requested runs completed with status `PASS`:

| Scenario | Runs | Observed result |
| --- | ---: | --- |
| Continuous follow and finite oracle | 3 | All three follower databases reached the sealed selected position and matched independent finite restores logically |
| Graceful promotion | 3 | Actual B follower files started writable; both APIs and baseline retained/revoked auth outcomes were correct |
| Natural crash | 3 | Sealed baseline survived; five later acknowledged writes per business DB were lost in each run; the in-flight request remained ambiguous |
| Deliberately lagged crash | 3 | Sealed baseline survived; exactly ten acknowledged unreplicated writes per business DB and the late session were absent |
| Fresh e2 and C reseed | 9 | Every promoted writer produced independently restorable e2 history; C matched finite e2 restores for all required DBs |
| Refusal controls | 1 set | All eight injected unsafe conditions were refused without writable startup |

The natural crash result is valid asynchronous tail loss, not evidence of a five-write RPO bound. Scheduling and local-file polling determined this observation.

### Timing observations

These are harness-local measurements, not HA SLOs:

- Graceful B start to functional API: median 363.7 ms; range 359.6–366.3 ms.
- Graceful quiesce action to functional API: median 5061.2 ms; range 4980.7–5130.7 ms.
- e2 C reseed after graceful promotion: median 3630.3 ms; range 3612.9–3699.6 ms.
- e2 C reseed after natural crash: median 3704.2 ms; range 3694.0–3717.1 ms.
- e2 C reseed after lagged crash: median 3679.9 ms; range 3639.1–3706.6 ms.

### Refusal controls

Promotion/recovery was refused for:

- a live source/follower process;
- a missing required database, without recreating it;
- malformed follow TXID state;
- a truncated database;
- reused epoch paths;
- unexpected follower exit;
- catch-up timeout;
- an apply error followed by later progress.

## Validation details

- Required files were checked before SQLite or TrailBase could create them.
- Candidate inspection used frozen copies so read validation could not leave WAL/SHM sidecars on the promotion candidate.
- Business operation keys and payloads were compared with an external expected manifest, not only row counts.
- Schema, selected application tables, structural integrity, and foreign keys were compared between stopped followers and finite restores.
- Structural validation set `PRAGMA ignore_check_constraints=ON`; TrailBase's custom `is_uuid`, `is_email`, and `jsonschema` CHECK expressions were **not evaluated** by Python SQLite.
- Real TrailBase startup/API/auth checks remained separate evidence.
- Client-observed operations and process/sync commands were fsynced to private JSONL ledgers; aggregate results reference private logs and record per-scenario evidence counts.
- Graceful classifications include SIGTERM/exit evidence and fail if SIGKILL escalation is required.
- e1 hash inventories stayed unchanged while e2 was produced.
- Logs, tokens, keys, raw user/session rows, databases, and machine result files remain private and are not published here.

## Upstream mismatch

TrailBase v0.33.11's `trail user add` command references the removed `_user.verified` column and failed with SQLite error code 1. With owner approval, the fixture used TrailBase's supported username-only registration endpoint instead. No auth table was edited directly.

## Decision

**GO for next experiments only:** test real S3-compatible transport and operator-supplied fencing privately.

This result does **not** establish S3/R2 CAS behavior, independent durability, external fencing, automatic election, host-loss recovery, service-hot replicas, Linux compatibility, zero RPO, zero RTO, or production readiness. The acknowledged tail loss confirms that automatic promotion still requires an approved loss/uncertainty policy.
