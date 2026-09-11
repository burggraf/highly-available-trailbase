# Unified Restore Acceptance Implementation Plan

**Goal:** Implement `hat-restore-acceptance-1` for every future D2/D3 oracle restore while preserving completed legacy authority and refusing unfinished legacy continuation.

**Scope:** Repository source, tests, and documentation only. No deployment, live/private access, restore, routing, activation, or reconciliation.

## Task 1: Pure canonical contracts

Files: `hat/recovery.py`, `tests/test_recovery.py`

1. Add failing mutation tables for canonical request bytes, phase/profile/epoch/position/restore-point bindings, exact authority objects, protected/fault ledger grammars, exact result shape, signatures/checks, and zero-loss classification.
2. Add the minimum pure constructors/validators and canonical serializer.
3. Preserve generic exception messages without secret values.
4. Run focused recovery-contract tests, commit red tests separately, then implementation.

## Task 2: Journal contract migration

Files: `hat/control.py`, `tests/test_transitions.py`, `tests/test_recovery_guards.py`

1. Add failing tests for exact legacy→new schema migration, interrupted migration, unknown shape/value refusal, new-row contract selection, completed-legacy authority/reconciliation compatibility, and every unfinished-legacy refusal.
2. Add `restore_contract`, exact schema validation, and contract checks to every inventoried operations reader/writer.
3. Preserve `DELETE`/`EXTRA`, directory fsync, locking, phase order, and route admission behavior.
4. Run focused journal/guard tests and commit tests then implementation.

## Task 3: Oracle request/result boundary

Files: `hat/control.py`, `tests/restore_baseline.py`, focused tests

1. Add failing tests for phase matrix preflight with zero artifacts, authority provenance, raw-byte copying, exact file modes/identities, canonical request, exact CLI restore arguments, result validation/retention, replacement refusal, and durable ordering.
2. Replace the oracle CLI with mandatory `--acceptance-request`; remove `positions.json` and all text conversions.
3. Replace security-relevant oracle assertions with explicit refusal.
4. Use the exact approved copy set and fixed installed support/binary validation.
5. Commit tests then implementation after focused green.

## Task 4: Replace all consumers and fakes

Files: `hat/control.py`, `hat/recovery.py`, `tests/test_recover_driver.py`, `tests/test_recovery*.py`, `tests/test_transitions.py`, `tests/restore_baseline.py`

1. Add failing integration tests for every D2/D3 oracle call, forbidden legacy fields, D3 baseline epoch injection removal, durable `verification-baseline`, fault-set equality, and refusal before activation/routing/reconciliation completion.
2. Convert every call site and fake to the exact result shape in one coordinated slice.
3. Ensure later journal proof validation is self-contained and exact.
4. Run focused recovery/transition suites and commit tests then implementation.

## Task 5: Crash and race boundaries

Files: focused tests and only necessary production helpers

1. Add deterministic injected failures around journal migration, intent, authority, request/copy/result/retention fsync, command start, and phase-done commit.
2. Add parent/file replacement and stale identity/hash cases within the unprivileged threat model.
3. Prove reopen never infers acceptance or replay from partial evidence.
4. Commit tests then minimal corrections.

## Task 6: Documentation, final verification, and review

Files: `docs/runbook.md`, `docs/status.md`, audit findings, relevant plans

Checkpoint `a63a12136b2847d76a01ee8ff5374b0f4618c653` records source/test closure for `hat-restore-acceptance-1`: exact journal migration and legacy restrictions, controller-built request/oracle result, descriptor/durability/crash coverage, and no manifest route authority. Final verification passed 168 focused tests with 233 subtests, 222 runtime tests, 115 D4 tests, `py_compile`, and `git diff --check`; runtime discovery emitted non-failing SQLite `ResourceWarning`s. The earlier `446097f` run with two stale fsync-order expectation failures remains preserved. This evidence does not qualify deployment/live behavior or fresh historical validation. D4 stock v0.33.11 infeasibility and all ACK, recoverability, provider, distributed-authority, controller-SPOF, capacity/fault-domain, partition, certificate, and load limitations remain unchanged. Do not claim zero-loss HA or production readiness.

1. Record source/test closure only; preserve no-deployment/live qualification and every remaining D4/operational limitation.
2. Run focused suites, full runtime, D4 discovery, `py_compile`, and `git diff --check` once. Preserve failures without blind retry.
3. Obtain sequential whole-branch specification then safety review at the exact SHA.
4. Correct only concrete findings and repeat affected read-only reviews.
5. Stop for owner approval before merge, push, deployment, live exercise, or worktree cleanup.
