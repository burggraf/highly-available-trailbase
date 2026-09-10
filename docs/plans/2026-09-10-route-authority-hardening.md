# Route Authority Hardening Implementation Plan

**Goal:** Make every completed-route authority check exact and require the exact incomplete-D2 route-pending journal boundary.

**Scope:** Repository code, tests, and status/runbook documentation only. No live or private access.

## Task 1: Add failing route-authority tests

Files: `tests/test_recovery_guards.py`, optionally `tests/test_transitions.py`

1. Add table-driven completed-ingress mutations for writer, epoch, missing/extra keys, malformed evidence, and same-hash substitution.
2. Add completed-reconciliation mutations and assert refusal preserves maintenance and does not invoke mutation callbacks.
3. Add incomplete-D2 exact-prefix tests for accepted route-pending state and refusal of missing, reordered, duplicate, extra, or nonempty-intent steps.
4. Run only the new focused tests and retain the expected failures.
5. Commit tests.

## Task 2: Implement the minimum shared validation

File: `hat/control.py`

1. Add one exact route-evidence predicate/parser.
2. Reuse it from `current_writer`, completed `ingress_allowed`, and completed `reconcile_existing`.
3. Replace incomplete-D2 existence checks with the exact ordered route-pending prefix and empty-intent requirement.
4. Preserve fail-closed exception handling, maintenance behavior, target-B-only reconciliation, and all permit bindings.
5. Run focused tests and commit implementation.

## Task 3: Update operational records

Files: `docs/runbook.md`, `docs/status.md`, `docs/plans/2026-09-10-d0-d3-operational-readiness-audit-findings.md`

1. Mark only the two source-level route-admission defects closed by this implementation.
2. Retain all live-validation, deployment, ACK, provider-settlement, SPOF, capacity, certificate, D4, and restore-manifest limitations.
3. State that no live exercise occurred and deployment remains separately authorized.
4. Commit documentation.

## Task 4: Verify and review

1. Run focused tests, full runtime tests, D4 tests, `py_compile`, and `git diff --check` once.
2. Preserve all failures; do not rerun-until-green.
3. Obtain sequential specification and safety reviews at the exact final SHA.
4. Correct only concrete defects and repeat affected read-only reviews.
5. Stop for owner authorization before merge, push, deployment, live exercise, or worktree cleanup.
