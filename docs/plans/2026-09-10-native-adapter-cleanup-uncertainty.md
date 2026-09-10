# Native Adapter Cleanup-Uncertainty Plan

> **REQUIRED SUB-SKILL:** Use the executing-plans skill to implement this plan task-by-task.

**Goal:** Make macOS `EPERM` during process-group disappearance checks an explicit fail-closed outcome instead of an uncaught platform exception.

**Architecture:** `_stop_group` may claim disappearance only after `os.killpg(pgid, 0)` raises `ProcessLookupError`. A successful probe or `PermissionError(errno.EPERM)` means disappearance is unproven, so polling continues to the existing deadline. Persistent `EPERM` becomes a dedicated bounded cleanup-uncertainty exception that `_command` records as an uncertain outcome.

**Tech Stack:** Python standard library, unittest.

---

### Task 1: Add failing cleanup-uncertainty tests

**Files:**
- Modify: `experiments/d4/test_native_adapter.py`

1. Add a deterministic test that replaces only the process-group probe boundary and makes signal `0` return persistent `EPERM`.
2. Require a dedicated cleanup-uncertainty exception containing bounded stdout/stderr and no claim that the group disappeared.
3. Update the real timeout/descendant test to accept exactly two safe outcomes: ordinary `TimeoutExpired` followed by proven child disappearance, or the dedicated cleanup-uncertainty exception without a disappearance assertion.
4. Add an adapter-level test requiring cleanup uncertainty to persist an exact uncertain outcome and remain unreleased/non-replayable.
5. Run focused tests and confirm they fail for the missing exception/handling.

### Task 2: Implement the minimum fail-closed behavior

**Files:**
- Modify: `experiments/d4/native_adapter.py`

1. Add one `CommandCleanupUncertain` exception carrying bounded stdout/stderr.
2. In `_stop_group`, treat only `ProcessLookupError` as disappearance.
3. On `PermissionError` with `errno.EPERM`, continue polling to the existing deadline; re-raise unrelated permission errors.
4. At the deadline, raise `CommandCleanupUncertain` if any `EPERM` was observed; otherwise preserve the existing survived-termination error.
5. In `_command`, persist bounded stdout/stderr plus `{"outcome":"cleanup","completion":"uncertain"}`, then raise the existing generic command-uncertain boundary without an exception chain.
6. Run focused native-adapter tests.

### Task 3: Verify and review

1. Run the native-adapter suite once, then D4 discovery once and runtime discovery once. Preserve any failure without rerun substitution.
2. Run `git diff --check` and the documentation-only audit changed-path checks updated to include this plan and the two bugfix files.
3. Obtain independent specification and safety review.
4. Record the new verification result without erasing the earlier `EPERM` failure.
5. Stop for explicit owner approval before integration, push, worktree cleanup, or live/private access.

## Non-claims

This does not prove process-group disappearance when macOS returns `EPERM`, add cancellation, authorize retries, or qualify native D4 execution. It only converts an ambiguous host observation into an explicit retained refusal category.
