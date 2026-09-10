# D4 Local Auth Logout Proof Implementation Plan

> **REQUIRED SUB-SKILL:** Use the executing-plans skill to implement this plan task-by-task.

**Goal:** Add a non-deployable logout-only adapter that releases HTTP 200 only after proving a refresh token transitioned from present in a predecessor session image to absent in a newer image.

**Architecture:** Reuse the native adapter's private path, command and restore machinery through a minimal exact-database subclass hook. Capture a predecessor after durable intent and before one forward; prove a strictly newer successor afterward. A reviewed private fixture confirms SQL transition semantics with native refresh oracles.

**Tech Stack:** Python standard library, SQLite, existing D4 admission/native adapter, pinned TrailBase 0.33.11 and Litestream 0.5.17.

---

### Task 1: Missing-module contracts

**Files:**
- Create: `experiments/d4/test_auth_logout_adapter.py`
- Later create: `experiments/d4/auth_logout_adapter.py`

1. Write tests importing the missing module and preserve the red.
2. Require exact JSON `POST /api/auth/v1/logout`, exact `refresh_token` body, and 86 alphanumeric characters; reject every alternate before journal/native/HTTP effects.
3. Model predecessor/successor session restores with an injected runner.
4. Require durable intent before predecessor sync, token presence before exactly one HTTP forward, successor absence, strictly increasing equal TXIDs, complete binding and proof-before-release.
5. Cover absent predecessor, present successor, non-increasing/mismatched TXID, malformed HTTP, command/transport errors and duplicate refusal without further effects.
6. Require secrets absent from journal, command/proof metadata and decisions; restored DBs are explicitly private secret-bearing evidence.

### Task 2: Minimal shared hook and adapter

**Files:**
- Modify: `experiments/d4/native_adapter.py`
- Modify: `experiments/d4/test_native_adapter.py`
- Create: `experiments/d4/auth_logout_adapter.py`

1. Add a failing regression for a subclass-defined exact database-name set.
2. Replace only the hard-coded main/aux database-set check with a class constant; default behavior remains exactly main/aux.
3. Run existing adapter tests green.
4. Implement `AuthLogoutAdapter` as a subclass with exactly `session`; reuse inherited identity, output and process-group controls.
5. Add only small inherited helpers if tests require them; do not broaden `NativeAdapter.validate_policy()` or main/aux surfaces.
6. Run logout, adapter, protocol and runtime tests; commit.

### Task 3: Private native qualification

**Files outside Git:**
- Create fresh `~/.config/hat/d4-qualification/auth-logout-<random>/run.py` and private fixture evidence.

1. Write static harness checks first and preserve missing-harness red.
2. Build one-shot fresh source/replicator fixture plus sequential predecessor/post/pre-login oracle copies. Keep listeners loopback-only, sockets root-contained, logs/output bounded and all credentials/tokens/images private.
3. Require one setup login outside the claim; pre-login stale image; one admitted logout; predecessor presence; successor absence with greater TXID; predecessor refresh 200; post refresh 401; stale image proving absence alone is insufficient.
4. Require malformed/refusal checks without replay, metadata secret scan, exact hashes/SQL, and process/group/thread/listener/socket cleanup.
5. Obtain independent static review and resolve blockers before execution.
6. Execute exactly one reviewed fresh run. Preserve failure; no automatic whole-run retry.
7. Obtain sanitized evidence review before qualification recording.

### Task 4: Record and integrate

**Files:**
- Modify: `docs/plans/2026-09-09-d4-local-auth-logout-plan.md`
- Modify: `docs/status.md`

1. Record tests, review history, failed attempts, native observations and limitations.
2. Run all experiment/runtime regressions, `git diff --check`, and assert no changes to `hat/`, `deploy/` or existing `tests/`.
3. Commit, fast-forward `main`, verify merged tests and clean the worktree. Do not push or deploy.

## Completion record

The adapter implementation was committed as `79b40e7`. A native WAL-header failure then exposed that `sqlite3.Connection.deserialize()` could not consume the finite restored session image. A failing WAL-mode regression was added before replacing deserialization with read-only immutable SQLite access through the retained `O_NOFOLLOW` descriptor; that correction is `6b04284`. The descriptor supplies both the image digest and the inode used for membership, with identity rechecked afterward. This `/dev/fd` mechanism is intentionally Unix-specific and remains experiment-only.

Two reviewed native roots failed safely and remain preserved:

- `al-b7IqYpxqHjNa` stopped before login because the harness treated an informational `lsof` file-descriptor field as an extra listener. Cleanup passed. A failing parser regression preceded the correction; exact one-record PID/address list checks still reject duplicate or additional listeners.
- `al-iOihV5yF0DF1` stopped after predecessor restore but before the logout HTTP request because deserialization rejected the valid WAL-mode image. The journal retained `forward_uncertain`; source and replicator exited cleanly. Read-only diagnosis confirmed pre-login/predecessor membership `0/1` and no logout attempt.

After static and code reviews, fresh run `al-WMqSG4vWaCsm` passed. Native evidence shows session membership `0→1→0`, equal file/replica proof positions advancing `1→2→3`, pre-login/predecessor/successor refresh statuses `401/200/401`, and an independent retained-session refresh `200`. The journal released the exact empty logout HTTP 200 only after the successor proof. One adapter HTTP event occurred; duplicate identity and malformed proof checks refused without replay. Oracle DB/WAL hashes were unchanged across refresh checks. All five processes exited 0, were reaped without forced kill or log overflow, and their process groups, TCP listeners and Unix socket disappeared.

The shell initially created the sanitized one-line stdout and empty stderr as `0644` beneath the canonical `0700` root. They were immediately tightened to `0600`; this resolved P2 packaging issue did not affect semantic evidence. Future harness launches set `umask 077` before redirection. Independent evidence review `fc4f7ac8-1d48-464c-a8e2-634dbb527a65` approved sanitized local recording/integration only. Final local regressions cover 10 logout adapter, 18 native adapter, 14 protocol and 107 runtime tests.

## Stop boundary

No login/refresh adapter, GET/cookie logout, account/admin mutation, remote storage, production listener, VPS/live data, deployment, automatic recovery, distributed authority, policy relaxation or paid resources. Owner authorization permitted fresh reruns only after each failed root was preserved and diagnosed; it does not broaden this scope. Passing proves only the bounded local nominal logout transition—not response-loss settlement, existing JWT invalidation, complete auth/ACK coverage, remote durability or HA.
