# D4 Local Response-Loss Qualification Implementation Plan

> **REQUIRED SUB-SKILL:** Use the executing-plans skill to implement this plan task-by-task.

**Goal:** Qualify fail-closed adapter behavior when TrailBase or Litestream completes an effect but the adapter does not receive the corresponding response.

**Architecture:** Keep production/runtime code unchanged unless a test exposes a contract gap. Add focused protocol regressions for durable uncertainty and permanent operation-ID refusal, then build a private one-shot harness with a loopback HTTP relay and Unix-socket relay around fresh native fixtures. Review code before native execution and review sanitized evidence before recording results.

**Tech Stack:** Python standard library, SQLite, existing `experiments/d4` kernel/adapter, pinned TrailBase 0.33.11 and Litestream 0.5.17.

---

### Task 1: Preserve baseline and add durable refusal regressions

**Files:**
- Modify: `experiments/d4/test_native_adapter.py`

**Step 1: Add failing tests**

For both existing injected forward-timeout and native-timeout paths, assert after closing/reopening the journal that:
- status is respectively `forward_uncertain` or `proof_uncertain`;
- no response is released;
- a second `admit_native()` with the same operation ID raises `operation identity already used`;
- opener/runner call counts are unchanged by the duplicate refusal;
- forward uncertainty emitted no native evidence directory;
- proof uncertainty emitted no restore intent or `proof.json`.

**Step 2: Run targeted tests and preserve red**

Run: `python3 experiments/d4/test_native_adapter.py`

Expected: FAIL only where the current tests/API do not expose the durable assertions. If all behavior already passes, retain that result as a contract-confirmation test addition and do not alter implementation merely to manufacture a red.

**Step 3: Make the minimum correction if required**

Modify only `experiments/d4/admission.py` or `experiments/d4/native_adapter.py` at the shared root cause. Do not add retries, reconciliation, listeners or new decision states.

**Step 4: Verify green**

Run adapter, protocol and 107 runtime tests. Preserve existing ResourceWarnings/parser stderr as known baseline categories.

**Step 5: Commit**

Commit focused tests and any necessary minimal fix.

### Task 2: Build a private one-shot native harness

**Files:**
- Create outside Git: `~/.config/hat/d4-qualification/response-loss-<random>/run.py`
- Create outside Git: private generated TrailBase/Litestream configuration and evidence

**Step 1: Write static harness checks first**

Before native execution, write checks that fail unless the harness has:
- exact `0700` root and owner-only regular/single-link pinned binaries;
- fresh direct-child source, replica and journal paths;
- loopback-only HTTP listener and root-contained Unix sockets;
- one control plus one fault request per relay/case;
- bounded readiness, command, thread and process-group cleanup;
- zero downstream response bytes during each fault;
- no automatic retry/replay and no operation-ID reuse except the explicit refusal check;
- explicit per-case journal reopen/status and callback/request counters;
- exact same-predicate stale/source/restored membership records;
- sanitized output separated from private logs/databases/credentials.

Run checks and preserve the missing-harness red.

**Step 2: Implement the minimum harness**

Use a single script and standard library only. Create four isolated cases from fresh initialized state:
1. main HTTP response loss;
2. aux HTTP response loss;
3. main sync response loss;
4. aux sync response loss.

The HTTP relay forwards the request once, reads and records upstream completion privately, then withholds all downstream bytes past the adapter's receipt timeout. The Unix relay forwards native sync once, parses/records the upstream HTTP 200 JSON and exact TXID privately, then withholds all downstream bytes past Litestream's sync deadline. Each relay first passes a separate non-faulted control operation.

**Step 3: Run static checks to green without starting native processes**

Syntax-check and inspect the harness. Verify binary hashes from copied bytes. Do not treat syntax/static success as execution evidence.

**Step 4: Obtain independent static review**

Provide only source, intended paths/contracts and baseline counts. Reviewer must check listener confinement, request cardinality, timeout chronology, response parsing/binding, stale predicate, private evidence, process/thread cleanup and absence of replay. Do not execute until all blocking findings are corrected and reviewed.

### Task 3: Execute once and inspect evidence

**Step 1: Start exactly one reviewed harness**

Launch via the managed process tool from the fresh private root. Do not poll. A failed whole run is preserved and not automatically retried.

**Step 2: Verify required outcomes**

For each HTTP-loss case require source exact membership, `forward_uncertain`, no proof commands/publication, zero released bytes and duplicate refusal without added calls.

For each sync-loss case require upstream exact TXID completion, exact-TXID independent restore without another sync, exact membership, `proof_uncertain`, no adapter restore/proof publication, zero released bytes and duplicate refusal without added calls.

For all cases require the stale image to fail the same SQL predicate, journal unchanged after later inspection, and exact thread/process/socket cleanup.

**Step 3: Preserve uncertainty and failures**

Never infer cancellation from timeout. Record forced cleanup or any unexpected effect. Do not replay successful controls or faulted operations.

### Task 4: Review, document and integrate locally

**Files:**
- Modify: `docs/plans/2026-09-09-d4-local-response-loss-plan.md`
- Modify: `docs/status.md`

**Step 1: Prepare sanitized evidence**

Exclude credentials, tokens, request payload secrets, raw DBs, journals and native logs. Include exact counters, chronology, statuses, TXIDs/hashes, same-predicate results and terminal lifecycle.

**Step 2: Obtain independent evidence review**

Qualification remains blocked until review accepts all four cases and the bounded interpretation.

**Step 3: Run final regression**

Run adapter, protocol and runtime suites; run `git diff --check`; verify no changes under `hat/`, `deploy/` or existing `tests/`.

**Step 4: Record bounded result and commit**

Document failed attempts and limitations. Commit locally, fast-forward `main`, rerun merged verification and remove the clean worktree. Do not push or deploy.

## Recorded evidence

- Baseline passed: 17 adapter, 14 protocol and 107 runtime tests. Existing ResourceWarnings/parser stderr remained the known baseline categories.
- Strengthened unit contracts reopened `forward_uncertain` and `proof_uncertain` journals, proved duplicate operation IDs refuse before callbacks/native commands, and checked absent proof publication. They passed immediately against existing behavior, so no kernel or adapter implementation changed.
- Private harness root: `~/.config/hat/d4-qualification/rl-z9WWB1TlIpH0/`. Only copied hash-pinned binaries, fixture source and evidence live there; no state from a completed fixture was reused.
- Static missing-harness and three review-finding red checks were preserved. Review sequence blocked hard-coded sync IDs, HTTP worker cleanup, daemon output bounds, real socket cleanup semantics, diagnostic image bounds/identity, early Unix evidence persistence and incomplete identity continuity. Each was corrected before execution. Final static review `5a8106a8-cc20-4be6-9329-f6073a30795b` found no issues and approved exactly one fresh local run.
- A pre-execution process scan matched its own wrapper PID `79825`; it exited before harness launch and created no fixture/case state. `preflight-scan-correction.json` records the corrected ancestor-excluding scan. This was not a native attempt.
- Exactly one reviewed native harness run, managed process `proc_0e13`, exited 0 after 37 seconds. No whole-run retry occurred.
- HTTP main and aux each observed TrailBase HTTP 200 completion, then sent zero downstream bytes until the adapter returned after about five seconds. Both decisions remained unreleased `forward_uncertain`; reopened journals contained one operation, duplicate invocation refused without a third relay request, source exact membership passed and the pre-fault image failed the same predicate. No native evidence operation directory existed.
- Sync main and aux each observed native HTTP 200 with TXID/replica TXID `2/2`, then sent zero downstream bytes until the CLI returned after about ten seconds. Both decisions remained unreleased `proof_uncertain`; reopened journals contained one operation with upstream status 200, duplicate invocation refused without a third relay request, and no adapter restore intent or proof publication existed. An independent restore at the upstream-reported TXID—without another sync—contained the exact captured TrailBase response ID/op_key/payload; the pre-fault image failed the same predicate.
- Exact predicate in all cases: `SELECT op_key,payload FROM hat_ops WHERE id=?`. Target/stale image hashes, generic integrity and zero foreign-key violations are recorded. Later inspections did not alter journal states or authorize replay/release.
- Eight TrailBase/Litestream fixture processes exited 0, were reaped without forced kill or log overflow and had no remaining process groups. HTTP/Unix relay threads and listeners stopped; relay and native sockets disappeared, with native sockets absent immediately after shutdown rather than removed by the harness.
- Harness metadata scan and independent read-only parent audit passed. The audit performed no request, sync, restore, replay or process launch. Sanitized evidence review `ae83ea74-2c8e-417e-aa8b-cfeaa7f755bd` found no issues and approved bounded local recording/integration only.

## Stop boundary

No additional native attempt after the one reviewed run without explicit owner approval. No auth proof, remote storage, production listener/proxy, VPS/live data, deployment, automatic recovery, distributed authority, policy relaxation or paid resource use. Timeout and later membership establish an ambiguous completed effect, not cancellation semantics, remote durability or complete ACK guarantees.
