# D4 Blocker Closure Implementation Plan

> **REQUIRED SUB-SKILL:** Use the executing-plans skill to implement this plan task-by-task.

**Goal:** Close every D4 contract, local publication, and host-observation blocker that can be independently proven, while preserving `infeasible` for unavailable stock TrailBase/macOS facts.

**Architecture:** Keep pure validation, pre-send closure observation, sandbox denial, and post-send Litestream proof as separate trust phases joined only by manager-owned content-addressed receipts. Use descriptor-relative filesystem primitives for all experimental adapter publication. Run a new private native fixture only after contract, publication, and host-capability gates pass independent review.

**Tech Stack:** Python 3 standard library, unittest, macOS AF_UNIX/`LOCAL_PEERCRED`, descriptor-relative filesystem APIs, pinned TrailBase v0.33.11 source/binary, Litestream v0.5.17.

---

### Task 1: Pin the reviewed phase-separated contract

**Files:**
- Create: `docs/plans/2026-09-10-d4-blocker-closure-design.md`
- Create: `docs/plans/2026-09-10-d4-blocker-closure-plan.md`

**Steps:**
1. Review the 13 blocker record and current validator/adapters.
2. Record the selected phase-separated design and rejected alternatives.
3. Run `git diff --check`.
4. Obtain independent design/spec review.
5. Commit only the two documents.

### Task 2: Add operation-specific Authorization closure

**Files:**
- Modify: `experiments/d4/surface_closure.py`
- Modify: `experiments/d4/test_surface_closure.py`

**Steps:**
1. Add failing tests proving main/aux require exactly one content type and one exact Bearer authorization header, while logout permits content type only.
2. Add failures for missing/duplicate/case-fold duplicates, Cookie, forwarding headers, combined values, bad scheme/whitespace/control/non-ASCII/oversize tokens, and unknown headers; assert zero callback calls.
3. Preserve valid header order if semantically equivalent, but freeze canonical validated bindings and never serialize token values into evidence helpers.
4. Run focused tests and confirm red.
5. Implement the minimum operation-specific header parser; keep framing outside this layer.
6. Run surface, native-adapter, logout-adapter, admission, and runtime suites.
7. Independently review raw-byte differentials and commit.

### Task 3: Separate process phases and socket identities

**Files:**
- Modify: `experiments/d4/surface_closure.py`
- Modify: `experiments/d4/test_surface_closure.py`
- Modify: `docs/plans/2026-09-09-d4-local-surface-closure-plan.md`

**Steps:**
1. Add failing tests for exact pre-send manager/TrailBase/opener/collector cardinality and ancestry, sandbox-probe receipt, and post-send Litestream receipt.
2. Add distinct listener pathname/listening-FD identity and accepted client/server endpoint identity; remove any accepted-endpoint/listener-path inode equality assumption. Every endpoint field names its kernel API/time, and unavailable linkage refuses.
3. Require content-addressed evidence and external trust inventory for every parent edge, lifecycle receipt, endpoint, peer credential, raw framing/header observation, and time/order fact. Bind exact HTTP version/Host/Content-Length/body boundary and absence of transfer/chunking before bytes are sent.
4. Reject extra/missing/overlapping roles, fixture-descendant collector, sandbox-probe substitution, unreceipted helper, stale process start, endpoint replacement, absent kernel link, any application bytes in either direction, and any Litestream pre-send presence or cross-phase/nonce reuse. Require Litestream launch strictly post-send.
5. Implement exact pure validation and immutable bindings; no subprocess/socket/path reads.
6. Run all D4/runtime/source/quarantine gates and independent adversarial review.
7. Commit focused schema/test changes.

### Task 4: Introduce descriptor-relative experimental publication

**Files:**
- Create: `experiments/d4/fd_publish.py`
- Create: `experiments/d4/test_fd_publish.py`
- Modify: `experiments/d4/native_adapter.py`
- Modify: `experiments/d4/auth_logout_adapter.py`
- Modify: `experiments/d4/admission.py`
- Modify: `experiments/d4/test_admission.py`
- Modify corresponding adapter tests.

**Steps:**
1. Write failing unit tests for traversal, symlink/hardlink, wrong owner/mode/type, parent replacement, destination identity drift, duplicate name, short write, fsync failure, lock loss, cross-device/unsupported rename, and post-operation digest mismatch.
2. Implement owner-only held-directory opening, single-component names, `O_EXCL|O_NOFOLLOW|O_CLOEXEC`, bounded writes, file/directory fsync, and immutable receipts.
3. Implement descriptor-relative atomic rename only with retained directory FD and expected destination identity/digest; otherwise refuse.
4. Route every admission journal, adapter artifact, and restored-image publication through the helper; retain adapter behavior and proof ordering. Spy tests must show `admission.py`, native adapter, and logout adapter have no direct security-sensitive pathname publication.
5. Add spies proving adapters cannot use direct pathname `_write`/`os.replace` publication.
6. Run focused tests, all D4/runtime tests, static source review, and independent race review.
7. Commit only experimental files/tests.

### Task 5: Qualify host primitives without TrailBase

**Files outside Git:**
- Create fresh: `~/.config/hat/d4-qualification/surface-primitives-<random>/`
- Create bounded probe/checker/evidence files only.

**Steps:**
1. Build a static-reviewed, owner-only probe harness with no TrailBase/Litestream execution. Include `test_probe.py`, `static_check.py`, exact blocker matrix JSON, and one receipt schema per blocker.
2. Test tiny readiness-handshaked local processes for PID/parent/start identity, FD inventory, CLOEXEC observation, sibling provenance, collector read-only input FDs, and cleanup/reaping.
3. Test a tiny AF_UNIX server/client for `LOCAL_PEERCRED`, listening identity, accepted endpoint identity, independent endpoint-to-listener/process linkage, and exact raw framing/header receipt. Send no TrailBase application bytes.
4. Test a pinned `sandbox-exec` profile using clean env/cwd, enumerated FDs, controlled positive/negative paths, and denial of external/loopback/DNS/UDS/subprocess capabilities.
5. Descriptor-bind canonical source archive/provenance and prior oracle packets.
6. Run each probe once through its deterministic test command. For every one of the 13 blocker IDs, require exactly one content-addressed receipt with `closed|unavailable|ambiguous`; only `closed` may clear that ID.
7. Any unavailable/ambiguous fact halts Tasks 6/7. Preserve the fresh root `pending`; every later attempt uses a new random root and never reopens or converts prior roots.
8. Obtain independent evidence/security review and record each blocker as closed or remaining.

### Task 6: Decide runtime registration and telemetry feasibility

**Files:**
- Modify only D4 plan/status documentation unless an independent stock-binary observation exists.

**Steps:**
1. Reconcile the pinned source expected route/job/plugin/log set with stock TrailBase runtime interfaces.
2. Require independent complete runtime registration evidence in a manager-held, content-addressed pre-send receipt with an externally fixed expected inventory; OpenAPI/config/self-report may not establish absence.
3. Require independent complete `logs.db` reader/writer and SQL call-path evidence in a separate manager-held pre-send receipt; raw logs cannot establish it.
4. If either observation is unavailable, record `infeasible`, do not build/run a native fixture, and retain blockers.
5. If both are available, specify exact bounded collector inputs and obtain review before implementation.

### Task 7: Build and review a fresh private native harness only if all gates close

**Files outside Git:**
- Create fresh: `~/.config/hat/d4-qualification/surface-closure-<random>/`

**Steps:**
1. Never reuse `surface-closure-6Ks3W2ng` or any failed/ambiguous probe root.
2. Build manager, independently observed sibling collector, held opener, separate sandbox-probe phase, and post-send Litestream phase with unique non-overlapping nonces and exact O_EXCL receipts.
3. Static review before execution. Then require a fresh owner authorization receipt with exact root, binary hashes, local UDS paths, three mutations, no external network, duration and expiry; absent/expired/mismatched authorization stops before spawn.
4. Execute denied-request zero-send matrix and only the three positive controls if every live observation is available.
5. Preserve all failures, cleanup evidence, secret scan, and pending quarantine.
6. Record feasible or infeasible without weakening requirements.

### Task 8: Final verification and checkpoint

**Files:**
- Modify: `docs/plans/2026-09-09-d4-local-surface-closure-plan.md`
- Modify: `docs/status.md`

**Steps:**
1. Run all D4 and runtime tests once as verification only; preserve any earlier or current failure without rerun substitution.
2. Run canonical source, quarantine, diff, changed-path, and clean-status gates.
3. Obtain independent final evidence/spec/security reviews.
4. Commit the exact result and non-claims.
5. Stop for explicit owner approval before integration, push, worktree cleanup, deployment, or evidence destruction.

## Global fail-closed rules

Any failed focused test/review, unavailable or ambiguous primitive, descriptor identity drift, incomplete receipt inventory, cleanup/reap uncertainty, or secret-scan finding blocks later native tasks. Every attempt uses a fresh random owner-only root; prior pending roots remain untouched. No partial set of closed blockers authorizes a fixture. No document authorizes system services, privileged helpers, production/live paths, binds outside the disposable root, external network, deployment, or mutations beyond the three exact local controls.
