# D0–D3 Operational Readiness Audit Implementation Plan

> **REQUIRED SUB-SKILL:** Use the executing-plans skill to implement this plan task-by-task.

**Goal:** Produce a repository-only operational-readiness audit and correct the D0–D3 manual recovery runbook without contacting or changing live systems.

**Architecture:** Trace operator-facing claims from documentation through the actual `hat/` command paths and tests. Record only supported facts, classify every gap, and keep contracts/qualification separate from implementation. Make the smallest documentation-only corrections needed for a safe manual operating baseline.

**Tech Stack:** Markdown, Python standard-library source inspection, unittest, Git.

---

### Task 1: Build the operator-action evidence map

**Files:**
- Create: `docs/plans/2026-09-10-d0-d3-operational-readiness-audit-findings.md`
- Read: `docs/runbook.md`
- Read: `docs/status.md`
- Read: `hat/control.py`
- Read: `hat/recovery.py`
- Read: `hat/transition.py`
- Read: `hat/node.py`
- Read: `hat/client.py`
- Read: relevant `tests/test_*.py`

**Steps:**
1. Inventory every operator-visible D0–D3 command and classify it as read-only or mutating.
2. For each command, identify exact authority/precondition inputs, durable intent behavior, replay policy, failure evidence, and relevant tests.
3. Compare those facts with `docs/runbook.md` and `docs/status.md`.
4. Record findings as `correct now`, `documentation correction`, `contract missing`, `operational qualification missing`, or `out of scope`.
5. Include exact source/test paths for positive claims; mark historical/live-only claims separately.
6. Confirm no credential, private infrastructure identifier, or raw evidence entered the document.
7. Run `git diff --check` and commit the evidence map.

### Task 2: Correct the manual runbook and add the readiness checklist

**Files:**
- Modify: `docs/runbook.md`
- Modify: `docs/plans/2026-09-10-d0-d3-operational-readiness-audit-findings.md`

**Steps:**
1. Add a clear current operating envelope: manual D0–D3 only, D4 stock-runtime infeasible, no automatic HA.
2. Add a non-disruptive observation checklist using only existing documented status surfaces; do not invent or execute commands.
3. Add a restore-verification checklist that distinguishes preparation, explicit mutation authorization, evidence retention, and acceptance. Do not label any restore command non-disruptive if it can create files, processes, sessions, or application requests.
4. Add manual drill prerequisites, stop conditions, retry prohibition, escalation criteria, and evidence-retention rules.
5. Correct stale or ambiguous existing instructions only where source/tests establish the behavior.
6. Record unresolved assumptions as blockers rather than procedures.
7. Run documentation assertions with `rg`, `git diff --check`, and changed-path checks.
8. Commit the runbook correction.

### Task 3: Record the prioritized operational risk register

**Files:**
- Modify: `docs/status.md`
- Modify: `docs/plans/2026-09-10-d0-d3-operational-readiness-audit-findings.md`

**Steps:**
1. Record C/ingress as a prototype single point of failure without proposing an unqualified automatic replacement.
2. Record sustained capacity and physical fault-domain validation as operational qualification gaps.
3. Record certificate rotation and administrative revocation as unqualified lifecycle procedures.
4. Record complete acknowledged-mutation coverage, provider late-effect settlement, and common authority-aware admission as missing contracts.
5. Order next work: documentation corrections, read-only contract research, separately authorized non-disruptive observations, then separately approved implementation/live drills.
6. State that D4 remains closed under stock TrailBase and that an instrumented/forked scope requires a new decision.
7. Run `git diff --check` and commit the status/risk update.

### Task 4: Verify and independently review the documentation checkpoint

**Files:**
- Modify only documentation if review identifies a factual defect.

**Steps:**
1. Verify the changed-path allowlist contains only the design, implementation plan/findings, runbook, and status documents.
2. Run 113 D4 tests and 107 runtime tests once; preserve any failure without rerun substitution.
3. Run `git diff --check` and verify a clean worktree after commits.
4. Obtain independent specification review tracing claims to source/tests.
5. Obtain independent safety review for mutation labeling, retry/evidence rules, secret handling, and non-authorization boundaries.
6. Correct only concrete documentation defects and repeat focused review.
7. Commit the exact reviewed checkpoint.
8. Stop for explicit owner approval before integration, push, worktree cleanup, live access, or evidence disposition.

## Global constraints

- Repository-only: no SSH, browser, provider API, private endpoint, power, routing, promotion, recovery, rejoin, credential, deployment, or evidence-root mutation.
- No new executable, service, script, dependency, protocol, or speculative automation.
- Existing private paths may be mentioned only at their already-public documentation level; do not read or copy private evidence for this audit.
- A timeout or missing evidence is uncertainty, not success or cancellation.
- Historical successful checks do not establish current live state.
- D4 infeasibility remains unchanged.
