# HAT development workflow

## Start here, every session

1. Read `README.md`, `docs/status.md`, and the **Execution state and acceptance** section of `docs/plans/2026-09-11-v1-manual-failover.md`.
2. Read the active task and its acceptance criteria, then the relevant `docs/v1-contract.md` sections and source/tests. The single-controller V1 plan wins over superseded architecture proposals; user safety restrictions always apply.
3. Run `git status --short --branch`, `git worktree list`, and inspect the actual diff. Locate the implementation worktree from the plan handoff; do not start a second competing implementation. Preserve unrelated/uncommitted files.
4. Reconcile recorded evidence with the actual revision and dirty files. Stale evidence is not a fresh pass. Read unresolved failures before running commands. If the recorded worktree is missing, inspect branches/commits; do not silently reconstruct or declare completion.

## Scope and authority

- New runtime code belongs under `rust/`. Python `hat/`, `tests/`, `experiments/`, and existing deployment files are historical executable references, not the Rust roadmap. Do not modify or run historical live/native harnesses without scoped authorization.
- Work in an isolated implementation branch/worktree by default. When the owner explicitly directs work on the clean `main` branch, use `main`, do not create a competing worktree, and preserve unrelated/uncommitted files. No new repository, consensus framework, speculative scaffold, or architecture reset.
- Owner-approved autonomy: finish **one explicitly authorized stage**, including local test/fix/review iterations, then stop at acceptance. A plan listing later stages is not permission to execute them.
- Owner permits local checkpoint commits. Commit only understood task-owned changes; label partial checkpoints honestly. Never sweep unrelated files into a commit. Merge, push, and worktree deletion require explicit approval.
- No deployment, private credential discovery/access, live services, fencing, infrastructure provisioning/spending, or destructive historical cleanup without separate scoped approval. Unit success cannot authorize these actions. Native tests must remain explicit opt-in with an approved disposable fixture.

## One authoritative state record

The active plan owns stage state, criterion IDs, evidence, and the restart handoff. `docs/status.md` is a short summary/pointer, not a second task tracker. `rust/README.md` describes actual executable behavior. Chat summaries and tool plan trackers are convenience only.

Stage states:
- `pending`: not started.
- `in_progress`: authorized work underway; criteria remain unmet.
- `blocked`: cannot safely continue; record exact reason and required decision/evidence.
- `accepted`: every approved criterion passed on the identified source, review is complete, and handoff/docs are current. Not synonymous with merged, deployed, or production-qualified.

Criterion states: `not_run`, `fail`, `pass`, `blocked`. No unchecked criterion counts as a pass. Approval and execution are separate: record criteria as `proposed` or `approved` with the owner decision reference. Do not infer approval of newly added requirements from approval of the workflow itself.

## Acceptance contract for each stage

Before implementation, freeze a small table in the active plan:

| ID | Observable requirement (including refusal cases) | Exact check/evidence | Result |
| --- | --- | --- | --- |
| Tn-AC1 | A behavior observable at its real boundary | Named test/command and fixture scope | not_run |

Include scope/non-goals, allowed effects, criterion approval, and completion gates. Future stages may retain draft criteria until they are authorized. Schema/API decisions inside the approved slice may be resolved locally and documented; changing architecture, safety promises, or acceptance requirements needs owner agreement. Do not weaken a test/criterion to make a stage pass.

Required gates for every implemented Rust stage:
- Trace real inputs/callers; write and observe a meaningful failing behavioral test before its implementation. A missing type/compiler error alone is not behavioral RED evidence.
- Named regression checks plus the whole package suite pass. CLI/integration claims exercise the real binary; mocks do not qualify transport/native behavior.
- Run the active plan's fmt, test, clippy, locked release build, and diff checks. Use managed background processes for long builds/tests; consume actual exit results, not filtered summaries.
- Review the full diff against every criterion, security/refusal boundaries, and scope. Record reviewer identity, findings, fixes, residual risks. Label self-review honestly; use a fresh read-only reviewer for security/authority/action boundaries. Review tooling failure is not approval.
- Record command, exit code, counts, source revision plus dirty-file scope (or patch digest), environment, and retained evidence path. Preserve failed attempts; subsequent green results do not erase them. Never put secrets/raw application payloads in public evidence.
- Update the plan, status summary, and executable usage docs before calling the stage accepted. If source changes after verification, rerun affected checks and final gates.

## Autonomous loop and stop rules

Within approved scope: RED → minimum fix → focused GREEN → package checks → review → fix findings → final gates. Do not ask permission for each routine local edit/test. Add no features from the next stage just to satisfy a review.

Stop for missing authorization, unsafe/unknown effects, incompatible contracts, unavailable prerequisites, infrastructure/tooling blockers, or a needed acceptance change. After two consecutive attempts fail at the same integrated milestone for an unresolved reason, record evidence and stop for focused diagnosis/owner decision; do not repeatedly rebuild/redeploy or reset state. Expected RED tests and distinct routine local fixes are not integrated-attempt failures.

On interruption or any stop, update the handoff even if tests are red. Record:

```text
Stage/state; criteria approval and current authorization
Branch/worktree; base/source commit; dirty files or patch digest
Implemented vs missing; criterion results; latest commands/exits/evidence
Review findings; failures/uncertainties; active processes (or none)
Exact next safe command/edit; blockers and decision needed
Commit/merge/deployment status
```

A checkpoint can refer to its containing commit rather than attempting to embed its own hash. On restart obtain that hash from Git. If a session dies before recording state, inspect the diff/processes and conservatively reverify—never infer acceptance from a commit message.
