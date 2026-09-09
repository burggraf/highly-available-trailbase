# D4 Offline Observer Implementation Plan

> **REQUIRED SUB-SKILL:** Use the executing-plans skill to implement this plan task-by-task.

**Goal:** Report missing, uncertain and unverified captured evidence without any action authorization or live access.

**Architecture:** A separate stdin/stdout Python entrypoint implements the approved observation-only design. It does not import operational HAT modules or dispatch through the manual controller. Captures remain unverified claims; every result refuses promotion.

**Tech Stack:** Python standard library (`json`, `sys`), existing `unittest`, real subprocess black-box checks.

---

## Task 1: Isolated baseline

- Worktree: `.worktrees/d4-observe`, branch `d4-observe`, based on `a2dfa4d`.
- Run `env -u HAT_CONTROL_ENTRY -u HAT_NODE_ENTRY -u HAT_TRANSITION_ENTRY -u HAT_RECOVERY_ENTRY python3 -m unittest discover -s tests -p 'test_*.py'`.
- Preserve results privately. No dependency installation is needed. Stop and investigate any baseline failure before implementation.

## Task 2: Failing tests

**Create:** `tests/test_observe.py`.

1. Assert `hat/observe.py` exists, then execute the real CLI using finite stdin and a five-second subprocess timeout.
2. Test an empty evidence mapping, uncertainty, and all-reported captures. Require `promotion_authorized` false, `decision` refusal, no capabilities, deterministic category statuses and refusal reasons.
3. Test malformed/duplicate/nonfinite JSON, unsupported versions, unknown fields/categories, malformed records, oversized bytes and unwanted command arguments. Require exit 2, safe refusal metadata, no raw-value echo.
4. Run the entrypoint under an audit hook denying network/process creation and filesystem mutation, with action/path/credential-shaped strings inside opaque captures. Require unchanged refusal and no capture echo. Include a negative control proving the hook rejects a forbidden operation.
5. Run `python3 tests/test_observe.py`; expect an explicit missing-entrypoint failure before implementation. Preserve red output.

## Task 3: Minimal implementation

**Create:** `hat/observe.py` only; existing runtime entrypoints stay untouched.

- Define eight fixed category names from the approved design and a 1 MiB input limit.
- Decode UTF-8 JSON with duplicate-key rejection and nonfinite-number rejection. Reject malformed envelopes and records without echoing input.
- Validate version as integer 1 (not bool), exact envelope fields, recognized category names, exact entry fields and supported states.
- Require a nonempty object/array capture for reported entries; allow optional nonempty capture for uncertain entries; disallow capture on missing entries.
- Map absent/missing to `missing`, uncertain to `uncertain`, reported to `reported_unverified`.
- Always return the equivalent of:

```python
report = {
    'mode': 'observation_only',
    'decision': 'refuse',
    'promotion_authorized': False,
    'action_capabilities': [],
    'evidence_statuses': states,
    'reasons': ['automatic_actions_disabled'] + [
        f'{state}:{name}' for name, state in states.items()
    ],
}
```

- Invalid input emits a fixed `invalid_capture` reason with the same refusal/capability metadata and exit 2; valid reporting exits 0. Never resolve captures, references, endpoints or executable arguments.
- Run the targeted tests green, then the unchanged current suite plus observer tests. No frozen qualification-runner changes.

## Recorded implementation evidence

- Initial worktree baseline: 97 tests passed. Pre-existing SQLite ResourceWarnings and expected parser-error output were retained.
- Red: the actual entrypoint was absent; the observer tests failed on that explicit assertion, while the audit-hook negative control passed.
- Green: 9 observer tests and 106 total current tests passed. The full suite retained the same pre-existing warning/output categories.
- Independent read-only review `fa9b8446-16b4-41b2-ba94-44aecf723775`: no issues, merge verdict OK. Test runs were parent-attested, not reproduced by the reviewer.
- Manual runtime modules, deployment files and frozen experiments remain unchanged. This is an offline inventory/refusal diagnostic only; nothing was installed or enabled.
- Private red/green/baseline logs: `~/.config/hat/d4-qualification/observer-code-9ad48c5b3dcc/`.

## Task 4: Documentation and independent review

**Create:** `docs/observation-only.md`; **modify:** `README.md` only to link it.

- Document the capture envelope, command, bounded input, refusal output, exit semantics and privacy/capability limits.
- State that no capture is authenticated/freshness-checked, no native proof semantics are validated and no live observation or HA is delivered.
- Inspect the diff for changes outside the approved files. Obtain independent read-only review of code/tests/docs; distinguish black-box local evidence from deployment qualification.
- Commit only verified changes. Do not install anything, enable actions, modify manual behavior or provision resources. Finish/integrate the branch according to the owner's workflow choice.
