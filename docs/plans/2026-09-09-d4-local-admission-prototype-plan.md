# D4 local admission prototype implementation plan

> Required discipline: isolated worktree, TDD, independent review, no deployment.

## Task 1 — baseline and red tests

- Run the unchanged current suite and preserve output privately.
- Create `experiments/d4/test_admission.py` against the design API.
- Cover input/surface validation, local journal ordering, proof binding, uncertainty, caller-asserted non-mutation refusal, replay, authority replacement, privacy and capability audit.
- Run the tests and retain the expected missing-module failure.

## Task 2 — minimal protocol kernel

- Create `experiments/d4/admission.py` with only standard-library imports.
- Implement strict request/outcome/proof validation, fixed surface mapping, private SQLite journal with exclusive flock and identity checks, and one synchronous `admit` operation.
- Store digests/metadata only. Never store body, response body, credentials, cookies or proof artifacts.
- Commit intent before forward, forward outcome before proof, and proof before release. Never retry callbacks or operation IDs.
- Keep this module disconnected from `hat/`, deployment and entrypoints.

## Task 3 — verify and review

- Run targeted tests then the complete current suite. Record SQLite-configured local durability narrowly; do not claim independent power-loss/filesystem qualification.
- Confirm no changes to `hat/`, `deploy/` or existing manual tests/entrypoints.
- Obtain independent read-only review focused on failure ordering, SQLite durability/authority, replay refusal, privacy and overclaiming.
- Apply only verified findings, rerun tests, commit and locally integrate using the established worktree workflow.

## Recorded local evidence

- Baseline: 107 current runtime tests passed, retaining existing warning/output categories.
- Initial red: 11 tests failed because the experiment module was absent.
- Initial green: 11 targeted tests passed.
- A callback-mutation regression then failed because `forward` could alter the caller's epoch/boot/body/headers after intent. The implementation now snapshots the forwarded request and immutable proof binding; the test passed.
- An existing SQLite sidecar-symlink test initially reached SQLite and raised `OperationalError`; explicit pre-open sidecar validation was added and passed.
- The first audit-hook test run failed only because its helper emitted literal `PASS\\n`; the original failure remains in private logs. Corrected helper plus negative controls passed.
- Fourteen targeted tests and all 107 current runtime tests passed after these corrections. `hat/`, `deploy/` and existing runtime `tests/` remain unchanged.
- Independent review `dd9ade8b-5176-4abc-b43e-0871b47ec516` found caller-supplied `mutation: none` could bypass proof after a mutating 4xx. A new regression reproduced `rejected`; the stronger correction removes `none`/`rejected` entirely so every recognized forwarded outcome requires proof. Fourteen targeted and 107 runtime tests passed after the fix. Follow-up review `46fc0be7-9234-4497-ac21-47e21b0804c3` found the safety findings resolved and no blockers. Its only P2 wording note—authorization/cookie headers are transient secrets, not non-secret headers—was corrected before final verification.

Private logs: `~/.config/hat/d4-qualification/admission-prototype-b4c3bbff4b5e/`.

## Stop boundary

Do not add an HTTP listener, native Litestream invocation, etcd/lease client, proof signer, systemd unit, HAProxy configuration or live installation. Those require a separately reviewed design and explicit rollout authority. Fixture callbacks are not deployment evidence.
