# D4 local native proof-adapter implementation plan

> Owner-approved fresh local harness only. Use isolated worktree and TDD. No listener, deployment or VPS data.

## Task 1 — baseline and contract tests

- Run 107 runtime tests and 14 protocol tests; preserve existing warning/output categories.
- Create `experiments/d4/test_native_adapter.py` first and retain missing-module red.
- Test pre-kernel refusal of every non-main/aux-create path, private/path/loopback/binary constraints, exact single forward, exact single native sync and restore, TXID/path binding, restored row membership and structural checks, proof output, response/sync/restore/membership uncertainty, secret non-persistence and no retries.

## Task 2 — minimal adapter

- Create `experiments/d4/native_adapter.py`, standard library only.
- `NativeAdapter` owns one fresh private run root, loopback base URL, exact hash-pinned Litestream binary/control socket, main/aux source DB paths and an injectable command runner/opener for tests.
- `admit_native()` validates first-slice policy before calling the existing kernel. Only exact `POST` collection creates for `main_ops` and `aux_ops` are allowed; auth/item/update/delete/query/admin paths refuse before journal or callbacks.
- Forward exactly once with proxy-disabled, redirect-disabled bounded HTTP. Store transient request/response in adapter memory only. Classify 2xx as completed and HTTP errors as possible; transport errors propagate. Never retry.
- Proof invokes one `sync -wait -json` and one exact-TXID `restore -integrity-check none`; validates command identity/output, then independently opens the restored copy read-only with custom CHECK constraints ignored, runs SQLite integrity/foreign-key checks and verifies exact returned ID/op_key/payload. Return a proof bound to the kernel requirement. Any error propagates to `proof_uncertain`.
- No daemon lifecycle, native server startup, incoming listener, remote backend or auth proof in this slice.

## Task 3 — review and native fresh-fixture qualification

- Run targeted, protocol and current runtime tests; assert no changes under `hat/`, `deploy/` or existing `tests/`.
- Independent static review before native execution.
- If approved, use new private local data and copied hash-verified official binaries. Start loopback TrailBase/Litestream fixtures with one-hour background intervals; submit one main and one aux operation through separate journal identities and the adapter; independently inspect evidence/restores. Include stale membership and malformed proof/TXID negative controls without replaying successful operations. Stop/reap exact processes.
- Independent evidence review, final regression, local integration and clean worktree removal.

## Recorded implementation evidence

- Baseline: 14 protocol and 107 current runtime tests passed.
- Red: nine adapter tests failed because `native_adapter.py` was absent.
- Initial green: nine adapter tests passed.
- An in-root symlink regression then failed because resolving a path erased its symlink identity; original-path validation and an explicit private evidence directory fixed it.
- Initial verification: ten adapter, 14 protocol and 107 runtime tests passed. Existing runtime warning/output categories remain. `hat/`, `deploy/` and existing `tests/` are unchanged.
- Static review `7c8cd2d3-671a-4b89-bc37-2c21dc8c88e6` blocked native execution on restored-file mode, descendant process cleanup and path-component/TOCTOU checks; it also requested complete adapter-side binding.
- Five focused regressions failed on the blocked implementation: restored mode was `0644`, intermediate symlink accepted, replaced DB still proved, wrong digest still reached native commands, and process-group runner was absent. Corrections add no-follow restored-file validation and `0600`, component/inode revalidation before use, full binding comparison and dedicated process-group termination/reaping. The first focused green attempt had only a stale expected error string; corrected tests then passed.
- Follow-up review `a2df5c82-a640-4635-a31c-accbd6c10395` confirmed the original P1/P2 fixes, then blocked native execution on an intermediate root-component symlink. It also identified unbounded native output and operation-directory identity replacement.
- Three regressions failed on that implementation: intermediate root symlink accepted, replaced operation directory still proved, and bounded runner output was absent. The first corrected run exposed only a test artifact placed outside its temporary root; no implementation check failed. The test was made self-contained.
- Second follow-up review `8ef43a35-ca76-4ca6-96d1-1f8a95544fd7` accepted bounded output and operation-directory identity, but blocked on a claimed `symlink/../root` normalization bypass. The regression showed this interpreter already preserved and refused the symlink; its red was only a classification mismatch. Raw `..` root components are nevertheless now explicitly refused before constructing an absolute path, making the invariant version-independent.
- Final static review `85de5596-d25a-456e-9734-e09b86a5c87c` found no issues and cleared one fresh private local fixture only. Current verification: 17 adapter, 14 protocol and 107 runtime tests pass; diff checks confirm no changes under `hat/`, `deploy/` or existing `tests/`.
- Exact harness review `5d3065ed-1c86-4e36-b3e7-d3bbefb8094f` blocked execution until explicit file-replica type, fresh/private replica paths, readiness bounds, process-group cleanup and root/binary checks were added. Follow-up `83513d3d-9c69-49ea-b3c4-dffbab6794ff` found no issues.
- First native attempt `native-adapter-native-33f1153a61e7` failed before replication readiness or any admission because a helper named `http` shadowed the imported module. Both process groups exited 0, were reaped without forced kill and disappeared. The root and failure are preserved and were not reused. A failing static namespace-collision check captured the defect.
- Review `2147c563-9d9d-4bc6-baa5-8ff364245ded` accepted the exact import alias fix and one fresh rerun. Fresh run `native-adapter-native-deee4e866770` used newly copied hash-verified binaries and passed: main and aux independently advanced file-replica TXID 1 to 2, exact restored rows matched ID/op_key/payload, and journals recorded bound proof before releasing HTTP 200. Six malformed proof variants were refused. TrailBase and Litestream exited 0, were reaped without forced kill and their process groups disappeared.
- Initial evidence review `20d408c3-a2d5-43eb-b4b3-020f017305db` required an explicit stale-predicate transcript rather than the original `null`/`REFUSED` summary. A read-only supplemental audit, without native process or replay, ran the exact membership SQL against both preserved TXID-1 images and recorded the expected rows as absent, with structural checks, zero foreign-key violations and image hashes. Follow-up `aab4142a-a821-4d7e-8551-462b3fb8e8e3` resolved the blocker and approved bounded local recording/merge.

Private logs: `~/.config/hat/d4-qualification/native-adapter-b868aa4ca5b9/`.

## Stop boundary

Do not add auth proof, actual proxy/listener, distributed authority, proof publication, remote storage, systemd/HAProxy wiring, live installation, automatic recovery or paid resources. Passing this slice does not qualify client receipt, complete mutations, remote durability or HA.
