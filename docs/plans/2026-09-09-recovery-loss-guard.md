# Approved local recovery loss guard

The owner authorized a local-only fail-closed correction after the source audit found that manual recovery accepted a nonempty fault `lost` classification. No deployment, provider action or live drill is authorized.

## Minimal implementation plan

1. Verify the unchanged current test baseline in `.worktrees/d4-loss-guard`.
2. Extend the existing fake-I/O recovery-driver fixture with one complete, well-formed classification that moves the acknowledged operation from `recovered` to `lost`. Add a regression requiring refusal at comparison, retained pending intent/failure, no activation or routing, and refusal of replay. Observe it fail before changing production code.
3. Reject nonempty `lost` in `recovery._fault_outcomes()` after existing structural/partition validation. Its sole production caller is the recovery comparison phase. Keep `classify_fault()` unchanged: accounting must still report lost operations.
4. Run targeted and full current tests, then obtain independent static review. Integrate locally using the existing main-branch workflow after verification; no push or installation. Preserve test logs outside Git.

## Local evidence

Baseline: 106 current tests passed. The new driver regression failed before implementation with `RuntimeError not raised`. After the two-line guard, six recovery-driver tests and 107 current tests passed. Full-suite SQLite ResourceWarnings and expected parser-error output remain; no frozen suite or native deployment was rerun. Logs are retained under `~/.config/hat/d4-qualification/observer-code-9ad48c5b3dcc/loss-guard-*`.

Independent static review `ae260677-465e-4735-be9a-8842e6d4ebd9` found no issues and approved local integration only. Tests were parent-attested, not independently rerun by the reviewer.

This guard only rejects explicitly reported acknowledged-write loss. It does not establish complete ACK/auth coverage, authenticate arbitrary oracle claims, settle provider uncertainty, or implement distributed admission. Existing malformed/overlapping/incomplete classification refusals and successful zero-loss recovery checks must remain intact.
