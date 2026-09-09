# Approved local recovery loss guard

The owner authorized a local-only fail-closed correction after the source audit found that manual recovery accepted a nonempty fault `lost` classification. At implementation approval, no deployment, provider action or live drill was authorized. The owner subsequently authorized installation on the supplied VPSs; the bounded C-only installation is recorded below.

## Minimal implementation plan

1. Verify the unchanged current test baseline in `.worktrees/d4-loss-guard`.
2. Extend the existing fake-I/O recovery-driver fixture with one complete, well-formed classification that moves the acknowledged operation from `recovered` to `lost`. Add a regression requiring refusal at comparison, retained pending intent/failure, no activation or routing, and refusal of replay. Observe it fail before changing production code.
3. Reject nonempty `lost` in `recovery._fault_outcomes()` after existing structural/partition validation. Its sole production caller is the recovery comparison phase. Keep `classify_fault()` unchanged: accounting must still report lost operations.
4. Run targeted and full current tests, then obtain independent static review. Integrate locally using the existing main-branch workflow after verification; no push or installation. Preserve test logs outside Git.

## Local evidence

Baseline: 106 current tests passed. The new driver regression failed before implementation with `RuntimeError not raised`. After the two-line guard, six recovery-driver tests and 107 current tests passed. Full-suite SQLite ResourceWarnings and expected parser-error output remain; no frozen suite or native deployment was rerun. Logs are retained under `~/.config/hat/d4-qualification/observer-code-9ad48c5b3dcc/loss-guard-*`.

Independent static review `ae260677-465e-4735-be9a-8842e6d4ebd9` found no issues and approved local integration only. Tests were parent-attested, not independently rerun by the reviewer.

This guard only rejects explicitly reported acknowledged-write loss. It does not establish complete ACK/auth coverage, authenticate arbitrary oracle claims, settle provider uncertainty, or implement distributed admission. Existing malformed/overlapping/incomplete classification refusals and successful zero-loss recovery checks remain intact.

## Authorized controller installation

The owner subsequently authorized installation on the supplied VPSs. Parent executed one narrowly scoped replacement on C from local commit `2a2e61d`; no recovery, power, activation, routing or service-restart action was run. No additional resources were provisioned and no push was performed.

- Initial read-only pinned preflight matched the installed predecessor/dependencies, completed D3 journal, expected healthy A/B roles and active ingress.
- Static installer review `60111130-389d-4ba1-9591-ead9acaf8bb3` blocked assertion-dependent safety gates under Python optimization. Original source and evidence were retained. Explicit optimization refusal was added before payload/state access, and installer/test interpreters use `-I -B`. The entire installer refused under `-I -O -B`; repeated native preflight with `PYTHONOPTIMIZE=1` reported `optimize=0`. Follow-up review `c8c46f6e-9e35-4854-ada2-596a915aa2d7` resolved the blocker before installation.
- Native wrong-predecessor-hash negative control refused before staging/replacement. Correct installation held the existing controller lock, revalidated protected hashes/state, retained the original file, atomically replaced only `/opt/hat-control/recovery.py`, and fsynced the containing directory.
- Six candidate and six exact installed-module driver checks passed on C. These tests used fake operational I/O; audit hooks prohibited subprocess/network effects and included a refusal negative control. They qualify the installed local policy guard, not actual failover or distributed admission.
- A separate read-only audit verified the installed hash, original backup, test identity, completion receipt and archive members. Journal bytes/rows, controller and ingress configuration, other protected modules, C boot and ingress PID remained unchanged. Fresh status reads showed healthy A writer/B standby in epoch `d1-59f3e121806a43dfb2326fb0d2a62eba`; no new restore/ACK/RPO acceptance is claimed.

Installed SHA-256: `7cfe3c7f211ab37d96f6291e50a09e027d88054f7241b396dcad77a8b2575f38`.
Retained predecessor SHA-256: `4a3601338aaa277705fd941e1e1f4e5114cc64b28475ef15d331a3f09bfddca8`.
Private archive SHA-256: `2db9e05c5132e834b1f37fec4c172005bcb15e66f1f8dc59396b40598ad18be1`.

Evidence: `~/.config/hat/d1-deployment/loss-guard-ab253c18980a/`, including original/repeated preflights, negative controls, installation receipts, `final-audit.json` and `controller-evidence.tar.gz`. C retains `/var/lib/hat-control/loss-guard-ab253c18980a/`. These are one-shot historical scripts, not approved retry/rollback tools. Timeout would have required separate inspection, not replay; the actual installation and audit completed without a timeout.

