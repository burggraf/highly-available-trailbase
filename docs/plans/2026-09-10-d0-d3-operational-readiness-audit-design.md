# D0–D3 Operational Readiness Audit Design

## Purpose

Convert the delivered D0–D3 manual recovery state into a concise, internally consistent operating baseline without reopening D4 or making live-system changes. D4 remains documented as infeasible under the approved stock TrailBase v0.33.11 contract.

This increment is documentation-only. It does not contact A, B, C, the provider, or private services, and it does not authorize power, routing, promotion, recovery, rejoin, credential, deployment, evidence-cleanup, or automatic-HA actions.

## Alternatives

1. **Focused operational audit (selected).** Reconcile the existing runbook, status, implementation, and tests; correct factual documentation defects and produce one prioritized readiness checklist.
2. **Full operations handbook.** Split incident response, drills, restore procedures, retention, and risks into multiple documents. Rejected as duplicative and costly to maintain at the current prototype stage.
3. **Code-backed audit.** Add new validation commands and tests. Deferred until the operating contract is settled; adding executables now would mix documentation findings with implementation and qualification.

## Sources of truth

The audit compares:

- `docs/runbook.md`: current operator instructions;
- `docs/status.md`: delivered state, preserved failures, limits, and non-claims;
- `hat/`: controller, recovery, transition, node, and client behavior;
- `tests/`: executable coverage of documented behavior.

Each important claim follows:

`documented instruction → code path → existing test/evidence → supported claim or blocker`

For each operator-visible action, record its actual preconditions, files/services/authority inputs, observational or mutating nature, failure/evidence behavior, replay policy, supporting tests/evidence, and documentation gaps.

## Deliverable

Create `docs/plans/2026-09-10-d0-d3-operational-readiness-audit.md` containing:

1. supported manual D0–D3 operating envelope;
2. operator-critical contradictions or stale instructions, ranked by safety impact;
3. a readiness checklist for restore verification, replication observation, evidence retention, escalation, and manual-drill prerequisites;
4. a risk register covering C/ingress, capacity, fault domains, certificate lifecycle, acknowledgement coverage, provider uncertainty, and authority-aware admission;
5. ordered next work, with contracts and read-only checks before code or live changes;
6. explicit non-authorizations.

Apply only clear factual corrections to `docs/runbook.md` and `docs/status.md`. Unverified assumptions remain blockers rather than becoming instructions. Add no script, abstraction, service, or operational command.

## Finding classes

- **Correct now:** documentation, implementation, and evidence agree.
- **Documentation correction:** implementation is clear but prose is stale or ambiguous.
- **Contract missing:** desired behavior lacks an authoritative external or safety contract.
- **Operational qualification missing:** implementation exists but has not been adequately demonstrated.
- **Out of scope:** automatic HA, D4 admission, or production claims.

## Work ordering

1. Correct unsafe or stale runbook instructions.
2. Define a repeatable non-disruptive restore-verification procedure.
3. Define drill cadence, evidence retention, escalation, and stop conditions.
4. Record prerequisites for C redundancy, sustained capacity, physical fault domains, and certificate rotation/revocation.
5. Keep complete acknowledged-mutation coverage, provider late-effect settlement, and common authority-aware admission as contract work, not implementation tasks.

## Acceptance

- Only documentation paths change.
- No credentials, infrastructure identifiers, or private evidence enter Git.
- Every positive claim is linked to code/tests or marked unverified.
- `git diff --check` passes.
- Existing relevant tests remain unchanged; run them if a documentation correction changes command semantics.
- Independent specification and safety review approve the exact result.
- Stop for explicit owner approval before push or any live follow-up.
