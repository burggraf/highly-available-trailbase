# Route Authority Hardening Design

## Purpose

Close the repository-level P0 ingress-admission gaps found by the D0–D3 operational audit without contacting or changing the deployed demo. The change is local code and tests only; it does not authorize ingress restart, reconciliation, routing, restore, or any live operation.

## Selected approach

Use one small exact route-evidence predicate in `hat/control.py` and reuse it wherever a route is interpreted as writer authority. A valid route is an exact dictionary:

```python
{"writer": target, "epoch": new_epoch, "config_sha": current_ingress_sha256}
```

Unknown, missing, or extra fields; malformed JSON; wrong writer or epoch; and same-hash substitutions all refuse.

Apply the predicate to:

- `current_writer`, preserving its exact completed-journal checks;
- the completed branch of `ingress_allowed`;
- completed-operation handling in `reconcile_existing`, while preserving its intentional target-B-only restriction and completed-D3-target-A refusal.

For incomplete D2 ingress admission, require the exact ordered D2 journal prefix through `baseline|done`, followed by `route|intent`, with empty evidence on every intent and no missing, reordered, duplicate, or extra step. Preserve the existing maintenance, failure, live permit, current boot, PID/birth, and config-hash checks.

## Rejected alternatives

- Calling `current_writer()` from every path would couple read-only ingress checks to journal lock/authority behavior.
- Leaving the paths documentation-blocked would preserve safety but not close the P0 source defect.
- Adding a generic policy or schema framework would be unnecessary for three call sites and one fixed phase sequence.

## Tests

Failing-first tests cover:

- completed ingress refusal for wrong writer, epoch, missing/extra route keys, malformed route, and same-hash tampering;
- completed reconciliation refusal with maintenance retained for the same mutations;
- unchanged target-B-only completed reconciliation behavior;
- incomplete D2 refusal for missing, reordered, duplicate, or extra steps and nonempty intent evidence;
- acceptance of the existing exact D2 pending boundary;
- no ingress start, maintenance removal, or other callback on refusal.

Run focused transition/recovery guard tests, the full runtime suite, and D4 tests. Preserve any failure without rerun substitution.

## Non-claims

This hardens local admission logic only. It does not establish a distributed authority, current deployment state, safe live reconciliation, automatic HA, D4 feasibility, or a unified restore-acceptance contract. Deployment and any live exercise require separate explicit authorization after review.
