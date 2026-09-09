# D4 local observation/refusal — approved scope

The owner approved this implementation boundary after review `53684887-4c53-4025-a1d9-cfd9267f22bb`: inspect captured evidence locally and report missing/uncertain proofs, with **no power, activation, routing or rejoin capability**, no live installation/spending, and no change to existing manual behavior. This does not satisfy or bypass the unresolved provider effect-admission gate.

## Smallest design

Add a standalone `python3 hat/observe.py` entrypoint, not a branch through the operational controller. It reads one bounded UTF-8 JSON document from stdin and writes one JSON refusal report. Python standard library only; no actuator imports, network, subprocesses, state files, credential loading, URI/path dereferencing, or new dependencies. Existing controller/node entrypoints remain unchanged.

The input is an explicitly labelled capture envelope, not a new authority/proof protocol:

```json
{"version":1,"evidence":{"fencing":{"state":"uncertain"},"restore_image":{"state":"reported","capture":{"positions":{"main":4,"session":3,"aux":3}}}}}
```

Recognized categories: `authority`, `acknowledged_data`, `auth_state`, `restore_image`, `fencing`, `node_admission`, `ingress`, `controller_prerequisites`. Missing entries default to missing. Each supplied entry has state `missing`, `uncertain` or `reported`. A reported entry requires a nonempty object/array capture; uncertain entries may carry one. Missing entries cannot carry a capture. Unknown envelope/category/entry fields, duplicate JSON keys, nonfinite numbers, unsupported versions and malformed structures are errors. Maximum stdin size: 1 MiB.

Captures are opaque recorded claims: this mode does not authenticate them, validate native evidence contents, establish freshness, resolve referenced files/URLs, compare cross-epoch positions, or infer complete ACK/auth coverage. Every reported capture is labelled `reported_unverified`. Sensitive capture values are never echoed in the report or error.

Every result, including errors, states `mode: observation_only`, `decision: refuse`, `promotion_authorized: false`, and empty `action_capabilities`. A valid result lists category states and machine-readable refusal reasons; all-present input still refuses because this mode has no action authority. Exit 0 means a report was produced, not that recovery is safe. Exit 2 denotes invalid input. No action-enable switch is provided.

## Acceptance

- Missing and uncertain categories produce their respective reasons; all-reported input remains unverified and refuses.
- Strict malformed/oversized/duplicate-key cases produce bounded errors without leaking input values.
- Black-box execution of the actual entrypoint proves stdin/stdout and exit behavior.
- An audit-hook subprocess rejects network/process creation and filesystem mutation while running the actual entrypoint against action-shaped/path-shaped captured data. No paths are followed.
- Existing manual tests remain unchanged and pass. Independent review precedes integration.

This is an offline evidence inventory/refusal diagnostic—not distributed HAT admission, a proof verifier, a live observer, or automatic HA. A provider answer, a certificate lifetime, an etcd lease, or an operator-provided `reported` claim cannot enable an action through it.
