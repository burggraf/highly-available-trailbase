# Offline observation/refusal

`hat/observe.py` inventories **declared capture states**, not verified proofs. It always refuses promotion. It has no power, activation, routing or rejoin path and does not change the existing manual controller.

Run from a checkout with a finite UTF-8 JSON capture on stdin:

```sh
python3 -B hat/observe.py <<'JSON'
{"version":1,"evidence":{"fencing":{"state":"uncertain","capture":{"provider_state":"offline"}},"restore_image":{"state":"reported","capture":{"epoch":"d1-example","positions":{"main":4,"session":3,"aux":3}}}}}
JSON
```

This is a separate offline entrypoint, **not** an installed `hat observe` command. No installation, daemon, root privileges, credentials, live probes, etcd connection or new dependencies are required.

## Capture envelope

The only top-level fields are integer `version: 1` and object `evidence`. Evidence recognizes these categories:

- `authority`
- `acknowledged_data`
- `auth_state`
- `restore_image`
- `fencing`
- `node_admission`
- `ingress`
- `controller_prerequisites`

Each optional entry is an object with `state` and optionally `capture`:

| Declared state | Capture | Reported status |
|---|---|---|
| Omitted entry or `missing` | No capture on an explicit missing entry | `missing` |
| `uncertain` | Optional nonempty object/array | `uncertain` |
| `reported` | Required nonempty object/array | `reported_unverified` |

Native captured JSON can be wrapped in `capture`; its contents are opaque. For example, a reported healthy backup remains **unverified**, and a captured offline observation does not clear declared fencing uncertainty. This mode does not authenticate captures, validate their native schemas/semantics, infer uncertainty from nested fields, establish freshness, resolve references, or determine ACK/auth preservation. The caller's wrapper state is a claim, not an authority decision.

Unknown fields/categories/states, duplicate keys (including inside captures), nonfinite or overflowing floating-point numbers, unsupported versions, malformed captures and input over **1 MiB** are rejected. No command arguments or action-enable flags are supported. Stdin is a finite document ending at EOF, not a live event stream.

## Refusal report

Every JSON result includes:

- `mode: "observation_only"`
- `decision: "refuse"`
- `promotion_authorized: false`
- `action_capabilities: []`
- `evidence_statuses` and `reasons`

Valid inputs report `automatic_actions_disabled` plus one `<status>:<category>` reason per category. Missing and uncertain evidence stays visible; all-reported input still refuses and remains unverified.

Exit **0** means reporting completed—not that recovery is safe. Invalid input exits **2** with reason `invalid_capture` and the same refusal/capability metadata. Capture contents, unknown field values and command arguments are not echoed in reports/errors.

The program does not follow captured paths/URLs, execute captured commands, load credentials, create subprocesses, access networks or write state files. Tests execute the real CLI and its complete entrypoint under an audit hook, including a negative control for forbidden file access. This checks the program's non-actuating behavior; it is not a sandbox guarantee against a hostile Python interpreter or modified code.

No HAT admission, RPO guarantee, live observation, automatic recovery or deployment readiness follows from a report. See the [approved scope](plans/2026-09-09-d4-observation-only-design.md) and [D4 qualification limits](plans/2026-09-09-d4-coordination-baseline.md).
