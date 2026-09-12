# Task 9E local node boundary contract

## Scope

Define the next safe boundary between the single controller and a future node agent. This slice validates versioned, strict JSON envelopes and local state binding only. It does not open a listener, make an HTTP/SSH call, spawn or stop a process, access TrailBase/Litestream, restore data, fence a provider, publish a route, or mutate a remote host.

## Data flow

1. The controller action command is converted into a versioned `NodeActionCommand` containing cluster, controller, node, incarnation, operation/request identity, server-derived digest, action kind, exact route generation, expected role/admission, and loss policy.
2. The node boundary parses bounded JSON with duplicate-key and unknown-field refusal.
3. A `NodeObservation` is produced from the local `NodeState` plus an explicitly supplied route-generation observation. Unknown route generation remains unknown; an action cannot validate against it.
4. The boundary validates exact cluster/node/incarnation identity, digest binding, action kind, generation, role, and admission before any future executor call.
5. Only the validated command/observation contract is returned to callers. Native execution remains a later adapter stage.

## Non-goals

No transport, authentication scheme, node listener, executor, process control, backup/restore, fencing, route publication, remote forwarding, deployment, or disruptive test is part of this slice.

## Test boundary

Use unit tests for strict wire round trips, duplicate/unknown/oversized input, digest mismatch, identity mismatch, unknown generation, stale generation, role/admission mismatch, and valid binding. Use a real local library boundary only; all tests use in-memory `NodeState` and no child/process or network effects.
