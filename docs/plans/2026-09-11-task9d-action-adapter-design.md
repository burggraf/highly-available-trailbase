# Task 9D local action-adapter contract

## Scope

Define the controller-to-node action boundary without executing an operating-system, TrailBase, Litestream, provider, SSH, systemd, or remote effect. The default dashboard uses an unavailable adapter and remains fail-closed. Tests may inject an in-memory adapter that only returns bounded outcomes.

## Data flow

1. An authenticated browser submits an action kind, request ID, operation ID, target, exact route generation, expected role/admission, and loss acknowledgement.
2. The controller validates origin/Host, CSRF, session, configured authority, target inventory, expected state, generation, and action policy.
3. The server derives the operation digest from the validated action fields; the browser cannot choose a digest.
4. If the adapter is unavailable, the request is refused before journal insertion.
5. For an available adapter, a new request is durably inserted once. Exact replay returns the retained receipt without dispatch; identity or parameter conflicts refuse.
6. The adapter receives a typed command bound to the cluster, authority, operation identity, target, generation, expected state, and loss policy. Its bounded outcome maps to `succeeded`, `failed_safe`, or `blocked_uncertain` in the journal. Uncertain outcomes block later mutations.

## Non-goals

No node-agent transport, process spawning, restore, fencing, route publication, forwarding to fm3, native binary invocation, remote deployment, or UI enablement is part of this slice.

## Test boundary

Use a real HTTP router/server integration test with an injected recording fake adapter for durable replay/conflict/outcome behavior. Keep the normal CLI/server on the unavailable adapter and retain refusal tests. Assert the fake receives no raw application payloads and no second dispatch for exact retries.
