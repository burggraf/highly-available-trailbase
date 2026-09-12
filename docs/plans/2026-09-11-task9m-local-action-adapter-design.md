# Task 9M local action-adapter client

## Scope

Add a library/test-only `LocalActionAdapter` implementing the existing `ActionAdapter` contract over the accepted local requester. It derives a validated `NodeActionCommand` from each `ActionCommand` using an injected incarnation, sends one authenticated request, and preserves success/failure/uncertainty semantics. It is not wired into the normal controller, which remains unavailable-adapter.

## Refusal rules

Invalid adapter token/incarnation or invalid action identity refuses before transport. A valid response preserves its bounded outcome/error. Any post-command transport uncertainty maps to `ActionAdapterError::Uncertain` rather than claiming refusal or success. No retry or fallback occurs.

## Non-goals

No normal-server wiring, default/native executor, production call site, daemon/service unit, TCP/HTTP/TLS/mTLS, remote host, credentials, process control, TrailBase/Litestream, backup/restore, fencing, route publication, deployment, or disruptive action.
