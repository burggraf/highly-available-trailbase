# Task 9J authenticated transport-to-executor boundary

## Scope

Connect the accepted Task 9I local listener to the existing injected `NodeExecutor` trait. One valid authenticated frame is decoded and passed exactly once to the injected executor; transport refusals happen before executor invocation, and bounded `ActionOutcome`/`ActionAdapterError` values are preserved. The listener lifecycle remains explicit and local.

## Refusal rules

Malformed, unauthenticated, oversized, stale/invalid nested, or cleanup-failed transport operations refuse before executor invocation. Executor refusal/uncertainty is returned unchanged. No command is retried or synthesized.

## Non-goals

No default/native executor, controller wiring, production call site, daemon/service unit, TCP/HTTP/TLS/mTLS, remote host, credentials, process control, TrailBase/Litestream, backup/restore, fencing, route publication, deployment, or disruptive action.
