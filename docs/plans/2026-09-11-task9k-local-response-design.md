# Task 9K local response contract

## Scope

Add a bounded versioned response envelope for the accepted local listener/executor boundary. A validated command is executed by an injected `NodeExecutor`; the listener writes one strict response frame encoding `succeeded`, `failed_safe`, `uncertain`, or a bounded refusal. Tests use Unix sockets only and decode the response with the public codec.

## Refusal rules

Response schema/version/unknown/duplicate fields, oversized/truncated/trailing frames, and unknown result values refuse. Transport/authentication errors happen before executor invocation and produce no response. Executor errors map only to the bounded refusal class; no raw error detail is serialized.

## Non-goals

No production call site, default/native executor, controller wiring, daemon/service unit, TCP/HTTP/TLS/mTLS, remote host, credentials, process control, TrailBase/Litestream, backup/restore, fencing, route publication, deployment, or disruptive action.
