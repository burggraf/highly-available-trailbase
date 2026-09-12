# Task 9L local authenticated requester

## Scope

Add a one-request client helper for the accepted local response contract. It connects to a supplied private Unix socket path, writes one authenticated `NodeActionCommand` frame, half-closes its write side, reads one bounded response frame, and returns the decoded action outcome/error. It performs no retry or fallback.

## Refusal rules

Invalid token/command, connect/write/read failure, malformed/truncated/oversized/trailing response, unknown response schema/result, and server transport refusal return bounded typed errors. The helper does not expose raw response detail or invoke any executor.

## Non-goals

No production call site, controller wiring, default/native executor, daemon/service unit, TCP/HTTP/TLS/mTLS, remote host, credentials, process control, TrailBase/Litestream, backup/restore, fencing, route publication, deployment, or disruptive action.
