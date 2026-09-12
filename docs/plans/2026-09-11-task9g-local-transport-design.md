# Task 9G local authenticated transport contract

## Scope

Define a bounded local frame around the validated Task 9E node command. A per-channel printable peer token authenticates the envelope, a versioned strict JSON wrapper carries the command wire JSON, and a four-byte big-endian length prefix bounds framing. Unix-socket pair tests exercise the real local byte boundary without opening a listener or contacting another process.

## Refusal rules

Reject invalid/short/oversized tokens, oversized or truncated frames, trailing bytes, duplicate or unknown envelope fields, unsupported schema, wrong peer token, and any node-command validation failure. Token comparison is length-independent and constant-time over the bounded input. The decoded command is still subject to Task 9E identity/digest/generation/role/admission checks by the node adapter.

## Non-goals

No persistent socket path, daemon/listener, TLS/mTLS, certificate or credential provisioning, remote host, process, TrailBase/Litestream, backup/restore, fencing, route publication, deployment, or native/disruptive action is included.
