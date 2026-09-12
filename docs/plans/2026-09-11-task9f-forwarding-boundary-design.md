# Task 9F local node-forwarding boundary

## Scope

Connect the Task 9D controller action command to the Task 9E node envelope in memory. A validating adapter selects a supplied observation, converts the command, checks exact state, and calls an injected executor. This proves the controller-to-node binding without implementing transport or native execution.

## Non-goals

No TCP/HTTP/SSH transport, authentication, process control, TrailBase/Litestream access, backup/restore, fencing, route publication, remote forwarding, deployment, or disruptive action is included. The normal CLI remains on the unavailable adapter; the in-memory adapter is test-only.

## Test boundary

Use an in-memory recording executor. A valid command reaches it exactly once with the fully bound node envelope. Missing/unknown-generation/stale/identity-mismatched observations refuse before executor invocation. Executor outcomes continue to use the existing bounded action result contract.
