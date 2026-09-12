# Task 9I persistent local Unix listener

## Scope

Add an explicit local lifecycle wrapper around the Task 9H Unix socket boundary. `LocalUnixListener::bind` owns one private mode-0700 parent path, `receive` accepts repeated bounded authenticated requests, and `shutdown` closes the listener and verifies/removes only the bound socket path. Tests exercise restart by shutting down and rebinding the same private path.

## Refusal rules

Invalid token, non-private parent, bind collision, missing/replaced/non-socket path, malformed or oversized/trailing frame, wrong token, invalid envelope, and invalid nested node command refuse. Socket identity (device/inode) is checked before cleanup; cleanup uncertainty is reported rather than deleting an unrelated path.

## Non-goals

No production call site, daemon/service unit, TCP/HTTP/TLS/mTLS, remote host, credentials/certificates, native executor, process, TrailBase/Litestream, backup/restore, fencing, route publication, deployment, or disruptive action.
