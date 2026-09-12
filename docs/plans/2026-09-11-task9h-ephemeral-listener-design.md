# Task 9H ephemeral local Unix listener

## Scope

Exercise the Task 9G frame codec through one temporary Unix-domain socket request. The helper binds a caller-supplied temporary path, accepts exactly one bounded frame, decodes/authenticates it, removes only the socket it created, and returns. Tests own the injected command and token.

## Refusal rules

Bind failure, I/O failure, truncated/oversized/trailing frames, wrong token, invalid envelope, and invalid nested node commands refuse. The read loop caps bytes before allocation can grow beyond the frame limit. A pre-existing socket path is never removed or overwritten because bind happens before cleanup ownership is established.

## Non-goals

No daemon, persistent listener, service lifecycle, TCP/HTTP/TLS/mTLS, remote host, credentials/certificates, native executor, process, TrailBase/Litestream, backup/restore, fencing, route publication, deployment, or disruptive action.
