# Task 9H ephemeral local Unix listener

## Scope

Exercise the Task 9G frame codec through one temporary Unix-domain socket request. The helper binds a caller-supplied socket path inside a private mode-0700 directory, accepts exactly one bounded frame, decodes/authenticates it, removes only the socket it created, and returns without waiting for peer half-close. Tests own the injected command and token.

## Refusal rules

Bind failure, non-private parent, I/O failure, truncated/oversized/trailing frames, wrong token, invalid envelope, and invalid nested node commands refuse. The listener reads the four-byte length and exactly that payload, caps allocation at the frame limit, then performs a nonblocking one-byte trailing check so a client that keeps its write side open cannot block completion. A pre-existing socket path is never removed or overwritten because bind happens before cleanup ownership is established; cleanup is confined to the private directory contract.

## Non-goals

No daemon, persistent listener, service lifecycle, TCP/HTTP/TLS/mTLS, remote host, credentials/certificates, native executor, process, TrailBase/Litestream, backup/restore, fencing, route publication, deployment, or disruptive action.
