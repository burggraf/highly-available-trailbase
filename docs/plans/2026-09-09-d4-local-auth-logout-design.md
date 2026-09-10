# D4 local auth logout proof design

Status: **proposal; explicit owner approval required before implementation or native execution.**

## Decision and scope

The smallest safety-relevant auth slice is exact JSON `POST /api/auth/v1/logout` for one refresh token. Logout deletes a row from TrailBase's separate session database. Restoring an older session image can re-enable a revoked refresh token, so a post-image absence check alone is not evidence: an image from before the login also lacks that token.

This slice therefore proves a bound **presence-to-absence transition**. It does not add login, refresh, cookie/GET logout, account deletion, registration, MFA, OAuth, admin session invalidation or any other auth surface. `refresh` is read-only in pinned TrailBase source, while login mints a session and remains a later positive-membership slice. Unsupported paths refuse before journal intent or forwarding.

Alternatives:
1. **Recommended — predecessor/post transition adapter.** Require a pre-forward exact-TXID session image containing the request token, then a newer post-forward exact-TXID image lacking it. This closes the stale-absence ambiguity with the least new mechanism.
2. Post-image absence only. Reject: a pre-login stale image passes.
3. Native oracle only. Useful compatibility evidence, but it would not connect proof ordering to the admission kernel.

## Adapter flow

Add a separate experimental `AuthLogoutAdapter`, disconnected from `hat/` and deployment. Reuse the native adapter's private path, binary, command, restored-image and process-group machinery through the smallest reviewed refactor; do not duplicate it or broaden the existing main/aux policy.

After the kernel durably commits intent, `forward()`:

1. strictly parses a body containing only an 86-character alphanumeric `refresh_token` and allows no query/cookie variant;
2. performs one bounded `sync -wait -json` for the session database;
3. restores that exact predecessor TXID and verifies generic integrity/foreign keys plus exactly one non-expired `_session` row for the token;
4. forwards the original logout request exactly once;
5. retains the response and predecessor binding only in memory.

Any preflight failure is conservatively `forward_uncertain`, even though forwarding may not have begun. No retry follows.

`prove()` consumes the forward context once, repeats full operation/request/epoch/boot/database binding, performs one post-forward session sync and one exact-TXID restore, and requires:

- post TXID and replica TXID equal and strictly greater than predecessor TXID;
- the exact request token absent from `_session`;
- predecessor and post image identities/hashes retained privately;
- proof metadata contains only operation binding, predecessor/post TXIDs and image hashes—never the token, body, credentials or response.

Only then may the kernel release TrailBase's exact HTTP 200 response. Any HTTP, sync, restore, structure or membership uncertainty remains unreleased and permanently single-use.

## Tests and native oracle

Unit tests first cover strict surface/body refusal, durable intent before predecessor capture, token presence requirement before forwarding, exactly one HTTP send, positive TXID progression, post absence, stale pre-login composite-predicate refusal, response/proof uncertainty, permanent duplicate refusal, binding mutation, file identity/output bounds and secret non-persistence. Existing main/aux adapter, protocol and runtime tests must remain unchanged.

One separately reviewed fresh private local harness then:

1. starts pinned TrailBase and Litestream on loopback/private Unix socket with main/session/aux local-file replicas;
2. creates a login session outside the claimed adapter operation and captures a pre-login stale image;
3. submits one logout through the kernel/adapter and requires proof before HTTP 200 release;
4. preserves predecessor/post images and verifies the composite SQL transition;
5. starts sequential loopback TrailBase oracles on copies, using the same pinned config/secrets and unchanged main/aux images: predecessor refresh returns 200; post-logout refresh returns 401; pre-login image demonstrates why absence alone is insufficient;
6. checks malformed bindings without replay, scans metadata for secrets, and stops/reaps every process/group/listener/socket with bounded logs and deadlines.

The native oracle validates the tested semantic mapping for pinned TrailBase; it is not invoked by the adapter and is not a production dependency.

## Interpretation and exclusions

Passing would establish only local, nominal, single-token POST logout sequencing and recoverable session revocation under pinned fixtures. It would not establish login durability, all-session GET logout, refresh/access-token invalidation, immediate invalidation of already-issued JWTs, every auth/account/admin mutation, concurrency, remote durability, response-loss settlement for this specialized preflight flow, distributed authority, HA, deployment safety or permission to install a gate.

No VPS/live data, paid resources, remote storage, production listener/proxy, HAProxy/systemd change, automatic recovery, push or rollout. Private credentials, tokens, session images, databases and raw logs remain outside Git. Failed attempts are preserved; no whole-run retry without separate approval.
