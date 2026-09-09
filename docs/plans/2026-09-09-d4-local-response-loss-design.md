# D4 local response-loss qualification design

## Status and scope

Owner-approved on 2026-09-09 for implementation and one bounded local execution. This slice adds temporary fixture-only loopback HTTP and private Unix-socket relays. It does not add a production listener, proxy, recovery action, deployment path or runtime import.

The goal is to demonstrate that the unchanged local native adapter fails closed when an effect completes but its response is not received. Timeout remains uncertainty, never evidence of cancellation or absence. All cases use fresh private local state and pinned TrailBase/Litestream binaries; completed fixture state is never reused.

Excluded: VPS/live data, remote backends, paid resources, authentication proof, HAProxy changes, automatic recovery, distributed authority, policy relaxation, complete ACK semantics, global cross-database atomicity and production qualification.

## Approach

Use real fixture relays rather than injected callback exceptions:

1. A loopback HTTP relay forwards one exact TrailBase request, observes the upstream response complete, then sends zero response bytes to the adapter until its five-second receipt deadline. This exercises the adapter's real HTTP boundary.
2. A private Unix-socket relay forwards one Litestream sync request, observes the native HTTP 200/JSON completion, then sends zero response bytes to the CLI until Litestream's ten-second sync deadline. This exercises the adapter's real native command boundary.

Each relay must pass a separate control before its fault case, count requests, record monotonic chronology and bind the retained upstream result to the operation/database. Relays are single-purpose harness code under a private evidence root, not repository or deployable components.

## Cases and expected state

Run four isolated cases: HTTP response loss for main and aux, then sync response loss for main and aux.

For HTTP response loss, TrailBase must contain the exact inserted ID/op_key/payload, while `admit_native()` raises and the reopened journal remains `forward_uncertain`. No sync, restore or proof command may be emitted.

For sync response loss, TrailBase's response reaches the adapter and native sync completes upstream, but the CLI receives no response. `admit_native()` raises and the reopened journal remains `proof_uncertain`. No adapter restore, `proof.json` or released body may exist.

A deliberate second call with the same operation ID must refuse before forwarding or native effects. Counters must remain unchanged. This is a refusal check, not permission to replay the mutation.

## Independent evidence

After the uncertain decision is fixed:

- HTTP-loss cases inspect the source database with exact `SELECT op_key,payload FROM hat_ops WHERE id=?`. Any diagnostic sync/restore is separately labelled and cannot become admission proof.
- Sync-loss cases restore the exact upstream-reported TXID without another sync and run the same membership predicate.
- A preserved stale image must fail that exact predicate. Record SQL, parameter, expected row, observed row, image hash, integrity result and foreign-key result.
- Later evidence must not modify the journal or authorize release, retry or reconciliation.

Sanitized review artifacts contain no credentials, tokens, request payload secrets, raw databases or journals. Private evidence may retain those where structurally necessary and must remain outside Git.

## Lifecycle and failure policy

Use owned `0700` roots; owner-only regular single-link binary/config/database files; fresh replica targets; bounded relay threads, child process groups, output and deadlines. Verify leaders are reaped, groups and relay threads disappear, sockets are removed and no forced kill was needed unless recorded. Process exit alone is insufficient.

Preserve every unsuccessful attempt with terminal state and diagnosis. Do not automatically retry a whole run. Native execution requires passing unit/regression tests and independent static review of the harness first. Qualification recording/local integration requires a separate sanitized evidence review.

Success establishes only bounded local response-loss refusal and exact operation membership under these fixtures. It does not establish remote durability, cancellation, full client receipt semantics, authentication, HA or deployment safety.
