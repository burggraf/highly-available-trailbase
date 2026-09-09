# D4 local native proof-adapter design — approval required

Status: **fresh local harness approved by the owner; implementation remains local-only**. The owner-approved protocol kernel at `experiments/d4/admission.py` intentionally has fixture callbacks and no I/O. Its stop boundary forbids a native proof producer without a separately reviewed design and explicit approval. This document does not authorize a listener, deployment or live write interception.

## Options

1. **Recommended: fresh local harness adapter.** Implement only under `experiments/d4/`. A bounded harness starts new loopback TrailBase/Litestream fixtures, passes one request through the protocol kernel, and uses real native sync/finite restore plus application- or database-level membership checks to produce a proof. No incoming HTTP listener and no reusable daemon/service configuration.
2. **Keep fixture callbacks only.** Lowest risk and already delivered, but does not test the kernel against native I/O or the response-loss boundaries observed separately.
3. **Build an actual proxy/listener.** Closest to a future gate but premature: distributed authority, remote durability, complete mutation coverage and safe client semantics remain unresolved. Not recommended or authorized.

## Recommended bounded adapter

The adapter is an experiment, not a reusable backend abstraction. It accepts only paths already fixed by the kernel and only a generated local fixture identity. All URLs must resolve to loopback; all database, socket, depot, journal and evidence paths must be descendants of a new private run root. Binaries are exact hash-pinned local files. Environment variables are allowlisted so no production/cloud credentials are inherited.

`forward(request)` performs exactly one loopback request and captures status/body privately. It must classify every returned outcome as `completed` or `possible`; it cannot claim non-mutation. Transport error after submission raises and leaves `forward_uncertain`. It never retries.

`prove(requirement)` is closure-bound to that exact forwarded request/outcome. It invokes native Litestream `sync -wait -json` once for the kernel-selected database, requires exact path and positive local/replica TXID equality, then restores that exact TXID into a new immutable evidence area. Sync timeout/error is proof uncertainty, even if later inspection finds an upload. No automatic retry.

Implementation is staged. The first executable slice supports only main/aux create and refuses auth paths before kernel forwarding; no auth path may inherit the kernel's broader classification merely because it is listed there. Later auth integration requires its native-oracle proof and separate review.

Membership checks are operation-specific and occur only on the restored copy:

- main/aux create: query exact returned ID, operation key and payload from the selected restored DB; generic SQLite structural/foreign-key checks may ignore TrailBase custom CHECK functions and must say so;
- login: run a native oracle on a writable copy of restored main/session/support state and require the returned refresh token to be accepted;
- logout: require the submitted refresh token to be denied by the restored oracle;
- refresh: conservatively sync session and require the submitted retained refresh token remains accepted; reviewed source says this handler does not write SQLite, but the experiment does not generalize that to all request side effects.

Transient tokens, passwords, cookies and response bodies remain only in private run artifacts/memory. The protocol journal stores hashes and bounded evidence metadata only. Sanitized review packets exclude secrets, keys, binaries and databases.

A valid adapter proof still means only: in this local fixture, the exact selected restored database/application check passed at the returned file-replica TXID. It does not authenticate remote storage, provide controller-independent publication, bind a distributed lease/owner, prove global cross-database atomicity or establish all admitted mutation paths.

## Failure checks

Before any positive release claim:

1. A stale restored image must fail the same operation membership predicate.
2. A proof with wrong operation/digest/epoch/boot/database/TXID must be refused by the existing kernel.
3. Upstream success with response withheld must leave `forward_uncertain` and no released body; later native state may contain the effect and must not cause automatic replay.
4. Native sync success with its response withheld must leave `proof_uncertain`; a later restored image may prove the effect, but the operation remains single-use without a separately designed reconciliation.
5. An unsupported path, item update/delete, register/admin path and query string must never reach `forward`.
6. Every process/thread must be identified, bounded, stopped and reaped. Timeout records partial output and uncertain completion; no whole-run retry.

## Exit and stop boundaries

Passing this harness would connect two already-tested local concepts: protocol ordering and native local-file recoverability. It would not authorize installation, HAProxy changes, a production listener, automatic recovery, external fencing, remote object-store claims or policy relaxation. Do not run it against A/B/C data or credentials.

After review, implementation requires explicit owner approval because it adds real loopback forwarding and native proof subprocesses beyond the existing kernel's stop boundary. A later production-facing design would still require a separate architecture decision for distributed authority, remote proof publication, supported workload enforcement and client timeout/reconciliation semantics.
