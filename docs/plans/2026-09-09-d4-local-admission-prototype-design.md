# D4 bounded local write-admission prototype

Status: owner-approved **local prototype only**. It is not a deployable HAT component, distributed authority, durability proof service, proxy configuration or rollout authorization.

## Purpose

Test the failure-ordering contract at the narrowest real seam without inventing automatic recovery:

1. reject unsupported mutations before forwarding;
2. durably record one request intent;
3. forward that request exactly once;
4. if upstream reports possible/actual mutation, durably retain uncertainty until a separately supplied proof result is validated;
5. expose upstream success only after valid bound proof;
6. never retry or reopen a used operation identity.

The prototype cannot prove that a supplied proof is true. Its tests use fixtures; native qualification remains separate. It demonstrates local sequencing and refusal only.

## Placement and API

Add `experiments/d4/admission.py` and `experiments/d4/test_admission.py`. Do not import it from `hat/`, install it, add a daemon/service, or change HAProxy. Standard library only.

`AdmissionJournal(root)` owns a private SQLite journal under an exclusive nonblocking `flock`, records request identity, exact request digest, classified surface, status, upstream outcome metadata and proof metadata using SQLite rollback journaling with `synchronous=EXTRA`. This is SQLite-configured local durability under the host/filesystem contract, not independent power-loss/filesystem qualification. Existing files must be private, singly linked and schema-recognized. One operation ID is permanently single-use, including malformed replay attempts.

`admit(journal, request, forward, prove)` is a synchronous protocol kernel. `request` contains exact method/path/body bytes, allowlisted headers (including transient authorization/cookie secrets), operation ID, deployment epoch and writer boot. `forward(request)` and `prove(requirement)` are caller callbacks; the experiment itself has no sockets, subprocesses, credentials or endpoint configuration.

Supported mutation classes are deliberately fixed:

| Method/path | Required recovered DB proof |
|---|---|
| `POST /api/records/v1/main_ops` | `main` |
| `POST /api/records/v1/aux_ops` | `aux` |
| `POST /api/auth/v1/login` | `session` |
| `POST /api/auth/v1/logout` | `session` |
| `POST /api/auth/v1/refresh` | `session` (conservative even though reviewed handler is read-only) |

No item paths, update/delete, register, admin/configuration, uploads, transactions, jobs, query strings or alternate spellings. Reads are outside this prototype, not implicitly authorized.

## State and outcomes

Before calling `forward`, insert and commit `intent`. Request bodies and authorization/cookie values are never stored; only SHA-256 and an allowlisted non-secret content type are retained. The operation ID is 32 lowercase hex and the epoch/boot are strict bounded identifiers.

`forward` returns `{status, response_body, mutation}` where `mutation` is `possible` or `completed`. A return or exception is not retried. The caller cannot assert that a forwarded request made no mutation: even a 4xx can follow an upstream effect.

- exceptions, malformed outcomes and any attempted `mutation: none` classification leave `forward_uncertain`;
- every recognized forwarded outcome requires proof, including upstream errors after possible mutation;
- malformed/failed proof leaves `proof_uncertain` and returns a fixed refusal, never the upstream status/body;
- pre-forward request/surface validation may refuse locally, but there is no post-forward proof bypass for a claimed rejection.

A valid proof must exactly bind operation ID, request digest, epoch, writer boot and required DB; report integer local/replica TXID equality greater than zero; report independently verified image membership; and carry a bounded opaque evidence ID. The journal records only bounded metadata, never proof artifacts or secrets. Once valid proof is committed, and only then, the original upstream status/body may be released. A proof callback exception after any forwarded request remains uncertain.

The caller receives a `Decision` with `released`, `status`, `body`, `reason`. Refusals use fixed bodies/reasons. A callback may have completed after timeout; all callback exceptions are uncertain, never negative/cancelled proof.

## Acceptance

Tests must first fail because the module is absent, then cover:

- exact fixed surface and malformed request rejection before journal/callback effects;
- durable intent observable inside `forward`;
- one forward and one proof on success, with proof committed before release;
- missing/mismatched/stale/malformed proof and proof exception with no success/body disclosure;
- upstream exception and possible-mutation error remain uncertain;
- caller-asserted non-mutation and 4xx-without-proof remain uncertain;
- duplicate same/different payload operation IDs refuse without callbacks and preserve rows;
- process death after durable intent leaves permanent pending uncertainty;
- database/root replacement and second-lock authority refusal;
- bodies and secret headers absent from SQLite/error/decision output;
- audit-hook negative controls showing no network/subprocess/file path dereference beyond the journal root.

These tests do not qualify a proof producer, TrailBase/Litestream integration, distributed owner, remote durability, client receipt, or live admission. A passing prototype is still non-deployable.
