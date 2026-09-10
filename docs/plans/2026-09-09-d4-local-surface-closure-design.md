# D4 Local Mutation-Surface Closure Design

**Status:** Proposed local-only experiment. No deployment, live service, remote resource, routing, recovery, or HA authorization.

## Goal

Determine whether, under one explicit local sandbox threat model, the declared capabilities of a fresh pinned TrailBase v0.33.11 fixture can expose only the already-qualified exact protected-state mutations:

- exact JSON `POST /api/records/v1/main_ops`;
- exact JSON `POST /api/records/v1/aux_ops`;
- exact JSON `POST /api/auth/v1/logout` for one refresh token.

This experiment qualifies exclusion feasibility, not additional mutation semantics. Unknown coverage is refusal.

## Why closure precedes another adapter

Pinned-source reconciliation at TrailBase tag `v0.33.11`, commit `f24291b894bb6c6696608e5f4c2f68666fe97686`, found 82 release-profile semantic routes (records 10, auth 31, admin 40, server 1), plus one debug-only `/api/whoami` declaration, scheduled jobs, manifest-defined WASM routes/jobs, embedding-defined custom routers, admin SQL/DDL/config/backup operations, direct filesystem/database capabilities, and secondary email/OAuth/object-store effects. Thirty-one built-in auth routes include mutating GETs and `DELETE /api/auth/v1/delete`, which deletes session rows and a user across separate databases without one transaction. The current D4 adapters validate only voluntary callers; they do not prevent bypass through TrailBase, admin, jobs, plugins, or direct writers.

Adding a login or account adapter now would enlarge nominal proof while leaving that dominant bypass intact.

## Protected-state boundary

Protected authoritative state is:

- `main.db` application and auth-user state;
- configured `aux.db` application state;
- `session.db` session, authorization-code, and OTP state;
- local object/config/migration/plugin files only when explicitly admitted by a future contract (none are admitted here).

The owner classified `logs.db` as **non-authoritative telemetry**. The pinned source census must show that no admission or protected-state decision reads it; runtime descriptor/SQL tracing must show that the fixture uses it only through the classified logging path. Its contents, availability, and TXID are never inputs to request policy, mutation proof, recovery release, or protected-state comparison. Log loss remains an explicit operational limitation. A protected mutation followed by logging failure remains uncertain unless the operation-specific adapter proves the protected result; telemetry never turns uncertainty into success. Any other logs-database reader or writer makes the fixture infeasible.

## Repository components

Keep the implementation under `experiments/d4/` and disconnected from `hat/`, deployment, and runtime imports.

1. `surface_manifest.json`: pinned machine-readable census. `routes` contains exactly the 82 release-profile upstream semantic route templates; `debug_only_routes` contains the separate `/api/whoami` declaration. Every upstream route has exact method, raw path template, handler, source anchor, conditional branch, authoritative effects, and secondary effects. All upstream templates default deny. `exact_allow_rules` separately contains the three HAT policy specializations and maps each to its upstream template/database; concrete `main_ops`/`aux_ops` paths are policy rules, not TrailBase route declarations. The manifest also has `listener_route_instances`, containing exactly the three `admin_auth_router` declarations duplicated on the independent admin listener; these are instance accounting and never change the semantic 82/83 counts. It lists built-in jobs, feature/config branches, WASM/custom-router registration points, listeners, and direct-writer capability classes. Duplicate entries, missing accounting, source-pin mismatch, or unaccounted entries fail. There is no workload `read` class; oracle reads use a separate fixture capability.
2. `surface_closure.py`: pure validation only. It accepts a bounded raw request plus an independently collected, content-addressed runtime attestation. It has no listener, forwarding client, subprocess call, or mutation. Only the three exact `exact_allow_rules` may return an operation/database binding, and each rule must reference a real upstream route template. Everything else refuses before an opener or adapter can run.
3. `test_surface_closure.py`: exhaustive manifest and policy tests. Tests derive denials from the manifest rather than maintaining a second hand-written endpoint list.

The census input graph is explicit: top-level release/debug server router assembly; every recursively merged/nested auth, OAuth, records, transaction, admin, admin-auth listener, WASM and custom router; all `cfg`/feature/config branches; job-registry construction; manifest-loaded routes/jobs; listener construction; and direct database/filesystem/provider bridges. Each source file is SHA-256 pinned. An independent reviewer reconciles every router constructor and merge edge to exactly one manifest entry. Each conditional arm records its runtime evidence as enabled or disabled. Empty plugin directories and use of the stock CLI rule out manifest and embedding custom routes only when independently observed. Any unresolved macro, generated route, compile feature, runtime registration, or graph edge is `runtime_unknown` and makes the result `infeasible`. OpenAPI and registration metadata may corroborate this graph but never establish completeness. No unclassified or potentially mutating route is probed in the qualification fixture. A route probe is permitted only after source review proves it has no authoritative or secondary effect; otherwise it runs, if needed at all, against a separate disposable copy with all DB/file/provider effects counted and discarded.

Reuse existing request validation and operation-specific adapters. Do not add a generic forwarding abstraction or production gate.

## Exact allow contract

An allowed request must match one of the three separately pinned `exact_allow_rules`, whose referenced upstream route template and condition are present in the census, and all of:

- exact ASCII method and byte-for-byte raw request target, with no query, fragment, percent escape, backslash, control byte, dot segment, duplicate slash, case variant, or trailing slash;
- case-insensitive header-name parsing with exactly one `Content-Type`, no duplicate/continued header, exact value bytes `application/json`, and no unclassified forwarding header;
- bounded UTF-8 JSON with no duplicate keys, non-finite numbers, invalid encoding, or trailing bytes, satisfying the existing exact operation schema; whitespace, object-key order, and equivalent JSON escapes retain the existing adapter semantics rather than creating a new serialization contract;
- regression acceptance of the exact request bytes retained from each prior successful native positive control;
- exact database binding (`main`, `aux`, or `session`);
- pinned TrailBase binary/source identity and fixture configuration generation;
- a complete, independently collected, content-addressed runtime attestation showing no unclassified route/job/plugin/listener/writer is enabled. Declarations are reconciliation inputs only, never proof.

Arrays, multipart/form bodies, file values, item update/delete, transaction APIs, all other auth routes, all admin operations, backup/restore, DDL/config/query, email/OAuth, object-store mutation, WASM/custom routes/jobs, and cross-database operations deny before any upstream call.

All non-control routes, including apparent reads, are denied to the workload. A GET is never presumed read-only by method. Reads needed for fixture setup or proof oracles use a separate private capability and receive source/runtime side-effect review; they are not admitted workload traffic.

## Local capability isolation

TrailBase supports Unix-domain socket addresses in the pinned source. A fresh private harness will bind main and independent admin listeners to separate UDS paths under a canonical `0700` root. No TrailBase TCP listener is permitted. Admin credentials and its UDS capability remain outside the workload boundary. After bind, independent checks require exact socket type, owner, mode, inode, parent ancestry and pathname; rename/replacement is tested as refusal.

Positive controls invoke the existing adapters through a private UDS HTTP opener. Repository closure code does not listen or proxy. The opener verifies macOS `LOCAL_PEERCRED` effective UID/groups against the launched service identity; an independent socket collector binds the listener inode/path to the exact TrailBase PID, ancestry, executable and argv before and during the connection. `LOCAL_PEERCRED` does not attest PID, so either check alone is insufficient. Inability to obtain both observations is `infeasible`.

A separately sandboxed untrusted process must be unable to connect to either UDS; read or write source/restored databases; write uploads, config, vault, migrations, backup, WASM, or plugin paths; or discover credentials/tokens. It starts via `exec` with stdin/stdout/stderr plus an explicitly enumerated descriptor allowlist only. The parent marks every other descriptor `FD_CLOEXEC`, then independently inspects the child's descriptors and ancestry. Tests deliberately offer inherited UDS and database descriptors and require launcher refusal before the child runs. Pathname denial alone is insufficient.

The sandbox may reach only a fixture-controlled refusal surface if one is needed for observation. Independent observations—not the fixture declaration—bind the result to binary/source/config hashes, sanitized exact environment, process argv/ancestry/tree, descriptor table, socket table, UDS peer credentials, registered jobs/plugins/routes, and writable paths. The pure validator receives a separate frozen manager-owned trust input for expected receipt nonce/digest, collector and fixture process identity, pinned artifact identities, service identity, window bounds, and condition resolutions; it never derives that input from the attestation. Content addressing alone establishes integrity, not independence. Task 5 must construct and verify the trust input from the manager and live observations; fixture-generated or merely self-consistent copies are infeasible. Every attestation item carries collector identity, timestamp, and source artifact hash. The validator rejects missing, extra, stale, self-reported-only, or unverifiable capabilities. If the host cannot enforce and inspect these denials, the result is `infeasible`; a loopback port, secret pathname, or voluntarily restricted process is not accepted as isolation.

## Fixture configuration and drift

The harness requires:

- signup, anonymous auth, OTP, OAuth providers, and record transactions disabled;
- no installed WASM component or custom router;
- every mutating scheduled/manual job absent or disabled during the measured window;
- separate inaccessible admin UDS;
- no alternate TrailBase, SQLite shell, migration tool, backup tool, or filesystem writer;
- exact private ownership, modes, non-symlink ancestry, process groups/trees, inherited/open descriptors, listeners, sockets, UDS peer credentials, and bounded logs;
- pinned binary, source, router-file, config, migration, plugin-directory, sandbox-profile, collector, and manifest hashes;
- launch under `env -i` with an exact environment allowlist; no ambient credential, socket, or descriptor inheritance.

Pinned-source verification proves one descriptor-bound snapshot: it enumerates and opens the complete expected source set through held descriptor-relative no-follow traversal, binds inventory entries to those retained descriptors/inodes, and hashes and reads only those descriptors. No later step consumes the mutable source pathnames; pathname state after the finite verification returns is not part of the proof. A capability declaration is a reconciliation input and is never trusted as evidence. Independent collectors capture argv/environment, process ancestry/tree, open descriptors, bound/connected sockets, path ownership/modes, writable-path probes, job/plugin listings, and side-effect-free registration/OpenAPI metadata after readiness and before each positive control. No route probe runs against the qualification fixture unless its lack of authoritative and secondary effects was established first; unknown routes fail closed rather than being probed. OpenAPI is corroborating evidence only. The source graph, independent runtime facts, configuration, registered jobs, plugin manifests, and observed listeners must agree. Any disagreement, collector blind spot, or unenumerated capability is `infeasible`.

## Qualification sequence

1. Preserve a missing-manifest/policy red.
2. Build the complete pinned census using the defined source input graph. Preserve a completeness red for the previously omitted account deletion. A reviewer independently reconciles every router constructor, recursive merge/nest edge, conditional arm, job registration and dynamic registration point against the manifest.
3. Implement pure fail-closed manifest, attestation and canonical raw-target/header validation with exhaustive manifest-derived tests, including alternate path encodings, duplicate/case-varied headers, duplicate JSON keys, invalid/non-finite/trailing JSON, exact prior positive-control request bytes, source/runtime disagreement and stale/missing collector evidence.
4. Independently review source, config, jobs, dynamic-route declarations, UDS isolation, sandbox profile, secret boundaries, and lifecycle checks before native execution.
5. In one fresh fixture, run every denied mutation route/body class through a counting boundary and require zero upstream calls. Use only the three exact qualified operations as positive controls.
6. Prove the sandboxed process cannot bypass the boundary or mutate protected paths. Verify no TCP/admin capability is exposed.
7. Verify telemetry independence, operation-specific proof, duplicate refusal, malformed proof refusal, and complete process/listener/socket/sandbox cleanup.
8. Preserve immutable sanitized failure evidence. Raw failed roots are quarantined separately under canonical owner-only `0700` ancestry with `0600` regular files, no links, a bounded 256 MiB/file-count manifest, access log, content hashes, and no reviewer access. New writes stop at terminal collection. The v1 pure validator accepts only the initial `pending` disposition because its exact manifest has no owner-authorization record; terminal retention or destruction remains refused until a separately reviewed, externally content-addressed owner-record contract exists. It validates a pre/post-stable descriptor snapshot rooted at an owner-only parent and returns immutable root/file inode evidence for Task 5 to bind to terminal collection; it does not claim future filesystem immutability. The retention disposition is recorded at the D4 integration checkpoint: continued encrypted/offline quarantine or explicit owner-authorized destruction; nothing is silently deleted. Review artifacts are independently scanned to exclude credentials, tokens, cookies, sensitive payloads, databases, WAL pages, raw bodies and raw logs. Reruns use fresh state only after diagnosis and review.
9. Obtain sanitized independent evidence review before recording any result.

## Success criteria

Success establishes only that independently observed capabilities of one fresh pinned fixture, under the tested macOS sandbox and descriptor threat model, allowed the three existing exact controls and denied the enumerated alternatives. It is not system-wide or deployed closure. It requires:

- complete pinned source/runtime graph and independently collected attestation with no `runtime_unknown`, missing, extra, stale, self-reported-only, or unverifiable capability;
- every omitted mutation denied with zero upstream calls;
- all three positive controls retaining their existing proof-before-release behavior;
- no direct main/admin/socket/filesystem/database bypass by the sandboxed identity;
- logs excluded from every protected-state decision and proof;
- no residual process, group, listener, socket, sandbox, secret, or writable fixture path.

A failed isolation check is a useful `infeasible` result and must not be replaced by a simulated success.

## Non-claims and stop boundaries

This does not establish protection against an arbitrary unsandboxed process already running as the fixture owner, remote durability, complete acknowledged-write preservation, response-loss settlement, client receipt, provider guarantees, global atomicity, authentication completeness, production admission, HA, automatic recovery, deployment safety, or permission to install a gate.

Stop on any uncatalogued route, enabled dynamic route/job, secondary listener, direct writer, denied upstream call, file/provider effect, source/runtime disagreement, or sandbox escape. Do not proceed to login or another per-endpoint proof while closure is red. Do not build a reduced TrailBase fork unless a separately reviewed infeasibility result shows the stock binary cannot close the local surface.
