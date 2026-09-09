# D4 acknowledgement boundary — decision packet, not implementation approval

Status: **design-only; no write-path changes authorized by this document**. Builds on the approved strict policy in the [D4 proposal](2026-09-09-d4-design-proposal.md). The installed explicit-loss guard remains useful but does not close the proof gaps below.

## Established facts

- `hat/client.py::produce()` durably records submission, receives/classifies an HTTP response, then durably records its outcome. A hard failure between response receipt and outcome persistence can leave an acknowledgement without a durable outcome. This producer also does not intercept arbitrary clients.
- `deploy/haproxy.cfg` admits collection/item paths without method restriction and admits login/logout/refresh. The proposal excludes unqualified update/delete semantics, but the current ingress does not enforce that proposed exclusion. No restriction has been installed.
- `hat/recovery.py::_protected_ledger()` validates supplied examples, not completeness of the deployed mutation surface. The installed `_fault_outcomes()` guard rejects reported loss; it cannot detect an omitted mutation or independently establish the semantics of a mislabeled classification.
- The existing finite restore/signature/oracle pipeline supplies bounded image evidence. Neither a recent backup time nor an asynchronously observed Litestream position binds an arbitrary HTTP response to a preserved native commit.

## Recommendation and alternatives

**Recommended next scope: contract feasibility for a bounded workload, before implementing a write gate.** Determine whether pinned native capabilities can bind every supported mutation's success to independently recoverable state. Preserve refusal whenever that binding is missing. Do not build a generic HTTP acknowledgement logger and call it durability.

| Approach | What it could establish | Cost / limitation |
|---|---|---|
| Bounded workload plus qualified acknowledgement/durability binding | Automatic recovery only when the exact protected set is recoverable and every other D4 gate passes | Requires an enforced mutation inventory and a native commit/image proof, not currently established. Async backup lag can still require refusal. |
| Change to a natively synchronous durability architecture | Could make successful writes survive an agreed replica-failure model without reconstructing HTTP semantics | Requires a separate platform/product decision, migration and failure qualification. No specific replacement is selected or claimed compatible. |
| Retain manual recovery and offline refusal | Keeps the currently demonstrated service and narrow installed loss guard | Does not deliver active-write automatic recovery or remove C's dependencies. |

The already-approved known-protected-boundary path is still valid in principle: all mutation admission must be closed, in-flight work settled, native mutators stopped, and the independently recovered image proven complete. That proof ceases to cover the service when any unaccounted mutation becomes possible. A stopped load generator alone does not establish closure. This is not a newly implemented certificate or admission API.

## Required ordering, not a proposed API

For an active-write acknowledgement mechanism to count as proof, the following obligations must hold for **every supported mutation path**, including security state:

1. Admission is enforceably inside the qualified boundary. Direct node access, privileged tools, admin/configuration changes, jobs and auth side effects are either covered or explicitly prevented during the qualified operating mode.
2. The application's actual success semantics and affected native state are known. A response status, user-supplied operation key, row count or response-body hash alone is not a database commit proof.
3. Before success is exposed through that boundary, the required evidence and corresponding recoverable state meet the selected failure model. If the design only retains complete ACK evidence while replication remains asynchronous, it must refuse recovery whenever the selected image lacks that protected state; it must not promise every active-write crash will recover.
4. Evidence is available without C and is bound to the deployment, writer incarnation and native backup generation/epoch. Cross-epoch TXIDs are never ordered. Quorum availability of an evidence record does not imply availability or completeness of the database image.
5. Recovery independently validates the selected image against that evidence. Auth revocation, deletion and ordering must be proven with qualified native semantics, not guessed from HTTP bodies or absent rows.

An evidence-before-response design can conservatively protect operations whose responses never reached the client. That is a safe superset, not proof of client receipt. A committed action with an unknown outcome must not be blindly retried. No home-grown replay log is proposed.

## Mutation inventory to settle

| Surface | Current evidence | Required feasibility result |
|---|---|---|
| Main/aux record creation | Bounded generated POSTs and supplied protected records | Complete admitted-client coverage and a native commit-to-image binding |
| Record update/delete | Routes permit them; historical tests demonstrate support | Either qualify ordering/identity/tombstone semantics or explicitly restrict them in the chosen workload |
| Login/logout/refresh and revocation | Historical auth cases, not a complete stream; pinned-source refresh path reads session/user state and returns a token without a SQLite write in that handler | Native session-state effects, acknowledgement timing and rollback-safe recovery proof; do not infer the entire request has no background/logging effects |
| Account/access/admin/configuration | Not covered by the fault producer | Enumerate actual reachable privileged paths; enforce coverage or exclusion |
| Background and apparently read-only operations | No complete mutation inventory established | Pinned source/installed-contract evidence of side effects and enforceable closure |
| Direct/private access and controller loss | C-centric ingress/evidence today | No bypass and controller-independent evidence/admission prerequisites |

## Feasibility exit criteria

The next investigation should produce a source-bound yes/no answer for the pinned TrailBase/Litestream contract, not a successful fake gate:

- Is there a supported way to bind each relevant native commit to a recoverable image before acknowledging, or to prove its inclusion later from complete durable evidence?
- Which mutation classes and concurrent/background paths can that mechanism actually cover?
- Can supported configuration enforce the selected surface without breaking required auth behavior or leaving an administrative bypass?
- Which obligations require upstream changes or a different storage architecture?

If the answer depends on an unimplemented native hook or incomplete semantic reconstruction, return that architectural cost to the owner before building it. A positive feasibility answer still does not settle provider late effects, distributed action admission, ingress authority, sizing, or rollout approval.

## Pinned-source feasibility findings

Public tag references were resolved and checked before downloading inert source archives:

- TrailBase `v0.33.11`: commit `f24291b894bb6c6696608e5f4c2f68666fe97686`, archive SHA-256 `78f694531b28e6f8eb7f600a6c4c63f37437b5e965a1a0a357c19dd5780fd852`.
- Litestream `v0.5.17`: commit `ccd326c175b583b5e82893a6078f06dcef5fba3f`, archive SHA-256 `cbfb487c66690679234ec46e28d03a2de60b795b7b4466f3444755fc4d39e7d8`.

Static reviews `869b7852-96bd-47c1-bfde-d3475da59082` and `b5f784a6-e594-4f98-88dc-b44c095a8e1c` ran under parent workflow `4593ef26-9fb8-4b5f-8db9-7681e483ae39`. They did not execute the source or reproduce deployed behavior. Release-tag source is not proof of an exact deployed binary build. Archives and manifests are retained privately under `~/.config/hat/d4-qualification/ack-contract-cd0d3e624e56/`.

**TrailBase supplies local completion ordering, not an external durability receipt.** Reviewed record handlers await writer results; explicit batches commit a same-database transaction. Login/session insertion and logout/session deletion are awaited; the reviewed refresh handler reads state and returns a token. Responses do not expose a native backup/commit identity. File cleanup can fail after a database mutation, so an HTTP error need not mean no mutation. Separate database connections and admin/background paths still require coverage. See pinned [write helpers](https://github.com/trailbaseio/trailbase/blob/f24291b894bb6c6696608e5f4c2f68666fe97686/crates/core/src/records/write_queries.rs) and [token handling](https://github.com/trailbaseio/trailbase/blob/f24291b894bb6c6696608e5f4c2f68666fe97686/crates/core/src/auth/tokens.rs).

**Litestream has a real candidate mechanism, not merely a proposed hook.** [`DB.SyncAndWait`](https://github.com/benbjohnson/litestream/blob/ccd326c175b583b5e82893a6078f06dcef5fba3f/db.go#L714-L728) calls local sync and then replica sync, propagating errors. The supported [`sync -wait` CLI](https://github.com/benbjohnson/litestream/blob/ccd326c175b583b5e82893a6078f06dcef5fba3f/cmd/litestream/sync.go) invokes the Unix control socket. This is worth native qualification before proposing a custom hook or storage replacement.

It is not yet an HA acknowledgement: [`Store.SyncDB`](https://github.com/benbjohnson/litestream/blob/ccd326c175b583b5e82893a6078f06dcef5fba3f/store.go#L428-L469) reads the local TXID after synchronization and separately reads cached replica position. Concurrent progress can make these differ; the response has no HAT epoch/incarnation binding or caller-specific commit identity. Backend upload completion is not independent read-back or restored-image verification. Timeout/error may follow partial or complete upload and therefore leaves outcome uncertain. HAT epoch/prefix isolation must not be confused with legacy Litestream generation fields.

### First native local-file result

Run `native-sync-a7101a149c22` used the official Darwin arm64 Litestream 0.5.17 binary, archive checksum verified; binary SHA-256 `205b4c315d61a7f5709c4ab9001084eadfa8c9d36e1c198f9887417c2d88bb73`. A fresh SQLite WAL/FULL toy database and private Unix socket were used, with no VPS/cloud access.

Baseline sync and finite restore were at TXID 1. After a known marker commit, native `sync -wait` returned local/replica TXID 2; a separate finite restore at 2 contained both expected rows and passed native full plus independent SQLite integrity checks. The pre-mutation restored image failed **the checker's membership predicate**, not a native recovery gate. An unavailable socket refused; a no-change request stayed at 2. Image checks completed while the exact identified daemon was running, before shutdown; SIGTERM then exited 0 and was reaped without forced kill. A separate post-run image/hash/integrity read also passed. All files and logs remain private under the run directory.

Static review `5b04d2d3-671a-4b89-bc37-2c21dc8c88e6` accepted this bounded result. Background replication was configured and **not excluded**. This does not prove an HTTP acknowledgement boundary, remote durability, concurrency, multi-database/auth coverage or HA. The smallest next negative check is a fresh local file replica with writes denied: observe native sync failure and independently inspect available recovery state, without inferring remote-backend or partial-upload semantics.

### Native local upload-denial result

Fresh run `native-sync-denied-3c18c61b658c` used the same verified binary and a separate local file replica. After baseline replication, every replica directory/file was made non-writable; an unprivileged write probe independently refused before a new marker was committed. Native `sync -wait` then returned nonzero with `.ltx.tmp: permission denied`. Replica inventory/hashes were unchanged, and a restore of the **latest available** replica—not merely an explicitly selected old cut—contained only the baseline. Its absent marker failed the checker's membership predicate.

Permissions stayed blocked through daemon shutdown. The daemon exited 0 and was reaped without forced kill, **while logging a failed database-close sync due to permission denial**. Exit code 0 is therefore not a replication-completion proof. Permissions were restored only after exit; separate source/restore/inventory/permission checks confirmed the source retained the new marker, the replica did not, and original modes were restored. All evidence remains under the private run directory. Static review `85f59283-77f5-4e19-b122-2441bc4d37c9` accepted these limited findings.

This is local upload-permission failure, not remote-backend or partial-upload/cancellation behavior. The next bounded local check will distinguish native upstream sync completion from client response receipt by withholding a captured success response after a pass-through relay control. It will not implement a HAT write gate.

### Native client-response-loss result

Fresh run `native-sync-lost-4cb6557c0a0e` used a fixture-only Unix-socket relay and the same pinned local file backend. A pass-through control returned the actual native JSON body to the CLI successfully (semantic forwarding, not byte-for-byte HTTP headers). After a SQLite marker commit, native `/sync` returned HTTP 200, `synced`, local/replica TXID 2. The relay retained that upstream response but sent zero bytes downstream until the CLI returned an awaiting-headers deadline error with exit 1. Monotonic timestamps establish commit → acceptance → upstream completion → withholding → CLI return → release.

The observed `1.0300145s` is elapsed time around the command wrapper, not separately instrumented child runtime or an RTO. A finite restore at the upstream-returned TXID 2 contained the marker and passed integrity before daemon shutdown. Both relay threads stopped; the daemon exited 0 on SIGTERM and was reaped without forced kill. A separate image/hash/chronology audit passed. Static review `7de4725e-0fc4-4ae4-b373-61f9b16b8292` accepted the bounded evidence; it did not reproduce the binary or image checks.

This is **client response-receipt timeout after native server completion**, not server continuation after cancellation. SQLite committed the mutation before sync; sync replicated it. It is one counterexample to timeout-implies-no-effect, not a guarantee that timeouts always commit. It proves neither remote durability nor restart/crash behavior. The relay is not an ACK gate or durable receipt/reconciliation mechanism. Raw source, responses, images and terminal evidence remain in the private run directory.

The next useful local evidence step is pinned TrailBase data plus logout/refresh finite restore. Additional component passes still cannot remove ambiguous outcomes or authorize a production write gate.

### Native TrailBase data/session compatibility result

Fresh local run `trail-sync-50635c41656a` used the official Darwin arm64 TrailBase archive digest `dea7a7e865f14405c3e09785a680c6830b1084bfd9785e7d44fc72b6a3583f91`, binary SHA-256 `88e64c0b207a4501b7074525a7f533d9b8a8e2aef1780cfeb5b45791e70a0f34`, and the pinned Litestream binary above. TrailBase reported `v0.33.11-0-gf24291b8`, SQLite `3.53.2`. Preparation first failed because the version parser selected the trailing SQLite version. The failed parser/output were retained; a corrected anchored parser passed the captured output and four negative cases, then native version was reconfirmed before any server start. No redownload or bootstrap replay was used to hide that failure.

Two generated local-admin sessions existed in the initial three-database image. After main/aux record creation and specific logout, sequential native sync/finite restore advanced this fresh fixture from `1/1/1` to `2/2/2`; these are not D3 epoch positions. A native oracle on copies of the old images accepted the source-revoked refresh token (200) and lacked the new records (404). The new-image oracle rejected that refresh token (401), accepted the retained refresh token (200), returned both exact records (200), and denied anonymous access (403). This demonstrates the tested refresh-session rollback difference, not immediate invalidation of all previously issued access tokens.

Restored originals remained untouched: oracle applications used separate copies. Generic SQLite structural and foreign-key checks passed with **custom CHECK constraints ignored**; native restore used `integrity-check none` because those schema functions are not present in generic SQLite. This is not full custom-constraint validation. Separate post-run image/hash/structure checks confirmed main/session/aux row counts `0/2/0` before and `1/1/1` after. PID-specific listener checks bound the three application processes to loopback, and all four processes (source, replicator, two oracles) exited 0 and were reaped without forced kill.

Static review `957ab9b6-dbeb-4cec-ad37-a6ec9d54f021` accepted the bounded recording. Generated credentials, tokens, keys, raw application logs and database images remain private; the reviewer received sanitized metadata and parent-attested image checks, not those artifacts. Non-admin authorization, complete mutation/ACK coverage, concurrency, global cross-database atomicity, remote durability and HA remain unqualified.

### Owner decision required before a write-admission prototype

Recommended direction, **approved by the owner for a bounded local-only prototype; not implemented or approved for rollout at this checkpoint**:

- One authorized writer. No minority takeover, automatic failback or health-only routing. Distributed authority/effect admission must be real before any eventual rollout, including manual paths.
- Initially qualify only the bounded main/aux create/read workload and the tested login/logout/refresh behavior. Update/delete, account/admin/configuration changes, uploads, jobs and direct bypasses must be covered or enforceably excluded; none is silently deemed safe. Qualification must address non-admin policy separately.
- Never expose mutation success merely because TrailBase returned success or a local replica advanced. A future ACK boundary must establish recoverability of the required native database state on the selected independent storage and publish controller-independent, epoch/incarnation-bound proof before releasing success. Native `sync -wait` is a candidate mechanism, not sufficient proof by itself; remote backend and proof-publication semantics still need qualification.
- If proof/authority is unavailable, refuse admission before forwarding when possible. After a forwarded mutation, uncertain completion stays uncertain: withhold success, retain intent/evidence and do not automatically replay. Stale auth or unproven recovered state must not open application traffic; diagnostics may remain available.
- Prototype and qualify locally first. No production write interception, new paid infrastructure, migration, fault drill or automatic activation is authorized by this choice. Any eventual deployment still requires reviewed proofs, resolved provider-effect obligations and explicit rollout approval.

Alternatives remain the synchronous-architecture evaluation or retaining manual/refusal behavior. The owner selected the bounded local-only prototype direction after reviewing these choices. This is a write-path design decision; it does not mean the currently supplied VPS topology or backup backend already satisfies the contract.

### Initial bounded native check plan (executed above)

Use only a fresh local disposable SQLite database, pinned Litestream binary, private Unix socket and local file replica. Do not touch retained fixtures, live data, production object-store credentials or HAT admission paths.

1. Retain a pre-mutation replica/restore negative control showing the new marker is absent.
2. Commit a known mutation, invoke native `sync -wait`, and independently restore the replica to verify the exact marker and SQLite integrity. Nominal CLI success alone is insufficient.
3. Exercise an already-synced no-change request and an invalid/unavailable control path; keep refusals distinct from upload cancellation or loss.
4. Retain source, binary hash/version, configuration, commands/results, restored images and exact process shutdown evidence. Do not reuse the run as an action-capable harness.

This first check would establish only a local-file native mechanism. Concurrent mutations, upload/response loss, remote-backend durability, every data/auth path, multi-database consistency, controller loss and provider/authority gates remain separate obligations. No proxy, global ACK log or active-write recovery claim is authorized by its result.

No live write restriction, proxy replacement, SDK patch, database migration, new infrastructure, support ticket or fault drill follows from this packet. Installation permission for the supplied VPSs does not select a new write/durability contract.
