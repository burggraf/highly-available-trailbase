# V1 contract — decision draft

**Status:** Owner decisions captured, including controller-dependent unattended restart, public HTTPS dashboard access and individual local operator accounts. Implementation contracts below are a design draft for review, not an implemented or qualified protocol and not permission to deploy. See the [implementation plan](plans/2026-09-11-v1-manual-failover.md).

**Implementation tracking:** this contract is not the progress ledger. Task 2 now has partial Rust unit code, but its checker CLI and validated route wire boundary remain unfinished. See the [active acceptance tracker](plans/2026-09-11-v1-manual-failover.md#execution-state-and-acceptance). The planning-pass statements below describe that earlier pass, not current implementation completion.

## Confirmed requirements

The owner confirmed these choices on 2026-09-11:

- One controller; its downtime does not interrupt an otherwise healthy, already-running primary.
- One writer, with manual promotion to a different node and accepted possible asynchronous write loss.
- Rust proxies on all nodes forward every application request to the primary in V1.
- Future scoped replica reads remain gated on qualified TrailBase read-only support.
- **A browser dashboard is required in V1, directly accessible over public HTTPS.** CLI-only or tunnel-only delivery is insufficient.
- **Individual local operator accounts share the same management permissions.** No SSO/client-certificate requirement for browser sign-in.
- **The existing primary must recover unattended after a node-agent restart or host reboot.** A restarted primary may wait for the controller to become reachable, then resume automatically only after fresh reconciliation/authorization. An already-running healthy primary continues during controller downtime. The owner explicitly accepted this availability tradeoff.
- The initial acceptance fixture may omit custom jobs and uploaded-file mutation. It still includes records, authentication, SSE, main/session/aux databases and recovery checks.
- Linux version, fencing provider/mechanism and public front door remain pending. Use local fixtures/fake adapters meanwhile; no private inventory discovery or live access is implied.

## Proposed dashboard boundary

Use one controller binary to serve static dashboard assets and the operation API. No separate frontend server, external dashboard database or mandatory frontend framework.

Required screens/actions:

- Nodes and current writer, with per-database positions, observation age, errors and unknown/stale state.
- Current route and operation status, including actionable refusal/uncertainty details without secrets or raw application payloads.
- Planned switchover, explicitly confirmed accepted-loss failover, operation inspection/reconciliation and clean rejoin.
- Visible confirmation of exact target/current generation before mutation; reused request identities retrieve the existing operation rather than execute again.

Expose the dashboard on its own configured public HTTPS origin, distinct from the TrailBase application origin and private node-control listener. Require a valid TLS identity and explicit bootstrap before public startup; no plaintext password endpoint or default account. TLS certificate provisioning/renewal and the actual hostname remain deployment inputs, not a requirement to build an ACME client. The HAT service can consume protected certificate/key files; renewal may initially restart the controller, which does not stop the healthy data plane.

**Proposed minimum access implementation:**

- A local operator CLI creates, disables and resets individual accounts through a protected controller-local channel. Passwords are read from a terminal or protected stdin, never command-line arguments, URLs or logs. No public registration, emailed reset flow or browser account-management UI in V1.
- Store salted Argon2id PHC password hashes, not encrypted/recoverable passwords. Use a maintained library and explicitly recorded work parameters; bound concurrent password checks so public login traffic cannot consume unbounded memory. Require at least 15 characters for this password-only design, permit spaces/Unicode and at least 64 characters, and reject oversize inputs without silent truncation.
- All enabled operator accounts may inspect and submit cluster operations. Local account maintenance requires controller-host privileges; there is no role hierarchy or online privilege escalation. Successful operation records identify the authenticated account, not a caller-supplied actor field.
- Use cryptographically random opaque session tokens, storing only their hashes server-side. Issue a host-only `__Host-hat_session` cookie with `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/` and no Domain. Proposed expiry: 30-minute idle and eight-hour absolute limits. Rotate tokens on login; never use browser local storage for credentials.
- Check account enabled state and session validity on each protected request. Logout, password reset and account disable revoke applicable sessions; revocation affects later requests but does not cancel an already accepted operation. Account disable/revocation remains possible while an operation is blocked; it cannot release the operation slot.
- Require exact configured Origin and JSON content type for browser mutations, including login; require a session-bound CSRF token for authenticated mutations. Reject unexpected Host, cross-origin credentialed access and untrusted forwarding headers. Do not rely on SameSite alone. The local CLI uses a separate OS-protected channel, not a public Origin-check exception.
- Apply bounded login rate limits per source and normalized account plus a global password-hashing concurrency limit. Use generic login failures and equivalent password-verification work for unknown accounts. Avoid permanent account lockout that lets an attacker disable operators. Expire/cap limiter entries and bound request/header/body sizes before hashing.
- Serve only local static assets under a restrictive CSP, with framing disabled, no inline executable HTML from observations, `nosniff`, no-store on sensitive responses and no secrets in errors. TLS failures never fall back to HTTP. Document MFA as a remaining password-only security limitation, not an implemented guarantee; reassess it before exposing a sensitive deployment.

Proposed management limits: 8 KiB login bodies, 64 KiB operation commands, 256 KiB node observations/results and bounded/paginated status history. These limits do not apply to streamed TrailBase application payloads. Exact rate/time thresholds and password parameters must be pinned/tested before enabling public login.

Use the same durable operation API for the dashboard and CLI. Client disconnection, refresh or lost responses cannot cancel accepted operations or justify another effect. Untrusted node/error text must be escaped, controls accessible, and secrets excluded from responses/logs.

## Unattended restart: approved availability policy

**Owner decision: yes.** A restarted primary waits for a reachable controller and fresh authorization, then resumes unattended if safe. A still-running primary remains independent of the controller. This does not approve every protocol detail below; implementation and fault qualification must establish those details.

| Situation | Required behavior |
| --- | --- |
| Controller stops; primary and agent remain healthy | Existing traffic/streams continue; no promotion or configuration change |
| Current primary agent restarts or its host reboots; controller reachable | Reconcile and automatically restart the same primary if safe; no operator approval for the normal path |
| Primary restarts while controller is unavailable | Proxy/agent starts, but TrailBase remains stopped; automatically resume the authorization process when the controller returns |
| Former primary returns after failover | Remain quarantined; never restart writable from remembered state |
| Failover/fencing is active or its outcome uncertain | Restart is blocked pending reconciliation; no competing operation |
| Controller has lost/corrupt/stale authority state | Refuse automatic writable startup; controller recovery needs an explicit procedure |

### Required ordering

1. Agent startup creates a fresh process incarnation, even on the same host boot. Historical route/role records do not reopen local application admission.
2. Verify child-process containment: an old TrailBase/Litestream child cannot remain writable outside the new agent's knowledge. Keep application admission closed during recovery.
3. The controller reconciles its durable journal and node observations. Same-primary restart competes for the same operation slot as manual failover; only one can be accepted. Unresolved previous effects retain that slot.
4. If the node is still the current primary, reserve and persist a restart operation with exact node/agent incarnation, writer identity and parameters. Check there is no outstanding fence or authorization that could conflict.
5. Validate local data, journal recovery, release/configuration and replication history. Whether Litestream can resume the existing history after local crash recovery is a native qualification requirement; detected rollback/incompatibility must not be ignored.
6. Issue fresh incarnation-bound startup authorization; the node persists acceptance before effects. Duplicate commands return retained status. A delayed grant for an earlier incarnation cannot start a writer.
7. Validate recovered primary/replication readiness, then publish its new route incarnation and open admission. The operation retains uncertainty if any response/effect is unsettled.

Existing-primary restart is automatic **recovery**, not automatic **failover**. It cannot select a standby, discard pending history, bypass fencing or reset a journal. Errors may still require operator intervention; unattended recovery is not a promise to self-repair corrupt databases or unknown authority.

### Controller-independent writable restart is out of scope

Do not implement a remembered `is_primary` flag or reuse a cached activation grant. An isolated old primary cannot infer whether another node has been promoted. The approved waiting policy avoids introducing a second authority mechanism. It may be revisited only through a separate design decision.

## Proposed control/data contracts

### Identity and encoding

Use versioned JSON objects with a required `schema_version: 1`, reject unknown fields and duplicate JSON keys, reject oversize input before parsing, and prohibit secrets in canonical results. Use UUID strings for cluster/request/operation/agent identities; node/database names use a bounded explicit ASCII grammar. Encode monotonically increasing generations/sequences as decimal strings on the JSON wire to avoid JavaScript integer truncation. Compare parsed integers, never their lexical representation. A per-database restore TXID is a separate validated hexadecimal value, comparable only within the same history.

Required records:

| Record | Required identity/state fields |
| --- | --- |
| Active route | cluster ID, route generation, primary node ID, writer epoch, primary agent incarnation, approved release/config digest |
| Operator request | request ID, cluster ID, expected route generation, expected writer epoch, kind, exact target node ID, explicit possible-loss acceptance for failover |
| Accepted operation | operation ID, authenticated operator ID or internal restart actor, original request/digest, ordered phase, state, created/updated observation times, retained outcomes |
| Node action | cluster/controller identity, operation ID, phase, action ID, per-node command sequence, expected agent incarnation/local revision, writer epoch, action kind, exact typed parameters |
| Node action result | same action/operation/target bindings, accepted revision, state, bounded typed result/error; never echo request fields as independent evidence |
| Node observation | cluster/node/agent identity, observation nonce, role/admission state, local revision, active/pending action, release/config identity, per-DB history/position/error and child observations |

Route endpoints come from trusted static inventory; an action or incoming public header cannot choose an arbitrary URL. Keep database inventory/configuration distinct from live authority; a config `primary` hint never authorizes a writer by itself. Initial bootstrap is an explicit journaled operation after proving the clean installation, not a normal startup fallback.

### Operations, durability and delayed commands

Controller operations are `active`, `succeeded`, `failed_safe` or `blocked_uncertain`. The latter retains the one mutation slot. A locally detected ordinary error is not automatically a safe failure. Node actions record acceptance before effects, and retain completed results for duplicate inspection.

Persist controller intent before dispatch. Include a strictly ordered node-command sequence and current expected local revision/incarnation. Persist node acceptance before effect execution; duplicates with identical immutable parameters return retained status and never repeat effects. Reused IDs with different parameters refuse. Retain ordering/tombstones so journal pruning cannot make an old command executable again.

After a controller crash or response loss, inspect using the same identities. **A node reporting “action not found” does not prove a delayed request cannot still arrive.** Do not release the slot or permit a competing activation solely from that observation. Either settle the original action, prove it was never dispatched using durable local evidence, or use a separately qualified fence/incarnation-change procedure that makes the old request permanently ineligible. No generic cancel/force/expiry shortcut.

A queued or accepted startup request that could still execute blocks opposite operations. For agent/host restart, old-incarnation requests are ineligible; prior effects still require inspection/containment rather than erasure. Reconciliation cannot mint a second identity for an uncertain first effect.

Use bundled SQLite local journals with explicit `synchronous=FULL`, foreign keys and transactional uniqueness constraints, plus one controller process lock. Execute blocking SQLite/password work off async I/O threads. Commit/fsync errors mean no effect may be dispatched; unknown commit results require reopen/inspection. SQLite file transactions do not replace required filesystem fsync/atomic publication for other state. Never copy a live controller DB as a backup or recover blindly from a stale one.

### Public operation API

Proposed endpoints, all on the authenticated dashboard origin except login:

```text
POST /api/v1/login
POST /api/v1/logout
GET  /api/v1/session
GET  /api/v1/status
POST /api/v1/operations
GET  /api/v1/operations/{operation_id}
GET  /api/v1/requests/{request_id}
POST /api/v1/operations/{operation_id}/reconcile
```

Operation submission returns `202` only after durable acceptance, not after completing the transition. Exact resubmission returns the existing receipt/status; identity/parameter/generation conflicts return `409`. Account attribution comes from the server session. `401`/`403` are authentication/authorization refusal, `413` size refusal and `429` throttling. A disconnected browser queries the known request ID instead of creating another operation. The dashboard confirms target and possible loss explicitly, disables unsafe controls based on observed state, and still relies on server-side checks against races.

Reconciliation is a bounded typed request within the retained operation; it is not a command shell or an operator override of uncertain fencing.

### Fencing boundary

Use one operator-supplied executable with versioned bounded JSON stdin/stdout. Input binds cluster, operation/action ID, exact provider resource identity, expected observed incarnation where the provider supports it, command kind and a deadline. Credential references are protected configuration, never argv or recorded result payloads. Public endpoints cannot supply executable paths or arbitrary arguments.

Separate `fence` from `inspect`; retain provider-issued request identity when available. Valid evidence must independently establish the exact old writer cannot write/restart during successor activation, and that no unsettled late power effect can hit a subsequently reused node. Adapter assertions or negative pings are insufficient by themselves. If the provider cannot establish required identity/settlement semantics, live qualification refuses or requires a separately reviewed persistent-fence procedure.

Action timeout is uncertainty, not cancellation. Keep old data and provider evidence. Reboot/rejoin is forbidden until pending power effects are settled. Do not assume credential revocation is an instantaneous fence.

### First runnable checks

- All public methods/routes, including GET logout and subscriptions, resolve only to the configured active primary; unknown/missing routes refuse.
- A route cannot start a writer; stale generations, conflicting equal generations and wrong target incarnations refuse.
- Agent restart while controller is down waits; controller return enables same-primary recovery without operator approval only after safe reconciliation.
- Manual failover racing automatic same-primary restart has one accepted operation, never overlapping effects.
- Delayed activation, node “not found,” controller restart and lost responses cannot release authority to conflicting work.
- Dashboard login/CSRF/session/revocation/rate-limit checks fail closed; refresh/double click/lost receipt cannot duplicate transitions.
- Fencing uncertainty, wrong restore history, missing DB, mismatched keys/config and live followers prevent activation.
- Child containment, SQLite durability ordering and each native Litestream restore/resume assumption receive real process tests, not only mocked results.

## Rust implementation direction and documentation evidence

Use one Cargo package, static embedded dashboard assets and standard browser APIs. Proposed library families:

- Tokio runtime; Axum for management routes/body middleware; Hyper/Hyper-util for streamed application forwarding.
- Rustls integration for server TLS and authenticated private peers; no homemade TLS or cryptographic verification.
- Rusqlite with bundled SQLite for the existing local-journal/session requirement; no ORM or connection-pool framework by default.
- RustCrypto Argon2id password hashing; OS-backed randomness for salts/session identities through a maintained crate. Serde/serde_json for bounded typed contracts.

Current documentation was consulted through Context7 for [Axum body limits](https://docs.rs/axum/latest/axum/extract/struct.DefaultBodyLimit.html), [Rusqlite transactions](https://docs.rs/rusqlite/latest/rusqlite/struct.Connection.html) and [Argon2](https://docs.rs/argon2/latest/argon2/). Streaming application forwarding must not inherit buffered management-body handling or a short whole-response timeout that breaks SSE.

Hyper-util's Context7 documentation fetch returned 404. Its [official builder documentation](https://docs.rs/hyper-util/latest/hyper_util/client/legacy/struct.Builder.html#method.retry_canceled_requests) was fetched directly: `retry_canceled_requests` defaults to true for requests disrupted before writing starts. Disable it for the deliberately single-attempt forwarding policy and test response-loss behavior; do not inaccurately describe that library default as a retry of known committed writes. Also avoid automatic redirects/body decompression in the proxy path.

The browser documentation tool was unavailable because the installed agent-browser version was unsupported; direct text fetching supplied the Hyper-util reference. No browser UI validation occurred and no tool installation was attempted.

Exact compatible crate versions, features and checksums must be resolved and retained in `Cargo.lock` when the first package is created, with dependencies added only as their slice needs them. This moves package pinning from prose-only Task 1 into Task 2 and later slices rather than creating an unused dependency scaffold. No version in a live `latest` documentation URL is a release pin.

Retain TrailBase v0.33.11 / Litestream v0.5.17 as the historical native baseline pending explicit requalification; this document does not claim they are the latest releases or newly tested here.

## Remaining Task 1 gates

- Review the proposed browser security and durable-command contracts; finalize exact action-specific parameter/result schemas and configuration shapes before implementing those action-capable boundaries.
- Resolve Rust TLS/session API details and exact package pins at the relevant implementation slice, not from remembered APIs.
- Keep Linux/fencing/front-door/certificate deployment inputs pending. No production guarantee follows from fake-adapter tests.
- Qualify filesystem/process containment, same-history restart, restore and external fencing before enabling native transitions.

**Decisions are recorded; detailed contracts remain draft and native qualification is outstanding. No Rust package, listener, service, account, certificate, provider action or live deployment change has been created in this pass.**
