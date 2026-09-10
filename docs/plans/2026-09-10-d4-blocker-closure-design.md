# D4 Blocker-Closure Design

## Purpose and boundary

D4 asks whether a fresh, local, non-deployable TrailBase fixture can expose only three qualified mutations—create one `main_ops` record, create one `aux_ops` record, and log out one refresh token—while every other capability is refused. Success requires independent proof before request bytes are sent and operation-specific recoverability proof before success is released. Unknown or unavailable observation remains `infeasible`; it is never replaced by configuration, OpenAPI, fixture JSON, or a self-consistent digest.

This work changes only `experiments/d4`, tests, and D4 plans/status. It does not install a listener, alter `hat/` or deployment, use live data, push automatically, or qualify HA. Litestream proof is not closure evidence or a remote-durability guarantee. `logs.db` remains telemetry and cannot release an operation.

## Alternatives considered

1. **One simultaneous six-process attestation.** Run manager, TrailBase, opener, collector, sandbox probe, and Litestream together. Rejected: Litestream is a post-request proof process with broad database/file descriptors; pretending it belongs to the pre-send closure snapshot confuses two trust boundaries and enlarges the writable surface.
2. **Phase-separated receipts (selected).** The pre-send snapshot contains manager, TrailBase, held opener, and sibling collector. A separately receipted sandbox probe establishes denials before controls. Litestream starts only after an accepted request for bounded sync/restore proof and has separate manager-owned lifecycle/evidence receipts. Pure validation cross-binds each phase without claiming simultaneity.
3. **Instrument or fork TrailBase.** Rejected by scope. A fork could expose route/job/log registries but would no longer prove the pinned stock `v0.33.11` binary.

## Contract model

### Requests

`ClosureRequest` remains a single already-framed request. Main/aux create require exactly two headers, each once after ASCII case-folding: `Content-Type: application/json` and `Authorization: Bearer <opaque-token>`. The token is bounded, single-line ASCII using an explicit token-character grammar. The validated binding retains no secret value, raw request body, or serializer-bearing request object. The caller alone retains the original request for immediate forwarding in the same stack. Raw authorization and refresh-token values are forbidden from receipts, exceptions, tracebacks, diagnostics, core-dump-enabled children, environment, argv, config evidence, HTTP error capture, and every persisted artifact; tests scan all bounded outputs. Secrets enter the opener through an owner-held descriptor, never argv or environment. Logout requires only content type and keeps its strict refresh token in the body. Cookie, forwarding, transfer/framing, duplicate, combined, whitespace-varied, unknown, or operation-inappropriate headers refuse before callback. HTTP framing remains the later UDS opener's responsibility.

### Phase-separated process topology

The pre-send process snapshot has exactly one manager, TrailBase fixture, opener, and collector. TrailBase and opener are manager children; collector is launched by the same independently identified manager and is not a fixture/opener descendant. Every process carries PID, parent PID, start identity, executable digest, argv, UID/groups, role, observation time, and evidence reference. The sandbox probe is represented by a manager receipt plus launch/exit identities and content-addressed denial evidence. Litestream is represented only by a post-send proof receipt with exact binary/config/argv, manager parent, start/exit window, descriptor/path allowlist, output bounds, and evidence digest.

The listed phase/socket fields are requirements, not an implementable schema until host and runtime capabilities are proven. Two draft `d4-phase-socket-1` validators were rejected after adversarial review accepted contract-breaking mutations; their commits remain in history and their code is reverted. Task 5 must first construct trust from independently observed kernel facts, and Task 6 must prove complete stock-runtime observation. Only if both close may pure validation be derived from those reviewed receipts under a new `d4-phase-socket-2` identifier. `d4-phase-socket-1` is permanently refused. The trusted boundary is the local owner-controlled parent process plus the separately reviewed observer; compromise of that manager/observer or the host kernel is out of scope. The collector alone is never authoritative for manager ancestry, FD identity, socket linkage, ordering, or zero-byte facts. Its input descriptors are exact, read-only, manager-opened, and inventory-bound. Sandbox-probe evidence is a separate pre-control phase and cannot substitute for the pre-send collector. Litestream must be absent from the pre-send snapshot; its unique post-send phase nonce and lifecycle may neither overlap nor rewrite a pre-send binding.

### Listening and accepted sockets

Listening identity and connected endpoint identity are separate objects. A listener binds UDS canonical path, pathname device/inode, listening FD device/inode, TrailBase PID/executable/argv, owner/mode, and evidence. A connection binds listener ID, opener endpoint device/inode/PID, accepted TrailBase endpoint device/inode/PID, local peer UID/groups, accepted time, and zero bytes before validation. No equality between pathname inode and accepted endpoint inode is assumed. Instead, independent kernel observation must link the accepted endpoint to the listener/process; if macOS cannot provide that link, the capability probe returns `infeasible` and no bytes are sent.

Every claimed endpoint field records the exact kernel API and observation timestamp; unsupported PID/inode/linkage facts are `infeasible`, never synthesized. PID start identity and complete listener/accepted/client FD inventories are observed while the connection is held. Zero bytes means no application bytes in either direction, including peer-prefetched bytes; draining or peeking does not turn bytes into zero. The opener connects and holds the socket, verifies `LOCAL_PEERCRED`, publishes an `O_EXCL` intent, then waits for separately hashed observer and collector receipts. A raw framing receipt independently binds the exact method/target/header order and bytes, HTTP version, Host, Content-Length, absence of Transfer-Encoding/chunking, complete body boundary, connection nonce, and zero-byte precondition. Only a validated immutable binding can authorize one write of those exact bytes; missing header observation stops before TrailBase I/O.

## Execution ordering correction

Host capability and stock-runtime feasibility are decisive gates and precede exact phase/socket schema and descriptor-publication implementation. First build and statically review a fresh owner-only host-probe root without executing TrailBase or Litestream. Probe execution itself requires a fresh bounded owner authorization immediately beforehand. Independently decide runtime registration and `logs.db` call-path observability. Any unavailable or ambiguous required fact ends D4 as `infeasible`; no exact schema, publication integration, or native harness is then built. This ordering prevents a synthetic schema from defining facts the host cannot independently observe.

## Descriptor-relative publication

All admission journal, adapter evidence, and restored-image publication in `admission.py`, `native_adapter.py`, and `auth_logout_adapter.py` moves through one experimental helper using a pre-opened owner-only directory FD. Names are single components. New files use `openat` semantics via `os.open(..., dir_fd=..., O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC)`, bounded write loops, file `fsync`, descriptor metadata/digest verification, and directory `fsync`. Atomic replacement uses `os.replace(..., src_dir_fd=..., dst_dir_fd=...)` only while the same directory FD is retained. Every ancestry component is opened `O_DIRECTORY|O_NOFOLLOW` and checked for exact owner/private mode/type/link identity. The threat model requires a fresh dedicated `0700` root with no untrusted same-UID writer; an exclusive descriptor-checked operation lock serializes every participating writer. Existing destinations require that lock and exact previous inode/digest; unsupported flags, hard links, cross-device behavior, identity drift, fsync error, unexpected writer, or uncertain replacement refuses. Post-operation verification is consistency evidence, not retroactive proof that an unserialized race was safe.

Native and logout adapters may call this helper; they must not retain path-based security-sensitive writes. This closes local evidence-path races only. It does not establish distributed fencing or safe production publication.

## Host capability probes

Before a new native harness or exact phase/socket schema exists, small disposable probes test only host primitives:

- owner/process start identity and parent/child facts;
- FD enumeration and `FD_CLOEXEC` visibility;
- `LOCAL_PEERCRED` on a tiny AF_UNIX socket;
- independent visibility of listening and accepted endpoint identities;
- `sandbox-exec` write/read/network denial observability;
- source archive and prior-oracle packet descriptor binding;
- exact raw HTTP framing/header observation on a tiny disposable UDS protocol that sends no TrailBase request;
- sibling/collector provenance, cleanup/reaping, and bounded sanitized receipt handling.

Each primitive has one deterministic command, failing-first fake case, exact receipt schema, phase nonce, and blocker ID. Probe processes use a clean environment/cwd, closed or enumerated inherited FDs, pinned sandbox profile, descriptor-relative disposable paths, bounded outputs, process-group/descendant accounting, and no network-capable helper. Sandbox tests distinguish policy denial from missing-path failure with controlled positive/negative files and deny external network, loopback, DNS, Unix-socket IPC, and subprocess escape. Unsupported/deprecated enforcement is `infeasible`. No TrailBase request is sent during these probes. Building and statically reviewing the harness does not authorize execution; even these tiny process/socket/sandbox probes require a fresh bounded owner authorization receipt immediately before they run. Runtime route/job/plugin completeness and `logs.db` SQL call-path completeness are independent pre-send gates with manager-held, content-addressed receipts and externally fixed inventories. Static source closure may define the expected set, but runtime declarations cannot prove it; raw logs cannot prove SQL call-path completeness. If stock macOS/TrailBase cannot expose either complete observation, those blockers remain and native qualification stops.

## Error handling and evidence

Every timeout is uncertainty. Every failed or ambiguous attempt gets a new random owner-only root and is retained `pending`; no prior pending root is reopened, cleaned, reused, or converted to success, and no silent deletion occurs. Failure serialization is bounded and sanitized, followed by a secret scan; retain hashes/metadata rather than raw bodies, DB/WAL pages, logs, credentials, or unrestricted probe output. Cleanup uncertainty is itself a pending blocker and forbids retry until diagnosed. Manager receipts and sanitized evidence use `O_EXCL`, descriptor hashing, exact schemas, bounded output, and no tokens, cookies, bodies, DB/WAL pages, or raw logs. Tests count callback/send attempts and require zero for every pre-send failure. Process groups are readiness-handshaked, bounded, terminated, and disappearance-checked without treating `EPERM` as absence.

## Acceptance

Each stage requires failing-first tests, focused and full D4/runtime regressions, canonical source verification, and independent spec/security review. Any red test, failed static/source/quarantine gate, unavailable host fact, cleanup/reap uncertainty, descriptor drift, or missing review is a hard stop and leaves `infeasible`/`pending`; later green reruns cannot erase a preserved failure. A new private native run is permitted only if contract, publication, runtime-registration, telemetry, and all 13 host-probe gates are closed and reviewed, and a fresh owner authorization receipt is recorded immediately before execution with exact root, binaries, allowed local UDS paths, duration/expiry, three mutations, and zero external network. No service, privileged helper, production/live path, bind outside the disposable root, deployment, or broader action is authorized. The final result may remain `infeasible`; that is a valid safe outcome. Integration, push, worktree cleanup, and any deployment require explicit owner authorization.
