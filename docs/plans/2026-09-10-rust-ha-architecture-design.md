# Rust TrailBase HA Architecture and Rewrite Plan

**Status:** High-level architecture, replicated/local state split, serialized mutation policy, and individual-certificate operator roles approved. Detailed Raft state-machine, protocol, certificate-lifecycle, and qualification designs remain to be completed before implementation.

**Goal:** Replace the Python production prototype with one installable Rust HAT executable that provides a highly available three-controller control plane for supported existing TrailBase applications.

**Relationship to the current system:** The Python implementation remains an executable specification, adversarial conformance suite, and historical demo deployment. The first Rust release supports clean Rust-native clusters only. It will not read or mutate Python journals, configuration, operation evidence, or deployment state.

---

## 1. Agreed product scope

The first product profile is `manual-async`:

- one active TrailBase writer;
- one or more warm standbys continuously restoring every declared database;
- a highly available controller quorum;
- operator-initiated planned switchover and unplanned failover;
- unplanned promotion only after independently confirmed fencing;
- restoration to the latest independently observable, jointly recoverable cut;
- explicit possible loss of acknowledged writes newer than that cut;
- multiple ingress instances behind an operator-supplied stable front door;
- cold quarantine and clean reseed/rejoin of a former writer;
- no blind retries after uncertain effects.

The normative first-release data-loss statement remains:

> Failover restores the latest independently observable replicated cut. Writes acknowledged after that cut may be lost.

D4 is not a prerequisite for `manual-async`. Future TrailBase hooks may add `durability-gated` and `strict` profiles without weakening or replacing the asynchronous profile.

## 2. Core technology decisions

- **Implementation:** Rust.
- **Packaging:** one compiled HAT executable, launched in several isolated roles.
- **Consensus:** embed a proven Raft implementation; OpenRaft is the preferred candidate subject to a bounded storage/network qualification spike.
- **Controller membership:** exactly three statically configured voting members in the first release.
- **Quorum:** any two of three controllers.
- **Persistence:** bundled SQLite through Rust, with a dedicated storage actor and explicit durability settings. Raft replicates logical decisions; controller SQLite files are never copied between members.
- **Controller transport:** direct bounded RPC over mTLS. S3 is not a consensus transport.
- **Replication:** continue using a separately pinned Litestream executable; do not rewrite the database replication engine.
- **Application runtime:** continue using a separately pinned TrailBase executable.
- **Ingress front door:** operator supplied. HAT controls and validates provider-neutral ingress adapters and route generations, not cloud DNS or floating-IP implementations.
- **Fencing:** operator-supplied integration behind a strict effect/inspection contract.
- **Migration:** clean Rust-native clusters first; a Python-state importer is a separate future project only if justified.

There is no overriding reason to choose Go. Go would incur similar rewrite cost while losing the direct ecosystem advantage for future TrailBase instrumentation. The official embeddable NATS server is also Go-based; adding a NATS/JetStream cluster would introduce a second distributed consensus system and violate the one-HAT-binary objective. NATS may be an optional event/notification integration later, never writer authority.

## 3. Topology

Controller and data-node roles may be co-located but are distinct identities and processes. Production guidance prefers distinct failure domains; small installations may use three hosts.

Example:

```text
                         Operator
                            |
                       hat admin CLI
                            |
                  current controller leader
                            |
              three-member Raft + SQLite quorum
                  /            |            \
         controller 1    controller 2    controller 3
              |               |               |
         optional node    optional node    optional node
         + executor       + executor       + executor
              |               |
          TrailBase       TrailBase
          Litestream      Litestream

       multiple ingress instances validating one committed route
                            |
             operator-supplied highly available front door
```

A controller leader is a coordinator, not sole authority. It may propose state changes, but safety-relevant decisions require quorum commitment.

If one controller fails, the other two retain quorum. If two fail, the existing writer may continue serving according to policy, but no promotion, route change, membership change, or new administrative operation is allowed.

### 3.1 Approved controller trust model

V0.1 targets crash/partition fault tolerance, not Byzantine fault tolerance. Controllers may crash, restart, become unreachable, or encounter delayed/reordered messages. Safety assumes controller software follows the protocol and durable storage meets the qualified persistence contract.

A compromised controller deliberately lying or violating the protocol is outside the v0.1 safety guarantee. mTLS authenticates peer identity, not correct software behavior. Privilege separation reduces exposure but does not turn Raft into Byzantine consensus. Suspected controller compromise requires a separately documented containment/recovery procedure, not ordinary failover. Additional signatures alone do not change this fault model.

## 4. One binary, multiple isolated roles

The same installed executable exposes role-specific subcommands:

```text
hat controller serve   unprivileged Raft member
hat node serve         unprivileged node health/status agent
hat executor serve     local privileged effect executor
hat oracle run         isolated unprivileged restore verifier
hat ingress check      route-admission check or adapter entrypoint
hat admin ...          operator CLI
hat doctor             installation and connectivity preflight
```

These are separate processes with separate systemd sandboxing and OS identities. “Single binary” means one versioned executable artifact, not one root process.

The controller must not run as root. The privileged executor has no public listener; it accepts an exact, bounded local protocol over a protected Unix socket and performs only enumerated service/filesystem actions. The oracle has no service-control authority. CLI processes are on-demand. Oracle and executor processes may use systemd socket/transient activation where this reduces idle processes without weakening evidence or cleanup semantics.

## 5. Consensus and operation semantics

The replicated state machine will contain at least:

- immutable cluster identity and three-member configuration;
- controller identities and certificate bindings;
- supported capability/profile declaration;
- node and application release identities;
- current writer, epoch, and monotonically increasing fencing token;
- operation identity, kind, target, ordered phase, and terminal state;
- committed effect intents and bounded results;
- fencing observations and uncertainty;
- accepted database cuts and restore results;
- node eligibility and refusal reasons;
- authorized route generation;
- upgrade compatibility state.

Raft does not prove external effects. Before fencing, process control, restore, activation, or routing, the intent must be quorum committed. Completion is committed only from independently validated evidence.

If a request times out, a controller dies, or leadership changes after an effect may have started, the next leader performs inspection/reconciliation only. It does not replay the effect unless the effect contract independently proves that no previous invocation began and the operation state explicitly permits execution.

An operator request is complete when its operation reaches a committed terminal state, not when the original leader or CLI connection survives. Client disconnect does not cancel a committed operation.

### 5.1 Approved replicated/local state boundary

Raft stores facts needed to determine authority or safely resume an operation, not application data, secrets, bulk telemetry, or raw diagnostics.

Replicated state includes approved identities and compatibility ranges, writer/epoch/fencing token, route generation, release/config/database-inventory identities, administrative requests and approvals, operation phases, effect intents, sanitized canonical results, eligibility/refusal decisions, accepted restore cuts/results, unresolved uncertainty, and append-only operation history with evidence digests. Snapshots preserve this logical state; the Raft log is not the permanent audit archive.

Frequent telemetry stays local. An observation used for an operation is captured and committed with its operation/request nonce, observer and target identities, boot/incarnation, relevant state/positions, release/config binding, validity constraints, and evidence binding. State-machine application is deterministic and does not consult local clocks. Exact freshness validation, expiry at effect execution, and invalidation after intervening changes remain protocol-design requirements; commitment alone does not make an observation indefinitely valid.

Controller-local state includes connections, caches, timers, telemetry, metrics, raw diagnostics, and temporary transfer files. Physical Raft storage is local to each member; logical safety state must remain recoverable from quorum persistence. Nodes independently retain their identity, local action intent/result journal, activation/quarantine records, protected release/config identities, restore workspaces, cleanup state, and secrets. Process state and database positions must be freshly inspected rather than trusted from a stale journal.

A replacement leader reconciles using exact operation identities. Missing required evidence or unknown effects block progress, never justify replay. Raft retains bounded canonical results and digests; protected full evidence may be archived separately. Missing optional diagnostics does not invalidate an already accepted canonical result, but missing evidence required by a pending phase refuses progress.

### 5.2 Approved operation serialization

V0.1 permits one cluster-wide mutating operation at a time, with no queue. Competing requests are rejected rather than retained for later execution. Status reads, telemetry, steady replication, and evidence collection remain concurrent.

The operation lifecycle distinguishes proposed/active work from `succeeded`, `failed-safe`, and `blocked-uncertain`. Success and independently established safe failure release the mutation slot. Uncertain effects, authority, or required cleanup retain it. Explicit reconciliation operates within the retained operation slot; it cannot acquire a competing slot or erase historical failures.

There is no generic cancellation once effects begin. A safe-stop request may stop before effects, follow explicitly authorized cleanup phases, or remain blocked when safety cannot be established. Detailed transitions and safe-stop authorization remain to be specified.

The serialization rule covers supported switchover, failover, rejoin, route repair, replacement, and upgrade operations. It does not introduce online controller membership changes or online certificate rotation into v0.1; offline recovery/replacement requires a separate procedure.

**Approved narrow exception:** an authorized administrator may quorum-commit operator-access revocation without acquiring the mutation slot, including while an operation is blocked. This exception only removes access; it cannot add identities or grant permissions. Revocation blocks subsequent requests on new and existing connections. It does not cancel previously committed operations, clear uncertainty, or release the slot. Without quorum, revocation refuses; there is no local bypass. ACL authorization and ordering must still be checked against committed state.

## 6. Manual first, automatic later

The first release has distributed controller availability but operator-triggered failover:

1. Controllers detect and report writer failure or degraded replication.
2. They do not automatically promote.
3. An authenticated administrator submits a failover operation to any reachable controller.
4. The operation is quorum committed.
5. The leader coordinates fencing, cut selection, restore, activation, acceptance, and routing.
6. Leadership may change without replaying completed or uncertain effects.

After fault qualification, an optional `automatic-async` policy may submit the same operation automatically. It remains disabled by default and requires explicit acceptance that recent acknowledged writes may be lost. D4 durability profiles are a separate later layer.

## 7. Networking and bootstrap

Controller peers use direct TCP RPC with built-in mTLS. No VPN product is mandatory.

Operators provide one reachable address per static controller. Private VPC/VLAN addresses are preferred; restricted public addresses are supported. WireGuard, Tailscale/Headscale, and orchestrator networks are optional deployment patterns.

A proposed initialization flow is:

```text
hat cluster init --controller c1=ADDR --controller c2=ADDR --controller c3=ADDR
hat cluster bootstrap --ssh HOST1 HOST2 HOST3
hat doctor
hat cluster activate
```

`cluster init` generates a cluster CA, three fixed controller identities, node-specific bootstrap bundles, a public manifest, firewall instructions, and an offline recovery package. An SSH-assisted bootstrap may use the administrator's existing SSH client; fully manual copying remains supported.

HAT does not silently change firewalls. It prints exact rules, tests reachability, and requires an explicit option before applying any generated rule.

## 8. Identity and TLS direction

The first release requires mTLS with pre-provisioned fixed controller identities:

- one certificate/key identity per controller;
- controller ID and configured address bound to certificate identity;
- separate identities for controller peers, node agents, and operator clients;
- no shared cluster bearer token;
- private keys stored in owner-only files or an approved OS key facility;
- certificate mismatch, replacement, expiry, or unapproved identity refuses participation.

Certificate issuance, expiry defaults, revocation, rotation, and offline recovery still require a dedicated design. Static controller membership does not mean certificates may be permanent or unrotatable.

### 8.1 Approved operator authorization model

Each operator uses an individual mTLS certificate, not a shared password or bearer token. A replicated ACL binds the certificate public-key hash to a role:

- `viewer`: status and authorized sanitized evidence, never secrets or unrestricted raw diagnostics;
- `operator`: switchover, failover, safe stop, and rejoin;
- `administrator`: configuration, upgrades, and supported identity/replacement procedures.

Operator additions and revocations require quorum commitment. Revocation is enforced by the ACL even before certificate expiry. ACL freshness on persistent connections and forwarded requests must be specified; an old TLS session is not permanent authorization. A separate offline recovery identity is proposed for the separately designed disaster-recovery procedure, not an online quorum bypass.

Mutating requests bind cluster ID, unique request ID, authenticated operator, operation kind and exact parameters, expected cluster generation/writer epoch, and expiry. Acceptance precedes execution through quorum commitment. Exact retries return the existing operation; reuse of an ID with different identity or parameters refuses. Deduplication retention and request-expiry enforcement remain protocol details.

Followers may securely forward requests, preserving authenticated identity. Losing the client connection does not cancel committed work. One authorized operator suffices initially; two-person approval is deferred. SSH remains bootstrap/convenience transport, not runtime authority.

## 9. Ingress model

HAT does not own the globally stable public IP/DNS/load balancer in the first release.

It provides:

- a quorum-committed route generation;
- exact writer, epoch, fencing token, release, and config binding;
- multiple ingress instances that independently validate that generation;
- health/admission endpoints intended for an operator-supplied load balancer;
- strict adapter contracts for applying and inspecting routes;
- refusal on stale, unknown, partially applied, or conflicting generations.

A single ingress process is never described as HA. Managed load balancers, Kubernetes services, VRRP/floating-IP systems, and DNS are external integrations.

## 10. Fencing integration direction

The preferred first interface is a strict operator-supplied executable adapter, with bounded canonical input on stdin and bounded canonical output on stdout. Credentials are supplied through protected files, environment files, or file descriptors, never argv or retained evidence.

Every request binds cluster, operation, exact provider target, expected incarnation, action, deadline, and idempotency identity. Every result binds terminal observed state and incarnation. Timeout or communication loss is uncertainty. A replacement leader may inspect but never blindly repeat an uncertain fence action.

Built-in cloud-provider SDKs and an HTTPS adapter can be considered later. The consensus core remains provider-neutral.

## 11. Rewrite and delivery roadmap

### Phase 0 — Architecture qualification spikes

Create disposable, non-production Rust spikes for:

- OpenRaft fixed three-member initialization and restart;
- bundled-SQLite Raft log/vote/state-machine storage;
- OpenRaft storage conformance tests;
- snapshots, crash boundaries, torn writes, disk-full behavior, and restore;
- bounded mTLS RPC, peer identity binding, partitions, and certificate expiry;
- leader loss before/during/after an external effect intent;
- one-binary multi-role packaging and systemd sandboxing.

A spike may reject OpenRaft or the proposed SQLite design. No spike result is production authority.

### Phase 1 — Stable schemas and crate skeleton

Define versioned Rust types for cluster configuration, release manifest, node observations, operation commands/results, refusal states, route generations, fence requests/results, and restore acceptance. Generate canonical fixtures shared with the Python conformance suite. Add one binary with inert role subcommands and no service-changing capability.

### Phase 2 — Consensus core

Implement fixed membership, mTLS peer transport, bundled-SQLite storage, snapshots, linearizable administrative writes, safe reads, metrics, quorum-loss behavior, and offline recovery documentation. Do not expose dynamic membership APIs.

### Phase 3 — Node and privileged executor

Implement exact local identity, release/config/database inventory, process supervision, durable local action intents, boot/incarnation binding, privilege separation, status, quiesce, freeze, activation, quarantine, and refusal semantics. Port adversarial Python tests as Rust tests and cross-language fixtures.

### Phase 4 — Replication and restore oracle

Generate exact Litestream configuration for every declared database. Implement lag/position observation, jointly recoverable cut selection, independent restore, integrity/foreign-key checks, application/auth probes, exact-position evidence, and result retention. Keep uploaded-file/object storage outside the SQLite guarantee unless separately configured.

### Phase 5 — Planned switchover

Implement the complete quorum-committed state machine for close ingress, quiesce, sync, freeze, compare, activate, baseline, route, verify, and failure retention. Require a clean one-pass disposable qualification before release.

### Phase 6 — Manual unplanned failover and rejoin

Implement operator-triggered failure recovery with external fencing, accepted-loss reporting, cold target validation, restore, activation, ingress, quarantine, clean reseed, and redundancy restoration. Prove leader changes at every phase and every external-effect uncertainty boundary.

### Phase 7 — Install, upgrade, rollback, and supported release

Deliver deterministic packages, systemd units, bootstrap bundles, doctor/preflight, compatibility checks, rolling controller upgrades, node upgrades, rollback, backup/restore, certificate procedures, runbooks, metrics, and a precise support matrix. Qualify first on disposable infrastructure, not the persistent Python demo.

### Phase 8 — Optional automatic and D4 profiles

Add `automatic-async` only after distributed fault qualification. Add D4 durability profiles only after upstream TrailBase hooks or an approved fork provides complete required observations.

## 12. Python retirement strategy

Do not translate files line by line. Port contracts and operations vertically:

1. Preserve canonical Python fixtures and failure cases.
2. Implement one Rust boundary.
3. Run Rust unit/property/fault tests.
4. Run cross-language conformance against retained fixtures.
5. Qualify the Rust boundary on disposable Linux hosts.
6. Mark the equivalent Python production path legacy only after approval.

The Python deployment remains untouched during Rust development. No in-place mixed Python/Rust control plane is supported.

## 13. Remaining architecture decisions

Before an implementation plan is approved, decide and document:

- exact schemas and freshness rules for the approved replicated/local state split;
- OpenRaft version and acceptance criteria;
- SQLite schema, durability mode, storage actor, and snapshot format;
- RPC encoding/framework, size limits, deadlines, and backpressure;
- certificate issuance, rotation, revocation, and recovery;
- operator ACL enforcement, forwarding, request deduplication, and implementation of the approved revocation exception;
- privileged executor authorization protocol;
- node observation freshness and eligibility rules;
- fence and ingress adapter schemas;
- release/config/database inventory format;
- controller/node upgrade compatibility and rollback;
- backup and disaster-recovery scope for controller state;
- supported Linux distributions and filesystem assumptions;
- automatic-async policy gates;
- upstream TrailBase/D4 integration boundary.

## 14. Current authorization boundary

This document authorizes architecture discussion and planning only. It does not authorize a Rust implementation, dependency addition, new service, port/firewall change, controller cluster initialization, certificate creation, paid infrastructure, migration of the Python demo, failover, routing, or production qualification.
