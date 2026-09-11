# Manual-Async TrailBase HA Product Plan

**Status:** Product direction approved. The high-level Rust architecture is recorded in [Rust TrailBase HA Architecture and Rewrite Plan](2026-09-10-rust-ha-architecture-design.md); detailed contracts and qualification remain pending.

**Goal:** Build an installable HA system that can run an existing, supported TrailBase application with one writer and one or more warm standbys, while explicitly allowing recent acknowledged writes to be lost during failover.

**Current baseline:** The repository and three-VPS environment contain an operator-controlled Python prototype for D0–D3 inventory, replication, switchover, fenced recovery, restore acceptance, routing, and cold rejoin. It is an executable specification and test harness, not a production product or a commitment to Python. D4 durability-gated acknowledgement remains infeasible with stock TrailBase v0.33.11 because complete mutation-surface and `logs.db` SQL-path observation are unavailable.

---

## 1. Product definition

The first product profile is `manual-async`:

- exactly one active TrailBase writer;
- one or more standbys continuously restoring every declared database;
- TrailBase stopped on standbys;
- operator-controlled planned switchover;
- operator-controlled unplanned promotion only after independent fencing proves the old writer incarnation cannot resume;
- restoration to the latest independently observable, jointly recoverable cut;
- explicit reporting of health, epoch, database positions, lag, eligibility, and refusal reasons;
- cold reseed/rejoin for a former writer;
- user-supplied ingress and fencing integrations behind strict contracts;
- durable operation intent, retained evidence, and refusal of blind replay.

The normative data-loss statement is:

> Failover restores the latest independently observable replicated cut. Writes acknowledged after that cut may be lost.

The product must not describe this profile as lossless, zero-RPO, synchronous, or durability-gated.

## 2. Guarantee profiles

| Profile | Promotion authority | Acknowledged-write contract | Initial scope |
| --- | --- | --- | --- |
| `manual-async` | Operator plus independently confirmed fencing | Recent acknowledged writes may be lost | First product |
| `automatic-async` | Quorum/common authority plus independently confirmed fencing | Recent acknowledged writes may be lost | Later, independent of D4 |
| `durability-gated` | Quorum/common authority plus fencing | Only explicitly supported and proven mutations receive the stronger guarantee | Requires D4/upstream hooks |
| `strict` | Same as durability-gated | Unsupported or unobservable mutation surfaces refuse | Future optional profile |

A deployment advertises only capabilities it has independently observed. Missing, malformed, stale, or uncertain evidence lowers eligibility or refuses the operation; it never silently upgrades the guarantee.

## 3. Initial supported application envelope

“Any existing TrailBase application” means any application satisfying a declared and verified support envelope. The first release requires:

- a pinned TrailBase release and compatible SQLite/Litestream versions;
- an explicit inventory of main, session/auth, auxiliary, and attached databases;
- identical migrations, configuration, signing keys, WASM/extensions, and application artifacts on every candidate;
- declared external dependencies and secret-version identifiers without storing secrets in product state;
- jobs, extensions, admin paths, and background mutators stopped on standbys and during transition boundaries;
- external or separately replicated storage for uploaded files and other non-SQLite state;
- a trustworthy external fencing integration for unplanned promotion;
- a user-supplied ingress integration with a read-only admission/status check;
- local filesystems with the required locking, ownership, atomic-rename, and durability behavior.

Apps outside this envelope are reported as unsupported, not accepted with weaker hidden assumptions.

## 4. Stable component model

The approved Rust architecture preserves these language-neutral boundaries:

1. **Node agent** — owns TrailBase/Litestream processes, local identity, database inventory, transition intents, health, freeze, activation, quarantine, and rejoin.
2. **Controller/CLI** — serializes operations, validates authority, records durable phase intent/result, coordinates fencing, restore, routing, and manual approvals.
3. **Restore oracle** — independently restores the declared cut and validates database integrity, application records, authentication state, release identity, and exact restore positions.
4. **Ingress adapter contract** — exposes admission and route application without making a manifest or health response promotion authority.
5. **Fence adapter contract** — binds target and incarnation, reports terminal external state, and treats timeout/communication loss as uncertainty.
6. **Configuration and release manifest** — declares nodes, databases, artifacts, storage, integrations, policies, and supported capability profile.
7. **Status/observability surface** — reports facts and refusals without claiming freshness, RPO, or promotion safety from liveness alone.

The current Python code supplies behavior and adversarial test cases for these components. Production will be rewritten incrementally in Rust; Python remains a conformance and fault-injection harness rather than production runtime.

## 5. Safety invariants retained without D4

The reduced durability promise does not justify weaker control-plane safety:

- one writer only;
- no promotion without independently proven fencing;
- no automatic action in `manual-async`;
- operation intent committed before mutation;
- timeout is uncertainty, not cancellation;
- no replay of an operation that may have started;
- exact node, boot/incarnation, epoch, target, release, config, and database bindings;
- all declared databases restored and accepted as one coordinated cut;
- route changes only after activation and restore acceptance;
- old data quarantined rather than deleted;
- rejoin uses a clean reseed, not resumption of stale writable state;
- manifests and health reports are evidence inputs, never independent authority;
- failures and uncertain outcomes remain retained after later success.

## 6. D4 integration seam

D4 is an additive capability, not a prerequisite for `manual-async`.

The initial system records the latest recoverable positions and reports possible acknowledged-write loss. If upstream TrailBase later exposes complete mutation registration and database-write observation, a durability module may:

- classify supported mutation surfaces;
- delay selected responses until recoverability proof exists;
- bind response, database position, and restored operation membership;
- reject unsupported or unobservable paths in stricter profiles;
- report a stronger RPO only for covered operations.

No D4 module may change fencing, single-writer, operation-journal, or route-authority rules. Disabling D4 returns the deployment to its explicit asynchronous-loss contract.

## 7. Delivery stages

### Stage 0 — Architecture decision (complete)

Rust, a single installed HAT executable with isolated process roles, a fixed three-controller OpenRaft quorum, direct mTLS RPC, bundled SQLite controller persistence, and clean native installations are approved. See the [architecture and rewrite plan](2026-09-10-rust-ha-architecture-design.md). OpenRaft and its SQLite storage design remain subject to a bounded qualification spike before production implementation.

### Stage 1 — Product and configuration contract

Specify the exact supported TrailBase app envelope, cluster configuration, release manifest, capability advertisement, secret references, database inventory, fencing interface, ingress interface, and error model. Include upgrade and rollback compatibility rules.

### Stage 2 — Installable single-controller `manual-async`

Package node agent, controller/CLI, restore oracle, systemd units, configuration validation, installer, upgrader, rollback, and status output. Retain the single controller initially but label it as a control/ingress SPOF.

### Stage 3 — Disposable qualification

On fresh disposable VMs, prove installation, bootstrap, steady replication, lag/refusal behavior, planned switchover, old-writer fencing, accepted-loss crash recovery, ingress transition, cold rejoin, reboot behavior, disk exhaustion, storage outage, and interrupted upgrades. Do not qualify on the persistent demo first.

### Stage 4 — Supported `manual-async` release

Publish the precise operating envelope, RPO wording, runbooks, compatibility matrix, install/upgrade/rollback procedures, evidence format, and unsupported features. Require operators to supply and qualify their own fence, ingress, storage, and secret integrations.

### Stage 5 — Distributed authority and `automatic-async`

Remove the controller/ingress single point of failure with a separately designed quorum/common-authority system. Automatic promotion still permits recent acknowledged-write loss and still requires terminal fencing proof.

### Stage 6 — Optional D4 durability profiles

After upstream instrumentation or an approved fork provides the missing observations, add `durability-gated` and possibly `strict` profiles without changing the baseline `manual-async` contract.

## 8. MVP acceptance criteria

The first product release is acceptable only when:

- installation and rollback work from a clean supported host;
- configuration rejects undeclared databases and incompatible artifacts;
- one writer and at least one standby run for a sustained qualification period;
- planned switchover succeeds from a clean operation in one pass;
- unplanned promotion refuses until external fencing is terminal;
- crash recovery publishes the exact recovered cut and possible-loss interval;
- auth/session, main, aux, and every declared attached database pass independent restore acceptance;
- old writer data is quarantined and rejoin starts from a clean reseed;
- every timeout and partial operation has a documented, tested disposition;
- ingress never routes to an ineligible candidate;
- upgrade interruption and rollback are tested;
- documentation makes no zero-loss, automatic-HA, or universal-app claim.

## 9. Explicit non-goals for the first release

- zero acknowledged-write loss;
- synchronous replication;
- automatic election or failover;
- multi-region active/active;
- automatic discovery of every app mutation surface;
- local uploaded-file HA without a separate storage design;
- transparent support for undeclared jobs, extensions, or attached databases;
- production availability percentages before repeated load/fault qualification.

## 10. Next discussion

The immediate next task is to define the exact replicated-versus-local state boundary and versioned protocol contracts in the [approved Rust architecture](2026-09-10-rust-ha-architecture-design.md). Then run the bounded OpenRaft, bundled-SQLite, mTLS, restart, snapshot, and crash-consistency spikes. No production implementation should begin until those spike acceptance criteria and security boundaries are approved.
