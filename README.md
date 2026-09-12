# Highly Available TrailBase (HAT)

An early-stage project for a single-writer [TrailBase](https://github.com/trailbaseio/trailbase) cluster, using [Litestream](https://github.com/benbjohnson/litestream) continuous backup and continuous restore through S3-compatible object storage.

**No production-ready HA deployment is provided.** A bounded local qualification harness and one partial disposable VPS probe exist; the remaining documents describe the intended system, feasibility gates, and work required.

## Current development — Rust V1

**Active scope:** one controller, primary-only proxies, manual fenced failover; no Raft or replica reads. **Current stage: Task 9E local node boundary contract accepted; native HAT qualification remains blocked.** Tasks 2 through 9E are accepted only for their recorded local boundaries; the Task 9B probe did not qualify the Rust controller/node operation boundary.

- [Active plan and restart handoff](docs/plans/2026-09-11-v1-manual-failover.md#execution-state-and-acceptance) — authoritative stage/acceptance tracker.
- [Development workflow](AGENTS.md) — restart procedure, autonomous stage loop, evidence and approval rules.
- [Current status](docs/status.md) and [Rust usage/limits](rust/README.md).

Tasks 2 through 8 and Task 9C are accepted on `main` for their stated local boundaries. Task 9D adds only a typed, injected local action-adapter contract: the normal server still uses an unavailable adapter and refuses native actions. Task 9E adds only strict in-memory node command/observation envelopes; transport and native execution remain deferred and separately qualified. The Task 9C console is loopback/SSH-tunnel friendly, derives the sole mutation authority from `controller_node` plus local `--node-id`, and shows unknown observations. One bounded, cleaned-up disposable probe used fresh test roots on fm1/fm2 and the checked-out Rust proxy; it did not qualify deployment, fencing, public HTTPS, or native failover/rejoin. See `docs/reports/v1-task9b-*` and `docs/reports/v1-task9c-*`.

Python `hat/`, `tests/`, `experiments/`, existing `deploy/`, and earlier plans are **historical implementation/evidence**, not instructions to resume old live operations or the current Rust roadmap. Preserve them; do not translate them wholesale or treat their checks as Rust qualification.

## Start here

- **[V1 single-controller manual failover plan](docs/plans/2026-09-11-v1-manual-failover.md):** current delivery scope—Rust proxies forward all application traffic to one primary, standbys keep TrailBase stopped, and one controller coordinates manual fenced failover. Raft is deferred; scoped replica reads await qualified TrailBase read-only support. Detailed implementation remains proposed.
- [Offline observation/refusal](docs/observation-only.md): inventory captured evidence without live access or action authorization; existing manual behavior is unchanged.

- [Master plan](docs/plans/2026-09-07-master-plan.md): goals, decisions, alternatives, milestones, and questions.
- [M0 local experiment](experiments/m0/README.md) and [result report](docs/reports/m0-local-failover.md): runnable local follow-to-writer qualification and sanitized results.
- [M1 Ubuntu provisioning and Linux parity report](docs/reports/m1-linux-parity.md): sanitized Task 4 result; the fresh short-root acceptance remains NO-GO because M0 did not produce the exact 13-result aggregate.
- [M0 execution plan](docs/plans/2026-09-07-m0-local-failover-execution-plan.md): the implemented task/check specification.
- [Upstream findings](docs/upstream-findings.md): version-pinned evidence and important limitations.
- [Architecture and failover protocol](docs/architecture.md): roles, fencing, replication history, promotion, and recovery.
- [TrailBase state and application behavior](docs/trailbase-state.md): databases, authentication, storage, realtime, and jobs.
- [Deployment and storage contract](docs/deployment.md): per-node setup, S3/R2 layout, credentials, and operations.
- [Work and issue register](docs/work-register.md): what to build, blockers, tests, and deferred capabilities.

## Background and retained qualification context

**Provider-independent cloud VMs/VPSs first.** Hosting-provider selection, SDKs, adapters, account details, and provisioning stay outside this repo. HAT defines portable deployment requirements and an operator-supplied fencing contract; no hosting provider needs to be chosen now.

One primary; one or more continuously restored standbys; stable HA ingress; shared S3/R2 application object storage. Read offloading is optional and disabled until genuine read-only operation is demonstrated.

**Current V1 safety policy:** operator-triggered promotion only, independently confirmed fencing, validated recoverable state, and explicit acceptance that recent acknowledged writes may be lost. No automatic promotion or overlapping writers. The earlier automatic-failover direction is deferred.

Important qualifications:

- Asynchronous backup can lose acknowledged writes. This is not synchronous replication or a zero-RPO design.
- In Litestream **v0.5.17**, continuous restore is spelled `litestream restore -f`; `--follow` is not a registered flag. S3 leasing exists as library infrastructure, not integrated CLI failover.
- A lease is not a fence: it does not itself stop an old TrailBase process, its jobs, or its object-store writes.
- Multiple database files do not acquire a shared transactional restore point merely by using the same bucket.
- TrailBase v0.33.11 opens databases writable and performs startup writes. A data-hot standby can follow with TrailBase stopped; a service-hot, query-serving standby needs upstream read-only support or a separately approved design.

Qualification baseline: **2026-09-07**, TrailBase **v0.33.11**, Litestream **v0.5.17**. Recheck upstream before further implementation and pin tested binaries rather than deploying a moving `latest` tag.

Licensed under the [Apache License 2.0](LICENSE).
