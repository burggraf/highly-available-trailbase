# Highly Available TrailBase (HAT)

An early-stage project for a single-writer [TrailBase](https://github.com/trailbaseio/trailbase) cluster, using [Litestream](https://github.com/benbjohnson/litestream) continuous backup and continuous restore through S3-compatible object storage.

**No production-ready HA deployment is provided.** A bounded local qualification harness now exists; the remaining documents describe the intended system, feasibility gates, and work required.

## Start here

- [Master plan](docs/plans/2026-09-07-master-plan.md): goals, decisions, alternatives, milestones, and questions.
- [M0 local experiment](experiments/m0/README.md) and [result report](docs/reports/m0-local-failover.md): runnable local follow-to-writer qualification and sanitized results.
- [M0 execution plan](docs/plans/2026-09-07-m0-local-failover-execution-plan.md): the implemented task/check specification.
- [Upstream findings](docs/upstream-findings.md): version-pinned evidence and important limitations.
- [Architecture and failover protocol](docs/architecture.md): roles, fencing, replication history, promotion, and recovery.
- [TrailBase state and application behavior](docs/trailbase-state.md): databases, authentication, storage, realtime, and jobs.
- [Deployment and storage contract](docs/deployment.md): per-node setup, S3/R2 layout, credentials, and operations.
- [Work and issue register](docs/work-register.md): what to build, blockers, tests, and deferred capabilities.

## Initial direction

**Provider-independent cloud VMs/VPSs first.** Hosting-provider selection, SDKs, adapters, account details, and provisioning stay outside this repo. HAT defines portable deployment requirements and an operator-supplied fencing contract; no hosting provider needs to be chosen now.

One primary; one or more continuously restored standbys; stable HA ingress; shared S3/R2 application object storage. Read offloading is optional and disabled until genuine read-only operation is demonstrated.

**Safety policy chosen:** automatically promote only when fencing is proven and a defined data-loss budget is satisfied; otherwise require operator review. Neither manual approval nor a lease permits overlapping writers.

Important qualifications:

- Asynchronous backup can lose acknowledged writes. This is not synchronous replication or a zero-RPO design.
- In Litestream **v0.5.17**, continuous restore is spelled `litestream restore -f`; `--follow` is not a registered flag. S3 leasing exists as library infrastructure, not integrated CLI failover.
- A lease is not a fence: it does not itself stop an old TrailBase process, its jobs, or its object-store writes.
- Multiple database files do not acquire a shared transactional restore point merely by using the same bucket.
- TrailBase v0.33.11 opens databases writable and performs startup writes. A data-hot standby can follow with TrailBase stopped; a service-hot, query-serving standby needs upstream read-only support or a separately approved design.

Qualification baseline: **2026-09-07**, TrailBase **v0.33.11**, Litestream **v0.5.17**. Recheck upstream before further implementation and pin tested binaries rather than deploying a moving `latest` tag.

Licensed under the [Apache License 2.0](LICENSE).
