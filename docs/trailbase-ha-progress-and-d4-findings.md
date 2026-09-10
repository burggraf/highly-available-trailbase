# TrailBase HA progress and D4 findings

This report summarizes what the HAT project has demonstrated, what its D4 investigation learned about stock TrailBase v0.33.11, and how close it is to a useful public HA system.

## ELI5 summary

Think of the system as two shops and a traffic cop:

- **A and B** are two copies of the TrailBase shop.
- **C** is the traffic cop directing customers to the active shop.
- **Litestream** continuously ships copies of the shop's ledgers elsewhere.
- **HAT** is the safety procedure for deciding when another shop may open.

## What we have accomplished

### D0 — We mapped the system

We identified every machine and service; where the three TrailBase databases live; how replication, routing, authentication, and credentials work; and which actions are observational versus dangerous. This gave us a reliable map instead of guessing.

### D1 — We built and verified a standby

We demonstrated one active TrailBase writer, a separate same-epoch standby, replication of all three databases, independent restoration of records and authentication state, and private guarded services and ingress.

In simple terms: **the backup shop can receive fresh copies, and we can independently prove those copies are usable.**

### D2 — We performed a planned handover

We safely moved service from A to B using ingress closure, durable operation journaling, source quiescing, physical/provider fencing, independent restore checks, fresh epochs, guarded activation, stable routing, and verification before reopening.

The operation encountered real failures, but we recovered through explicit, non-replaying reconciliation. The procedure therefore survived imperfect reality instead of only passing a happy-path simulation.

### D3 — We recovered from loss of the writer

We demonstrated a real operator-controlled recovery:

- B was lost/offline;
- a safe recovery point was selected;
- A was restored and activated in a new epoch;
- all **51 acknowledged test writes** were recovered;
- no acknowledged test writes were missing;
- 87 unacknowledged requests correctly remained unknown rather than being invented as successes or failures;
- B was rebuilt as a clean standby;
- records and authentication were independently restored again.

Observed availability loss was bracketed at roughly **68 seconds**, but that is one measurement, not a universal RTO guarantee.

### Safety hardening

We built durable operation intents and outcomes, no blind replay after uncertain effects, exact phase ordering, exact writer/epoch/route/evidence bindings, process and boot identity checks, private-file and symlink protections, fencing and maintenance gates, explicit reconciliation paths, fail-closed process-cleanup uncertainty, and tests for malformed, stale, reordered, duplicated, and substituted evidence.

At the current repository checkpoint, 31 focused route-authority tests, 115 D4 tests, and 115 runtime tests passed. These are source/test results, not fresh live-deployment qualification.

## What D4 taught us

D4 asked a harder question:

> Can a machine automatically decide that failover is safe while clients are actively writing?

For stock TrailBase v0.33.11, the answer is currently **no—not with the proof standard we chose**.

### 1. An HTTP success is not durable-recovery proof

TrailBase may successfully commit locally and return HTTP 200 before Litestream has produced an independently recoverable copy. Therefore, "the client received success" does not necessarily mean "another machine can recover that write."

Our external ledger cannot fully solve this because it is not on every possible client path, is written after receiving the response, can lose the outcome if the process crashes between response receipt and persistence, and does not cover every data, authentication, admin, or background mutation.

### 2. A timeout does not mean nothing happened

Our experiments proved this directly. We deliberately lost responses after TrailBase had accepted a mutation and after Litestream had completed synchronization. The caller saw a timeout, but the operation had happened.

An automatic controller therefore must not blindly retry timed-out writes. It must retain them as **uncertain** until independently settled.

### 3. Litestream has useful primitives, but not a complete ACK contract

`sync -wait` can synchronize and wait for replica progress. We proved that exact records could then be independently restored.

Its result is not naturally bound to one specific HTTP mutation, a HAT operation, a writer incarnation, an epoch, the complete set of affected databases, client receipt of the response, or an independent remote read-back. It is a promising building block, not a complete HA guarantee.

### 4. TrailBase uses multiple databases and mutation surfaces

Important state can exist in the main, sessions/auth, and auxiliary databases, as well as admin/configuration paths, jobs, plugins, custom routes, or direct database access. There is no global transaction covering all of them.

We successfully proved narrow operations such as main/aux creation and single-token logout, but that does not automatically cover login, refresh, deletion, updates, account changes, admin actions, uploads, jobs, or extensions.

### 5. Stock TrailBase cannot expose everything we must observe

This was the decisive D4 blocker. Stock TrailBase does not expose an independent, complete inventory of every effective runtime route, job, plugin, custom handler, listener, or every reader/writer of `logs.db`.

Configuration, OpenAPI, logs, source inspection, file descriptors, and self-reporting each show part of the picture, but none proves completeness. Without completeness, we cannot honestly say that every possible mutation passed through our durability gate.

Closing this likely requires TrailBase instrumentation, a maintained fork, upstream-supported hooks, or a different architecture with synchronous durability below TrailBase.

### 6. Automatic authority is still missing

We do not yet have one distributed authority governing automated promotion, manual activation, fencing, routing, stale controller responses, provider requests that complete late, and reused VM incarnations. A future automatic controller cannot be safe if an older manual command can bypass it.

### 7. The topology itself is not highly available

C remains the ingress node, controller, coordination dependency, and a single point of failure. We also have not qualified real capacity, independent physical fault domains, asymmetric network partitions, whole-host pauses, certificate rotation/revocation, or sustained production load.

## How close are we?

### Close to a worthwhile experimental release

We are reasonably close to publishing something honest and useful as:

> **A fail-closed, operator-controlled TrailBase recovery and switchover toolkit with independently verified restores.**

That would be valuable because it includes real recovery experience, conservative uncertainty semantics, fencing and anti-replay behavior, authentication restoration checks, explicit failure history, and a detailed explanation of why automatic HA is harder than health checks plus routing.

Before publishing that first release, the remaining bounded work is:

1. a unified restore-acceptance manifest/schema;
2. one fresh, reproducible disposable-infrastructure demonstration;
3. installation and configuration packaging;
4. public documentation with private-environment assumptions removed;
5. an explicit threat model and supported failure model.

That is a bounded path to an **experimental/manual HA or disaster-recovery release**.

### Not close to production automatic HA

For a claim such as "TrailBase automatically fails over without losing acknowledged writes," we are still in the architecture stage, not the polishing stage.

The major remaining pieces are:

1. a complete mutation and acknowledgement boundary;
2. synchronous or independently provable recoverability;
3. TrailBase instrumentation/forking or an alternative storage architecture;
4. distributed authority covering manual and automatic actions;
5. provider late-effect settlement;
6. redundant ingress/control;
7. partition, capacity, certificate, and fault-domain qualification.

These are fundamental contracts, not missing convenience features.

## Honest assessment

- **Publishable research/prototype:** nearly there.
- **Useful operator-controlled recovery product:** within a few substantial milestones.
- **Automatic failover with bounded data-loss claims:** significantly farther away.
- **Production-grade, zero-acknowledged-write-loss HA:** not achievable honestly with the current stock TrailBase/Litestream interface alone.

The strongest initial public project would sell honesty rather than magic:

> **HAT gives TrailBase conservative, independently verified manual recovery—and refuses when safety cannot be proven.**

That is already differentiated and worthwhile. Automatic HA can follow only after the architecture supplies the missing proof.
