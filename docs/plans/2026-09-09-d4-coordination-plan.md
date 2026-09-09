# D4 Isolated Coordination Implementation Plan

> **REQUIRED SUB-SKILL:** Use the executing-plans skill to implement this plan task-by-task.

**Goal:** Establish a reproducible, isolated coordination baseline before changing HAT authority or enabling automatic actions.

**Architecture:** Use three real etcd members and the official matching `etcdctl`, outside the running VPS deployment. Qualify each prerequisite separately; a successful key transaction is not proof of safe TrailBase promotion. Keep the approved strict acknowledged-write preservation policy and the current manual deployment unchanged.

**Tech Stack:** Official etcd v3.7.1 candidate, Docker Linux/arm64 on the operator workstation, official `etcdctl` v3, existing Python standard-library test suite. Release selection is provisional pending qualification, not an installation recommendation for A/B/C.

---

## Scope and checkpoint

The owner approved the recommended staged path after reviewing the D4 proposal. Start with local, isolated coordination checks only. No VPS service changes, real fencing, ingress replacement, automatic activation, acknowledgement-policy relaxation or old experiment-runner execution.

First checkpoint: at most 30 minutes of active work on the native baseline, then report evidence and gaps before expanding the slice. Stop on unexpected effects or an unresolved infrastructure failure. Preserve every attempt. Keep `main` and the existing D3 deployment intact; this first slice changes documentation and private lab artifacts only, not application code. A feature worktree is to be selected before implementation changes to HAT.

The existing proposal remains the architecture reference. Its staged approach and strict-loss policy are approved; individual rollout/timing decisions and mutating automatic capabilities are not.

## Checkpoint disposition

The first run established native three-member health but stopped on transaction stdin EOF. Focused diagnosis then found that the pinned `etcdctl txn` uses `context.Background()` and did not honor the tested command deadline. See `2026-09-09-d4-coordination-baseline.md`. Tasks below retain the original test sequence as history; transaction, lease and quorum-loss tasks are not marked complete. Before another run, qualify the official Go v3 client's explicit context/ambiguous-result contract and exact client-process cleanup. No HAT implementation begins at this checkpoint.

### Independent review and next-client exit criteria

Review `e3b3f6ac-e24f-43d9-aff6-bed29cb96650` permits isolated official-client qualification, not HAT integration. Add these explicit checks before expanding the native sequence:

1. An unavailable endpoint returns a bounded explicit-context error. Record actual elapsed time, not just the configured timeout.
2. A real transaction commits while its response is deliberately withheld at a test-only client boundary until the context expires. Require the caller to receive an uncertain timeout and an independent witness to observe the exact committed operation ID. Count actual sends and forbid retry. This is a controlled response-loss model, not network-partition qualification.
3. Do not infer non-commit from timeout or a temporarily absent readback. The withheld-response test proves the positive ambiguous-commit case only; unresolved production outcomes must retain their pending intent.
4. Preserve client/server lifecycle evidence. All keys, certificates, binaries and processes are disposable lab resources; HAT APIs, provider actions and the running deployment remain inaccessible to this test.

Passing these checks qualifies neither `Journal` nor fencing, promotion, zero RPO, HA ingress or the 120-second objective. Subsequent gates remain mandatory.

**Focused follow-up result:** the official-client explicit-deadline and committed-response-withheld checks passed in a fresh single-member lab, with an expected failing negative control. Exact observations and limitations are in `2026-09-09-d4-coordination-baseline.md`. Subsequent isolated contention, basic lease-expiry, quorum-loss, client/peer TLS and scoped-permission checks also passed, with a preserved SDK permission-error classification correction. Remaining gates include renewal/paused-holder/watch behavior, certificate lifecycle, representative resources and all HAT-specific authority/fencing/data/ingress obligations. See the baseline report; these are not automatic-HA acceptance results.

## Task 1: Record environment and pin the native candidate

**Files:**
- Update: `docs/plans/2026-09-09-d4-coordination-plan.md` with the checkpoint result.
- Private evidence only: `~/.config/hat/d4-qualification/<unique-run>/` (0700).
- No changes: `hat/`, `deploy/`, `experiments/`, or live configuration.

1. Record clean application baseline and current local tooling:
   ```sh
   git status --short
   git rev-parse HEAD
   docker version --format '{{json .}}'
   ```
   Expected: application HEAD `a46bd28…`; only D4 planning documents differ; local Docker engine available.
2. Read the official release metadata and supported-platform/release notes. Current discovery: GitHub identifies v3.7.1 as a non-prerelease, published 2026-07-23. Reference: https://github.com/etcd-io/etcd/releases/tag/v3.7.1 . Do not execute the example cleanup commands.
3. Pull `gcr.io/etcd-development/etcd:v3.7.1` using the process tool. Inspect its resolved digest, Linux architecture and image ID. Save raw output; use the immutable resolved image for every member, not a mutable tag.
4. Run the image's `etcd --version` and `etcdctl version` in short-lived, named, network-disabled containers. Assert the actual version before continuing. Do not interpret an available Docker client as a running server or a successful pull as a binary check.

## Task 2: Start a three-member disposable baseline

**Files:**
- Private manifest: `<run>/manifest.json` — image identity, exact container/network names, commands and data paths.
- Private member data/logs: `<run>/{a,b,c}/` and command outputs.

1. Allocate one unique internal Docker network and three private data directories; refuse pre-existing names/paths. No published host ports, host networking, Docker socket mount, production secrets or restart policy.
2. Start one foreground `docker run` per member through the process tool, with an explicit name, private bind-mounted data directory, immutable image and these server arguments (substitute exact recorded names):
   ```text
   /usr/local/bin/etcd
   --name a
   --data-dir /etcd-data
   --listen-client-urls http://0.0.0.0:2379
   --advertise-client-urls http://<a-container>:2379
   --listen-peer-urls http://0.0.0.0:2380
   --initial-advertise-peer-urls http://<a-container>:2380
   --initial-cluster a=http://<a-container>:2380,b=http://<b-container>:2380,c=http://<c-container>:2380
   --initial-cluster-token <unique-run>
   --initial-cluster-state new
   ```
3. Use bounded readiness checks and record `etcdctl --write-out=json endpoint status` / `endpoint health` for all three endpoints. Assert three distinct member IDs and a common cluster ID/version. Preserve failed probes; no indefinite retry loop.
4. Explicit limitation: this initial private plaintext network tests native coordination only. It does **not** qualify TLS, access control, VPS isolation, disk headroom, or production topology.

## Task 3: Exercise actual transaction exclusion

**Private evidence:** exact stdin, arguments, return codes and JSON responses for each command.

1. Use `etcdctl txn --help` from the pinned image to verify its installed command contract.
2. Run the same transaction twice against a unique lab key:
   ```text
   version("/hat-lab/owner") = "0"

   put /hat-lab/owner owner-a

   get /hat-lab/owner
   ```
   **Native correction:** the final `get` line must be followed by an additional newline, terminating the final section with a blank line. Without it the pinned CLI exits 3 / EOF before committing. This fixes framing only, not the separate transaction-deadline gap described above.
   Expected first response: `succeeded=true`; second: `succeeded=false`, owner unchanged. A command's exit code alone does not prove the comparison succeeded.
3. Submit competing transactions from two client processes to another unused key and assert exactly one success. Save both responses and read back the winner.
4. Compare against the wrong existing value/revision and assert refusal with no change. These are native coordinator checks, not a HAT fencing-token implementation.

## Task 4: Lease expiry and durable intent separation

1. Grant a short lab lease using the pinned command; obtain its ID from the actual documented output. Do not silently confuse JSON decimal IDs with CLI hexadecimal IDs.
2. Attach a lab owner key to that lease and write a separate unleased pending-intent key.
3. Read both keys successfully, then allow the lease to expire without renewal. With a bounded observation deadline, require deletion of the owner key while the intent remains.
4. Attempt a transaction comparing the expired owner value; assert refusal. This demonstrates why HAT's pending effects cannot be stored only in lease-attached keys.
5. Keep-alive loss, paused holders, stale successful responses, watch reconnect/compaction and ambiguous transaction results remain separate qualification cases; this expiry test does not stand in for them.

## Task 5: One-member versus quorum loss

1. Stop exactly one recorded lab member. Require a new conditional write/read through the two survivors to succeed after bounded election readiness.
2. Stop a second recorded member. With explicit client deadlines, require a linearizable read and a write through the remaining member to fail. Do not use serializable reads to claim current authority.
3. Record timeouts as unavailable/uncertain outcomes, not proof that every submitted request was cancelled. Do not reissue an uncertain effect as a retry.
4. Stop the last lab member. Save container inspection, logs, manifests and data; verify all three are stopped and no host ports were published. Do not remove evidence or touch unrelated containers/networks.

## Task 6: Checkpoint, not automatic promotion

1. Summarize exact commands/results and unresolved cases in a sanitized report at `docs/plans/2026-09-09-d4-coordination-baseline.md`. Keep raw outputs privately.
2. Confirm the checkout contains no HAT runtime changes. Local/native tests alone do not authorize live rollout.
3. Obtain bounded independent review of the design and baseline evidence scope before writing the HAT authority adapter.
4. Next tasks, only after that review: authenticated client/peer TLS and permissions; ambiguous responses and lease lifecycle; supported VPS resource checks; durable effect/boot fencing contract; strict ACK preservation source; redundant private ingress. Do not code around any unresolved safety contract.
5. Only after these gates: write a failing HAT authority-admission test, implement the smallest supported adapter, run native integration and review it. Preserve the D2/D3 direction/history behavior while separating operation kind from direction. No automatic mutating controller is part of this initial plan.

## Acceptance statement

A passing initial baseline means only: the pinned real coordinator/client can establish exclusive ownership, expire a lease without erasing durable intent, and distinguish one-member loss from quorum loss in this isolated environment. It does not prove single-writer TrailBase safety, zero RPO, a two-minute RTO, stale provider-action cancellation, or HA ingress.
