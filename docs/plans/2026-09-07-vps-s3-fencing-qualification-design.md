# VPS, S3, and fencing qualification design

Date: 2026-09-07
Status: approved design for a bounded private qualification

## Goal

Qualify the current pinned TrailBase/Litestream premise on three disposable Ubuntu VPSs using real IDrive e2 S3-compatible storage and independently completed Linode power fencing before building the HAT supervisor.

This is deployment-specific evidence, not a provider certification or production HA claim.

## Topology

- `fm1`: source writer and Litestream uploader.
- `fm2`: continuous data-hot follower and promotion candidate.
- `fm3`: independent verifier, fencing initiator, and clean-reseed target.

Use TrailBase v0.33.11 and Litestream v0.5.17. Keep experiment state under `/var/lib/hat-qualification`. Install only required Ubuntu packages. Inject credentials through root-only files, never command arguments or committed configuration, and remove VPS copies after the round.

Use unique run and epoch prefixes in the dedicated private bucket. Separate Litestream histories, conditional-operation probes, and activation/fence evidence. Never reuse a prefix or automatically delete failed evidence.

## Gates

### 1. Linux baseline

Run the existing three-database M0 fixture on Ubuntu. Cover continuous following, graceful promotion, crash recovery, fresh epoch creation, authentication continuity, clean reseed, and refusal controls. Record exact binary and embedded SQLite versions and checksums on each participating node.

### 2. S3 compatibility

Test ordinary PUT, GET, HEAD, LIST, and DELETE plus conditional create, replacement, and deletion using `If-None-Match`, `If-Match`, current, stale, and missing ETags. Race simultaneous contenders. Simulate lost responses and require reconciliation by rereading authoritative state. Verify Litestream continuously replicates and restores all required databases through IDrive e2, then establishes a fresh epoch and clean standby.

### 3. Fence behavior

Have fm3 request fm1 shutdown through the Linode API. Completion requires the provider to report the exact instance offline plus independent application unreachability. An accepted request, SSH failure, or stale observation alone is insufficient. Exercise failed, timed-out, duplicate, and already-offline requests. Unknown outcomes prohibit promotion.

### 4. Old-node safety

After fm2 promotion, boot fm1 with writable services disabled. Preserve and quarantine its old state. It must not mutate the old or current epoch. It may rejoin only from a clean restore of fm2's new epoch.

## Safety and refusal policy

Immediately fail the qualification on a second writer, shared-prefix mutation, missing required database, corrupt restore, uncertain fence, unexpected process exit, or unresolved acknowledged operation. There is no force-promote bypass.

The coordinator owns every process it launches and verifies node/boot identity before disruptive operations. It records provider request and completion evidence. Failed run directories remain intact; uncertain runs are never resumed.

## Evidence

Keep private, fsynced JSONL ledgers for commands, client operations, S3 requests/responses and ETags, fence observations, process exits, boot identities, timings, and artifact references. Compare exact business keys and payload hashes, schema, integrity, authentication outcomes, and all required databases.

Publish only sanitized aggregate results. Do not publish credentials, addresses, account or instance IDs, raw authentication/session rows, private logs, or hosting-specific integration code.

## Implementation approach

Use a small local Python standard-library coordinator and minimal VPS-local shell/Python helpers. Add pure tests for S3 and fence response classification and promotion guards before live probes. Reuse the M0 fixture and safety helpers rather than creating a controller framework. This round qualifies dependencies; it does not implement automated election or the production supervisor.
