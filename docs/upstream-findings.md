# Upstream findings and evidence

Checked: **2026-09-07**. Method: GitHub release API, downloaded release-tag source archives, current official documentation, and issue/PR status. Context7 was used for discovery; release-tag source is the authority for executable behavior. **No end-to-end cluster, release executable, S3/R2 lease, or fault experiment was run in this planning pass.**

## Baseline

| Component | Latest stable release observed | Published | Source commit |
| --- | --- | --- | --- |
| TrailBase | [v0.33.11](https://github.com/trailbaseio/trailbase/releases/tag/v0.33.11) | 2026-09-04 | `f24291b894bb6c6696608e5f4c2f68666fe97686` |
| Litestream | [v0.5.17](https://github.com/benbjohnson/litestream/releases/tag/v0.5.17) | 2026-08-31 | `ccd326c175b583b5e82893a6078f06dcef5fba3f` |

These are a research baseline, not a certified compatible pair. At implementation time fetch the then-current releases, record checksums/platform/SQLite versions, repeat qualification, and pin the resulting artifacts. Do not mix a `main`-branch feature description with a released binary promise.

## L1. Continuous restore exists, with a different flag

[CLI source](https://github.com/benbjohnson/litestream/blob/v0.5.17/cmd/litestream/restore.go#L25-L40) registers `-f` and `-follow-interval`, not `--follow`.

```sh
# Illustrative: real bucket, credentials, prefix and output path must be supplied.
litestream restore -f -follow-interval 1s \
  -o /var/lib/hat/follow/main.db s3://BACKUP_BUCKET/EPOCH_PREFIX/main
```

[Official restore documentation](https://litestream.io/reference/restore/) says follow was introduced in v0.5.9, requires read-only consumers, defaults to polling every second, and cannot combine with a fixed TXID or timestamp. Crash-recovery TXID sidecars were added in v0.5.10. One invocation follows one DB; HAT must coordinate the required set.

Consequences: this is asynchronous, polling-based, per-file replication through remote storage. It is not synchronous commit, transaction forwarding, automatic election, or a cluster-wide commit index.

## L2. Follow mode and promotion need qualification

[Restore/follow implementation](https://github.com/benbjohnson/litestream/blob/v0.5.17/replica.go#L608-L1064):

- Initial restore writes a temporary DB, syncs, and renames it.
- Follow maintains `<database>-txid`, applies newer LTX pages in place, and attempts gap filling from higher compaction levels.
- Existing output requires a usable TXID sidecar. History/snapshot-position checks can reject resumption and require a fresh restore.
- Incremental application changes header bytes 18–19 to DELETE journal mode and randomizes bytes 24–27 (SQLite's file change counter). Do not mistake the source comment's “schema change counter” wording for the actual schema-cookie offset.
- [Unix locking](https://github.com/benbjohnson/litestream/blob/v0.5.17/internal/lock_unix.go) uses SQLite-compatible `fcntl` byte-range locks, with blocking acquisition.
- The loop can log apply errors and keep running; a live process is not proof of a healthy/complete follower.
- Page writes occur before final decoder validation and sync; no SQLite rollback transaction surrounds this apply path. Interrupted/corrupt apply and recovery must be tested before treating the output as safe for readers or promotion. This is a qualification concern, not a demonstrated corruption claim.

Tests include [basic follow and recovery](https://github.com/benbjohnson/litestream/blob/v0.5.17/replica_test.go#L2061-L2475); this does not establish correctness with TrailBase connection pools, ongoing long reads, abrupt kill mid-page-write, DDL, or promotion. Do not use SQLite `immutable=1` on a changing follower: it bypasses assumptions required for safe concurrent mutation/visibility.

The initial snapshot's journal behavior, read-connection caching, WAL/SHM absence, lock starvation, follow stop latency, incomplete LTX reads, shrinking/page-size changes, and crash sidecar ordering all belong in M0 experiments. Any anomalous file set is rebuilt in a clean directory, not opened writable on faith.

## L3. Distributed leasing is library infrastructure, not CLI HA

[Leaser interface](https://github.com/benbjohnson/litestream/blob/v0.5.17/leaser.go) and [S3 implementation](https://github.com/benbjohnson/litestream/blob/v0.5.17/s3/leaser.go) exist:

- Key: `<Path>/lock.json`; default TTL: 30 seconds.
- New acquisition: `PutObject` with `If-None-Match: *`.
- Expired takeover and renewal: `PutObject` with `If-Match: <etag>`.
- Release: `DeleteObject` with `If-Match: <etag>`.
- Body: generation, expiry, owner. Default owner is hostname/PID based.
- Expiration uses local wall-clock time. Generation increments on takeover of an existing object but resets to 1 when no lock exists.

Source search found no production wiring from the released `replicate` CLI into these lease methods. As checked:

- [Issue #1301](https://github.com/benbjohnson/litestream/issues/1301), expose leasing in replication lifecycle: **open**.
- [PR #1317](https://github.com/benbjohnson/litestream/pull/1317), standalone `s3lease` subprocess runner: **open, unmerged**.

Do not publish a fictional `lease:` YAML field or assume `replicate -exec` acquires a lease. An upstream merge could reduce HAT work, but subprocess supervision alone still would not establish independent fencing, multi-DB consistency, routing, or RPO.

## L4. Replication process supervision and explicit flush are useful building blocks

[`replicate -exec`](https://github.com/benbjohnson/litestream/blob/v0.5.17/cmd/litestream/replicate.go) can start a subprocess. HAT should reuse existing mechanisms where their shutdown/error semantics satisfy its process contract; it still must manage the lease, all followers, readiness, and fencing.

[`sync -wait`](https://github.com/benbjohnson/litestream/blob/v0.5.17/cmd/litestream/sync.go) requests immediate sync through the running process's IPC endpoint and waits through remote replication. Qualify its exact success/position semantics and IPC setup for each DB before using it as switchover evidence. It is not an automatic acknowledgement barrier for TrailBase HTTP writes, nor an atomic flush of multiple DBs.

Litestream [creates `_litestream_lock`](https://github.com/benbjohnson/litestream/blob/v0.5.17/README.md#source-database-changes) in a source DB. Allow its intended schema effect, do not expose it as an application API, and do not expect byte identity with a never-replicated DB. Do not run outbound replication against follower-owned files.

## S1. S3 and R2 require distinct qualification

- AWS documents [conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html) and [conditional deletes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-deletes.html). Use the exact tested API/bucket type and permissions.
- R2 documents [strong read/write/delete/list consistency](https://developers.cloudflare.com/r2/reference/consistency/) for direct APIs. Its permission changes are eventually consistent (potentially up to a minute), so credential revocation is not an immediate fence.
- R2's [S3 compatibility table](https://developers.cloudflare.com/r2/api/s3/api/) lists conditional `PutObject` support. Its `DeleteObject` row does not explicitly establish conditional-delete support. **Test stale-ETag release behavior; do not infer equivalence from “S3-compatible.”**
- Conditional create/update/delete must be tested under contention, expired takeover, stale renewal/release, and a successful request whose response is lost.
- Cached public R2 domains relax observable consistency. Never use them for lock/activation/backup control traffic.

If required conditional-delete behavior is absent, do not replace it with unconditional delete. Options to evaluate: an independently reviewed CAS-only release/tombstone protocol, a different coordination backend, or excluding that provider from automatic HA. A protocol change must account for generation, ownership, and publication semantics.

## T1. TrailBase-specific evidence

See [TrailBase state and behavior](trailbase-state.md) for the release-pinned source inventory, startup-write blockers, actual DB filenames, auth/session state, object storage, jobs, and realtime behavior. Its read-only findings must be considered alongside L2; neither tool's individual feature list proves the combined system is safe.

## Additional foundational references

- [SQLite atomic commit and multi-file transactions](https://www.sqlite.org/atomiccommit.html#multi_file_transactions).
- [SQLite WAL limitations](https://www.sqlite.org/wal.html): attached-database transactions are atomic within each DB, not across the set in WAL mode.
- [SQLite URI `immutable` semantics](https://www.sqlite.org/uri.html#uriimmutable).
- [TrailBase production/SSE guidance](https://trailbase.io/documentation/production/).

Follow these with targeted source review and experiments; documentation is evidence of an intended contract, not a substitute for failure testing.
