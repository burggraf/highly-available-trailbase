# M1 Ubuntu provisioning and Linux parity (sanitized)

**Date:** 2026-09-08  
**Decision:** **NO-GO**

## What passed

The fresh acceptance attempt completed the existing preflight, remote initialization, provisioning, reboot identity, and post-reboot checks on all three disposable Ubuntu 24.04 nodes. It verified:

- pinned TrailBase `v0.33.11` and Litestream `v0.5.17` artifacts, checksums, executable hashes, versions, build, and embedded SQLite;
- exact required-package state;
- writer-service stop/mask state before provisioning; and
- reboot identity plus post-reboot binary, package, and masked/inactive service state.

The M0 work root was disk-backed and directly below the approved boundary, using the short form `/var/lib/hat-qualification/m0-<10-hex-digits>`. The full local run ID, local evidence root, normal remote root, work root, and preflight socket-path set were retained in private evidence. The longest generated socket path was preflighted below Litestream's 100-byte limit. Private inventory, node identities, package versions, evidence, and logs remain outside Git.

The observed node baseline was one CPU, about 984 MiB RAM, and about 19 GiB available root-disk space. No out-of-memory observation was recorded.

## What did not pass

The unchanged M0 workload was attempted once on `fm1`:

```text
python3 experiments/m0/run.py ... --scenario all --repeat 3
```

The workload exited nonzero before writing its aggregate result. Private evidence contains one run and 31 manifest-listed log files, but no complete `result.json`; therefore the exact 13-result aggregate, complete manifest/hash acceptance, and guard acceptance cannot be established. This is a truthful **NO-GO**, not a reduced scenario or repetition count.

The short disk-backed root removed the prior `/run` capacity and socket-path workspace blockers observed during the earlier attempt. The failure in this attempt is not classified as an out-of-memory failure.

All M0 processes were cleaned up by the scoped run/cleanup path, and private partial evidence was retained for inspection. No fixture, scenario, repetition, memory limit, or acceptance guard was changed.

## Decision and next step

Task 4 remains **NO-GO**. The Linux parity qualification cannot be treated as complete because the exact 13-result `all --repeat 3` aggregate and its complete evidence checks did not pass. Task 5 may proceed independently because it qualifies Litestream's S3 backup transport rather than the full M0 matrix.
