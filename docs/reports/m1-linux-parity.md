# M1 Ubuntu provisioning and Linux parity (sanitized)

**Date:** 2026-09-08  
**Decision:** **NO-GO**

## What passed

All three disposable Ubuntu 24.04 nodes passed:

- pinned TrailBase `v0.33.11` and Litestream `v0.5.17` artifact, checksum, executable-hash, version, build, and embedded-SQLite checks;
- exact required-package state checks;
- writer-service stop/mask checks before provisioning; and
- reboot identity plus post-reboot binary, package, and masked/inactive service checks.

Private inventory, node identities, package versions, evidence, and logs remain outside Git.

## What did not pass

The required unmodified M0 command never produced the complete 13-result `all --repeat 3` PASS aggregate on the 1 GB VPS:

```text
python3 experiments/m0/run.py ... --scenario all --repeat 3
```

Two workspace constraints were observed:

1. The default `/run` tmpfs was about 97 MiB. M0 produced roughly 250 MiB of working data and logs, filled that filesystem, and stopped with `No space left on device`.
2. Moving the working data under the disk-backed qualification root avoided tmpfs exhaustion, but the longer nested path exceeded M0's conservative Litestream Unix-socket path bound during a later scenario. The preserved diagnostic was `BLOCKED: Litestream socket path is too long`.

Neither failure demonstrates that 1 GB of RAM is insufficient: no out-of-memory failure was observed. It also does not prove that 1 GB is sufficient, because the full workload did not complete.

No fixture, repetition, scenario, or acceptance check was reduced. Partial evidence was retained privately. After investigation, no qualification process remained running and both writer services were masked and inactive on every node.

## Decision and next step

Task 4 is a completed **NO-GO qualification**, not a successful Linux parity result. It does not authorize relying on Ubuntu parity for supervisor implementation.

Task 5 may proceed independently because it qualifies Litestream's S3 backup transport rather than the full M0 matrix. If Task 4 is revisited, use one deliberately short, fresh, disk-backed path under the approved `/var/lib/hat-qualification` boundary, check the final socket paths before execution, and run the unchanged command once. Change this decision to GO only after the exact 13-result repeat-3 aggregate and its complete log manifest pass.
