# Pinned Litestream logs

`litestream-0.5.17-replicate.jsonl` contains real v0.5.17 records from the D1 uploader and followers, with infrastructure paths/addresses and timestamps redacted. Duplicate JSON `level` keys and nested TXIDs are intentionally preserved.

Source contracts: [store.go](https://github.com/benbjohnson/litestream/blob/v0.5.17/store.go) and [db.go](https://github.com/benbjohnson/litestream/blob/v0.5.17/db.go), especially `EnforceL0RetentionByTime`.

`retention.enabled=false` skips remote deletion, not local L0 cleanup. The INFO `l0 retention enforced` event reports an integer candidate count and a hexadecimal `max_l1_txid`; it does not prove every local removal succeeded. Separate error records still fail the gate. This fixture is parser regression evidence, not backup integrity or failover evidence.

## D3 native standby contracts

`d3-native-standby-status.json` captures an actual restoring and healthy status from an isolated Ubuntu component running the pinned Litestream v0.5.17 and D2 node logic. Epoch and sampling time are normalized. `d3-native-follower-argv.json` captures all three native follower argument vectors, with sandbox paths mapped back to the deployment layout; flags and ordering are unchanged.

The component used a copy of `node.py` with only filesystem constants/config paths substituted, an unprivileged account, existing backup read access, and a temporary loopback status listener. It captured 30 samples, reached healthy with three exact followers, and stopped. Two earlier fixture-setup failures (directory umask and missing logs directory) are retained privately. B remained the live writer. This is native producer-contract evidence, **not** unmodified installed-dispatcher, recovery, fencing, or rejoin proof.
