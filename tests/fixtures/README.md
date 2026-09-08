# Pinned Litestream logs

`litestream-0.5.17-replicate.jsonl` contains real v0.5.17 records from the D1 uploader and followers, with infrastructure paths/addresses and timestamps redacted. Duplicate JSON `level` keys and nested TXIDs are intentionally preserved.

Source contracts: [store.go](https://github.com/benbjohnson/litestream/blob/v0.5.17/store.go) and [db.go](https://github.com/benbjohnson/litestream/blob/v0.5.17/db.go), especially `EnforceL0RetentionByTime`.

`retention.enabled=false` skips remote deletion, not local L0 cleanup. The INFO `l0 retention enforced` event reports an integer candidate count and a hexadecimal `max_l1_txid`; it does not prove every local removal succeeded. Separate error records still fail the gate. This fixture is parser regression evidence, not backup integrity or failover evidence.
