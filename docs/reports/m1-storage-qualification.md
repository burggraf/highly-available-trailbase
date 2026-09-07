# M1 storage qualification (sanitized)

**Run:** `20260907T202507Z-63437eb227`  
**Date:** 2026-09-07  
**Decision:** **NO-GO** (exit `2`)

## Provenance

The live matrix was run against the private S3-compatible environment file
`~/.config/hat/m1-idrivee2.env`:

```text
python3 experiments/m1/run.py storage \
  --s3-env ~/.config/hat/m1-idrivee2.env \
  --work-root ~/.config/hat/m1-storage-runs
```

Credentials, endpoint, bucket, and private payloads are not included in this
report. The complete mode-`0600` JSONL evidence is outside Git at the path in
`~/.config/hat/m1-latest-storage-evidence`; the pointer itself is mode `0600`.

## Matrix result

- Ordinary unconditional `PUT` completed and its `GET`/`HEAD` bytes, SHA-256
  values, and ETags matched.
- Ordinary unconditional `DELETE` completed with HTTP `204`; subsequent
  `HEAD` and `GET` both returned `404`.
- Conditional create/replace and race operations were exercised with their
  request conditions recorded in evidence.
- Stale conditional `DELETE` was incorrectly accepted (`204`) and removed the
  replacement; missing conditional `DELETE` was also accepted (`204`).
- The create race produced more than one successful winner.
- Fresh-prefix objects and local evidence were preserved; cleanup was not
  requested and was not performed.

The capability gate therefore remains **NO-GO** until conditional DELETE and
race semantics are corrected by the provider. No cleanup command was run and
no push was performed.
