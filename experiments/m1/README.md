# M1 safe VPS preflight and remote initialization

This standard-library harness performs a read-only preflight against exactly three private inventory nodes and a separately explicit mutating `init-remote` phase. SSH and SCP always use a freshly built `known_hosts` containing only the inventory's pinned Ed25519 keys.

## Private setup

`~/.config/hat/m1-inventory.json` and `~/.config/hat/m1-linode.env` must be owned by the current user, have mode `0600`, and live below a private parent directory. The env file contains exactly `export LINODE_TOKEN=...`, `export HAT_FM1_LINODE_ID=...`, `export HAT_FM2_LINODE_ID=...`, and `export HAT_FM3_LINODE_ID=...`; the token is parsed but never returned or recorded. Inventory names must be `fm1`, `fm2`, and `fm3`, with unique provider IDs, addresses, and pinned `SHA256:` fingerprints. Each node also has an exact expected `hostname`; hostname duplicates are allowed because they are a fact check, not an identity key.

## Checks

```sh
python3 -m unittest discover -s experiments/m1 -p 'test_run.py' -v
python3 experiments/m1/run.py preflight \
  --inventory ~/.config/hat/m1-inventory.json \
  --linode-env ~/.config/hat/m1-linode.env \
  --work-root /tmp/hat-m1
```

Preflight validates the pinned host key before collection and only reads hostname, boot ID, Ubuntu release, CPU, memory, disk, time synchronization, and outbound TLS. It does not create or change remote state.

After a successful preflight, remote state is created only by the explicit mutating command:

```sh
python3 experiments/m1/run.py init-remote \
  --inventory ~/.config/hat/m1-inventory.json \
  --linode-env ~/.config/hat/m1-linode.env \
  --work-root /tmp/hat-m1
```

`init-remote` verifies the root-owned, non-symlink `/var/lib/hat-qualification` base, atomically creates a unique `0700` run directory, and removes a newly-created directory if verification fails. Failed local runs remain private for inspection.

## Storage qualification

```sh
python3 experiments/m1/run.py storage \
  --s3-env ~/.config/hat/m1-idrivee2.env \
  --work-root ~/.config/hat/m1-storage-runs
```

The storage run uses a fresh unique prefix and records its complete operation matrix—including ordinary unconditional PUT/DELETE, conditional headers, and races—in a mode-`0600` evidence file below the private work root. Provider/request exceptions are recorded as bounded `NO-GO` results. It prints `storage PASS` and exits `0` when all capabilities hold; capability mismatches are fully collected, print `storage NO-GO`, and exit `2`. Fresh local and remote artifacts are preserved by default, including after `NO-GO`; cleanup is explicit opt-in and runs only after an accepted `PASS`:

```sh
python3 experiments/m1/run.py storage \
  --s3-env ~/.config/hat/m1-idrivee2.env \
  --work-root ~/.config/hat/m1-storage-runs \
  --cleanup
```

Each run publishes its local evidence path (and no credentials) to the mode-`0600` pointer `~/.config/hat/m1-latest-storage-evidence`.

## Provider-neutral fencing contract

The operator-owned executable receives `inspect`, `power-off`, or `power-on` plus a temporary JSON target path. It must write exactly one JSON object to stdout. Evidence is accepted only when `action`, the complete `target`, request ID/time, completion time, terminal `state`, and strictly ordered observations are present. Promotion accepts only a fresh exact-target `power-off` completion whose terminal state is `offline`; request acceptance, timeout, malformed output, duplicate observations, identity mismatch, and `running` state fail closed.

The optional non-destructive check validates every inventory target without requesting a power change:

```sh
python3 experiments/m1/run.py fence-inspect \
  --inventory ~/.config/hat/m1-inventory.json \
  --fence-command ~/.config/hat/m1-fence-linode \
  --work-root /tmp/hat-m1
```

The Linode adapter is intentionally operator-private (`~/.config/hat/m1-fence-linode`), maps only the three IDs in the private env file, and never places the token in arguments or output.
