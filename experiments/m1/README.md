# M1 safe VPS preflight

This standard-library harness performs a read-only preflight against exactly the private inventory nodes. It uses OpenSSH argument arrays and a single shell-quoted remote command, creates fresh `0700` local evidence roots, and writes redacted, fsynced JSONL evidence. Inventory and credentials stay under `~/.config/hat` and are never committed.

## Private setup

`~/.config/hat/m1-inventory.json` and `~/.config/hat/m1-linode.env` must be owned by the current user, have mode `0600`, and live below a private parent directory. The env file must contain exactly `HAT_FM1_LINODE_ID`, `HAT_FM2_LINODE_ID`, and `HAT_FM3_LINODE_ID`. Inventory has exactly three or more nodes, each with a unique name, provider ID, label, address, `root@address` SSH target, and pinned `SHA256:` host-key fingerprint.

## Checks

```sh
python3 -m unittest discover -s experiments/m1 -p 'test_run.py' -v
python3 experiments/m1/run.py preflight \
  --inventory ~/.config/hat/m1-inventory.json \
  --work-root /tmp/hat-m1
```

Preflight validates the pinned host key before collection, binds SSH/SCP to a generated isolated known_hosts file, and only reads hostname, boot ID, Ubuntu release, CPU, memory, disk, time synchronization, and outbound TLS. It does not create the remote run root. Call `ensure_remote_root` only in a later mutating phase after preflight passes. Failed runs remain in the private run root for inspection.
