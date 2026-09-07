# M1 Acceptance (sanitized)

**Run:** 2026-09-07T19:29:00Z  
**Decision:** GO

## Capability assumptions

- Python 3 and the standard-library test harness are available.
- OpenSSH `ssh`, `scp`, `ssh-keyscan`, and `ssh-keygen` are available.
- The operator supplied private inventory and Linode environment files outside this repository, with the required ownership and modes.
- No inventory contents, credentials, hostnames, fingerprints, or evidence payloads are included here.

## Checks

```text
python3 -m unittest discover -s experiments/m1 -p 'test_run.py' -v
Ran 63 tests: OK

python3 -m unittest discover -s experiments/m0 -p 'test_run.py' -q
Ran 38 tests: OK

python3 experiments/m1/run.py preflight --inventory <private-inventory> --linode-env <private-env> --work-root /tmp/hat-m1-live
preflight passed: 3 nodes

python3 experiments/m1/run.py init-remote --inventory <private-inventory> --linode-env <private-env> --work-root /tmp/hat-m1-live
init-remote passed: 3 nodes
```

The live run used pinned host keys and the read-only preflight command set, then explicitly ran the separate mutating `init-remote` phase. Temporary local run data was removed after validation. No push was performed.
