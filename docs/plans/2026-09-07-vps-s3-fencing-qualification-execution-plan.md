# VPS, S3, and Fencing Qualification Implementation Plan

> **REQUIRED SUB-SKILL:** Use the executing-plans skill to implement this plan task-by-task.

**Goal:** Produce reproducible private evidence that pinned TrailBase/Litestream work on Ubuntu with IDrive e2 and that completed external VPS power fencing safely precedes promotion.

**Architecture:** A local standard-library Python coordinator drives disposable nodes over OpenSSH, tests S3 with a minimal SigV4 client, invokes a provider-neutral fence executable, and reuses the M0 fixture. Private inventory, credentials, provider adapter, logs, and run artifacts remain outside Git; only generic harness code and sanitized results are committed.

**Tech Stack:** Python 3 standard library, OpenSSH, curl/HTTP, SQLite, TrailBase v0.33.11, Litestream v0.5.17, Ubuntu 24.04, S3-compatible HTTP API, systemd only for proving disabled restart behavior.

---

## Global safety rules

- Work directly on `main`, as previously approved; do not create a worktree.
- Never print, commit, or place credentials in process arguments.
- Restrict local and remote secret files to mode `0600`; private directories to `0700`.
- Use only `/var/lib/hat-qualification/<run-id>` and `/run/hat-qualification` remotely.
- Before any stop/reboot/power action, match expected instance ID, label, public address, SSH host key, and boot ID.
- Never delete a VPS, bucket, access key, or failed evidence automatically.
- A fence request is not success. Require provider `offline`, application unreachability, and a changed boot ID after restart.
- Never start a writer after unknown fence, restore, inventory, or lineage state.
- Every live task first runs its dry/unit checks and writes to a fresh run prefix.

### Private inputs

Create, outside Git:

```text
~/.config/hat/m1-idrivee2.env     # existing, mode 0600
~/.config/hat/m1-linode.env       # existing, mode 0600
~/.config/hat/m1-inventory.json   # node names, SSH names, expected provider IDs/labels/IPs
~/.config/hat/m1-fence-linode     # private provider adapter, mode 0700
```

The committed harness accepts private paths through CLI options; it contains no provider IDs, addresses, or secrets.

---

### Task 1: Safe remote coordinator foundation

**Files:**
- Create: `experiments/m1/run.py`
- Create: `experiments/m1/test_run.py`
- Create: `experiments/m1/README.md`

**Step 1: Write failing tests**

Test that inventory parsing rejects unknown keys, duplicate nodes/addresses/instance IDs, non-`root` SSH users, fewer than three nodes, and private files not owned by the current user or broader than `0600`. Test shell argument transport with `shlex.quote`. Test that remote run roots must resolve below `/var/lib/hat-qualification/<fresh-id>` and cannot already exist.

```python
def test_inventory_rejects_duplicate_instance_ids(self):
    inventory = valid_inventory()
    inventory["nodes"][1]["instance_id"] = inventory["nodes"][0]["instance_id"]
    with self.assertRaises(ValueError):
        validate_inventory(inventory)
```

**Step 2: Run tests and verify RED**

```sh
python3 -m unittest discover -s experiments/m1 -p 'test_run.py' -v
```

Expected: import/function failures.

**Step 3: Implement the minimum foundation**

Implement:

```python
@dataclass(frozen=True)
class Node:
    name: str
    ssh: str
    instance_id: int
    provider_label: str
    address: str

@dataclass(frozen=True)
class RunContext:
    run_id: str
    local_root: Path
    remote_root: str
```

Add `load_inventory()`, `require_private_file()`, `ssh(node, argv, input=None)`, `scp_to()`, `new_run_context()`, JSONL append+`fsync`, redaction, and `preflight`. Use argument arrays locally and a single quoted remote command. Record command metadata without environment values.

`preflight` must collect SSH host keys, `hostname`, `/proc/sys/kernel/random/boot_id`, OS release, CPU, memory, disk, time synchronization, and outbound TLS. It must not mutate nodes.

**Step 4: Run tests and local static checks**

```sh
python3 -m unittest discover -s experiments/m1 -p 'test_run.py' -v
python3 -m py_compile experiments/m1/run.py
git diff --check
```

Expected: PASS.

**Step 5: Run private preflight**

Create `~/.config/hat/m1-inventory.json` from the already verified nodes, mode `0600`, then run:

```sh
python3 experiments/m1/run.py preflight \
  --inventory ~/.config/hat/m1-inventory.json \
  --work-root /tmp/hat-m1
```

Expected: all three exact identities and Ubuntu 24.04 pass; no remote mutation.

**Step 6: Commit**

```sh
git add experiments/m1
 git commit -m "test: add safe VPS qualification foundation"
```

---

### Task 2: Minimal S3 SigV4 capability probe

**Files:**
- Modify: `experiments/m1/run.py`
- Modify: `experiments/m1/test_run.py`

**Step 1: Write failing unit tests**

Use published AWS SigV4 examples to test canonical URI/query/header ordering, payload SHA-256, signing key derivation, and Authorization output. Test response classification:

```python
self.assertEqual(classify_precondition(412), "refused")
self.assertEqual(classify_precondition(409), "conflict")
self.assertEqual(classify_precondition(200), "applied")
self.assertEqual(classify_precondition(None), "unknown")
```

Test ETag preservation, including quotes. Test that an unknown response can only resolve after authoritative HEAD/GET content comparison.

**Step 2: Verify RED**

Run the M1 unit command; expect missing SigV4/client functions.

**Step 3: Implement minimal HTTP client**

Use `hashlib`, `hmac`, `urllib.parse`, and `http.client`. Implement only required S3 operations: PUT, GET, HEAD, prefix LIST, and DELETE, each accepting explicit conditional headers. Credentials come from the protected env file loaded into memory. Never log Authorization headers or secrets.

Expose a `storage` scenario that uses `qualification/<run-id>/control/` and records status, request ID, ETag, payload hash, and reconciliation result.

**Step 4: Run unit tests**

Expected: PASS.

**Step 5: Run live S3 matrix**

The fresh prefix must prove:

- basic PUT/HEAD/GET/LIST/DELETE;
- create with `If-None-Match: *` succeeds once and refuses the second request;
- replace with current `If-Match` succeeds;
- stale/missing `If-Match` refuses;
- conditional DELETE with current ETag succeeds;
- stale conditional DELETE refuses without deleting the replacement;
- two simultaneous creates produce exactly one winner;
- two replacements from one ETag produce exactly one winner;
- a deliberately discarded client response is reconciled through HEAD/GET.

Do not infer semantics from status alone; verify final bytes and ETag lineage.

```sh
python3 experiments/m1/run.py storage \
  --inventory ~/.config/hat/m1-inventory.json \
  --s3-env ~/.config/hat/m1-idrivee2.env \
  --work-root /tmp/hat-m1
```

Expected: PASS or a bounded provider capability NO-GO.

**Step 6: Commit**

```sh
git add experiments/m1/run.py experiments/m1/test_run.py
 git commit -m "test: qualify S3 conditional operations"
```

---

### Task 3: Provider-neutral fencing contract

**Files:**
- Modify: `experiments/m1/run.py`
- Modify: `experiments/m1/test_run.py`
- Modify: `experiments/m1/README.md`

**Step 1: Write failing contract tests**

Define the private executable protocol:

```text
m1-fence <action> <target-json-path>
```

Actions are `inspect`, `power-off`, and `power-on`. Stdout is one JSON object. A successful `power-off` result includes exact target identity, request time, completed time, provider state `offline`, and an observation sequence. Nonzero exit, malformed JSON, mismatched identity, timeout, `running`, or request-only evidence is unknown/failure.

Add deterministic fake executables for confirmed, failed, no-op, timeout, malformed, mismatched, delayed, duplicate, and already-offline outcomes. Assert `promotion_allowed()` returns true only for completed exact-target isolation.

**Step 2: Verify RED**

Run M1 tests; expect missing fence parser/validator.

**Step 3: Implement contract and private adapter**

Implement generic `invoke_fence()` and `validate_fence_evidence()` in committed code. Create `~/.config/hat/m1-fence-linode` privately. It loads `m1-linode.env`, maps only the approved instance IDs, calls Linode API v4, and polls until the exact instance reaches the requested terminal state. It emits no token.

**Step 4: Run contract tests and non-destructive live inspect**

```sh
python3 -m unittest discover -s experiments/m1 -p 'test_run.py' -v
python3 experiments/m1/run.py fence-inspect \
  --inventory ~/.config/hat/m1-inventory.json \
  --fence-command ~/.config/hat/m1-fence-linode \
  --work-root /tmp/hat-m1
```

Expected: fake matrix PASS; all live target identities match without power changes.

**Step 5: Commit only generic files**

```sh
git add experiments/m1
 git commit -m "test: define external fencing qualification contract"
```

---

### Task 4: Provision pinned Ubuntu artifacts and run Linux parity

**Files:**
- Modify: `experiments/m1/run.py`
- Modify: `experiments/m1/test_run.py`

**Step 1: Add failing artifact/provisioning tests**

Test archive member validation, expected executable names, version parsing, checksum mismatch refusal, idempotent package checks, and remote path confinement. No download may execute before digest and archive checks pass.

**Step 2: Verify RED, then implement**

Add `provision` to install only `ca-certificates`, `curl`, `python3`, `unzip`, and SQLite CLI if absent; retrieve Linux ARM/x86 artifacts matching each node; compare GitHub release digests and published checksums; extract under the run root; verify `--version` and executable SHA-256.

Create disabled `hat-trailbase.service` and `hat-litestream.service` masks/placeholders solely to prove that reboot cannot auto-start a writer. Do not expose TrailBase publicly.

**Step 3: Run unit tests and provision**

```sh
python3 experiments/m1/run.py provision \
  --inventory ~/.config/hat/m1-inventory.json \
  --work-root /tmp/hat-m1
```

Expected: homogeneous pinned versions and hashes recorded privately.

**Step 4: Run M0 parity on fm1**

Copy the committed `experiments/m0` directory and invoke its `all --repeat 3` against a fresh fm1-local work root. Downloaded release artifacts remain node-local. Copy back only the private aggregate result and logs.

Expected: all positive scenarios and guards pass on Ubuntu within the 1 GB memory envelope. Resource exhaustion is a failed qualification, not permission to reduce fixture correctness.

**Step 5: Commit**

```sh
git add experiments/m1
 git commit -m "test: qualify pinned binaries on Ubuntu"
```

---

### Task 5: Cross-host Litestream over IDrive e2

**Files:**
- Modify: `experiments/m1/run.py`
- Modify: `experiments/m1/test_run.py`

**Step 1: Write failing config and lineage tests**

Test generated Litestream v0.5.17 config uses singular `replica`, explicit IDrive endpoint/region/bucket, unique run/epoch/database paths, environment placeholders, and exactly `main`, `session`, and `aux`. Reject reused/colliding prefixes and secret interpolation into persisted evidence.

**Step 2: Implement and run tests**

Generate root-only runtime config on fm1 and launch one uploader. Launch one `restore -f` per DB on fm2 with TrailBase stopped. Reuse M0 fixture creation and logical comparison helpers. Keep credentials out of argv and scrub copied config.

**Step 3: Run live replication scenario**

Write externally ledgered operations through TrailBase on fm1. Force remote sync for each DB, wait until fm2 reaches selected per-DB positions, stop followers strictly, finite-restore the same cuts independently, and compare schema, integrity, keys, and payload hashes.

Repeat through a fresh e2 prefix after writable promotion, then clean-restore fm3. Assert e1 object/hash inventory never changes after e2 starts.

Expected: exact three-DB match and restorable fresh epoch; otherwise NO-GO.

**Step 4: Commit**

```sh
git add experiments/m1
 git commit -m "test: qualify cross-host S3 replication"
```

---

### Task 6: Live external fence, promotion, and old-node rejoin

**Files:**
- Modify: `experiments/m1/run.py`
- Modify: `experiments/m1/test_run.py`

**Step 1: Write failing state-machine guard tests**

Test promotion refusal for request-only fence evidence, wrong target/incarnation, stale evidence, running provider state, reachable old application, restore mismatch, reused epoch, and any unknown field. Test duplicate fence requests and already-offline target are safe only after fresh exact-state confirmation.

**Step 2: Implement minimum integrated scenario**

Sequence:

1. Record fm1 provider, SSH, boot, process, activation, and epoch identity.
2. Start fm1 writer/uploader and fm2 stopped-app followers.
3. Submit externally ledgered writes, including one concurrent with failure.
4. From the local coordinator, invoke the private adapter to power off fm1.
5. Require exact provider `offline`; separately require TrailBase unreachability.
6. Select and validate a finite recovery cut for every DB.
7. Stop fm2 followers and promote the actual files into a fresh e2 namespace.
8. Verify writable TrailBase APIs/auth and exact recovered operation outcomes.
9. Power on fm1; require a changed boot ID and disabled writer services.
10. Quarantine old state, restore e2 cleanly, and join fm1 as stopped-app follower.
11. Verify no e1 mutation after takeover and no second writer at any point.

Do not automatically retry ambiguous application writes.

**Step 3: Exercise refusal cases before live promotion**

Run fake/controlled unknown, timeout, no-op, mismatched target, stale boot identity, and application-still-reachable cases. Each must prove the writer start callback was not invoked.

**Step 4: Run one live drill**

```sh
python3 experiments/m1/run.py failover \
  --inventory ~/.config/hat/m1-inventory.json \
  --s3-env ~/.config/hat/m1-idrivee2.env \
  --fence-command ~/.config/hat/m1-fence-linode \
  --work-root /tmp/hat-m1
```

Expected: completed fence precedes promotion; fm1 returns only as a clean standby.

**Step 5: Commit**

```sh
git add experiments/m1
 git commit -m "test: qualify fenced VPS promotion and rejoin"
```

---

### Task 7: Repeatability, independent review, and sanitized report

**Files:**
- Modify: `experiments/m1/run.py`
- Modify: `experiments/m1/test_run.py`
- Modify: `experiments/m1/README.md`
- Create: `docs/reports/m1-vps-s3-fencing-qualification.md`
- Modify: `docs/work-register.md`
- Modify: `README.md`

**Step 1: Add aggregate-run tests**

Test unique roots/prefixes, no resume, aggregate completeness, evidence references, timing/loss summaries, refusal counts, sanitization, and secret/hostname/address/provider-ID rejection in public output.

**Step 2: Run three fresh integrated drills**

Each repetition must start from fresh run/epoch paths. Rotate source/promotion roles where practical without changing the independent fence requirement. Preserve every raw run privately.

```sh
python3 experiments/m1/run.py all --repeat 3 \
  --inventory ~/.config/hat/m1-inventory.json \
  --s3-env ~/.config/hat/m1-idrivee2.env \
  --fence-command ~/.config/hat/m1-fence-linode \
  --work-root /tmp/hat-m1
```

Expected: all gates pass. Any safety failure makes the aggregate NO-GO.

**Step 3: Verify credentials and cleanup state**

- Ensure no credentials exist in Git, public report, process lists, shell histories generated by the harness, or copied artifacts.
- Leave all nodes powered on, writer services disabled, and no qualification process running.
- Remove remote credential copies only after evidence collection.
- Keep bucket histories and node forensic directories until the owner approves deletion.

**Step 4: Request independent code/evidence review**

Review against the approved design, this plan, private aggregate evidence, and public claims. Fix every Critical/Important finding and rerun affected gates.

**Step 5: Publish bounded result**

Report exact versions/hashes, generic Ubuntu/VPS capability assumptions, S3 operation matrix, fence completion semantics, repetition count, timing ranges, acknowledged/ambiguous/lost outcomes, refusal cases, limits, and GO/NO-GO for beginning M1 supervisor implementation. Do not identify the provider as certified or publish private infrastructure details.

Update the work register only with narrowly supported evidence. Do not close broader M0/M1 issues wholesale.

**Step 6: Final verification and commit**

```sh
python3 -m unittest discover -s experiments/m0 -p 'test_run.py' -v
python3 -m unittest discover -s experiments/m1 -p 'test_run.py' -v
python3 -m py_compile experiments/m0/run.py experiments/m1/run.py
git diff --check
git status --short
```

Inspect the staged file list for DBs, logs, JSONL, result files, addresses, IDs, hostnames, emails, tokens, and access keys before committing.

```sh
git add README.md docs experiments/m1
 git commit -m "test: report VPS storage and fencing qualification"
```

Push only after the owner reviews the final decision and sanitized report.
