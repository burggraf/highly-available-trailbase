# D4 Local Mutation-Surface Closure Implementation Plan

> **REQUIRED SUB-SKILL:** Use the executing-plans skill to implement this plan task-by-task.

**Goal:** Determine whether one fresh pinned local TrailBase fixture can expose only the three already-qualified exact mutation controls under an independently observed macOS sandbox/descriptor threat model.

**Architecture:** Commit a pinned exhaustive surface census and a pure fail-closed request/attestation validator under `experiments/d4/`. Keep all listener, UDS opener, sandbox, native process, credential and fixture logic outside Git in a fresh private harness. Unknown source/runtime capability or unenforceable isolation returns `infeasible`; it never becomes simulated closure.

**Tech Stack:** Python standard library, JSON, pinned TrailBase v0.33.11 source/binary, macOS Unix-domain sockets/`LOCAL_PEERCRED`/`sandbox-exec`, existing D4 native/logout adapters.

---

### Task 1: Freeze the complete source-census contract

**Files:**
- Create: `experiments/d4/test_surface_closure.py`
- Later create: `experiments/d4/surface_manifest.json`
- Later create: `experiments/d4/surface_closure.py`

**Step 1: Write the missing-manifest red**

Import `surface_closure`, load `surface_manifest.json`, and require:

```python
self.assertEqual(manifest['source'], {
    'repo': 'trailbaseio/trailbase',
    'tag': 'v0.33.11',
    'commit': 'f24291b894bb6c6696608e5f4c2f68666fe97686',
})
self.assertEqual(len(manifest['routes']), 82)
self.assertEqual(len(manifest['debug_only_routes']), 1)
self.assertIn(('DELETE', '/api/auth/v1/delete'), route_keys)
self.assertEqual(set(manifest['section_counts'].items()), {('records',10),('auth',31),('admin',40),('server',1)})
self.assertEqual(set(manifest['exact_allow_rules']), {
    'POST /api/records/v1/main_ops',
    'POST /api/records/v1/aux_ops',
    'POST /api/auth/v1/logout',
})
```

Require exact top-level keys; unique release `(method,path)` pairs; exactly 82 release templates with section counts 10/31/40/1; one separately pinned debug-only `/api/whoami`; every upstream template default denied; exactly three separate HAT `exact_allow_rules`, each mapped to a real upstream template and exact `main|aux|session` binding; source-file SHA-256 and anchors shaped as `{line, contains}`; explicit condition/effects/secondary-effects on every route; and explicit capability classes for jobs, WASM/custom routers, listeners, direct DB/files/config/provider writers, and logs telemetry. A missing file, digest mismatch, out-of-range line, missing anchor text, source tag/commit mismatch, or extra router source returns `infeasible` before any callback.

**Step 2: Run the red**

Run: `python3 experiments/d4/test_surface_closure.py`

Expected: import or manifest-not-found failure. Preserve stdout/stderr under private `~/.config/hat/d4-qualification/surface-closure-contract/` with `umask 077`.

**Step 3: Build the pinned manifest from the reviewed source graph**

Enumerate every recursively wired semantic route from release/debug server, auth/OAuth, records/transactions, admin, admin-auth listener instances, and WASM/custom registration, including disabled conditional arms. The release census must contain generic `POST /api/records/v1/{name}` and conditional `POST /api/transaction/v1/execute`, never synthetic `main_ops`/`aux_ops`; it uses exact `/api/healthcheck`. Put debug-only `GET /api/whoami` outside the 82 release list. Record `listener_route_instances` as an exact top-level field containing the three duplicated `admin_auth_router` login/status/GET-logout declarations; validate unique method/path/handler/source/condition entries and keep them separate from semantic-route count. Add SHA-256 for every inspected router/job/bridge source file. All non-control routes are `deny`; no workload `read` classification exists. An unresolved source graph edge, macro, generated route, or compile feature is a hard `infeasible` state and cannot be cleared by runtime observation. A source-enumerated dynamic registration point (WASM manifest, custom router, runtime job) may start as `runtime_unknown` in the static census only to describe the capability; native eligibility remains forbidden until independent content-addressed fixture attestation resolves that exact point to absent. The eligibility input must contain no unresolved `runtime_unknown`.

Do not generate from OpenAPI alone and do not infer safety from HTTP method. The reviewed source artifact's canonical path is `/private/var/folders/d0/z9jph2ld4v9gw45bwg0f1j900000gn/T/hat-ack-contract-sources-p2anepgt/trailbase`; its sibling `manifest.json` binds tag `v0.33.11` to commit `f24291b894bb6c6696608e5f4c2f68666fe97686`. Private/native checks must copy this inert artifact to a fresh canonical source root or stop if it is absent; they never silently refetch or substitute source.

**Step 4: Add the smallest manifest loader/validator**

`surface_closure.py` uses only the Python standard library. `verify_source(source_root, provenance_path, manifest)` opens a canonical source root and every descendant with held descriptor-relative `O_NOFOLLOW` traversal. It enumerates and opens the complete expected Rust file set first, binds each inventory entry to that retained descriptor/inode snapshot, then hashes and validates anchors only from those descriptors; no downstream step consumes the mutable pathnames. It verifies the provenance tag/commit and exact census facts from one retained provenance descriptor. Reject unknown/missing keys, duplicate routes, unsupported values, wrong section/debug/`listener_route_instances` count or shape, synthetic policy paths in the upstream census, wrong source identity, missing source hashes/anchors, every unresolved source-graph item, any native-eligibility input retaining `runtime_unknown`, and any exact policy rule set other than:

```python
ALLOWED = {
    ('POST', '/api/records/v1/main_ops'): 'main',
    ('POST', '/api/records/v1/aux_ops'): 'aux',
    ('POST', '/api/auth/v1/logout'): 'session',
}
```

Each create rule references upstream `POST /api/records/v1/{name}`; logout references upstream `POST /api/auth/v1/logout`. Upstream census entries remain denied by default; exact policy specialization is evaluated only by `bind_request`.

**Step 5: Run green and independently reconcile the census**

From repository root, run:

```bash
python3 experiments/d4/test_surface_closure.py
python3 -I -B -c "from pathlib import Path; import sys; sys.path.insert(0,'experiments/d4'); import surface_closure as s; s.verify_source(Path('/private/var/folders/d0/z9jph2ld4v9gw45bwg0f1j900000gn/T/hat-ack-contract-sources-p2anepgt/trailbase'), Path('/private/var/folders/d0/z9jph2ld4v9gw45bwg0f1j900000gn/T/hat-ack-contract-sources-p2anepgt/manifest.json'), s.load_manifest())"
```

Expected: PASS. Unit tests must also prove missing/tampered source, bad anchors and wrong provenance return `infeasible`; assert release section counts, generic create/transaction presence, exact healthcheck, debug-only whoami, three admin-auth listener instances, and absence of synthetic allow paths from upstream routes. Then obtain a read-only reviewer that checks every router constructor, merge/nest edge, conditional arm, job registration and dynamic registration point against the manifest. Any omission blocks later work.

**Step 6: Commit**

```bash
git add experiments/d4/surface_manifest.json experiments/d4/surface_closure.py experiments/d4/test_surface_closure.py
git commit -m "Inventory pinned TrailBase mutation surfaces"
```

### Task 2: Enforce exact raw request closure

**Files:**
- Modify: `experiments/d4/surface_closure.py`
- Modify: `experiments/d4/test_surface_closure.py`

**Step 1: Write request-validation reds**

Define a frozen `ClosureRequest(method: bytes, target: bytes, headers: tuple[tuple[bytes,bytes],...], body: bytes)` in tests first. Require refusal for:

- every upstream manifest route (all default denied) and every request not matching one of the three separate exact policy rules;
- non-ASCII/control method bytes, lowercase/mixed/alternate methods, and every non-exact method;
- non-ASCII/control target bytes, query/fragment, percent escapes, backslash, dot segments, duplicate slash, case/trailing-slash variants;
- non-ASCII/control header-name/value bytes, duplicate/continued/missing headers, header-name OWS, value OWS, name case variants, parameterized/wrong/case-varied `Content-Type`, and every unclassified forwarding header; only one case-insensitively parsed name with exact value bytes `application/json` passes;
- invalid UTF-8, duplicate JSON keys, non-finite values, trailing non-whitespace bytes, wrong keys/types/limits, arrays, multipart and form bodies. Preserve existing adapter semantics by accepting otherwise valid JSON with surrounding whitespace, either key order, internal whitespace, and equivalent escapes.

Retain exact request bytes from successful main, aux and logout native controls and require all three to pass.

**Step 2: Run the focused red**

Run: `python3 experiments/d4/test_surface_closure.py`

Expected: request-validator tests fail because `ClosureRequest`/`bind_request` are absent.

**Step 3: Implement the minimum pure validator**

Parse raw target before any normalization. Parse header names case-insensitively from the tuple while retaining duplicate detection. Reuse the existing strict JSON duplicate/non-finite approach and existing operation schemas; do not impose sorted/compact JSON serialization. `ClosureRequest` is the post-framing pure boundary: the later listener task must independently reject ambiguous request lines, HTTP versions, Host/authority, Content-Length, Transfer-Encoding, chunking, and incomplete bodies before constructing it; no framing claim is made by this pure Task 2 validator. Return only an immutable `(operation_kind,database,validated_request)` binding. No listener, opener, subprocess, filesystem mutation, journal or generic forwarder.

**Step 4: Prove denied requests have zero effects**

Use a counting callback in tests and call it only after `bind_request` succeeds. Derive the deny matrix from upstream routes plus exact policy rules and assert every denied case leaves the count at zero. This is a pure `bind_request` test: it sends **no** denied request to TrailBase. If later diagnosis requires route-level probing, use only a separate disposable source/database/filesystem copy, record every effect before discarding it, and never probe an unknown or potentially mutating route in the qualification fixture.

**Step 5: Run tests and commit**

Run:

```bash
python3 experiments/d4/test_surface_closure.py
python3 experiments/d4/test_native_adapter.py
python3 experiments/d4/test_auth_logout_adapter.py
python3 experiments/d4/test_admission.py
```

Expected: all pass.

```bash
git add experiments/d4/surface_closure.py experiments/d4/test_surface_closure.py
git commit -m "Refuse unqualified TrailBase surfaces"
```

### Task 3: Validate independently collected runtime attestation

**Files:**
- Modify: `experiments/d4/surface_closure.py`
- Modify: `experiments/d4/test_surface_closure.py`

**Step 1: Write attestation reds**

Require an exact, content-addressed attestation schema with:

- collector/source/binary/config/migration/plugin/sandbox-profile hashes;
- `env -i` argv/environment and exact process ancestry/tree;
- descriptors with `FD_CLOEXEC`, owner/process/type/path/inode;
- bound/connected sockets, exact UDS socket type, canonical pathname, non-symlink parent ancestry, owner/mode/device/inode, and peer UID/groups;
- listener-inode-to-TrailBase-PID/executable/argv binding;
- registered jobs/plugins/routes and every condition resolution;
- writable-path probes from the sandboxed identity;
- explicit `unknown`, `missing`, `extra`, `stale`, and `self_reported_only` arrays;
- monotonic collection window and evidence-file SHA-256 bindings.

Red cases remove or alter each field, add a TCP listener/direct writer/mutating job/plugin/custom route, retain a `runtime_unknown`, claim runtime absence for an unresolved source-graph item, omit content-addressed absence evidence for a declared dynamic registration point, inherit a UDS/DB descriptor, allow a protected write, change a digest, replace a socket inode, or provide declaration-only evidence. Every case must return `infeasible` before a positive callback. Add `validate_quarantine(root, manifest)` tests requiring canonical owner-only non-symlink ancestry, `0700` directories, `0600` single-link regular files, exact file-count/byte/hash manifest, no special files, and an explicit pending/retain-encrypted/owner-authorized-destroy disposition.

**Step 2: Implement exact validation**

`validate_attestation` requires a separate frozen manager-owned trust input containing the expected manager-receipt digest/nonce, collector source digest and PID/parent, fixture PID/start identity, pinned source/binary/config/migration/plugin/sandbox identities, service UID/groups, collection bounds, expected condition resolutions, and the exact manager-verified evidence `(id,path,digest,size,kind)` inventory. Telemetry requires a content-addressed complete-scan evidence reference, so empty observed reader/writer sets are never accepted from a bare `logs_only` claim. It is never constructed from attestation fields. Pure validation proves exact schema, bounds, canonical integrity and cross-consistency against that input; it cannot prove live collector independence, peer credentials, PID/inode truth, or sandbox enforcement. Task 5 must construct and independently verify the trust input from the process manager and live observations. A fixture-generated copy, a self-consistent digest, or matching declaration remains insufficient.

Keep validation structural and boring. Recompute the canonical attestation digest with the digest field omitted. Require empty uncertainty arrays, exact pinned facts, no TCP listener, exactly two private UDS listeners with all socket/path/ancestry fields observed, only allowlisted descriptors/processes/jobs, content-addressed independent absence for every source-enumerated dynamic registration point, no unresolved source item or `runtime_unknown`, denied protected writes, and logs classified only as telemetry. Missing one identity field, pathname replacement, or noncanonical/symlinked ancestry is `infeasible`. Declarations may be compared but never satisfy evidence.

Implement `validate_quarantine` as a read-only, descriptor-bound `lstat`/hash snapshot; it never chmods, deletes, encrypts, or follows links. Under the exact v1 manifest schema, only the initial `pending` disposition can pass: `retain_encrypted` and `owner_authorized_destroy` remain fail-closed until a separately reviewed, externally content-addressed owner-record contract exists. The root parent is the owner-controlled base for this fixed signature; parent, root, descendants, and every retained file/directory descriptor are pre/post identity-bound. The returned immutable inode snapshot is evidence for Task 5 to bind to terminal collection, not a claim of future filesystem immutability. Do not add signing/key infrastructure: a signature from the same fixture would add no authority. The private native phase uses a separately reviewed `collect.py`, launched by the parent process manager—not by `run.py` and not as its descendant—while the fixture is paused at an explicit collection gate. `collect.py` validates the live fixture receipt, creates `attestation.json` with `O_EXCL`, records its own PID/parent/timestamps/source hash, hashes every evidence file, and signals completion. `run.py` has no attestation-writing path and only resumes after validating the collector receipt. Unit tests reject fixture-produced/self-reported JSON even if it copies collector-looking fields. Independent review binds collector source hash, process-manager receipt, artifact ownership and collection window.

**Step 3: Run mutation tests and commit**

Run: `python3 experiments/d4/test_surface_closure.py`

Expected: PASS.

```bash
git add experiments/d4/surface_closure.py experiments/d4/test_surface_closure.py
git commit -m "Require observed closure capabilities"
```

### Task 4: Static review before native feasibility work

**Files:**
- No production/runtime files.
- Private review artifacts only.

**Step 1: Run complete local regressions**

```bash
python3 experiments/d4/test_surface_closure.py
python3 experiments/d4/test_auth_logout_adapter.py
python3 experiments/d4/test_native_adapter.py
python3 experiments/d4/test_admission.py
env -u HAT_CONTROL_ENTRY -u HAT_NODE_ENTRY -u HAT_TRANSITION_ENTRY -u HAT_RECOVERY_ENTRY \
  python3 -m unittest discover -s tests -p 'test_*.py'
git diff --check
test -z "$(git diff --name-only 8f9e094 -- hat deploy tests)"
```

Expected baseline categories: 10 logout, 18 native-adapter, 14 protocol and 107 runtime tests plus the new closure tests. Existing SQLite `ResourceWarning`s and expected parser stderr remain known categories.

All commands run from `/Users/markb/dev/hat/.worktrees/d4-surface-closure`. First require `git merge-base --is-ancestor 8f9e094 HEAD` and `test "$(git rev-parse 8f9e094)" = 8f9e094403df5ce78adb48babb06a82a602ad6e4`; a missing/wrong baseline stops rather than changing the diff base. Run the exact source-verification command from Task 1 plus:

```bash
python3 experiments/d4/test_surface_closure.py SurfaceManifestTests.test_source_artifact_mismatches_are_infeasible
python3 experiments/d4/test_surface_closure.py ClosureRequestTests.test_raw_byte_differentials_refuse_before_callback
python3 experiments/d4/test_surface_closure.py AttestationTests.test_missing_extra_stale_or_self_reported_facts_are_infeasible
python3 experiments/d4/test_surface_closure.py QuarantineTests.test_only_canonical_private_manifested_roots_pass
```

Each command must pass independently.

**Step 2: Obtain independent code/census review**

Review exact manifest completeness, raw parser differentials, attestation false-success paths, callback ordering, logs exclusion and scope. Resolve every P0/P1 before any native process.

**Step 3: Commit review corrections**

Use a focused commit message. Preserve red/green evidence privately.

### Task 5: Build a private fail-closed isolation harness

**Files outside Git:**
- Create fresh: `~/.config/hat/d4-qualification/surface-closure-<random>/run.py`
- Create fresh private collector/sandbox profile/static checker and evidence.

**Step 1: Preserve missing-harness/static reds**

The static checker requires pinned binary/source/code hashes, canonical `0700` root, `0600` files, `umask 077` before shell redirection, fresh-root whitelist, bounded logs, process groups and exact cleanup.

**Step 2: Configure only the declared fixture**

Use a newly copied hash-verified TrailBase binary and inert pinned source. Litestream is included only because the already-qualified main/aux/logout positive-control adapters require native sync/restore proof; it is not closure evidence or a remote-durability claim. Bind main and independent admin to separate UDS paths; reject every TCP listener. Disable signup, anonymous, OTP, OAuth providers, transactions and mutating jobs. Require empty WASM/plugin/custom-router state. Launch with `env -i` and an exact environment.

**Step 3: Independently collect runtime facts**

Pause `run.py` after readiness. From the parent process manager, launch separately reviewed `collect.py --fixture-receipt <private-path> --output <new-O_EXCL-path>` as a sibling, never a fixture child. It independently collects process argv/environment/tree, descriptors, `FD_CLOEXEC`, sockets, exact UDS socket type/canonical path/non-symlink ancestry/device/inode/owner/mode, listener inode-to-PID/executable/argv, job/plugin/route metadata, dynamic-point absence, and writable-path probes. It records monotonic/wall timestamps, PID/parent, collector/source hashes and content-addresses each artifact. Parent and reviewer verify the process-manager receipt, ownership and collection window; fixture-generated/self-reported files are rejected. Any collector blind spot or unresolved `runtime_unknown` yields `infeasible`.

For every positive-control HTTP request, the private UDS opener must first connect **without sending request bytes**, read macOS `LOCAL_PEERCRED`, and compare effective UID/groups with the launched service identity. It writes an `O_EXCL` held-connection receipt and blocks. The parent launches `collect.py` again as a sibling; the collector must bind the exact listener inode/path/PID/executable/argv and both endpoints of that live accepted connection to the launched TrailBase process. Only after the opener validates the collector's content-addressed connection receipt may it send request bytes. Missing/mismatched peer credentials, unavailable connected-endpoint observation, replacement, timeout, or stale receipt returns `infeasible` with zero request bytes sent. The connection remains held throughout observation, so replacing the listener cannot redirect that request.

Only source-proven side-effect-free metadata may be queried in the qualification fixture. Unknown routes are never probed there.

**Step 4: Test inherited-descriptor and path bypasses**

Launch the sandboxed identity with only stdin/stdout/stderr and an explicit descriptor allowlist. Deliberately offer UDS and DB descriptors; the launcher must refuse before exec. Require `FD_CLOEXEC` elsewhere. Test UDS rename/replacement before connect and while the positive connection is held, wrong peer UID/groups, stale/missing connection-collector receipt, direct connection, DB/config/migration/upload/backup/plugin writes, and credential reads as denied. Assert zero request bytes for every identity/connection failure. If `sandbox-exec` cannot enforce and expose these facts, record `infeasible` and stop.

**Step 5: Run the deny matrix and positive controls**

Every denied manifest route/body variant is evaluated only by `bind_request` and must stop before the counting opener, with zero TrailBase requests. No denied or unclassified endpoint is contacted in the qualification fixture. Any necessary route-level diagnostic uses a separate disposable fixture copy with DB/file/provider effects counted, retained as sanitized evidence, then discarded from qualification. Invoke the exact retained main/aux/logout bytes only through their existing adapters via a private UDS HTTP opener. Preserve existing proof-before-release and duplicate/malformed-proof refusal.

**Step 6: Prove telemetry independence and cleanup**

Require the source census and runtime SQL/descriptor tracing to enumerate every `logs.db` reader/writer and show only the classified logging path. Any other reader/writer is `infeasible`. Inject a logging failure after a protected mutation in a disposable diagnostic copy and prove telemetry cannot release success: only the operation-specific protected-state adapter may resolve the operation; absent that proof the result remains uncertain. Stop and reap every process/group; prove all descriptors/listeners/UDS/sandbox children disappear. Scan sanitized metadata for tokens, cookies, credentials, payloads, DB/WAL bytes, raw bodies and raw logs.

**Step 7: Review before execution, then use fresh roots for reruns**

Obtain independent static harness review first. Preserve immutable sanitized failures. Quarantine raw roots beneath canonical owner-only `0700` non-symlink ancestry; require directories `0700`, regular files `0600`, `st_nlink==1`, no symlinks/devices/sockets after shutdown, a 256 MiB/file-count manifest, content hashes and access log. No reviewer reads raw secrets. Diagnose every failure before a fresh rerun. Before integration or worktree cleanup, an independent gate records either continued encrypted/offline quarantine or explicit owner-authorized destruction; silent deletion is forbidden.

### Task 6: Record feasible or infeasible result

**Files:**
- Modify: `docs/plans/2026-09-09-d4-local-surface-closure-plan.md`
- Modify: `docs/status.md`

**Step 1: Obtain sanitized evidence review**

The reviewer cross-checks census/attestation, zero-upstream counts, exact positive controls, sandbox bypass tests, telemetry independence, lifecycle and secret scan. A failed enforcement primitive is recorded as `infeasible`, not retried into a weaker claim.

**Step 2: Record exact result and limits**

Document every failure/root, review ID, test count, observed capability, raw-retention disposition, and non-claims. Do not describe local fixture feasibility as deployed closure.

**Step 3: Final verification and commit**

From the pinned worktree/root, repeat Task 4 regressions, exact source verification, quarantine validator, `git diff --check`, `test -z "$(git diff --name-only 8f9e094 -- hat deploy tests)"`, and clean status. Enforce an exact changed-path allowlist:

```bash
python3 - <<'PY'
import subprocess
allowed={
 'experiments/d4/surface_manifest.json',
 'experiments/d4/surface_closure.py',
 'experiments/d4/test_surface_closure.py',
 'docs/plans/2026-09-09-d4-local-surface-closure-plan.md',
 'docs/status.md',
}
changed=set(subprocess.check_output(['git','diff','--name-only','--diff-filter=ACMRTUXB','8f9e094'],text=True).splitlines())
extra=changed-allowed
assert not extra,sorted(extra)
PY
```

Every changed path must be allowlisted; the negative path check remains defense in depth. Commit documentation and obtain final read-only review.

**Step 4: Stop at the post-result checkpoint**

Report the feasible/infeasible result and required raw-retention disposition. Local fast-forward integration, merged retest and worktree/branch cleanup are optional post-qualification actions requiring explicit owner approval. Never push or deploy as part of this plan.

### Recorded result: infeasible before native execution

Task 1–4 pure validation and static review completed at repository commit `592e61fd5ebbdb6fecb8cbbfd003c1218e87fb79`. Canonical verification retained the pinned TrailBase `v0.33.11` source commit and exact 82-route census. Task 4 local checks passed: 66 surface-closure tests, 10 logout-adapter tests, 18 native-adapter tests, 14 admission tests, 108 D4 discovery tests, and 107 runtime tests; known SQLite `ResourceWarning`s and expected parser stderr remained non-failing categories. The later Task 6 final rerun preserved a non-clean result: surface and logout passed, then `NativeAdapterTests.test_default_command_timeout_stops_descendant_process_group` errored when its post-termination `os.killpg(pgid, 0)` probe returned macOS `EPERM`; execution stopped before admission. No retry was substituted. The remaining independent gates were then run separately and passed: 107 runtime tests, canonical source proof, canonical quarantine test, diff/path allowlists, and clean status. This unchanged environment-sensitive test-helper failure remains unresolved and prevents claiming a clean one-shot final suite. Task 3 final review workflow `c74d50c9-ca02-4731-ad7c-2bec8ab67eb7` and Task 4 correction review workflow `6ee53b6e-ffef-4739-8721-e8bfbfbcd070` returned OK.

Task 5 stopped at static preflight without starting TrailBase, Litestream, a collector, sandbox probe, socket, or request. The private root `/Users/markb/.config/hat/d4-qualification/surface-closure-6Ks3W2ng` records `infeasible_static`, zero request bytes and 13 exact refusal blockers: process-role observability; listener/accepted-socket observability; authenticated header closure; runtime registration completeness; `logs.db` SQL call-path observability; peer/collector-receipt ordering; process cleanup/reaping; descriptor-relative artifact paths; descriptor-relative adapter publication; sibling provenance; collector live-observation schema; source-archive verification; and prior-oracle packet qualification. Static checker self-tests passed and the gate exits `2` by design. Independent refusal review workflow `831c9c49-dea5-43a1-8437-e9ed7bc8e64f` found no false-green or spawn bypass.

This is an **infeasible qualification result**, not a failed native attempt and not evidence that the underlying capabilities are impossible. The private root remains owner-only with disposition `pending`; it contains dormant harness source and bounded metadata, but no copied TrailBase/Litestream binaries or pinned source archive, credentials, payloads, databases, WALs, raw logs, request bodies, or native evidence. No deletion, encryption, integration, cleanup, push, deployment, production gate, listener, routing, power, recovery, rejoin, or HA capability is authorized or claimed.

### 2026-09-10 blocker-closure follow-up

Task 2 closed the operation-specific header boundary at `e83fae6`: main/aux require exact JSON content type plus one bounded Bearer authorization header, logout accepts JSON content type only, persistent bindings contain no request secret/body, and parse errors retain no body-bearing exception graph. Independent specification and security reviews approved the boundary; 71 surface tests passed.

The attempted pre-probe `d4-phase-socket-1` schema was not qualified. Adversarial reviews demonstrated concrete accepted contract-breaking mutations after both `437fd3c` and `7b49459`. Their code was reverted without rewriting history by `c311c95` and `401e63a`; Task 2 files were verified byte-for-byte against `e83fae6`. `d4-phase-socket-1` is permanently refused. Any future schema must use a new identifier and be derived only from independently reviewed host receipts.

The fresh owner-only build root `/Users/markb/.config/hat/d4-qualification/surface-primitives-ggdgh6k1` contains a dormant static harness with zero probe/native execution. The implementer reported its static checker/tests passing, but the retained `build-report.json` and `terminal.json` still record validation and commands as `pending`; no retained static-pass claim is accepted. Independent specification review found generic placeholder dispatch, incomplete authorization/receipt binding, and no deterministic implementation for the 13 blocker probes. A requested parallel security reviewer was unavailable and produced no verdict. The root remains unchanged `pending`; it is not authorized for execution, reuse, conversion, cleanup, or deletion.

The subsequent read-only Task 6 decision is **infeasible under the approved stock-runtime contract**. Stock TrailBase v0.33.11 has no complete independently observable pre-send inventory of its effective runtime route/job/plugin/listener graph and no complete independent `logs.db` SQL call-path observer. Source census, OpenAPI/configuration, self-report, route probing, asynchronous raw logs, database contents, and FD snapshots cannot establish absence. Either unavailable fact independently blocks qualification. Therefore Task 5 probes will not execute, Tasks 3/4/7 will not resume, and no TrailBase, Litestream, collector, sandbox probe, opener, socket, or request bytes will be started. This does not prove an instrumented or forked design impossible; that would be a new scope requiring explicit approval.

Final current verification ran once and passed 113 D4 tests, 107 runtime tests, canonical pinned-source verification, and `git diff --check`; expected parser stderr and existing SQLite `ResourceWarning`s remained non-failing. The earlier retained `surface-closure-6Ks3W2ng` root includes dormant harness source rather than metadata alone, and its internal `__pycache__` is mode `0755`, violating the exact all-directories-`0700` quarantine policy despite the enclosing `0700` root. That pending violation is preserved without chmod, cleanup, deletion, or a safety claim.

## Stop boundary

No production listener/proxy, live data/VPS, remote storage, paid resource, deployment, routing, power, activation, recovery, rejoin, automatic replay, policy relaxation, TrailBase fork, login adapter, or new mutation proof. Any unknown/unobserved capability, mutating probe, sandbox escape, inherited descriptor, direct writer, secondary effect, or denied upstream call ends the experiment as refusal/infeasible.
