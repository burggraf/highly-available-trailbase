# D4 native coordination checkpoint — partial, not qualified

Date: 2026-09-09. Local run `coord-f340a3cd307b`, started 14:08:36 UTC. No VPS, HAT runtime, ingress, credentials or provider actions were changed. All lab server containers and the diagnostic client container are stopped; data/logs are retained.

## Verified

- Local Docker engine: Linux/arm64 under OrbStack on the operator workstation.
- Official candidate: etcd and etcdctl **3.7.1**, actual native version outputs checked. Server reports Git SHA `5e7fd0d`, Go `go1.26.5`.
- Immutable image reference: `gcr.io/etcd-development/etcd@sha256:a9983dd6d9283138ab926daa307c6c25623636703ecf5645d5df4d666ce9eba2`.
- Linux/arm64 image ID: `sha256:9ff3c85f7268593c7630b5a7ed6497efa4f657f603aeb415dcf1c41f33e092fd`.
- Three real members started on one unique internal Docker network, without published host ports or production inputs. Each had a private retained data directory, 256 MiB memory cap, one CPU, no added capabilities and no restart policy.
- Native endpoint status and health confirmed three distinct member IDs, one common cluster ID, matching version and three healthy endpoints.

These resource caps are a tiny local test configuration, **not** measured VPS sizing or production recommendations. The private plaintext network does not qualify TLS/access control.

## First check stopped: transaction stdin framing

The initial transaction command exited **3**, stderr **`Error: EOF`**. The supplied final failure operation ended with one newline rather than a blank line. The pinned source requires a blank line after each section, including the final section, before calling `Commit()`.

All three servers were stopped by the checker's cleanup path and their logs/inspection retained. Transaction exclusion, lease expiry, one-member loss and quorum loss checks **did not run**. No passing result is claimed for those cases.

## Focused diagnosis exposed a second client-contract gap

A network-disabled, throwaway client was given the original input and reproduced exit 3 / EOF. With the extra terminating blank line, the same pinned client did not exit within the outer **8-second** deadline despite `--command-timeout=2s` and `--dial-timeout=1s`, against deliberately unreachable `127.0.0.1:1`.

The pinned source explains the missing transaction deadline:

```go
txn := mustClientFromCmd(cmd).Txn(context.Background())
```

`txn_command.go` does not supply `commandCtx` or a transaction deadline. This observation is specifically about the tested txn command; do not generalize it to every etcdctl command or to the etcd server.

Killing the local Docker CLI on timeout did not stop its attached container. The exact remaining container was identified by its full ID, image, network-disabled configuration, executable and arguments; inspection/logs were saved before stopping it. No unrelated containers were stopped. An outer subprocess timeout alone is therefore insufficient lifecycle management for this test setup, and is not cancellation proof for remote effects.

An earlier optional Docker inspect format field (`Config.Entrypoint`) was absent. Full image JSON was inspected instead; this harmless reporting error is also recorded rather than hidden.

## Decision at this checkpoint

- Keep etcd 3.7.1 as a **candidate**, not a deployment pin already qualified for HAT.
- **Do not use etcdctl txn as HAT's bounded runtime transaction client.** Its tested timeout contract is insufficient. Do not compensate by designing a generic retry/kill wrapper.
- Next isolated qualification should use the maintained official Go v3 client with explicit request contexts, while still treating a timeout as an uncertain transaction outcome. This adds no dependency or runtime code to HAT at this checkpoint.
- Use named client containers/processes and preserve their identities before execution; cleanup must verify and stop the exact owned resources even when the attached CLI dies.
- Correct stdin framing in any future diagnostic use, but do not rerun the entire failed baseline just to obtain a green result. First review the changed client contract and write the focused failing deadline/cancellation-ambiguity checks.

## Follow-up: official Go client — focused checks passed

Independent review `e3b3f6ac-e24f-43d9-aff6-bed29cb96650` approved isolated client qualification subject to an explicit committed-but-response-lost check. Follow-up run `go-868abb5b7479` used a **fresh single-member** lab to isolate that contract; it did not rerun or complete the earlier three-member baseline.

The private test module pinned official API/client v3.7.1 with gRPC v1.82.1. It cross-compiled a Linux/arm64 test binary using Go 1.26.0; the server remained the immutable image above. This is recorded build provenance, not a production toolchain/security qualification. Binary SHA-256: `d4c67af408d6b2e068b8a90360b2051bd4136cf97d10e665e93c0570710e0593`.

Observed checks:

- **Explicit deadline:** a transaction to unavailable loopback port 1 returned a context deadline in **501.623324 ms** with a 500 ms context. It did not inherit the CLI's unbounded transaction wait.
- **Committed result withheld:** a test-only interceptor let a real conditional transaction succeed, then withheld that success from its caller until the one-second context expired. The caller received a deadline after **1.002468548 s**, while a separate official-client connection observed the exact operation value, version 1 and committed revision 3.
- **No application replay:** one instrumented transaction invocation occurred. The raw test labels this counter `actual sends`; precisely, it counts unary invoker calls, not packet-level transmissions. No retry loop was used. This is client-boundary response suppression after a real commit, **not a physical network-partition test**.
- **Negative control:** with response suppression disabled, the same deadline expectation deliberately failed with `got <nil>` (exit 1). The positive run then passed both checks (exit 0). The check therefore did not manufacture a timeout independently of the injected condition.
- Client containers were named and their full IDs recorded before attachment. Both clients and the server were inspected and stopped; no published ports, OOM kills, production inputs or HAT changes. Private data and outputs remain available.

Conclusion: explicit contexts bound the tested client wait, **not server-side commit**. A timeout cannot authorize replay or establish that an operation never happened. The exact positive witness in this controlled case is not a general readback/resume algorithm; absent or otherwise unresolved evidence must leave pending intent unresolved.

Private follow-up evidence: `~/.config/hat/d4-qualification/go-868abb5b7479/`, including `client_test.go`, locked `go.mod`/`go.sum`, build output, `resource-identities.json`, command evidence and `result.json`. No Go module or dependency was added to HAT.

## Pending gates

Exclusive transaction ownership under contention; lease renewal/expiry and durable-intent separation; one-member/quorum loss; authenticated client/peer TLS and permissions; stale responses and watch reconnect; VPS resource qualification; actual provider delayed-effect guarantees; acknowledged-write preservation; redundant ingress. No safe automatic activation or automatic HA claim follows from this checkpoint.

## Evidence and source

Private: `~/.config/hat/d4-qualification/coord-f340a3cd307b/` contains the manifest, image/version outputs, one-shot check, numbered command intent/stdout/stderr/outcome files, retained member data, `failure.json`, partial `result.json` and `stdin-diagnosis/`.

Official pinned source: https://raw.githubusercontent.com/etcd-io/etcd/v3.7.1/etcdctl/ctlv3/command/txn_command.go . Read both section parsing and transaction context construction when reviewing the finding.
