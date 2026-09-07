# M0 local follow-to-writer experiment

This standard-library Python harness tests whether pinned, unmodified TrailBase and Litestream executables can continuously restore three TrailBase databases, promote the stopped follower files, and create a fresh replication epoch.

It is a local lifecycle experiment, not a production HA controller.

## Prerequisites

- Python 3.11+
- GitHub CLI (`gh`), authenticated for release downloads
- A supported native host architecture
- TrailBase v0.33.11
- Litestream v0.5.17
- A new private work directory outside this checkout

The recorded run used macOS ARM64. Linux qualification remains required before drawing deployment conclusions.

## Retrieve pinned macOS ARM64 artifacts

```sh
WORK=$(mktemp -d /tmp/hat-m0.XXXXXX)
chmod 700 "$WORK"
mkdir "$WORK/artifacts"

gh release download v0.33.11 --repo trailbaseio/trailbase \
  --pattern trailbase_v0.33.11_aarch64_apple_darwin.zip \
  --dir "$WORK/artifacts"
gh release download v0.5.17 --repo benbjohnson/litestream \
  --pattern litestream-0.5.17-darwin-arm64.tar.gz \
  --pattern checksums.txt --dir "$WORK/artifacts"
```

Before extraction, compare SHA-256 values with both published checksums and GitHub release-asset digests. Inspect archive members and extract only below `$WORK/artifacts`. Do not install globally or use `sudo`.

Recorded release archive SHA-256 values:

- TrailBase: `dea7a7e865f14405c3e09785a680c6830b1084bfd9785e7d44fc72b6a3583f91`
- Litestream: `e211f68ff7658d19f193f2914417afdf8f89a053ff8f263e5d6b3b1d3bbc7b08`

Recorded executable SHA-256 values:

- `trail`: `88e64c0b207a4501b7074525a7f533d9b8a8e2aef1780cfeb5b45791e70a0f34`
- `litestream`: `205b4c315d61a7f5709c4ab9001084eadfa8c9d36e1c198f9887417c2d88bb73`

## Commands

```sh
python3 -m unittest discover -s experiments/m0 -p 'test_run.py' -v

python3 experiments/m0/run.py \
  --trail "$TRAIL" --litestream "$LITESTREAM" \
  --work-root "$WORK" --scenario preflight

python3 experiments/m0/run.py \
  --trail "$TRAIL" --litestream "$LITESTREAM" \
  --work-root "$WORK" --scenario all --repeat 3
```

Each command creates new run directories and never resumes or deletes failed evidence. Exit codes are 0 for requested checks passing, 1 for detected correctness failure, and 2 for an environmental/upstream capability blocker.

## TrailBase v0.33.11 bootstrap deviation

The planned `trail user add` flow is broken in v0.33.11: the CLI inserts `_user.verified`, but migration `U1785764695__unverified_email.sql` removes that column. The approved experiment revision uses TrailBase's supported username-only registration HTTP endpoint and then exercises login, refresh, and logout normally. It does not edit auth tables directly.

## Interpretation and limits

Passing demonstrates only the tested local lifecycle:

- stopped TrailBase followers;
- local-file Litestream transport on one machine;
- `main.db`, `session.db`, and one attached `aux.db`;
- controlled and abrupt process termination;
- promotion of actual followed files;
- fresh e2 history and stopped-application C follower;
- listed refusal controls.

It does not validate S3/R2 semantics, independent durability, host failure, external fencing, election, live read replicas, zero RPO, zero RTO, arbitrary interrupted page application, production load, or Linux. Structural checks use Python SQLite with `ignore_check_constraints=ON`; TrailBase-specific CHECK functions are not evaluated. Raw logs, keys, tokens, databases, ledgers, and machine results remain in the private work directory and must not be committed.
