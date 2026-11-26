# AGENTS.md

Guidance for coding agents working in this repository. It is public: do not add
private hostnames, credentials, internal runbook names or links to repositories
that are not published.

## What this repository is

The zero-knowledge sync server for Myne: a Go program that stores and relays
encrypted blobs. It never sees plaintext, the master password, the recovery
phrase or a key that could decrypt anything. It is trust boundary TB5 in the
protocol's threat model: a curious or compelled operator sees opaque blobs,
hashed account identifiers, counters and aggregate quota — nothing more.

## Layout

- `cmd/myne-server/` — the binary.
- `internal/httpapi/` — routing, config, CORS, logging, metrics, health.
- `internal/store/` — `mem` and `fs` backends.
- `internal/accounts/`, `auth/`, `authapi/` — account numbers, SCRAM, device approval.
- `internal/syncapi/`, `attachments/`, `awareness/`, `poke/` — sync, attachments, live frames, SSE.
- `internal/b2bpersist/`, `membership/`, `grouppkg/`, `profiles/`, `relay/`, `headid/` — the B2B surface.
- `internal/adminapi/`, `panel/`, `console/` — operator surfaces.
- `internal/backup/`, `gcquota/`, `ids/`, `authpersist/` — backup/restore, quota/reclaim, ids.
- `deploy/` — Helm charts and Kubernetes manifests.
- `Dockerfile`, `scripts/fetchtool`, `scripts/repro-gate.sh`.

## Build and test

```bash
go build ./...
go test ./... -count=1
```

The byte-level vector gate expects a checkout of the public
[`myne-test-vectors`](https://github.com/myne-md/myne-test-vectors) repository:

```bash
MYNE_TEST_VECTORS_DIR=/path/to/myne-test-vectors go test ./... -run Vector -count=1 -v
```

`go.mod` is pure standard library today; there is no `go.sum`. The image bundles
sha256-pinned restic and rclone, fetched by `scripts/fetchtool`; see `NOTICE`.

## Rules

- **Ciphertext only.** No plaintext, no key material, no decrypt path.
- **No persistent per-IP logging.** Abuse is per-account counters.
- **No server-side last-write-wins.** The per-note counter is opaque; user
  timestamps live inside the encrypted blob.
- **No email at signup or recovery — ever.**
- Wire-protocol or storage-schema changes update the main repo's
  `docs/spec/server-protocol.md` and include migration notes.
- Docker image bases and bundled binaries stay pinned by digest/sha256; the image
  is built from this source, not pulled from an unpublished package.
- Commits carry a `Signed-off-by:` trailer (DCO 1.1). No CLA.
- Never commit credentials, tokens, private keys or internal hostnames.
- Security reports go through `SECURITY.md`; do not open a public issue.

## License

Code and documentation are AGPL-3.0-only. The banner and Myne Marks are not
licensed; see `LICENSING.md`, `LICENSE-ASSETS` and `TRADEMARK.md`.
