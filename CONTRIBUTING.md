# Contributing

Thanks for improving the Myne sync server. The server is deliberately small at
the trust boundary: it stores ciphertext, relays it, and never holds a key.

## Before you start

- For a bug, open an issue with the Go version, storage backend, and the exact
  request/response shape.
- For a security issue, do **not** open a public issue; follow `SECURITY.md`.
- For a wire-protocol or storage-schema change, open a short proposal and update
  the main repo's `docs/spec/server-protocol.md` in the same change. Migration
  notes are part of the change, not a follow-up.

## Build and test

```bash
go build ./...
go test ./... -count=1
```

The byte-level vector gate uses the public `myne-test-vectors` repository:

```bash
git clone https://github.com/myne-md/myne-test-vectors /tmp/myne-test-vectors
MYNE_TEST_VECTORS_DIR=/tmp/myne-test-vectors go test ./... -run Vector -count=1 -v
```

No third-party Go modules are used today; if you add one, it must be pinned and
recorded in `NOTICE`.

## Trust-boundary checklist

- The server stores and relays ciphertext only; no plaintext, key material or
  decrypt path.
- No persistent per-IP logging; abuse mitigation is per-account.
- No server-side last-write-wins; user timestamps stay inside the encrypted blob.
- No email signup or recovery.
- Wire/storage changes carry spec and migration notes.
- Tests and `go vet` pass.

## DCO

Every commit carries a `Signed-off-by:` trailer:

```bash
git commit -s
```

The [Developer Certificate of Origin 1.1](https://developercertificate.org/)
applies. There is no CLA. Code and documentation are AGPL-3.0-only; the banner
and Myne Marks are not licensed (see `LICENSING.md`).
