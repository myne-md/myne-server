## Summary

<!-- What does this change, and why? -->

## Linked work

- Closes #

## Type of change

- [ ] Bug fix
- [ ] Feature / enhancement
- [ ] Documentation / spec
- [ ] Refactor / chore
- [ ] Breaking change (wire protocol or storage schema)

## How was this tested?

<!-- Commands run, deployment covered (Docker / bare / etc.). -->

## Trust-boundary checklist

- [ ] The server still stores/relays **ciphertext only** — no plaintext, no key material, no way to decrypt.
- [ ] No cross-account correlation surface and **no persistent per-IP logging** introduced (abuse is per-account counters).
- [ ] Hosted and self-hosted still share the exact same trust boundary (TB5).
- [ ] Wire-protocol or storage-schema changes are reflected in `myne/docs/spec/server-protocol.md` and include migration notes.
- [ ] `gofmt`, `go vet`, `go test ./...` pass; the vector gate passes with `MYNE_TEST_VECTORS_DIR`.

## Developer Certificate of Origin

- [ ] I certify the [DCO](https://developercertificate.org/): this contribution is mine to give under AGPL-3.0-only.
