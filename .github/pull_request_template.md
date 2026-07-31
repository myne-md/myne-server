<!--
PR title = conventional-commit subject carrying the Plane ID, e.g.
  feat(storage): opaque blob GC by version counter (MYND-###)
Do NOT mention AI/assistant tooling anywhere — the commit-msg hook rejects attribution trailers.
-->

## Summary

<!-- What does this change, and why? -->

## Linked work

- Plane task: MYND-
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

- [ ] Conventional-commit subject carrying the Plane ID.
- [ ] The server still stores/relays **ciphertext only** — no plaintext, no key material, no way to decrypt.
- [ ] No cross-account correlation surface and **no persistent per-IP logging** introduced (abuse is per-account counters).
- [ ] Hosted and self-hosted still share the exact same trust boundary (TB5).
- [ ] Wire-protocol or storage-schema changes are reflected in `myne/docs/spec/server-protocol.md` and include migration notes.
- [ ] Tests / lint pass.

## Developer Certificate of Origin

- [ ] I certify the [DCO](https://developercertificate.org/): this contribution is mine to give under the repository's license (AGPL-3.0).
