# myne-server — Phase 2 sync server (placeholder)

> Companion repository to [`myne`](https://github.com/myne-md/myne). License: AGPL-3.0-or-later (matches main repo).

## Status

**Phase 2 — not yet started.** This repository is an empty scaffold; no application logic has shipped.

Phase 1 (current) is desktop-only with local vault storage; Phase 2 introduces this Go-based zero-knowledge sync server. Until Phase 1's recovery drill closes (see main repo `the agent tooling repository/features/phase-1-plan/shared.md` pre-ship gate), do not start work here.

## Stack target

- **Go** (per `vision.md` Phase 2; matches existing team expertise)
- libsodium-equivalent crypto via `golang.org/x/crypto` — primitives must produce **bit-identical outputs** to Phase 1 Rust client (validated by [`myne-test-vectors/`](https://github.com/myne-md/myne-test-vectors))
- No custom primitive implementations
- Hash-pinned `go.sum`; minimal direct dependencies (same discipline as main repo Phase 1)

## Hard architectural commitments (from `vision.md` + main repo CLAUDE.md)

These are **non-negotiable**. Walking any of them back silently breaks the zero-knowledge claim:

- **No persistent server-side IP logging.** Abuse mitigation works on per-account counters, not per-IP. This must be in the protocol design from day one, not retrofitted.
- **User-meaningful timestamps live inside the encrypted blob.** The server uses an opaque per-note version counter for conflict detection; conflict resolution happens client-side after decryption. **No server-side last-write-wins.**
- **Self-hosted and hosted servers share the exact same trust boundary (TB5).** Same protocol, same security model. Operator-level distinction does not exist; what a hosted operator can see, a self-host operator can see (and vice versa).
- **No email at signup, no email recovery — ever.** This applies to both client and server.

## Deferred design decisions (Phase 2 start)

When Phase 2 begins, document these in the main repo `design notes.md`:
- Auth mechanism — main repo has v005 OPAQUE commitment (`decisions.md` 2026-04-26 "Server-auth deliberately deferred to Phase 2") but Phase 2 may decide differently
- Conflict resolution UX (client-side, but server's per-note version counter shape needs a spec)
- Server protocol document — `docs/spec/server-protocol.md` (does not exist yet) is where this goes

## Vector verification

Every server-side primitive (Argon2id, HKDF-SHA-256, XChaCha20-Poly1305+CTX) must be validated against the `myne-test-vectors/` companion. CI gates merge on green vectors.

## Gotchas

- **Don't add `User-Agent` or `X-Forwarded-For` parsing without thinking.** These leak per-IP info into logs unless explicitly discarded; the no-IP-logging commitment requires active discarding, not just passive non-logging.
- **`time.Now()` server-side is for opaque version counters only.** It is NOT a user-meaningful timestamp; never expose it in API responses as if it were.
- **Operator-policy docs go in `docs/self-host-policy.md`** in the main repo (Plan 1 §C8a/C8b), not here.
