# myne-server — Phase 2 sync server (placeholder)

> Companion repository to [`myne`](https://github.com/myne-md/myne). License: AGPL-3.0 (matches main repo).

## Status

**Phase 2 — in progress (MYND-419–423).** The blind blob store is implemented: 11 Go packages, all
tests green. Bootstrap (Go module + AGPL + CI + blind store + per-note version counter), auth
(SCRAM-SHA-256-PLUS + per-device tokens + device-approval gate), push/pull (`/sync/push`, `/sync/pull`,
`/sync/blob` — CAS + cursor + error codes), GC/quota (horizon-GC + per-account quota + rate-limit, never
IP), and attachments (resumable range + poke) have landed. Run `go test ./...` from this directory.

The `:0` ephemeral-port surfacing (`MYNE_SERVER_ADDR=:0` + `MYNE_SERVER_PORTFILE`, MYND-428 task 1) lets
the desktop E2E harness spawn an isolated server per test file and read the bound port back race-free.

Phase 1 is desktop-only with local vault storage; this Go-based zero-knowledge sync server is the
Phase 2 server side. The client side (engine, device-mgmt, deletion, fork-conflict) lives in the main
`myne` repo (MYND-424–428).

## Stack target

- **Go** (per `vision.md` Phase 2; matches existing team expertise)
- libsodium-equivalent crypto via `golang.org/x/crypto` — primitives must produce **bit-identical outputs** to Phase 1 Rust client (validated by [`myne-test-vectors/`](https://github.com/myne-md/myne-test-vectors))
- No custom primitive implementations
- Hash-pinned `go.sum`; minimal direct dependencies (same discipline as main repo Phase 1)

## Hard architectural commitments (from `vision.md` + main repo AGENTS.md)

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

Every server-side primitive must be validated against the `myne-test-vectors/` companion, and **CI really does gate on it** — `the CI configuration` clones the companion with the `vectors_token` secret, pins it to an explicit SHA, and fails the step outright when the secret is missing rather than skipping. This repo is currently the *only* one in the project where the vector gate runs in CI; the main repo's `vector-verification` step and mobile's `protocol-vectors` step are both commented out (see the main repo's `the CI configuration`, MYND-635).

**Which primitives, precisely** — this list used to read "Argon2id, HKDF-SHA-256, XChaCha20-Poly1305+CTX", and none of those three exist in this codebase. They cannot: the server is zero-knowledge, never holds `root_key` and never decrypts vault content, so it has no KEK derivation and no AEAD. Naming them here described a client and invited someone to "restore" crypto the trust boundary forbids. What the server actually implements, and what the vectors pin:

| Surface | Primitive | Vector category |
|---|---|---|
| Device enrolment / auth | SCRAM-SHA-256-PLUS over **PBKDF2**-HMAC-SHA-256 (`internal/auth/scram`) | `scram-auth` |
| Channel binding | the RFC 9266 `tls-exporter` label + length constants | `tls-exporter` |
| Fork-consistency head | canonical head encoding + head-id (`internal/headid`) | `vault-head` |

Three categories, not the whole companion — the other 49 are client-side surfaces this server never touches. The Go runners **skip with a message** when the companion is absent (`t.Skipf`), which is why the CI step clones it explicitly instead of relying on a checkout that might not be there: a skipped vector test is a green test that verified nothing.

The companion is pinned to a **fixed SHA** rather than tracking `develop`, deliberately — bump it in its own commit when the three categories above change, so a vector edit and a server change never land as one indistinguishable green run.

## Gotchas

- **Don't add `User-Agent` or `X-Forwarded-For` parsing without thinking.** These leak per-IP info into logs unless explicitly discarded; the no-IP-logging commitment requires active discarding, not just passive non-logging.
- **`time.Now()` server-side is for opaque version counters only.** It is NOT a user-meaningful timestamp; never expose it in API responses as if it were.
- **Operator-policy docs go in `docs/self-host-policy.md`** in the main repo (Plan 1 §C8a/C8b), not here.
- **Unix-socket paths are capped at ~104 bytes (`sun_path`).** `net.Listen("unix", path)` fails with `bind: invalid argument` when the path is too long — and `t.TempDir()` embeds the full test name, which blows the limit on macOS. Keep socket paths short: use `os.MkdirTemp("", "a")` in tests, and short deploy paths (`/tmp/myne-admin.sock`, `/run/myne/admin.sock`) in prod. Bit the admin socket (MYND-506); would bite any future UDS the same way.
