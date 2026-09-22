# KNOWN GAPS — B2B server surface (myne-md/myne#711)

Flagged by `/pr-review` on the branch. These ship in this branch but are NOT
complete; they are recorded here so the gap is not silent. Each is a follow-up,
not a "known and accepted" state.

1. **B2B state is RAM-only.** `membership`, `relay`, `profiles` and the
   retirement registry are constructed inline in `httpapi.NewServer` and have no
   persistence layer, unlike device auth (`auth.json`). On a restart: pending
   invites and the only copy of person-private `MYY5` profiles are lost;
   `HasOwner(vault)` goes false so a surviving vault device token can again write
   `vault.meta` (the owner-only gate reverts to the pre-B2B path); a retired sync
   id is no longer refused. Fix: serialize and reload these stores alongside
   `Devices`/`Tokens`/`Creds`, or refuse B2B on the fs backend.
2. **Reclamation never runs.** `retirement.DueReclaims` has no production
   caller, so the grace-bounded reclamation window records but never deletes.
   Fix: a scheduler that calls `DueReclaims()` and deletes the named blobs.
3. **B2B routes are not rate-limited.** `h.rl` gates only the sync routes and the
   pre-auth limiter only `/auth/*`; the relay, membership, profile and retire
   routes are unbounded for an authenticated caller. Fix: wrap them in a shared
   limiter or a per-account quota.
4. **Access log carries the vault/person id in the URL path.**
   `/b2b/vaults/{hash}/...` writes the account hash (and the person id or profile
   id) into the access log, a per-account timeline. Fix: redact or normalize the
   `/b2b/...` path segments in `accessLog`.
