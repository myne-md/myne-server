# KNOWN GAPS — B2B server surface (myne-md/myne#711)

Flagged by `/pr-review` on the branch. These ship in this branch but are NOT
complete; they are recorded here so the gap is not silent. Each is a follow-up,
not a "known and accepted" state.

1. **B2B state is RAM-only — FIXED (`internal/b2bpersist`).** The membership bindings and
   per-vault tokens, the invite relay, the person-private profile store, the group-package
   relay and the retirement registry are serialized to ONE `b2b.json` beside `auth.json`
   (0600, same volume, fs backend only), loaded before listen and flushed on SIGTERM. The
   retirement registry is also hoisted out of the sync surface's constructor
   (`httpapi.WithRetirementRegistry`), so the instance the persistence loads is the instance
   the enforcement uses. Covered by `internal/b2bpersist/b2bpersist_test.go` (a save/reload
   cycle through a real restart, plus the fail-closed cases).
2. **Reclamation never runs — FIXED (myne-server#17).** `retirement.DueReclaims` had no
   production caller, so the grace window recorded and never deleted. It is now driven by
   `gcquota.RetirementReclaimer`, and the store gained `ReclaimRetired` (both backends): it
   drops a retired namespace's ciphertext body without requiring a tombstone record, which is
   what made the old path unable to touch a retired id at all. The registry exposes a
   non-consuming `DueRetirements` plus `Reclaimed`, so a FAILED reclaim stays due and is
   retried instead of being lost. Covered by `internal/store/retirement_reclaim_test.go` (both
   backends) and `internal/gcquota/retirement_test.go`.
3. **B2B routes are not rate-limited — FIXED (myne-server#18).** The ten `/b2b/*` routes now
   pass through a per-account bucket (`authapi.WithB2BRateLimiter`, keyed on the resolved
   vault/account, never an IP), and `/b2b/vaults/{account_hash}/retire` — which lives on the
   SYNC mux and so was missing from every scoped fix — consults the sync bucket like its
   neighbours.
4. **Access log carries the vault/person id in the URL path.**
   `/b2b/vaults/{hash}/...` writes the account hash (and the person id or profile
   id) into the access log, a per-account timeline. Fix: redact or normalize the
   `/b2b/...` path segments in `accessLog`.
