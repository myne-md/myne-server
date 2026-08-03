// SPDX-License-Identifier: AGPL-3.0

// Package httpapi is the bootstrap HTTP surface: a health endpoint behind the
// no-IP middleware, wired with the deny-by-default Authenticator seam. The
// push/pull/poke wire handlers land in MYND-421 (after auth, MYND-420); they will
// register on the same router behind a requireSession(Authenticator) guard.
package httpapi

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/myne-md/myne-server/internal/accounts"
	"github.com/myne-md/myne-server/internal/adminapi"
	"github.com/myne-md/myne-server/internal/attachments"
	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/authapi"
	"github.com/myne-md/myne-server/internal/authpersist"
	"github.com/myne-md/myne-server/internal/backup"
	"github.com/myne-md/myne-server/internal/gcquota"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/poke"
	"github.com/myne-md/myne-server/internal/store"
	"github.com/myne-md/myne-server/internal/syncapi"
)

// gcInterval is how often the horizon-GC scheduler sweeps (MYND-440). Coarse —
// reclamation is not latency-sensitive; the marker is a day bucket.
const gcInterval = time.Hour

// Connection-level timeouts (defense-in-depth). TB5 self-hosters may front the server
// with an untuned reverse proxy, so the server hardens itself rather than relying on
// the edge. ReadHeaderTimeout is the load-bearing slowloris defense (gosec G112): it
// bounds the time to receive request headers WITHOUT limiting body transfer, so a
// legitimate large opaque-blob push (up to syncapi.MaxBlobSize, 64 MiB) on a slow
// link is not truncated. IdleTimeout bounds kept-alive idle connections. ReadTimeout
// and WriteTimeout are deliberately left unset: a wall-clock cap on the whole request
// or response would cut off a slow but legitimate 64 MiB blob transfer — body-size
// abuse is bounded by http.MaxBytesReader in the handlers, not by a connection clock.
const (
	readHeaderTimeout = 15 * time.Second
	idleTimeout       = 120 * time.Second
)

// newHTTPServer builds an http.Server with the hardened connection timeouts applied.
// Both the public edge and the internal metrics listener route through it so neither
// is left with Go's unlimited defaults.
func newHTTPServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
	}
}

// boundPort returns the resolved TCP port a listener is bound to (0 if the
// listener is not TCP). With addr ":0" the OS assigns an ephemeral port; this is
// how the E2E harness (MYND-428) reads back the actual port race-free.
func boundPort(ln net.Listener) int {
	if tcp, ok := ln.Addr().(*net.TCPAddr); ok {
		return tcp.Port
	}
	return 0
}

// surfaceBoundAddr reports the resolved listen address so a harness binding ":0"
// can discover the ephemeral port without a race: it always logs the address,
// and — when MYNE_SERVER_PORTFILE is set — writes the bare port number to that
// file (the harness reads it back). Best-effort: a portfile write error is
// logged, not fatal (the log line still carries the address).
func surfaceBoundAddr(ln net.Listener) {
	log.Printf("myne-server: listening on %s", ln.Addr().String())
	pf := os.Getenv("MYNE_SERVER_PORTFILE")
	if pf == "" {
		return
	}
	if err := os.WriteFile(pf, []byte(strconv.Itoa(boundPort(ln))), 0o600); err != nil {
		log.Printf("myne-server: could not write portfile %q: %v", pf, err)
	}
}

// Run resolves the listener for addr (so ":0" picks an ephemeral port), surfaces
// the bound address (log + optional portfile, MYND-428), then serves until ctx
// is cancelled and shuts down gracefully. It wires the in-memory blind store +
// device registry + per-device token auth + push/pull routes + per-account
// rate-limit + quota guard (MYND-422), all behind the no-IP middleware.
func Run(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	surfaceBoundAddr(ln)
	return runListener(ctx, ln)
}

// runListener serves on an already-bound listener (the testable seam; Run
// resolves the listener and surfaces its port first).
func runListener(ctx context.Context, ln net.Listener) error {
	// Operator config from MYNE_* env vars (MYND-438, SYNC-23) — fail fast on any
	// invalid value so a misconfigured server never starts.
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	// Forward-only on-disk migrations run at boot, BEFORE listen (no concurrent
	// writes → nothing lost on rollback). Snapshot-verify-then-migrate is fail-closed;
	// a newer on-disk version than this binary supports refuses to start (SYNC-30).
	if cfg.StorageBackend == "fs" {
		if err := store.NewMigrator(cfg.StoragePath).Run(); err != nil {
			return err
		}
	}
	blobStore, err := cfg.newStore()
	if err != nil {
		return err
	}
	log.Printf("myne-server: storage=%s rate-limit=%d/%d quota-ceiling=%d horizon=%d extended-retention=%t",
		cfg.StorageBackend, cfg.RateLimitBurst, cfg.RateLimitRefill,
		cfg.Policy.QuotaCeilingBytes, cfg.Policy.HorizonMarkers, cfg.Policy.ExtendedRetention)

	// Pre-auth global limiters (DoS hardening): one for the /auth/* surface, one for
	// the pre-auth vault.meta GET. Two independent buckets so a meta-fetch flood does
	// not starve enrollment (and vice versa). Account/IP-independent by construction
	// (C4/AS14) — they smooth pre-auth churn; the hard bounds are the maps' caps.
	preAuthAuth := gcquota.NewGlobalLimiter(cfg.PreAuthBurst, cfg.PreAuthRefill)
	preAuthMeta := gcquota.NewGlobalLimiter(cfg.PreAuthBurst, cfg.PreAuthRefill)

	reg := auth.NewRegistry()
	tokens := auth.NewTokenStore(reg)
	authHandler := authapi.New(reg, tokens).
		WithPreAuthLimiter(preAuthAuth).
		WithLimits(int(cfg.MaxAccounts), int(cfg.MaxHandshakes), time.Duration(cfg.HandshakeTTLSeconds)*time.Second)

	// Persist device-auth state (registry + per-device tokens + per-account SCRAM
	// verifiers) so a restart does not de-enroll every device (clients would otherwise
	// 401 after every deploy/reboot/crash). fs-backend only — the mem backend stays
	// pure in-RAM. Load happens BEFORE listen: a corrupt/too-new auth.json fails closed
	// (refuses to start) rather than silently de-enrolling the fleet; an ABSENT file is
	// the legitimate first-boot path (start empty → one re-enroll → persists thereafter).
	var authCoord *authpersist.Coordinator
	if cfg.StorageBackend == "fs" {
		authCoord, err = authpersist.Wire(reg, tokens, authHandler, filepath.Join(cfg.StoragePath, "auth.json"))
		if err != nil {
			return err
		}
		// Coalesce auth-state writes: the handler hook marks dirty; this flusher writes
		// at most once per debounce window (kills the O(N²) save-per-mutation), and
		// flushes a final time on ctx cancel (below, synchronously) so nothing is lost.
		go authCoord.Start(ctx)
	}

	// Per-account operator enforcement policy (MYND-506): freeze + quota/device-cap
	// overrides, persisted to accounts.json beside auth.json. fs-backend only (mem is
	// the dev/E2E reference — no enforcement, like authpersist). Load fails closed on a
	// too-new/corrupt file; an absent file is first boot (empty → all defaults).
	var acctStore *accounts.Store
	if cfg.StorageBackend == "fs" {
		acctStore = accounts.New(filepath.Join(cfg.StoragePath, "accounts.json"))
		if err := acctStore.Load(); err != nil {
			return err
		}
		go acctStore.Start(ctx)
	}

	// Rate-limit keyed on account_number_hash, never IP (C4). Quota ceiling
	// 0 = unlimited until set (SYNC-23; hosted value lands with MYND-430). The
	// clamped horizon policy (cfg.Policy) is consumed by the GC scheduler (MYND-440).
	rl := gcquota.NewRateLimiter(cfg.RateLimitBurst, cfg.RateLimitRefill)
	qg := gcquota.NewQuotaGuard(cfg.Policy.QuotaCeilingBytes)
	if acctStore != nil {
		// A per-account quota override wins over the global ceiling; the enroll gate
		// enforces freeze + the effective per-account device cap (MYND-506).
		qg.WithOverride(acctStore.EffectiveQuota)
		authHandler.WithAccountGate(acctStore.Frozen, func(a ids.AccountNumberHash) uint64 {
			return acctStore.EffectiveMaxDevices(a, cfg.MaxDevicesPerAccount)
		})
	}

	// Refill the rate-limiter buckets periodically (server-internal timer; not a
	// user-facing timestamp).
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				rl.Refill()
				preAuthAuth.Refill()
				preAuthMeta.Refill()
			}
		}
	}()

	// Attachment store follows the SAME backend selection as the blob store
	// (MYND-468): fs shares the volume (one snapshot = blobs + attachments +
	// auth), mem is the dev/E2E reference. Before this the attachment store was
	// unconditionally in-memory — bodies vanished on restart and 64 MiB uploads
	// lived in RSS.
	var attachStore attachments.Backend
	if cfg.StorageBackend == "fs" {
		fsAttach, err := attachments.NewFSStore(cfg.StoragePath)
		if err != nil {
			return err
		}
		attachStore = fsAttach.WithMaxIDs(int(cfg.MaxAttachmentsPerVault))
	} else {
		attachStore = attachments.NewStore().WithMaxIDs(int(cfg.MaxAttachmentsPerVault))
	}

	ready := NewReadiness()
	metrics := NewMetrics()
	// F4: the production activity recorder — every authed sync touch stamps the
	// device's LastActivity with the shared day-bucket marker (the SAME unit the
	// horizon-GC sweep uses), so a long-silent device soft-retires and stops
	// blocking tombstone reclaim. Registry is in scope here; the closure keeps
	// syncapi decoupled from auth.Registry.
	activityTouch := func(a ids.AccountNumberHash, d ids.DeviceID) {
		_ = reg.TouchActivity(a, d, gcquota.DayBucketMarker())
	}
	// usedBytes is the unified AS17 stored-byte total the quota gate is defined
	// against — blobs + attachments. One definition, read by both /account/status and
	// the operator admin API so the two projections can't drift.
	usedBytes := gcquota.UnifiedUsedBytes(blobStore, attachStore)
	// GET /account/status projection (MYND-506): the caller's own stored bytes +
	// device count + frozen + EFFECTIVE ceilings. Same sources as the admin API,
	// scoped to one (token-resolved) account.
	accountStatus := func(a ids.AccountNumberHash) any {
		v := accountStatusView{
			StoredBytes: usedBytes(a),
			DeviceCount: reg.CountActiveDevices(a),
			QuotaBytes:  cfg.Policy.QuotaCeilingBytes,
			MaxDevices:  cfg.MaxDevicesPerAccount,
		}
		if acctStore != nil {
			v.Frozen = acctStore.Frozen(a)
			v.QuotaBytes = acctStore.EffectiveQuota(a, cfg.Policy.QuotaCeilingBytes)
			v.MaxDevices = acctStore.EffectiveMaxDevices(a, cfg.MaxDevicesPerAccount)
		}
		return v
	}
	srv := newHTTPServer(NewServer(blobStore, tokens, authHandler, rl, qg, ready, metrics, preAuthMeta, attachStore, activityTouch, acctStore, accountStatus, cfg.AllowedOrigins))

	// Aggregate-only metrics on a SEPARATE listener (SYNC-24) — never the public edge.
	// Disabled unless MYNE_METRICS_ADDR is set; bind it to localhost/internal only.
	var metricsSrv *http.Server
	if cfg.MetricsAddr != "" {
		metricsSrv = newHTTPServer(metrics.MetricsHandler())
		metricsSrv.Addr = cfg.MetricsAddr
		go func() {
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("myne-server: metrics listener: %v", err)
			}
		}()
	}

	// Horizon-GC scheduler (MYND-440, SYNC-25): periodically drive the existing
	// MYND-422 substrate across all accounts; report reclaimed count as an aggregate
	// metric. Only when the backend can enumerate accounts (mem/fs both can).
	// MYND-468: a reclaimed ATTACHMENT tombstone record also drops its stored body
	// via the reclaim bridge — one horizon, one ack rule, one retention switch
	// ("no parallel attachment-GC path", ledger SYNC-8). Enumeration stays the blob
	// store's: attachment bodies only become reclaimable through a blob-plane
	// tombstone record, so an account with bodies but no records has nothing to sweep.
	if lister, ok := blobStore.(interface {
		ListAccounts() []ids.AccountNumberHash
	}); ok {
		gc := gcquota.NewHorizonGC(blobStore, reg, cfg.Policy).
			WithAttachmentReclaim(func(a ids.AccountNumberHash, attHex string) (uint64, bool) {
				id, ok := attachments.ParseID(attHex)
				if !ok {
					return 0, false
				}
				freed, ok := attachStore.Reclaim(a, id)
				if ok {
					metrics.ObserveAttachmentReclaimed(freed)
				}
				return freed, ok
			})
		sched := gcquota.NewScheduler(gc, lister.ListAccounts, func(n int) {
			for i := 0; i < n; i++ {
				metrics.IncTombstoneReclaimed()
			}
		}, gcInterval)
		go sched.Start(ctx)
	}

	// Built-in encrypted off-box backup (MYND-505). Best-effort: a failed run logs
	// and is retried on the next tick — it never blocks serving. Only started when
	// enabled (which loadConfig already gates on the fs backend + a repo + a
	// password file). The ticker is an internal timer only; no wall-clock/IP surface.
	if cfg.BackupEnabled {
		backupSched := backup.NewScheduler(
			cfg.backupRunner(),
			cfg.StoragePath,
			time.Duration(cfg.BackupIntervalSeconds)*time.Second,
			func(err error) {
				log.Printf("backup: scheduled run failed, will retry next interval: %v", err)
			},
		)
		go backupSched.Start(ctx)
		log.Printf("backup: scheduled encrypted off-box backup every %ds (retention %dd)", cfg.BackupIntervalSeconds, cfg.BackupRetentionDays)
	}

	// Operator console admin API (MYND-506) on a LOCAL Unix domain socket — never a
	// TCP port / public edge; access is filesystem permissions on the socket. Disabled
	// unless MYNE_ADMIN_SOCKET is set. A bind failure fails startup; it serves until
	// ctx cancel.
	adminLn, err := adminapi.Listen(cfg.AdminSocket)
	if err != nil {
		return err
	}
	if adminLn != nil {
		// Live enforcement-state projection: accounts from the store, stored bytes =
		// blobs + attachments (the unified AS17 total), device count from the registry,
		// policy from the accounts store (nil on mem backend → defaults). No wall-clock
		// / activity / time-series is exposed (MYND-440 aggregate-only).
		listAccounts := func() []ids.AccountNumberHash {
			if l, ok := blobStore.(interface {
				ListAccounts() []ids.AccountNumberHash
			}); ok {
				return l.ListAccounts()
			}
			return nil
		}
		// Irreversible account delete (MYND-506) — remove-then-forget: blob +
		// attachment data first, then auth + policy, so no half-deleted account is
		// served if a later step fails.
		deleteAccount := func(a ids.AccountNumberHash) error {
			if err := blobStore.DeleteAccount(a); err != nil {
				return err
			}
			attachStore.DeleteAccount(a)
			authHandler.DeleteAccount(a)
			if acctStore != nil {
				acctStore.Delete(a)
			}
			return nil
		}
		adminMux := adminapi.New(listAccounts, usedBytes, reg.CountActiveDevices, acctStore, cfg.MaxAccounts).
			WithDelete(deleteAccount).Mux()
		go adminapi.Serve(ctx, adminLn, adminMux)
		log.Printf("myne-server: operator admin API on unix socket %s", cfg.AdminSocket)
	}

	// Migrations already ran (pre-listen, above) and the store is open → ready to serve.
	ready.SetReady()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		// Graceful shutdown: stop reporting ready so an orchestrator stops routing
		// before in-flight connections drain.
		ready.SetNotReady()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if authCoord != nil {
			authCoord.Flush() // synchronously persist any coalesced-but-unwritten auth state
		}
		if metricsSrv != nil {
			_ = metricsSrv.Shutdown(shutdownCtx)
		}
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// NewRouter builds a health-only HTTP handler behind the no-IP middleware. The
// Authenticator is the deny-by-default seam; used for the bootstrap health surface
// and tests. Use NewServer for the full server (health + sync routes).
func NewRouter(a auth.Authenticator) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthz)
	_ = a
	return noIP(mux)
}

// NewServer builds the full HTTP handler: health + the push/pull sync routes, all
// behind the no-IP middleware. Every sync route is session-bound via the token
// store (MYND-420); the health probe is the only open endpoint. rl/qg may be nil
// (policy disabled). attachStore is the attachment Backend (MYND-468 — the caller
// selects mem/fs to match the blob store; nil constructs a fresh in-memory one,
// the pre-468 behavior tests rely on).
// accountStatusView is the caller-facing GET /account/status body (MYND-506): the
// user's own live stats + EFFECTIVE ceilings + frozen state. Effective = the
// per-account override when set, else the global default (0 = unlimited).
type accountStatusView struct {
	StoredBytes uint64 `json:"stored_bytes"`
	DeviceCount uint64 `json:"device_count"`
	Frozen      bool   `json:"frozen"`
	QuotaBytes  uint64 `json:"quota_bytes"`
	MaxDevices  uint64 `json:"max_devices"`
}

func NewServer(s store.BlobStore, tokens *auth.TokenStore, authHandler *authapi.Handler, rl syncapi.RateLimiter, qg *gcquota.QuotaGuard, ready *Readiness, metrics *Metrics, preAuthMeta syncapi.PreAuthLimiter, attachStore attachments.Backend, activityTouch func(ids.AccountNumberHash, ids.DeviceID), acctStore *accounts.Store, accountStatus func(ids.AccountNumberHash) any, allowedOrigins string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthz)
	if ready != nil {
		mux.HandleFunc("/readyz", ready.handler) // readiness probe (MYND-440)
	}
	if attachStore == nil {
		attachStore = attachments.NewStore()
	}

	authHandler.Register(mux) // device auth + management (MYND-420/425); persistence-wired upstream
	notifier := poke.NewNotifier()
	syncMux := syncapi.New(s, tokens).WithPolicy(rl, qg).WithNotifier(notifier).WithPreAuthLimiter(preAuthMeta).
		// MYND-468 §11.4 bridge: an attachment tombstone record marks the stored
		// body deleted (absent to HEAD/GET); physical reclaim rides horizon-GC.
		WithAttachmentDeleter(func(a ids.AccountNumberHash, id [32]byte) {
			attachStore.MarkDeleted(a, attachments.AttachmentID(id))
		}).
		// F4: record device activity on every authed pull/push so the horizon-GC
		// soft-retire actually fires (a long-silent device leaves the must-ack set,
		// unblocking tombstone reclaim). nil when the caller wires no registry.
		WithActivityTouch(activityTouch).
		// #8: the push gate resolves "current" from the SAME unified total the
		// attachment route and /account/status use. It used to read the blob
		// store alone, so an account whose attachments already filled the quota
		// kept pushing note blobs past a ceiling its own status endpoint
		// reported as full.
		WithUsedBytes(gcquota.UnifiedUsedBytes(s, attachStore))
	if metrics != nil {
		syncMux = syncMux.WithMetrics(metrics.ObserveBlobStored)
	}
	if acctStore != nil {
		// Operator freeze gates PUSH here; pull never consults it (MYND-506).
		syncMux = syncMux.WithFrozenCheck(acctStore.Frozen)
	}
	if accountStatus != nil {
		syncMux = syncMux.WithAccountStatus(accountStatus) // GET /account/status (token-derived)
	}
	syncMux.Register(mux)
	// SSE poke (MYND-423): same per-account token bucket as the sync routes (one
	// token per connection attempt), plus the notifier's per-account stream cap
	// and a heartbeat keep-alive — the low-latency layer clients keep open while
	// unlocked (sync-protocol §8.3 as amended).
	poke.NewHandler(notifier, tokens).WithPolicy(rl).Register(mux)
	// Attachment transport: same per-account rate-limit + a UNIFIED quota — attachment
	// bytes are added to the blob store's per-account total against one AS17 ceiling
	// (no separate, bypassable budget), plus a per-vault id cap (OOM bound).
	attachMux := attachments.New(attachStore, tokens).
		WithPolicy(rl, qg, func(a ids.AccountNumberHash) uint64 { return s.QuotaBytes(a) })
	if metrics != nil {
		attachMux = attachMux.WithMetrics(metrics.ObserveAttachmentStored)
	}
	if acctStore != nil {
		// #9: the same operator freeze the sync push honours. Uploads precede
		// the push, so gating one route and not the other let a frozen account
		// keep writing the bytes GC cannot reclaim.
		attachMux = attachMux.WithFrozenCheck(acctStore.Frozen)
	}
	attachMux.Register(mux) // resumable transport (MYND-423)

	// noIP stays the OUTERMOST layer, blanking RemoteAddr before anything reads it.
	// The request-count + structured access-log middleware sit INSIDE noIP, so they
	// never observe a client IP (defense in depth, SYNC-24).
	var h http.Handler = mux
	if metrics != nil {
		h = metrics.middleware(h)
	}
	h = accessLog(nil, h)
	// CORS for the browser client (main repo phase3-web-client task 34) sits
	// directly INSIDE noIP and outside everything else: preflights must be
	// answered before any router or token check runs, because the routes the
	// browser hits first are pre-auth ones and several do not implement OPTIONS
	// at all. Empty allowlist = nil policy = no CORS code path.
	h = cors(parseAllowedOrigins(allowedOrigins), h)
	return noIP(h)
}
