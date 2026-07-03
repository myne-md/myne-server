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

	"github.com/myne-md/myne-server/internal/attachments"
	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/authapi"
	"github.com/myne-md/myne-server/internal/authpersist"
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

	// Rate-limit keyed on account_number_hash, never IP (C4). Quota ceiling
	// 0 = unlimited until set (SYNC-23; hosted value lands with MYND-430). The
	// clamped horizon policy (cfg.Policy) is consumed by the GC scheduler (MYND-440).
	rl := gcquota.NewRateLimiter(cfg.RateLimitBurst, cfg.RateLimitRefill)
	qg := gcquota.NewQuotaGuard(cfg.Policy.QuotaCeilingBytes)

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

	ready := NewReadiness()
	metrics := NewMetrics()
	srv := newHTTPServer(NewServer(blobStore, tokens, authHandler, rl, qg, ready, metrics, preAuthMeta, int(cfg.MaxAttachmentsPerVault)))

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
	if lister, ok := blobStore.(interface {
		ListAccounts() []ids.AccountNumberHash
	}); ok {
		gc := gcquota.NewHorizonGC(blobStore, reg, cfg.Policy)
		sched := gcquota.NewScheduler(gc, lister.ListAccounts, func(n int) {
			for i := 0; i < n; i++ {
				metrics.IncTombstoneReclaimed()
			}
		}, gcInterval)
		go sched.Start(ctx)
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
// (policy disabled).
func NewServer(s store.BlobStore, tokens *auth.TokenStore, authHandler *authapi.Handler, rl syncapi.RateLimiter, qg *gcquota.QuotaGuard, ready *Readiness, metrics *Metrics, preAuthMeta syncapi.PreAuthLimiter, attachMaxIDs int) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthz)
	if ready != nil {
		mux.HandleFunc("/readyz", ready.handler) // readiness probe (MYND-440)
	}

	authHandler.Register(mux) // device auth + management (MYND-420/425); persistence-wired upstream
	notifier := poke.NewNotifier()
	syncMux := syncapi.New(s, tokens).WithPolicy(rl, qg).WithNotifier(notifier).WithPreAuthLimiter(preAuthMeta)
	if metrics != nil {
		syncMux = syncMux.WithMetrics(metrics.ObserveBlobStored)
	}
	syncMux.Register(mux)
	poke.NewHandler(notifier, tokens).Register(mux) // opt-in SSE (MYND-423)
	// Attachment transport: same per-account rate-limit + a UNIFIED quota — attachment
	// bytes are added to the blob store's per-account total against one AS17 ceiling
	// (no separate, bypassable budget), plus a per-vault id cap (OOM bound).
	attachments.New(attachments.NewStore().WithMaxIDs(int(attachMaxIDs)), tokens).
		WithPolicy(rl, qg, func(a ids.AccountNumberHash) uint64 { return s.QuotaBytes(a) }).
		Register(mux) // resumable transport (MYND-423)

	// noIP stays the OUTERMOST layer, blanking RemoteAddr before anything reads it.
	// The request-count + structured access-log middleware sit INSIDE noIP, so they
	// never observe a client IP (defense in depth, SYNC-24).
	var h http.Handler = mux
	if metrics != nil {
		h = metrics.middleware(h)
	}
	h = accessLog(nil, h)
	return noIP(h)
}
