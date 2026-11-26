// SPDX-License-Identifier: AGPL-3.0-only

// Command myne-server is the Phase 2 zero-knowledge sync server: a blind blob
// store that persists opaque ciphertext per vault and never reads, merges, or
// reorders plaintext (trust boundary TB5). This is the bootstrap entry point;
// the push/pull/poke wire handlers land in a later slice (MYND-421) behind the
// authenticated session seam (MYND-420). It serves only a health endpoint today.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/myne-md/myne-server/internal/adminapi"
	"github.com/myne-md/myne-server/internal/httpapi"
)

func main() {
	// Subcommand dispatch (the distroless runtime image has no shell, so these are
	// invoked directly, never via a wrapper script).
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck":
			// Self-probe for the container HEALTHCHECK: the binary probes its own
			// /healthz over loopback and maps the result to an exit code. Reads only
			// the static 200 body — no IP/timestamp surface.
			os.Exit(httpapi.HealthCheckProbe(os.Getenv("MYNE_SERVER_ADDR")))
		case "backup", "backup-check", "restore":
			// On-demand encrypted off-box backup / integrity check / restore
			// (MYND-505). Runs the bundled restic against the fs store and exits by
			// result. Cancelled cleanly on SIGTERM so a long operation doesn't wedge
			// a shutdown.
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			sub := os.Args[1]
			if sub == "backup-check" {
				sub = "check"
			}
			os.Exit(httpapi.BackupCLI(ctx, sub, os.Args[2:]))
		case "admin":
			// Operator console CLI (MYND-506): a thin client over the local admin
			// Unix socket. No server process runs here; it dials the running server.
			os.Exit(adminapi.RunCLI(os.Getenv("MYNE_ADMIN_SOCKET"), os.Args[2:]))
		}
	}

	addr := os.Getenv("MYNE_SERVER_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// httpapi.Run resolves the listener and logs the *bound* address (so ":0"
	// reports its ephemeral port); announce only the requested addr here.
	log.Printf("myne-server: blind blob store (bootstrap) starting on %s", addr)
	if err := httpapi.Run(ctx, addr); err != nil {
		log.Fatalf("myne-server: %v", err)
	}
}
