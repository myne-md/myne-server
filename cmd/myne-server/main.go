// SPDX-License-Identifier: AGPL-3.0

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

	"github.com/myne-md/myne-server/internal/httpapi"
)

func main() {
	// `myne-server healthcheck` is a self-probe for the container HEALTHCHECK:
	// the distroless runtime image has no shell or curl, so the binary probes
	// its own /healthz over loopback and maps the result to an exit code. It
	// reads only the static 200 body — no IP/timestamp surface.
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(httpapi.HealthCheckProbe(os.Getenv("MYNE_SERVER_ADDR")))
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
