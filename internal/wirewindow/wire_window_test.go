package wirewindow_test

import (
	"testing"
	"time"

	"github.com/myne-md/myne-server/internal/awareness"
	"github.com/myne-md/myne-server/internal/poke"
	"github.com/myne-md/myne-server/internal/syncapi"
	"github.com/myne-md/myne-server/internal/wirewindow"
)

// The client pins the same file, so a number that moves here without a re-emit
// leaves the client asking for a window this server no longer serves - a truncated
// fetch at best, a reconnect loop at worst. Failing here is what forces the emit.
func TestThePublishedWindowMatchesThisServersConstants(t *testing.T) {
	w, err := wirewindow.Load()
	if err != nil {
		t.Fatalf("wire-window.json does not parse: %v", err)
	}

	if got, want := w.SSEHeartbeatS, int64(poke.DefaultHeartbeatInterval/time.Second); got != want {
		t.Errorf("sse_heartbeat_s is %d but poke.DefaultHeartbeatInterval is %ds: re-emit wire-window.json and bump the client's pin", got, want)
	}
	if got, want := w.AwarenessHeartbeatS, int64(awareness.DefaultHeartbeat/time.Second); got != want {
		t.Errorf("awareness_heartbeat_s is %d but awareness.DefaultHeartbeat is %ds: re-emit wire-window.json", got, want)
	}
	if got, want := w.MaxBlobFetchIDs, int64(syncapi.MaxBlobFetchIDs); got != want {
		t.Errorf("max_blob_fetch_ids is %d but syncapi.MaxBlobFetchIDs is %d: re-emit wire-window.json and bump the client's pin", got, want)
	}
	if got, want := w.MaxBlobFetchBytes, int64(syncapi.MaxBlobFetchBytes); got != want {
		t.Errorf("max_blob_fetch_bytes is %d but syncapi.MaxBlobFetchBytes is %d: re-emit wire-window.json and bump the client's pin", got, want)
	}
}

// A zero in the artefact would make every comparison above pass by matching a
// bound the client also reads as zero, so the file is checked for meaning too.
func TestThePublishedWindowCarriesNoZeroBound(t *testing.T) {
	w, err := wirewindow.Load()
	if err != nil {
		t.Fatalf("wire-window.json does not parse: %v", err)
	}
	if w.EmittedFrom == "" {
		t.Error("emitted_from is empty: the pin must name the commit it came from so its age is visible")
	}
	for name, v := range map[string]int64{
		"sse_heartbeat_s":       w.SSEHeartbeatS,
		"awareness_heartbeat_s": w.AwarenessHeartbeatS,
		"max_blob_fetch_ids":    w.MaxBlobFetchIDs,
		"max_blob_fetch_bytes":  w.MaxBlobFetchBytes,
	} {
		if v <= 0 {
			t.Errorf("%s is %d, which is not a window", name, v)
		}
	}
}
