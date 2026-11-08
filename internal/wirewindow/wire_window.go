package wirewindow

// This package publishes the numbers the CLIENTS must agree with, and holds them
// to this repository's own constants.
//
// Before it existed the agreement was checked only by a script in the client
// repository that scraped these Go sources for `const` lines and compared them
// with the Rust constants. That script cannot run where this checkout is absent -
// which is every push in a fresh client worktree - so on both sides the numbers
// were, in practice, unverified.
//
// The rule this package states is one-directional on purpose: change a number
// HERE and `go test ./...` fails until `wire-window.json` is re-emitted, because a
// number that moves without the client learning about it is the whole defect. The
// client pins the same file and asserts its own constants against it.

import (
	_ "embed"
	"encoding/json"
)

// File is the published artefact, embedded so a test cannot pass against a
// different copy than the one the repository ships.
//
//go:embed wire-window.json
var File []byte

// Window is the on-disk shape. Field names are the contract: the client's test
// deserialises exactly these, so renaming one breaks it loudly rather than quietly
// defaulting a bound to zero.
type Window struct {
	EmittedFrom         string `json:"emitted_from"`
	SSEHeartbeatS       int64  `json:"sse_heartbeat_s"`
	AwarenessHeartbeatS int64  `json:"awareness_heartbeat_s"`
	MaxBlobFetchIDs     int64  `json:"max_blob_fetch_ids"`
	MaxBlobFetchBytes   int64  `json:"max_blob_fetch_bytes"`
}

// Load parses the embedded artefact.
func Load() (Window, error) {
	var w Window
	err := json.Unmarshal(File, &w)
	return w, err
}
