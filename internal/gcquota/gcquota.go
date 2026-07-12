// SPDX-License-Identifier: AGPL-3.0

// Package gcquota is the tombstone horizon-GC + quota + rate-limit policy layer
// (MYND-422). It sits on the MYND-419 substrate (dedup-byte counter + tombstone
// record + per-device cursor ack) and the MYND-420 device registry (retire +
// coarse last-activity hook). It never inspects ciphertext, never learns "deleted"
// meaning (AS6), never keys on IP (C4 — rate-limit is keyed on account_number_hash).
package gcquota

import (
	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

// Policy is the operator-tunable knobs (protocol-vs-policy split). The PROTOCOL
// exposes the counters/markers; the OPERATOR sets these. Hosted MUST NOT enable
// ExtendedRetention or any IP logging; self-host MAY extend retention (a documented
// deviation — retention duration is a policy knob, not a trust-boundary property).
type Policy struct {
	// HorizonMarkers is the tombstone horizon, expressed in coarse activity-marker
	// units (e.g. day buckets). Design: 120 d default; self-host tunable with a
	// floor (>= MinHorizonMarkers) to keep the Cassandra-zombie margin.
	HorizonMarkers uint64
	// QuotaCeilingBytes is the per-account dedup-byte ceiling (0 = unlimited; hosted
	// value is set by the payment epic MYND-430).
	QuotaCeilingBytes uint64
	// ExtendedRetention, when true (self-host only), disables Layer-2 reclamation.
	ExtendedRetention bool
}

// Default markers (the design's 120 d default / 30 d floor, in day-bucket units).
const (
	DefaultHorizonMarkers = 120
	MinHorizonMarkers     = 30
)

// DefaultPolicy returns the hosted defaults (120-marker horizon, no extended
// retention; quota ceiling left 0 = set by MYND-430).
func DefaultPolicy() Policy {
	return Policy{HorizonMarkers: DefaultHorizonMarkers}
}

// Clamp enforces the self-host horizon floor.
func (p Policy) Clamp() Policy {
	if p.HorizonMarkers < MinHorizonMarkers {
		p.HorizonMarkers = MinHorizonMarkers
	}
	return p
}

// AttachmentReclaimer physically reclaims a tombstoned attachment BODY when its
// blob-plane tombstone record is reclaimed (MYND-468, §11.4: "no parallel
// attachment-GC path" — the body rides the record's unchanged ack-gated rule).
// Injected as a closure so gcquota never imports the attachments package.
// Returns the bytes released (aggregate metrics only).
type AttachmentReclaimer func(account ids.AccountNumberHash, attachmentIDHex string) (bytesFreed uint64, reclaimed bool)

// HorizonGC runs the hybrid horizon-GC over a vault.
type HorizonGC struct {
	store       store.BlobStore
	reg         *auth.Registry
	policy      Policy
	attachments AttachmentReclaimer // optional (nil = no attachment store wired)
}

// NewHorizonGC wires the store + registry + policy.
func NewHorizonGC(s store.BlobStore, reg *auth.Registry, p Policy) *HorizonGC {
	return &HorizonGC{store: s, reg: reg, policy: p.Clamp()}
}

// WithAttachmentReclaim attaches the attachment-body reclaim bridge (MYND-468).
func (g *HorizonGC) WithAttachmentReclaim(fn AttachmentReclaimer) *HorizonGC {
	g.attachments = fn
	return g
}

// Run performs one GC pass for an account at the given coarse current marker:
//   - soft-retire devices whose last-activity is older than (current - horizon)
//     (excluded from the must-ack set; on return they re-enroll → full-reconcile);
//   - for each not-yet-reclaimed tombstone, if EVERY horizon-active device's cursor
//     has acked past the tombstone's change-sequence, Layer-2 reclaim it (drop the
//     ciphertext, keep the marker). Returns the number reclaimed + retired.
//
// The current marker is a coarse monotone value (day bucket), NOT a wall-clock and
// never API-exposed (R4 — within the accepted A13 longitudinal-timing envelope).
func (g *HorizonGC) Run(account ids.AccountNumberHash, currentMarker uint64) (reclaimed, retired int) {
	cutoff := uint64(0)
	if currentMarker > g.policy.HorizonMarkers {
		cutoff = currentMarker - g.policy.HorizonMarkers
	}

	// Partition devices into horizon-active vs soft-retire.
	var active []ids.DeviceID
	for _, d := range g.reg.List(account) {
		if d.Retired {
			continue
		}
		if d.LastActivity != 0 && d.LastActivity < cutoff {
			// Past horizon → soft-retire (reuses AS16 retirement; on return the
			// device re-enrolls → forced full-reconcile, never silent resurrection).
			//
			// LastActivity == 0 means "never seen" (a freshly enrolled or a
			// persistence-restored device), NOT "infinitely stale". Phase 1 has no
			// production writer for LastActivity (TouchActivity is unwired), so every
			// device sits at 0; treating 0 as past-horizon would soft-retire the entire
			// fleet on the first hourly sweep (mass-401, undermining auth persistence).
			// Excluding 0 keeps the sweep a no-op until TouchActivity lands, and stays
			// forward-compatible: a device with any nonzero activity that falls behind
			// the horizon still retires as designed.
			_ = g.reg.Retire(account, d.DeviceID)
			retired++
			continue
		}
		active = append(active, d.DeviceID)
	}

	if g.policy.ExtendedRetention {
		// Self-host opted out of Layer-2 reclamation: soft-retire still runs, but
		// ciphertext is retained (documented policy deviation).
		return 0, retired
	}

	for _, blobID := range g.store.ListTombstones(account) {
		_, changeSeq, alreadyReclaimed, ok := g.store.TombstoneRecord(account, blobID)
		if !ok || alreadyReclaimed {
			continue
		}
		if g.allActiveAcked(account, active, changeSeq) {
			if err := g.store.ReclaimTombstone(account, blobID); err == nil {
				reclaimed++
				// MYND-468: a reclaimed ATTACHMENT record also drops its stored
				// body (one horizon, one ack rule, one retention switch — the
				// ExtendedRetention early-return above already skipped both).
				if g.attachments != nil {
					if attHex := g.store.BlobAttachmentID(account, blobID); attHex != "" {
						_, _ = g.attachments(account, attHex)
					}
				}
			}
		}
	}
	return reclaimed, retired
}

// allActiveAcked reports whether every horizon-active device has acked past seq.
func (g *HorizonGC) allActiveAcked(account ids.AccountNumberHash, active []ids.DeviceID, seq uint64) bool {
	for _, d := range active {
		if g.store.DeviceCursor(account, d) < seq {
			return false
		}
	}
	return true
}
