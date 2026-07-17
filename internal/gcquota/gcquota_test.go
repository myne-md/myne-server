// SPDX-License-Identifier: AGPL-3.0

package gcquota

import (
	"testing"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

func acct(b byte) ids.AccountNumberHash {
	var a ids.AccountNumberHash
	a[0] = b
	return a
}
func dev(b byte) ids.DeviceID {
	var d ids.DeviceID
	d[0] = b
	return d
}
func blob(b byte) ids.BlobID {
	var id ids.BlobID
	id[0] = b
	return id
}
func nonce(b byte) [store.ContentNonceLen]byte {
	var n [store.ContentNonceLen]byte
	n[0] = b
	return n
}

// enroll registers an approved device directly in the registry for GC tests.
func enrollDev(t *testing.T, reg *auth.Registry, ts *auth.TokenStore, a ids.AccountNumberHash, d ids.DeviceID) {
	t.Helper()
	en := auth.NewEnrollment(reg, ts)
	if _, err := en.Enroll(a, d, auth.PathRecovery); err != nil { // recovery → self-approve
		t.Fatal(err)
	}
}

func TestHorizonGC_ReclaimsWhenAllActiveAcked(t *testing.T) {
	st := store.NewMemStore()
	reg := auth.NewRegistry()
	ts := auth.NewTokenStore(reg)
	a := acct(1)
	d1, d2 := dev(1), dev(2)
	enrollDev(t, reg, ts, a, d1)
	enrollDev(t, reg, ts, a, d2)
	reg.TouchActivity(a, d1, 100)
	reg.TouchActivity(a, d2, 100)

	// Push a blob then tombstone it (its changeSeq = 1).
	if _, err := st.PushBlob(a, blob(1), 0, nonce(1), []byte("x")); err != nil {
		t.Fatal(err)
	}
	_ = st.SetTombstone(a, blob(1), 1)

	g := NewHorizonGC(st, reg, DefaultPolicy())

	// Not all devices acked past seq 1 → not reclaimed.
	st.AckCursor(a, d1, 1)
	if rec, _ := g.Run(a, 100); rec != 0 {
		t.Fatalf("reclaimed %d before all acked, want 0", rec)
	}
	// Now d2 acks too → reclaimed.
	st.AckCursor(a, d2, 1)
	rec, _ := g.Run(a, 100)
	if rec != 1 {
		t.Fatalf("reclaimed %d, want 1", rec)
	}
	if _, _, reclaimed, ok := st.TombstoneRecord(a, blob(1)); !ok || !reclaimed {
		t.Fatalf("tombstone not marked reclaimed")
	}
	// The reclaim floor advanced (cursor-expired anchor).
	if st.GCFloor(a) != 1 {
		t.Fatalf("GCFloor = %d, want 1", st.GCFloor(a))
	}
}

func TestHorizonGC_SoftRetiresPastHorizonDevice(t *testing.T) {
	st := store.NewMemStore()
	reg := auth.NewRegistry()
	ts := auth.NewTokenStore(reg)
	a := acct(2)
	d1, dStale := dev(1), dev(9)
	enrollDev(t, reg, ts, a, d1)
	enrollDev(t, reg, ts, a, dStale)
	reg.TouchActivity(a, d1, 200)
	reg.TouchActivity(a, dStale, 10) // far behind

	// Tombstone acked only by the active device.
	if _, err := st.PushBlob(a, blob(1), 0, nonce(1), []byte("x")); err != nil {
		t.Fatal(err)
	}
	_ = st.SetTombstone(a, blob(1), 1)
	st.AckCursor(a, d1, 1)

	g := NewHorizonGC(st, reg, DefaultPolicy()) // horizon 120; cutoff = 200-120 = 80
	rec, retired := g.Run(a, 200)
	if retired != 1 {
		t.Fatalf("retired %d, want 1 (the stale device)", retired)
	}
	if rec != 1 {
		t.Fatalf("reclaimed %d, want 1 (stale device excluded from must-ack)", rec)
	}
	if r, _ := reg.Get(a, dStale); !r.Retired {
		t.Fatal("stale device not soft-retired")
	}
}

// F3 at the GC layer: a blob resurrected by a post-tombstone version advance
// must never be reclaimed by a later pass — the push cleared the tombstone
// record, so even a fully-acked sweep has nothing to act on.
func TestHorizonGC_ResurrectedBlobNotReclaimed(t *testing.T) {
	st := store.NewMemStore()
	reg := auth.NewRegistry()
	ts := auth.NewTokenStore(reg)
	a := acct(5)
	d1 := dev(1)
	enrollDev(t, reg, ts, a, d1)
	reg.TouchActivity(a, d1, 100)

	if _, err := st.PushBlob(a, blob(1), 0, nonce(1), []byte("v1")); err != nil {
		t.Fatal(err)
	}
	_ = st.SetTombstone(a, blob(1), 1)
	// Resurrection: a legitimate conflict push advances the version (seq 2).
	if _, err := st.PushBlob(a, blob(1), 1, nonce(2), []byte("v2")); err != nil {
		t.Fatal(err)
	}
	st.AckCursor(a, d1, 2) // fully acked — the ack gate would NOT protect it

	g := NewHorizonGC(st, reg, DefaultPolicy())
	if rec, _ := g.Run(a, 100); rec != 0 {
		t.Fatalf("reclaimed %d, want 0 (tombstone cleared by the version advance)", rec)
	}
	if ct, v, err := st.GetBlob(a, blob(1)); err != nil || v != 2 || string(ct) != "v2" {
		t.Fatalf("resurrected body damaged: %q v=%d err=%v", ct, v, err)
	}
}

func TestPolicy_HorizonFloor(t *testing.T) {
	p := Policy{HorizonMarkers: 5}.Clamp()
	if p.HorizonMarkers != MinHorizonMarkers {
		t.Fatalf("horizon %d, want clamped to %d", p.HorizonMarkers, MinHorizonMarkers)
	}
}

func TestRateLimiter_BucketAndRefill(t *testing.T) {
	rl := NewRateLimiter(2, 1)
	a := acct(3)
	if !rl.Allow(a) || !rl.Allow(a) {
		t.Fatal("first two requests should pass (burst=2)")
	}
	if rl.Allow(a) {
		t.Fatal("third request should be limited")
	}
	rl.Refill() // +1
	if !rl.Allow(a) {
		t.Fatal("after refill one request should pass")
	}
}

func TestQuotaGuard_Ceiling(t *testing.T) {
	st := store.NewMemStore()
	a := acct(4)
	qg := NewQuotaGuard(100)
	if qg.WouldExceed(st, a, 100) {
		t.Fatal("100 into empty 100-ceiling should fit")
	}
	if _, err := st.PushBlob(a, blob(1), 0, nonce(1), make([]byte, 80)); err != nil {
		t.Fatal(err)
	}
	if !qg.WouldExceed(st, a, 30) { // 80 + 30 > 100
		t.Fatal("80+30 over 100 ceiling should exceed")
	}
	if qg.WouldExceed(st, a, 20) { // 80 + 20 == 100
		t.Fatal("80+20 == 100 should fit")
	}
	// Unlimited ceiling never exceeds.
	if NewQuotaGuard(0).WouldExceed(st, a, 1<<40) {
		t.Fatal("unlimited ceiling should never exceed")
	}
}
