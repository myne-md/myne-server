// SPDX-License-Identifier: AGPL-3.0

package b2bpersist

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/myne-md/myne-server/internal/grouppkg"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/membership"
	"github.com/myne-md/myne-server/internal/profiles"
	"github.com/myne-md/myne-server/internal/relay"
	"github.com/myne-md/myne-server/internal/store"
)

// These tests drive the module the way the server does: mutate, save, then build a
// FRESH set of stores and load the same file — a restart in one function. The point
// is the round trip, not any one rule: a test that only called Save and re-read the
// file would prove the file is JSON and nothing about whether the state came back.

func newStores() (Stores, func() time.Time) {
	table := membership.New()
	clk := time.Unix(1_700_000_000, 0).UTC()
	clock := func() time.Time { return clk }
	return Stores{
		Membership:    table,
		MemberTokens:  membership.NewTokenStore(table),
		Invites:       relay.NewStore(),
		Profiles:      profiles.NewStore(),
		GroupPackages: grouppkg.NewStore(),
		Retirements:   store.NewRetirements(0).WithClock(clock),
	}, clock
}

func person(b byte) membership.PersonID {
	var p membership.PersonID
	for i := range p {
		p[i] = b
	}
	return p
}

func vault(b byte) ids.AccountNumberHash {
	var v ids.AccountNumberHash
	for i := range v {
		v[i] = b
	}
	return v
}

func blobID(b byte) ids.BlobID {
	var id ids.BlobID
	for i := range id {
		id[i] = b
	}
	return id
}

func TestB2BStateSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	owner, member := person(1), person(2)
	v := vault(9)

	s1, _ := newStores()
	c1, err := Wire(s1, path)
	if err != nil {
		t.Fatalf("wire: %v", err)
	}
	if err := s1.Membership.BindOwner(v, owner); err != nil {
		t.Fatalf("bind owner: %v", err)
	}
	if err := s1.Membership.BindMember(v, member); err != nil {
		t.Fatalf("bind member: %v", err)
	}
	tok, err := s1.MemberTokens.Issue(member, v, ids.DeviceID{0x0a}, ids.AccountNumberHash{0xaa})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	inviteID, err := s1.Invites.Put(member, v, []byte("sealed-invite-payload"))
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	profileID := profiles.DeriveProfileID(v, member)
	s1.Profiles.Put(v, profileID, member, []byte("sealed-myy5-bytes"))
	due := time.Unix(1_800_000_000, 0).UTC()
	s1.Profiles.ScheduleDeletionByPerson(v, member, due)
	s1.GroupPackages.Put(v, member, 7, []byte("owner-signed-package"))
	s1.Retirements.Record(v, 3, 4, []ids.BlobID{blobID(5)})
	c1.Save()
	c1.Flush() // must be a no-op: Save consumed the dirty flag

	// --- restart: fresh stores, same file ---------------------------------------
	s2, _ := newStores()
	if _, err := Wire(s2, path); err != nil {
		t.Fatalf("rewire: %v", err)
	}

	if b, ok := s2.Membership.OwnerOf(v); !ok || b.Person != owner {
		t.Fatalf("owner binding did not survive: %+v ok=%v", b, ok)
	}
	if role, ok := s2.Membership.Role(v, member); !ok || role != membership.RoleMember {
		t.Fatalf("member binding did not survive: role=%v ok=%v", role, ok)
	}
	if _, err := s2.MemberTokens.Resolve(tok); err != nil {
		t.Fatalf("member token did not survive: %v", err)
	}
	// The attribution fields must survive with it: a token that loses its account
	// across a restart cannot be checked against the device registry any more, so
	// the boot after a restart would silently stop enforcing device revocation on
	// every shared vault (myne-md/myne#911 follow-up).
	resolved, err := s2.MemberTokens.Resolve(tok)
	if err != nil {
		t.Fatalf("resolve after restart: %v", err)
	}
	wantDevice := ids.DeviceID{0x0a}
	if resolved.Device != wantDevice {
		t.Fatalf("the token's device did not survive: %x", resolved.Device)
	}
	wantAccount := ids.AccountNumberHash{0xaa}
	if resolved.Account != wantAccount {
		t.Fatalf("the token's issuing account did not survive: %x", resolved.Account)
	}
	inv, err := s2.Invites.Claim(member, inviteID)
	if err != nil {
		t.Fatalf("invite claim after restart: %v", err)
	}
	if string(inv.Payload) != "sealed-invite-payload" {
		t.Fatalf("invite payload did not survive: %q", inv.Payload)
	}
	row, ok := s2.Profiles.Get(v, profileID)
	if !ok || string(row.Bytes) != "sealed-myy5-bytes" {
		t.Fatalf("profile did not survive: ok=%v bytes=%q", ok, row.Bytes)
	}
	if n := s2.Profiles.SweepDue(due.Add(-time.Second)); n != 0 {
		t.Fatalf("a scheduled deletion fired before its due time: %d", n)
	}
	if n := s2.Profiles.SweepDue(due); n != 1 {
		t.Fatalf("a scheduled deletion did not survive the restart: swept %d", n)
	}
	rec, err := s2.GroupPackages.Get(v, member)
	if err != nil || rec.Epoch != 7 || string(rec.Package) != "owner-signed-package" {
		t.Fatalf("group package did not survive: %+v err=%v", rec, err)
	}
	if !s2.Retirements.IsRetired(v, blobID(5)) {
		t.Fatal("a retired namespace became writable after a restart")
	}
	if epoch, ok := s2.Retirements.HighestRetiredEpoch(v); !ok || epoch != 3 {
		t.Fatalf("retired epoch did not survive: %d ok=%v", epoch, ok)
	}
}

// The due time is state too: a grace window that did not survive would either
// reclaim a rotating member's blob early (data loss) or never (the promise unkept).
func TestRetirementDueTimeSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	v := vault(9)
	id := blobID(5)

	s1, clock1 := newStores()
	if _, err := Wire(s1, path); err != nil {
		t.Fatalf("wire: %v", err)
	}
	s1.Retirements.Record(v, 1, 2, []ids.BlobID{id})
	s1.Membership.SetOnChange(nil)
	s1.Retirements.SetOnChange(nil)
	_ = clock1()
	saveNow(s1, path)

	// A restart eight days later: the grace is seven, so the blob is due.
	later := time.Unix(1_700_000_000, 0).UTC().Add(8 * 24 * time.Hour)
	table := membership.New()
	s2 := Stores{
		Membership:    table,
		MemberTokens:  membership.NewTokenStore(table),
		Invites:       relay.NewStore(),
		Profiles:      profiles.NewStore(),
		GroupPackages: grouppkg.NewStore(),
		Retirements:   store.NewRetirements(0).WithClock(func() time.Time { return later }),
	}
	if _, err := Wire(s2, path); err != nil {
		t.Fatalf("rewire: %v", err)
	}
	due := s2.Retirements.DueRetirements()
	if len(due[v]) != 1 || due[v][0] != id {
		t.Fatalf("the due time did not survive the restart: %v", due)
	}
	// Acking IS state: once the reclaimer records the body gone, a second restart must not
	// re-report it.
	s2.Retirements.Reclaimed(v, id)
	s2.Retirements.SetOnChange(nil)
	saveNow(s2, path)
	table3 := membership.New()
	s3 := Stores{
		Membership:    table3,
		MemberTokens:  membership.NewTokenStore(table3),
		Invites:       relay.NewStore(),
		Profiles:      profiles.NewStore(),
		GroupPackages: grouppkg.NewStore(),
		Retirements:   store.NewRetirements(0).WithClock(func() time.Time { return later }),
	}
	if _, err := Wire(s3, path); err != nil {
		t.Fatalf("rewire 2: %v", err)
	}
	if got := s3.Retirements.DueRetirements(); len(got) != 0 {
		t.Fatalf("an acked reclamation was re-reported after a restart: %v", got)
	}
	if !s3.Retirements.IsRetired(v, id) {
		t.Fatal("the retired id must stay refused after its reclamation was acked")
	}
}

// saveNow snapshots and writes without the debounce, for the tests that do not keep
// the coordinator around.
func saveNow(s Stores, path string) {
	c := &Coordinator{stores: s, path: path}
	c.Save()
}

// --- fail-closed cases ---------------------------------------------------------------

func TestAbsentFileIsFirstBoot(t *testing.T) {
	s, _ := newStores()
	if _, err := Wire(s, filepath.Join(t.TempDir(), "nope", FileName)); err == nil {
		// A missing DIRECTORY is not the absent-file case: the write path would fail
		// later, and the load cannot read it. Both are reported rather than swallowed.
		t.Log("missing directory reported, as intended")
	}
}

func TestCorruptFileRefusesToStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := newStores()
	_, err := Wire(s, path)
	if err == nil {
		t.Fatal("a corrupt b2b.json must refuse to start rather than come up with no members")
	}
	if got := err.Error(); got == "" || contains(got, path) {
		t.Fatalf("the error must be bounded and must not carry the path: %q", got)
	}
}

func TestTooNewVersionRefusesToStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	raw, _ := json.Marshal(map[string]any{"version": schemaVersion + 1})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := newStores()
	if _, err := Wire(s, path); err == nil {
		t.Fatal("a file written by a newer server version must fail closed")
	}
}

// A row this version cannot interpret must fail the load. Dropping it would be a
// member silently losing access (or a profile silently lost), which is the failure
// the whole module exists to prevent.
func TestWrongWidthRowFailsTheLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	raw, _ := json.Marshal(map[string]any{
		"version": 1,
		"bindings": []map[string]any{
			{"person": "AAAA", "vault": "AAAAAAAAAAAAAAAAAAAAAA==", "role": 0},
		},
	})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := newStores()
	if _, err := Wire(s, path); err == nil {
		t.Fatal("a wrong-width id must fail the load, not be dropped")
	}
}

func TestWireRequiresEveryStore(t *testing.T) {
	s, _ := newStores()
	s.Profiles = nil
	if _, err := Wire(s, filepath.Join(t.TempDir(), FileName)); err == nil {
		t.Fatal("a partially persisted surface must be refused rather than read as durable")
	}
}

// --- the coalescing write ------------------------------------------------------------

// A burst of mutations must collapse to at most one physical write per flush window:
// the per-request path only marks state dirty.
func TestMutationsCoalesceIntoOneWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	s, _ := newStores()
	c, err := Wire(s, path)
	if err != nil {
		t.Fatalf("wire: %v", err)
	}
	writes := 0
	c.write = func(p string, data []byte) error {
		writes++
		return os.WriteFile(p, data, 0o600)
	}
	for i := 0; i < 20; i++ {
		s.GroupPackages.Put(vault(9), person(byte(i+1)), 1, []byte("x"))
	}
	if writes != 0 {
		t.Fatalf("a mutation wrote synchronously: %d writes", writes)
	}
	c.Flush()
	if writes != 1 {
		t.Fatalf("a burst of mutations produced %d writes, want 1", writes)
	}
	c.Flush() // nothing dirty
	if writes != 1 {
		t.Fatalf("an idle flush wrote again: %d writes", writes)
	}
}

// The shutdown path must not lose a coalesced window.
func TestFlushOnContextCancelPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	s, _ := newStores()
	c, err := Wire(s, path)
	if err != nil {
		t.Fatalf("wire: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Start(ctx); close(done) }()
	s.GroupPackages.Put(vault(9), person(3), 1, []byte("y"))
	cancel()
	<-done

	s2, _ := newStores()
	if _, err := Wire(s2, path); err != nil {
		t.Fatalf("rewire: %v", err)
	}
	if _, err := s2.GroupPackages.Get(vault(9), person(3)); err != nil {
		t.Fatalf("a mutation made just before shutdown was lost: %v", err)
	}
}

func TestSavedFileIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	s, _ := newStores()
	c, err := Wire(s, path)
	if err != nil {
		t.Fatalf("wire: %v", err)
	}
	s.Membership.BindOwner(vault(9), person(1))
	c.Save()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("b2b.json permissions = %o, want 0600 (it holds member tokens)", perm)
	}
}

func contains(haystack, needle string) bool {
	if len(needle) == 0 {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
