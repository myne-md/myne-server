package gcquota

import (
	"testing"

	"github.com/myne-md/myne-server/internal/ids"
)

// #8: three places needed the account's stored-byte total and each resolved it
// for itself. The push gate counted blobs only, while the attachment gate and
// GET /account/status counted blobs PLUS attachments — so an account whose
// attachments already filled the quota kept pushing note blobs past a ceiling
// its own status endpoint reported as full, and the operator's number
// disagreed with what was enforced.
//
// `UnifiedUsedBytes` is now the one definition all three read.

type fakeBlobs map[ids.AccountNumberHash]uint64

func (f fakeBlobs) QuotaBytes(a ids.AccountNumberHash) uint64 { return f[a] }

type fakeAttachments map[ids.AccountNumberHash]uint64

func (f fakeAttachments) AccountBytes(a ids.AccountNumberHash) uint64 { return f[a] }

func TestUnifiedUsedBytesCountsBothSources(t *testing.T) {
	var a ids.AccountNumberHash
	a[0] = 0x42

	used := UnifiedUsedBytes(fakeBlobs{a: 100}, fakeAttachments{a: 25})
	if got := used(a); got != 125 {
		t.Fatalf("want 125 (blobs + attachments), got %d", got)
	}
}

func TestUnifiedUsedBytesToleratesAMissingSource(t *testing.T) {
	// A notes-only deployment wires no attachment store; that must read as
	// "no attachment bytes", never as a panic on the push path.
	var a ids.AccountNumberHash
	a[0] = 0x42

	if got := UnifiedUsedBytes(fakeBlobs{a: 7}, nil)(a); got != 7 {
		t.Fatalf("want 7, got %d", got)
	}
	if got := UnifiedUsedBytes(nil, fakeAttachments{a: 9})(a); got != 9 {
		t.Fatalf("want 9, got %d", got)
	}
}

func TestQuotaCeilingAppliesToTheCombinedFigure(t *testing.T) {
	// The property the split violated: attachments consume the SAME ceiling the
	// push path enforces.
	var a ids.AccountNumberHash
	a[0] = 0x42
	q := NewQuotaGuard(100)

	used := UnifiedUsedBytes(fakeBlobs{a: 60}, fakeAttachments{a: 30})
	if !q.WouldExceedTotalForAccount(a, used(a), 20) {
		t.Fatal("60 blob + 30 attachment + 20 new must exceed a 100-byte ceiling")
	}
	// Blob-only accounting would have let this through — that was the defect.
	if q.WouldExceedTotalForAccount(a, fakeBlobs{a: 60}.QuotaBytes(a), 20) {
		t.Fatal("sanity: the blob-only figure is under the ceiling, which is why the split hid")
	}
}
