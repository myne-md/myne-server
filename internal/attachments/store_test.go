// SPDX-License-Identifier: AGPL-3.0-or-later

package attachments

import (
	"testing"

	"github.com/myne-md/myne-server/internal/ids"
)

func aid(b byte) AttachmentID {
	var id AttachmentID
	id[0] = b
	return id
}

// The server NEVER auto-deletes an attachment: a complete blob persists until an
// explicit Delete (the user-sweep effect, propagated as a §11 tombstone — there is
// no server-side refcount/GC, the note→attachment graph is AEAD-internal).
func TestStore_NoAutoDeletePersists(t *testing.T) {
	s := NewStore()
	var a ids.AccountNumberHash
	id := aid(1)
	if err := s.WriteAt(a, id, 0, 3, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	if !s.Has(a, id) {
		t.Fatal("attachment should be complete + present")
	}
	// No call deletes it implicitly; only explicit Delete removes it.
	s.Delete(a, id)
	if s.Has(a, id) {
		t.Fatal("Delete should remove the attachment")
	}
}

func TestStore_TooLarge(t *testing.T) {
	s := NewStore()
	var a ids.AccountNumberHash
	if err := s.WriteAt(a, aid(2), 0, MaxAttachmentSize+1, []byte("x")); err != ErrTooLarge {
		t.Fatalf("oversize total = %v, want ErrTooLarge", err)
	}
}
