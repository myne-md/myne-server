// SPDX-License-Identifier: AGPL-3.0-or-later

package poke

import (
	"testing"

	"github.com/myne-md/myne-server/internal/ids"
)

func acct(b byte) ids.AccountNumberHash {
	var a ids.AccountNumberHash
	a[0] = b
	return a
}

func TestNotifier_SignalsSubscriber(t *testing.T) {
	n := NewNotifier()
	a := acct(1)
	ch := n.subscribe(a)
	defer n.unsubscribe(a, ch)

	if n.SubscriberCount(a) != 1 {
		t.Fatalf("subscriber count = %d, want 1", n.SubscriberCount(a))
	}
	n.Notify(a)
	select {
	case _, ok := <-ch:
		if !ok {
			t.Fatal("channel closed")
		}
		// The signal is struct{}{} — literally zero payload (no id/version/count).
	default:
		t.Fatal("no poke delivered")
	}
}

func TestNotifier_Coalesces(t *testing.T) {
	n := NewNotifier()
	a := acct(2)
	ch := n.subscribe(a)
	defer n.unsubscribe(a, ch)
	// Two notifies before a read → coalesced to a single pending signal (buffer 1).
	n.Notify(a)
	n.Notify(a)
	<-ch // one
	select {
	case <-ch:
		t.Fatal("second (coalesced) poke should not be pending")
	default:
	}
}

func TestNotifier_IsolatedPerAccount(t *testing.T) {
	n := NewNotifier()
	a, b := acct(3), acct(4)
	chA := n.subscribe(a)
	defer n.unsubscribe(a, chA)
	n.Notify(b) // different account
	select {
	case <-chA:
		t.Fatal("account A got account B's poke")
	default:
	}
}
