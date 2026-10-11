// SPDX-License-Identifier: AGPL-3.0

package awareness

import (
	"bytes"
	"sync"
	"testing"

	"github.com/myne-md/myne-server/internal/ids"
)

func ns(b byte) ids.AccountNumberHash { return ids.AccountNumberHash{b} }

func room(b byte) RoomID { return RoomID{b} }

func TestPublishReachesRoomSubscribersOnly(t *testing.T) {
	r := NewRelay()
	a := ns(1)
	roomA, roomB := room(0xA), room(0xB)

	subA, ok := r.Subscribe(a, 8, 4, []RoomID{roomA})
	if !ok {
		t.Fatal("subscribe A refused")
	}
	subB, ok := r.Subscribe(a, 8, 4, []RoomID{roomB})
	if !ok {
		t.Fatal("subscribe B refused")
	}
	subOther, _ := r.Subscribe(ns(2), 8, 4, []RoomID{roomA})

	r.Publish(a, roomA, []byte("hello-A"))

	if got := subA.Drain(); len(got) != 1 || !bytes.Equal(got[0].Bytes, []byte("hello-A")) {
		t.Fatalf("room A subscriber must get the frame, got %v", got)
	}
	if got := subB.Drain(); len(got) != 0 {
		t.Fatalf("room B subscriber must NOT get room A's frame, got %v", got)
	}
	if got := subOther.Drain(); len(got) != 0 {
		t.Fatalf("another namespace must NOT get the frame, got %v", got)
	}
}

func TestPublisherIncluded(t *testing.T) {
	// The relay is device-agnostic: a publisher's own subscribed stream receives
	// its frame too (the client drops its own echo).
	r := NewRelay()
	h, _ := r.Subscribe(ns(1), 8, 4, []RoomID{room(0xA)})
	r.Publish(ns(1), room(0xA), []byte("own"))
	got := h.Drain()
	if len(got) != 1 || !bytes.Equal(got[0].Bytes, []byte("own")) {
		t.Fatalf("publisher's own stream must receive the frame, got %v", got)
	}
}

func TestPerVaultCapRefuses(t *testing.T) {
	r := NewRelay()
	a := ns(1)
	h1, ok := r.Subscribe(a, 1, 4, []RoomID{room(1)})
	if !ok {
		t.Fatal("first subscribe should succeed")
	}
	if _, ok := r.Subscribe(a, 1, 4, []RoomID{room(1)}); ok {
		t.Fatal("second subscribe at the cap must be refused")
	}
	// The refusal must not disturb the existing subscriber.
	r.Publish(a, room(1), []byte("x"))
	if got := h1.Drain(); len(got) != 1 {
		t.Fatalf("existing subscriber disturbed by a refused subscribe, got %v", got)
	}
}

func TestSaturatedSubscriberDropsOldest(t *testing.T) {
	r := NewRelay()
	a := ns(1)
	h, _ := r.Subscribe(a, 8, 2, []RoomID{room(1)})
	r.Publish(a, room(1), []byte("f1"))
	r.Publish(a, room(1), []byte("f2"))
	r.Publish(a, room(1), []byte("f3"))
	got := h.Drain()
	if len(got) != 2 {
		t.Fatalf("queue cap 2 must hold 2 frames, got %d", len(got))
	}
	// Oldest (f1) dropped, newest (f3) retained; the subscriber stays subscribed.
	if !bytes.Equal(got[0].Bytes, []byte("f2")) || !bytes.Equal(got[1].Bytes, []byte("f3")) {
		t.Fatalf("drop-oldest must keep the newest, got %q, %q", got[0].Bytes, got[1].Bytes)
	}
	r.Publish(a, room(1), []byte("f4"))
	if got := h.Drain(); len(got) != 1 || !bytes.Equal(got[0].Bytes, []byte("f4")) {
		t.Fatalf("subscriber must stay subscribed after saturation, got %v", got)
	}
}

func TestNamespaceKeyDeletedWhenLastLeaves(t *testing.T) {
	r := NewRelay()
	a := ns(1)
	h1, _ := r.Subscribe(a, 8, 4, []RoomID{room(1)})
	h2, _ := r.Subscribe(a, 8, 4, []RoomID{room(2)})
	r.Unsubscribe(a, h1)
	if _, ok := r.subs[a]; !ok {
		t.Fatal("namespace key dropped while a subscriber remains")
	}
	r.Unsubscribe(a, h2)
	if _, ok := r.subs[a]; ok {
		t.Fatal("namespace key must be deleted when its last subscriber leaves")
	}
	if r.SubscriberCount(a) != 0 {
		t.Fatal("SubscriberCount must be 0 after the last leaves")
	}
}

func TestAQueueFullDoesNotBlockThePublisher(t *testing.T) {
	// A subscriber that never drains must not block Publish (the whole point of
	// drop-oldest). If offer blocked, this test would hang.
	r := NewRelay()
	a := ns(1)
	_, _ = r.Subscribe(a, 8, 1, []RoomID{room(1)})
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			r.Publish(a, room(1), []byte("frame"))
		}
		close(done)
	}()
	<-done
}

func TestTerminateTokenClosesOnlyThatToken(t *testing.T) {
	r := NewRelay()
	a := ns(1)
	h1, _ := r.Subscribe(a, 8, 4, []RoomID{room(1)})
	r.SetToken(a, h1, "tok-1")
	h2, _ := r.Subscribe(a, 8, 4, []RoomID{room(1)})
	r.SetToken(a, h2, "tok-2")

	r.TerminateToken("tok-1")

	select {
	case <-h1.Done():
	default:
		t.Fatal("stream under the revoked token must be terminated")
	}
	select {
	case <-h2.Done():
		t.Fatal("a different token's stream must NOT be terminated")
	default:
	}
}

func TestConcurrentSubscribePublishUnsubscribe(t *testing.T) {
	r := NewRelay()
	a := ns(1)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				h, ok := r.Subscribe(a, 64, 4, []RoomID{room(1), room(2)})
				if !ok {
					continue
				}
				r.Publish(a, room(1), []byte("x"))
				h.Drain()
				r.Unsubscribe(a, h)
			}
		}()
	}
	wg.Wait()
}
