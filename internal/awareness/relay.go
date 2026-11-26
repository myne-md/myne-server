// SPDX-License-Identifier: AGPL-3.0-only

// Package awareness is the live-awareness relay (epic live-collab, sub-feature
// 3): a RAM-only, device-agnostic fan-out of opaque frames from a publisher to
// every subscriber of a note room in a vault namespace. It mirrors the poke
// Notifier shape but transports content, never inspects a frame byte, and
// matches the room id by exact equality. The frame is end-to-end-sealed
// (protocol/src/awareness_frame.rs); the relay holds no key. See
// docs/spec/server-protocol.md §3.5 and design notes/sync/0657.
package awareness

import (
	"sync"

	"github.com/myne-md/myne-server/internal/ids"
)

// RoomIDLen is the awareness room id length in bytes (protocol.md §3.4).
const RoomIDLen = 16

// RoomID is the per-note, note-unlinkable routing key. The relay matches it by
// exact equality and never parses it.
type RoomID [RoomIDLen]byte

// Frame is one opaque awareness frame addressed to a room. Bytes is never
// inspected by the relay; it is forwarded verbatim.
type Frame struct {
	Room  RoomID
	Bytes []byte
}

// subscriber is one open awareness stream: a declared room set and a bounded
// FIFO queue of frames, oldest droppable. Its mutex guards the room set and the
// queue; the relay's mutex guards membership in the namespace map.
type subscriber struct {
	mu        sync.Mutex
	rooms     map[RoomID]struct{}
	queue     []Frame
	queueCap  int
	notify    chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	closed    bool
	// token is the authenticating bearer token (hex), used only to terminate
	// the stream on member removal; it is NOT a person or device id, so the
	// relay stays person-agnostic. Empty until SetToken registers it.
	token string
}

func (s *subscriber) inRoom(r RoomID) bool {
	_, ok := s.rooms[r]
	return ok
}

// offer enqueues a frame when the room is subscribed, dropping the OLDEST
// queued frame when the queue is full (never blocking the publisher), and
// signals the consumer.
func (s *subscriber) offer(f Frame) {
	s.mu.Lock()
	if s.closed || !s.inRoom(f.Room) {
		s.mu.Unlock()
		return
	}
	if len(s.queue) >= s.queueCap {
		s.queue = s.queue[1:]
	}
	cp := make([]byte, len(f.Bytes))
	copy(cp, f.Bytes)
	s.queue = append(s.queue, Frame{Room: f.Room, Bytes: cp})
	s.mu.Unlock()
	select {
	case s.notify <- struct{}{}:
	default: // a signal is already pending
	}
}

// Handle is the receive side of a subscription.
type Handle struct {
	sub *subscriber
}

// Notify returns a channel that receives a signal when frames may be available.
func (h *Handle) Notify() <-chan struct{} { return h.sub.notify }

// Done returns a channel closed when the stream is terminated out-of-band (a
// member removal), so the SSE loop can stop immediately rather than at the next
// reconnect.
func (h *Handle) Done() <-chan struct{} { return h.sub.done }

// Drain returns and clears the queued frames, oldest first.
func (h *Handle) Drain() []Frame {
	h.sub.mu.Lock()
	defer h.sub.mu.Unlock()
	out := h.sub.queue
	h.sub.queue = nil
	return out
}

// SetRooms replaces the subscription's room set (the GET initial set or a POST
// update).
func (h *Handle) SetRooms(rooms []RoomID) {
	h.sub.mu.Lock()
	defer h.sub.mu.Unlock()
	h.sub.rooms = make(map[RoomID]struct{}, len(rooms))
	for _, r := range rooms {
		h.sub.rooms[r] = struct{}{}
	}
}

// AddRooms adds rooms to the subscription's set.
func (h *Handle) AddRooms(rooms []RoomID) {
	h.sub.mu.Lock()
	defer h.sub.mu.Unlock()
	for _, r := range rooms {
		h.sub.rooms[r] = struct{}{}
	}
}

// RemoveRooms removes rooms from the subscription's set.
func (h *Handle) RemoveRooms(rooms []RoomID) {
	h.sub.mu.Lock()
	defer h.sub.mu.Unlock()
	for _, r := range rooms {
		delete(h.sub.rooms, r)
	}
}

// Relay is the RAM-only fan-out. It holds no persisted state, writes no log,
// and reads no frame byte.
type Relay struct {
	mu   sync.Mutex
	subs map[ids.AccountNumberHash]map[*subscriber]struct{}
}

// NewRelay returns an empty relay.
func NewRelay() *Relay {
	return &Relay{subs: make(map[ids.AccountNumberHash]map[*subscriber]struct{})}
}

// Subscribe registers a new stream for the vault namespace, subscribed to the
// declared room set. It returns false when the namespace is already at maxPer,
// without disturbing existing subscribers.
func (r *Relay) Subscribe(namespace ids.AccountNumberHash, maxPer, queueCap int, rooms []RoomID) (*Handle, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.subs[namespace]
	if len(m) >= maxPer {
		return nil, false
	}
	if m == nil {
		m = make(map[*subscriber]struct{})
		r.subs[namespace] = m
	}
	s := &subscriber{
		rooms:    make(map[RoomID]struct{}, len(rooms)),
		queueCap: queueCap,
		notify:   make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
	for _, room := range rooms {
		s.rooms[room] = struct{}{}
	}
	m[s] = struct{}{}
	return &Handle{sub: s}, true
}

// Unsubscribe removes the stream and drops the namespace key when its last
// subscriber leaves, so the map never accumulates an empty entry per vault seen.
func (r *Relay) Unsubscribe(namespace ids.AccountNumberHash, h *Handle) {
	if h == nil || h.sub == nil {
		return
	}
	r.mu.Lock()
	if m := r.subs[namespace]; m != nil {
		delete(m, h.sub)
		if len(m) == 0 {
			delete(r.subs, namespace)
		}
	}
	r.mu.Unlock()
	h.sub.mu.Lock()
	h.sub.closed = true
	h.sub.mu.Unlock()
}

// Publish fans an opaque frame out to every subscriber of the room in the
// namespace, the publisher included (the relay is device-agnostic and does not
// know which subscriber published). A saturated subscriber drops its oldest
// queued frame rather than blocking the publisher.
func (r *Relay) Publish(namespace ids.AccountNumberHash, room RoomID, frame []byte) {
	r.mu.Lock()
	targets := make([]*subscriber, 0, len(r.subs[namespace]))
	for s := range r.subs[namespace] {
		targets = append(targets, s)
	}
	r.mu.Unlock()
	for _, s := range targets {
		s.offer(Frame{Room: room, Bytes: frame})
	}
}

// SubscriberCount is for tests/observability (no IP or user data).
func (r *Relay) SubscriberCount(namespace ids.AccountNumberHash) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.subs[namespace])
}

// TerminateToken closes every open stream (in any namespace) authenticated with
// the token hex. Called on member removal so the removed member's streams stop at
// once. It keys on the TOKEN, not a person or device, so the relay holds no
// person-scoped state.
func (r *Relay) TerminateToken(token string) {
	if token == "" {
		return
	}
	r.mu.Lock()
	var targets []*subscriber
	for _, m := range r.subs {
		for s := range m {
			targets = append(targets, s)
		}
	}
	r.mu.Unlock()
	for _, s := range targets {
		s.mu.Lock()
		match := s.token == token && !s.closed
		s.mu.Unlock()
		if match {
			s.closeOnce.Do(func() { close(s.done) })
		}
	}
}

// SetToken records the authenticating bearer token (hex) on a stream. It scopes
// a POST subscription update to the connection that owns it and lets the relay
// terminate the stream on member removal. It is NOT a person or device id, so the
// relay stays person-agnostic (SYNC-26).
func (r *Relay) SetToken(namespace ids.AccountNumberHash, h *Handle, token string) {
	_ = namespace
	if h == nil || h.sub == nil {
		return
	}
	h.sub.mu.Lock()
	h.sub.token = token
	h.sub.mu.Unlock()
}

// UpdateRoomsForToken applies a subscription update to every stream in the
// namespace authenticated with the token (the client's own GET stream), without
// tearing it.
func (r *Relay) UpdateRoomsForToken(namespace ids.AccountNumberHash, token string, subscribe, unsubscribe []RoomID) {
	r.mu.Lock()
	targets := make([]*subscriber, 0, len(r.subs[namespace]))
	for s := range r.subs[namespace] {
		targets = append(targets, s)
	}
	r.mu.Unlock()
	for _, s := range targets {
		s.mu.Lock()
		if s.token == token && !s.closed {
			for _, room := range subscribe {
				s.rooms[room] = struct{}{}
			}
			for _, room := range unsubscribe {
				delete(s.rooms, room)
			}
		}
		s.mu.Unlock()
	}
}
