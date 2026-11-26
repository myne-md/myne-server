// SPDX-License-Identifier: AGPL-3.0-only

package awareness

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/membership"
)

// Defaults. The subscriber cap is larger than the poke's single-user 8 because a
// shared vault has many members times devices; the frame/batch caps bound the
// relay's memory; the heartbeat matches the poke's so a client can detect a dead
// stream with the same 65 s read timeout.
const (
	DefaultMaxSubscribers = 64
	DefaultQueueCap       = 64
	MaxFrameSize          = 64 * 1024
	MaxFramesPerPost      = 16
	DefaultHeartbeat      = 30 * time.Second
	// MaxPostBodyBytes bounds the POST body before decode: 16 frames of 64 KiB
	// base64-encoded (x4/3) plus envelope slack.
	MaxPostBodyBytes = 4 << 20
)

// TokenAuth is the device-token session path (satisfied by *auth.TokenStore).
type TokenAuth interface {
	AuthenticateSession(token ids.DeviceToken) (auth.Session, error)
}

// MembershipResolver is the B2B per-vault membership seam (satisfied by
// *authapi.Handler), the same one syncapi uses.
type MembershipResolver interface {
	ResolveMember(bearerHex string) (b membership.Binding, ok bool)
}

// RateLimiter gates requests per account (nil = disabled); never IP.
type RateLimiter interface {
	Allow(account ids.AccountNumberHash) bool
}

// Handler serves the GET/POST /sync/awareness pair.
type Handler struct {
	relay      *Relay
	auth       TokenAuth
	membership MembershipResolver
	rl         RateLimiter // the awareness sub-bucket, separate from push/pull
	heartbeat  time.Duration
	maxSubs    int
	frameCap   int
	batchCap   int
}

// NewHandler wires the relay + the device-token authenticator.
func NewHandler(relay *Relay, ts TokenAuth) *Handler {
	return &Handler{
		relay:     relay,
		auth:      ts,
		heartbeat: DefaultHeartbeat,
		maxSubs:   DefaultMaxSubscribers,
		frameCap:  MaxFrameSize,
		batchCap:  MaxFramesPerPost,
	}
}

// WithPolicy attaches the awareness rate sub-bucket (nil = disabled).
func (h *Handler) WithPolicy(rl RateLimiter) *Handler { h.rl = rl; return h }

// WithMembership attaches the B2B membership resolver so a member token is
// accepted on both routes.
func (h *Handler) WithMembership(m MembershipResolver) *Handler { h.membership = m; return h }

// WithCaps overrides the subscriber/frame/batch caps (tests + config).
func (h *Handler) WithCaps(maxSubs, frameCap, batchCap int) *Handler {
	h.maxSubs, h.frameCap, h.batchCap = maxSubs, frameCap, batchCap
	return h
}

// WithHeartbeat overrides the keep-alive cadence (tests).
func (h *Handler) WithHeartbeat(d time.Duration) *Handler { h.heartbeat = d; return h }

// Register wires the two method patterns on the root mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /sync/awareness", h.handleGet)
	mux.HandleFunc("POST /sync/awareness", h.handlePost)
}

// session resolves the bearer token to a vault namespace: the device-token path
// first, then the per-vault membership resolver.
func (h *Handler) session(r *http.Request) (auth.Session, bool) {
	authz := r.Header.Get("Authorization")
	const pfx = "Bearer "
	if !strings.HasPrefix(authz, pfx) {
		return auth.Session{}, false
	}
	hexTok := strings.TrimPrefix(authz, pfx)
	tok, err := hex.DecodeString(hexTok)
	if err != nil {
		return auth.Session{}, false
	}
	if sess, err := h.auth.AuthenticateSession(ids.DeviceToken(tok)); err == nil {
		return sess, true
	}
	if h.membership != nil {
		if b, ok := h.membership.ResolveMember(hexTok); ok {
			vault := b.Vault
			return auth.Session{Account: vault}, true
		}
	}
	return auth.Session{}, false
}

func bearerHex(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error_code":"` + code + `"}`))
}

// parseRooms parses a comma-separated list of 32-hex room ids; empty is valid.
func parseRooms(s string) ([]RoomID, bool) {
	if strings.TrimSpace(s) == "" {
		return nil, true
	}
	parts := strings.Split(s, ",")
	out := make([]RoomID, 0, len(parts))
	for _, p := range parts {
		room, ok := parseRoom(p)
		if !ok {
			return nil, false
		}
		out = append(out, room)
	}
	return out, true
}

func parseRoom(s string) (RoomID, bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != RoomIDLen {
		return RoomID{}, false
	}
	var r RoomID
	copy(r[:], b)
	return r, true
}

func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.session(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// One token per connection attempt from the awareness sub-bucket.
	if h.rl != nil && !h.rl.Allow(sess.Account) {
		writeError(w, http.StatusTooManyRequests, "rate")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		// Fail closed, never a silent hang.
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	rooms, ok := parseRooms(r.URL.Query().Get("rooms"))
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	handle, ok := h.relay.Subscribe(sess.Account, h.maxSubs, DefaultQueueCap, rooms)
	if !ok {
		writeError(w, http.StatusTooManyRequests, "rate")
		return
	}
	defer h.relay.Unsubscribe(sess.Account, handle)
	h.relay.SetToken(sess.Account, handle, bearerHex(r))

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	hb := time.NewTicker(h.heartbeat)
	defer hb.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-handle.Done():
			// Terminated out-of-band (member removal): stop now, not at reconnect.
			return
		case <-handle.Notify():
			for _, f := range handle.Drain() {
				if _, err := w.Write(encodeEnvelope(f)); err != nil {
					return
				}
			}
			flusher.Flush()
		case <-hb.C:
			if _, err := w.Write([]byte(":hb\n\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

type postFrame struct {
	RoomIDHex string `json:"room_id_hex"`
	FrameB64  string `json:"frame_b64"`
}

type postReq struct {
	RoomsSubscribe   []string    `json:"rooms_subscribe"`
	RoomsUnsubscribe []string    `json:"rooms_unsubscribe"`
	Frames           []postFrame `json:"frames"`
}

func (h *Handler) handlePost(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.session(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if h.rl != nil && !h.rl.Allow(sess.Account) {
		writeError(w, http.StatusTooManyRequests, "rate")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxPostBodyBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if len(body) > MaxPostBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large")
		return
	}
	var req postReq
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if len(req.Frames) > h.batchCap {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large")
		return
	}
	subscribe, ok := parseRooms(strings.Join(req.RoomsSubscribe, ","))
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	unsubscribe, ok := parseRooms(strings.Join(req.RoomsUnsubscribe, ","))
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	type publish struct {
		room  RoomID
		frame []byte
	}
	pubs := make([]publish, 0, len(req.Frames))
	for _, fr := range req.Frames {
		room, ok := parseRoom(fr.RoomIDHex)
		if !ok {
			writeError(w, http.StatusBadRequest, "bad_request")
			return
		}
		frame, err := base64.StdEncoding.DecodeString(fr.FrameB64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request")
			return
		}
		if len(frame) > h.frameCap {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large")
			return
		}
		pubs = append(pubs, publish{room: room, frame: frame})
	}

	if len(subscribe) > 0 || len(unsubscribe) > 0 {
		h.relay.UpdateRoomsForToken(sess.Account, bearerHex(r), subscribe, unsubscribe)
	}
	for _, p := range pubs {
		h.relay.Publish(sess.Account, p.room, p.frame)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// encodeEnvelope renders one SSE data line in the {room_id_hex, frame_b64}
// envelope. The frame bytes are never interpreted.
func encodeEnvelope(f Frame) []byte {
	env := `data: {"room_id_hex":"` + hex.EncodeToString(f.Room[:]) +
		`","frame_b64":"` + base64.StdEncoding.EncodeToString(f.Bytes) + `"}` + "\n\n"
	return []byte(env)
}
