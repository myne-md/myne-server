// SPDX-License-Identifier: AGPL-3.0

package awareness

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/membership"
)

type fakeAuth struct {
	tokens map[string]ids.AccountNumberHash
}

func (f fakeAuth) AuthenticateSession(t ids.DeviceToken) (auth.Session, error) {
	if acct, ok := f.tokens[hex.EncodeToString(t)]; ok {
		return auth.Session{Account: acct}, nil
	}
	return auth.Session{}, auth.ErrUnauthenticated
}

type fakeMembership struct {
	m map[string]ids.AccountNumberHash
}

func (f fakeMembership) ResolveMember(bearerHex string) (membership.Binding, bool) {
	if v, ok := f.m[bearerHex]; ok {
		return membership.Binding{Vault: v, Role: membership.RoleMember}, true
	}
	return membership.Binding{}, false
}

type allowAll struct{}

func (allowAll) Allow(ids.AccountNumberHash) bool { return true }

type denyAll struct{}

func (denyAll) Allow(ids.AccountNumberHash) bool { return false }

// devToken is a fixed 32-byte device token as lowercase hex.
func devToken() string { return strings.Repeat("ab", 32) }

func hexRoom(b byte) string { return hex.EncodeToString(bytes.Repeat([]byte{b}, RoomIDLen)) }

func newTestHandler() (*Handler, *Relay) {
	relay := NewRelay()
	auth := fakeAuth{tokens: map[string]ids.AccountNumberHash{devToken(): ns(1)}}
	h := NewHandler(relay, auth).WithPolicy(allowAll{})
	return h, relay
}

func readDataLine(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read SSE line: %v", err)
		}
		if strings.HasPrefix(line, "data:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		}
	}
}

func TestGetThenPostDeliversFrame(t *testing.T) {
	h, relay := newTestHandler()
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/sync/awareness?rooms="+hexRoom(0xA), nil)
	req.Header.Set("Authorization", "Bearer "+devToken())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d", resp.StatusCode)
	}
	defer resp.Body.Close()

	// Wait until the stream is subscribed before publishing.
	for i := 0; i < 100 && relay.SubscriberCount(ns(1)) == 0; i++ {
		time.Sleep(5 * time.Millisecond)
	}

	frame := []byte("hello-awareness")
	body := `{"frames":[{"room_id_hex":"` + hexRoom(0xA) + `","frame_b64":"` + base64.StdEncoding.EncodeToString(frame) + `"}]}`
	preq, _ := http.NewRequest("POST", srv.URL+"/sync/awareness", strings.NewReader(body))
	preq.Header.Set("Authorization", "Bearer "+devToken())
	presp, err := http.DefaultClient.Do(preq)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	if presp.StatusCode != http.StatusOK {
		t.Fatalf("POST status = %d", presp.StatusCode)
	}
	_ = presp.Body.Close()

	env := readDataLine(t, bufio.NewReader(resp.Body))
	if !strings.Contains(env, hexRoom(0xA)) || !strings.Contains(env, base64.StdEncoding.EncodeToString(frame)) {
		t.Fatalf("envelope missing room/frame: %s", env)
	}
}

func TestCrossVaultIsolation(t *testing.T) {
	relay := NewRelay()
	// Two tokens: one vault 1, one vault 2.
	auth := fakeAuth{tokens: map[string]ids.AccountNumberHash{
		devToken():               ns(1),
		strings.Repeat("cd", 32): ns(2),
	}}
	h := NewHandler(relay, auth).WithPolicy(allowAll{})
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Vault 2's stream.
	req, _ := http.NewRequest("GET", srv.URL+"/sync/awareness?rooms="+hexRoom(0xA), nil)
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("cd", 32))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET vault2: %v", err)
	}
	defer resp.Body.Close()
	for i := 0; i < 100 && relay.SubscriberCount(ns(2)) == 0; i++ {
		time.Sleep(5 * time.Millisecond)
	}

	// Publish in vault 1 (must NOT reach vault 2).
	pub := func(token, room string, frame []byte) {
		body := `{"frames":[{"room_id_hex":"` + room + `","frame_b64":"` + base64.StdEncoding.EncodeToString(frame) + `"}]}`
		preq, _ := http.NewRequest("POST", srv.URL+"/sync/awareness", strings.NewReader(body))
		preq.Header.Set("Authorization", "Bearer "+token)
		presp, err := http.DefaultClient.Do(preq)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		_ = presp.Body.Close()
	}
	pub(devToken(), hexRoom(0xA), []byte("vault1-frame"))
	// Then a vault-2 sanity frame: the FIRST line vault 2 reads must be this one.
	pub(strings.Repeat("cd", 32), hexRoom(0xA), []byte("vault2-sanity"))

	env := readDataLine(t, bufio.NewReader(resp.Body))
	if !strings.Contains(env, base64.StdEncoding.EncodeToString([]byte("vault2-sanity"))) {
		t.Fatalf("vault 2 received a frame from vault 1: %s", env)
	}
}

// openAwarenessStream opens one SSE stream and hands the caller the live
// response.
//
// It returns the RESPONSE rather than a status code, and that is the whole
// reason it exists as a helper instead of an `open() int` closure. A
// `defer resp.Body.Close()` inside the helper ties the stream's lifetime to the
// helper's: the first subscriber is released before the next request is issued,
// so a per-vault cap of 1 never appears to be reached and the 429 assertion
// reads 200. This is NOT a timing race to be papered over — the ordering is
// decided by the server, and it is decided the FAILING way here:
//
//	handler.go:178  h.relay.Subscribe(...)   <- the slot is taken
//	handler.go:189  flusher.Flush()          <- headers reach the client
//
// so once `Do` returns, the slot is held for as long as the body stays open.
// Closing it inside the helper contradicts a guarantee the server makes
// synchronously, and which toolchain you run decides whether you notice: go
// 1.26.4 (the CI image and go.mod pin) resolves it the failing way every run,
// while 1.27 passed by scheduling the second GET before the close was observed.
// The test was therefore green locally and red in CI, which reads as flake and
// is not one.
//
// The caller owns the lifetime and MUST `defer resp.Body.Close()` — the same
// shape internal/poke/poke_test.go's openStream uses for the same cap on the
// poke route.
func openAwarenessStream(t *testing.T, url, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", url+"/sync/awareness", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	return resp
}

func TestHTTPPerVaultCapRefuses(t *testing.T) {
	h, _ := newTestHandler()
	h = h.WithCaps(1, MaxFrameSize, MaxFramesPerPost)
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// The first stream stays open for the whole test: the slot it holds is
	// precisely what the second request must be refused for.
	first := openAwarenessStream(t, srv.URL, devToken())
	defer first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first GET = %d", first.StatusCode)
	}

	second := openAwarenessStream(t, srv.URL, devToken())
	defer second.Body.Close()
	if second.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second GET at cap = %d, want 429", second.StatusCode)
	}
}

func TestRateBucketRefuses(t *testing.T) {
	relay := NewRelay()
	auth := fakeAuth{tokens: map[string]ids.AccountNumberHash{devToken(): ns(1)}}
	h := NewHandler(relay, auth).WithPolicy(denyAll{})
	mux := http.NewServeMux()
	h.Register(mux)

	getReq := httptest.NewRequest("GET", "/sync/awareness", nil)
	getReq.Header.Set("Authorization", "Bearer "+devToken())
	rec := httptest.NewRecorder()
	h.handleGet(rec, getReq)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("GET under a denied awareness bucket = %d, want 429", rec.Code)
	}

	postReq := httptest.NewRequest("POST", "/sync/awareness", strings.NewReader(`{}`))
	postReq.Header.Set("Authorization", "Bearer "+devToken())
	prec := httptest.NewRecorder()
	h.handlePost(prec, postReq)
	if prec.Code != http.StatusTooManyRequests {
		t.Fatalf("POST under a denied awareness bucket = %d, want 429", prec.Code)
	}
}

func TestPostCapsAndMalformed(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{"oversize-frame", `{"frames":[{"room_id_hex":"` + hexRoom(0xA) + `","frame_b64":"` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), MaxFrameSize+1)) + `"}]}`, http.StatusRequestEntityTooLarge},
		{"malformed-base64", `{"frames":[{"room_id_hex":"` + hexRoom(0xA) + `","frame_b64":"!!!not-base64!!!"}]}`, http.StatusBadRequest},
		{"malformed-room", `{"frames":[{"room_id_hex":"zz","frame_b64":"aGk="}]}`, http.StatusBadRequest},
		{"bad-json", `{`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := newTestHandler()
			req := httptest.NewRequest("POST", "/sync/awareness", strings.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer "+devToken())
			rec := httptest.NewRecorder()
			h.handlePost(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("%s: status = %d, want %d", tc.name, rec.Code, tc.want)
			}
		})
	}

	// A batch over the cap is 413.
	h, _ := newTestHandler()
	var frames []string
	for i := 0; i < MaxFramesPerPost+1; i++ {
		frames = append(frames, `{"room_id_hex":"`+hexRoom(0xA)+`","frame_b64":"aGk="}`)
	}
	req := httptest.NewRequest("POST", "/sync/awareness", strings.NewReader(`{"frames":[`+strings.Join(frames, ",")+`]}`))
	req.Header.Set("Authorization", "Bearer "+devToken())
	rec := httptest.NewRecorder()
	h.handlePost(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("batch over cap = %d, want 413", rec.Code)
	}
}

// noFlushWriter is an http.ResponseWriter with no Flush method.
type noFlushWriter struct {
	h      http.Header
	status int
}

func (w *noFlushWriter) Header() http.Header         { return w.h }
func (w *noFlushWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *noFlushWriter) WriteHeader(s int)           { w.status = s }

func TestNonFlushableWriterFailsClosed(t *testing.T) {
	h, _ := newTestHandler()
	req := httptest.NewRequest("GET", "/sync/awareness", nil)
	req.Header.Set("Authorization", "Bearer "+devToken())
	w := &noFlushWriter{h: http.Header{}}
	h.handleGet(w, req)
	if w.status != http.StatusInternalServerError {
		t.Fatalf("non-flushable writer status = %d, want 500", w.status)
	}
}

func TestMemberRemovalTerminatesStream(t *testing.T) {
	relay := NewRelay()
	memberTok := strings.Repeat("ef", 32)
	h := NewHandler(relay, fakeAuth{tokens: map[string]ids.AccountNumberHash{}}).
		WithPolicy(allowAll{}).
		WithMembership(fakeMembership{m: map[string]ids.AccountNumberHash{memberTok: ns(1)}})
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/sync/awareness", nil)
	req.Header.Set("Authorization", "Bearer "+memberTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	for i := 0; i < 100 && relay.SubscriberCount(ns(1)) == 0; i++ {
		time.Sleep(5 * time.Millisecond)
	}

	// The removal observer fires TerminateToken; the stream must close promptly.
	relay.TerminateToken(memberTok)
	closed := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not close after termination")
	}
}

func TestMembershipTokenAccepted(t *testing.T) {
	relay := NewRelay()
	memberTok := strings.Repeat("ef", 32)
	h := NewHandler(relay, fakeAuth{tokens: map[string]ids.AccountNumberHash{}}).
		WithPolicy(allowAll{}).
		WithMembership(fakeMembership{m: map[string]ids.AccountNumberHash{memberTok: ns(7)}})

	// A member token (unknown to the device store) opens the stream and publishes.
	req := httptest.NewRequest("POST", "/sync/awareness", strings.NewReader(
		`{"frames":[{"room_id_hex":"`+hexRoom(0xA)+`","frame_b64":"aGk="}]}`))
	req.Header.Set("Authorization", "Bearer "+memberTok)
	rec := httptest.NewRecorder()
	h.handlePost(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("membership-token POST = %d, want 200", rec.Code)
	}
	if relay.SubscriberCount(ns(7)) != 0 {
		t.Fatal("POST alone must not subscribe")
	}

	getReq := httptest.NewRequest("GET", "/sync/awareness", nil)
	getReq.Header.Set("Authorization", "Bearer "+memberTok)
	// A GET under a membership token subscribes; cancel via context so it returns.
	ctx, cancel := context.WithCancel(getReq.Context())
	defer cancel()
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	rec2 := httptest.NewRecorder()
	h.handleGet(rec2, getReq.WithContext(ctx))
	if rec2.Code != http.StatusOK {
		t.Fatalf("membership-token GET = %d, want 200", rec2.Code)
	}
}
