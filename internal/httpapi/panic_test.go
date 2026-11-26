// SPDX-License-Identifier: AGPL-3.0-only

package httpapi

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// A panicking handler must not put the client's address into the log stream.
//
// This is the one no-IP test that watches the process's REAL stderr rather than
// an injected logger. Every other one (`TestNoIP_DiscardsSourceIP`,
// `TestAccessLog_NoIPField`, the cors ordering test) inspects handler-visible
// state or a `*bytes.Buffer` — so all three would have passed while `net/http`
// wrote `http: panic serving 127.0.0.1:54321` to the container's log stream,
// because that line is emitted above the handler chain and carries
// `http.conn.remoteAddr`, which `noIP` cannot reach.
//
// The request goes over a real TCP connection on purpose: `httptest.NewRecorder`
// never populates the conn-level address, so a recorder-based test could not
// observe the leak even in principle.
func TestVectorNoIPOnHandlerPanic(t *testing.T) {
	// Capture BOTH sinks a leak could use: the `log` package's default output
	// (where a nil ErrorLog would land) and slog's default handler (where the
	// recovery middleware writes).
	realStderr := os.Stderr
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = pw
	prevSlog := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(pw, nil)))
	t.Cleanup(func() {
		os.Stderr = realStderr
		slog.SetDefault(prevSlog)
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/boom", func(http.ResponseWriter, *http.Request) {
		panic("handler exploded")
	})
	srv := newHTTPServer(recoverPanic(noIP(mux)))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	resp, err := http.Get("http://" + ln.Addr().String() + "/boom")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (a panic must not become a dropped connection)", resp.StatusCode)
	}
	_ = body

	// Let the writes drain, then read what reached the pipe.
	time.Sleep(50 * time.Millisecond)
	_ = pw.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, pr)
	logged := buf.String()

	// The listener's own address shares the loopback host with the client's, so
	// asserting on "127.0.0.1" alone would be ambiguous. The client's PORT is
	// unique to its connection, and it is the part `http.conn.remoteAddr`
	// contributes that nothing legitimate would print.
	if strings.Contains(logged, "panic serving") {
		t.Errorf("net/http's connection-level panic line reached a sink:\n%s", logged)
	}
	if strings.Contains(logged, "handler exploded") {
		t.Errorf("the panic value reached a sink; it can carry request-derived state:\n%s", logged)
	}
	// The panic must still be observable, or discarding ErrorLog would have
	// traded an IP leak for silence.
	if !strings.Contains(logged, "handler_panic") {
		t.Errorf("a panic must still be logged, IP-free:\n%s", logged)
	}
	if !strings.Contains(logged, "/boom") {
		t.Errorf("the route is the actionable field and must survive:\n%s", logged)
	}
}
