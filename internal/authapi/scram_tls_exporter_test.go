// SPDX-License-Identifier: AGPL-3.0-only

package authapi

import (
	"bufio"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/auth/scram"
	"github.com/myne-md/myne-server/internal/ids"
)

// F5 end-to-end: over a REAL app-terminated TLS 1.3 connection, the server binds
// the SCRAM handshake to the RFC 9266 tls-exporter — init advertises cbind, and
// client-final MUST carry the exporter of the same connection or the proof is
// rejected. This proves the server half of the -PLUS wiring; the exporter itself
// is proven byte-identical to the rustls client's by the cross-impl probe
// (scratchpad/f5-cbind), so a rustls client feeding its exporter verifies here too.
func TestScramPlus_RealTLSExporterBindsAndEmptyIsRejected(t *testing.T) {
	reg := auth.NewRegistry()
	tokens := auth.NewTokenStore(reg)
	mux := http.NewServeMux()
	New(reg, tokens).Register(mux)

	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	srv.StartTLS()
	defer srv.Close()

	// Register a credential over TLS (register needs no channel binding).
	account := strings.Repeat("42", 16)
	username := account // AS9: username = account-hash hex
	secret := []byte(strings.Repeat("\xcd", 32))
	salt := []byte(strings.Repeat("\x11", 16))
	cred, err := scram.MakeCredential(secret, salt, 1)
	if err != nil {
		t.Fatal(err)
	}
	regBody, _ := json.Marshal(registerReq{
		AccountHashHex: account, Username: username,
		SaltHex: hex.EncodeToString(salt), Iterations: 1,
		StoredKeyHex: hex.EncodeToString(cred.StoredKey),
		ServerKeyHex: hex.EncodeToString(cred.ServerKey),
	})
	if resp, err := srv.Client().Post(srv.URL+"/auth/register", "application/json", strings.NewReader(string(regBody))); err != nil {
		t.Fatal(err)
	} else if resp.StatusCode != 200 {
		t.Fatalf("register: %d", resp.StatusCode)
	}

	host := strings.TrimPrefix(srv.URL, "https://")

	// runHandshake drives init+final over ONE raw TLS conn, computing the client
	// cbind via `mkCbind(connectionState)`. Returns the final HTTP status.
	runHandshake := func(t *testing.T, dev byte, mkCbind func(tls.ConnectionState) []byte) int {
		t.Helper()
		conn, err := tls.Dial("tcp", host, &tls.Config{
			RootCAs:    srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
			ServerName: "example.com", // httptest's cert CN
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		br := bufio.NewReader(conn)

		clientNonce := "cn-tls-" + hex.EncodeToString([]byte{dev})
		initBody, _ := json.Marshal(scramInitReq{
			AccountHashHex: account, Username: username, ClientNonce: clientNonce,
		})
		irResp := rawPost(t, conn, br, host, "/auth/scram/init", initBody)
		if irResp.StatusCode != 200 {
			t.Fatalf("init: %d", irResp.StatusCode)
		}
		var ir scramInitResp
		mustJSON(t, irResp, &ir)
		// The server advertised app-terminated TLS binding.
		if ir.Cbind != scram.CbindName {
			t.Fatalf("init cbind = %q, want %q", ir.Cbind, scram.CbindName)
		}

		cbind := mkCbind(conn.ConnectionState())
		proof, _, err := scram.ClientProof(secret, cred, username, clientNonce, ir.CombinedNonce, cbind)
		if err != nil {
			t.Fatal(err)
		}
		clientFinal := scram.ClientFinalMessage(ir.CombinedNonce, cbind, proof)
		d := devID(dev)
		finalBody, _ := json.Marshal(scramFinalReq{
			HandshakeID: ir.HandshakeID, ClientFinal: clientFinal,
			DeviceIDHex: hex.EncodeToString(d[:]), Path: "recovery",
		})
		frResp := rawPost(t, conn, br, host, "/auth/scram/final", finalBody)
		return frResp.StatusCode
	}

	// The REAL exporter binds and the proof verifies → 200.
	realCbind := func(cs tls.ConnectionState) []byte {
		ekm, err := cs.ExportKeyingMaterial(scram.ExporterLabel, nil, scram.ExporterLen)
		if err != nil {
			t.Fatal(err)
		}
		return ekm
	}
	if got := runHandshake(t, 0x01, realCbind); got != 200 {
		t.Fatalf("real tls-exporter cbind: final status %d, want 200", got)
	}

	// An EMPTY cbind against an app-terminated server → channel-binding mismatch → 401.
	emptyCbind := func(tls.ConnectionState) []byte { return nil }
	if got := runHandshake(t, 0x02, emptyCbind); got != 401 {
		t.Fatalf("empty cbind vs app-terminated server: final status %d, want 401", got)
	}
}

// rawPost writes an HTTP/1.1 POST over the raw conn and reads one response using a
// shared bufio.Reader (so keep-alive lets init + final share the connection — the
// whole point, since the exporter is per-connection).
func rawPost(t *testing.T, conn *tls.Conn, br *bufio.Reader, host, path string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://"+host+path, strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if err := req.Write(conn); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func mustJSON(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("decode: %v (%s)", err, b)
	}
}

var _ = ids.DeviceID{}
