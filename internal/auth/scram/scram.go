// SPDX-License-Identifier: AGPL-3.0

// Package scram implements SCRAM-SHA-256-PLUS (RFC 7677 / RFC 5802) with
// tls-exporter channel binding (RFC 9266), hand-wired from the closed primitive
// set — crypto/sha256, crypto/hmac, crypto/pbkdf2 — with ZERO new crypto
// dependency (preserves the §6 audit-substitute posture). The client side runs in
// the Rust core over raw TLS (this Go side is the server + a reference client for
// tests + cross-impl golden vectors).
//
// The authenticated secret is the high-entropy HKDF(root_key,"server-auth") value,
// so the iteration count is minimal (i=1); the server NEVER sees the secret — it
// stores only the StoredKey/ServerKey verifier and verifies a proof.
//
// SECURITY: the hand-wired channel-binding assembly + the live tls-exporter
// integration are gated by the MYND-420 R3 primitive-level review before
// production trust (see features/sync-server-auth/review-r3-scram-tls-exporter.md).
package scram

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// CbindName is the RFC 9266 channel-binding type name used in the gs2 header.
const CbindName = "tls-exporter"

// ExporterLabel is the RFC 9266 TLS keying-material exporter label. FROZEN,
// cross-implementation load-bearing: the Go server and the Rust client MUST feed
// this exact label (and a 32-byte length) to their TLS exporter or the channel
// binding diverges and every -PLUS handshake fails. Verified byte-identical
// between Go crypto/tls and rustls/ring over TLS 1.3 (features/.../review-r3).
const ExporterLabel = "EXPORTER-Channel-Binding"

// ExporterLen is the frozen tls-exporter output length (RFC 9266 uses 32).
const ExporterLen = 32

// gs2Header is the fixed GS2 header for SCRAM-SHA-256-PLUS with tls-exporter
// channel binding and no authzid.
const gs2Header = "p=" + CbindName + ",,"

// Errors.
var (
	ErrProofMismatch        = errors.New("scram: client proof mismatch")
	ErrChannelBindMismatch  = errors.New("scram: channel binding mismatch")
	ErrNonceMismatch        = errors.New("scram: nonce mismatch")
	ErrMalformedMessage     = errors.New("scram: malformed message")
	ErrServerSigMismatch    = errors.New("scram: server signature mismatch")
	ErrUnsupportedIteration = errors.New("scram: non-positive iteration count")
)

func b64e(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func sha(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

func mac(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func xor(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// Credential is the server-stored verifier — never the secret. A stolen
// Credential cannot impersonate the client (ClientKey is not derivable from
// StoredKey without inverting SHA-256).
type Credential struct {
	Salt       []byte
	Iterations int
	StoredKey  []byte // SHA-256(ClientKey)
	ServerKey  []byte // HMAC(SaltedPassword, "Server Key")
}

// MakeCredential derives the SCRAM verifier from the high-entropy server-auth
// secret. iterations is the PBKDF2 count (1 for a 256-bit secret).
func MakeCredential(secret, salt []byte, iterations int) (Credential, error) {
	if iterations < 1 {
		return Credential{}, ErrUnsupportedIteration
	}
	sp, err := pbkdf2.Key(sha256.New, string(secret), salt, iterations, sha256.Size)
	if err != nil {
		return Credential{}, err
	}
	clientKey := mac(sp, []byte("Client Key"))
	serverKey := mac(sp, []byte("Server Key"))
	return Credential{
		Salt:       append([]byte(nil), salt...),
		Iterations: iterations,
		StoredKey:  sha(clientKey),
		ServerKey:  serverKey,
	}, nil
}

// --- message construction (canonical SCRAM strings) ---

func clientFirstBare(username, clientNonce string) string {
	return "n=" + username + ",r=" + clientNonce
}

func serverFirst(combinedNonce string, salt []byte, iterations int) string {
	return "r=" + combinedNonce + ",s=" + b64e(salt) + ",i=" + strconv.Itoa(iterations)
}

// clientFinalNoProof: c=<b64(gs2-header || cbindData)>,r=<combinedNonce>.
func clientFinalNoProof(cbindData []byte, combinedNonce string) string {
	cbindInput := append([]byte(gs2Header), cbindData...)
	return "c=" + b64e(cbindInput) + ",r=" + combinedNonce
}

func authMessage(username, clientNonce, combinedNonce string, salt []byte, iterations int, cbindData []byte) string {
	return clientFirstBare(username, clientNonce) + "," +
		serverFirst(combinedNonce, salt, iterations) + "," +
		clientFinalNoProof(cbindData, combinedNonce)
}

// ClientProof computes the SCRAM client proof from the secret + the handshake
// parameters. This is the Rust-core client's job in production; the Go version is
// the reference for tests + golden vectors.
func ClientProof(secret []byte, cred Credential, username, clientNonce, combinedNonce string, cbindData []byte) (proof []byte, serverSig []byte, err error) {
	if cred.Iterations < 1 {
		return nil, nil, ErrUnsupportedIteration
	}
	sp, err := pbkdf2.Key(sha256.New, string(secret), cred.Salt, cred.Iterations, sha256.Size)
	if err != nil {
		return nil, nil, err
	}
	clientKey := mac(sp, []byte("Client Key"))
	storedKey := sha(clientKey)
	serverKey := mac(sp, []byte("Server Key"))
	am := []byte(authMessage(username, clientNonce, combinedNonce, cred.Salt, cred.Iterations, cbindData))
	clientSig := mac(storedKey, am)
	serverSig = mac(serverKey, am)
	return xor(clientKey, clientSig), serverSig, nil
}

// VerifyClientFinal verifies a client-final message against the stored credential
// and the server's own channel-binding data. On success it returns the
// server-signature the client checks (mutual auth). The whole flow is value-driven
// (nonces + cbindData supplied by the caller) so it is exhaustively testable and
// reused by the live handler with crypto/rand nonces + the real tls-exporter.
func VerifyClientFinal(cred Credential, username, clientNonce, combinedNonce string, serverCbindData []byte, clientFinal string) (serverSig []byte, err error) {
	c, r, p, ok := parseClientFinal(clientFinal)
	if !ok {
		return nil, ErrMalformedMessage
	}
	// Channel binding: c= must equal b64(gs2-header || serverCbindData).
	wantC := b64e(append([]byte(gs2Header), serverCbindData...))
	if subtle.ConstantTimeCompare([]byte(c), []byte(wantC)) != 1 {
		return nil, ErrChannelBindMismatch
	}
	// Nonce: r= must equal the combined nonce the server issued.
	if subtle.ConstantTimeCompare([]byte(r), []byte(combinedNonce)) != 1 {
		return nil, ErrNonceMismatch
	}
	proof, derr := base64.StdEncoding.DecodeString(p)
	if derr != nil || len(proof) != sha256.Size {
		return nil, ErrMalformedMessage
	}
	am := []byte(authMessage(username, clientNonce, combinedNonce, cred.Salt, cred.Iterations, serverCbindData))
	clientSig := mac(cred.StoredKey, am)
	clientKey := xor(proof, clientSig)
	if subtle.ConstantTimeCompare(sha(clientKey), cred.StoredKey) != 1 {
		return nil, ErrProofMismatch
	}
	return mac(cred.ServerKey, am), nil
}

func parseClientFinal(s string) (c, r, p string, ok bool) {
	for _, part := range strings.Split(s, ",") {
		switch {
		case strings.HasPrefix(part, "c="):
			c = part[2:]
		case strings.HasPrefix(part, "r="):
			r = part[2:]
		case strings.HasPrefix(part, "p="):
			p = part[2:]
		}
	}
	if c == "" || r == "" || p == "" {
		return "", "", "", false
	}
	return c, r, p, true
}

// ClientFinalMessage assembles the wire client-final (reference client / tests).
func ClientFinalMessage(combinedNonce string, cbindData, proof []byte) string {
	return fmt.Sprintf("%s,p=%s", clientFinalNoProof(cbindData, combinedNonce), b64e(proof))
}
