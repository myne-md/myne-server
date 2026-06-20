// SPDX-License-Identifier: AGPL-3.0-or-later

package scram

import (
	"bytes"
	"errors"
	"testing"
)

const (
	user     = "MY-DEMO"
	clientN  = "clientnonce123"
	serverN  = "servernonce456"
	combined = clientN + serverN
	iter     = 1
)

var (
	secret     = bytes.Repeat([]byte{0xAB}, 32) // stands in for HKDF(root_key,"server-auth")
	salt       = bytes.Repeat([]byte{0x11}, 16)
	cbind      = bytes.Repeat([]byte{0xCB}, 32) // stands in for the tls-exporter material
	otherCbind = bytes.Repeat([]byte{0xFF}, 32)
)

func successfulExchange(t *testing.T) (Credential, []byte) {
	t.Helper()
	cred, err := MakeCredential(secret, salt, iter)
	if err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}
	proof, clientServerSig, err := ClientProof(secret, cred, user, clientN, combined, cbind)
	if err != nil {
		t.Fatalf("ClientProof: %v", err)
	}
	final := ClientFinalMessage(combined, cbind, proof)
	serverSig, err := VerifyClientFinal(cred, user, clientN, combined, cbind, final)
	if err != nil {
		t.Fatalf("VerifyClientFinal: %v", err)
	}
	// Mutual auth: the server signature the server returns must match the one the
	// client independently computed.
	if !bytes.Equal(serverSig, clientServerSig) {
		t.Fatalf("server signature mismatch (mutual auth broken)")
	}
	return cred, serverSig
}

func TestSCRAM_SuccessRoundTrip(t *testing.T) {
	successfulExchange(t)
}

func TestSCRAM_WrongSecretRejected(t *testing.T) {
	cred, _ := MakeCredential(secret, salt, iter)
	wrong := bytes.Repeat([]byte{0x00}, 32)
	proof, _, err := ClientProof(wrong, cred, user, clientN, combined, cbind)
	if err != nil {
		t.Fatal(err)
	}
	final := ClientFinalMessage(combined, cbind, proof)
	if _, err := VerifyClientFinal(cred, user, clientN, combined, cbind, final); !errors.Is(err, ErrProofMismatch) {
		t.Fatalf("wrong secret accepted: %v, want ErrProofMismatch", err)
	}
}

func TestSCRAM_ChannelBindingMismatchRejected(t *testing.T) {
	cred, _ := MakeCredential(secret, salt, iter)
	// Client binds to `cbind`, but the server's TLS session yields `otherCbind`
	// (a MitM with a different TLS channel) → must be rejected.
	proof, _, err := ClientProof(secret, cred, user, clientN, combined, cbind)
	if err != nil {
		t.Fatal(err)
	}
	final := ClientFinalMessage(combined, cbind, proof)
	if _, err := VerifyClientFinal(cred, user, clientN, combined, otherCbind, final); !errors.Is(err, ErrChannelBindMismatch) {
		t.Fatalf("channel-binding mismatch accepted: %v, want ErrChannelBindMismatch", err)
	}
}

func TestSCRAM_TamperedProofRejected(t *testing.T) {
	cred, _ := MakeCredential(secret, salt, iter)
	proof, _, err := ClientProof(secret, cred, user, clientN, combined, cbind)
	if err != nil {
		t.Fatal(err)
	}
	proof[0] ^= 0x01 // flip one bit
	final := ClientFinalMessage(combined, cbind, proof)
	if _, err := VerifyClientFinal(cred, user, clientN, combined, cbind, final); !errors.Is(err, ErrProofMismatch) {
		t.Fatalf("tampered proof accepted: %v, want ErrProofMismatch", err)
	}
}

func TestSCRAM_NonceMismatchRejected(t *testing.T) {
	cred, _ := MakeCredential(secret, salt, iter)
	proof, _, err := ClientProof(secret, cred, user, clientN, combined, cbind)
	if err != nil {
		t.Fatal(err)
	}
	// Client final built with the right combined nonce, but the server expects a
	// different one (replay / nonce confusion).
	final := ClientFinalMessage(combined, cbind, proof)
	if _, err := VerifyClientFinal(cred, user, clientN, "DIFFERENTnonce", cbind, final); err == nil {
		t.Fatal("nonce mismatch accepted, want error")
	}
}

func TestSCRAM_VerifierHidesSecret(t *testing.T) {
	// The stored verifier must not equal the secret, and StoredKey != ServerKey.
	cred, _ := MakeCredential(secret, salt, iter)
	if bytes.Equal(cred.StoredKey, secret) || bytes.Equal(cred.ServerKey, secret) {
		t.Fatal("verifier leaks the secret")
	}
	if bytes.Equal(cred.StoredKey, cred.ServerKey) {
		t.Fatal("StoredKey == ServerKey (domain separation broken)")
	}
}
