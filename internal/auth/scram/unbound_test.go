// SPDX-License-Identifier: AGPL-3.0

package scram

import (
	"errors"
	"testing"
)

// A browser can obtain neither TLS-exporter keying material nor certificate
// pinning, so the Phase 3 web client is permanently unbound (main repo
// `decisions.md` 2026-07-26). These tests pin the two halves of that: the server
// accepts an honestly-unbound session where it advertised no binding, and a
// bound client cannot be downgraded into one.

const (
	testUser  = "0123456789abcdef"
	testCNon  = "clientnonce"
	testCombo = "clientnonceservernonce"
)

func testCredential(t *testing.T, secret []byte) Credential {
	t.Helper()
	cred, err := MakeCredential(secret, []byte("saltsaltsaltsalt"), 4096)
	if err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}
	return cred
}

func TestUnboundSessionAcceptedWhenServerAdvertisesNoBinding(t *testing.T) {
	secret := []byte("high-entropy-verifier-secret")
	cred := testCredential(t, secret)

	proof, wantServerSig, err := ClientProofUnbound(secret, cred, testUser, testCNon, testCombo)
	if err != nil {
		t.Fatalf("ClientProofUnbound: %v", err)
	}
	final := ClientFinalMessageUnbound(testCombo, proof)

	gotSig, bound, err := VerifyClientFinalWithPolicy(cred, testUser, testCNon, testCombo, nil, true, final)
	if err != nil {
		t.Fatalf("unbound client-final rejected: %v", err)
	}
	if bound {
		t.Error("bound = true for an n,, handshake")
	}
	if string(gotSig) != string(wantServerSig) {
		t.Error("server signature mismatch — mutual auth would fail on the client")
	}
}

// The downgrade this design turns on. A client that computed its proof over the
// BOUND header cannot have that proof accepted as an unbound one, because the
// gs2 header is inside the AuthMessage the proof MACs.
func TestBoundClientCannotBeDowngradedToUnbound(t *testing.T) {
	secret := []byte("high-entropy-verifier-secret")
	cred := testCredential(t, secret)
	cbind := []byte("thirty-two-bytes-of-exporter-xxx")

	proof, _, err := ClientProof(secret, cred, testUser, testCNon, testCombo, cbind)
	if err != nil {
		t.Fatalf("ClientProof: %v", err)
	}
	boundFinal := ClientFinalMessage(testCombo, cbind, proof)

	// An attacker rewrites the c= attribute to the unbound form, keeping the
	// proof. The c= now parses, but the proof was MACed over `p=tls-exporter,,`
	// plus the exporter, so verification fails.
	forged := ClientFinalMessageUnbound(testCombo, proof)
	if _, _, err := VerifyClientFinalWithPolicy(cred, testUser, testCNon, testCombo, cbind, true, forged); err == nil {
		t.Fatal("a bound client's proof was accepted under the unbound header — downgrade possible")
	}

	// And the honest bound path still works with the same inputs.
	if _, bound, err := VerifyClientFinalWithPolicy(cred, testUser, testCNon, testCombo, cbind, true, boundFinal); err != nil || !bound {
		t.Fatalf("bound handshake broke: err=%v bound=%v", err, bound)
	}
}

// Where the server DID advertise tls-exporter, the unbound form must be refused
// outright — otherwise stripping the advertisement is a downgrade.
func TestUnboundRefusedWhenPolicyDisallowsIt(t *testing.T) {
	secret := []byte("high-entropy-verifier-secret")
	cred := testCredential(t, secret)

	proof, _, err := ClientProofUnbound(secret, cred, testUser, testCNon, testCombo)
	if err != nil {
		t.Fatalf("ClientProofUnbound: %v", err)
	}
	final := ClientFinalMessageUnbound(testCombo, proof)

	_, _, err = VerifyClientFinalWithPolicy(cred, testUser, testCNon, testCombo, nil, false, final)
	if !errors.Is(err, ErrChannelBindMismatch) {
		t.Fatalf("unbound accepted despite allowUnbound=false: err=%v", err)
	}
}

// The pre-existing bound-only entry point must behave exactly as before — every
// shipped native client goes through it.
func TestVerifyClientFinalStaysBoundOnly(t *testing.T) {
	secret := []byte("high-entropy-verifier-secret")
	cred := testCredential(t, secret)

	proof, _, err := ClientProofUnbound(secret, cred, testUser, testCNon, testCombo)
	if err != nil {
		t.Fatalf("ClientProofUnbound: %v", err)
	}
	if _, err := VerifyClientFinal(cred, testUser, testCNon, testCombo, nil, ClientFinalMessageUnbound(testCombo, proof)); !errors.Is(err, ErrChannelBindMismatch) {
		t.Fatalf("VerifyClientFinal accepted an unbound final: %v", err)
	}
}

// An `n,,` header with channel-binding bytes appended is not something any
// conforming client sends; accepting it would blur bound and unbound.
func TestUnboundHeaderWithAppendedCbindDataIsRejected(t *testing.T) {
	secret := []byte("high-entropy-verifier-secret")
	cred := testCredential(t, secret)
	cbind := []byte("thirty-two-bytes-of-exporter-xxx")

	// c = b64("n,," || cbind) — neither the bound nor the unbound candidate.
	forged := "c=" + b64e(append([]byte(gs2HeaderUnbound), cbind...)) + ",r=" + testCombo + ",p=" + b64e(make([]byte, 32))
	if _, _, err := VerifyClientFinalWithPolicy(cred, testUser, testCNon, testCombo, cbind, true, forged); !errors.Is(err, ErrChannelBindMismatch) {
		t.Fatalf("n,, with appended cbind data was not rejected: %v", err)
	}
}
