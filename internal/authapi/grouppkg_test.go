// SPDX-License-Identifier: AGPL-3.0-only

package authapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/myne-md/myne-server/internal/grouppkg"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/membership"
)

// groupPkgEnv builds vault A with an owner, and a bound member with its own
// person session token.
type groupPkgEnv struct {
	*b2bEnv
	ownerA string
	member string // person session token (an /auth device token)
	// memberVaultTs is the member's per-vault membership token (RoleMember),
	// distinct from its person session. Used to prove a non-owner cannot write.
	memberVaultTs string
	vaultA        ids.AccountNumberHash
	memberP       membership.PersonID
}

func newGroupPkgEnv(t *testing.T) *groupPkgEnv {
	t.Helper()
	e := newB2BEnv(t)
	_, vaultTokA := e.account(t, b2bVaultA, 0x0b)
	_, _ = e.account(t, b2bOwner, 0x0a)
	_, ownerA := e.bind(t, b2bVaultA, vaultTokA, b2bOwner, "owner")
	if ownerA.TokenHex == "" {
		t.Fatal("owner binding must issue a token")
	}
	// The member's PERSON SESSION is an ordinary /auth device token for the
	// member's own account; its membership binding (and its per-vault token) is
	// created separately by the owner, exactly as an invite claim does in
	// production.
	_, memberTok := e.account(t, b2bMember, 0x0d)
	resp, memberBind := e.bind(t, b2bVaultA, ownerA.TokenHex, b2bMember, "member")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bind member: want 200, got %d", resp.StatusCode)
	}
	mp, _ := parsePersonID(b2bMember)
	return &groupPkgEnv{
		b2bEnv:        e,
		ownerA:        ownerA.TokenHex,
		member:        memberTok,
		memberVaultTs: memberBind.TokenHex,
		vaultA:        acct(t, b2bVaultA),
		memberP:       mp,
	}
}

func (e *groupPkgEnv) put(t *testing.T, bearer, personHex string, epoch uint64, pkg []byte) *http.Response {
	t.Helper()
	resp, _ := sendJSON(t, http.MethodPut,
		e.srv.URL+"/b2b/vaults/"+b2bVaultA+"/group-packages/"+personHex, bearer,
		putGroupPackageReq{Epoch: epoch, PackageB64: base64.StdEncoding.EncodeToString(pkg)})
	return resp
}

func (e *groupPkgEnv) get(t *testing.T, bearer, personHex string) (*http.Response, getGroupPackageResp) {
	t.Helper()
	resp, body := sendJSON(t, http.MethodGet,
		e.srv.URL+"/b2b/vaults/"+b2bVaultA+"/group-packages/"+personHex, bearer, nil)
	var gr getGroupPackageResp
	_ = json.Unmarshal(body, &gr)
	return resp, gr
}

// The owner writes a package; the bound member reads its own byte-identically.
func TestGroupPackage_OwnerWritesMemberReadsItsOwn(t *testing.T) {
	e := newGroupPkgEnv(t)
	pkg := []byte("owner-signed group package, opaque to the server")

	if resp := e.put(t, e.ownerA, b2bMember, 2, pkg); resp.StatusCode != http.StatusOK {
		t.Fatalf("owner put: want 200, got %d", resp.StatusCode)
	}
	resp, got := e.get(t, e.member, b2bMember)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member get: want 200, got %d", resp.StatusCode)
	}
	if got.Epoch != 2 {
		t.Fatalf("epoch = %d, want 2", got.Epoch)
	}
	decoded, err := base64.StdEncoding.DecodeString(got.PackageB64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, pkg) {
		t.Fatalf("package round-trip = %q, want %q", decoded, pkg)
	}
}

// Latest-per-recipient: a write at an epoch not greater than the stored one is
// ignored, so a replayed or stale write cannot regress a caught-up recipient.
func TestGroupPackage_NewerEpochSupersedesOlderAndStaleIsIgnored(t *testing.T) {
	e := newGroupPkgEnv(t)
	older := []byte("epoch 2 package")
	newer := []byte("epoch 3 package")

	if resp := e.put(t, e.ownerA, b2bMember, 2, older); resp.StatusCode != http.StatusOK {
		t.Fatalf("put epoch 2: want 200, got %d", resp.StatusCode)
	}
	// A strictly newer epoch supersedes.
	if resp := e.put(t, e.ownerA, b2bMember, 3, newer); resp.StatusCode != http.StatusOK {
		t.Fatalf("put epoch 3: want 200, got %d", resp.StatusCode)
	}
	// A stale epoch is ignored.
	if resp := e.put(t, e.ownerA, b2bMember, 2, []byte("replayed epoch 2")); resp.StatusCode != http.StatusOK {
		t.Fatalf("stale put: want 200, got %d", resp.StatusCode)
	}
	_, got := e.get(t, e.member, b2bMember)
	if got.Epoch != 3 {
		t.Fatalf("epoch = %d, want 3 (the newer package)", got.Epoch)
	}
	decoded, _ := base64.StdEncoding.DecodeString(got.PackageB64)
	if !bytes.Equal(decoded, newer) {
		t.Fatalf("retained package = %q, want the epoch-3 bytes", decoded)
	}
}

// Authorization: only the owner writes; only the bound member reads its own.
func TestGroupPackage_AuthorizationRefusals(t *testing.T) {
	e := newGroupPkgEnv(t)
	pkg := []byte("package")
	if resp := e.put(t, e.ownerA, b2bMember, 2, pkg); resp.StatusCode != http.StatusOK {
		t.Fatalf("owner put: want 200, got %d", resp.StatusCode)
	}

	// A member's per-vault token (RoleMember) may not write: only the owner may.
	if resp := e.put(t, e.memberVaultTs, b2bMember, 3, pkg); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member put: want 403, got %d", resp.StatusCode)
	}
	// An unknown bearer may not read.
	if resp, _ := e.get(t, "deadbeef", b2bMember); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown bearer get: want 401, got %d", resp.StatusCode)
	}
	// A different, unbound account reads nothing.
	_, otherTok := e.account(t, b2bOther, 0x0e)
	if resp, _ := e.get(t, otherTok, b2bMember); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unbound reader: want 403, got %d", resp.StatusCode)
	}
	// The bound member may not address another person's package: the path person
	// must be its own, and a mismatch is a not-found rather than a leak.
	if resp, _ := e.get(t, e.member, b2bOwner); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-person get: want 404, got %d", resp.StatusCode)
	}
	// A malformed person id is a client bug.
	if resp := e.put(t, e.ownerA, "not-hex", 3, pkg); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed person: want 400, got %d", resp.StatusCode)
	}
	// An over-cap package is refused.
	if resp := e.put(t, e.ownerA, b2bMember, 4, bytes.Repeat([]byte{0x41}, MaxGroupPackageBytes+1)); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("over-cap package: want 400, got %d", resp.StatusCode)
	}
	// An absent package reads as not-found.
	if resp, _ := e.get(t, e.member, b2bAnybody); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("absent package: want 404, got %d", resp.StatusCode)
	}
}

// The store copies its input and is vault-scoped, so a caller's buffer cannot
// mutate a served record and one vault cannot read another's package.
func TestGroupPackageStore_CopiesAndScopesByVault(t *testing.T) {
	s := grouppkg.NewStore()
	vaultA := acct(t, b2bVaultA)
	vaultB := acct(t, b2bVaultB)
	person := membership.PersonID{}

	buf := []byte("first")
	s.Put(vaultA, person, 1, buf)
	buf[0] = 'X' // mutate the caller's buffer after Put
	rec, err := s.Get(vaultA, person)
	if err != nil {
		t.Fatal(err)
	}
	if string(rec.Package) != "first" {
		t.Fatalf("stored package = %q, want the copy %q", rec.Package, "first")
	}
	if _, err := s.Get(vaultB, person); err == nil {
		t.Fatal("a package stored under one vault must not be readable under another")
	}
}
