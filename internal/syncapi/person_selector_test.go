// SPDX-License-Identifier: AGPL-3.0
// The person-selector authorization (myne-md/myne#911 task 7).
//
// What these tests exist for, stated as the failure: a session that is not bound
// to a vault must not reach that vault's blobs, and one that IS bound must reach
// them with no per-vault token of its own. A missing membership check is not a
// crash and not a compile error; it is a read and a write on somebody else's
// namespace, which is invisible unless a test asks for it by name.
package syncapi

import (
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/myne-md/myne-server/internal/auth"
	"github.com/myne-md/myne-server/internal/ids"
	"github.com/myne-md/myne-server/internal/store"
)

// personHarness is the selector tests' fixture: a vault with its own device
// token, a person account with a device token, and a membership fake the test
// can bind them into.
type personHarness struct {
	srv        *httptest.Server
	st         store.BlobStore
	vaultToken string
	person     string
	personAcct ids.AccountNumberHash
	vault      ids.AccountNumberHash
	mem        *fakeMembership
}

func newPersonHarness(t *testing.T) *personHarness {
	t.Helper()
	st := store.NewMemStore()
	reg := auth.NewRegistry()
	ts := auth.NewTokenStore(reg)
	en := auth.NewEnrollment(reg, ts)

	var vault ids.AccountNumberHash
	vault[0] = 0x5a
	var personAcct ids.AccountNumberHash
	personAcct[0] = 0x77

	var dv ids.DeviceID
	dv[0] = 0x01
	vaultRes, err := en.Enroll(vault, dv, auth.PathPassword)
	if err != nil {
		t.Fatal(err)
	}
	var dp ids.DeviceID
	dp[0] = 0x02
	personRes, err := en.Enroll(personAcct, dp, auth.PathRecovery)
	if err != nil {
		t.Fatal(err)
	}

	mem := &fakeMembership{
		vault:    vault,
		owners:   map[ids.AccountNumberHash]bool{},
		bindings: map[ids.AccountNumberHash]map[ids.AccountNumberHash]string{},
	}
	mux := http.NewServeMux()
	New(st, ts).WithMembership(mem).Register(mux)
	return &personHarness{
		srv:        httptest.NewServer(mux),
		st:         st,
		vaultToken: hex.EncodeToString(vaultRes.Token[:]),
		person:     hex.EncodeToString(personRes.Token[:]),
		personAcct: personAcct,
		vault:      vault,
		mem:        mem,
	}
}

func (p *personHarness) close() { p.srv.Close() }

func (p *personHarness) bind(role string) {
	p.mem.bindings[p.vault] = map[ids.AccountNumberHash]string{p.personAcct: role}
}

// post hits a path with a bearer and a raw JSON body, returning status + body.
func (p *personHarness) post(t *testing.T, path, bearer, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, p.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	buf := new(strings.Builder)
	if _, err := io.Copy(buf, res.Body); err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, buf.String()
}

func (p *personHarness) putMeta(t *testing.T, query, bearer, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, p.srv.URL+"/vault.meta"+query, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	buf := new(strings.Builder)
	if _, err := io.Copy(buf, res.Body); err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, buf.String()
}

const emptyPushBody = `{"blobs":[]}`

// metaFrame builds a minimal `vault.meta` prefix: six leading bytes (magic,
// version, one reserved byte) followed by the §9.3 offset-6 namespace field, then
// the opaque tail. The server checks the offset-6 field against the publish
// selector before it binds an owner, so a fixture that is not a real frame would
// be testing a body the route now refuses (myne-md/myne#911).
func (p *personHarness) metaFrame(tag string) string {
	return "MYP5\x02\x00" + string(p.vault[:]) + tag
}

func (p *personHarness) getMeta(t *testing.T, query, bearer string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, p.srv.URL+"/vault.meta"+query, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	buf := new(strings.Builder)
	if _, err := io.Copy(buf, res.Body); err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, buf.String()
}

func TestPersonSessionWithoutBindingIsRefused(t *testing.T) {
	h := newPersonHarness(t)
	defer h.close()

	code, body := h.post(t, "/sync/push?account="+hex.EncodeToString(h.vault[:]), h.person, emptyPushBody)
	if code != http.StatusForbidden {
		t.Fatalf("unbound person selector: got %d %s, want 403 forbidden", code, body)
	}
	if !strings.Contains(body, "forbidden") {
		t.Fatalf("refusal body = %q, want a forbidden code", body)
	}
}

func TestPersonSessionSelectsABoundVault(t *testing.T) {
	h := newPersonHarness(t)
	defer h.close()
	h.bind("member")

	code, body := h.post(t, "/sync/push?account="+hex.EncodeToString(h.vault[:]), h.person, emptyPushBody)
	if code == http.StatusForbidden || code == http.StatusUnauthorized {
		t.Fatalf("bound person refused: %d %s", code, body)
	}
}

// The pull half of "a person token authorizes push AND pull": the two routes
// share `namespaceSession`, and this pins that they actually both use it. A
// resolver wired into push only would leave every read unauthenticated, which is
// the worse half of the pair.
func TestPersonSessionPullsABoundVault(t *testing.T) {
	h := newPersonHarness(t)
	defer h.close()
	h.bind("member")

	req, err := http.NewRequest(http.MethodGet, h.srv.URL+"/sync/pull?account="+hex.EncodeToString(h.vault[:])+"&cursor=0", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.person)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusUnauthorized {
		t.Fatalf("bound person refused on pull: %d", res.StatusCode)
	}
}

// The meta PULL half of the same rule (myne-md/myne#911).
//
// The failure this pins, stated as the symptom: the authed GET arm used
// `h.session` and served `GetMeta(sess.Account)`, so a person session asking for
// `?account=<vault>` was answered from the PERSON namespace, which holds no
// `vault.meta` at all. Every poll answered 404, so a password change made on one
// device never reached a second one, and a device whose local frame was dirty
// then pushed its stale copy over the server's. That is a silent credential
// rollback, and it is exactly what "never a silent fall back to the caller's own
// namespace" forbids.
func TestPersonSessionGetsABoundVaultsMeta(t *testing.T) {
	h := newPersonHarness(t)
	defer h.close()
	h.bind("owner")
	frame := h.metaFrame("META")
	if code, body := h.putMeta(t, "?account="+hex.EncodeToString(h.vault[:]), h.person, frame); code != http.StatusOK {
		t.Fatalf("publish: got %d %s", code, body)
	}
	code, body := h.getMeta(t, "?account="+hex.EncodeToString(h.vault[:]), h.person)
	if code != http.StatusOK {
		t.Fatalf("bound person could not read the vault's meta: got %d %s", code, body)
	}
	if body != frame {
		t.Fatalf("served the wrong frame: got %q, want %q", body, frame)
	}
}

func TestPersonSessionIsRefusedAnUnboundVaultsMeta(t *testing.T) {
	h := newPersonHarness(t)
	defer h.close()
	// No binding. The refusal must be the selector's, not a fall-through to the
	// caller's own namespace and not a retry as a pre-auth fetch.
	code, body := h.getMeta(t, "?account="+hex.EncodeToString(h.vault[:]), h.person)
	if code != http.StatusForbidden {
		t.Fatalf("unbound selector on meta: got %d %s, want 403 forbidden", code, body)
	}
}

// Publishing binds the owner BEFORE the frame is stored, so the frame has to
// name the namespace the selector names. Without this a client bug publishes
// under the wrong selector, `BindOwner` (first-write only) makes it permanent,
// and the real owner is refused forever with no way to unwind it.
func TestPublishRefusesAFrameForAnotherNamespace(t *testing.T) {
	h := newPersonHarness(t)
	defer h.close()
	// A frame that names a different namespace.
	other := ids.AccountNumberHash{}
	other[0] = 0x42
	frame := "MYP5\x02\x00" + string(other[:]) + "META"
	code, body := h.putMeta(t, "?account="+hex.EncodeToString(h.vault[:]), h.person, frame)
	if code != http.StatusBadRequest {
		t.Fatalf("mismatched publish: got %d %s, want 400 bad_request", code, body)
	}
	if _, ok := h.mem.bindings[h.vault][h.personAcct]; ok {
		t.Fatal("a refused publish bound an owner")
	}
}

func TestPersonSessionRefusesAMalformedSelector(t *testing.T) {
	h := newPersonHarness(t)
	defer h.close()
	h.bind("owner")

	code, body := h.post(t, "/sync/push?account=zzzz", h.person, emptyPushBody)
	// 400, not a silent fall back to the caller's own namespace: a typo in the
	// selector must not become a write to the wrong vault.
	if code != http.StatusBadRequest {
		t.Fatalf("malformed selector: got %d %s, want 400 bad_request", code, body)
	}
}

func TestLegacyVaultTokenIsUnchangedByTheSelector(t *testing.T) {
	// The regression half: a vault's own device token, with no selector, takes
	// exactly the path it took before the feature. If this goes red, the
	// selector logic reached a caller it was not meant for.
	h := newPersonHarness(t)
	defer h.close()

	code, body := h.post(t, "/sync/push", h.vaultToken, emptyPushBody)
	if code == http.StatusUnauthorized || code == http.StatusForbidden {
		t.Fatalf("legacy vault token refused: %d %s", code, body)
	}
}

func TestPublishBindsTheOwnerOnFirstWrite(t *testing.T) {
	h := newPersonHarness(t)
	defer h.close()

	code, body := h.putMeta(t, "?account="+hex.EncodeToString(h.vault[:]), h.person, h.metaFrame("META"))
	if code != http.StatusOK {
		t.Fatalf("publish: got %d %s, want 200", code, body)
	}
	role, ok := h.mem.bindings[h.vault][h.personAcct]
	if !ok || role != "owner" {
		t.Fatalf("publishing did not bind the owner: bindings=%v", h.mem.bindings)
	}
	got, err := h.st.GetMeta(h.vault)
	if err != nil || string(got) != h.metaFrame("META") {
		t.Fatalf("meta not stored under the vault: %q err=%v", got, err)
	}
}

func TestPublishRefusesAnotherPersonsVault(t *testing.T) {
	h := newPersonHarness(t)
	defer h.close()
	// Somebody else owns this vault. Both views of the fake are set, because the
	// publish path asks two different questions: "is this person bound" (the
	// bindings map) and "does this vault have an owner at all" (owners), and the
	// refusal it must produce depends on the second when the first is false.
	var other ids.AccountNumberHash
	other[0] = 0x99
	h.mem.bindings[h.vault] = map[ids.AccountNumberHash]string{other: "owner"}
	h.mem.owners[h.vault] = true

	code, body := h.putMeta(t, "?account="+hex.EncodeToString(h.vault[:]), h.person, h.metaFrame("META"))
	if code != http.StatusForbidden {
		t.Fatalf("foreign publish: got %d %s, want 403", code, body)
	}
	if _, err := h.st.GetMeta(h.vault); err == nil {
		t.Fatal("a refused publish wrote the vault's meta")
	}
}

// One revocation covers every vault (myne-md/myne#911 task 9).
//
// A member device holds a PER-VAULT membership token, so revoking the device on
// the person account used to leave that token working: the device the owner
// removed kept syncing the vaults that had been shared with it. The token now
// names the device it was issued to and the session asks the registry on every
// request, so the same act that revokes the device ends its shared-vault access
// too, without a per-vault sweep.
//
// Driven through the real pull route with the fake membership seam, in both
// directions: an active device authorizes, a revoked one is refused with
// `device_revoked` rather than `unauthenticated` (so the client learns the owner
// removed it instead of re-enrolling), and an unattributable token (the zero
// device) is never refused by a guess.
func TestARevokedDeviceStopsAuthenticatingItsMembershipToken(t *testing.T) {
	h := newPersonHarness(t)
	defer h.close()
	const memberBearer = "aabbccddeeff00112233445566778899"
	h.mem.memberBearer = memberBearer
	h.mem.device = ids.DeviceID{0x02}

	get := func() (int, string) {
		req, err := http.NewRequest(http.MethodGet, h.srv.URL+"/sync/pull?cursor=0", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+memberBearer)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		buf := new(strings.Builder)
		if _, err := io.Copy(buf, res.Body); err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, buf.String()
	}

	if status, body := get(); status == http.StatusUnauthorized {
		t.Fatalf("an active device must sync its shared vault, got %d %s", status, body)
	}

	h.mem.deviceRevoked = true
	status, body := get()
	if status != http.StatusUnauthorized {
		t.Fatalf("a revoked device must be refused, got %d %s", status, body)
	}
	if !strings.Contains(body, "device_revoked") {
		t.Fatalf("the refusal must name the revocation, got %s", body)
	}

	// An unattributable token (no device recorded, i.e. one issued before the
	// field existed) is not refused by a guess: the check must skip it.
	h.mem.device = ids.DeviceID{}
	if status, body := get(); status == http.StatusUnauthorized {
		t.Fatalf("an unattributable token must keep working, got %d %s", status, body)
	}
}
