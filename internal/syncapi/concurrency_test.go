// SPDX-License-Identifier: AGPL-3.0

package syncapi

// End-to-end concurrency stress over the real HTTP surface (mux + bearer auth + JSON
// + store). The functional suite drives one request at a time; these fire many
// concurrent /sync/push requests through the production handler to prove the wire
// layer preserves the store's CAS guarantees: a same-blob race admits exactly one
// 200 and the rest 409 blob_stale, a same-genesis-head race admits one 200 and the
// rest 409 head_stale, and distinct-blob pushes all land. Run under `-race`.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// rawPush issues one /sync/push and returns (status, error_code). Safe for goroutines
// (never calls t.Fatal); a transport failure surfaces as status -1.
func rawPush(srvURL, token, body string) (int, string) {
	req, _ := http.NewRequest(http.MethodPost, srvURL+"/sync/push", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return -1, "transport"
	}
	defer resp.Body.Close()
	var e errBody
	_ = json.NewDecoder(resp.Body).Decode(&e)
	return resp.StatusCode, e.ErrorCode
}

// fanOutPush runs n concurrent pushes (bodies[i]) released at once and returns the
// per-request (status, code). Each goroutine writes only its own slot — no shared
// mutation, so distinct-index slice writes are race-free.
func fanOutPush(srvURL, token string, bodies []string) (statuses []int, codes []string) {
	n := len(bodies)
	statuses = make([]int, n)
	codes = make([]string, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			statuses[i], codes[i] = rawPush(srvURL, token, bodies[i])
		}(i)
	}
	close(start)
	wg.Wait()
	return statuses, codes
}

func TestConcurrent_HTTPPush_SameBlob_SingleWinner(t *testing.T) {
	srv, token := setup(t)
	defer srv.Close()
	id := strings.Repeat("a1", 16)
	nonceHex := strings.Repeat("cb", 24)

	const n = 48
	bodies := make([]string, n)
	for i := range bodies {
		ct := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("racer-%03d", i)))
		bodies[i] = `{"blobs":[{"blob_id_hex":"` + id + `","base_version":0,"content_nonce_hex":"` + nonceHex +
			`","ciphertext_b64":"` + ct + `"}]}`
	}
	statuses, codes := fanOutPush(srv.URL, token, bodies)

	var ok200, conflict409 int
	for i := range statuses {
		switch statuses[i] {
		case 200:
			ok200++
		case http.StatusConflict:
			conflict409++
			if codes[i] != "blob_stale" {
				t.Errorf("conflict code = %q, want blob_stale", codes[i])
			}
		default:
			t.Errorf("unexpected status %d (code %q)", statuses[i], codes[i])
		}
	}
	if ok200 != 1 || conflict409 != n-1 {
		t.Fatalf("same-blob race: 200=%d 409=%d, want 1/%d", ok200, conflict409, n-1)
	}

	// Pull confirms exactly one stored version.
	resp, body := do(t, srv, http.MethodGet, "/sync/pull?cursor=0&limit=10000", token, "")
	if resp.StatusCode != 200 {
		t.Fatalf("pull: %d %s", resp.StatusCode, body)
	}
	var pl pullResp
	if err := json.Unmarshal(body, &pl); err != nil {
		t.Fatal(err)
	}
	if len(pl.Metas) != 1 || pl.Metas[0].Version != 1 {
		t.Fatalf("pull after race: %+v", pl)
	}
}

func TestConcurrent_HTTPPush_DistinctBlobs_AllStored(t *testing.T) {
	srv, token := setup(t)
	defer srv.Close()
	nonceHex := strings.Repeat("cb", 24)

	const n = 48
	bodies := make([]string, n)
	for i := range bodies {
		id := fmt.Sprintf("%032x", i+1) // distinct 16-byte blob id
		ct := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("blob-%03d", i)))
		bodies[i] = `{"blobs":[{"blob_id_hex":"` + id + `","base_version":0,"content_nonce_hex":"` + nonceHex +
			`","ciphertext_b64":"` + ct + `"}]}`
	}
	statuses, codes := fanOutPush(srv.URL, token, bodies)
	for i := range statuses {
		if statuses[i] != 200 {
			t.Errorf("blob %d status %d code %q, want 200", i, statuses[i], codes[i])
		}
	}

	resp, body := do(t, srv, http.MethodGet, "/sync/pull?cursor=0&limit=10000", token, "")
	if resp.StatusCode != 200 {
		t.Fatalf("pull: %d %s", resp.StatusCode, body)
	}
	var pl pullResp
	if err := json.Unmarshal(body, &pl); err != nil {
		t.Fatal(err)
	}
	if len(pl.Metas) != n {
		t.Fatalf("pulled %d metas, want %d", len(pl.Metas), n)
	}
}

func TestConcurrent_HTTPHead_GenesisRace_SingleWinner(t *testing.T) {
	srv, token := setup(t)
	defer srv.Close()
	prevZero := strings.Repeat("00", 32)

	const n = 32
	bodies := make([]string, n)
	for i := range bodies {
		rec := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("genesis-%03d", i)))
		bodies[i] = `{"blobs":[],"new_head":{"prev_head_hash_hex":"` + prevZero + `","record_b64":"` + rec + `"}}`
	}
	statuses, codes := fanOutPush(srv.URL, token, bodies)

	var ok, conflict int
	for i := range statuses {
		switch statuses[i] {
		case 200:
			ok++
		case http.StatusConflict:
			conflict++
			if codes[i] != "head_stale" {
				t.Errorf("head conflict code = %q, want head_stale", codes[i])
			}
		default:
			t.Errorf("unexpected status %d code %q", statuses[i], codes[i])
		}
	}
	if ok != 1 || conflict != n-1 {
		t.Fatalf("genesis head race: 200=%d 409=%d, want 1/%d", ok, conflict, n-1)
	}
}
