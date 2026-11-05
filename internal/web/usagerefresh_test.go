package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"claude-utilities/internal/usage"
	"claude-utilities/internal/vault"
)

// Refresh satisfies usageAPI for the map fake the other web tests use. The refresh route's own
// tests below run a real *usage.Poller over a fake Doer, so this needs no behaviour beyond
// reporting what the map already holds.
func (u fakeUsage) RefreshNow(_ context.Context, ids []string) []usage.RefreshResult {
	out := []usage.RefreshResult{}
	for _, id := range ids {
		x, ok := u[id]
		st := usage.Refreshed
		if !ok {
			st = usage.UnknownID
		}
		out = append(out, usage.RefreshResult{ID: id, Status: st, Usage: x})
	}
	return out
}

// --- a rig with a real poller behind a fake endpoint ---

const refreshBody = `{"five_hour":{"utilization":20,"resets_at":"2026-11-04T17:00:00Z"},
"seven_day":{"utilization":60,"resets_at":"2026-11-10T17:00:00Z"}}`

// stubDoer answers the usage request from a func. Nothing here reaches the real endpoint: the Doer
// seam is the only way usage.Fetch makes a request.
type stubDoer struct {
	mu    sync.Mutex
	calls int
	fn    func() (*http.Response, error)
}

func (d *stubDoer) Do(*http.Request) (*http.Response, error) {
	d.mu.Lock()
	d.calls++
	d.mu.Unlock()
	return d.fn()
}

func (d *stubDoer) n() int { d.mu.Lock(); defer d.mu.Unlock(); return d.calls }

func reply(code int, body string, hdr map[string]string) *http.Response {
	h := http.Header{}
	for k, v := range hdr {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: h}
}

type refreshRig struct {
	*rig
	doer   *stubDoer
	poller *usage.Poller
}

func newRefreshRig(t *testing.T, labels ...string) *refreshRig {
	t.Helper()
	t.Setenv("REFRESH_TEST_KEY", "test-passphrase")
	v, err := vault.Open(filepath.Join(t.TempDir(), "vault.bin"), "REFRESH_TEST_KEY")
	if err != nil {
		t.Fatal(err)
	}
	d := &stubDoer{fn: func() (*http.Response, error) { return reply(http.StatusOK, refreshBody, nil), nil }}
	p := usage.NewPoller(d, time.Hour)
	p.SetAccounts(v.List)
	r := &rig{t: t, fh: &fakeHub{}, v: v, pw: &fakePW{pw: adminPW}, now: fixedNow}
	r.h = newHandler(r.fh, v, p, r.pw, nil, func() time.Time { return r.now })
	for i, label := range labels {
		err := v.Put(vault.Account{ID: string(rune('a' + i)), Label: label, Identity: "uuid-" + label,
			Updated: fixedNow, Block: json.RawMessage(`{"accessToken":"` + blockSecret + `"}`)})
		if err != nil {
			t.Fatal(err)
		}
	}
	return &refreshRig{rig: r, doer: d, poller: p}
}

type gotRow struct {
	ID            string     `json:"id"`
	Status        string     `json:"status"`
	UpdatedAt     *time.Time `json:"updatedAt"`
	RetryAfterSec int64      `json:"retryAfterSec"`
	Error         string     `json:"error"`
}

func (rr *refreshRig) post(s *session, csrf, body string) (*httptest.ResponseRecorder, []gotRow) {
	rr.t.Helper()
	w := rr.do(http.MethodPost, "/api/usage/refresh", body, s, csrf)
	var out struct {
		Results []gotRow `json:"results"`
	}
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			rr.t.Fatalf("body %q: %v", w.Body.String(), err)
		}
	}
	return w, out.Results
}

func TestRefreshWithoutSessionIs401(t *testing.T) {
	rr := newRefreshRig(t, "one")
	if w, _ := rr.post(nil, "", `{}`); w.Code != http.StatusUnauthorized || w.Body.Len() != 0 {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	if rr.doer.n() != 0 {
		t.Fatal("unauthenticated request reached the usage endpoint")
	}
}

func TestRefreshWithWrongCSRFIs403(t *testing.T) {
	rr := newRefreshRig(t, "one")
	s := rr.login()
	w, _ := rr.post(s, "not-the-token", `{}`)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "CSRF") {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	if rr.doer.n() != 0 {
		t.Fatal("request without a CSRF token reached the usage endpoint")
	}
}

func TestRefreshAllPollsEveryAccount(t *testing.T) {
	rr := newRefreshRig(t, "one", "two")
	s := rr.login()
	w, rows := rr.post(s, s.csrf, `{}`)
	if w.Code != http.StatusOK || len(rows) != 2 {
		t.Fatalf("status %d rows %+v", w.Code, rows)
	}
	for _, row := range rows {
		if row.Status != "refreshed" || row.UpdatedAt == nil || row.RetryAfterSec != 0 {
			t.Fatalf("row %+v", row)
		}
	}
	if rr.doer.n() != 2 {
		t.Fatalf("calls = %d", rr.doer.n())
	}
	// The response must never carry a credential block.
	if strings.Contains(w.Body.String(), blockSecret) {
		t.Fatal("response leaked a token")
	}
}

func TestRefreshOneAccountPollsOnlyThatAccount(t *testing.T) {
	rr := newRefreshRig(t, "one", "two")
	s := rr.login()
	w, rows := rr.post(s, s.csrf, `{"account":"b"}`)
	if w.Code != http.StatusOK || len(rows) != 1 || rows[0].ID != "b" || rows[0].Status != "refreshed" {
		t.Fatalf("status %d rows %+v", w.Code, rows)
	}
	if rr.doer.n() != 1 {
		t.Fatalf("calls = %d", rr.doer.n())
	}
}

func TestRefreshUnknownAccountReportsUnknownID(t *testing.T) {
	rr := newRefreshRig(t, "one")
	s := rr.login()
	w, rows := rr.post(s, s.csrf, `{"account":"nope"}`)
	if w.Code != http.StatusOK || len(rows) != 1 || rows[0].Status != "unknown_id" {
		t.Fatalf("status %d rows %+v", w.Code, rows)
	}
	if rr.doer.n() != 0 {
		t.Fatal("an unknown id reached the usage endpoint")
	}
}

func TestRefreshTwiceInsideTheIntervalIsRateLimitedPerAccount(t *testing.T) {
	rr := newRefreshRig(t, "one")
	s := rr.login()
	if _, rows := rr.post(s, s.csrf, `{"account":"a"}`); rows[0].Status != "refreshed" {
		t.Fatalf("first: %+v", rows)
	}
	w, rows := rr.post(s, s.csrf, `{"account":"a"}`)
	if w.Code != http.StatusOK || rows[0].Status != "rate_limited" || rows[0].RetryAfterSec != 15 {
		t.Fatalf("status %d rows %+v", w.Code, rows)
	}
	if rr.doer.n() != 1 {
		t.Fatalf("the refused refresh hit the endpoint: %d calls", rr.doer.n())
	}
}

func TestRefreshOverTheGlobalLimitIs429(t *testing.T) {
	rr := newRefreshRig(t, "one")
	s := rr.login()
	for i := 0; i < maxRefreshRequests; i++ {
		if w, _ := rr.post(s, s.csrf, `{}`); w.Code != http.StatusOK {
			t.Fatalf("request %d: status %d", i, w.Code)
		}
	}
	w, _ := rr.post(s, s.csrf, `{}`)
	if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), "wait") {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	// The window moves on.
	rr.now = rr.now.Add(refreshWindow + time.Second)
	if w, _ := rr.post(s, s.csrf, `{}`); w.Code != http.StatusOK {
		t.Fatalf("after the window: status %d", w.Code)
	}
}

func TestRefreshFailureReportsTheCategoryNotTheToken(t *testing.T) {
	rr := newRefreshRig(t, "one")
	rr.doer.fn = func() (*http.Response, error) {
		return reply(http.StatusUnauthorized, "Bearer "+blockSecret, nil), nil
	}
	s := rr.login()
	w, rows := rr.post(s, s.csrf, `{"account":"a"}`)
	if w.Code != http.StatusOK || rows[0].Status != "error" || rows[0].Error != "unauthorized" {
		t.Fatalf("status %d rows %+v", w.Code, rows)
	}
	if strings.Contains(w.Body.String(), blockSecret) {
		t.Fatal("response leaked a token")
	}
}

// Two admins clicking at once must cost the endpoint one request per account.
func TestConcurrentRefreshRequestsShareOneUsageCall(t *testing.T) {
	rr := newRefreshRig(t, "one")
	entered, release := make(chan struct{}, 1), make(chan struct{})
	rr.doer.fn = func() (*http.Response, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return reply(http.StatusOK, refreshBody, nil), nil
	}
	s := rr.login()
	var wg sync.WaitGroup
	codes := make([]int, 2)
	wg.Add(1)
	go func() { defer wg.Done(); w, _ := rr.post(s, s.csrf, `{"account":"a"}`); codes[0] = w.Code }()
	<-entered
	wg.Add(1)
	go func() { defer wg.Done(); w, _ := rr.post(s, s.csrf, `{"account":"a"}`); codes[1] = w.Code }()
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if rr.doer.n() != 1 {
		t.Fatalf("calls = %d", rr.doer.n())
	}
	for i, c := range codes {
		if c != http.StatusOK {
			t.Fatalf("caller %d: status %d", i, c)
		}
	}
}

func TestRefreshWithoutABodyRefreshesEverything(t *testing.T) {
	rr := newRefreshRig(t, "one")
	s := rr.login()
	// A bare POST, the way curl or an older page would send it.
	req := httptest.NewRequest(http.MethodPost, "/api/usage/refresh", nil)
	req.AddCookie(s.cookie)
	req.Header.Set("X-CSRF-Token", s.csrf)
	w := httptest.NewRecorder()
	rr.h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"refreshed"`) {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
}

func TestRefreshRejectsAnOverlongAccountID(t *testing.T) {
	rr := newRefreshRig(t, "one")
	s := rr.login()
	w, _ := rr.post(s, s.csrf, `{"account":"`+strings.Repeat("x", maxLabel+1)+`"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	if rr.doer.n() != 0 {
		t.Fatal("an overlong id reached the usage endpoint")
	}
}

func TestRefreshedUsageShowsOnTheAccountsEndpoint(t *testing.T) {
	rr := newRefreshRig(t, "one")
	s := rr.login()
	rr.post(s, s.csrf, `{}`)
	w := rr.do(http.MethodGet, "/api/accounts", "", s, "")
	var accs []accountView
	if err := json.Unmarshal(w.Body.Bytes(), &accs); err != nil {
		t.Fatal(err)
	}
	if len(accs) != 1 || accs[0].SevenDay == nil || accs[0].SevenDay.LeftPct != 40 {
		t.Fatalf("accounts = %+v", accs)
	}
}
