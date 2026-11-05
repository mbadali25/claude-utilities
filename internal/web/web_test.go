package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"claude-utilities/internal/adminpw"
	"claude-utilities/internal/hub"
	"claude-utilities/internal/logx"
	"claude-utilities/internal/proto"
	"claude-utilities/internal/usage"
	"claude-utilities/internal/vault"
)

const (
	adminPW     = "correct horse battery staple"
	blockSecret = "SECRET-BLOCK-VALUE-9f3a"
)

var fixedNow = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

type fakeHub struct {
	mu         sync.Mutex
	hosts      []hub.HostView
	pending    []hub.PendingView
	swapCalls  [][2]string
	swapErr    error
	allowCalls []string
	allowErr   error
	denyCalls  []string
	denyErr    error
	revoked    []string
	importFn   func(host, label string) (vault.Account, error)
	relabelFn  func(id, label string) error

	addFn    func(host, label string) (string, error)
	statusFn func(id string) (hub.AddView, error)
	codeFn   func(id, code string) error
	cancelFn func(id string) error
}

func (f *fakeHub) AddAccount(_ context.Context, host, label string) (string, error) {
	return f.addFn(host, label)
}
func (f *fakeHub) AddStatus(id string) (hub.AddView, error) { return f.statusFn(id) }
func (f *fakeHub) AddCode(id, code string) error            { return f.codeFn(id, code) }
func (f *fakeHub) AddCancel(id string) error                { return f.cancelFn(id) }

func (f *fakeHub) Hosts() []hub.HostView { f.mu.Lock(); defer f.mu.Unlock(); return f.hosts }
func (f *fakeHub) Pending() []hub.PendingView {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]hub.PendingView(nil), f.pending...)
}
func (f *fakeHub) Swap(_ context.Context, host, acct string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.swapCalls = append(f.swapCalls, [2]string{host, acct})
	return f.swapErr
}
func (f *fakeHub) NewEnrolCode() (string, time.Time) {
	return "abcd2345", fixedNow.Add(10 * time.Minute)
}
func (f *fakeHub) Revoke(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, id)
	return nil
}
func (f *fakeHub) Import(_ context.Context, host, label string) (vault.Account, error) {
	return f.importFn(host, label)
}
func (f *fakeHub) Relabel(id, label string) error { return f.relabelFn(id, label) }
func (f *fakeHub) Allow(fp string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allowCalls = append(f.allowCalls, fp)
	if f.allowErr != nil {
		return "", f.allowErr
	}
	f.drop(fp)
	return "host-1", nil
}
func (f *fakeHub) Deny(fp string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.denyCalls = append(f.denyCalls, fp)
	if f.denyErr != nil {
		return f.denyErr
	}
	f.drop(fp)
	return nil
}
func (f *fakeHub) drop(fp string) {
	var keep []hub.PendingView
	for _, p := range f.pending {
		if p.Fingerprint != fp {
			keep = append(keep, p)
		}
	}
	f.pending = keep
}
func (f *fakeHub) allowN() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.allowCalls) }
func (f *fakeHub) denyN() int  { f.mu.Lock(); defer f.mu.Unlock(); return len(f.denyCalls) }

type fakeUsage map[string]usage.Usage

func (u fakeUsage) Last(id string) (usage.Usage, bool) { x, ok := u[id]; return x, ok }

// fakePW stands in for *adminpw.Store so the web tests do not pay for an argon2id derivation on
// every login. adminpw's own tests cover hashing, persistence and the env bootstrap.
type fakePW struct {
	mu   sync.Mutex
	pw   string
	sets []string
	err  error
}

func (f *fakePW) Verify(password string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return password != "" && password == f.pw
}

func (f *fakePW) Set(password string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	if len([]rune(password)) < adminpw.MinLength {
		return adminpw.ErrTooShort
	}
	f.sets = append(f.sets, password)
	f.pw = password
	return nil
}

func (f *fakePW) setN() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.sets) }

type rig struct {
	t     *testing.T
	h     http.Handler
	fh    *fakeHub
	v     *vault.Vault
	usage fakeUsage
	pw    *fakePW
	now   time.Time
}

func newRig(t *testing.T) *rig {
	t.Helper()
	t.Setenv("WEB_TEST_KEY", "test-passphrase")
	v, err := vault.Open(filepath.Join(t.TempDir(), "vault.bin"), "WEB_TEST_KEY")
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, fh: &fakeHub{}, v: v, usage: fakeUsage{}, pw: &fakePW{pw: adminPW}, now: fixedNow}
	r.fh.relabelFn = func(id, label string) error { // mirrors hub.Relabel over the real vault
		err := v.Relabel(id, label)
		if errors.Is(err, vault.ErrNotFound) {
			return hub.ErrUnknownAccount
		}
		return err
	}
	r.h = newHandler(r.fh, v, r.usage, r.pw, func() time.Time { return r.now })
	return r
}

func (r *rig) seed(id, label string) {
	r.t.Helper()
	err := r.v.Put(vault.Account{ID: id, Label: label, Identity: "uuid-" + id, Updated: fixedNow,
		Block: json.RawMessage(`{"accessToken":"` + blockSecret + `"}`)})
	if err != nil {
		r.t.Fatal(err)
	}
}

type session struct {
	cookie *http.Cookie
	csrf   string
}

var csrfRe = regexp.MustCompile(`<meta name="csrf-token" content="([^"]+)"`)

func (r *rig) do(method, path, body string, s *session, csrf string) *httptest.ResponseRecorder {
	r.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if s != nil {
		req.AddCookie(s.cookie)
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	r.h.ServeHTTP(w, req)
	return w
}

func (r *rig) loginRaw(pw string) *httptest.ResponseRecorder {
	r.t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(url.Values{"password": {pw}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.h.ServeHTTP(w, req)
	return w
}

func (r *rig) login() *session {
	r.t.Helper()
	w := r.loginRaw(adminPW)
	if w.Code != http.StatusSeeOther {
		r.t.Fatalf("login status %d", w.Code)
	}
	var c *http.Cookie
	for _, ck := range w.Result().Cookies() {
		if ck.Name == cookieName {
			c = ck
		}
	}
	if c == nil {
		r.t.Fatal("no session cookie")
	}
	s := &session{cookie: c}
	page := r.do(http.MethodGet, "/", "", s, "").Body.String()
	m := csrfRe.FindStringSubmatch(page)
	if m == nil {
		r.t.Fatalf("no csrf token in page")
	}
	s.csrf = m[1]
	return s
}

func page(r *rig, s *session) string {
	r.t.Helper()
	w := r.do(http.MethodGet, "/", "", s, "")
	b, _ := io.ReadAll(w.Body)
	return string(b)
}

func TestLoginCookieFlagsAndWrongPassword(t *testing.T) {
	r := newRig(t)
	w := r.loginRaw("wrong")
	if w.Code != http.StatusUnauthorized || len(w.Result().Cookies()) != 0 {
		t.Fatalf("wrong password: %d cookies %v", w.Code, w.Result().Cookies())
	}
	w = r.loginRaw(adminPW)
	cs := w.Result().Cookies()
	if len(cs) != 1 || !cs[0].HttpOnly || !cs[0].Secure || cs[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie flags: %+v", cs)
	}
}

func TestLoginLocksOutAfterRepeatedFailures(t *testing.T) {
	r := newRig(t)
	for i := 0; i < maxLoginFailures; i++ {
		r.loginRaw("wrong")
	}
	if w := r.loginRaw(adminPW); w.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429 even for the right password", w.Code)
	}
}

func TestPageShowsLoginFormWithoutSession(t *testing.T) {
	r := newRig(t)
	body := page(r, nil)
	if !strings.Contains(body, `name="password"`) || strings.Contains(body, "csrf-token") {
		t.Fatalf("login page wrong: %s", body)
	}
}

func TestAccountsNeverIncludeTokens(t *testing.T) {
	r := newRig(t)
	r.seed("a1", "personal")
	s := r.login()
	w := r.do(http.MethodGet, "/api/accounts", "", s, "")
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "personal") {
		t.Fatalf("status %d body %s", w.Code, body)
	}
	for _, bad := range []string{blockSecret, "accessToken", `"block"`} {
		if strings.Contains(body, bad) {
			t.Fatalf("body leaks %q: %s", bad, body)
		}
	}
}

func TestUnauthenticatedRequestRejected(t *testing.T) {
	r := newRig(t)
	for _, rt := range [][2]string{
		{"GET", "/api/accounts"}, {"GET", "/api/hosts"}, {"GET", "/api/pending"},
		{"POST", "/api/swap"}, {"POST", "/api/enrol-code"}, {"POST", "/api/hosts/h1/revoke"},
		{"POST", "/api/import"}, {"POST", "/api/pending/ab/allow"}, {"POST", "/api/pending/ab/deny"},
	} {
		w := r.do(rt[0], rt[1], "{}", nil, "")
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s = %d, want 401", rt[0], rt[1], w.Code)
		}
	}
}

func TestForgedCookieRejected(t *testing.T) {
	r := newRig(t)
	w := r.do("GET", "/api/accounts", "", &session{cookie: &http.Cookie{Name: cookieName, Value: "forged"}}, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
}

func TestSwapEndpointCallsHub(t *testing.T) {
	r := newRig(t)
	s := r.login()
	w := r.do("POST", "/api/swap", `{"host":"h1","account":"a1"}`, s, s.csrf)
	if w.Code != 200 {
		t.Fatalf("status %d %s", w.Code, w.Body)
	}
	if len(r.fh.swapCalls) != 1 || r.fh.swapCalls[0] != [2]string{"h1", "a1"} {
		t.Fatalf("calls %v", r.fh.swapCalls)
	}
}

func TestSwapRequiresCSRF(t *testing.T) {
	r := newRig(t)
	s := r.login()
	for _, tok := range []string{"", "wrong"} {
		if w := r.do("POST", "/api/swap", `{"host":"h1","account":"a1"}`, s, tok); w.Code != http.StatusForbidden {
			t.Fatalf("csrf %q: status %d", tok, w.Code)
		}
	}
	if len(r.fh.swapCalls) != 0 {
		t.Fatal("swap ran without a valid CSRF token")
	}
}

func TestSwapErrorShowsReasonNotToken(t *testing.T) {
	r := newRig(t)
	s := r.login()
	r.fh.swapErr = fmt.Errorf("hub: agent refused swap: disk full Bearer sk-ant-oat01-LEAKME123")
	w := r.do("POST", "/api/swap", `{"host":"h1","account":"a1"}`, s, s.csrf)
	if w.Code < 400 || !strings.Contains(w.Body.String(), "disk full") || strings.Contains(w.Body.String(), "LEAKME123") {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
	r.fh.swapErr = hub.ErrUnknownLiveAccount
	w = r.do("POST", "/api/swap", `{"host":"h1","account":"a1"}`, s, s.csrf)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "import") {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
	r.fh.swapErr = hub.ErrUnknownHost
	if w = r.do("POST", "/api/swap", `{"host":"h1","account":"a1"}`, s, s.csrf); w.Code != http.StatusNotFound {
		t.Fatalf("status %d", w.Code)
	}
}

func TestSwapRejectsMalformedBody(t *testing.T) {
	r := newRig(t)
	s := r.login()
	for _, b := range []string{`{`, `{"host":"","account":"a"}`, `{"host":"h","account":"a","x":1}`} {
		if w := r.do("POST", "/api/swap", b, s, s.csrf); w.Code != http.StatusBadRequest {
			t.Errorf("body %q: status %d", b, w.Code)
		}
	}
}

func TestHostsShowNeedsReloadBadge(t *testing.T) {
	r := newRig(t)
	r.fh.hosts = []hub.HostView{{HostID: "h1", Name: "box", OS: "linux", Online: true, ActiveAccount: "a1",
		Sessions: []hub.SessionView{{Session: proto.Session{PID: 7, ID: "s1"}, NeedsReload: true}}}}
	s := r.login()
	var hosts []struct {
		HostID      string `json:"hostId"`
		NeedsReload bool   `json:"needsReload"`
		Sessions    []struct {
			NeedsReload bool `json:"needsReload"`
		} `json:"sessions"`
	}
	w := r.do("GET", "/api/hosts", "", s, "")
	if err := json.Unmarshal(w.Body.Bytes(), &hosts); err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || !hosts[0].NeedsReload || !hosts[0].Sessions[0].NeedsReload {
		t.Fatalf("hosts %s", w.Body)
	}
	if !strings.Contains(page(r, s), "Needs reload") {
		t.Fatal("page lacks the Needs reload badge label")
	}
}

func TestLoginFailureUsesStructuredAllowlistedLogger(t *testing.T) {
	var buf bytes.Buffer
	old := logger
	logger = logx.New(&buf)
	defer func() { logger = old }()
	r := newRig(t)
	r.loginFrom("203.0.113.9:1234", "nope-"+adminPW)
	out := buf.String()
	if !strings.Contains(out, `"msg":"login failed"`) || !strings.Contains(out, "203.0.113.9") || strings.Contains(out, "[dropped]") {
		t.Fatalf("log: %s", out)
	}
	if strings.Contains(out, adminPW) {
		t.Fatal("password logged")
	}
}

func TestHubErrorDoesNotEchoAgentSuppliedText(t *testing.T) {
	for name, err := range map[string]error{
		"plain": fmt.Errorf("%w: got %q for export_req", hub.ErrUnexpectedReply, "AGENT-CONTROLLED"),
		"swap":  fmt.Errorf("%w: %w", hub.ErrSwapOutcomeUnknown, fmt.Errorf("%w: got %q for swap_req", hub.ErrUnexpectedReply, "AGENT-CONTROLLED")),
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			hubError(w, err)
			if strings.Contains(w.Body.String(), "AGENT-CONTROLLED") {
				t.Fatalf("echoed: %s", w.Body)
			}
			if w.Code != http.StatusBadGateway {
				t.Fatalf("status %d", w.Code)
			}
		})
	}
}

func TestHostsShowSwapBlockedBadge(t *testing.T) {
	r := newRig(t)
	r.fh.hosts = []hub.HostView{{HostID: "h1", Name: "box", Online: true, SwapBlocked: true}, {HostID: "h2", Name: "ok", Online: true}}
	s := r.login()
	var hosts []struct {
		HostID      string `json:"hostId"`
		SwapBlocked bool   `json:"swapBlocked"`
	}
	w := r.do("GET", "/api/hosts", "", s, "")
	if err := json.Unmarshal(w.Body.Bytes(), &hosts); err != nil || len(hosts) != 2 {
		t.Fatalf("%v %s", err, w.Body)
	}
	if !hosts[0].SwapBlocked || hosts[1].SwapBlocked {
		t.Fatalf("hosts %s", w.Body)
	}
	if !strings.Contains(page(r, s), "Swaps blocked") {
		t.Fatal("page lacks the Swaps blocked badge label")
	}
}

func TestUsageShowsLastKnownWithAgeOnError(t *testing.T) {
	r := newRig(t)
	r.seed("a1", "personal")
	r.usage["a1"] = usage.Usage{
		SevenDay:  usage.Window{UsedPct: 95, ResetsAt: fixedNow.Add(48 * time.Hour)},
		FetchedAt: fixedNow.Add(-10 * time.Minute),
		Err:       "rate limited",
	}
	s := r.login()
	var accts []struct {
		SevenDay *struct {
			LeftPct  float64   `json:"leftPct"`
			ResetsAt time.Time `json:"resetsAt"`
		} `json:"sevenDay"`
		FiveHour   *struct{} `json:"fiveHour"`
		AgeSeconds *int64    `json:"ageSeconds"`
		Error      string    `json:"error"`
	}
	w := r.do("GET", "/api/accounts", "", s, "")
	if err := json.Unmarshal(w.Body.Bytes(), &accts); err != nil || len(accts) != 1 {
		t.Fatalf("%v %s", err, w.Body)
	}
	a := accts[0]
	if a.SevenDay == nil || a.SevenDay.LeftPct != 5 || a.FiveHour != nil {
		t.Fatalf("windows: %s", w.Body)
	}
	if a.AgeSeconds == nil || *a.AgeSeconds != 600 || a.Error != "rate limited" {
		t.Fatalf("age/error: %s", w.Body)
	}
}

func TestAccountOwnerIsHostNameOrServer(t *testing.T) {
	r := newRig(t)
	r.seed("a1", "one")
	r.seed("a2", "two")
	r.fh.hosts = []hub.HostView{{HostID: "h1", Name: "box", ActiveAccount: "a1"}}
	s := r.login()
	var accts []struct{ ID, Owner string }
	w := r.do("GET", "/api/accounts", "", s, "")
	if err := json.Unmarshal(w.Body.Bytes(), &accts); err != nil {
		t.Fatal(err)
	}
	if accts[0].Owner != "box" || accts[1].Owner != "server" {
		t.Fatalf("owners %+v", accts)
	}
}

func TestImportCreatesAccountFromHost(t *testing.T) {
	r := newRig(t)
	r.fh.importFn = func(host, label string) (vault.Account, error) {
		a := vault.Account{ID: "new1", Label: label, Identity: "uuid-new", Updated: fixedNow,
			Block: json.RawMessage(`{"accessToken":"` + blockSecret + `"}`)}
		if host != "h1" {
			return vault.Account{}, hub.ErrUnknownHost
		}
		return a, r.v.Put(a)
	}
	s := r.login()
	w := r.do("POST", "/api/import", `{"host":"h1","label":"work"}`, s, s.csrf)
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), "work") || strings.Contains(w.Body.String(), blockSecret) {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
	if got := r.do("GET", "/api/accounts", "", s, "").Body.String(); !strings.Contains(got, "work") {
		t.Fatalf("accounts %s", got)
	}
	if w = r.do("POST", "/api/import", `{"host":"zz","label":"x"}`, s, s.csrf); w.Code != http.StatusNotFound {
		t.Fatalf("unknown host status %d", w.Code)
	}
	r.fh.importFn = func(string, string) (vault.Account, error) { return vault.Account{}, hub.ErrAlreadyStored }
	if w = r.do("POST", "/api/import", `{"host":"h1","label":"x"}`, s, s.csrf); w.Code != http.StatusConflict {
		t.Fatalf("duplicate status %d", w.Code)
	}
}

func TestEnrolCodeAndRevoke(t *testing.T) {
	r := newRig(t)
	s := r.login()
	w := r.do("POST", "/api/enrol-code", "", s, s.csrf)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "abcd2345") {
		t.Fatalf("enrol-code %d %s", w.Code, w.Body)
	}
	if w = r.do("POST", "/api/hosts/h9/revoke", "", s, s.csrf); w.Code != 200 || len(r.fh.revoked) != 1 || r.fh.revoked[0] != "h9" {
		t.Fatalf("revoke %d %v", w.Code, r.fh.revoked)
	}
}

func TestMcpOAuthNoticeShownInUI(t *testing.T) {
	r := newRig(t)
	s := r.login()
	p := page(r, s)
	for _, want := range []string{"MCP logins may belong to another account", "Add account: import from a logged-in host"} {
		if !strings.Contains(p, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(p, "/api/login/") {
		t.Error("web OAuth login routes must not be offered (spike S1 deferred)")
	}
}

// --- pending connections ---

func pendingView(fp string) hub.PendingView {
	return hub.PendingView{Fingerprint: fp, HostName: "laptop-7", OS: "windows", SourceIP: "192.168.1.50",
		Since: fixedNow.Add(-time.Minute), ExpiresAt: fixedNow.Add(4 * time.Minute)}
}

func TestPendingListRequiresAdminSession(t *testing.T) {
	r := newRig(t)
	r.fh.pending = []hub.PendingView{pendingView("ABCD-EFGH")}
	w := r.do("GET", "/api/pending", "", nil, "")
	if w.Code != http.StatusUnauthorized || w.Body.Len() != 0 {
		t.Fatalf("status %d body %q", w.Code, w.Body)
	}
}

func TestAllowWithoutAdminSessionIs401(t *testing.T) {
	r := newRig(t)
	r.fh.pending = []hub.PendingView{pendingView("ABCD-EFGH")}
	w := r.do("POST", "/api/pending/ABCD-EFGH/allow", "", nil, "whatever")
	if w.Code != http.StatusUnauthorized || r.fh.allowN() != 0 {
		t.Fatalf("status %d allow calls %d", w.Code, r.fh.allowN())
	}
}

func TestAllowWithWrongCSRFIs403(t *testing.T) {
	r := newRig(t)
	r.fh.pending = []hub.PendingView{pendingView("ABCD-EFGH")}
	s := r.login()
	for _, tok := range []string{"", "wrong"} {
		if w := r.do("POST", "/api/pending/ABCD-EFGH/allow", "", s, tok); w.Code != http.StatusForbidden {
			t.Fatalf("csrf %q: status %d", tok, w.Code)
		}
	}
	if r.fh.allowN() != 0 {
		t.Fatal("Allow called without a valid CSRF token")
	}
}

func TestDenyWithWrongCSRFIs403(t *testing.T) {
	r := newRig(t)
	r.fh.pending = []hub.PendingView{pendingView("ABCD-EFGH")}
	s := r.login()
	if w := r.do("POST", "/api/pending/ABCD-EFGH/deny", "", s, "wrong"); w.Code != http.StatusForbidden || r.fh.denyN() != 0 {
		t.Fatalf("status %d deny calls %d", w.Code, r.fh.denyN())
	}
}

func TestAllowCallsHubAndResponseNeverContainsToken(t *testing.T) {
	r := newRig(t)
	r.fh.pending = []hub.PendingView{pendingView("ABCD-EFGH")}
	s := r.login()
	w := r.do("POST", "/api/pending/ABCD-EFGH/allow", "", s, s.csrf)
	if w.Code != 200 {
		t.Fatalf("status %d %s", w.Code, w.Body)
	}
	var got map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || len(got) != 1 || got["hostId"] != "host-1" {
		t.Fatalf("body %s", w.Body)
	}
	if strings.Contains(strings.ToLower(w.Body.String()), "token") {
		t.Fatal("body mentions a token")
	}
	if r.fh.allowN() != 1 || r.fh.allowCalls[0] != "ABCD-EFGH" {
		t.Fatalf("calls %v", r.fh.allowCalls)
	}
}

func TestAllowExpiredEntryIs410WithReason(t *testing.T) {
	r := newRig(t)
	r.fh.allowErr = hub.ErrPendingExpired
	s := r.login()
	w := r.do("POST", "/api/pending/ABCD-EFGH/allow", "", s, s.csrf)
	if w.Code != http.StatusGone || !strings.Contains(w.Body.String(), "expired") {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
}

func TestAllowUnknownFingerprintIs404(t *testing.T) {
	r := newRig(t)
	r.fh.allowErr = hub.ErrNotPending
	s := r.login()
	if w := r.do("POST", "/api/pending/NOPE/allow", "", s, s.csrf); w.Code != http.StatusNotFound {
		t.Fatalf("status %d", w.Code)
	}
	r.fh.denyErr = hub.ErrNotPending
	if w := r.do("POST", "/api/pending/NOPE/deny", "", s, s.csrf); w.Code != http.StatusNotFound {
		t.Fatalf("deny status %d", w.Code)
	}
}

func TestAllowOtherFailureIs500WithoutDetailLeak(t *testing.T) {
	r := newRig(t)
	r.fh.allowErr = errors.New("hub: persist failed: password=hunter2")
	s := r.login()
	w := r.do("POST", "/api/pending/ABCD-EFGH/allow", "", s, s.csrf)
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "hunter2") {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
}

func TestDenyThenListNoLongerShowsEntry(t *testing.T) {
	r := newRig(t)
	r.fh.pending = []hub.PendingView{pendingView("ABCD-EFGH")}
	s := r.login()
	if got := r.do("GET", "/api/pending", "", s, "").Body.String(); !strings.Contains(got, "ABCD-EFGH") {
		t.Fatalf("list before deny: %s", got)
	}
	if w := r.do("POST", "/api/pending/ABCD-EFGH/deny", "", s, s.csrf); w.Code != 200 {
		t.Fatalf("deny status %d", w.Code)
	}
	if got := r.do("GET", "/api/pending", "", s, "").Body.String(); strings.Contains(got, "ABCD-EFGH") {
		t.Fatalf("list after deny: %s", got)
	}
}

func TestPendingPanelShowsFingerprintHostOSIPAndMatchInstruction(t *testing.T) {
	r := newRig(t)
	r.fh.pending = []hub.PendingView{pendingView("ABCD-EFGH")}
	s := r.login()
	p := page(r, s)
	for _, want := range []string{"Pending connections", "ABCD-EFGH", "laptop-7", "windows", "192.168.1.50",
		"Match this code with the one the agent printed before you click Allow", "Allow", "Deny"} {
		if !strings.Contains(p, want) {
			t.Errorf("page lacks %q", want)
		}
	}
}

func TestPendingPanelEscapesAgentSuppliedText(t *testing.T) {
	r := newRig(t)
	pv := pendingView("ABCD-EFGH")
	pv.HostName = `<script>alert(1)</script>`
	r.fh.pending = []hub.PendingView{pv}
	s := r.login()
	if p := page(r, s); strings.Contains(p, "<script>alert(1)") {
		t.Fatal("host name rendered unescaped")
	}
}

func TestPendingPanelRenderedEmptyWhenQueueEmpty(t *testing.T) {
	r := newRig(t)
	s := r.login()
	p := page(r, s)
	if !strings.Contains(p, "Pending connections") || !strings.Contains(p, "No pending connections") {
		t.Fatal("empty panel missing")
	}
	// The script also holds the sentence (for client-side refresh), so look at the rendered panel only.
	start := strings.Index(p, `id="pending-panel"`)
	end := strings.Index(p[start:], "</section>")
	if start < 0 || end < 0 {
		t.Fatal("panel markup not found")
	}
	if strings.Contains(p[start:start+end], "Match this code") {
		t.Fatal("instruction shown with no entries")
	}
}

func TestCSRFTokenRotatesPerSession(t *testing.T) {
	r := newRig(t)
	a, b := r.login(), r.login()
	if a.csrf == b.csrf || a.cookie.Value == b.cookie.Value {
		t.Fatal("two sessions share a token")
	}
	// session A's CSRF token is not valid in session B.
	if w := r.do("POST", "/api/swap", `{"host":"h","account":"a"}`, b, a.csrf); w.Code != http.StatusForbidden {
		t.Fatalf("cross-session csrf accepted: %d", w.Code)
	}
}

func (r *rig) loginFrom(addr, pw string) *httptest.ResponseRecorder {
	r.t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(url.Values{"password": {pw}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = addr
	w := httptest.NewRecorder()
	r.h.ServeHTTP(w, req)
	return w
}

func TestLoginLockoutIsPerSourceIP(t *testing.T) {
	r := newRig(t)
	for i := 0; i < maxLoginFailures; i++ {
		r.loginFrom("10.0.0.9:1111", "wrong")
	}
	if w := r.loginFrom("10.0.0.9:2222", adminPW); w.Code != http.StatusTooManyRequests {
		t.Fatalf("attacker status %d, want 429", w.Code)
	}
	if w := r.loginFrom("10.0.0.5:3333", adminPW); w.Code != http.StatusSeeOther {
		t.Fatalf("admin on another IP status %d, want 303", w.Code)
	}
	r.now = r.now.Add(loginWindow + time.Second)
	if w := r.loginFrom("10.0.0.9:4444", adminPW); w.Code != http.StatusSeeOther {
		t.Fatalf("after the window status %d, want 303", w.Code)
	}
}

func TestHandlerRejectsMissingPasswordStore(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Handler accepted a nil password store")
		}
	}()
	Handler(nil, nil, nil, nil)
}

func TestWrongMethodOnAPIWithoutSessionIs401(t *testing.T) {
	r := newRig(t)
	for _, rt := range [][2]string{{"GET", "/api/swap"}, {"POST", "/api/accounts"}, {"GET", "/api/nope"}} {
		if w := r.do(rt[0], rt[1], "", nil, ""); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s = %d, want 401", rt[0], rt[1], w.Code)
		}
	}
}

func TestSessionExpires(t *testing.T) {
	r := newRig(t)
	s := r.login()
	if w := r.do("GET", "/api/accounts", "", s, ""); w.Code != 200 {
		t.Fatalf("fresh session %d", w.Code)
	}
	r.now = r.now.Add(sessionTTL)
	if w := r.do("GET", "/api/accounts", "", s, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("expired session %d, want 401", w.Code)
	}
}

func TestSessionCapEvictsSoonestToExpire(t *testing.T) {
	r := newRig(t)
	first := r.login()
	for i := 0; i < maxSessions; i++ {
		r.now = r.now.Add(time.Second)
		r.loginFrom("10.1.0.1:1", adminPW)
	}
	if w := r.do("GET", "/api/accounts", "", first, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("evicted cookie replay %d, want 401", w.Code)
	}
}

func TestImportLabelValidation(t *testing.T) {
	r := newRig(t)
	called := false
	r.fh.importFn = func(host, label string) (vault.Account, error) {
		called = true
		return vault.Account{ID: "n", Label: label, Identity: "uuid-n", Block: json.RawMessage(`{"accessToken":"` + blockSecret + `"}`)}, nil
	}
	r.seed("a1", "Personal")
	s := r.login()
	for name, body := range map[string]string{
		"whitespace": `{"host":"h1","label":"   "}`,
		"too long":   `{"host":"h1","label":"` + strings.Repeat("x", maxLabel+1) + `"}`,
		"empty":      `{"host":"h1","label":""}`,
	} {
		if w := r.do("POST", "/api/import", body, s, s.csrf); w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, w.Code)
		}
	}
	if w := r.do("POST", "/api/import", `{"host":"h1","label":" personal "}`, s, s.csrf); w.Code != http.StatusConflict {
		t.Errorf("duplicate label status %d, want 409", w.Code)
	}
	if called {
		t.Fatal("hub.Import ran for an invalid label")
	}
	w := r.do("POST", "/api/import", `{"host":"h1","label":"  work  "}`, s, s.csrf)
	if w.Code != http.StatusCreated || strings.Contains(w.Body.String(), blockSecret) || strings.Contains(w.Body.String(), "Block") {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
}

func TestRelabelRenamesAndResponseHasNoBlock(t *testing.T) {
	r := newRig(t)
	r.seed("bf326924b152796e", "Main (mbadali25)")
	s := r.login()
	w := r.do("POST", "/api/accounts/bf326924b152796e/label", `{"label":"  anewdevteam ✓  "}`, s, s.csrf)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), blockSecret) {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
	var v accountView
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil || v.Label != "anewdevteam ✓" || v.ID != "bf326924b152796e" {
		t.Fatalf("view %+v err %v", v, err)
	}
	list := r.do("GET", "/api/accounts", "", s, "").Body.String()
	if !strings.Contains(list, "anewdevteam ✓") || strings.Contains(list, "mbadali25") {
		t.Fatalf("list: %s", list)
	}
}

func TestRelabelErrors(t *testing.T) {
	r := newRig(t)
	r.seed("a1", "Personal")
	r.seed("a2", "Work")
	s := r.login()
	cases := map[string]struct {
		path, body string
		want       int
	}{
		"empty":      {"/api/accounts/a1/label", `{"label":""}`, 400},
		"whitespace": {"/api/accounts/a1/label", `{"label":"   "}`, 400},
		"too long":   {"/api/accounts/a1/label", `{"label":"` + strings.Repeat("x", maxLabel+1) + `"}`, 400},
		"unknown":    {"/api/accounts/a1/label", `{"label":"x","extra":1}`, 400},
		"duplicate":  {"/api/accounts/a1/label", `{"label":" WORK "}`, 409},
		"unknown id": {"/api/accounts/nope/label", `{"label":"fresh"}`, 404},
	}
	for name, c := range cases {
		w := r.do("POST", c.path, c.body, s, s.csrf)
		if w.Code != c.want || !strings.Contains(w.Body.String(), `"error"`) {
			t.Errorf("%s: status %d body %s, want %d with an error", name, w.Code, w.Body, c.want)
		}
	}
	if a, _ := r.v.Get("a1"); a.Label != "Personal" {
		t.Fatalf("label changed by rejected rename: %q", a.Label)
	}
}

func TestRelabelRequiresSessionAndCSRF(t *testing.T) {
	r := newRig(t)
	r.seed("a1", "Personal")
	s := r.login()
	body := `{"label":"New"}`
	if w := r.do("POST", "/api/accounts/a1/label", body, nil, ""); w.Code != http.StatusUnauthorized {
		t.Errorf("no session: %d", w.Code)
	}
	if w := r.do("POST", "/api/accounts/a1/label", body, s, ""); w.Code != http.StatusForbidden {
		t.Errorf("missing CSRF: %d", w.Code)
	}
	if w := r.do("POST", "/api/accounts/a1/label", body, s, "wrong"); w.Code != http.StatusForbidden {
		t.Errorf("wrong CSRF: %d", w.Code)
	}
	if a, _ := r.v.Get("a1"); a.Label != "Personal" {
		t.Fatalf("label changed without auth: %q", a.Label)
	}
}

func TestConcurrentRelabelToSameLabelHasOneWinner(t *testing.T) {
	r := newRig(t)
	const n = 6
	for i := 0; i < n; i++ {
		r.seed(fmt.Sprintf("a%d", i), fmt.Sprintf("old%d", i))
	}
	s := r.login()
	codes := make(chan int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes <- r.do("POST", fmt.Sprintf("/api/accounts/a%d/label", i), `{"label":"Same"}`, s, s.csrf).Code
		}(i)
	}
	wg.Wait()
	close(codes)
	ok, conflict := 0, 0
	for c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusConflict:
			conflict++
		default:
			t.Errorf("status %d", c)
		}
	}
	if ok != 1 || conflict != n-1 {
		t.Fatalf("ok %d conflict %d", ok, conflict)
	}
}

func TestUIHasRenameControl(t *testing.T) {
	r := newRig(t)
	s := r.login()
	p := page(r, s)
	if !strings.Contains(p, "/label'") || !strings.Contains(p, "'Rename'") {
		t.Fatal("index.html has no rename control")
	}
}

func TestUnknownHubErrorIsGenericBadGateway(t *testing.T) {
	r := newRig(t)
	r.fh.swapErr = errors.New("boom detail-that-stays-in-the-log")
	s := r.login()
	w := r.do("POST", "/api/swap", `{"host":"h","account":"a"}`, s, s.csrf)
	if w.Code != http.StatusBadGateway || strings.Contains(w.Body.String(), "detail-that-stays") {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
}

func TestSecurityHeaders(t *testing.T) {
	r := newRig(t)
	w := r.do("GET", "/", "", nil, "")
	h := w.Header()
	if !strings.Contains(h.Get("Content-Security-Policy"), "default-src 'none'") || h.Get("Cache-Control") != "no-store" ||
		h.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers %v", h)
	}
}
