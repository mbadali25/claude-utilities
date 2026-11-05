package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"claude-utilities/internal/hub"
	"claude-utilities/internal/logx"
	"claude-utilities/internal/vault"
)

const (
	webURL  = "https://claude.com/cai/oauth/authorize?state=WEB-PLANTED-STATE"
	webCode = "WEB-PLANTED-CODE-0123"
)

type addCalls struct {
	adds   [][2]string
	codes  [][2]string
	cancel []string
}

func addRig(t *testing.T) (*rig, *addCalls) {
	t.Helper()
	r := newRig(t)
	c := &addCalls{}
	r.fh.addFn = func(host, label string) (string, error) {
		c.adds = append(c.adds, [2]string{host, label})
		return "0123456789abcdef", nil
	}
	r.fh.statusFn = func(id string) (hub.AddView, error) {
		return hub.AddView{ID: id, State: hub.AddAwaitingCode, URL: webURL}, nil
	}
	r.fh.codeFn = func(id, code string) error {
		c.codes = append(c.codes, [2]string{id, code})
		return nil
	}
	r.fh.cancelFn = func(id string) error { c.cancel = append(c.cancel, id); return nil }
	return r, c
}

var addPaths = []struct{ method, path, body string }{
	{"POST", "/api/accounts/add", `{"host":"h1","label":"x"}`},
	{"GET", "/api/accounts/add/0123456789abcdef", ""},
	{"POST", "/api/accounts/add/0123456789abcdef/code", `{"code":"c"}`},
	{"POST", "/api/accounts/add/0123456789abcdef/cancel", ""},
}

func TestAddAccountRequiresSession(t *testing.T) {
	r, c := addRig(t)
	for _, p := range addPaths {
		if w := r.do(p.method, p.path, p.body, nil, ""); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: status %d", p.method, p.path, w.Code)
		}
	}
	// A wrong-method probe learns nothing either.
	if w := r.do("DELETE", "/api/accounts/add", "", nil, ""); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong method: status %d", w.Code)
	}
	if len(c.adds)+len(c.codes)+len(c.cancel) != 0 {
		t.Fatal("hub was called without a session")
	}
}

func TestAddAccountPostsRequireCSRF(t *testing.T) {
	r, c := addRig(t)
	s := r.login()
	for _, p := range addPaths {
		if p.method != "POST" {
			continue
		}
		if w := r.do(p.method, p.path, p.body, s, ""); w.Code != http.StatusForbidden {
			t.Errorf("%s no csrf: status %d", p.path, w.Code)
		}
		if w := r.do(p.method, p.path, p.body, s, "wrong"); w.Code != http.StatusForbidden {
			t.Errorf("%s bad csrf: status %d", p.path, w.Code)
		}
	}
	if len(c.adds)+len(c.codes)+len(c.cancel) != 0 {
		t.Fatal("hub was called without a valid CSRF token")
	}
	// The status read needs only the session.
	if w := r.do("GET", addPaths[1].path, "", s, ""); w.Code != http.StatusOK {
		t.Errorf("status GET: %d", w.Code)
	}
}

func TestAddAccountStartsJob(t *testing.T) {
	r, c := addRig(t)
	s := r.login()
	w := r.do("POST", "/api/accounts/add", `{"host":"h1","label":"  Work  "}`, s, s.csrf)
	if w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), `"id":"0123456789abcdef"`) {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
	if len(c.adds) != 1 || c.adds[0] != [2]string{"h1", "Work"} {
		t.Fatalf("hub calls %v", c.adds)
	}
}

func TestAddAccountValidatesLabel(t *testing.T) {
	r, c := addRig(t)
	r.seed("a1", "Taken")
	s := r.login()
	for _, body := range []string{
		`{"host":"h1","label":""}`, `{"host":"h1","label":"   "}`, `{"host":"","label":"x"}`,
		`{"host":"h1","label":"` + strings.Repeat("x", 65) + `"}`,
	} {
		if w := r.do("POST", "/api/accounts/add", body, s, s.csrf); w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d", body, w.Code)
		}
	}
	if w := r.do("POST", "/api/accounts/add", `{"host":"h1","label":"taken"}`, s, s.csrf); w.Code != http.StatusConflict {
		t.Errorf("duplicate label: status %d", w.Code)
	}
	if len(c.adds) != 0 {
		t.Fatalf("hub called for invalid input: %v", c.adds)
	}
}

func TestAddUnknownFieldsRefused(t *testing.T) {
	r, c := addRig(t)
	s := r.login()
	if w := r.do("POST", "/api/accounts/add", `{"host":"h1","label":"x","extra":1}`, s, s.csrf); w.Code != http.StatusBadRequest {
		t.Errorf("add: status %d", w.Code)
	}
	if w := r.do("POST", addPaths[2].path, `{"code":"c","extra":1}`, s, s.csrf); w.Code != http.StatusBadRequest {
		t.Errorf("code: status %d", w.Code)
	}
	if len(c.adds)+len(c.codes) != 0 {
		t.Fatal("hub called")
	}
}

func TestAddAccountMapsHubErrors(t *testing.T) {
	r, _ := addRig(t)
	s := r.login()
	cases := []struct {
		err  error
		want int
	}{
		{hub.ErrUnknownHost, http.StatusNotFound},
		{hub.ErrAgentOffline, http.StatusConflict},
		{hub.ErrAddBusy, http.StatusConflict},
		{vault.ErrLabelTaken, http.StatusConflict},
	}
	for _, c := range cases {
		r.fh.addFn = func(string, string) (string, error) { return "", c.err }
		if w := r.do("POST", "/api/accounts/add", `{"host":"h1","label":"x"}`, s, s.csrf); w.Code != c.want {
			t.Errorf("%v: status %d, want %d", c.err, w.Code, c.want)
		}
	}
	r.fh.statusFn = func(string) (hub.AddView, error) { return hub.AddView{}, hub.ErrNoAdd }
	if w := r.do("GET", addPaths[1].path, "", s, ""); w.Code != http.StatusNotFound {
		t.Errorf("status unknown id: %d", w.Code)
	}
	r.fh.codeFn = func(string, string) error { return hub.ErrNoAdd }
	if w := r.do("POST", addPaths[2].path, `{"code":"c"}`, s, s.csrf); w.Code != http.StatusNotFound {
		t.Errorf("code unknown id: %d", w.Code)
	}
	r.fh.codeFn = func(string, string) error { return hub.ErrNotAwaitingCode }
	if w := r.do("POST", addPaths[2].path, `{"code":"c"}`, s, s.csrf); w.Code != http.StatusConflict {
		t.Errorf("code wrong state: %d", w.Code)
	}
	r.fh.cancelFn = func(string) error { return hub.ErrNoAdd }
	if w := r.do("POST", addPaths[3].path, "", s, s.csrf); w.Code != http.StatusNotFound {
		t.Errorf("cancel unknown id: %d", w.Code)
	}
}

func TestAddStatusJSON(t *testing.T) {
	r, _ := addRig(t)
	s := r.login()
	w := r.do("GET", addPaths[1].path, "", s, "")
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["state"] != "awaiting_code" || got["url"] != webURL {
		t.Fatalf("body %s", w.Body)
	}
	if got["account"] != nil || got["error"] != nil {
		t.Fatalf("unexpected fields in %s", w.Body)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("status response is cacheable")
	}
	r.fh.statusFn = func(id string) (hub.AddView, error) {
		return hub.AddView{ID: id, State: hub.AddFailed, Error: "timed out"}, nil
	}
	w = r.do("GET", addPaths[1].path, "", s, "")
	if strings.Contains(w.Body.String(), `"url"`) || !strings.Contains(w.Body.String(), `"error":"timed out"`) {
		t.Fatalf("body %s", w.Body)
	}
}

func TestAddStatusNeverReturnsBlock(t *testing.T) {
	r, _ := addRig(t)
	s := r.login()
	r.fh.statusFn = func(id string) (hub.AddView, error) {
		// Even if the hub leaked a block, the web layer has no field to carry it.
		a := vault.Account{ID: "n1", Label: "new", Identity: "uuid-n1", Block: json.RawMessage(`{"accessToken":"` + blockSecret + `"}`)}
		return hub.AddView{ID: id, State: hub.AddDone, Account: &a}, nil
	}
	w := r.do("GET", addPaths[1].path, "", s, "")
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), blockSecret) || !strings.Contains(w.Body.String(), `"label":"new"`) {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
}

func TestAddCodeRejectsEmptyAndOversize(t *testing.T) {
	r, c := addRig(t)
	s := r.login()
	for _, code := range []string{"", "   ", strings.Repeat("a", 2049)} {
		b, _ := json.Marshal(map[string]string{"code": code})
		if w := r.do("POST", addPaths[2].path, string(b), s, s.csrf); w.Code != http.StatusBadRequest {
			t.Errorf("code len %d: status %d", len(code), w.Code)
		}
	}
	if len(c.codes) != 0 {
		t.Fatalf("hub called: %v", c.codes)
	}
	if w := r.do("POST", addPaths[2].path, `{"code":"`+strings.Repeat("a", 2048)+`"}`, s, s.csrf); w.Code != http.StatusOK {
		t.Errorf("max-size code: status %d", w.Code)
	}
	if len(c.codes) != 1 || c.codes[0][0] != "0123456789abcdef" {
		t.Fatalf("hub calls %v", c.codes)
	}
}

func TestAddCodeNotLogged(t *testing.T) {
	r, _ := addRig(t)
	var buf bytes.Buffer
	prev := logger
	logger = logx.New(&buf)
	defer func() { logger = prev }()
	r.fh.codeFn = func(string, string) error { return hub.ErrNotAwaitingCode }
	s := r.login()
	r.do("POST", addPaths[2].path, `{"code":"`+webCode+`"}`, s, s.csrf)
	r.fh.codeFn = func(string, string) error { return errTest }
	r.do("POST", addPaths[2].path, `{"code":"`+webCode+`"}`, s, s.csrf)
	if strings.Contains(buf.String(), webCode) {
		t.Fatalf("code in log: %s", buf.String())
	}
}

func TestAddCancelCallsHub(t *testing.T) {
	r, c := addRig(t)
	s := r.login()
	if w := r.do("POST", addPaths[3].path, "", s, s.csrf); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
	if len(c.cancel) != 1 || c.cancel[0] != "0123456789abcdef" {
		t.Fatalf("cancel calls %v", c.cancel)
	}
}

var (
	idShape = regexp.MustCompile(`^[0-9a-f]{16}$`)
	errTest = errors.New("boom")
)

func TestAddRejectsMalformedID(t *testing.T) {
	r, c := addRig(t)
	s := r.login()
	for _, id := range []string{"short", strings.Repeat("g", 16), strings.Repeat("a", 17)} {
		if w := r.do("GET", "/api/accounts/add/"+id, "", s, ""); w.Code != http.StatusNotFound {
			t.Errorf("GET %q: status %d", id, w.Code)
		}
		if w := r.do("POST", "/api/accounts/add/"+id+"/code", `{"code":"c"}`, s, s.csrf); w.Code != http.StatusNotFound {
			t.Errorf("code %q: status %d", id, w.Code)
		}
	}
	if len(c.codes) != 0 || !idShape.MatchString("0123456789abcdef") {
		t.Fatal("hub called for a malformed id")
	}
}

func TestUIHasAddAccountPanel(t *testing.T) {
	r, _ := addRig(t)
	s := r.login()
	p := page(r, s)
	for _, want := range []string{"add-form", "/api/accounts/add", "'/code'", "'/cancel'", "Open Anthropic sign-in", "Anthropic&#39;s own page"} {
		if !strings.Contains(p, want) && !strings.Contains(p, strings.ReplaceAll(want, "&#39;", "'")) {
			t.Errorf("index.html lacks %q", want)
		}
	}
	// Every request goes through call(), which sets X-CSRF-Token; a second fetch would bypass it.
	if n := strings.Count(p, "fetch("); n != 1 || !strings.Contains(p, "'X-CSRF-Token': csrf") {
		t.Errorf("index.html has %d fetch calls or lacks the CSRF header", n)
	}
	// Neither the URL nor the code may reach storage, the title or the query string.
	for _, bad := range []string{"localStorage", "sessionStorage", "document.title", "location.search"} {
		if strings.Contains(p, bad) {
			t.Errorf("index.html uses %s", bad)
		}
	}
}
