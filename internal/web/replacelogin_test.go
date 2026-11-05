package web

import (
	"net/http"
	"strings"
	"testing"

	"claude-utilities/internal/hub"
)

type replaceCalls struct{ calls [][2]string }

func replaceRig(t *testing.T) (*rig, *replaceCalls, *addCalls) {
	t.Helper()
	r, ac := addRig(t)
	rc := &replaceCalls{}
	r.fh.replaceFn = func(host, account string) (string, error) {
		rc.calls = append(rc.calls, [2]string{host, account})
		return "0123456789abcdef", nil
	}
	r.seed("a1", "Work")
	return r, rc, ac
}

func TestReplaceRequiresSessionAndCSRF(t *testing.T) {
	r, rc, _ := replaceRig(t)
	body := `{"host":"h1","account":"a1"}`
	if w := r.do("POST", "/api/accounts/add", body, nil, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("no session: %d", w.Code)
	}
	s := r.login()
	if w := r.do("POST", "/api/accounts/add", body, s, ""); w.Code != http.StatusForbidden {
		t.Fatalf("no csrf: %d", w.Code)
	}
	if w := r.do("POST", "/api/accounts/add", body, s, "wrong"); w.Code != http.StatusForbidden {
		t.Fatalf("bad csrf: %d", w.Code)
	}
	if len(rc.calls) != 0 {
		t.Fatal("hub reached without a session and a CSRF token")
	}
}

func TestReplaceStartsAReplaceJobNotAnAdd(t *testing.T) {
	r, rc, ac := replaceRig(t)
	s := r.login()
	// The label is the account's own; one sent along is ignored, not an error and not a rename.
	w := r.do("POST", "/api/accounts/add", `{"host":"h1","account":"a1","label":"whatever"}`, s, s.csrf)
	if w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), `"id":"0123456789abcdef"`) {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
	if len(rc.calls) != 1 || rc.calls[0] != [2]string{"h1", "a1"} || len(ac.adds) != 0 {
		t.Fatalf("replace %v add %v", rc.calls, ac.adds)
	}
	if a, _ := r.v.Get("a1"); a.Label != "Work" {
		t.Fatalf("label changed to %q", a.Label)
	}
}

func TestReplaceUnknownAccountIs404(t *testing.T) {
	r, _, _ := replaceRig(t)
	r.fh.replaceFn = func(string, string) (string, error) { return "", hub.ErrUnknownAccount }
	s := r.login()
	if w := r.do("POST", "/api/accounts/add", `{"host":"h1","account":"nope"}`, s, s.csrf); w.Code != http.StatusNotFound {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
}

func TestReplaceValidatesInput(t *testing.T) {
	r, rc, _ := replaceRig(t)
	s := r.login()
	for _, body := range []string{
		`{"host":"","account":"a1"}`,
		`{"host":"h1","account":"` + strings.Repeat("x", maxAccountID+1) + `"}`,
		`{"host":"h1","account":"a1","extra":1}`,
	} {
		if w := r.do("POST", "/api/accounts/add", body, s, s.csrf); w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d", body, w.Code)
		}
	}
	if len(rc.calls) != 0 {
		t.Fatalf("hub called for invalid input: %v", rc.calls)
	}
}

func TestReplaceMapsBusyAndOffline(t *testing.T) {
	r, _, _ := replaceRig(t)
	s := r.login()
	for err, want := range map[error]int{hub.ErrAddBusy: 409, hub.ErrAgentOffline: 409, hub.ErrUnknownHost: 404} {
		e := err
		r.fh.replaceFn = func(string, string) (string, error) { return "", e }
		if w := r.do("POST", "/api/accounts/add", `{"host":"h1","account":"a1"}`, s, s.csrf); w.Code != want {
			t.Errorf("%v: status %d", e, w.Code)
		}
	}
}

func TestReplaceStatusCarriesReplaceFlagAndWarningButNoBlock(t *testing.T) {
	r, _, _ := replaceRig(t)
	r.fh.statusFn = func(id string) (hub.AddView, error) {
		a, _ := r.v.Get("a1")
		return hub.AddView{ID: id, State: hub.AddDone, Replace: true, Account: &a,
			Warning: "A host is still signed in with the previous login."}, nil
	}
	s := r.login()
	w := r.do("GET", "/api/accounts/add/0123456789abcdef", "", s, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	b := w.Body.String()
	for _, want := range []string{`"replace":true`, `"warning":"A host is still signed in`, `"id":"a1"`} {
		if !strings.Contains(b, want) {
			t.Errorf("body lacks %s: %s", want, b)
		}
	}
	if strings.Contains(b, blockSecret) || strings.Contains(b, "block") {
		t.Fatalf("a credential block reached the response: %s", b)
	}
}
