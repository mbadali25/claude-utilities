package web

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"claude-utilities/internal/logx"
)

// setCookie returns the one Set-Cookie header the response carries, so a test can read the
// raw attributes (http.Cookie parses "Max-Age=0" back to MaxAge -1, so the string matters).
func setCookie(t *testing.T, h http.Header) string {
	t.Helper()
	cs := h.Values("Set-Cookie")
	if len(cs) != 1 {
		t.Fatalf("Set-Cookie headers %v, want exactly one", cs)
	}
	return cs[0]
}

func TestLogoutClearsTheCookieWithTheSameAttributesAsLogin(t *testing.T) {
	r := newRig(t)
	set := setCookie(t, r.loginRaw(adminPW).Header())
	s := r.login()
	w := r.do("POST", "/api/logout", "", s, s.csrf)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
	clear := setCookie(t, w.Header())
	if !strings.Contains(clear, "Max-Age=0") {
		t.Errorf("clearing cookie %q does not expire the cookie", clear)
	}
	if strings.Contains(clear, s.cookie.Value) {
		t.Errorf("clearing cookie echoes the session token: %q", clear)
	}
	// Every attribute login set must come back, or a browser keeps a second cookie.
	for _, want := range []string{cookieName + "=", "Path=/", "HttpOnly", "Secure", "SameSite=Strict"} {
		if !strings.Contains(clear, want) {
			t.Errorf("clearing cookie %q lacks %q (login set: %q)", clear, want, set)
		}
	}
}

func TestLogoutMakesTheSessionUnusable(t *testing.T) {
	r := newRig(t)
	s := r.login()
	if w := r.do("GET", "/api/accounts", "", s, ""); w.Code != http.StatusOK {
		t.Fatalf("before logout: status %d", w.Code)
	}
	if w := r.do("POST", "/api/logout", "", s, s.csrf); w.Code != http.StatusOK {
		t.Fatalf("logout status %d %s", w.Code, w.Body)
	}
	// A replayed cookie is worth nothing now, whatever the route or the method.
	for _, rt := range [][3]string{
		{"GET", "/api/accounts", ""}, {"GET", "/api/hosts", ""},
		{"POST", "/api/enrol-code", s.csrf}, {"POST", "/api/logout", s.csrf},
	} {
		if w := r.do(rt[0], rt[1], "", s, rt[2]); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s after logout = %d, want 401", rt[0], rt[1], w.Code)
		}
	}
	if p := page(r, s); !strings.Contains(p, `name="password"`) || strings.Contains(p, "csrf-token") {
		t.Error("the page still renders the signed-in UI after logout")
	}
}

// A logout without a session is answered by apiGate like every other /api/ route: 401 with an
// empty body, so a probe learns nothing and nothing panics on the missing cookie.
func TestLogoutWithoutSessionIs401(t *testing.T) {
	r := newRig(t)
	for name, s := range map[string]*session{
		"no cookie": nil,
		"forged":    {cookie: &http.Cookie{Name: cookieName, Value: "forged"}},
	} {
		w := r.do("POST", "/api/logout", "", s, "whatever")
		if w.Code != http.StatusUnauthorized || w.Body.Len() != 0 {
			t.Errorf("%s: status %d body %q, want 401 and no body", name, w.Code, w.Body)
		}
		if cs := w.Header().Values("Set-Cookie"); len(cs) != 0 {
			t.Errorf("%s: unauthenticated logout set a cookie: %v", name, cs)
		}
	}
}

func TestLogoutRequiresCSRFAndTheSessionSurvivesWithout(t *testing.T) {
	r := newRig(t)
	s := r.login()
	for _, tok := range []string{"", "wrong", "wrong" + s.csrf} {
		w := r.do("POST", "/api/logout", "", s, tok)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "CSRF") {
			t.Fatalf("csrf %q: status %d body %s", tok, w.Code, w.Body)
		}
		if cs := w.Header().Values("Set-Cookie"); len(cs) != 0 {
			t.Fatalf("csrf %q: the cookie was cleared anyway: %v", tok, cs)
		}
	}
	if w := r.do("GET", "/api/accounts", "", s, ""); w.Code != http.StatusOK {
		t.Fatalf("session dropped by a CSRF-less logout: status %d", w.Code)
	}
}

func TestLogoutEndsOnlyTheCallersSession(t *testing.T) {
	r := newRig(t)
	a, b := r.login(), r.login()
	if w := r.do("POST", "/api/logout", "", a, a.csrf); w.Code != http.StatusOK {
		t.Fatalf("logout status %d", w.Code)
	}
	if w := r.do("GET", "/api/accounts", "", b, ""); w.Code != http.StatusOK {
		t.Fatalf("the other session was signed out too: status %d", w.Code)
	}
	if w := r.do("POST", "/api/enrol-code", "", b, b.csrf); w.Code != http.StatusOK {
		t.Fatalf("the other session lost its CSRF token: status %d", w.Code)
	}
}

func TestUIHasLogOutInTheAccountMenu(t *testing.T) {
	r := newRig(t)
	s := r.login()
	p := page(r, s)
	for _, want := range []string{"Log out", `id="mi-out"`, "/api/logout"} {
		if !strings.Contains(p, want) {
			t.Errorf("index.html lacks %q", want)
		}
	}
	if strings.Contains(page(r, nil), "/api/logout") {
		t.Error("the sign-in page offers the logout route")
	}
}

func TestLogoutNeverLogsTheSessionToken(t *testing.T) {
	var buf bytes.Buffer
	old := logger
	logger = logx.New(&buf)
	defer func() { logger = old }()
	r := newRig(t)
	s := r.login()
	r.do("POST", "/api/logout", "", s, s.csrf)
	out := buf.String()
	if !strings.Contains(out, `"msg":"logout"`) || !strings.Contains(out, "logout") {
		t.Fatalf("log lacks the logout line: %s", out)
	}
	for _, bad := range []string{s.cookie.Value, s.csrf} {
		if strings.Contains(out, bad) {
			t.Fatalf("log holds a session token: %s", out)
		}
	}
	if strings.Contains(out, "[dropped]") {
		t.Fatalf("a log field was not allowlisted: %s", out)
	}
}
