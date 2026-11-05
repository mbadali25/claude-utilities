package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"claude-utilities/internal/adminpw"
	"claude-utilities/internal/logx"
)

const newPW = "a-new-long-password"

func body(current, next string) string {
	b, _ := json.Marshal(map[string]string{"current": current, "new": next})
	return string(b)
}

func TestSetPasswordHappyPathStoresAndInvalidatesSessions(t *testing.T) {
	r := newRig(t)
	s := r.login()
	other := r.login() // a second admin session must also be ended
	w := r.do("POST", "/api/password", body(adminPW, newPW), s, s.csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
	if r.pw.setN() != 1 || r.pw.sets[0] != newPW {
		t.Fatalf("Set calls %v", r.pw.sets)
	}
	for name, sess := range map[string]*session{"caller": s, "other": other} {
		if got := r.do("GET", "/api/accounts", "", sess, "").Code; got != http.StatusUnauthorized {
			t.Errorf("%s session still works: %d, want 401", name, got)
		}
	}
	// The old password no longer signs in; the new one does.
	if got := r.loginRaw(adminPW).Code; got != http.StatusUnauthorized {
		t.Errorf("old password status %d, want 401", got)
	}
	if got := r.loginRaw(newPW).Code; got != http.StatusSeeOther {
		t.Errorf("new password status %d, want 303", got)
	}
}

func TestSetPasswordWrongCurrentIsRejectedAndChangesNothing(t *testing.T) {
	r := newRig(t)
	s := r.login()
	w := r.do("POST", "/api/password", body("not-the-password", newPW), s, s.csrf)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "current password is wrong") {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
	if r.pw.setN() != 0 {
		t.Fatalf("Set ran for a wrong current password: %v", r.pw.sets)
	}
	// The session survives a wrong attempt, and the original password still works.
	if got := r.do("GET", "/api/accounts", "", s, "").Code; got != http.StatusOK {
		t.Fatalf("session dropped on a failed attempt: %d", got)
	}
	if !r.pw.Verify(adminPW) {
		t.Fatal("the stored password changed")
	}
}

func TestSetPasswordTooShortIsRejected(t *testing.T) {
	r := newRig(t)
	s := r.login()
	short := strings.Repeat("x", adminpw.MinLength-1)
	w := r.do("POST", "/api/password", body(adminPW, short), s, s.csrf)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), fmt.Sprint(adminpw.MinLength)) {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
	if r.pw.setN() != 0 {
		t.Fatalf("a short password was stored: %v", r.pw.sets)
	}
	if got := r.do("GET", "/api/accounts", "", s, "").Code; got != http.StatusOK {
		t.Fatalf("session dropped for a too-short password: %d", got)
	}
}

func TestSetPasswordRequiresSessionAndCSRF(t *testing.T) {
	r := newRig(t)
	s := r.login()
	if w := r.do("POST", "/api/password", body(adminPW, newPW), nil, "whatever"); w.Code != http.StatusUnauthorized {
		t.Errorf("no session: %d, want 401", w.Code)
	}
	for _, tok := range []string{"", "wrong"} {
		w := r.do("POST", "/api/password", body(adminPW, newPW), s, tok)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "CSRF") {
			t.Errorf("csrf %q: status %d body %s", tok, w.Code, w.Body)
		}
	}
	if r.pw.setN() != 0 {
		t.Fatalf("password changed without a session or CSRF token: %v", r.pw.sets)
	}
}

func TestSetPasswordIsRateLimitedPerSourceIP(t *testing.T) {
	r := newRig(t)
	s := r.login()
	for i := 0; i < maxLoginFailures; i++ {
		if w := r.do("POST", "/api/password", body("wrong", newPW), s, s.csrf); w.Code != http.StatusForbidden {
			t.Fatalf("attempt %d: status %d", i, w.Code)
		}
	}
	// Budget spent: even the right current password is refused now.
	if w := r.do("POST", "/api/password", body(adminPW, newPW), s, s.csrf); w.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429", w.Code)
	}
	// The shared per-IP budget also locks the login form, and clears with the window.
	if w := r.loginRaw(adminPW); w.Code != http.StatusTooManyRequests {
		t.Fatalf("login status %d, want 429", w.Code)
	}
	r.now = r.now.Add(loginWindow + time.Second)
	if w := r.do("POST", "/api/password", body(adminPW, newPW), s, s.csrf); w.Code != http.StatusOK {
		t.Fatalf("after the window: status %d body %s", w.Code, w.Body)
	}
}

func TestSetPasswordRejectsMalformedBody(t *testing.T) {
	r := newRig(t)
	s := r.login()
	cases := map[string]struct {
		body string
		want int
	}{
		"truncated":     {`{`, http.StatusBadRequest},
		"unknown field": {`{"current":"a","new":"b","extra":1}`, http.StatusBadRequest},
		"empty current": {body("", newPW), http.StatusBadRequest},
		"empty new":     {body(adminPW, ""), http.StatusBadRequest},
		"huge new":      {body(adminPW, strings.Repeat("y", maxPassword+1)), http.StatusBadRequest},
	}
	for name, c := range cases {
		if w := r.do("POST", "/api/password", c.body, s, s.csrf); w.Code != c.want {
			t.Errorf("%s: status %d, want %d", name, w.Code, c.want)
		}
	}
	if r.pw.setN() != 0 {
		t.Fatalf("password changed by a malformed request: %v", r.pw.sets)
	}
}

func TestSetPasswordStoreFailureIs500AndKeepsTheSession(t *testing.T) {
	r := newRig(t)
	s := r.login()
	r.pw.err = errors.New("adminpw: rename: disk full password=hunter2")
	w := r.do("POST", "/api/password", body(adminPW, newPW), s, s.csrf)
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "hunter2") {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
	if got := r.do("GET", "/api/accounts", "", s, "").Code; got != http.StatusOK {
		t.Fatalf("sessions dropped although nothing was stored: %d", got)
	}
}

func TestSetPasswordNeverLogsAPassword(t *testing.T) {
	var buf bytes.Buffer
	old := logger
	logger = logx.New(&buf)
	defer func() { logger = old }()
	r := newRig(t)
	s := r.login()
	r.do("POST", "/api/password", body("wrong-"+adminPW, newPW), s, s.csrf)
	r.do("POST", "/api/password", body(adminPW, newPW), s, s.csrf)
	out := buf.String()
	for _, want := range []string{"password change failed", "password changed", "set_password"} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q: %s", want, out)
		}
	}
	for _, bad := range []string{adminPW, newPW} {
		if strings.Contains(out, bad) {
			t.Fatalf("log holds a password: %s", out)
		}
	}
	if strings.Contains(out, "[dropped]") {
		t.Fatalf("a log field was not allowlisted: %s", out)
	}
}

func TestUIHasChangePasswordForm(t *testing.T) {
	r := newRig(t)
	s := r.login()
	p := page(r, s)
	for _, want := range []string{"Admin password", `id="pw-form"`, "/api/password", `minlength="12"`} {
		if !strings.Contains(p, want) {
			t.Errorf("index.html lacks %q", want)
		}
	}
	if strings.Contains(page(r, nil), "/api/password") {
		t.Error("the change-password form is offered without a session")
	}
}
