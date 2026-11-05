package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"claude-utilities/internal/hub"
	"claude-utilities/internal/logx"
	"claude-utilities/internal/usage"
)

const removePath = "/api/accounts/remove"

func rmBody(id string, force bool) string {
	b, _ := json.Marshal(map[string]any{"account": id, "force": force})
	return string(b)
}

func TestRemoveAccountNeedsASessionAndACSRFToken(t *testing.T) {
	r := newRig(t)
	r.seed("a1", "work")

	if w := r.do("POST", removePath, rmBody("a1", false), nil, ""); w.Code != http.StatusUnauthorized {
		t.Errorf("no session: status %d", w.Code)
	}
	s := r.login()
	for _, tok := range []string{"", "wrong", "wrong" + s.csrf} {
		w := r.do("POST", removePath, rmBody("a1", false), s, tok)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "CSRF") {
			t.Errorf("csrf %q: status %d body %s", tok, w.Code, w.Body)
		}
	}
	// A wrong-method probe learns nothing about the route, like every other /api/ path.
	if w := r.do("DELETE", removePath, "", nil, ""); w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated DELETE: status %d", w.Code)
	}
	if n := len(r.fh.removes()); n != 0 {
		t.Fatalf("the hub was asked to remove an account %d times without a valid request", n)
	}
	if _, ok := r.v.Get("a1"); !ok {
		t.Fatal("the account was removed by a request with no CSRF token")
	}
}

func TestRemoveAccountDeletesAndDropsThePollerState(t *testing.T) {
	r := newRig(t)
	r.seed("a1", "work")
	r.seed("a2", "spare")
	r.usage["a1"] = usage.Usage{FetchedAt: fixedNow, Err: "rate limited"}
	r.usage["a2"] = usage.Usage{FetchedAt: fixedNow}
	s := r.login()

	w := r.do("POST", removePath, rmBody("a1", false), s, s.csrf)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
	if _, ok := r.v.Get("a1"); ok {
		t.Fatal("the account is still in the vault")
	}
	if _, ok := r.usage["a1"]; ok {
		t.Fatal("the poller still holds the removed account's usage")
	}
	if _, ok := r.v.Get("a2"); !ok {
		t.Fatal("another account was removed")
	}
	if _, ok := r.usage["a2"]; !ok {
		t.Fatal("another account's poller state was dropped")
	}
	if got := r.fh.removes(); len(got) != 1 || got[0][0] != "a1" || got[0][1] != false {
		t.Fatalf("hub calls: %v", got)
	}
	// The account is gone from the list the page reads, and no response ever carried the block.
	list := r.do("GET", "/api/accounts", "", s, "").Body.String()
	if strings.Contains(list, `"id":"a1"`) {
		t.Fatalf("the removed account is still listed: %s", list)
	}
	if strings.Contains(w.Body.String(), blockSecret) || strings.Contains(list, blockSecret) {
		t.Fatal("a response carried the credential block")
	}
}

func TestRemoveAccountUnknownIDIs404(t *testing.T) {
	r := newRig(t)
	r.seed("a1", "work")
	s := r.login()

	w := r.do("POST", removePath, rmBody("nope", false), s, s.csrf)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
	if _, ok := r.v.Get("a1"); !ok {
		t.Fatal("a 404 removed a different account")
	}
}

// The held-live refusal: 409, the host named in the body so the UI can say which one, and nothing
// removed. The poller state has to survive too, or a refused removal would still blank the card.
func TestRemoveAccountHeldLiveIs409AndNamesTheHost(t *testing.T) {
	r := newRig(t)
	r.seed("a1", "work")
	r.usage["a1"] = usage.Usage{FetchedAt: fixedNow}
	r.fh.removeFn = func(string, bool) error {
		return &hub.HeldLiveError{HostID: "h-oak", HostName: "oak (windows)"}
	}
	s := r.login()

	w := r.do("POST", removePath, rmBody("a1", false), s, s.csrf)
	if w.Code != http.StatusConflict {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
	var out struct {
		Error  string `json:"error"`
		HeldBy string `json:"heldBy"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.HeldBy != "oak (windows)" {
		t.Fatalf("heldBy %q", out.HeldBy)
	}
	if out.Error == "" {
		t.Fatal("no error sentence for the operator")
	}
	if _, ok := r.v.Get("a1"); !ok {
		t.Fatal("a refused removal deleted the account")
	}
	if _, ok := r.usage["a1"]; !ok {
		t.Fatal("a refused removal dropped the poller state anyway")
	}
}

func TestRemoveAccountForceIsPassedThroughAndWins(t *testing.T) {
	r := newRig(t)
	r.seed("a1", "work")
	r.usage["a1"] = usage.Usage{FetchedAt: fixedNow}
	held := &hub.HeldLiveError{HostID: "h-oak", HostName: "oak"}
	r.fh.removeFn = func(id string, force bool) error {
		if !force {
			return held
		}
		return r.v.Delete(id)
	}
	s := r.login()

	if w := r.do("POST", removePath, rmBody("a1", false), s, s.csrf); w.Code != http.StatusConflict {
		t.Fatalf("without force: status %d", w.Code)
	}
	w := r.do("POST", removePath, rmBody("a1", true), s, s.csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("with force: status %d body %s", w.Code, w.Body)
	}
	if _, ok := r.v.Get("a1"); ok {
		t.Fatal("force did not remove the account")
	}
	if _, ok := r.usage["a1"]; ok {
		t.Fatal("force did not drop the poller state")
	}
	got := r.fh.removes()
	if len(got) != 2 || got[0][1] != false || got[1][1] != true {
		t.Fatalf("force flag not passed through: %v", got)
	}
}

func TestRemoveAccountRejectsABadBody(t *testing.T) {
	r := newRig(t)
	r.seed("a1", "work")
	s := r.login()

	for _, b := range []string{
		``, `{`, `[]`, `{"account":""}`, `{"account":"a1","extra":1}`,
		`{"account":"` + strings.Repeat("a", maxAccountID+1) + `"}`,
		`{"account":"a1"}{"account":"a1"}`,
	} {
		if w := r.do("POST", removePath, b, s, s.csrf); w.Code != http.StatusBadRequest {
			t.Errorf("body %q: status %d", b, w.Code)
		}
	}
	if n := len(r.fh.removes()); n != 0 {
		t.Fatalf("a malformed body reached the hub %d times", n)
	}
	if _, ok := r.v.Get("a1"); !ok {
		t.Fatal("a malformed body removed an account")
	}
}

func TestRemoveAccountIsRateLimitedPerSource(t *testing.T) {
	r := newRig(t)
	s := r.login()
	r.fh.removeFn = func(string, bool) error { return hub.ErrUnknownAccount }

	for i := 0; i < maxRemovals; i++ {
		if w := r.do("POST", removePath, rmBody("nope", false), s, s.csrf); w.Code != http.StatusNotFound {
			t.Fatalf("request %d: status %d", i, w.Code)
		}
	}
	w := r.do("POST", removePath, rmBody("nope", false), s, s.csrf)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("over the budget: status %d body %s", w.Code, w.Body)
	}
	if n := len(r.fh.removes()); n != maxRemovals {
		t.Fatalf("the hub saw %d removals, want %d", n, maxRemovals)
	}
	// The window is a window: it reopens.
	r.now = fixedNow.Add(removeWindow + time.Second)
	if w := r.do("POST", removePath, rmBody("nope", false), s, s.csrf); w.Code != http.StatusNotFound {
		t.Fatalf("after the window: status %d", w.Code)
	}
}

// The log line is the audit record. It carries the opaque account id and never the host name,
// which is agent-supplied text, nor anything from the credential block.
func TestRemoveAccountLogsTheIDAndNotTheHostName(t *testing.T) {
	r := newRig(t)
	r.seed("a1", "work")
	var buf bytes.Buffer
	old := logger
	logger = logx.New(&buf)
	defer func() { logger = old }()

	s := r.login()
	r.fh.removeFn = func(string, bool) error {
		return &hub.HeldLiveError{HostID: "h-oak", HostName: "oak-the-host-name"}
	}
	if w := r.do("POST", removePath, rmBody("a1", false), s, s.csrf); w.Code != http.StatusConflict {
		t.Fatalf("status %d", w.Code)
	}
	r.fh.removeFn = func(id string, _ bool) error { return r.v.Delete(id) }
	if w := r.do("POST", removePath, rmBody("a1", true), s, s.csrf); w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}

	logs := buf.String()
	if !strings.Contains(logs, "remove_account") || !strings.Contains(logs, "a1") {
		t.Fatalf("no audit line: %s", logs)
	}
	for _, bad := range []string{"oak-the-host-name", blockSecret} {
		if strings.Contains(logs, bad) {
			t.Fatalf("the audit line leaked %q: %s", bad, logs)
		}
	}
}
