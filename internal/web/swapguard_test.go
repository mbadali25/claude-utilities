package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"claude-utilities/internal/hub"
	"claude-utilities/internal/proto"
	"claude-utilities/internal/vault"
)

func swapBody(t *testing.T, r *rig, s *session) (int, map[string]any) {
	t.Helper()
	w := r.do("POST", "/api/swap", `{"host":"h1","account":"a1"}`, s, s.csrf)
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("body %q: %v", w.Body.String(), err)
	}
	return w.Code, m
}

func TestSwapHeldElsewhereIs409WithCodeAndHolder(t *testing.T) {
	r := newRig(t)
	s := r.login()
	r.fh.swapErr = &hub.HeldError{Host: "one"}
	code, m := swapBody(t, r, s)
	if code != http.StatusConflict || m["code"] != "held_elsewhere" || m["holder"] != "one" {
		t.Fatalf("got %d %v", code, m)
	}
	if want := "Held by one: swap that host to another account first, or sign in again"; m["error"] != want {
		t.Fatalf("error %q, want %q", m["error"], want)
	}
}

func TestSwapUnauthorizedIs409SignInAgain(t *testing.T) {
	r := newRig(t)
	s := r.login()
	r.fh.swapErr = hub.ErrSignInAgain
	code, m := swapBody(t, r, s)
	if code != http.StatusConflict || m["code"] != "sign_in_again" {
		t.Fatalf("got %d %v", code, m)
	}
	if e, _ := m["error"].(string); !strings.Contains(e, "sign in again first") {
		t.Fatalf("error %q", e)
	}
}

func TestSwapSuccessCarriesWarningsAndHome(t *testing.T) {
	r := newRig(t)
	s := r.login()
	r.fh.swapRes = &hub.SwapResult{Outcome: hub.SwapDone, Home: proto.HomeMoved, Warnings: []hub.SwapWarning{
		{Code: hub.WarnStaleCopy, AgeHours: 9}, {Code: hub.WarnHolderOffline, Host: "one"}}}
	code, m := swapBody(t, r, s)
	if code != http.StatusOK || m["ok"] != true || m["outcome"] != "swapped" || m["home"] != proto.HomeMoved {
		t.Fatalf("got %d %v", code, m)
	}
	ws, _ := m["warnings"].([]any)
	if len(ws) != 2 {
		t.Fatalf("warnings %v", m["warnings"])
	}
	w0, _ := ws[0].(map[string]any)
	w1, _ := ws[1].(map[string]any)
	if w0["code"] != "stale_copy" || w0["ageHours"] != float64(9) || w1["code"] != "holder_offline" || w1["host"] != "one" {
		t.Fatalf("warnings %v", ws)
	}
}

func TestSwapSuccessWithoutWarningsHasEmptyList(t *testing.T) {
	r := newRig(t)
	s := r.login()
	_, m := swapBody(t, r, s)
	if ws, ok := m["warnings"].([]any); !ok || len(ws) != 0 {
		t.Fatalf("warnings %v", m["warnings"])
	}
	if _, has := m["home"]; has {
		t.Fatalf("home present with nothing reported: %v", m)
	}
}

// The page cannot run script in a Go test, so this pins the pieces the screenshots then show:
// the amber note on the card, the option suffixes, the disabled-with-reason for a refused login,
// the confirm caution, and the result line's cautions. The behaviour itself is covered by the
// browser run (docs/runbooks/claude-swap-e2e.md).
func TestPageCarriesTheStaleAndRefusalCopy(t *testing.T) {
	r := newRig(t)
	p := page(r, r.login())
	for _, want := range []string{
		`'Stored login is ' + a.copyAgeHours + ' h old.`,
		`acct-note warn stale-copy`,
		`' (refused)'`,
		`' (' + a.copyAgeHours + ' h old)'`,
		`'Sign in again first: Anthropic refused the stored login for '`,
		`go.disabled = !!w`,
		`'cwarn'`,
		`function swapNotes(j)`,
		`home_moved`,
		`.swapmsg.warn`,
	} {
		if !strings.Contains(p, want) {
			t.Fatalf("page is missing %q", want)
		}
	}
}

func TestAccountsReportCopyAgeAndStaleFlag(t *testing.T) {
	r := newRig(t)
	s := r.login()
	for _, c := range []struct {
		id  string
		age time.Duration
	}{{"fresh", 2 * time.Hour}, {"edge", 6 * time.Hour}, {"old", 7*time.Hour + 40*time.Minute}, {"unknown", -1}} {
		a := vault.Account{ID: c.id, Label: c.id, Identity: "uuid-" + c.id, Block: json.RawMessage(`{"accessToken":"x"}`)}
		if c.age >= 0 {
			a.Updated = fixedNow.Add(-c.age)
		}
		if err := r.v.Put(a); err != nil {
			t.Fatal(err)
		}
	}
	w := r.do("GET", "/api/accounts", "", s, "")
	var list []struct {
		ID           string `json:"id"`
		CopyAgeHours *int   `json:"copyAgeHours"`
		Stale        bool   `json:"stale"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	type want struct {
		hrs   int
		known bool
		stale bool
	}
	exp := map[string]want{"fresh": {2, true, false}, "edge": {6, true, false}, "old": {7, true, true}, "unknown": {0, false, false}}
	for _, a := range list {
		e := exp[a.ID]
		if (a.CopyAgeHours != nil) != e.known || (e.known && *a.CopyAgeHours != e.hrs) || a.Stale != e.stale {
			t.Fatalf("%s: hours %v stale %v, want %+v", a.ID, a.CopyAgeHours, a.Stale, e)
		}
	}
	if strings.Contains(w.Body.String(), "accessToken") {
		t.Fatal("a credential block reached the accounts response")
	}
}
