package web

import (
	"encoding/json"
	"strings"
	"testing"

	"claude-utilities/internal/hub"
)

// The run-as user reaches the browser as JSON and is omitted, not blanked, when the agent has
// not reported one: the card must not read "agent runs as nothing".
func TestHostsJSONCarriesRunAs(t *testing.T) {
	r := newRig(t)
	r.fh.hosts = []hub.HostView{
		{HostID: "h1", Name: "box", OS: "linux", RunAs: "dadeush", Online: true},
		{HostID: "h2", Name: "old", OS: "linux", Online: true},
	}
	s := r.login()
	var hosts []struct {
		HostID string `json:"hostId"`
		RunAs  string `json:"runAs"`
	}
	w := r.do("GET", "/api/hosts", "", s, "")
	if err := json.Unmarshal(w.Body.Bytes(), &hosts); err != nil || len(hosts) != 2 {
		t.Fatalf("%v %s", err, w.Body)
	}
	if hosts[0].RunAs != "dadeush" {
		t.Fatalf("host 0 runAs = %q, want dadeush: %s", hosts[0].RunAs, w.Body)
	}
	if hosts[1].RunAs != "" {
		t.Fatalf("host 1 runAs = %q, want empty: %s", hosts[1].RunAs, w.Body)
	}
	if strings.Contains(w.Body.String(), `"runAs":""`) {
		t.Fatalf("an unreported runAs is serialised rather than omitted: %s", w.Body)
	}
}

// The card wording is the one the runbook tells people to look for, and a username is
// agent-controlled text: it must go through textContent, never assigned HTML.
func TestUIShowsTheRunAsUserOnTheHostCard(t *testing.T) {
	r := newRig(t)
	s := r.login()
	p := page(r, s)
	for _, want := range []string{
		"agent runs as ",
		"h.runAs ? h.os",
		"(h.runAs || '')", // the host filter searches it too
	} {
		if !strings.Contains(p, want) {
			t.Errorf("index.html lacks %q", want)
		}
	}
	// el() sets textContent; an innerHTML path would make a username an injection point.
	if strings.Contains(p, "innerHTML = h.runAs") || strings.Contains(p, "innerHTML=h.runAs") {
		t.Error("index.html assigns a username as HTML")
	}
}
