package web

import (
	"encoding/json"
	"strings"
	"testing"

	"claude-utilities/internal/hub"
	"claude-utilities/internal/proto"
)

// The reason reaches the browser as JSON, and is omitted rather than blanked
// when nothing is wrong.
func TestHostsJSONCarriesIdentityReason(t *testing.T) {
	r := newRig(t)
	r.fh.hosts = []hub.HostView{
		{HostID: "h1", Name: "box", OS: "linux", Online: true, IdentityReason: proto.ReasonNoHome},
		{HostID: "h2", Name: "fine", OS: "linux", Online: true},
	}
	s := r.login()
	var hosts []struct {
		HostID         string `json:"hostId"`
		IdentityReason string `json:"identityReason"`
	}
	w := r.do("GET", "/api/hosts", "", s, "")
	if err := json.Unmarshal(w.Body.Bytes(), &hosts); err != nil || len(hosts) != 2 {
		t.Fatalf("%v %s", err, w.Body)
	}
	if hosts[0].IdentityReason != proto.ReasonNoHome {
		t.Fatalf("host 0 identityReason = %q: %s", hosts[0].IdentityReason, w.Body)
	}
	if hosts[1].IdentityReason != "" {
		t.Fatalf("host 1 identityReason = %q, want empty: %s", hosts[1].IdentityReason, w.Body)
	}
	if strings.Contains(w.Body.String(), `"identityReason":""`) {
		t.Fatalf("an absent reason is serialised rather than omitted: %s", w.Body)
	}
}

// The card must say what to do about it, not just that something is wrong: the
// wording is what the runbook tells people to look for.
func TestUIExplainsNoHomeOnTheHostCard(t *testing.T) {
	r := newRig(t)
	s := r.login()
	p := page(r, s)
	for _, want := range []string{
		"no_home",
		"Environment=HOME=",
		// The wiring, not just the table: without this the strings above would pass
		// while hostCard never looked at the field.
		"identReason(h.identityReason)",
		// Own-property lookup, so a code like "constructor" cannot render an empty chip.
		"hasOwnProperty.call(IDENT_REASON",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("index.html lacks %q", want)
		}
	}
	// The hint text is agent-independent, but it still goes through textContent.
	if strings.Contains(p, "innerHTML = ir") || strings.Contains(p, "innerHTML=ir") {
		t.Error("index.html assigns the reason hint as HTML")
	}
}
