package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"claude-utilities/internal/hub"
	"claude-utilities/internal/proto"
)

// The Hosts poll carries the reason a host names no account, so the card can explain itself; a
// host that names one grows no key, so an older UI sees the old shape.
func TestHostsPollCarriesIdentityReason(t *testing.T) {
	r := newRig(t)
	r.fh.hosts = []hub.HostView{
		{HostID: "h-1", Name: "linuxbox", OS: "linux", Online: true, IdentityReason: proto.ReasonNoClaudeJSON},
		{HostID: "h-2", Name: "winbox", OS: "windows", Online: true, ActiveAccount: "A"},
	}
	s := r.login()
	w := r.do(http.MethodGet, "/api/hosts", "", s, "")
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var out []hostJSON
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != 2 || out[0].IdentityReason != proto.ReasonNoClaudeJSON || out[1].IdentityReason != "" {
		t.Fatalf("hosts = %+v", out)
	}
	if n := strings.Count(w.Body.String(), `"identityReason"`); n != 1 {
		t.Fatalf("identityReason appears %d times, want only on the host without an account: %s", n, w.Body)
	}
}

// Every code the hub can pass on needs its own sentence and fix in the page. A code with no entry
// falls back to the general line, which is most of the way back to the silence this replaces.
func TestPageExplainsEveryIdentityReason(t *testing.T) {
	for _, c := range []string{proto.ReasonNoClaudeJSON, proto.ReasonNoOAuthAccount, proto.ReasonUnreadable,
		proto.ReasonConfigDirElsewhere, proto.ReasonHomeMismatch, proto.ReasonParseError, proto.ReasonNoCredentials} {
		if !strings.Contains(indexHTML, c+": {") {
			t.Errorf("the page has no explanation for %q", c)
		}
	}
}
