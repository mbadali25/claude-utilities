package hub

import (
	"fmt"
	"strings"
	"testing"

	"claude-utilities/internal/proto"
)

// A host that names no account carries the reason through to the view, and stops carrying it the
// moment it names one.
func TestHostViewCarriesIdentityReason(t *testing.T) {
	f := newFixture(t)
	f.seedAccounts()
	a, _, _ := f.enrol("box")
	a.send(proto.TypeReport, "", proto.Report{IdentityReason: proto.ReasonNoClaudeJSON})
	eventually(t, func() bool { return f.h.Hosts()[0].IdentityReason == proto.ReasonNoClaudeJSON })
	if v := f.h.Hosts()[0]; v.ActiveAccount != "" {
		t.Fatalf("a host with no identity has no active account: %+v", v)
	}
	a.send(proto.TypeReport, "", proto.Report{ActiveIdentity: "id-a", CredsPresent: true})
	eventually(t, func() bool { return f.h.Hosts()[0].ActiveAccount == "A" })
	if r := f.h.Hosts()[0].IdentityReason; r != "" {
		t.Fatalf("reason beside a known identity: %q", r)
	}
}

// The reason is agent-supplied. Only a code this hub knows reaches an operator, so a host cannot
// put a path, an address or markup in front of one.
func TestHostViewDropsUnknownIdentityReason(t *testing.T) {
	f := newFixture(t)
	a, _, _ := f.enrol("box")
	for i, bad := range []string{
		"/home/planted-user/.claude.json",
		"planted@example.test",
		`<script>alert(1)</script>`,
		"NO_CLAUDE_JSON",
	} {
		// A known code first, so a dropped one is visible as the reason going back to empty. The
		// session id is the sentinel each report is waited on: reports are applied asynchronously.
		mark := fmt.Sprintf("s%d", i)
		a.send(proto.TypeReport, "", proto.Report{IdentityReason: proto.ReasonNoClaudeJSON})
		eventually(t, func() bool { return f.h.Hosts()[0].IdentityReason == proto.ReasonNoClaudeJSON })
		a.send(proto.TypeReport, "", proto.Report{IdentityReason: bad,
			Sessions: []proto.Session{{PID: i + 1, ID: mark}}})
		eventually(t, func() bool {
			ss := f.h.Hosts()[0].Sessions
			return len(ss) == 1 && ss[0].ID == mark
		})
		if r := f.h.Hosts()[0].IdentityReason; r != "" {
			t.Fatalf("unknown code %q surfaced as %q", bad, r)
		}
	}
	// A report that also names an identity must not smuggle the code through.
	a.send(proto.TypeReport, "", proto.Report{ActiveIdentity: "id-x", IdentityReason: proto.ReasonHomeMismatch})
	eventually(t, func() bool { return f.h.Hosts()[0].IdentityReason == "" })
	if out := f.logs.String(); strings.Contains(out, "planted") || strings.Contains(out, "script") {
		t.Fatalf("agent text leaked into the log:\n%s", out)
	}
}

// Reports arrive on every heartbeat: the code is logged when it changes, as a code, and the host's
// own identity never is.
func TestIdentityReasonLoggedOnChangeOnly(t *testing.T) {
	f := newFixture(t)
	a, _, _ := f.enrol("box")
	for i := 0; i < 3; i++ {
		a.send(proto.TypeReport, "", proto.Report{IdentityReason: proto.ReasonConfigDirElsewhere})
	}
	eventually(t, func() bool { return f.h.Hosts()[0].IdentityReason == proto.ReasonConfigDirElsewhere })
	a.send(proto.TypeReport, "", proto.Report{ActiveIdentity: "planted@example.test", CredsPresent: true})
	eventually(t, func() bool { return f.h.Hosts()[0].IdentityReason == "" })
	out := f.logs.String()
	if n := strings.Count(out, proto.ReasonConfigDirElsewhere); n != 1 {
		t.Fatalf("reason logged %d times:\n%s", n, out)
	}
	if !strings.Contains(out, `"result":"no_identity"`) {
		t.Fatalf("log lacks the no-identity result:\n%s", out)
	}
	if strings.Contains(out, "planted@example.test") {
		t.Fatalf("identity leaked into the log:\n%s", out)
	}
}
