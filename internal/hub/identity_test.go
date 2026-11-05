package hub

import (
	"testing"

	"claude-utilities/internal/proto"
)

func hostViewByName(t *testing.T, h *Hub, name string) HostView {
	t.Helper()
	for _, hv := range h.Hosts() {
		if hv.Name == name {
			return hv
		}
	}
	t.Fatalf("no host named %q", name)
	return HostView{}
}

// A known reason code reaches the UI, so "credentials present, no account" can
// be told apart from "the agent cannot read the home directory".
func TestIdentityReasonReachesHostView(t *testing.T) {
	f := newFixture(t)
	code, _ := f.h.NewEnrolCode()
	a := f.dial("", proto.Hello{Code: code, HostName: "box", OS: "linux", Nonce: "n1"})
	a.recv(proto.TypeApproved)
	a.send(proto.TypeReport, "", proto.Report{CredsPresent: true, IdentityReason: proto.ReasonNoHome})
	eventually(t, func() bool {
		return hostViewByName(t, f.h, "box").IdentityReason == proto.ReasonNoHome
	})
}

// Anything that is not a known code is dropped, so the field is never
// agent-controlled free text and the UI has nothing to escape.
func TestUnknownIdentityReasonDropped(t *testing.T) {
	f := newFixture(t)
	code, _ := f.h.NewEnrolCode()
	a := f.dial("", proto.Hello{Code: code, HostName: "box", OS: "linux", Nonce: "n1"})
	a.recv(proto.TypeApproved)
	a.send(proto.TypeReport, "", proto.Report{CredsPresent: true,
		IdentityReason: `<img src=x onerror=alert(1)>`})
	a.send(proto.TypeReport, "", proto.Report{CredsPresent: true,
		IdentityReason: `<img src=x onerror=alert(1)>`})
	eventually(t, func() bool { return hostViewByName(t, f.h, "box").Online })
	if got := hostViewByName(t, f.h, "box").IdentityReason; got != "" {
		t.Fatalf("IdentityReason = %q, want dropped", got)
	}
}

// A later report that resolves the problem clears the reason.
func TestIdentityReasonClearedOnGoodReport(t *testing.T) {
	f := newFixture(t)
	code, _ := f.h.NewEnrolCode()
	a := f.dial("", proto.Hello{Code: code, HostName: "box", OS: "linux", Nonce: "n1"})
	a.recv(proto.TypeApproved)
	a.send(proto.TypeReport, "", proto.Report{CredsPresent: true, IdentityReason: proto.ReasonNoHome})
	eventually(t, func() bool {
		return hostViewByName(t, f.h, "box").IdentityReason == proto.ReasonNoHome
	})
	a.send(proto.TypeReport, "", proto.Report{CredsPresent: true, ActiveIdentity: "id-a"})
	eventually(t, func() bool {
		return hostViewByName(t, f.h, "box").IdentityReason == ""
	})
}
