package hub

import (
	"encoding/json"
	"strings"
	"testing"

	"claude-utilities/internal/proto"
)

// TestRunAsFromHelloReachesHostView covers the enrol-by-code path: the username the agent
// reports is what the Hosts view hands the UI.
func TestRunAsFromHelloReachesHostView(t *testing.T) {
	f := newFixture(t)
	code, _ := f.h.NewEnrolCode()
	a := f.dial("", proto.Hello{Code: code, HostName: "box", OS: "linux", Nonce: "n1", RunAs: "dadeush"})
	a.recv(proto.TypeApproved)
	eventually(t, func() bool {
		for _, hv := range f.h.Hosts() {
			if hv.Name == "box" && hv.RunAs == "dadeush" {
				return true
			}
		}
		return false
	})
}

// TestRunAsRefreshedOnReconnect is what makes `install-agent.sh --reconfigure` visible: the
// host keeps its enrolment token but comes back as a different local user.
func TestRunAsRefreshedOnReconnect(t *testing.T) {
	f := newFixture(t)
	code, _ := f.h.NewEnrolCode()
	a := f.dial("", proto.Hello{Code: code, HostName: "box", OS: "linux", Nonce: "n1", RunAs: "dadeush"})
	var ap proto.Approved
	if err := json.Unmarshal(a.recv(proto.TypeApproved).Body, &ap); err != nil {
		t.Fatal(err)
	}
	b := f.dial("", proto.Hello{Token: ap.Token, HostName: "box", OS: "linux", RunAs: "root"})
	_ = b
	eventually(t, func() bool {
		for _, hv := range f.h.Hosts() {
			if hv.Name == "box" && hv.RunAs == "root" {
				return true
			}
		}
		return false
	})

	// An older agent sends no RunAs; the last known value must survive rather than blank out.
	c := f.dial("", proto.Hello{Token: ap.Token, HostName: "box", OS: "linux"})
	_ = c
	eventually(t, func() bool {
		for _, hv := range f.h.Hosts() {
			if hv.Name == "box" && hv.Online && hv.RunAs == "root" {
				return true
			}
		}
		return false
	})
}

// TestRunAsSanitized keeps agent-controlled text bounded and control-free, exactly as
// HostName and OS already are.
func TestRunAsSanitized(t *testing.T) {
	hl := sanitizeHello(proto.Hello{RunAs: strings.Repeat("u", maxFieldLen*3) + "\x07"})
	if len([]rune(hl.RunAs)) > maxFieldLen {
		t.Fatalf("RunAs not clipped: %d runes", len([]rune(hl.RunAs)))
	}
	if strings.Contains(hl.RunAs, "\x07") {
		t.Fatal("control character survived clip")
	}
}

// TestRunAsNotInFingerprint pins the compatibility rule: adding RunAs must not change the
// 8-character value the owner matches in the UI, or an upgraded agent becomes unapprovable.
func TestRunAsNotInFingerprint(t *testing.T) {
	base := proto.Hello{HostName: "box", OS: "linux", Nonce: "n1"}
	with := base
	with.RunAs = "dadeush"
	if proto.Fingerprint(base) != proto.Fingerprint(with) {
		t.Fatal("RunAs changed the fingerprint")
	}
}
