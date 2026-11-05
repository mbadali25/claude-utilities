package install

import (
	"strings"
	"testing"
)

func TestRenderSystemdUnitHasRestartAlways(t *testing.T) {
	u := RenderSystemdUserUnit("/opt/claude swap/agent", "/home/u/.local/state/claude-swap")
	for _, want := range []string{"Restart=always", "[Install]", "WantedBy=default.target", `ExecStart="/opt/claude swap/agent" run`} {
		if !strings.Contains(u, want) {
			t.Errorf("unit missing %q:\n%s", want, u)
		}
	}
}

func TestSchtasksArgsQuoteExePathWithSpaces(t *testing.T) {
	a := SchtasksCreateArgs(`C:\Program Files\swap\agent.exe`, "alice")
	want := []string{"/Create", "/SC", "ONLOGON", "/TN", "ClaudeSwapAgent", "/RU", "alice", "/TR", `"C:\Program Files\swap\agent.exe" run`}
	if len(a) != len(want) {
		t.Fatalf("got %v", a)
	}
	for i := range want {
		if a[i] != want[i] {
			t.Errorf("arg %d: got %q want %q", i, a[i], want[i])
		}
	}
}

func TestRenderUnitNeverContainsToken(t *testing.T) {
	u := RenderSystemdUserUnit("/usr/bin/agent", "/state")
	for _, bad := range []string{"accessToken", "refreshToken", "CLAUDESWAP_KEY", "sk-ant", "Password"} {
		if strings.Contains(u, bad) {
			t.Errorf("unit contains %q", bad)
		}
	}
}

func TestRenderUnitStripsNewlines(t *testing.T) {
	u := RenderSystemdUserUnit("/a\nExecStartPre=/bin/evil", "/s\nX=1")
	if strings.Contains(u, "\nExecStartPre=") || strings.Contains(u, "\nX=1") {
		t.Errorf("newline injection:\n%s", u)
	}
}
