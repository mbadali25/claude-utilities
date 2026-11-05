package install

import (
	"os"
	"path/filepath"
	"runtime"
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
	want := []string{"/Create", "/F", "/SC", "ONLOGON", "/RL", "LIMITED", "/IT", "/TN", "ClaudeSwapAgent", "/RU", "alice", "/TR", `"C:\Program Files\swap\agent.exe" run`}
	if len(a) != len(want) {
		t.Fatalf("got %v", a)
	}
	for i := range want {
		if a[i] != want[i] {
			t.Errorf("arg %d: got %q want %q", i, a[i], want[i])
		}
	}
}

func TestSchtasksArgsAvoidPasswordPrompt(t *testing.T) {
	a := strings.Join(SchtasksCreateArgs(`C:\a.exe`, `D\u`), " ")
	for _, want := range []string{"/IT", "/F", "/RL LIMITED"} {
		if !strings.Contains(a, want) {
			t.Errorf("args missing %q: %s", want, a)
		}
	}
	if strings.Contains(a, "/RP") {
		t.Errorf("args must not carry a password: %s", a)
	}
}

func TestRenderUnitStripsNewlines(t *testing.T) {
	u := RenderSystemdUserUnit("/a\nExecStartPre=/bin/evil", "/s\nX=1")
	if strings.Contains(u, "\nExecStartPre=") || strings.Contains(u, "\nX=1") {
		t.Errorf("newline injection:\n%s", u)
	}
}

func TestRenderUnitEscapesSpecifiersAndQuotes(t *testing.T) {
	u := RenderSystemdUserUnit(`/opt/a%h/b$X/c"d\e`, "/s%h")
	for _, want := range []string{`ExecStart="/opt/a%%h/b$$X/c\"d\\e" run`, "WorkingDirectory=/s%%h", `Environment="CLAUDESWAP_STATE_DIR=/s%%h"`} {
		if !strings.Contains(u, want) {
			t.Errorf("unit missing %q:\n%s", want, u)
		}
	}
}

func TestAbsExe(t *testing.T) {
	got, err := absExe("agent")
	if err != nil || !filepath.IsAbs(got) {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := absExe(`C:\a"b.exe`); err == nil {
		t.Error("want error for quote in path")
	}
}

func TestInstallUnitWritesFileAndTightensStateDir(t *testing.T) {
	home := t.TempDir()
	state := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(state, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // second run overwrites cleanly
		p, err := installUnit(home, "/usr/bin/agent", state)
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(p)
		if err != nil || !strings.Contains(string(b), `ExecStart="/usr/bin/agent" run`) {
			t.Fatalf("unit: %v\n%s", err, b)
		}
	}
	ents, _ := os.ReadDir(filepath.Join(home, ".config", "systemd", "user"))
	if len(ents) != 1 {
		t.Errorf("leftover temp files: %v", ents)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(state)
		if fi.Mode().Perm() != 0o700 {
			t.Errorf("state dir mode %v", fi.Mode().Perm())
		}
	}
}

func TestWindowsUser(t *testing.T) {
	t.Setenv("USERNAME", "")
	if _, err := windowsUser(); err == nil {
		t.Error("want error")
	}
	t.Setenv("USERNAME", "bob")
	t.Setenv("USERDOMAIN", "CORP")
	if u, _ := windowsUser(); u != `CORP\bob` {
		t.Errorf("got %q", u)
	}
}
