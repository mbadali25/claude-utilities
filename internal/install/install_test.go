package install

import (
	"bytes"
	"errors"
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

func TestEnvironmentKeepsDollarLiteral(t *testing.T) {
	u := RenderSystemdUserUnit("/a", "/s/$HOME/x")
	if !strings.Contains(u, `Environment="CLAUDESWAP_STATE_DIR=/s/$HOME/x"`) {
		t.Errorf("Environment= must not double '$':\n%s", u)
	}
}

func TestRenderUnitNeverContainsToken(t *testing.T) {
	for name, s := range map[string]string{
		"unit": RenderSystemdUserUnit("/usr/bin/claude-swap-agent", "/home/u/.local/state/claude-swap"),
		"task": RenderTaskXML(`C:\a\agent.exe`, `C:\state`, `CORP\bob`),
	} {
		low := strings.ToLower(strings.ReplaceAll(s, "InteractiveToken", ""))
		for _, bad := range []string{"token", "secret", "password", "bearer", "sk-ant", "oauth", "@"} {
			if strings.Contains(low, bad) {
				t.Errorf("%s contains %q:\n%s", name, bad, s)
			}
		}
	}
}

func TestSchtasksArgsUseXMLAndNoPassword(t *testing.T) {
	a := strings.Join(SchtasksCreateArgs(`C:\t.xml`), " ")
	if a != `/Create /F /TN ClaudeSwapAgent /XML C:\t.xml` {
		t.Errorf("got %s", a)
	}
	if strings.Contains(a, "/RP") {
		t.Errorf("args must not carry a password: %s", a)
	}
}

func TestTaskXMLSettingsAndEnv(t *testing.T) {
	x := RenderTaskXML(`C:\Program Files\swap\agent.exe`, `C:\Users\a&b\state`, `CORP\bob`)
	for _, want := range []string{
		"<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>",
		"<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
		"<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>",
		"<RestartOnFailure>",
		"<LogonType>InteractiveToken</LogonType>",
		"<UserId>CORP\\bob</UserId>",
		`set &#34;CLAUDESWAP_STATE_DIR=C:\Users\a&amp;b\state&#34; &amp;&amp; &#34;C:\Program Files\swap\agent.exe&#34; run`,
	} {
		if !strings.Contains(x, want) {
			t.Errorf("task xml missing %q:\n%s", want, x)
		}
	}
}

func TestUTF16LE(t *testing.T) {
	if got := utf16LE("a"); !bytes.Equal(got, []byte{0xFF, 0xFE, 'a', 0}) {
		t.Errorf("got %v", got)
	}
}

func TestAbsStateDir(t *testing.T) {
	if _, err := absStateDir("/s\nX=1"); err == nil {
		t.Error("want error for line break")
	}
	dir := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := absStateDir(link); err == nil {
		t.Error("want error for symlink")
	}
	if got, err := absStateDir(dir); err != nil || got != dir {
		t.Errorf("got %q, %v", got, err)
	}
}

func TestInstallLinuxPrintsNextSteps(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	var out bytes.Buffer
	ran := false
	run := func(string, ...string) ([]byte, error) { ran = true; return nil, nil }
	if err := installFor("linux", "/usr/bin/agent", filepath.Join(t.TempDir(), "st"), run, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"systemctl --user daemon-reload", "enable --now claude-swap-agent.service", "loginctl enable-linger"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}
	if ran {
		t.Error("linux install must not run external commands")
	}
}

func TestInstallWindowsRunsIcaclsThenSchtasks(t *testing.T) {
	t.Setenv("USERNAME", "bob")
	t.Setenv("USERDOMAIN", "CORP")
	state := filepath.Join(t.TempDir(), "st")
	var calls []string
	run := func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	}
	var out bytes.Buffer
	if err := installFor("windows", "agent.exe", state, run, &out); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || !strings.HasPrefix(calls[0], "icacls "+state+" /inheritance:r /grant:r CORP\\bob:(OI)(CI)F") || !strings.HasPrefix(calls[1], "schtasks /Create /F /TN ClaudeSwapAgent /XML ") {
		t.Errorf("calls: %v", calls)
	}
	if _, err := os.Stat(state); err != nil {
		t.Errorf("state dir not created: %v", err)
	}
}

func TestInstallWindowsReportsFailureAndRejectsPercent(t *testing.T) {
	t.Setenv("USERNAME", "bob")
	fail := func(string, ...string) ([]byte, error) { return []byte("denied"), errors.New("exit 1") }
	err := installFor("windows", "agent.exe", filepath.Join(t.TempDir(), "st"), fail, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Errorf("want icacls error with output, got %v", err)
	}
	ok := func(string, ...string) ([]byte, error) { return nil, nil }
	if err := installFor("windows", "agent.exe", filepath.Join(t.TempDir(), "100%"), ok, &bytes.Buffer{}); err == nil {
		t.Error("want error for percent in state dir")
	}
}
