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

// fakeExe creates a real file so checkExe accepts it.
func fakeExe(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agent")
	if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRenderSystemdUnitHasRestartAlways(t *testing.T) {
	u := RenderSystemdUserUnit("/opt/claude swap/agent", "/home/u/.local/state/claude-swap")
	for _, want := range []string{"Restart=always", "[Install]", "WantedBy=default.target", `ExecStart="/opt/claude swap/agent" run`, "StartLimitIntervalSec=", "StartLimitBurst="} {
		if !strings.Contains(u, want) {
			t.Errorf("unit missing %q:\n%s", want, u)
		}
	}
	if strings.Contains(u, "network-online") {
		t.Errorf("a user unit cannot order on network-online.target:\n%s", u)
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

func TestEnvironmentKeepsDollarLiteral(t *testing.T) {
	u := RenderSystemdUserUnit("/a", "/s/$HOME/x")
	if !strings.Contains(u, `Environment="CLAUDESWAP_STATE_DIR=/s/$HOME/x"`) {
		t.Errorf("Environment= must not double '$':\n%s", u)
	}
}

func TestRenderUnitNeverContainsToken(t *testing.T) {
	u := strings.ToLower(RenderSystemdUserUnit("/usr/bin/claude-swap-agent", "/home/u/.local/state/claude-swap"))
	a := strings.ToLower(strings.Join(SchtasksCreateArgs(`C:\a\agent.exe`, `CORP\bob`), " "))
	for name, s := range map[string]string{"unit": u, "schtasks": a} {
		for _, bad := range []string{"token", "secret", "password", "bearer", "sk-ant", "oauth"} {
			if strings.Contains(s, bad) {
				t.Errorf("%s contains %q:\n%s", name, bad, s)
			}
		}
	}
	if strings.Contains(a, "/rp") {
		t.Errorf("args must not carry a password: %s", a)
	}
}

func TestSchtasksArgsQuoteExePathWithSpaces(t *testing.T) {
	a := SchtasksCreateArgs(`C:\Program Files\claude swap\agent.exe`, `CORP\bob`)
	want := []string{"/Create", "/SC", "ONLOGON", "/TN", "ClaudeSwapAgent", "/RU", `CORP\bob`, "/TR", `"C:\Program Files\claude swap\agent.exe" run`}
	if strings.Join(a, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("got %q\nwant %q", a, want)
	}
	if got := SchtasksCreateArgs(`C:\a"b\x.exe`, "u")[8]; got != `"C:\a\"b\x.exe" run` {
		t.Errorf("embedded quote not escaped: %s", got)
	}
}

func TestCheckExe(t *testing.T) {
	good := fakeExe(t)
	if err := checkExe(good); err != nil {
		t.Errorf("unexpected: %v", err)
	}
	for name, p := range map[string]string{
		"relative":  "agent",
		"missing":   filepath.Join(t.TempDir(), "nope"),
		"directory": t.TempDir(),
		"newline":   good + "\nx",
	} {
		if checkExe(p) == nil {
			t.Errorf("%s: want error for %q", name, p)
		}
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

func TestIsLinkCoversJunctionsNotOtherReparsePoints(t *testing.T) {
	if !isLink(os.ModeSymlink) || !isLink(os.ModeIrregular|os.ModeDir) || isLink(os.ModeDir) || isLink(0) {
		t.Error("isLink misclassifies modes")
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
	if err := installFor("linux", fakeExe(t), filepath.Join(t.TempDir(), "st"), run, &out); err != nil {
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

// useTaskDefault makes dir the state dir the logon task will resolve at run time.
func useTaskDefault(t *testing.T, dir string) {
	t.Helper()
	old := taskStateDir
	taskStateDir = func() (string, error) { return dir, nil }
	t.Cleanup(func() { taskStateDir = old })
}

// schtasks cannot pass CLAUDESWAP_STATE_DIR, so a different state dir would be invisible to the
// logon-run agent: install must refuse before touching the system.
func TestInstallWindowsRefusesStateDirThatDiffersFromTaskDefault(t *testing.T) {
	t.Setenv("USERNAME", "bob")
	useTaskDefault(t, filepath.Join(t.TempDir(), "default"))
	other := filepath.Join(t.TempDir(), "elsewhere")
	run := func(string, ...string) ([]byte, error) { t.Error("must not run"); return nil, nil }
	err := installFor("windows", fakeExe(t), other, run, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), StateDirEnv) {
		t.Fatalf("want refusal naming %s, got %v", StateDirEnv, err)
	}
	if _, serr := os.Stat(other); serr == nil {
		t.Error("state dir created despite refusal")
	}
}

func TestTaskStateDirIsUnderUserConfigDir(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("AppData", cfg)
	t.Setenv("XDG_CONFIG_HOME", cfg)
	got, err := TaskStateDir()
	if err != nil || got != filepath.Join(cfg, DefaultStateDirName) {
		t.Fatalf("%q %v", got, err)
	}
}

func TestInstallRejectsMissingOrRelativeExe(t *testing.T) {
	run := func(string, ...string) ([]byte, error) { t.Error("must not run"); return nil, nil }
	for _, exe := range []string{"agent.exe", filepath.Join(t.TempDir(), "missing")} {
		if err := installFor("windows", exe, filepath.Join(t.TempDir(), "st"), run, &bytes.Buffer{}); err == nil {
			t.Errorf("want error for %q", exe)
		}
	}
}

func TestInstallWindowsRunsIcaclsThenSchtasks(t *testing.T) {
	t.Setenv("USERNAME", "bob")
	t.Setenv("USERDOMAIN", "CORP")
	state := filepath.Join(t.TempDir(), "st")
	useTaskDefault(t, state)
	exe := fakeExe(t)
	var calls []string
	run := func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	}
	var out bytes.Buffer
	if err := installFor("windows", exe, state, run, &out); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || !strings.HasPrefix(calls[0], "icacls "+state+" /inheritance:r /grant:r CORP\\bob:(OI)(CI)F") || !strings.HasPrefix(calls[1], "schtasks /Create /SC ONLOGON /TN ClaudeSwapAgent /RU CORP\\bob /TR ") {
		t.Errorf("calls: %v", calls)
	}
	if !strings.Contains(out.String(), "schtasks /Run /TN ClaudeSwapAgent") {
		t.Errorf("output missing run hint:\n%s", out.String())
	}
}

func TestInstallWindowsSkipsIcaclsOnNonEmptyDir(t *testing.T) {
	t.Setenv("USERNAME", "bob")
	state := t.TempDir()
	useTaskDefault(t, state)
	if err := os.WriteFile(filepath.Join(state, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls []string
	run := func(name string, args ...string) ([]byte, error) { calls = append(calls, name); return nil, nil }
	if err := installFor("windows", fakeExe(t), state, run, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0] != "schtasks" {
		t.Errorf("calls: %v", calls)
	}
}

func TestInstallWindowsReportsFailure(t *testing.T) {
	t.Setenv("USERNAME", "bob")
	fail := func(string, ...string) ([]byte, error) { return []byte("denied"), errors.New("exit 1") }
	state := filepath.Join(t.TempDir(), "st")
	useTaskDefault(t, state)
	err := installFor("windows", fakeExe(t), state, fail, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Errorf("want icacls error with output, got %v", err)
	}
}
