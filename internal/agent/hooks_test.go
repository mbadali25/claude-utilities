package agent

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sandboxSettings points SettingsPath at a temporary config dir. Nothing in these tests may touch
// a real ~/.claude: the hook install edits a live settings.json.
func sandboxSettings(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", dir)
	return filepath.Join(dir, settingsName)
}

func readRaw(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("settings is not JSON: %v: %s", err, data)
	}
	return m
}

// ourEntries counts this program's groups under one event.
func ourEntries(t *testing.T, m map[string]any, event string) int {
	t.Helper()
	hooks, ok := m["hooks"].(map[string]any)
	if !ok {
		return 0
	}
	list, ok := hooks[event].([]any)
	if !ok {
		return 0
	}
	n := 0
	for _, g := range list {
		if isOurs(g) {
			n++
		}
	}
	return n
}

func TestInstallHooksIsIdempotent(t *testing.T) {
	path := sandboxSettings(t)
	for i := 0; i < 3; i++ {
		got, err := InstallHooks("/opt/claude-swap/agent")
		if err != nil {
			t.Fatal(err)
		}
		if got != path {
			t.Fatalf("edited %s, want %s", got, path)
		}
	}
	m := readRaw(t, path)
	for _, ev := range hookEvents {
		if n := ourEntries(t, m, ev); n != 1 {
			t.Fatalf("%s has %d of our entries after three installs, want 1", ev, n)
		}
	}
}

func TestInstallHooksLeavesEverythingElseAlone(t *testing.T) {
	path := sandboxSettings(t)
	before := `{
  "model": "opus",
  "permissions": {"allow": ["Bash(ls)"]},
  "hooks": {
    "SessionStart": [{"hooks": [{"type": "command", "command": "someone-elses-hook"}]}],
    "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "audit"}]}]
  }
}`
	if err := os.WriteFile(path, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallHooks("/opt/agent"); err != nil {
		t.Fatal(err)
	}
	m := readRaw(t, path)
	if m["model"] != "opus" {
		t.Fatalf("model lost: %v", m["model"])
	}
	if _, ok := m["permissions"]; !ok {
		t.Fatal("permissions lost")
	}
	hooks := m["hooks"].(map[string]any)
	ss := hooks["SessionStart"].([]any)
	if len(ss) != 2 {
		t.Fatalf("SessionStart has %d groups, want the stranger's plus ours", len(ss))
	}
	if isOurs(ss[0]) {
		t.Fatal("the stranger's hook was replaced")
	}
	if len(hooks["PreToolUse"].([]any)) != 1 {
		t.Fatal("PreToolUse was touched")
	}

	// Uninstall gives the stranger's hooks back untouched and drops only ours.
	_, n, err := UninstallHooks()
	if err != nil {
		t.Fatal(err)
	}
	if n != len(hookEvents) {
		t.Fatalf("removed %d entries, want %d", n, len(hookEvents))
	}
	m = readRaw(t, path)
	hooks = m["hooks"].(map[string]any)
	if len(hooks["SessionStart"].([]any)) != 1 || ourEntries(t, m, "SessionStart") != 0 {
		t.Fatalf("SessionStart after uninstall: %v", hooks["SessionStart"])
	}
	if len(hooks["PreToolUse"].([]any)) != 1 {
		t.Fatal("PreToolUse was touched by the uninstall")
	}
}

func TestUninstallPrunesWhatItEmpties(t *testing.T) {
	path := sandboxSettings(t)
	if _, err := InstallHooks("/opt/agent"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := UninstallHooks(); err != nil {
		t.Fatal(err)
	}
	m := readRaw(t, path)
	if _, ok := m["hooks"]; ok {
		t.Fatalf("an empty hooks object was left behind: %v", m)
	}
}

func TestUninstallWithNothingInstalledChangesNothing(t *testing.T) {
	path := sandboxSettings(t)
	before := `{"model":"opus"}` + "\n"
	if err := os.WriteFile(path, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	_, n, err := UninstallHooks()
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("removed %d entries", n)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != before {
		t.Fatalf("the file was rewritten: %q", data)
	}
}

func TestInstallKeepsABackup(t *testing.T) {
	path := sandboxSettings(t)
	before := `{"model":"opus"}`
	if err := os.WriteFile(path, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallHooks("/opt/agent"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path + backupSuffix)
	if err != nil {
		t.Fatalf("no backup: %v", err)
	}
	if string(data) != before {
		t.Fatalf("backup = %q, want the previous file", data)
	}
}

func TestInstallRefusesUnparseableSettings(t *testing.T) {
	path := sandboxSettings(t)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallHooks("/opt/agent"); err == nil {
		t.Fatal("a settings file this cannot parse must not be rewritten")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "{not json" {
		t.Fatalf("the file was changed: %q %v", data, err)
	}
}

func TestInstallOnAMissingFileCreatesOne(t *testing.T) {
	path := sandboxSettings(t)
	if _, err := os.Stat(path); err == nil {
		t.Fatal("the sandbox should start empty")
	}
	if _, err := InstallHooks("/opt/agent"); err != nil {
		t.Fatal(err)
	}
	m := readRaw(t, path)
	if ourEntries(t, m, hookEvents[0]) != 1 {
		t.Fatalf("settings = %v", m)
	}
}

func TestHookCommandQuotesAPathWithSpaces(t *testing.T) {
	got := HookCommand(`C:\Program Files\claude-swap\agent.exe`)
	if !strings.HasPrefix(got, `"C:\Program Files\claude-swap\agent.exe"`) {
		t.Fatalf("not quoted: %s", got)
	}
	if !strings.Contains(got, hookTag) {
		t.Fatalf("the marker is missing, so an uninstall could not find it: %s", got)
	}
}

func TestRunHookDeliversTheQueueAsAdditionalContext(t *testing.T) {
	dir := t.TempDir()
	q := newQueue(dir, fixedClock())
	if err := q.enqueue(CommandTask{CommandID: "c1", Command: "reload_plugins", SessionID: testSession}); err != nil {
		t.Fatal(err)
	}
	in := strings.NewReader(`{"session_id":"` + testSession + `","hook_event_name":"UserPromptSubmit","cwd":"/w"}`)
	var out bytes.Buffer
	if err := RunHook(in, &out, dir, fixedClock()); err != nil {
		t.Fatal(err)
	}
	var o struct {
		HookSpecificOutput struct {
			HookEventName     string `json:"hookEventName"`
			AdditionalContext string `json:"additionalContext"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(out.Bytes(), &o); err != nil {
		t.Fatalf("hook output is not JSON: %v: %s", err, out.String())
	}
	if o.HookSpecificOutput.HookEventName != "UserPromptSubmit" {
		t.Fatalf("event = %q", o.HookSpecificOutput.HookEventName)
	}
	if !strings.Contains(o.HookSpecificOutput.AdditionalContext, "/reload-plugins") {
		t.Fatalf("context = %q", o.HookSpecificOutput.AdditionalContext)
	}
	// The entry is now delivered, so the next report tells the hub.
	if got := q.delivered(); len(got) != 1 || got[0].CommandID != "c1" {
		t.Fatalf("delivered = %+v", got)
	}
	// A second run has nothing to say.
	out.Reset()
	if err := RunHook(strings.NewReader(`{"session_id":"`+testSession+`"}`), &out, dir, fixedClock()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "additionalContext") {
		t.Fatalf("the instruction was delivered twice: %s", out.String())
	}
}

func TestRunHookAlwaysWritesValidJSON(t *testing.T) {
	dir := t.TempDir()
	for _, in := range []string{"", "not json", `{"session_id":""}`, `{"session_id":"../escape"}`, `{}`} {
		var out bytes.Buffer
		if err := RunHook(strings.NewReader(in), &out, dir, fixedClock()); err != nil {
			t.Fatalf("input %q: %v", in, err)
		}
		var m map[string]any
		if err := json.Unmarshal(out.Bytes(), &m); err != nil {
			t.Fatalf("input %q gave non-JSON %q", in, out.String())
		}
		if _, ok := m["hookSpecificOutput"]; ok {
			t.Fatalf("input %q injected context: %s", in, out.String())
		}
	}
}

// The instruction must ask, not claim: a hook cannot run a slash command.
func TestInstructionTextIsHonestAboutWhatItCanDo(t *testing.T) {
	got := instructionText([]queueEntry{
		{CommandID: "c1", Command: "reload_plugins"},
		{CommandID: "c2", Command: "remote_control_enable"},
		{CommandID: "c3", Command: "rename_remote", Name: "alpha"},
	})
	for _, want := range []string{"/reload-plugins", "cannot be enabled from outside", "latched", "alpha"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q: %s", want, got)
		}
	}
	for _, unwanted := range []string{"has been reloaded", "Remote Control is now on"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("claims too much (%q): %s", unwanted, got)
		}
	}
}
