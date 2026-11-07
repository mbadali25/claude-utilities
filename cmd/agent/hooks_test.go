package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"claude-utilities/internal/agent"
)

// isolate() points CLAUDE_CONFIG_DIR at a temporary directory, so these never touch a real
// ~/.claude - the hook install edits a live settings.json.

func TestHooksSubcommandNeedsInstallOrUninstall(t *testing.T) {
	isolate(t)
	for _, args := range [][]string{{"hooks"}, {"hooks", "bogus"}} {
		code, _, errOut := run(t, context.Background(), args...)
		if code != 1 || !strings.Contains(errOut, "install or uninstall") {
			t.Fatalf("%v: code %d %q", args, code, errOut)
		}
	}
}

func TestHooksInstallThenUninstall(t *testing.T) {
	dir := isolate(t)
	settings := filepath.Join(dir, "claude", "settings.json")

	code, out, errOut := run(t, context.Background(), "hooks", "install")
	if code != 0 {
		t.Fatalf("install: code %d %q", code, errOut)
	}
	if !strings.Contains(out, "hook installed in") {
		t.Fatalf("install said %q", out)
	}
	data, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("settings is not JSON: %s", data)
	}
	if _, ok := m["hooks"]; !ok {
		t.Fatalf("no hooks written: %s", data)
	}

	code, out, errOut = run(t, context.Background(), "hooks", "uninstall")
	if code != 0 {
		t.Fatalf("uninstall: code %d %q", code, errOut)
	}
	if !strings.Contains(out, "removed 2 hook entries") {
		t.Fatalf("uninstall said %q", out)
	}
}

// The hook must always answer with JSON and exit 0, whatever it is handed: a failing hook
// interrupts the user's session.
func TestHookSubcommandAlwaysSucceedsWithJSON(t *testing.T) {
	isolate(t)
	for _, in := range []string{"", "garbage", `{"session_id":"nope"}`} {
		var out bytes.Buffer
		if code := hookCmd(nil, strings.NewReader(in), &out); code != 0 {
			t.Fatalf("input %q: code %d", in, code)
		}
		var m map[string]any
		if err := json.Unmarshal(out.Bytes(), &m); err != nil {
			t.Fatalf("input %q gave non-JSON %q", in, out.String())
		}
	}
}

// The installed command string must carry the marker the uninstall looks for, otherwise an
// uninstall would silently leave the hook behind.
func TestInstalledCommandCarriesTheMarker(t *testing.T) {
	dir := isolate(t)
	if _, err := run2(t, "hooks", "install"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "claude-swap-session-control") {
		t.Fatalf("no marker in %s", data)
	}
	if _, _, err := agent.UninstallHooks(); err != nil {
		t.Fatal(err)
	}
}

func run2(t *testing.T, args ...string) (string, error) {
	t.Helper()
	code, out, errOut := run(t, context.Background(), args...)
	if code != 0 {
		return out, errorf(errOut)
	}
	return out, nil
}

type cliError string

func (e cliError) Error() string { return string(e) }

func errorf(s string) error { return cliError(s) }

const hookTestSession = "11111111-2222-3333-4444-555555555555"

// seedQueue writes one pending instruction where the agent's queue keeps it under stateDir.
func seedQueue(t *testing.T, stateDir string) {
	t.Helper()
	qd := filepath.Join(stateDir, "commands")
	if err := os.MkdirAll(qd, 0o700); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"sessionId": hookTestSession, "entries": []any{
		map[string]any{"commandId": "c1", "command": "reload_plugins", "queuedAt": time.Now()}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(qd, hookTestSession+".json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func hookPayload() string {
	return `{"session_id":"` + hookTestSession + `","hook_event_name":"UserPromptSubmit","cwd":"/w"}`
}

func runHook(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := hookCmd(args, strings.NewReader(hookPayload()), &out)
	return code, out.String()
}

// The laptop case: the unit sets CLAUDESWAP_STATE_DIR, Claude runs the hook without it, so only
// the --state-dir baked into the command can find the queue.
func TestHookReadsTheQueueFromStateDirFlagWithEnvUnset(t *testing.T) {
	isolate(t)
	t.Setenv("CLAUDESWAP_STATE_DIR", "")
	dir := t.TempDir()
	seedQueue(t, dir)
	code, out := runHook(t, "--tag", "claude-swap-session-control", "--state-dir", dir)
	if code != 0 || !strings.Contains(out, "additionalContext") {
		t.Fatalf("code %d, queue not delivered: %q", code, out)
	}
}

func TestHookStateDirFlagOverridesEnv(t *testing.T) {
	isolate(t) // env points at an empty state dir
	dir := t.TempDir()
	seedQueue(t, dir)
	_, out := runHook(t, "--state-dir", dir)
	if !strings.Contains(out, "additionalContext") {
		t.Fatalf("flag did not win over env: %q", out)
	}
}

// An entry installed before --state-dir existed has no flag and must keep reading the env/default dir.
func TestHookWithoutFlagFallsBackToTheDefaultStateDir(t *testing.T) {
	dir := isolate(t)
	seedQueue(t, filepath.Join(dir, "state"))
	_, out := runHook(t, "--tag", "claude-swap-session-control")
	if !strings.Contains(out, "additionalContext") {
		t.Fatalf("no fallback to env state dir: %q", out)
	}
}

func TestHookBadStateDirStillAnswersEmptyJSON(t *testing.T) {
	isolate(t)
	bad := filepath.Join(t.TempDir(), "nope", "missing")
	code, out := runHook(t, "--state-dir", bad)
	if code != 0 || strings.TrimSpace(out) != "{}" {
		t.Fatalf("code %d out %q", code, out)
	}
	code, out = runHook(t, "--no-such-flag")
	if code != 0 || strings.TrimSpace(out) != "{}" {
		t.Fatalf("bad flag: code %d out %q", code, out)
	}
}

// hooks install bakes the install-time state dir (env wins) into the command.
func TestHooksInstallBakesTheStateDirIntoTheCommand(t *testing.T) {
	dir := isolate(t)
	if _, err := run2(t, "hooks", "install"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	// A Windows path is double-quoted, a plain POSIX one is not; both carry the slash form.
	want := filepath.ToSlash(filepath.Join(dir, "state"))
	if !strings.Contains(string(data), "--state-dir "+want) && !strings.Contains(string(data), `--state-dir \"`+want+`\"`) {
		t.Fatalf("settings lacks --state-dir %q: %s", want, data)
	}
}
