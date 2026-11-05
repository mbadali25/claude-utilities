package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
		if code := hookCmd(strings.NewReader(in), &out); code != 0 {
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
