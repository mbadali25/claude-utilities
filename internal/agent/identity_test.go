package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"claude-utilities/internal/logx"
	"claude-utilities/internal/proto"
)

// A root system unit with no Environment=HOME= has no home to read
// ~/.claude.json from. That must read as "the agent cannot tell", not as
// "this host has no login".
func TestClaudeJSONPathReportsNoHome(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	old := homeDirFn
	t.Cleanup(func() { homeDirFn = old })

	homeDirFn = func() (string, error) { return "", errors.New("$HOME is not defined") }
	if path, reason := claudeJSONPath(); path != "" || reason != proto.ReasonNoHome {
		t.Fatalf("no home = %q, %q", path, reason)
	}
	// An empty home with no error is the same situation.
	homeDirFn = func() (string, error) { return "", nil }
	if path, reason := claudeJSONPath(); path != "" || reason != proto.ReasonNoHome {
		t.Fatalf("empty home = %q, %q", path, reason)
	}
	homeDirFn = func() (string, error) { return filepath.Join("x", "home"), nil }
	if path, reason := claudeJSONPath(); path != filepath.Join("x", "home", ".claude.json") || reason != "" {
		t.Fatalf("with home = %q, %q", path, reason)
	}
}

// CLAUDE_CONFIG_DIR answers the question without a home, so no reason is due.
func TestClaudeJSONPathConfigDirNeedsNoHome(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", dir)
	old := homeDirFn
	t.Cleanup(func() { homeDirFn = old })
	homeDirFn = func() (string, error) { return "", errors.New("$HOME is not defined") }
	if path, reason := claudeJSONPath(); path != filepath.Join(dir, ".claude.json") || reason != "" {
		t.Fatalf("with config dir = %q, %q", path, reason)
	}
}

// The reason reaches the report even with credentials present, which is exactly
// the case the hub would otherwise show as a host with a login and no account.
func TestReportCarriesIdentityReason(t *testing.T) {
	r := newRig(t, "https://x", strings.Repeat("0", 64))
	writeCreds(t, r.creds, testBlock(origSecret, future()))
	r.a.identity = func() (string, string) { return "", proto.ReasonNoHome }

	rep := r.a.report(context.Background())
	if !rep.CredsPresent || rep.ActiveIdentity != "" || rep.IdentityReason != proto.ReasonNoHome {
		t.Fatalf("report = %+v", rep)
	}
	if !proto.ValidIdentityReason(rep.IdentityReason) {
		t.Fatalf("hub would drop %q", rep.IdentityReason)
	}
	// Logged once, as a fixed code and with no path.
	if got := r.log.String(); !strings.Contains(got, proto.ReasonNoHome) {
		t.Fatalf("reason not logged: %s", got)
	}
	r.a.report(context.Background())
	if n := strings.Count(r.log.String(), "no_identity"); n != 1 {
		t.Fatalf("warned %d times, want 1: %s", n, r.log.String())
	}
}

func TestReportNoIdentityReasonWhenHomeResolves(t *testing.T) {
	r := newRig(t, "https://x", strings.Repeat("0", 64))
	writeCreds(t, r.creds, testBlock(origSecret, future()))
	if rep := r.a.report(context.Background()); rep.IdentityReason != "" {
		t.Fatalf("reason = %q, want none", rep.IdentityReason)
	}
}

// The default seam wires claudeJSONPath to readIdentity: a real home with a
// real .claude.json gives an identity and no reason.
func TestDefaultIdentitySeam(t *testing.T) {
	home := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", home)
	if err := os.WriteFile(filepath.Join(home, ".claude.json"),
		[]byte(`{"oauthAccount":{"emailAddress":"a@example.test"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	a := newAgent(Config{StateDir: home}, logx.New(&syncBuf{}))
	if ident, reason := a.identity(); ident != "a@example.test" || reason != "" {
		t.Fatalf("identity = %q, %q", ident, reason)
	}
}
