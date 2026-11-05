package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"claude-utilities/internal/credfile"
	"claude-utilities/internal/logx"
	"claude-utilities/internal/proto"
)

// A host enrolled as one user and later run as another - a system unit with User=root and
// HOME=/root that keeps the state dir from the original per-user enrolment - has a credsPath in
// agent.json naming the enrolling user's home. The swap must follow the home the agent actually
// runs in, which is the one the identity probe reads, not the path baked in at enrol: otherwise it
// rewrites a different user's login, reports success, and the card never changes.
func TestSwapFollowsLiveHomeNotStoredCredsPath(t *testing.T) {
	live, other := t.TempDir(), t.TempDir()
	liveCreds := filepath.Join(live, ".credentials.json")
	otherCreds := filepath.Join(other, ".credentials.json")
	writeCreds(t, liveCreds, testBlock("ACCESS-LIVE-HOME", future()))
	writeCreds(t, otherCreds, testBlock("ACCESS-OTHER-USER", future()))
	before, err := os.ReadFile(otherCreds)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv(claudeConfigDirEnv, live)
	logs := &syncBuf{}
	cfg := Config{CredsPath: otherCreds, StateDir: t.TempDir()}
	got, err := resolveCredsPath(cfg, logx.New(logs))
	if err != nil {
		t.Fatal(err)
	}
	if got != liveCreds {
		t.Fatalf("resolved %q, want the live home's file", got)
	}

	cfg.CredsPath = got
	block := testBlock(newSecret, future())
	if res := newAgent(cfg, logx.New(logs)).applySwap(proto.SwapReq{Block: block, Account: "acct"}); !res.OK {
		t.Fatalf("swap refused: %+v", res)
	}
	switch b, rerr := credfile.ReadBlock(liveCreds); {
	case rerr != nil:
		t.Fatalf("live home unreadable after swap: %v", rerr)
	case !sameJSON(t, b, block):
		t.Fatal("the swap did not reach the live home's credentials file")
	}
	after, err := os.ReadFile(otherCreds)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("the other user's credentials file was rewritten: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(other, backupDirName)); serr == nil {
		t.Fatal("a token backup was written into the other user's home")
	}

	// The divergence is the misconfiguration that caused this, so it must be visible - as a reason
	// code only: a credentials path names a user's home.
	out := logs.String()
	if !strings.Contains(out, reasonHomeMoved) {
		t.Fatalf("divergence not reported:\n%s", out)
	}
	for _, leak := range []string{".credentials.json", backupDirName} {
		if strings.Contains(out, leak) {
			t.Fatalf("a credentials path leaked into the log:\n%s", out)
		}
	}
}

// A stored path that agrees with the live home is the normal case and says nothing.
func TestResolveCredsPathSilentWhenStoredPathAgrees(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(claudeConfigDirEnv, dir)
	want := filepath.Join(dir, ".credentials.json")
	logs := &syncBuf{}
	got, err := resolveCredsPath(Config{CredsPath: want}, logx.New(logs))
	if err != nil || got != want {
		t.Fatalf("got %q, %v", got, err)
	}
	if strings.Contains(logs.String(), reasonHomeMoved) {
		t.Fatalf("agreeing path reported as moved:\n%s", logs.String())
	}
}

// Live resolution needs a home. A unit that passes none used to run anyway on the stored path, so
// the stored path stays the fallback: the fix must not stop such a host starting.
func TestResolveCredsPathFallsBackWhenHomeUnresolvable(t *testing.T) {
	t.Setenv(claudeConfigDirEnv, "")
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	stored := filepath.Join(t.TempDir(), ".credentials.json")
	logs := &syncBuf{}
	got, err := resolveCredsPath(Config{CredsPath: stored}, logx.New(logs))
	if err != nil || got != stored {
		t.Fatalf("got %q, %v; want the stored path", got, err)
	}
	if _, err := resolveCredsPath(Config{}, logx.New(logs)); err == nil {
		t.Fatal("no home and no stored path accepted")
	}
}
