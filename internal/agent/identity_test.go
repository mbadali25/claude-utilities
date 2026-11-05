package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"claude-utilities/internal/proto"
)

const signedIn = `{"oauthAccount":{"emailAddress":"a@example.test","accountUuid":"u-1"}}`

// homeProbe is an identityProbe rooted at a temp dir: no test reads the real home.
func homeProbe(home string) identityProbe { return identityProbe{home: home} }

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", filepath.Base(path), err)
	}
}

func TestIdentityProbeReasons(t *testing.T) {
	t.Run("no claude json", func(t *testing.T) {
		id, reason := homeProbe(t.TempDir()).run()
		if id != "" || reason != proto.ReasonNoClaudeJSON {
			t.Fatalf("got %q/%q", id, reason)
		}
	})
	t.Run("signed in by email, then by uuid", func(t *testing.T) {
		home := t.TempDir()
		p := filepath.Join(home, ".claude.json")
		writeFile(t, p, signedIn)
		if id, reason := homeProbe(home).run(); id != "a@example.test" || reason != "" {
			t.Fatalf("got %q/%q", id, reason)
		}
		writeFile(t, p, `{"oauthAccount":{"accountUuid":"u-1"}}`)
		if id, reason := homeProbe(home).run(); id != "u-1" || reason != "" {
			t.Fatalf("got %q/%q", id, reason)
		}
	})
	t.Run("no oauth account", func(t *testing.T) {
		home := t.TempDir()
		writeFile(t, filepath.Join(home, ".claude.json"), `{"numStartups":3}`)
		if id, reason := homeProbe(home).run(); id != "" || reason != proto.ReasonNoOAuthAccount {
			t.Fatalf("got %q/%q", id, reason)
		}
	})
	t.Run("parse error", func(t *testing.T) {
		home := t.TempDir()
		writeFile(t, filepath.Join(home, ".claude.json"), "not json at all")
		if id, reason := homeProbe(home).run(); id != "" || reason != proto.ReasonParseError {
			t.Fatalf("got %q/%q", id, reason)
		}
	})
	t.Run("absurd identity is a parse error", func(t *testing.T) {
		home := t.TempDir()
		writeFile(t, filepath.Join(home, ".claude.json"),
			`{"oauthAccount":{"emailAddress":"`+strings.Repeat("x", maxIdentity+1)+`"}}`)
		if id, reason := homeProbe(home).run(); id != "" || reason != proto.ReasonParseError {
			t.Fatalf("got %q/%q", id, reason)
		}
	})
	// A directory where the file should be reads as unreadable on every platform, which is what a
	// permission denial looks like to the agent: the file is there and it cannot have it.
	t.Run("unreadable", func(t *testing.T) {
		home := t.TempDir()
		if err := os.Mkdir(filepath.Join(home, ".claude.json"), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if id, reason := homeProbe(home).run(); id != "" || reason != proto.ReasonUnreadable {
			t.Fatalf("got %q/%q", id, reason)
		}
	})
	t.Run("no home", func(t *testing.T) {
		if id, reason := (identityProbe{}).run(); id != "" || reason != proto.ReasonNoHome {
			t.Fatalf("got %q/%q", id, reason)
		}
	})
}

// CLAUDE_CONFIG_DIR outranks the bare "nothing is signed in": the operator's own login is
// probably in the default dir, and the agent is looking somewhere else.
func TestIdentityProbeConfigDirElsewhere(t *testing.T) {
	home, cfg := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(home, ".claude.json"), signedIn) // the user IS signed in, just not there
	p := identityProbe{home: home, configDir: cfg}
	if id, reason := p.run(); id != "" || reason != proto.ReasonConfigDirElsewhere {
		t.Fatalf("missing file in config dir: %q/%q", id, reason)
	}
	writeFile(t, filepath.Join(cfg, ".claude.json"), `{"numStartups":1}`)
	if id, reason := p.run(); id != "" || reason != proto.ReasonConfigDirElsewhere {
		t.Fatalf("account-less file in config dir: %q/%q", id, reason)
	}
	writeFile(t, filepath.Join(cfg, ".claude.json"), signedIn)
	if id, reason := p.run(); id != "a@example.test" || reason != "" {
		t.Fatalf("signed in inside the config dir: %q/%q", id, reason)
	}
}

// Another user on the host is signed in and the agent runs as someone else: the fix is a
// different one, so the code is too. Only the other file's existence is probed, never its text.
func TestIdentityProbeHomeMismatch(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "agentuser")
	other := filepath.Join(root, "someone")
	for _, d := range []string{home, other} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	p := identityProbe{home: home, otherHomeGlobs: []string{filepath.Join(root, "*", ".claude.json")}}
	if _, reason := p.run(); reason != proto.ReasonNoClaudeJSON {
		t.Fatalf("no other home signed in: %q", reason)
	}
	writeFile(t, filepath.Join(other, ".claude.json"), signedIn)
	if id, reason := p.run(); id != "" || reason != proto.ReasonHomeMismatch {
		t.Fatalf("other home signed in: %q/%q", id, reason)
	}
	// Our own home must not count as "someone else", even though the glob matches it.
	writeFile(t, filepath.Join(home, ".claude.json"), signedIn)
	if id, reason := p.run(); id != "a@example.test" || reason != "" {
		t.Fatalf("our own home: %q/%q", id, reason)
	}
	// An empty file is not a sign-in.
	_ = os.Remove(filepath.Join(home, ".claude.json"))
	writeFile(t, filepath.Join(other, ".claude.json"), "")
	if _, reason := p.run(); reason != proto.ReasonNoClaudeJSON {
		t.Fatalf("empty file in the other home: %q", reason)
	}
}

// The glob is capped, and the cap must not push the named files (/root) off the end: a host with
// many home directories where only root is signed in is still a home_mismatch.
func TestIdentityProbeHomeMismatchIsBounded(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < maxOtherHomes+5; i++ {
		d := filepath.Join(root, string(rune('a'+i%26))+string(rune('a'+i/26)))
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		writeFile(t, filepath.Join(d, ".claude.json"), "") // crowds the glob; an empty file is no sign-in
	}
	// The named file stands in for /root: outside the glob, so only the cap can lose it.
	super := t.TempDir()
	writeFile(t, filepath.Join(super, ".claude.json"), signedIn)
	p := identityProbe{home: filepath.Join(root, "none"),
		otherHomeGlobs: []string{filepath.Join(root, "*", ".claude.json")},
		otherHomeFiles: []string{filepath.Join(super, ".claude.json")}}
	if n := len(p.candidates()); n > maxOtherHomes+len(p.otherHomeFiles) {
		t.Fatalf("probed %d candidates, cap is %d plus the named files", n, maxOtherHomes)
	}
	if _, reason := p.run(); reason != proto.ReasonHomeMismatch {
		t.Fatalf("the named file was capped away: reason = %q", reason)
	}
}

// The report must explain itself even with no credentials file at all: that is exactly the host
// in the complaint (connected, never signed in, "No active account" and no reason).
func TestReportCarriesIdentityReason(t *testing.T) {
	r := newRig(t, "https://x", strings.Repeat("0", 64))
	r.a.identity = func() (string, string) { return "", proto.ReasonNoClaudeJSON }
	rep := r.a.report(context.Background())
	if rep.CredsPresent || rep.ActiveIdentity != "" || rep.IdentityReason != proto.ReasonNoClaudeJSON {
		t.Fatalf("never signed in: %+v", rep)
	}
	// An account is named but the host holds no login block: a different fix, a different code.
	r2 := newRig(t, "https://x", strings.Repeat("0", 64))
	r2.a.identity = func() (string, string) { return "a@example.test", "" }
	if rep := r2.a.report(context.Background()); rep.IdentityReason != proto.ReasonNoCredentials {
		t.Fatalf("no credentials: %+v", rep)
	}
	// With a login and an identity there is nothing to explain.
	writeCreds(t, r2.creds, testBlock(origSecret, future()))
	r2.a.ident = &identityCache{probe: r2.a.identity}
	if rep := r2.a.report(context.Background()); rep.ActiveIdentity != "a@example.test" || rep.IdentityReason != "" {
		t.Fatalf("signed in: %+v", rep)
	}
}

// fakeIdentityClock drives the watcher: one tick channel, one signal channel, and a probe that
// announces every call, so a test never sleeps.
type fakeIdentityClock struct {
	ticks  chan time.Time
	hups   chan os.Signal
	probed chan struct{}
}

// watch wires the fakes into the rig's agent and runs the watcher until the returned stop is called.
func (f *fakeIdentityClock) watch(t *testing.T, r *rig, probe func() (string, string)) func() {
	t.Helper()
	f.ticks, f.hups, f.probed = make(chan time.Time), make(chan os.Signal, 1), make(chan struct{}, 16)
	r.a.identity = func() (string, string) {
		id, reason := probe()
		f.probed <- struct{}{}
		return id, reason
	}
	r.a.ident = &identityCache{probe: func() (string, string) { return r.a.identity() }, log: r.a.log}
	r.a.identityEvery = time.Hour // never fires: the test owns the clock
	r.a.tick = func(time.Duration) (<-chan time.Time, func()) { return f.ticks, func() {} }
	r.a.hup = func() (<-chan os.Signal, func()) { return f.hups, func() {} }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.a.watchIdentity(ctx) }()
	f.await(t) // the watcher probes once on start
	return func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("identity watcher did not stop")
		}
	}
}

func (f *fakeIdentityClock) await(t *testing.T) {
	t.Helper()
	select {
	case <-f.probed:
	case <-time.After(5 * time.Second):
		t.Fatal("identity was never re-read")
	}
}

// tick fires the refresh timer and waits for the re-read it causes.
func (f *fakeIdentityClock) tick(t *testing.T) {
	t.Helper()
	f.ticks <- time.Now()
	f.await(t)
}

// A sign-in, a sign-out and a switch after the agent started, each picked up by the ticker with
// no restart, and each visible in the next report.
func TestIdentityRefreshFollowsSignInAndOut(t *testing.T) {
	r := newRig(t, "https://x", strings.Repeat("0", 64))
	writeCreds(t, r.creds, testBlock(origSecret, future()))
	home := t.TempDir()
	p := filepath.Join(home, ".claude.json")
	var clk fakeIdentityClock
	stop := clk.watch(t, r, homeProbe(home).run)
	defer stop()

	if rep := r.a.report(context.Background()); rep.ActiveIdentity != "" || rep.IdentityReason != proto.ReasonNoClaudeJSON {
		t.Fatalf("before the sign-in: %+v", rep)
	}
	writeFile(t, p, signedIn) // someone runs `claude auth login`
	if rep := r.a.report(context.Background()); rep.ActiveIdentity != "" {
		t.Fatalf("identity must not change between refreshes: %+v", rep)
	}
	clk.tick(t)
	if rep := r.a.report(context.Background()); rep.ActiveIdentity != "a@example.test" || rep.IdentityReason != "" {
		t.Fatalf("after the sign-in: %+v", rep)
	}
	writeFile(t, p, `{"oauthAccount":{"emailAddress":"b@example.test"}}`) // switched account
	clk.tick(t)
	if rep := r.a.report(context.Background()); rep.ActiveIdentity != "b@example.test" || rep.IdentityReason != "" {
		t.Fatalf("after the switch: %+v", rep)
	}
	if err := os.Remove(p); err != nil { // signed out
		t.Fatalf("remove: %v", err)
	}
	clk.tick(t)
	if rep := r.a.report(context.Background()); rep.ActiveIdentity != "" || rep.IdentityReason != proto.ReasonNoClaudeJSON {
		t.Fatalf("after the sign-out: %+v", rep)
	}
	// Codes and counts only: no address, no path.
	if logs := r.log.String(); strings.Contains(logs, "example.test") || strings.Contains(logs, home) {
		t.Fatalf("identity or path leaked into the log: %s", logs)
	}
	if !strings.Contains(r.log.String(), proto.ReasonNoClaudeJSON) {
		t.Fatalf("reason code was never logged: %s", r.log.String())
	}
}

// A reload signal re-reads at once, so an operator need not wait out the refresh interval. The
// seam is nil on Windows (no SIGHUP), which the watcher must also survive.
func TestIdentitySignalRefreshes(t *testing.T) {
	r := newRig(t, "https://x", strings.Repeat("0", 64))
	writeCreds(t, r.creds, testBlock(origSecret, future()))
	home := t.TempDir()
	var clk fakeIdentityClock
	stop := clk.watch(t, r, homeProbe(home).run)
	defer stop()
	writeFile(t, filepath.Join(home, ".claude.json"), signedIn)
	clk.hups <- os.Interrupt // stands in for SIGHUP: the watcher reacts to anything on this channel
	clk.await(t)
	if rep := r.a.report(context.Background()); rep.ActiveIdentity != "a@example.test" {
		t.Fatalf("after the signal: %+v", rep)
	}
}

func TestIdentityWatcherSurvivesNoSignalChannel(t *testing.T) {
	r := newRig(t, "https://x", strings.Repeat("0", 64))
	r.a.identity = func() (string, string) { return "", proto.ReasonHomeMismatch }
	r.a.ident = &identityCache{probe: func() (string, string) { return r.a.identity() }, log: r.a.log}
	r.a.tick = func(time.Duration) (<-chan time.Time, func()) { return nil, func() {} }
	r.a.hup = func() (<-chan os.Signal, func()) { return nil, func() {} } // the Windows seam
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.a.watchIdentity(ctx) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not stop with nil channels")
	}
	if _, reason := r.a.ident.current(); reason != proto.ReasonHomeMismatch {
		t.Fatalf("reason = %q", reason)
	}
}

// Reports go out every heartbeat; the code is logged when it changes, not every time it is read.
func TestIdentityCacheLogsOnChangeOnly(t *testing.T) {
	r := newRig(t, "https://x", strings.Repeat("0", 64))
	reason := proto.ReasonNoClaudeJSON
	c := &identityCache{probe: func() (string, string) { return "", reason }, log: r.a.log}
	for i := 0; i < 4; i++ {
		c.refresh()
	}
	if n := strings.Count(r.log.String(), proto.ReasonNoClaudeJSON); n != 1 {
		t.Fatalf("logged the same reason %d times:\n%s", n, r.log.String())
	}
	reason = proto.ReasonHomeMismatch
	c.refresh()
	c.refresh()
	if n := strings.Count(r.log.String(), proto.ReasonHomeMismatch); n != 1 {
		t.Fatalf("logged the new reason %d times:\n%s", n, r.log.String())
	}
}
