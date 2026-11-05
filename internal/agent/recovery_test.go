package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"claude-utilities/internal/credfile"
	"claude-utilities/internal/proto"
)

const refreshedSecret = "ACCESS-REFRESHED-BY-CLAUDE-CODE"

func journalGone(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Stat(journalPath(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal left behind: %v", err)
	}
}

// Claude Code rotates the token after the journal is written but before Replace's rename:
// Replace aborts (ErrChangedDuringSwap), the live block is neither old nor new, and the agent
// must neither restore an older backup nor wedge.
func TestSwapAbortedByConcurrentRefreshDoesNotWedge(t *testing.T) {
	r := newRig(t, "https://x", strings.Repeat("0", 64))
	orig := testBlock(origSecret, future())
	refreshed := testBlock(refreshedSecret, future())
	writeCreds(t, r.creds, orig)

	// What Replace leaves behind when Claude Code rewrites the file mid-swap: new content,
	// no backup, ErrChangedDuringSwap.
	r.a.replace = func(string, json.RawMessage) (string, error) {
		writeCreds(t, r.creds, refreshed)
		return "", credfile.ErrChangedDuringSwap
	}
	res := r.a.applySwap(proto.SwapReq{Block: testBlock(newSecret, future()), Account: "b"})
	r.a.replace = credfile.Replace
	if res.OK {
		t.Fatal("swap succeeded over a concurrent refresh")
	}
	if live, _ := credfile.ReadBlock(r.creds); !sameJSON(t, live, refreshed) {
		t.Fatal("agent overwrote the refreshed block")
	}
	journalGone(t, r.dir)
	if r.a.blocked.Load() {
		t.Fatal("agent reports itself blocked")
	}
	// The next swap works.
	next := testBlock(newSecret, future())
	if res := r.a.applySwap(proto.SwapReq{Block: next}); !res.OK {
		t.Fatalf("later swap refused: %s", res.Reason)
	}
}

// Crash between backup and rename, then Claude Code rotates the token before restart: the
// stale backup must not overwrite the newer block.
func TestRecoveryLeavesRotatedBlockAlone(t *testing.T) {
	r := newRig(t, "https://x", strings.Repeat("0", 64))
	orig := testBlock(origSecret, future())
	writeCreds(t, r.creds, orig)
	// A backup of orig exists, as after the crash.
	nextB := testBlock(newSecret, future())
	if _, err := credfile.Replace(r.creds, nextB); err != nil {
		t.Fatal(err)
	}
	rotated := testBlock(refreshedSecret, future())
	writeCreds(t, r.creds, rotated)
	j := journal{State: journalSwap, PrevHash: hashBlock(orig), NewHash: hashBlock(nextB)}
	if err := writeJournal(r.dir, j); err != nil {
		t.Fatal(err)
	}
	if err := r.a.recoverJournal(); err != nil {
		t.Fatal(err)
	}
	if live, _ := credfile.ReadBlock(r.creds); !sameJSON(t, live, rotated) {
		t.Fatal("recovery overwrote a block it did not write")
	}
	journalGone(t, r.dir)
}

func TestCorruptJournalIsQuarantined(t *testing.T) {
	for name, content := range map[string]string{"garbage": "{not json", "empty": "", "wrong state": `{"state":"x","prevHash":"h"}`} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, "https://x", strings.Repeat("0", 64))
			writeCreds(t, r.creds, testBlock(origSecret, future()))
			if err := os.WriteFile(journalPath(r.dir), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := r.a.recoverJournal(); err != nil {
				t.Fatal(err)
			}
			journalGone(t, r.dir)
			if _, err := os.Stat(journalPath(r.dir) + ".corrupt"); err != nil {
				t.Fatalf("not quarantined: %v", err)
			}
			if res := r.a.applySwap(proto.SwapReq{Block: testBlock(newSecret, future())}); !res.OK {
				t.Fatalf("swap refused after quarantine: %s", res.Reason)
			}
		})
	}
}

func TestUnrecoverableJournalIsReportedAsBlocked(t *testing.T) {
	r := newRig(t, "https://x", strings.Repeat("0", 64))
	nb := testBlock(newSecret, future())
	writeCreds(t, r.creds, nb)
	if err := writeJournal(r.dir, journal{State: journalSwap, PrevHash: hashBlock(testBlock(origSecret, future())), NewHash: hashBlock(nb)}); err != nil {
		t.Fatal(err)
	}
	if rep := r.a.report(context.Background()); rep.SwapBlocked {
		t.Fatal("blocked before any recovery ran")
	}
	if err := r.a.recoverJournal(); err == nil {
		t.Fatal("expected recovery error")
	}
	if rep := r.a.report(context.Background()); !rep.SwapBlocked {
		t.Fatal("report hides the wedge")
	}
	if err := clearJournal(r.dir); err != nil {
		t.Fatal(err)
	}
	if err := r.a.recoverJournal(); err != nil {
		t.Fatal(err)
	}
	if rep := r.a.report(context.Background()); rep.SwapBlocked {
		t.Fatal("still blocked after recovery")
	}
}

func TestJournalAndStateFilesAre0600(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("POSIX modes only")
	}
	dir := t.TempDir()
	if err := writeJournal(dir, journal{State: journalSwap, PrevHash: "h"}); err != nil {
		t.Fatal(err)
	}
	if err := writePrivate(filepath.Join(dir, deniedFileName), []byte("{}")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{journalPath(dir), filepath.Join(dir, deniedFileName)} {
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", filepath.Base(p), st, err)
		}
	}
	if ents, _ := filepath.Glob(filepath.Join(dir, ".*.tmp")); len(ents) != 0 {
		t.Fatalf("temp files left: %v", ents)
	}
}

func TestFatalDialErrorsStopRun(t *testing.T) {
	cases := map[string]string{
		"bad pin":      "https://127.0.0.1:1",
		"plain http":   "http://127.0.0.1:1",
		"userinfo url": "https://user:pw@127.0.0.1:1",
	}
	for name, url := range cases {
		t.Run(name, func(t *testing.T) {
			pin := strings.Repeat("a", 64)
			if name == "bad pin" {
				pin = "nothex"
			}
			r := newRig(t, url, pin)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := r.a.run(ctx)
			if err == nil || ctx.Err() != nil || !fatal(err) {
				t.Fatalf("run kept redialling: %v", err)
			}
			if strings.Contains(r.log.String(), "pw@") {
				t.Fatal("log leaks URL password")
			}
		})
	}
}

func TestRevokedOrBadTokenStopsRedial(t *testing.T) {
	for _, reason := range []string{"revoked", "bad token"} {
		t.Run(reason, func(t *testing.T) {
			fs := newFakeServer(t, func(_ context.Context, ws *websocket.Conn, _ int, _ proto.Hello) {
				_ = ws.Close(websocket.StatusPolicyViolation, reason)
			})
			r := newRig(t, fs.ts.URL, fs.pin)
			writeCreds(t, r.creds, testBlock(origSecret, future()))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := r.a.run(ctx); !errors.Is(err, ErrRejected) {
				t.Fatalf("run returned %v", err)
			}
			if n := fs.conns.Load(); n != 1 {
				t.Fatalf("agent redialled: %d connections", n)
			}
		})
	}
}

func TestOtherServerClosesStillRedial(t *testing.T) {
	fs := newFakeServer(t, func(_ context.Context, ws *websocket.Conn, n int, _ proto.Hello) {
		if n < 3 {
			_ = ws.Close(websocket.StatusPolicyViolation, "replaced")
			return
		}
		<-time.After(time.Second)
	})
	r := newRig(t, fs.ts.URL, fs.pin)
	writeCreds(t, r.creds, testBlock(origSecret, future()))
	stop := r.start(t)
	defer stop()
	recvHello(t, fs)
	recvHello(t, fs)
	recvHello(t, fs)
}

func TestDenialIsKeyedByServer(t *testing.T) {
	r := newEnrolRig(t)
	pinA, pinB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	a := targetKey("https://a.example", pinA)
	d := proto.Denied{Reason: "no", RetryAfter: time.Hour}
	if err := denied(r.o, r.o.Log, &r.out, d, a); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	if err := checkDenied(r.o, a); !errors.Is(err, ErrDenied) {
		t.Fatalf("same server not blocked: %v", err)
	}
	if err := checkDenied(r.o, targetKey("https://b.example", pinA)); err != nil {
		t.Fatalf("other URL blocked: %v", err)
	}
	if err := checkDenied(r.o, targetKey("https://a.example", pinB)); err != nil {
		t.Fatalf("other pin blocked: %v", err)
	}
	if _, err := os.Stat(filepath.Join(r.o.StateDir, deniedFileName)); err != nil {
		t.Fatal("another server's check deleted the denial record")
	}
}

func TestFirstReportDoesNotBlockReadLoop(t *testing.T) {
	release := make(chan struct{})
	fs := newFakeServer(t, func(ctx context.Context, ws *websocket.Conn, _ int, _ proto.Hello) {
		sendEnv(t, ctx, ws, proto.TypeExportReq, "e1", nil)
		for {
			env, err := readEnv(ctx, ws)
			if err != nil {
				return
			}
			if env.Type == proto.TypeExportRes {
				close(release)
				return
			}
		}
	})
	r := newRig(t, fs.ts.URL, fs.pin)
	writeCreds(t, r.creds, testBlock(origSecret, future()))
	slow := make(chan struct{})
	r.a.scan = func(ctx context.Context) ([]proto.Session, error) {
		select {
		case <-slow:
		case <-ctx.Done():
		}
		return nil, nil
	}
	stop := r.start(t)
	defer stop()
	defer close(slow)
	select {
	case <-release:
	case <-time.After(3 * time.Second):
		t.Fatal("export request starved by a slow first scan")
	}
}
