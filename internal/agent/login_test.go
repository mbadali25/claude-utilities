package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"claude-utilities/internal/proto"
)

const (
	testJobID   = "00112233445566ff"
	testJobID2  = "ffeeddccbbaa9988"
	goodCode    = "GOOD-CODE-0123456789"
	plantState  = "PLANTED-STATE-VALUE"
	plantedURL  = "https://claude.com/cai/oauth/authorize?code=true&state=" + plantState
	fakeIdent   = "fake.user@example.invalid"
	fakeRefresh = "r-fresh"
)

// fakeChild is one fake `claude auth login`.
type fakeChild struct {
	dir    string
	outW   *io.PipeWriter
	stdinR *io.PipeReader
	done   chan error
	killed atomic.Bool
	once   sync.Once
	finish func(err error)
}

type fakeRunner struct {
	mu       sync.Mutex
	children []*fakeChild
	startErr error
	// prompt is what the child prints at once; empty prints nothing.
	prompt string
	// behave runs after the prompt; nil means: read one line as the code, then succeed on goodCode.
	behave func(c *fakeChild)
}

func (r *fakeRunner) Start(_ context.Context, configDir string) (io.Reader, io.WriteCloser, func() error, func(), error) {
	if r.startErr != nil {
		return nil, nil, nil, nil, r.startErr
	}
	outR, outW := io.Pipe()
	inR, inW := io.Pipe()
	c := &fakeChild{dir: configDir, outW: outW, stdinR: inR, done: make(chan error, 1)}
	c.finish = func(err error) {
		c.once.Do(func() {
			_ = outW.Close()
			_ = inR.Close()
			c.done <- err
		})
	}
	r.mu.Lock()
	r.children = append(r.children, c)
	r.mu.Unlock()
	go func() {
		if r.prompt != "" {
			_, _ = outW.Write([]byte(r.prompt))
		}
		if r.behave != nil {
			r.behave(c)
			return
		}
		line, _ := bufio.NewReader(inR).ReadString('\n')
		if strings.TrimSpace(line) != goodCode {
			c.finish(errors.New("exit status 1"))
			return
		}
		writeFakeLogin(configDir)
		c.finish(nil)
	}()
	wait := func() error { return <-c.done }
	kill := func() {
		c.killed.Store(true)
		c.finish(errors.New("killed"))
	}
	return outR, inW, wait, kill, nil
}

func (r *fakeRunner) child(i int) *fakeChild {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i >= len(r.children) {
		return nil
	}
	return r.children[i]
}

func writeFakeLogin(dir string) {
	blk := `{"claudeAiOauth":` + string(testBlock("fresh", future())) + `,"mcpOAuth":{"x":1}}`
	_ = os.WriteFile(filepath.Join(dir, ".credentials.json"), []byte(blk), 0o600)
	_ = os.WriteFile(filepath.Join(dir, ".claude.json"), []byte(`{"oauthAccount":{"emailAddress":"`+fakeIdent+`"}}`), 0o600)
}

func osc8(url string) string {
	return "Opening browser to sign in...\nIf the browser didn't open, visit: \x1b]8;;" + url + "\x1b\\" + url + "\x1b]8;;\x1b\\\nPaste code here if prompted > "
}

// drive runs the agent against a fake server whose handler is fn, then stops it.
func drive(t *testing.T, r *rig, run *fakeRunner, fn func(ctx context.Context, ws *websocket.Conn), opts ...func(*agent)) {
	t.Helper()
	done := make(chan struct{})
	fs := newFakeServer(t, func(ctx context.Context, ws *websocket.Conn, n int, _ proto.Hello) {
		if n != 1 {
			<-ctx.Done()
			return
		}
		defer close(done)
		fn(ctx, ws)
	})
	r.a.cfg.ServerURL, r.a.cfg.Pin = fs.ts.URL, fs.pin
	r.a.login = run
	r.a.urlTimeout, r.a.jobTimeout, r.a.exitTimeout = 2*time.Second, 5*time.Second, 2*time.Second
	for _, o := range opts {
		o(r.a)
	}
	stop := r.start(t)
	defer stop()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("scenario did not finish")
	}
}

// waitFor reads frames until one of type typ arrives (heartbeat reports are skipped).
func waitFor(t *testing.T, ctx context.Context, ws *websocket.Conn, typ string) proto.Envelope {
	t.Helper()
	for {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		env, err := readEnv(rctx, ws)
		cancel()
		if err != nil {
			t.Fatalf("waiting for %s: %v", typ, err)
		}
		if env.Type == typ {
			return env
		}
	}
}

func eventuallyT(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

func gone(path string) bool { _, err := os.Stat(path); return os.IsNotExist(err) }

func TestExtractLoginURL(t *testing.T) {
	good := "https://claude.com/cai/oauth/authorize?code=true&state=s"
	cases := []struct {
		name string
		in   string
		want string
		err  error // nil: no error; errNeedMore; or any other error via anyErr
	}{
		{"osc8 and duplicate", osc8(good), good, nil},
		{"plain", "visit: " + good + "\nPaste", good, nil},
		{"csi after url", good + "\x1b[0m more", good, nil},
		{"bel terminated", "\x1b]8;;" + good + "\x07text", good, nil},
	}
	for _, c := range cases {
		got, err := extractLoginURL([]byte(c.in))
		if err != nil || got != c.want {
			t.Errorf("%s: got %q err %v", c.name, got, err)
		}
		if strings.ContainsAny(got, "\x1b\x07") {
			t.Errorf("%s: control bytes in %q", c.name, got)
		}
	}
	if _, err := extractLoginURL([]byte("visit: " + good)); !errors.Is(err, errNeedMore) {
		t.Errorf("truncated: %v", err)
	}
	if _, err := extractLoginURL([]byte("nothing here yet\n")); !errors.Is(err, errNeedMore) {
		t.Errorf("no url yet should need more, got %v", err)
	}
	for name, in := range map[string]string{
		"evil host": "visit: https://evil.example/cai/oauth/authorize?a=b\n",
		"http":      "visit: http://claude.com/cai/oauth/authorize\n",
		"too long":  "visit: https://claude.com/oauth/authorize?" + strings.Repeat("a", 5000) + "\n",
	} {
		if _, err := extractLoginURL([]byte(in)); err == nil || errors.Is(err, errNeedMore) {
			t.Errorf("%s accepted or deferred: %v", name, err)
		}
	}
	if _, err := extractLoginURL([]byte("visit: https://claude.com/oauth/authorize?" + strings.Repeat("a", 5000))); err == nil || errors.Is(err, errNeedMore) {
		t.Errorf("unbounded unterminated url must fail, got %v", err)
	}
}

func TestLoginSendsURLThenDone(t *testing.T) {
	r := newRig(t, "", "")
	writeCreds(t, r.creds, testBlock("live", future()))
	before, _ := os.ReadFile(r.creds)
	run := &fakeRunner{prompt: osc8(plantedURL)}
	drive(t, r, run, func(ctx context.Context, ws *websocket.Conn) {
		sendEnv(t, ctx, ws, proto.TypeLoginStart, testJobID, proto.LoginStart{})
		u := waitFor(t, ctx, ws, proto.TypeLoginURL)
		var lu proto.LoginURL
		_ = json.Unmarshal(u.Body, &lu)
		if u.ID != testJobID || lu.URL != plantedURL {
			t.Errorf("url frame id %q url %q", u.ID, lu.URL)
		}
		sendEnv(t, ctx, ws, proto.TypeLoginCode, testJobID, proto.LoginCode{Code: goodCode})
		d := waitFor(t, ctx, ws, proto.TypeLoginDone)
		var ld proto.LoginDone
		_ = json.Unmarshal(d.Body, &ld)
		if d.ID != testJobID || ld.Err != "" || ld.Identity != fakeIdent {
			t.Errorf("done id %q ident %q err %q", d.ID, ld.Identity, ld.Err)
		}
		if !sameJSON(t, ld.Block, testBlock("fresh", future())) {
			// future() differs by milliseconds; compare the stable field instead
			if !bytes.Contains(ld.Block, []byte(`"accessToken":"fresh"`)) || bytes.Contains(ld.Block, []byte("mcpOAuth")) {
				t.Errorf("block %s", ld.Block)
			}
		}
	})
	eventuallyT(t, func() bool { return gone(run.child(0).dir) })
	after, _ := os.ReadFile(r.creds)
	if !bytes.Equal(before, after) {
		t.Fatal("live credentials changed")
	}
	if run.child(0).dir == filepath.Dir(r.creds) || !strings.HasPrefix(filepath.Base(run.child(0).dir), "login-") {
		t.Fatalf("config dir %q is not a login-* temp dir", run.child(0).dir)
	}
}

func TestLoginNoURLTimesOut(t *testing.T) {
	r := newRig(t, "", "")
	run := &fakeRunner{behave: func(c *fakeChild) {}} // prints nothing, never exits
	drive(t, r, run, func(ctx context.Context, ws *websocket.Conn) {
		sendEnv(t, ctx, ws, proto.TypeLoginStart, testJobID, proto.LoginStart{})
		d := waitFor(t, ctx, ws, proto.TypeLoginDone)
		var ld proto.LoginDone
		_ = json.Unmarshal(d.Body, &ld)
		if !strings.Contains(ld.Err, "no sign-in URL") {
			t.Errorf("err %q", ld.Err)
		}
	}, func(a *agent) { a.urlTimeout = 80 * time.Millisecond })
	if !run.child(0).killed.Load() {
		t.Fatal("child not killed")
	}
	eventuallyT(t, func() bool { return gone(run.child(0).dir) })
}

func TestLoginRejectsBadURL(t *testing.T) {
	r := newRig(t, "", "")
	run := &fakeRunner{prompt: osc8("https://evil.example/cai/oauth/authorize?state=x")}
	drive(t, r, run, func(ctx context.Context, ws *websocket.Conn) {
		sendEnv(t, ctx, ws, proto.TypeLoginStart, testJobID, proto.LoginStart{})
		d := waitFor(t, ctx, ws, proto.TypeLoginDone)
		var ld proto.LoginDone
		_ = json.Unmarshal(d.Body, &ld)
		if !strings.Contains(ld.Err, "bad sign-in URL") || strings.Contains(ld.Err, "evil") {
			t.Errorf("err %q", ld.Err)
		}
	})
	if !run.child(0).killed.Load() {
		t.Fatal("child not killed")
	}
}

func TestLoginWrongCode(t *testing.T) {
	r := newRig(t, "", "")
	run := &fakeRunner{prompt: osc8(plantedURL)}
	drive(t, r, run, func(ctx context.Context, ws *websocket.Conn) {
		sendEnv(t, ctx, ws, proto.TypeLoginStart, testJobID, proto.LoginStart{})
		waitFor(t, ctx, ws, proto.TypeLoginURL)
		sendEnv(t, ctx, ws, proto.TypeLoginCode, testJobID, proto.LoginCode{Code: "WRONG"})
		d := waitFor(t, ctx, ws, proto.TypeLoginDone)
		var ld proto.LoginDone
		_ = json.Unmarshal(d.Body, &ld)
		if ld.Err != "sign-in rejected" || len(ld.Block) != 0 {
			t.Errorf("done %+v", ld)
		}
	})
	eventuallyT(t, func() bool { return gone(run.child(0).dir) })
}

func TestLoginNoCredentialsAfterExit(t *testing.T) {
	r := newRig(t, "", "")
	run := &fakeRunner{prompt: osc8(plantedURL), behave: func(c *fakeChild) {
		_, _ = bufio.NewReader(c.stdinR).ReadString('\n')
		c.finish(nil) // exit 0 but wrote nothing
	}}
	drive(t, r, run, func(ctx context.Context, ws *websocket.Conn) {
		sendEnv(t, ctx, ws, proto.TypeLoginStart, testJobID, proto.LoginStart{})
		waitFor(t, ctx, ws, proto.TypeLoginURL)
		sendEnv(t, ctx, ws, proto.TypeLoginCode, testJobID, proto.LoginCode{Code: goodCode})
		d := waitFor(t, ctx, ws, proto.TypeLoginDone)
		var ld proto.LoginDone
		_ = json.Unmarshal(d.Body, &ld)
		if ld.Err != "no credentials after sign-in" {
			t.Errorf("err %q", ld.Err)
		}
	})
}

func TestLoginCancelKillsChildAndRemovesDir(t *testing.T) {
	r := newRig(t, "", "")
	run := &fakeRunner{prompt: osc8(plantedURL), behave: func(c *fakeChild) {}}
	drive(t, r, run, func(ctx context.Context, ws *websocket.Conn) {
		sendEnv(t, ctx, ws, proto.TypeLoginStart, testJobID, proto.LoginStart{})
		waitFor(t, ctx, ws, proto.TypeLoginURL)
		sendEnv(t, ctx, ws, proto.TypeLoginCancel, testJobID, nil)
		eventuallyT(t, func() bool { return run.child(0).killed.Load() })
		eventuallyT(t, func() bool { return gone(run.child(0).dir) })
	})
}

func TestLoginSecondStartRefused(t *testing.T) {
	r := newRig(t, "", "")
	run := &fakeRunner{prompt: osc8(plantedURL), behave: func(c *fakeChild) {}}
	drive(t, r, run, func(ctx context.Context, ws *websocket.Conn) {
		sendEnv(t, ctx, ws, proto.TypeLoginStart, testJobID, proto.LoginStart{})
		waitFor(t, ctx, ws, proto.TypeLoginURL)
		sendEnv(t, ctx, ws, proto.TypeLoginStart, testJobID2, proto.LoginStart{})
		d := waitFor(t, ctx, ws, proto.TypeLoginDone)
		var ld proto.LoginDone
		_ = json.Unmarshal(d.Body, &ld)
		if d.ID != testJobID2 || !strings.Contains(ld.Err, "already running") {
			t.Errorf("done id %q err %q", d.ID, ld.Err)
		}
		if run.child(1) != nil || run.child(0).killed.Load() {
			t.Error("the first job was disturbed or a second child started")
		}
	})
}

func TestLoginRefusesBadJobIDs(t *testing.T) {
	r := newRig(t, "", "")
	run := &fakeRunner{prompt: osc8(plantedURL)}
	drive(t, r, run, func(ctx context.Context, ws *websocket.Conn) {
		sendEnv(t, ctx, ws, proto.TypeLoginStart, "", proto.LoginStart{}) // ignored
		sendEnv(t, ctx, ws, proto.TypeLoginStart, "../../evil", proto.LoginStart{})
		d := waitFor(t, ctx, ws, proto.TypeLoginDone)
		var ld proto.LoginDone
		_ = json.Unmarshal(d.Body, &ld)
		if d.ID != "../../evil" || ld.Err == "" {
			t.Errorf("done id %q err %q", d.ID, ld.Err)
		}
		if run.child(0) != nil {
			t.Error("a child started for a bad id")
		}
	})
}

func TestLoginCodeWithoutJobReportsError(t *testing.T) {
	r := newRig(t, "", "")
	drive(t, r, &fakeRunner{}, func(ctx context.Context, ws *websocket.Conn) {
		sendEnv(t, ctx, ws, proto.TypeLoginCode, testJobID, proto.LoginCode{Code: goodCode})
		d := waitFor(t, ctx, ws, proto.TypeLoginDone)
		var ld proto.LoginDone
		_ = json.Unmarshal(d.Body, &ld)
		if ld.Err == "" {
			t.Error("expected an error")
		}
	})
}

func TestLoginCLIMissing(t *testing.T) {
	r := newRig(t, "", "")
	run := &fakeRunner{startErr: errNoCLI}
	drive(t, r, run, func(ctx context.Context, ws *websocket.Conn) {
		sendEnv(t, ctx, ws, proto.TypeLoginStart, testJobID, proto.LoginStart{})
		d := waitFor(t, ctx, ws, proto.TypeLoginDone)
		var ld proto.LoginDone
		_ = json.Unmarshal(d.Body, &ld)
		if ld.Err != "claude CLI not found on host" {
			t.Errorf("err %q", ld.Err)
		}
	})
}

func TestLoginNeverLogsURLCodeOrBlock(t *testing.T) {
	r := newRig(t, "", "")
	run := &fakeRunner{prompt: osc8(plantedURL)}
	drive(t, r, run, func(ctx context.Context, ws *websocket.Conn) {
		sendEnv(t, ctx, ws, proto.TypeLoginStart, testJobID, proto.LoginStart{})
		waitFor(t, ctx, ws, proto.TypeLoginURL)
		sendEnv(t, ctx, ws, proto.TypeLoginCode, testJobID, proto.LoginCode{Code: goodCode})
		waitFor(t, ctx, ws, proto.TypeLoginDone)
	})
	logs := r.log.String()
	if !strings.Contains(logs, "login_start") {
		t.Fatalf("expected login log lines, got %s", logs)
	}
	for _, secret := range []string{plantState, "oauth/authorize", goodCode, "fresh", fakeIdent, "example.invalid", fakeRefresh} {
		if strings.Contains(logs, secret) {
			t.Fatalf("log leaks %q: %s", secret, logs)
		}
	}
}

func TestCleanStaleLoginsRemovesStrays(t *testing.T) {
	dir := t.TempDir()
	stray := filepath.Join(dir, "login-deadbeef")
	if err := os.MkdirAll(filepath.Join(stray, "backups"), 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(stray, ".credentials.json"), []byte("x"), 0o600)
	keepDir := filepath.Join(dir, "other")
	_ = os.MkdirAll(keepDir, 0o700)
	keepFile := filepath.Join(dir, "login-notes.txt") // a file, not a dir: left alone
	_ = os.WriteFile(keepFile, []byte("x"), 0o600)
	cleanStaleLogins(dir)
	if !gone(stray) {
		t.Fatal("stray login dir survived")
	}
	if gone(keepDir) || gone(keepFile) {
		t.Fatal("unrelated entries were removed")
	}
}
