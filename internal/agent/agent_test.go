package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"claude-utilities/internal/credfile"
	"claude-utilities/internal/logx"
	"claude-utilities/internal/proto"
)

const (
	origSecret = "ACCESS-ORIGINAL-SECRET"
	newSecret  = "ACCESS-NEW-SECRET"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func testBlock(access string, expiryMs int64) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"accessToken":%q,"refreshToken":"r-%s","expiresAt":%d,"refreshTokenExpiresAt":%d,"scopes":["a"],"subscriptionType":"max","subscriptionTypeSource":"x","rateLimitTier":"t"}`,
		access, access, expiryMs, expiryMs))
}

func future() int64 { return time.Now().Add(24 * time.Hour).UnixMilli() }

func writeCreds(t *testing.T, path string, block json.RawMessage) {
	t.Helper()
	data := fmt.Sprintf(`{"claudeAiOauth":%s,"mcpOAuth":{"srv":{"k":"mcp-keep"}}}`, block)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func sameJSON(t *testing.T, a, b json.RawMessage) bool {
	t.Helper()
	var ba, bb bytes.Buffer
	if err := json.Compact(&ba, a); err != nil {
		t.Fatal(err)
	}
	if err := json.Compact(&bb, b); err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(ba.Bytes(), bb.Bytes())
}

// fakeServer is a TLS websocket server; handler runs once per connection after the hello.
type fakeServer struct {
	ts     *httptest.Server
	pin    string
	conns  atomic.Int32
	hellos chan proto.Hello
}

func newFakeServer(t *testing.T, handler func(ctx context.Context, ws *websocket.Conn, n int, h proto.Hello)) *fakeServer {
	t.Helper()
	fs := &fakeServer{hellos: make(chan proto.Hello, 16)}
	fs.ts = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		n := int(fs.conns.Add(1))
		ctx := r.Context()
		_, data, err := ws.Read(ctx)
		if err != nil {
			return
		}
		env, err := proto.Decode(data)
		if err != nil || env.Type != proto.TypeHello {
			return
		}
		var h proto.Hello
		_ = json.Unmarshal(env.Body, &h)
		fs.hellos <- h
		handler(ctx, ws, n, h)
	}))
	fs.ts.Config.ErrorLog = log.New(io.Discard, "", 0) // wrong-pin tests make clients abort the handshake
	fs.ts.StartTLS()
	t.Cleanup(fs.ts.Close)
	sum := sha256.Sum256(fs.ts.Certificate().Raw)
	fs.pin = hex.EncodeToString(sum[:])
	return fs
}

func sendEnv(t *testing.T, ctx context.Context, ws *websocket.Conn, typ, id string, body any) {
	t.Helper()
	b, err := proto.Encode(typ, id, body)
	if err != nil {
		t.Error(err)
		return
	}
	if err := ws.Write(ctx, websocket.MessageText, b); err != nil {
		t.Logf("server write: %v", err)
	}
}

func readEnv(ctx context.Context, ws *websocket.Conn) (proto.Envelope, error) {
	_, data, err := ws.Read(ctx)
	if err != nil {
		return proto.Envelope{}, err
	}
	return proto.Decode(data)
}

type rig struct {
	a     *agent
	log   *syncBuf
	creds string
	dir   string
}

func newRig(t *testing.T, serverURL, pin string) *rig {
	t.Helper()
	dir := t.TempDir()
	creds := filepath.Join(dir, ".credentials.json")
	logs := &syncBuf{}
	a := newAgent(Config{ServerURL: serverURL, Token: "tok-AGENT-SECRET", Pin: pin, CredsPath: creds, StateDir: dir}, logx.New(logs))
	a.delay = func(int) time.Duration { return time.Millisecond }
	a.heartbeat = 20 * time.Millisecond
	a.hostName = "test-host"
	a.identity = func() string { return "id-1" }
	a.scan = func(context.Context) ([]proto.Session, error) { return nil, nil }
	return &rig{a: a, log: logs, creds: creds, dir: dir}
}

func (r *rig) start(t *testing.T) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.a.run(ctx) }()
	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("agent did not stop")
			}
		})
	}
}

func recvHello(t *testing.T, fs *fakeServer) proto.Hello {
	t.Helper()
	select {
	case h := <-fs.hellos:
		return h
	case <-time.After(5 * time.Second):
		t.Fatal("no hello")
		return proto.Hello{}
	}
}

func TestNextDelayGrowsAndCaps(t *testing.T) {
	for attempt := 0; attempt < 40; attempt++ {
		nominal := time.Duration(1<<min(attempt, 10)) * time.Second
		if nominal > 60*time.Second {
			nominal = 60 * time.Second
		}
		for i := 0; i < 50; i++ {
			d := NextDelay(attempt)
			if d > nominal || d < nominal*8/10 {
				t.Fatalf("attempt %d: %v outside [%v, %v]", attempt, d, nominal*8/10, nominal)
			}
		}
	}
	for _, a := range []int{-5, 1 << 30} {
		if d := NextDelay(a); d <= 0 || d > 60*time.Second {
			t.Fatalf("attempt %d: %v", a, d)
		}
	}
}

func TestReconnectsAfterServerDrop(t *testing.T) {
	fs := newFakeServer(t, func(ctx context.Context, ws *websocket.Conn, n int, _ proto.Hello) {
		if n == 1 {
			_ = ws.Close(websocket.StatusGoingAway, "drop")
			return
		}
		for {
			if _, err := readEnv(ctx, ws); err != nil {
				return
			}
		}
	})
	r := newRig(t, fs.ts.URL, fs.pin)
	writeCreds(t, r.creds, testBlock(origSecret, future()))
	stop := r.start(t)
	defer stop()
	h1, h2 := recvHello(t, fs), recvHello(t, fs)
	if h1.Token != "tok-AGENT-SECRET" || h2.Token != h1.Token || h2.HostName != "test-host" {
		t.Fatalf("hellos: %+v %+v", h1.HostName, h2.HostName)
	}
}

func TestRejectsServerWithWrongPin(t *testing.T) {
	fs := newFakeServer(t, func(context.Context, *websocket.Conn, int, proto.Hello) {})
	wrong := strings.Repeat("0", 64)
	r := newRig(t, fs.ts.URL, wrong)
	stop := r.start(t)
	time.Sleep(300 * time.Millisecond)
	stop()
	if n := fs.conns.Load(); n != 0 {
		t.Fatalf("agent completed %d websocket handshakes with a wrongly pinned server", n)
	}
	if len(fs.hellos) != 0 {
		t.Fatal("agent sent a hello (and its token) to a wrongly pinned server")
	}
	if strings.Contains(r.log.String(), "tok-AGENT-SECRET") {
		t.Fatal("token in log")
	}
	// A missing pin and a plaintext URL fail closed too.
	if _, err := dialPinned(context.Background(), fs.ts.URL, ""); err == nil {
		t.Fatal("empty pin accepted")
	}
	if _, err := dialPinned(context.Background(), strings.Replace(fs.ts.URL, "https", "http", 1), fs.pin); !errors.Is(err, ErrInsecureURL) {
		t.Fatalf("plaintext url: %v", err)
	}
}

func TestExportReqReturnsLiveBlockWithoutLoggingIt(t *testing.T) {
	var res proto.ExportRes
	got := make(chan struct{})
	fs := newFakeServer(t, func(ctx context.Context, ws *websocket.Conn, _ int, _ proto.Hello) {
		sendEnv(t, ctx, ws, proto.TypeExportReq, "e1", nil)
		for {
			env, err := readEnv(ctx, ws)
			if err != nil {
				return
			}
			if env.Type == proto.TypeExportRes && env.ID == "e1" {
				_ = json.Unmarshal(env.Body, &res)
				close(got)
				return
			}
		}
	})
	r := newRig(t, fs.ts.URL, fs.pin)
	block := testBlock(origSecret, future())
	writeCreds(t, r.creds, block)
	stop := r.start(t)
	defer stop()
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("no export_res")
	}
	if !sameJSON(t, res.Block, block) || res.Identity != "id-1" || res.Err != "" {
		t.Fatalf("export: identity=%q err=%q", res.Identity, res.Err)
	}
	stop()
	for _, secret := range []string{origSecret, "r-" + origSecret, "tok-AGENT-SECRET"} {
		if strings.Contains(r.log.String(), secret) {
			t.Fatalf("log leaks %q: %s", secret, r.log.String())
		}
	}
}

func TestExportReqWithoutLoginReportsError(t *testing.T) {
	r := newRig(t, "https://x", strings.Repeat("0", 64))
	res := r.a.export()
	if res.Err == "" || len(res.Block) != 0 {
		t.Fatalf("export of missing file: %+v", res.Err)
	}
}

func TestSwapAppliesBlockAndVerifiesReadBack(t *testing.T) {
	var res proto.SwapRes
	got := make(chan struct{})
	next := testBlock(newSecret, future())
	fs := newFakeServer(t, func(ctx context.Context, ws *websocket.Conn, _ int, _ proto.Hello) {
		sendEnv(t, ctx, ws, proto.TypeSwapReq, "s1", proto.SwapReq{Block: next, Account: "acct-b"})
		for {
			env, err := readEnv(ctx, ws)
			if err != nil {
				return
			}
			if env.Type == proto.TypeSwapRes && env.ID == "s1" {
				_ = json.Unmarshal(env.Body, &res)
				close(got)
				return
			}
		}
	})
	r := newRig(t, fs.ts.URL, fs.pin)
	writeCreds(t, r.creds, testBlock(origSecret, future()))
	stop := r.start(t)
	defer stop()
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("no swap_res")
	}
	if !res.OK {
		t.Fatalf("swap failed: %s", res.Reason)
	}
	live, err := credfile.ReadBlock(r.creds)
	if err != nil || !sameJSON(t, live, next) {
		t.Fatalf("live block not replaced: %v", err)
	}
	raw, _ := os.ReadFile(r.creds)
	if !strings.Contains(string(raw), "mcp-keep") {
		t.Fatal("mcpOAuth dropped")
	}
	if _, err := os.Stat(journalPath(r.dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal left behind: %v", err)
	}
	stop()
	if strings.Contains(r.log.String(), newSecret) {
		t.Fatal("log leaks new block")
	}
}

func TestSwapRollsBackWhenReadBackFails(t *testing.T) {
	r := newRig(t, "https://x", strings.Repeat("0", 64))
	orig := testBlock(origSecret, future())
	writeCreds(t, r.creds, orig)
	r.a.readBack = func(string) (json.RawMessage, error) { return testBlock("SOMETHING-ELSE", future()), nil }
	res := r.a.applySwap(proto.SwapReq{Block: testBlock(newSecret, future()), Account: "acct-b"})
	if res.OK || res.Reason == "" {
		t.Fatalf("expected failure, got %+v", res)
	}
	live, err := credfile.ReadBlock(r.creds)
	if err != nil || !sameJSON(t, live, orig) {
		t.Fatalf("original not restored: %v", err)
	}
	if _, err := os.Stat(journalPath(r.dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal left behind after rollback: %v", err)
	}
	// Read-back error (not just mismatch) rolls back as well.
	r.a.readBack = func(string) (json.RawMessage, error) { return nil, errors.New("disk gone") }
	if res := r.a.applySwap(proto.SwapReq{Block: testBlock(newSecret, future())}); res.OK {
		t.Fatal("read-back error accepted")
	}
	if live, _ := credfile.ReadBlock(r.creds); !sameJSON(t, live, orig) {
		t.Fatal("original not restored after read-back error")
	}
}

func TestSwapRefusesExpiredRefreshToken(t *testing.T) {
	r := newRig(t, "https://x", strings.Repeat("0", 64))
	orig := testBlock(origSecret, future())
	writeCreds(t, r.creds, orig)
	expired := testBlock(newSecret, time.Now().Add(-time.Hour).UnixMilli())
	res := r.a.applySwap(proto.SwapReq{Block: expired, Account: "acct-b"})
	if res.OK || res.Reason != "refresh token expired" {
		t.Fatalf("got %+v", res)
	}
	if live, _ := credfile.ReadBlock(r.creds); !sameJSON(t, live, orig) {
		t.Fatal("file changed despite refusal")
	}
	if _, err := os.Stat(journalPath(r.dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("journal written for a refused swap")
	}
	// A block missing keys is refused with a fixed reason that does not echo it.
	res = r.a.applySwap(proto.SwapReq{Block: json.RawMessage(`{"accessToken":"` + newSecret + `"}`)})
	if res.OK || strings.Contains(res.Reason, newSecret) {
		t.Fatalf("got %+v", res)
	}
}

func TestJournalRollsBackAfterCrash(t *testing.T) {
	r := newRig(t, "https://x", strings.Repeat("0", 64))
	orig := testBlock(origSecret, future())
	nextB := testBlock(newSecret, future())
	writeCreds(t, r.creds, orig)

	// Crash before the swap landed: the file is untouched, the journal is just cleared.
	if err := writeJournal(r.dir, journal{State: journalSwap, PrevHash: hashBlock(orig)}); err != nil {
		t.Fatal(err)
	}
	if err := r.a.recoverJournal(); err != nil {
		t.Fatal(err)
	}
	if live, _ := credfile.ReadBlock(r.creds); !sameJSON(t, live, orig) {
		t.Fatal("block changed by a no-op recovery")
	}
	if _, err := os.Stat(journalPath(r.dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("journal not cleared")
	}

	// Crash after the rename, before the journal learned the backup path.
	if err := writeJournal(r.dir, journal{State: journalSwap, PrevHash: hashBlock(orig), NewHash: hashBlock(nextB)}); err != nil {
		t.Fatal(err)
	}
	if _, err := credfile.Replace(r.creds, nextB); err != nil {
		t.Fatal(err)
	}
	if err := r.a.recoverJournal(); err != nil {
		t.Fatal(err)
	}
	live, err := credfile.ReadBlock(r.creds)
	if err != nil || !sameJSON(t, live, orig) {
		t.Fatalf("original not restored after crash: %v", err)
	}
	if _, err := os.Stat(journalPath(r.dir)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("journal not cleared after restore")
	}

	// Crash with the backup path recorded.
	backup, err := credfile.Replace(r.creds, nextB)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeJournal(r.dir, journal{State: journalSwap, PrevHash: hashBlock(orig), NewHash: hashBlock(nextB), BackupPath: backup}); err != nil {
		t.Fatal(err)
	}
	if err := r.a.recoverJournal(); err != nil {
		t.Fatal(err)
	}
	if live, _ := credfile.ReadBlock(r.creds); !sameJSON(t, live, orig) {
		t.Fatal("original not restored via recorded backup")
	}
	raw, _ := os.ReadFile(r.creds)
	if !strings.Contains(string(raw), "mcp-keep") {
		t.Fatal("mcpOAuth dropped by recovery")
	}

	// run() recovers before it dials: swap, leave a journal, start the agent.
	if _, err := credfile.Replace(r.creds, nextB); err != nil {
		t.Fatal(err)
	}
	if err := writeJournal(r.dir, journal{State: journalSwap, PrevHash: hashBlock(orig), NewHash: hashBlock(nextB)}); err != nil {
		t.Fatal(err)
	}
	fs := newFakeServer(t, func(ctx context.Context, ws *websocket.Conn, _ int, _ proto.Hello) {
		for {
			if _, err := readEnv(ctx, ws); err != nil {
				return
			}
		}
	})
	r.a.cfg.ServerURL, r.a.cfg.Pin = fs.ts.URL, fs.pin
	stop := r.start(t)
	recvHello(t, fs)
	stop()
	if live, _ := credfile.ReadBlock(r.creds); !sameJSON(t, live, orig) {
		t.Fatal("run did not recover the journal at startup")
	}
}

func TestJournalWithNoMatchingBackupKeepsJournal(t *testing.T) {
	r := newRig(t, "https://x", strings.Repeat("0", 64))
	writeCreds(t, r.creds, testBlock(newSecret, future()))
	if err := writeJournal(r.dir, journal{State: journalSwap, PrevHash: hashBlock(testBlock(origSecret, future())), NewHash: currentHash(r.creds)}); err != nil {
		t.Fatal(err)
	}
	if err := r.a.recoverJournal(); err == nil {
		t.Fatal("recovery without a backup reported success")
	}
	if _, err := os.Stat(journalPath(r.dir)); err != nil {
		t.Fatal("journal dropped though nothing was restored")
	}
	res := r.a.applySwap(proto.SwapReq{Block: testBlock("ACCESS-THIRD", future())})
	if res.OK {
		t.Fatal("swap proceeded over an unrecovered journal")
	}
}

func TestMissingCredsFileReportsCredsPresentFalse(t *testing.T) {
	r := newRig(t, "https://x", strings.Repeat("0", 64))
	rep := r.a.report(context.Background())
	if rep.CredsPresent || rep.ActiveIdentity != "" {
		t.Fatalf("report for missing file: %+v", rep)
	}
	b, err := json.Marshal(rep)
	if err != nil || !strings.Contains(string(b), `"sessions":[]`) {
		t.Fatalf("sessions must marshal as []: %s %v", b, err)
	}
	writeCreds(t, r.creds, testBlock(origSecret, future()))
	if rep := r.a.report(context.Background()); !rep.CredsPresent || rep.ActiveIdentity != "id-1" {
		t.Fatalf("report with file: %+v", rep)
	}
}

func TestHeartbeatCarriesSessions(t *testing.T) {
	want := proto.Session{PID: 42, ID: "sess-1", Cwd: "/w", StartedAt: time.UnixMilli(1700000000000)}
	reports := make(chan proto.Report, 8)
	fs := newFakeServer(t, func(ctx context.Context, ws *websocket.Conn, _ int, _ proto.Hello) {
		for {
			env, err := readEnv(ctx, ws)
			if err != nil {
				return
			}
			if env.Type == proto.TypeReport {
				var rep proto.Report
				_ = json.Unmarshal(env.Body, &rep)
				reports <- rep
			}
		}
	})
	r := newRig(t, fs.ts.URL, fs.pin)
	writeCreds(t, r.creds, testBlock(origSecret, future()))
	r.a.scan = func(context.Context) ([]proto.Session, error) { return []proto.Session{want}, nil }
	stop := r.start(t)
	defer stop()
	for i := 0; i < 3; i++ { // the initial report plus at least two heartbeats
		select {
		case rep := <-reports:
			if len(rep.Sessions) != 1 || rep.Sessions[0].ID != want.ID || rep.Sessions[0].PID != 42 || !rep.CredsPresent {
				t.Fatalf("report %d: %+v", i, rep)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d reports", i)
		}
	}
}

func TestReadIdentity(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".claude.json")
	if got := readIdentity(p); got != "" {
		t.Fatalf("missing file: %q", got)
	}
	_ = os.WriteFile(p, []byte(`{"oauthAccount":{"emailAddress":"a@example.test","accountUuid":"u-1"}}`), 0o600)
	if got := readIdentity(p); got != "a@example.test" {
		t.Fatalf("got %q", got)
	}
	_ = os.WriteFile(p, []byte(`{"oauthAccount":{"accountUuid":"u-1"}}`), 0o600)
	if got := readIdentity(p); got != "u-1" {
		t.Fatalf("got %q", got)
	}
	_ = os.WriteFile(p, []byte(`not json`), 0o600)
	if got := readIdentity(p); got != "" {
		t.Fatalf("corrupt file: %q", got)
	}
}

func TestConfigRoundTripAndMasking(t *testing.T) {
	dir := t.TempDir()
	c := Config{ServerURL: "https://h:1", Token: "tok-ROUNDTRIP", Pin: "ab", CredsPath: "/c", StateDir: dir}
	if err := SaveConfig(c); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(dir)
	if err != nil || got.Token != c.Token || got.ServerURL != c.ServerURL || got.StateDir != dir {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	for _, s := range []string{fmt.Sprint(c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c)} {
		if strings.Contains(s, "tok-ROUNDTRIP") {
			t.Fatalf("Config prints its token: %s", s)
		}
	}
	if _, err := LoadConfig(t.TempDir()); err == nil {
		t.Fatal("missing config accepted")
	}
}
