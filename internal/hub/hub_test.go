package hub

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"claude-utilities/internal/logx"
	"claude-utilities/internal/ownership"
	"claude-utilities/internal/proto"
	"claude-utilities/internal/vault"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

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

type fixture struct {
	t        *testing.T
	h        *Hub
	srv      *httptest.Server
	clk      *clock
	v        *vault.Vault
	reg      *ownership.Registry
	logs     *syncBuf
	tokens   string
	rejMu    sync.Mutex
	rejected []error
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	t.Setenv("HUB_TEST_KEY", "test-passphrase")
	dir := t.TempDir()
	v, err := vault.Open(filepath.Join(dir, "vault.bin"), "HUB_TEST_KEY")
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, v: v, reg: ownership.New(), logs: &syncBuf{}, tokens: filepath.Join(dir, "hosts.json"),
		clk: &clock{t: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}}
	f.h = New(v, f.reg, f.tokens, logx.New(f.logs))
	f.h.now = f.clk.Now
	f.h.ipOf = func(r *http.Request) string {
		if ip := r.Header.Get("X-Test-IP"); ip != "" {
			return ip
		}
		return "10.0.0.1"
	}
	f.h.onReject = func(err error) {
		f.rejMu.Lock()
		f.rejected = append(f.rejected, err)
		f.rejMu.Unlock()
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.h.ServeWS))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fixture) rejections() []error {
	f.rejMu.Lock()
	defer f.rejMu.Unlock()
	return append([]error(nil), f.rejected...)
}

func (f *fixture) waitRejected(want error) {
	f.t.Helper()
	eventually(f.t, func() bool {
		for _, e := range f.rejections() {
			if errors.Is(e, want) {
				return true
			}
		}
		return false
	})
}

func eventually(t *testing.T, cond func() bool) {
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

type agent struct {
	t    *testing.T
	ws   *websocket.Conn
	mu   sync.Mutex
	seen []string // every envelope type received, in order
}

func (f *fixture) dial(ip string, hello proto.Hello) *agent {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	hdr := http.Header{}
	if ip != "" {
		hdr.Set("X-Test-IP", ip)
	}
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(f.srv.URL, "http"), &websocket.DialOptions{HTTPHeader: hdr})
	if err != nil {
		f.t.Fatal(err)
	}
	a := &agent{t: f.t, ws: ws}
	f.t.Cleanup(func() { _ = ws.CloseNow() })
	a.send(proto.TypeHello, "", hello)
	return a
}

// dialQuiet is dial for goroutines: it never calls t.Fatal and returns nil on failure.
func (f *fixture) dialQuiet(ip string, hello proto.Hello) *agent {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(f.srv.URL, "http"),
		&websocket.DialOptions{HTTPHeader: http.Header{"X-Test-Ip": []string{ip}}})
	if err != nil {
		return nil
	}
	b, _ := proto.Encode(proto.TypeHello, "", hello)
	if err := ws.Write(ctx, websocket.MessageText, b); err != nil {
		_ = ws.CloseNow()
		return nil
	}
	return &agent{t: f.t, ws: ws}
}

func (a *agent) send(typ, id string, body any) {
	a.t.Helper()
	b, err := proto.Encode(typ, id, body)
	if err != nil {
		a.t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := a.ws.Write(ctx, websocket.MessageText, b); err != nil {
		a.t.Fatal(err)
	}
}

func (a *agent) recvWithin(d time.Duration) (proto.Envelope, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	_, data, err := a.ws.Read(ctx)
	if err != nil {
		return proto.Envelope{}, err
	}
	env, err := proto.Decode(data)
	if err != nil {
		a.t.Fatal(err)
	}
	a.mu.Lock()
	a.seen = append(a.seen, env.Type)
	a.mu.Unlock()
	return env, nil
}

func (a *agent) recv(wantType string) proto.Envelope {
	a.t.Helper()
	env, err := a.recvWithin(3 * time.Second)
	if err != nil {
		a.t.Fatalf("waiting for %s: %v", wantType, err)
	}
	if env.Type != wantType {
		a.t.Fatalf("got %s, want %s", env.Type, wantType)
	}
	return env
}

func (a *agent) types() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.seen...)
}

// expectClosed reads until the server closes the socket and checks the close reason.
func (a *agent) expectClosed(reason string) {
	a.t.Helper()
	for {
		_, err := a.recvWithin(3 * time.Second)
		if err == nil {
			continue
		}
		if websocket.CloseStatus(err) == -1 {
			a.t.Fatalf("not a clean close: %v", err)
		}
		if reason != "" && !strings.Contains(err.Error(), `"`+reason+`"`) {
			a.t.Fatalf("close error %q lacks reason %q", err, reason)
		}
		return
	}
}

// enrol joins by pre-approved code and returns the agent plus its token and host id.
func (f *fixture) enrol(name string) (a *agent, token, hostID string) {
	f.t.Helper()
	code, _ := f.h.NewEnrolCode()
	a = f.dial("", proto.Hello{Code: code, HostName: name, OS: "linux", Nonce: "n-" + name})
	var ap proto.Approved
	if err := json.Unmarshal(a.recv(proto.TypeApproved).Body, &ap); err != nil {
		f.t.Fatal(err)
	}
	var id string
	eventually(f.t, func() bool {
		for _, hv := range f.h.Hosts() {
			if hv.Name == name && hv.Online {
				id = hv.HostID
			}
		}
		return id != ""
	})
	return a, ap.Token, id
}

func TestEnrolCodeSingleUse(t *testing.T) {
	f := newFixture(t)
	code, _ := f.h.NewEnrolCode()
	a := f.dial("", proto.Hello{Code: code, HostName: "box", OS: "linux", Nonce: "1"})
	a.recv(proto.TypeApproved)
	b := f.dial("", proto.Hello{Code: code, HostName: "box2", OS: "linux", Nonce: "2"})
	b.expectClosed("bad code")
	f.waitRejected(ErrBadCode)
}

func TestEnrolCodeExpires(t *testing.T) {
	f := newFixture(t)
	code, exp := f.h.NewEnrolCode()
	if !exp.Equal(f.clk.Now().Add(EnrolCodeTTL)) {
		t.Fatalf("expiry %v", exp)
	}
	f.clk.Advance(EnrolCodeTTL + time.Second)
	a := f.dial("", proto.Hello{Code: code, HostName: "box", OS: "linux", Nonce: "1"})
	a.expectClosed("bad code")
	f.waitRejected(ErrBadCode)
}

func TestBadTokenRejected(t *testing.T) {
	f := newFixture(t)
	a := f.dial("", proto.Hello{Token: "not-a-token", HostName: "box", OS: "linux"})
	a.expectClosed("bad token")
	f.waitRejected(ErrBadToken)
}

func TestRevokedTokenRejected(t *testing.T) {
	f := newFixture(t)
	a, token, id := f.enrol("box")
	if err := f.h.Revoke(id); err != nil {
		t.Fatal(err)
	}
	a.expectClosed("revoked")
	b := f.dial("", proto.Hello{Token: token, HostName: "box", OS: "linux"})
	b.expectClosed("revoked")
	f.waitRejected(ErrRevoked)
	if len(f.h.Hosts()) != 0 {
		t.Fatal("revoked host still listed")
	}
	if err := f.h.Revoke("nope"); !errors.Is(err, ErrUnknownHost) {
		t.Fatalf("got %v", err)
	}
}

func TestEnrolledHostSurvivesRestartWithHashOnly(t *testing.T) {
	f := newFixture(t)
	_, token, id := f.enrol("box")
	raw, err := os.ReadFile(f.tokens)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(token))
	if strings.Contains(string(raw), token) || !strings.Contains(string(raw), hex.EncodeToString(sum[:])) {
		t.Fatalf("tokens file must hold only the SHA-256: %s", raw)
	}
	h2 := New(f.v, ownership.New(), f.tokens, logx.New(&syncBuf{}))
	if v := h2.Hosts(); len(v) != 1 || v[0].HostID != id || v[0].Online {
		t.Fatalf("restart view: %+v", v)
	}
}

// The session census is logged as counts. A session's name and cwd may carry a person's
// name or a path, so neither may ever reach a log line.
func TestSessionCensusLogsCountsNeverNamesOrPaths(t *testing.T) {
	f := newFixture(t)
	a, _, _ := f.enrol("box")
	const name, cwd = "planted-name-abc", "/planted/path/xyz"
	rep := proto.Report{Sessions: []proto.Session{
		{PID: 1, ID: "s1", Name: name, Cwd: cwd, Status: "busy", RemoteControl: true},
		{PID: 2, ID: "s2", Cwd: cwd},
	}}
	a.send(proto.TypeReport, "", rep)
	eventually(t, func() bool { return strings.Contains(f.logs.String(), "host sessions changed") })
	out := f.logs.String()
	for _, leak := range []string{name, cwd, "planted"} {
		if strings.Contains(out, leak) {
			t.Fatalf("leaked %q into logs:\n%s", leak, out)
		}
	}
	for _, want := range []string{`"sessionCount":2`, `"namedCount":1`, `"remoteCount":1`} {
		if !strings.Contains(out, want) {
			t.Fatalf("log lacks %s:\n%s", want, out)
		}
	}
	if strings.Contains(out, "[dropped]") {
		t.Fatalf("a census key is not allowlisted:\n%s", out)
	}
	// Reports arrive on every heartbeat, so an unchanged census must not log again.
	before := strings.Count(out, "host sessions changed")
	a.send(proto.TypeReport, "", rep)
	a.send(proto.TypeHeartbeat, "", nil)
	eventually(t, func() bool { return len(f.h.Hosts()[0].Sessions) == 2 })
	if got := strings.Count(f.logs.String(), "host sessions changed"); got != before {
		t.Fatalf("unchanged census logged %d times, want %d", got, before)
	}
}

func TestSessionTallyCountsNamedAndRemote(t *testing.T) {
	got := tallySessions([]proto.Session{
		{PID: 1, Name: "a"},
		{PID: 2},                  // unnamed
		{PID: 3, RemoteName: "r"}, // a remote name counts as named
		{PID: 4, Name: "d", RemoteControl: true},
	})
	if want := (sessionTally{total: 4, named: 3, remote: 1, set: true}); got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	// A host with no sessions is still "reported": the zero tally must differ from unset.
	if empty := tallySessions(nil); empty == (sessionTally{}) {
		t.Fatal("an empty report must not look like a host that never reported")
	}
}

func TestHeartbeatTimeoutMarksOffline(t *testing.T) {
	f := newFixture(t)
	a, _, id := f.enrol("box")
	f.reg.SwapIn("A", id)
	f.clk.Advance(OfflineAfter - time.Second)
	if !f.h.Hosts()[0].Online {
		t.Fatal("offline too early")
	}
	f.clk.Advance(2 * time.Second)
	if f.h.Hosts()[0].Online {
		t.Fatal("still online after 45 s of silence")
	}
	a.expectClosed("heartbeat timeout")
	if !f.reg.OwnerOf("A").Server {
		t.Fatal("lost host must give up ownership")
	}
}

func TestSwapRefusesOfflineHost(t *testing.T) {
	f := newFixture(t)
	f.seedAccounts()
	a, _, id := f.enrol("box")
	f.clk.Advance(OfflineAfter + time.Second)
	if _, err := f.h.Swap(context.Background(), id, "B"); !errors.Is(err, ErrAgentOffline) {
		t.Fatalf("got %v", err)
	}
	a.expectClosed("")
	if _, err := f.h.Swap(context.Background(), "ghost", "B"); !errors.Is(err, ErrUnknownHost) {
		t.Fatalf("got %v", err)
	}
}

func (f *fixture) seedAccounts() {
	f.t.Helper()
	for _, a := range []vault.Account{
		{ID: "A", Label: "a", Identity: "id-a", Block: json.RawMessage(`{"tok":"A-stored"}`)},
		{ID: "B", Label: "b", Identity: "id-b", Block: json.RawMessage(`{"tok":"B-stored"}`)},
		{ID: "C", Label: "c", Identity: "id-c", Block: json.RawMessage(`{"tok":"C-stored"}`)},
	} {
		if err := f.v.Put(a); err != nil {
			f.t.Fatal(err)
		}
	}
}

// script drives a fake agent's answers to export and swap requests.
type script struct {
	mu          sync.Mutex
	identity    string // the host's live identity
	liveBlock   string
	swapOK      bool
	swapDelay   time.Duration
	order       []string
	liveAtSwap  json.RawMessage // vault copy of the live account when swap_req arrived
	swapBlocks  []string
	inflight    int
	overlapped  bool
	f           *fixture
	identityOf  map[string]string
	stopSwapRes bool
	// staleIdentity mimics the real agent: a swap rewrites the login but never ~/.claude.json,
	// so the reported identity keeps naming the previous account.
	staleIdentity bool
	// home is the proto.Home* code the fake agent reports in its swap result ("" like an older agent).
	home string
}

func (f *fixture) newScript(identity, block string) *script {
	return &script{f: f, identity: identity, liveBlock: block, swapOK: true,
		identityOf: map[string]string{"A": "id-a", "B": "id-b", "C": "id-c"}}
}

func (s *script) serve(a *agent) {
	go func() {
		for {
			env, err := a.recvWithin(30 * time.Second)
			if err != nil {
				return
			}
			switch env.Type {
			case proto.TypeExportReq:
				s.mu.Lock()
				s.order = append(s.order, env.Type)
				if s.inflight > 0 {
					s.overlapped = true
				}
				s.inflight++
				res := proto.ExportRes{Identity: s.identity, Block: json.RawMessage(s.liveBlock)}
				s.mu.Unlock()
				a.send(proto.TypeExportRes, env.ID, res)
			case proto.TypeSwapReq:
				var req proto.SwapReq
				_ = json.Unmarshal(env.Body, &req)
				s.mu.Lock()
				s.order = append(s.order, env.Type)
				s.swapBlocks = append(s.swapBlocks, string(req.Block))
				if acct, ok := s.f.v.Get(s.identityFor()); ok {
					s.liveAtSwap = acct.Block
				}
				ok, delay, mute, home := s.swapOK, s.swapDelay, s.stopSwapRes, s.home
				s.mu.Unlock()
				if mute {
					continue // never answer: the hub must time out
				}
				time.Sleep(delay)
				s.mu.Lock()
				if ok {
					if !s.staleIdentity {
						s.identity = s.identityOf[req.Account]
					}
					s.liveBlock = string(req.Block)
				}
				s.inflight--
				s.mu.Unlock()
				res := proto.SwapRes{OK: ok, Home: home}
				if !ok {
					res.Reason = "refused by test"
				}
				a.send(proto.TypeSwapRes, env.ID, res)
			}
		}
	}()
}

// identityFor maps the script's live identity back to a vault account id. Callers hold s.mu.
func (s *script) identityFor() string {
	for id, ident := range s.identityOf {
		if ident == s.identity {
			return id
		}
	}
	return ""
}

func (s *script) snapshot() (order []string, blocks []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.order...), append([]string(nil), s.swapBlocks...)
}

func TestSwapWritesBackLiveBlockBeforeSending(t *testing.T) {
	f := newFixture(t)
	f.seedAccounts()
	a, _, id := f.enrol("box")
	f.reg.SwapIn("A", id)
	s := f.newScript("id-a", `{"tok":"A-refreshed"}`)
	s.serve(a)
	if _, err := f.h.Swap(context.Background(), id, "B"); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	got := string(s.liveAtSwap)
	s.mu.Unlock()
	if got != `{"tok":"A-refreshed"}` {
		t.Fatalf("vault held %q when swap_req arrived", got)
	}
	if order, blocks := s.snapshot(); len(order) != 2 || order[0] != proto.TypeExportReq || order[1] != proto.TypeSwapReq ||
		blocks[0] != `{"tok":"B-stored"}` {
		t.Fatalf("order %v blocks %v", order, blocks)
	}
	if o := f.reg.OwnerOf("B"); o.HostID != id {
		t.Fatalf("owner of B: %+v", o)
	}
}

func TestSwapUnknownLiveAccountReturnsErrUnknownLiveAccountAndSendsNothing(t *testing.T) {
	f := newFixture(t)
	f.seedAccounts()
	a, _, id := f.enrol("box")
	s := f.newScript("id-stranger", `{"tok":"hand-login"}`)
	s.serve(a)
	_, err := f.h.Swap(context.Background(), id, "B")
	if !errors.Is(err, ErrUnknownLiveAccount) {
		t.Fatalf("got %v", err)
	}
	if order, _ := s.snapshot(); len(order) != 1 || order[0] != proto.TypeExportReq {
		t.Fatalf("agent saw %v; only the export request is allowed", order)
	}
	for _, acct := range f.v.List() {
		if strings.Contains(string(acct.Block), "hand-login") {
			t.Fatal("unknown login was written into the vault")
		}
	}
	if !f.reg.OwnerOf("B").Server {
		t.Fatal("ownership changed")
	}
}

func TestSwapFailureLeavesOwnershipUnchanged(t *testing.T) {
	f := newFixture(t)
	f.seedAccounts()
	a, _, id := f.enrol("box")
	f.reg.SwapIn("A", id)
	s := f.newScript("id-a", `{"tok":"A-live"}`)
	s.swapOK = false
	s.serve(a)
	_, err := f.h.Swap(context.Background(), id, "B")
	if err == nil || !strings.Contains(err.Error(), "refused by test") {
		t.Fatalf("got %v", err)
	}
	if f.reg.OwnerOf("A").HostID != id || !f.reg.OwnerOf("B").Server {
		t.Fatal("ownership must not move on a failed swap")
	}
}

func TestSwapSuccessMarksSessionsNeedsReload(t *testing.T) {
	f := newFixture(t)
	f.seedAccounts()
	a, _, id := f.enrol("box")
	s := f.newScript("id-a", `{"tok":"A-live"}`)
	s.serve(a)
	old := f.clk.Now().Add(-time.Hour)
	a.send(proto.TypeReport, "", proto.Report{ActiveIdentity: "id-a", CredsPresent: true,
		Sessions: []proto.Session{{PID: 1, ID: "s1", Cwd: "/x", StartedAt: old}}})
	eventually(t, func() bool { return len(f.h.Hosts()[0].Sessions) == 1 })
	if v := f.h.Hosts()[0]; v.ActiveAccount != "A" || v.Sessions[0].NeedsReload {
		t.Fatalf("before swap: %+v", v)
	}
	if _, err := f.h.Swap(context.Background(), id, "B"); err != nil {
		t.Fatal(err)
	}
	v := f.h.Hosts()[0]
	if !v.Sessions[0].NeedsReload || v.ActiveAccount != "B" {
		t.Fatalf("after swap: %+v", v)
	}
}

func TestConcurrentSwapsSameHostSerialised(t *testing.T) {
	f := newFixture(t)
	f.seedAccounts()
	a, _, id := f.enrol("box")
	s := f.newScript("id-a", `{"tok":"A-live"}`)
	s.swapDelay = 40 * time.Millisecond
	s.serve(a)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, target := range []string{"B", "C"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = f.h.Swap(context.Background(), id, target)
		}()
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("swaps failed: %v %v", errs[0], errs[1])
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.overlapped {
		t.Fatal("two swaps were in flight on one host")
	}
}

func TestTokenNeverInLogs(t *testing.T) {
	f := newFixture(t)
	code, _ := f.h.NewEnrolCode()
	a := f.dial("", proto.Hello{Code: code, HostName: "box", OS: "linux", Nonce: "1"})
	var ap1 proto.Approved
	_ = json.Unmarshal(a.recv(proto.TypeApproved).Body, &ap1)
	b := f.dial("", proto.Hello{HostName: "box2", OS: "linux", Nonce: "2"})
	env := b.recv(proto.TypePending)
	var p proto.Pending
	_ = json.Unmarshal(env.Body, &p)
	if _, err := f.h.Allow(p.Fingerprint); err != nil {
		t.Fatal(err)
	}
	var ap2 proto.Approved
	_ = json.Unmarshal(b.recv(proto.TypeApproved).Body, &ap2)
	c := f.dial("", proto.Hello{Token: ap1.Token, HostName: "box", OS: "linux"})
	_ = c
	bad := f.dial("", proto.Hello{Token: "wrong-token-value", Code: "wrong-code-value", HostName: "x", OS: "y"})
	bad.expectClosed("")
	eventually(t, func() bool { return strings.Contains(f.logs.String(), "agent connected") })
	out := f.logs.String()
	for _, secret := range []string{ap1.Token, ap2.Token, code, "wrong-token-value", "wrong-code-value"} {
		if secret == "" || strings.Contains(out, secret) {
			t.Fatalf("secret %q leaked into logs:\n%s", secret, out)
		}
	}
}

func TestEnsureCertStableFingerprintAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	c1, k1, fp1, err := EnsureCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	c2, k2, fp2, err := EnsureCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fp1 != fp2 || c1 != c2 || k1 != k2 || len(fp1) != 64 {
		t.Fatalf("fingerprint changed: %q vs %q", fp1, fp2)
	}
	_, _, fp3, err := EnsureCert(t.TempDir())
	if err != nil || fp3 == fp1 {
		t.Fatalf("separate dirs must differ: %v", err)
	}
	// A corrupt pair is replaced rather than trusted.
	if err := os.WriteFile(k1, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, fp4, err := EnsureCert(dir); err != nil || fp4 == fp1 {
		t.Fatalf("corrupt key not regenerated: %v", err)
	}
}
