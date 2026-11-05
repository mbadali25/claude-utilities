package hub

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"claude-utilities/internal/ownership"
	"claude-utilities/internal/proto"
	"claude-utilities/internal/vault"
)

const (
	addURL      = "https://claude.com/cai/oauth/authorize?code=true&state=PLANTED-STATE"
	addCodeVal  = "PLANTED-ONE-TIME-CODE-123"
	newBlock    = `{"claudeAiOauth":{"accessToken":"NEW-ACCESS","refreshToken":"NEW-REFRESH"},"mcpOAuth":{"x":1}}`
	newIdentity = "new.person@example.invalid"
)

// trySend is send for a background goroutine: a write that races the fixture's teardown is
// returned, never fatal, because t.Fatal outside the test goroutine is not allowed.
func (a *agent) trySend(typ, id string, body any) error {
	b, err := proto.Encode(typ, id, body)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return a.ws.Write(ctx, websocket.MessageText, b)
}

// loginAgent drives a fake agent's side of an add-account job.
type loginAgent struct {
	mu       sync.Mutex
	a        *agent
	url      string
	doneWith proto.LoginDone
	seen     []string
	codes    []string
	ids      []string
	cancels  int
	noURL    bool // never send login_url
}

func (f *fixture) loginAgent(a *agent) *loginAgent {
	la := &loginAgent{a: a, url: addURL, doneWith: proto.LoginDone{Block: json.RawMessage(newBlock), Identity: newIdentity}}
	go func() {
		for {
			env, err := a.recvWithin(30 * time.Second)
			if err != nil {
				return
			}
			la.mu.Lock()
			la.seen = append(la.seen, env.Type)
			la.ids = append(la.ids, env.ID)
			url, done, noURL := la.url, la.doneWith, la.noURL
			la.mu.Unlock()
			switch env.Type {
			case proto.TypeLoginStart:
				if !noURL {
					_ = a.trySend(proto.TypeLoginURL, env.ID, proto.LoginURL{URL: url})
				}
			case proto.TypeLoginCode:
				var lc proto.LoginCode
				_ = json.Unmarshal(env.Body, &lc)
				la.mu.Lock()
				la.codes = append(la.codes, lc.Code)
				la.mu.Unlock()
				_ = a.trySend(proto.TypeLoginDone, env.ID, done)
			case proto.TypeLoginCancel:
				la.mu.Lock()
				la.cancels++
				la.mu.Unlock()
			case proto.TypeExportReq:
				_ = a.trySend(proto.TypeExportRes, env.ID, proto.ExportRes{Identity: "id-a", Block: json.RawMessage(`{"tok":"A-stored"}`)})
			case proto.TypeSwapReq:
				_ = a.trySend(proto.TypeSwapRes, env.ID, proto.SwapRes{OK: true})
			}
		}
	}()
	return la
}

func (la *loginAgent) saw(typ string) bool {
	la.mu.Lock()
	defer la.mu.Unlock()
	for _, s := range la.seen {
		if s == typ {
			return true
		}
	}
	return false
}

func (f *fixture) waitState(id string, want AddState) AddView {
	f.t.Helper()
	var v AddView
	eventually(f.t, func() bool {
		var err error
		v, err = f.h.AddStatus(id)
		return err == nil && v.State == want
	})
	return v
}

var hex16 = regexp.MustCompile(`^[0-9a-f]{16}$`)

func TestAddAccountHappyPath(t *testing.T) {
	f := newFixture(t)
	a, _, host := f.enrol("box")
	la := f.loginAgent(a)
	id, err := f.h.AddAccount(context.Background(), host, "fresh")
	if err != nil || !hex16.MatchString(id) {
		t.Fatalf("id %q err %v", id, err)
	}
	v := f.waitState(id, AddAwaitingCode)
	if v.URL != addURL {
		t.Fatalf("url %q", v.URL)
	}
	if err := f.h.AddCode(id, addCodeVal); err != nil {
		t.Fatal(err)
	}
	v = f.waitState(id, AddDone)
	if v.Account == nil || v.Account.Label != "fresh" || v.Account.Identity != newIdentity || len(v.Account.Block) != 0 {
		t.Fatalf("view %+v", v)
	}
	got, ok := f.v.Get(v.Account.ID)
	if !ok || string(got.Block) != `{"accessToken":"NEW-ACCESS","refreshToken":"NEW-REFRESH"}` {
		t.Fatalf("vault block %q ok=%v (claudeAiOauth only)", got.Block, ok)
	}
	if o := f.reg.OwnerOf(v.Account.ID); o != (ownership.Owner{Server: true}) {
		t.Fatalf("owner %+v: an added account must be unowned", o)
	}
	if h := f.reg.HostsUsing(v.Account.ID); len(h) != 0 {
		t.Fatalf("hosts using %v", h)
	}
	for _, hv := range f.h.Hosts() {
		if hv.ActiveAccount != "" {
			t.Fatalf("host active account changed to %q", hv.ActiveAccount)
		}
	}
	la.mu.Lock()
	defer la.mu.Unlock()
	if len(la.ids) == 0 || la.ids[0] != id || len(la.codes) != 1 || la.codes[0] != addCodeVal {
		t.Fatalf("ids %v codes %v", la.ids, la.codes)
	}
	if v.URL != "" {
		t.Fatalf("done view still carries the url")
	}
}

func TestAddAccountDuplicateIdentity(t *testing.T) {
	f := newFixture(t)
	f.seedAccounts()
	a, _, host := f.enrol("box")
	la := f.loginAgent(a)
	la.doneWith = proto.LoginDone{Block: json.RawMessage(newBlock), Identity: "id-a"}
	id, err := f.h.AddAccount(context.Background(), host, "dup")
	if err != nil {
		t.Fatal(err)
	}
	f.waitState(id, AddAwaitingCode)
	if err := f.h.AddCode(id, addCodeVal); err != nil {
		t.Fatal(err)
	}
	v := f.waitState(id, AddFailed)
	if !strings.Contains(v.Error, "already stored") || v.Account != nil {
		t.Fatalf("view %+v", v)
	}
	if n := len(f.v.List()); n != 3 {
		t.Fatalf("vault has %d accounts", n)
	}
}

// A sign-in waits up to 10 minutes, so the label AddAccount checked at the start can be taken by an
// import or a rename before the login comes back. The shared store must refuse it, not store a
// second account under the same label.
func TestAddAccountLabelTakenDuringSignIn(t *testing.T) {
	f := newFixture(t)
	a, _, host := f.enrol("box")
	f.loginAgent(a)
	id, err := f.h.AddAccount(context.Background(), host, "fresh")
	if err != nil {
		t.Fatal(err)
	}
	f.waitState(id, AddAwaitingCode)
	if err := f.v.Put(vault.Account{ID: "Z", Label: "Fresh", Identity: "id-z", Block: json.RawMessage(`{"tok":"Z"}`)}); err != nil {
		t.Fatal(err)
	}
	if err := f.h.AddCode(id, addCodeVal); err != nil {
		t.Fatal(err)
	}
	v := f.waitState(id, AddFailed)
	if !strings.Contains(v.Error, "label already exists") || v.Account != nil {
		t.Fatalf("view %+v", v)
	}
	if n := len(f.v.List()); n != 1 {
		t.Fatalf("vault holds %d accounts; only the one that claimed the label may exist", n)
	}
}

func TestAddAccountBlockWithMcpOnlyRefused(t *testing.T) {
	f := newFixture(t)
	a, _, host := f.enrol("box")
	la := f.loginAgent(a)
	la.doneWith = proto.LoginDone{Block: json.RawMessage(`{"mcpOAuth":{"x":1}}`), Identity: newIdentity}
	id, _ := f.h.AddAccount(context.Background(), host, "mcp")
	f.waitState(id, AddAwaitingCode)
	_ = f.h.AddCode(id, addCodeVal)
	v := f.waitState(id, AddFailed)
	if !strings.Contains(v.Error, "mcpOAuth") || len(f.v.List()) != 0 {
		t.Fatalf("view %+v accounts %d", v, len(f.v.List()))
	}
}

func TestAddAccountAgentReportsError(t *testing.T) {
	f := newFixture(t)
	a, _, host := f.enrol("box")
	la := f.loginAgent(a)
	la.doneWith = proto.LoginDone{Err: "sign-in rejected for " + newIdentity}
	id, _ := f.h.AddAccount(context.Background(), host, "x")
	f.waitState(id, AddAwaitingCode)
	_ = f.h.AddCode(id, addCodeVal)
	v := f.waitState(id, AddFailed)
	if !strings.Contains(v.Error, "sign-in rejected") || strings.Contains(v.Error, newIdentity) {
		t.Fatalf("error %q (must be redacted)", v.Error)
	}
}

func TestAddAccountRejectsBadURLFromAgent(t *testing.T) {
	f := newFixture(t)
	a, _, host := f.enrol("box")
	la := f.loginAgent(a)
	la.url = "https://evil.example/cai/oauth/authorize?state=x"
	id, _ := f.h.AddAccount(context.Background(), host, "x")
	v := f.waitState(id, AddFailed)
	if strings.Contains(v.Error, "evil") || v.URL != "" {
		t.Fatalf("view %+v", v)
	}
	eventually(t, func() bool { return la.saw(proto.TypeLoginCancel) })
}

func TestAddAccountBusy(t *testing.T) {
	f := newFixture(t)
	a, _, host := f.enrol("box")
	f.loginAgent(a)
	id, err := f.h.AddAccount(context.Background(), host, "one")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.AddAccount(context.Background(), host, "two"); !errors.Is(err, ErrAddBusy) {
		t.Fatalf("err %v", err)
	}
	if err := f.h.AddCancel(id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.AddAccount(context.Background(), host, "two"); err != nil {
		t.Fatalf("after cancel: %v", err)
	}
}

func TestAddAccountValidationAndOffline(t *testing.T) {
	f := newFixture(t)
	if _, err := f.h.AddAccount(context.Background(), "nope", "l"); !errors.Is(err, ErrUnknownHost) {
		t.Fatalf("err %v", err)
	}
	_, _, host := f.enrol("box")
	if _, err := f.h.AddAccount(context.Background(), host, "  "); err == nil {
		t.Fatal("empty label accepted")
	}
	if _, err := f.h.AddAccount(context.Background(), host, strings.Repeat("x", 65)); err == nil {
		t.Fatal("long label accepted")
	}
}

func TestAddAccountAgentDropFails(t *testing.T) {
	f := newFixture(t)
	a, _, host := f.enrol("box")
	f.loginAgent(a)
	id, _ := f.h.AddAccount(context.Background(), host, "x")
	f.waitState(id, AddAwaitingCode)
	_ = a.ws.CloseNow()
	v := f.waitState(id, AddFailed)
	if !strings.Contains(v.Error, "agent offline") {
		t.Fatalf("error %q", v.Error)
	}
}

func TestAddAccountJobExpiresAfter10Min(t *testing.T) {
	f := newFixture(t)
	a, _, host := f.enrol("box")
	la := f.loginAgent(a)
	id, _ := f.h.AddAccount(context.Background(), host, "x")
	f.waitState(id, AddAwaitingCode)
	f.clk.Advance(9 * time.Minute)
	if v, _ := f.h.AddStatus(id); v.State != AddAwaitingCode {
		t.Fatalf("state %s after 9 min", v.State)
	}
	f.clk.Advance(2 * time.Minute)
	v, err := f.h.AddStatus(id)
	if err != nil || v.State != AddFailed || !strings.Contains(v.Error, "timed out") {
		t.Fatalf("view %+v err %v", v, err)
	}
	eventually(t, func() bool { return la.saw(proto.TypeLoginCancel) })
	if err := f.h.AddCode(id, addCodeVal); !errors.Is(err, ErrNotAwaitingCode) {
		t.Fatalf("code after expiry: %v", err)
	}
	// Finished jobs are swept 15 minutes after they end.
	f.clk.Advance(16 * time.Minute)
	if _, err := f.h.AddStatus(id); !errors.Is(err, ErrNoAdd) {
		t.Fatalf("swept job: %v", err)
	}
}

func TestAddCodeWrongState(t *testing.T) {
	f := newFixture(t)
	a, _, host := f.enrol("box")
	la := f.loginAgent(a)
	la.noURL = true
	id, _ := f.h.AddAccount(context.Background(), host, "x")
	if err := f.h.AddCode(id, addCodeVal); !errors.Is(err, ErrNotAwaitingCode) {
		t.Fatalf("err %v", err)
	}
	if err := f.h.AddCode("0000000000000000", addCodeVal); !errors.Is(err, ErrNoAdd) {
		t.Fatalf("unknown id: %v", err)
	}
	if err := f.h.AddCancel("0000000000000000"); !errors.Is(err, ErrNoAdd) {
		t.Fatalf("cancel unknown: %v", err)
	}
}

func TestAddCodeBadInput(t *testing.T) {
	f := newFixture(t)
	a, _, host := f.enrol("box")
	f.loginAgent(a)
	id, _ := f.h.AddAccount(context.Background(), host, "x")
	f.waitState(id, AddAwaitingCode)
	for _, c := range []string{"", "  ", strings.Repeat("a", 2049), "a\nb"} {
		if err := f.h.AddCode(id, c); err == nil {
			t.Fatalf("code %q accepted", c)
		}
	}
	if v, _ := f.h.AddStatus(id); v.State != AddAwaitingCode {
		t.Fatalf("a rejected code moved the job to %s", v.State)
	}
}

func TestAddStatusHidesURLOutsideAwaitingCode(t *testing.T) {
	f := newFixture(t)
	a, _, host := f.enrol("box")
	f.loginAgent(a)
	id, _ := f.h.AddAccount(context.Background(), host, "x")
	f.waitState(id, AddAwaitingCode)
	_ = f.h.AddCancel(id)
	v, _ := f.h.AddStatus(id)
	if v.State != AddCancelled || v.URL != "" {
		t.Fatalf("view %+v", v)
	}
	if _, err := f.h.AddStatus("nope"); !errors.Is(err, ErrNoAdd) {
		t.Fatalf("err %v", err)
	}
}

func TestAddCancelTellsAgent(t *testing.T) {
	f := newFixture(t)
	a, _, host := f.enrol("box")
	la := f.loginAgent(a)
	id, _ := f.h.AddAccount(context.Background(), host, "x")
	f.waitState(id, AddAwaitingCode)
	_ = f.h.AddCancel(id)
	eventually(t, func() bool { return la.saw(proto.TypeLoginCancel) })
	if err := f.h.AddCancel(id); err != nil { // cancelling a finished job is a no-op
		t.Fatalf("second cancel: %v", err)
	}
}

func TestDispatchLoginFramesNotProtocolViolation(t *testing.T) {
	f := newFixture(t)
	a, _, host := f.enrol("box")
	// A frame for a job the hub does not know is ignored; the connection stays up.
	a.send(proto.TypeLoginURL, "0000000000000000", proto.LoginURL{URL: addURL})
	a.send(proto.TypeLoginDone, "0000000000000000", proto.LoginDone{Err: "x"})
	a.send(proto.TypeHeartbeat, "", nil)
	time.Sleep(50 * time.Millisecond)
	for _, hv := range f.h.Hosts() {
		if hv.HostID == host && !hv.Online {
			t.Fatal("host dropped after login frames for an unknown job")
		}
	}
}

func TestDispatchLoginFrameEmptyIDIsViolation(t *testing.T) {
	for _, typ := range []string{proto.TypeLoginURL, proto.TypeLoginDone} {
		f := newFixture(t)
		a, _, _ := f.enrol("box")
		a.send(typ, "", proto.LoginDone{Err: "x"})
		a.expectClosed("unexpected message")
	}
}

func TestAddIgnoresFramesFromAnotherConnection(t *testing.T) {
	f := newFixture(t)
	a, _, host := f.enrol("box")
	f.loginAgent(a)
	b, _, _ := f.enrol("other")
	id, _ := f.h.AddAccount(context.Background(), host, "x")
	f.waitState(id, AddAwaitingCode)
	b.send(proto.TypeLoginDone, id, proto.LoginDone{Err: "hijack"})
	time.Sleep(50 * time.Millisecond)
	if v, _ := f.h.AddStatus(id); v.State != AddAwaitingCode {
		t.Fatalf("another host's frame moved the job to %s", v.State)
	}
}

func TestAddDoesNotHoldSwapMuWhileWaiting(t *testing.T) {
	f := newFixture(t)
	f.seedAccounts()
	a, _, host := f.enrol("box")
	f.loginAgent(a)
	f.reg.SwapIn("A", host)
	id, _ := f.h.AddAccount(context.Background(), host, "x")
	f.waitState(id, AddAwaitingCode)
	errc := make(chan error, 1)
	go func() { _, swerr := f.h.Swap(context.Background(), host, "B"); errc <- swerr }()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("swap during add: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("swap blocked while an add waits for the code")
	}
}

func TestAddLogsNoSecrets(t *testing.T) {
	f := newFixture(t)
	a, _, host := f.enrol("box")
	f.loginAgent(a)
	id, _ := f.h.AddAccount(context.Background(), host, "x")
	f.waitState(id, AddAwaitingCode)
	_ = f.h.AddCode(id, addCodeVal)
	f.waitState(id, AddDone)
	logs := f.logs.String()
	if !strings.Contains(logs, "login_start") {
		t.Fatalf("no add-account log lines: %s", logs)
	}
	for _, s := range []string{"PLANTED-STATE", "oauth/authorize", addCodeVal, "NEW-ACCESS", "NEW-REFRESH", newIdentity, "example.invalid"} {
		if strings.Contains(logs, s) {
			t.Fatalf("log leaks %q: %s", s, logs)
		}
	}
}
