package agent

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"claude-utilities/internal/logx"
	"claude-utilities/internal/proto"
)

const enrolToken = "tok-ENROL-SECRET-xyz"

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type enrolRig struct {
	o     enrolOpts
	out   bytes.Buffer
	log   *syncBuf
	clock *fakeClock
	waits []time.Duration
}

func newEnrolRig(t *testing.T) *enrolRig {
	t.Helper()
	r := &enrolRig{log: &syncBuf{}, clock: &fakeClock{t: time.Unix(1_800_000_000, 0)}}
	r.o = enrolOpts{
		StateDir: t.TempDir(), HostName: "new-host", CredsPath: filepath.Join(t.TempDir(), ".credentials.json"),
		Now: r.clock.now, Log: logx.New(r.log),
		After: func(d time.Duration) <-chan time.Time { r.waits = append(r.waits, d); return make(chan time.Time) },
	}
	return r
}

func approveAfterPending(t *testing.T, extra chan string) func(context.Context, *websocket.Conn, int, proto.Hello) {
	return func(ctx context.Context, ws *websocket.Conn, _ int, h proto.Hello) {
		sendEnv(t, ctx, ws, proto.TypePending, "", proto.Pending{Fingerprint: proto.Fingerprint(h), ExpiresAt: time.Now().Add(10 * time.Minute)})
		// While pending the agent must stay silent.
		// (A read context that expires closes the socket, so read in the background instead.)
		go func() {
			for {
				env, err := readEnv(ctx, ws)
				if err != nil {
					return
				}
				extra <- env.Type
			}
		}()
		time.Sleep(200 * time.Millisecond)
		sendEnv(t, ctx, ws, proto.TypeApproved, "", proto.Approved{Token: enrolToken})
		<-ctx.Done()
	}
}

func TestEnrolPrintsFingerprintMatchingHello(t *testing.T) {
	fs := newFakeServer(t, approveAfterPending(t, make(chan string, 16)))
	r := newEnrolRig(t)
	cfg, err := enrol(context.Background(), r.o, fs.ts.URL, fs.pin, "", &r.out)
	if err != nil {
		t.Fatal(err)
	}
	h := recvHello(t, fs)
	if h.Token != "" || h.Code != "" || h.Nonce == "" || h.HostName != "new-host" {
		t.Fatalf("hello: host=%q nonce-empty=%v", h.HostName, h.Nonce == "")
	}
	out := r.out.String()
	if !strings.Contains(out, "Fingerprint: "+proto.Fingerprint(h)) {
		t.Fatalf("console lacks fingerprint of the sent hello: %q", out)
	}
	if !strings.Contains(out, "approve this host in the web UI") {
		t.Fatalf("console lacks approval prompt: %q", out)
	}
	if strings.Contains(out, h.Nonce) {
		t.Fatal("console shows the nonce")
	}
	if cfg.Token != enrolToken || cfg.ServerURL != fs.ts.URL {
		t.Fatal("config not returned")
	}
}

func TestEnrolSendsNothingAfterHelloUntilApproved(t *testing.T) {
	extra := make(chan string, 16)
	fs := newFakeServer(t, approveAfterPending(t, extra))
	r := newEnrolRig(t)
	if _, err := enrol(context.Background(), r.o, fs.ts.URL, fs.pin, "", &r.out); err != nil {
		t.Fatal(err)
	}
	if len(extra) != 0 {
		t.Fatalf("agent sent %d frame(s) while pending (first type %q)", len(extra), <-extra)
	}
}

func TestEnrolStoresApprovedTokenAt0600AndNeverLogsIt(t *testing.T) {
	fs := newFakeServer(t, approveAfterPending(t, make(chan string, 16)))
	r := newEnrolRig(t)
	if _, err := enrol(context.Background(), r.o, fs.ts.URL, fs.pin, "", &r.out); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(r.o.StateDir, "agent.json")
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("agent.json mode %v", st.Mode().Perm())
	}
	got, err := LoadConfig(r.o.StateDir)
	if err != nil || got.Token != enrolToken || got.Pin != fs.pin || got.CredsPath != r.o.CredsPath {
		t.Fatalf("stored config: %v", err)
	}
	if strings.Contains(r.out.String(), enrolToken) || strings.Contains(r.log.String(), enrolToken) {
		t.Fatal("token printed or logged")
	}
}

func TestEnrolDeniedExitsWithReasonAndHonoursRetryAfter(t *testing.T) {
	fs := newFakeServer(t, func(ctx context.Context, ws *websocket.Conn, _ int, h proto.Hello) {
		sendEnv(t, ctx, ws, proto.TypePending, "", proto.Pending{Fingerprint: proto.Fingerprint(h), ExpiresAt: time.Now().Add(time.Minute)})
		sendEnv(t, ctx, ws, proto.TypeDenied, "", proto.Denied{Reason: "not my laptop", RetryAfter: 5 * time.Minute})
		<-ctx.Done()
	})
	r := newEnrolRig(t)
	_, err := enrol(context.Background(), r.o, fs.ts.URL, fs.pin, "", &r.out)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
	if !strings.Contains(r.out.String(), "not my laptop") {
		t.Fatalf("reason not printed: %q", r.out.String())
	}
	if _, serr := os.Stat(filepath.Join(r.o.StateDir, "agent.json")); serr == nil {
		t.Fatal("config written after denial")
	}
	// Inside RetryAfter: no dial at all.
	r.clock.advance(4 * time.Minute)
	if _, err := enrol(context.Background(), r.o, fs.ts.URL, fs.pin, "", &r.out); !errors.Is(err, ErrDenied) {
		t.Fatalf("early retry: %v", err)
	}
	if n := fs.conns.Load(); n != 1 {
		t.Fatalf("agent re-dialled inside RetryAfter: %d connections", n)
	}
	// After it: dials again.
	r.clock.advance(2 * time.Minute)
	_, _ = enrol(context.Background(), r.o, fs.ts.URL, fs.pin, "", &r.out)
	if n := fs.conns.Load(); n != 2 {
		t.Fatalf("agent did not retry after RetryAfter: %d connections", n)
	}
}

func TestEnrolTimesOutAfter10Min(t *testing.T) {
	fs := newFakeServer(t, func(ctx context.Context, ws *websocket.Conn, _ int, h proto.Hello) {
		sendEnv(t, ctx, ws, proto.TypePending, "", proto.Pending{Fingerprint: proto.Fingerprint(h), ExpiresAt: time.Now().Add(time.Hour)})
		<-ctx.Done()
	})
	r := newEnrolRig(t)
	fired := make(chan time.Time)
	r.o.After = func(d time.Duration) <-chan time.Time {
		r.waits = append(r.waits, d)
		go func() { time.Sleep(100 * time.Millisecond); close(fired) }() // the "10 minutes" pass
		return fired
	}
	_, err := enrol(context.Background(), r.o, fs.ts.URL, fs.pin, "", &r.out)
	if !errors.Is(err, ErrApprovalTimeout) {
		t.Fatalf("want ErrApprovalTimeout, got %v", err)
	}
	if len(r.waits) != 1 || r.waits[0] != 10*time.Minute {
		t.Fatalf("approval wait = %v", r.waits)
	}
	if _, serr := os.Stat(filepath.Join(r.o.StateDir, "agent.json")); serr == nil {
		t.Fatal("config written after timeout")
	}
}

func TestEnrolWithCodeSkipsPending(t *testing.T) {
	fs := newFakeServer(t, func(ctx context.Context, ws *websocket.Conn, _ int, h proto.Hello) {
		sendEnv(t, ctx, ws, proto.TypeApproved, "", proto.Approved{Token: enrolToken})
		<-ctx.Done()
	})
	r := newEnrolRig(t)
	cfg, err := enrol(context.Background(), r.o, fs.ts.URL, fs.pin, "code-123", &r.out)
	if err != nil || cfg.Token != enrolToken {
		t.Fatalf("enrol with code: %v", err)
	}
	if h := recvHello(t, fs); h.Code != "code-123" || h.Token != "" {
		t.Fatalf("server saw code %q token-empty=%v", h.Code, h.Token == "")
	}
	if strings.Contains(r.out.String(), "Fingerprint") {
		t.Fatal("pre-approved path printed a pending fingerprint")
	}
	if strings.Contains(r.out.String()+r.log.String(), "code-123") {
		t.Fatal("enrolment code printed or logged")
	}
}

func TestEnrolFreshNonceEachAttempt(t *testing.T) {
	fs := newFakeServer(t, approveAfterPending(t, make(chan string, 16)))
	var outs [2]bytes.Buffer
	var nonces [2]string
	for i := range outs {
		r := newEnrolRig(t)
		if _, err := enrol(context.Background(), r.o, fs.ts.URL, fs.pin, "", &outs[i]); err != nil {
			t.Fatal(err)
		}
		nonces[i] = recvHello(t, fs).Nonce
	}
	if nonces[0] == "" || nonces[0] == nonces[1] {
		t.Fatal("nonce reused across attempts")
	}
	fp := func(b bytes.Buffer) string {
		for _, l := range strings.Split(b.String(), "\n") {
			if v, ok := strings.CutPrefix(l, "Fingerprint: "); ok {
				return v
			}
		}
		return ""
	}
	if fp(outs[0]) == "" || fp(outs[0]) == fp(outs[1]) {
		t.Fatalf("fingerprints equal: %q %q", fp(outs[0]), fp(outs[1]))
	}
}

func TestEnrolRejectsFingerprintMismatch(t *testing.T) {
	fs := newFakeServer(t, func(ctx context.Context, ws *websocket.Conn, _ int, _ proto.Hello) {
		sendEnv(t, ctx, ws, proto.TypePending, "", proto.Pending{Fingerprint: "zzzzzzzz", ExpiresAt: time.Now().Add(time.Minute)})
		<-ctx.Done()
	})
	r := newEnrolRig(t)
	_, err := enrol(context.Background(), r.o, fs.ts.URL, fs.pin, "", &r.out)
	if !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("got %v", err)
	}
}

func TestEnrolWrongPinNeverSendsHello(t *testing.T) {
	fs := newFakeServer(t, func(context.Context, *websocket.Conn, int, proto.Hello) {})
	r := newEnrolRig(t)
	if _, err := enrol(context.Background(), r.o, fs.ts.URL, strings.Repeat("0", 64), "", &r.out); err == nil {
		t.Fatal("enrolled against a wrongly pinned server")
	}
	if len(fs.hellos) != 0 {
		t.Fatal("hello sent to wrongly pinned server")
	}
}
