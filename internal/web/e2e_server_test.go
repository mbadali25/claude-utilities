package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"claude-utilities/internal/hub"
	"claude-utilities/internal/proto"
	"claude-utilities/internal/tunnel"
	"claude-utilities/internal/vault"
)

// The fixture estate the browser run drives. It is the shape Matthew reported (a Linux host sitting
// on the account the dropdown preselected, a Linux host with nothing signed in, a Windows host with
// six sessions and a stale login) plus one host for each way a swap can end.
const (
	e2eNoop    = "h-noop"
	e2eNoIdent = "h-noident"
	e2eOK      = "h-ok"
	e2eRefused = "h-refused"
	e2eExpired = "h-expired"
	e2eOffline = "h-offline"
	e2eBlocked = "h-blocked"
	e2eSlow    = "h-slow"
)

func e2eSessions(n int, stale bool) []hub.SessionView {
	out := make([]hub.SessionView, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, hub.SessionView{
			Session: proto.Session{
				PID: 4100 + i, ID: fmt.Sprintf("8c1d9e%02d-11d4-4e7a-9a21-7c5be0d4a1%02d", i, i),
				Name: []string{"api refactor", "docs sweep", "release notes", "flaky test", "infra bump", "review queue"}[i%6],
				Cwd:  []string{"/home/dev/src/api", "/home/dev/src/docs"}[i%2], Status: "busy",
				StartedAt: time.Now().Add(-time.Duration(20+i*7) * time.Minute).UTC(),
			},
			NeedsReload: stale,
		})
	}
	return out
}

// TestE2EServer is not a test: it is the way the Playwright run gets the real handler, the real
// index.html and fake agents in one process. It is skipped unless CLAUDESWAP_E2E_ADDR is set, so
// `go test ./...` never blocks on it. Nothing here touches a real credential file or a real host.
func TestE2EServer(t *testing.T) {
	addr := os.Getenv("CLAUDESWAP_E2E_ADDR")
	if addr == "" {
		t.Skip("set CLAUDESWAP_E2E_ADDR to serve the UI for a browser run")
	}
	r := newRig(t)
	r.seed("acct-x", "work@example.test")
	r.seed("acct-y", "personal@example.test")

	r.fh.hosts = []hub.HostView{
		{HostID: e2eNoop, Name: "ivy (linux)", OS: "linux", Online: true, ActiveAccount: "acct-x", Sessions: []hub.SessionView{}},
		{HostID: e2eNoIdent, Name: "birch (linux)", OS: "linux", Online: true, ActiveAccount: "", Sessions: []hub.SessionView{}},
		{HostID: e2eOK, Name: "oak (windows)", OS: "windows", Online: true, ActiveAccount: "acct-x", Sessions: e2eSessions(6, true)},
		{HostID: e2eRefused, Name: "elm (linux)", OS: "linux", Online: true, ActiveAccount: "acct-x", Sessions: []hub.SessionView{}},
		{HostID: e2eExpired, Name: "fir (linux)", OS: "linux", Online: true, ActiveAccount: "acct-x", Sessions: []hub.SessionView{}},
		{HostID: e2eOffline, Name: "pine (linux)", OS: "linux", Online: false, ActiveAccount: "acct-x", Sessions: []hub.SessionView{}},
		{HostID: e2eBlocked, Name: "yew (windows)", OS: "windows", Online: true, ActiveAccount: "acct-x", SwapBlocked: true, Sessions: []hub.SessionView{}},
		{HostID: e2eSlow, Name: "ash (linux)", OS: "linux", Online: true, ActiveAccount: "acct-x", Sessions: []hub.SessionView{}},
	}

	// One host per ending. The two refusals carry a token-shaped string so the run also proves the
	// reason reaches the card with the secret redacted out of it.
	r.fh.swapFn = func(host, acct string) (hub.SwapOutcome, error) {
		switch host {
		case e2eNoop: // already-active only for the account it really holds, as the hub does
			if acct == "acct-x" {
				return hub.SwapAlreadyActive, nil
			}
			return hub.SwapDone, nil
		case e2eOK:
			return hub.SwapDone, nil
		case e2eSlow: // held open on purpose, so the browser run can photograph the in-flight state
			time.Sleep(90 * time.Second)
			return hub.SwapDone, nil
		case e2eRefused:
			return "", fmt.Errorf("hub: agent refused swap: no space left on device")
		case e2eExpired:
			return "", fmt.Errorf("hub: agent refused swap: the stored login is expired or unauthorized")
		case e2eOffline:
			return "", hub.ErrAgentOffline
		case e2eNoIdent:
			return "", hub.ErrUnknownLiveAccount
		case e2eBlocked:
			return "", errors.New("hub: a previous swap on this host has not finished")
		}
		return hub.SwapDone, nil
	}

	if os.Getenv("CLAUDESWAP_E2E_TUNNELS") != "" {
		r.tn = e2eTunnels(t, r)
		r.h = newHandler(r.fh, r.v, r.usage, r.pw, r.tn, func() time.Time { return r.now })
	}

	srv := &http.Server{Addr: addr, Handler: r.h, ReadHeaderTimeout: 5 * time.Second}
	t.Logf("e2e UI on http://%s  password: %s", addr, adminPW)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatal(err)
	}
}

// e2eFakeRunner is a tunnel.Runner that spawns NOTHING. It is scripted per label, so the browser
// run can photograph every tunnel state without an ssh binary, a network or a real host.
type e2eFakeRunner struct{ mu sync.Mutex }

type e2eFakeProc struct {
	code   int
	stderr string
	linger time.Duration
	done   chan struct{}
	once   sync.Once
}

func (p *e2eFakeProc) Pid() int { return 4242 }
func (p *e2eFakeProc) Wait() int {
	if p.linger > 0 {
		select {
		case <-p.done:
		case <-time.After(p.linger):
		}
	}
	return p.code
}
func (p *e2eFakeProc) Kill() error    { p.once.Do(func() { close(p.done) }); return nil }
func (p *e2eFakeProc) Stderr() string { return p.stderr }

func (r *e2eFakeRunner) Start(_ context.Context, s tunnel.Spec, _, _ string) (tunnel.Proc, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := &e2eFakeProc{done: make(chan struct{})}
	switch s.Label {
	case "SRL-LIN": // settles and stays up
		p.linger = time.Hour
	case "TSS": // a denied key: terminal, so the card shows failed and offers Restart
		p.code, p.stderr = 255, "Permission denied (publickey)."
	case "ASH": // a stale listener on the host: retryable, so the card shows it retrying
		p.code, p.stderr = 1, "Warning: remote port forwarding failed for listen port 8443"
	default:
		p.linger = time.Hour
	}
	return p, nil
}

// e2eTunnels builds the Tunnels fixture: one tunnel per state the panel can show. Every address
// is in .invalid, which can never resolve, and no supervisor child is a real process.
func e2eTunnels(t *testing.T, r *rig) tunnelAPI {
	t.Helper()
	t.Setenv("CLAUDESWAP_E2E_TUNNEL_KEY", "e2e-passphrase-not-a-real-one")
	dir := t.TempDir()
	kr, err := vault.OpenKeyring(filepath.Join(dir, vault.KeyringFileName), "CLAUDESWAP_E2E_TUNNEL_KEY")
	if err != nil {
		t.Fatal(err)
	}
	m, err := tunnel.NewManager(tunnel.Options{DataDir: dir, Runner: &e2eFakeRunner{},
		Grace: 200 * time.Millisecond, Delay: func(int) time.Duration { return 3 * time.Second }}, kr)
	if err != nil {
		t.Fatal(err)
	}
	// e2eHostKey is a valid ed25519 public key that belongs to no host: it only has to parse.
	const e2eHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK7Zr1gkRlEb3qZ3Q2nEhKr9f3TRTZ0Rql7dP1xN0xZ1 e2e"
	for _, f := range []struct {
		id, label, addr, user string
		seedHostKey, enable   bool
		revoke                bool
		rotate                bool
	}{
		// up, and joined onto the Hosts tab's own "oak" row
		{id: e2eOK, label: "SRL-LIN", addr: "srl-lin.estate.invalid", user: "svcclaude", seedHostKey: true, enable: true},
		// failed: the operator has not pasted the line yet
		{id: "tun-tss", label: "TSS", addr: "tss-box.estate.invalid", user: "operator", seedHostKey: true, enable: true},
		// retrying, mid-rotation: both lines valid
		{id: "tun-ash", label: "ASH", addr: "ash.estate.invalid", user: "builder", seedHostKey: true, enable: true, rotate: true},
		// configured but off, with no host key recorded yet: the first onboarding step
		{id: "tun-new", label: "FIR", addr: "fir.estate.invalid", user: "deploy"},
		// a revoked key, whose line is still on the host
		{id: "tun-gone", label: "PINE", addr: "pine.estate.invalid", user: "operator", seedHostKey: true, revoke: true},
	} {
		if _, err := m.Add(tunnel.Spec{ID: f.id, Label: f.label, Address: f.addr, User: f.user}); err != nil {
			t.Fatalf("add %s: %v", f.label, err)
		}
		if f.seedHostKey {
			if _, err := m.SeedHostKey(f.id, e2eHostKey); err != nil {
				t.Fatalf("seed %s: %v", f.label, err)
			}
		}
		if f.enable {
			if _, err := m.SetEnabled(f.id, true); err != nil {
				t.Fatalf("enable %s: %v", f.label, err)
			}
		}
		if f.rotate {
			if _, err := m.RotateKey(f.id); err != nil {
				t.Fatalf("rotate %s: %v", f.label, err)
			}
		}
		if f.revoke {
			if _, err := m.RevokeKey(f.id); err != nil {
				t.Fatalf("revoke %s: %v", f.label, err)
			}
		}
	}
	m.Start(context.Background())
	return m
}
