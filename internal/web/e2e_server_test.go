package web

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"claude-utilities/internal/hub"
	"claude-utilities/internal/proto"
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

// e2eVerdicts gives the first three sessions one verdict each, so the browser run photographs
// every status label the UI can draw - including the two that share the "unsupported" status and
// are told apart only by their reason code (Restart required against Unsupported).
func e2eVerdicts(i int, id string) []hub.CommandTargetView {
	now := time.Now().UTC()
	v := func(cmd, status, code, mech, hint string) []hub.CommandTargetView {
		return []hub.CommandTargetView{{ID: "e2e-" + id, Command: cmd, Status: status, Code: code,
			Mechanism: mech, Hint: hint, CreatedAt: now, UpdatedAt: now}}
	}
	switch i {
	case 0:
		return v(proto.CmdRestartSessions, proto.StatusUnsupported, proto.CodeRequiresRestart,
			"relaunch", "claude --resume "+id+" --remote-control \"api refactor\"")
	case 1:
		return v(proto.CmdReloadPlugins, proto.StatusDelivered, "", "hook-queue", "")
	case 2:
		return v(proto.CmdRemoteControlEnable, proto.StatusUnsupported, proto.CodeInboxUnproven,
			"inbox", "the experimental per-session inbox has an unproven wire frame; nothing was sent")
	}
	return nil
}

func e2eSessions(n int, stale bool) []hub.SessionView {
	out := make([]hub.SessionView, 0, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("8c1d9e%02d-11d4-4e7a-9a21-7c5be0d4a1%02d", i, i)
		out = append(out, hub.SessionView{
			Session: proto.Session{
				PID: 4100 + i, ID: id,
				Name: []string{"api refactor", "docs sweep", "release notes", "flaky test", "infra bump", "review queue"}[i%6],
				Cwd:  []string{"/home/dev/src/api", "/home/dev/src/docs"}[i%2], Status: "busy",
				StartedAt: time.Now().Add(-time.Duration(20+i*7) * time.Minute).UTC(),
			},
			NeedsReload: stale,
			Commands:    e2eVerdicts(i, id),
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

	srv := &http.Server{Addr: addr, Handler: r.h, ReadHeaderTimeout: 5 * time.Second}
	t.Logf("e2e UI on http://%s  password: %s", addr, adminPW)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatal(err)
	}
}
