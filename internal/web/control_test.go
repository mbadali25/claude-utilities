package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"claude-utilities/internal/hub"
	"claude-utilities/internal/proto"
)

func sampleView() hub.CommandView {
	return hub.CommandView{ID: "cmd-1", Command: proto.CmdReloadPlugins, Scope: hub.ScopeSession,
		CreatedAt: fixedNow,
		Counts:    hub.CommandCounts{Total: 1, Queued: 1},
		Targets: []hub.CommandTargetView{{ID: "cmd-1-0-0", HostID: "h-1", SessionID: "s-1", PID: 7,
			Command: proto.CmdReloadPlugins, Status: proto.StatusQueued, Mechanism: "hook-queue",
			CreatedAt: fixedNow, UpdatedAt: fixedNow}}}
}

func TestSessionCommandNeedsASessionAndACSRFToken(t *testing.T) {
	r := newRig(t)
	r.fh.commandView = sampleView()
	body := `{"command":"reload_plugins","scope":"session","host":"h-1","session":"s-1"}`

	if w := r.do(http.MethodPost, "/api/sessions/command", body, nil, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("no session: %d", w.Code)
	}
	s := r.login()
	if w := r.do(http.MethodPost, "/api/sessions/command", body, s, ""); w.Code != http.StatusForbidden {
		t.Fatalf("no CSRF token: %d", w.Code)
	}
	if w := r.do(http.MethodPost, "/api/sessions/command", body, s, "wrong"); w.Code != http.StatusForbidden {
		t.Fatalf("wrong CSRF token: %d", w.Code)
	}
	if n := len(r.fh.commands()); n != 0 {
		t.Fatalf("%d commands reached the hub without authentication", n)
	}
	w := r.do(http.MethodPost, "/api/sessions/command", body, s, s.csrf)
	if w.Code != http.StatusAccepted {
		t.Fatalf("authenticated: %d %s", w.Code, w.Body.String())
	}
}

func TestSessionCommandPassesTheRequestThrough(t *testing.T) {
	r := newRig(t)
	r.fh.commandView = sampleView()
	s := r.login()
	body := `{"command":"repair","scope":"all","confirm":true,"onlyNeedsReload":true,"requestId":"idem-7"}`
	w := r.do(http.MethodPost, "/api/sessions/command", body, s, s.csrf)
	if w.Code != http.StatusAccepted {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	got := r.fh.commands()
	if len(got) != 1 {
		t.Fatalf("commands = %+v", got)
	}
	want := hub.CommandRequest{Command: proto.CmdRepair, Scope: hub.ScopeAll,
		OnlyNeedsReload: true, Confirm: true, RequestID: "idem-7"}
	if got[0] != want {
		t.Fatalf("request = %+v, want %+v", got[0], want)
	}
}

func TestSessionCommandResponseShape(t *testing.T) {
	r := newRig(t)
	v := sampleView()
	v.Targets[0].Status = proto.StatusUnsupported
	v.Targets[0].Code = proto.CodeRequiresRestart
	v.Targets[0].Mechanism = "relaunch"
	v.Targets[0].Hint = "claude --resume s-1 --remote-control alpha"
	v.Counts = hub.CommandCounts{Total: 1, Unsupported: 1}
	r.fh.commandView = v
	s := r.login()
	w := r.do(http.MethodPost, "/api/sessions/command",
		`{"command":"remote_control_enable","scope":"session","host":"h-1","session":"s-1"}`, s, s.csrf)
	if w.Code != http.StatusAccepted {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var out commandViewJSON
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%v: %s", err, w.Body.String())
	}
	if out.ID != "cmd-1" || out.Scope != "session" || out.Counts.Total != 1 || out.Counts.Unsupported != 1 {
		t.Fatalf("out = %+v", out)
	}
	if len(out.Targets) != 1 {
		t.Fatalf("targets = %+v", out.Targets)
	}
	tg := out.Targets[0]
	if tg.HostID != "h-1" || tg.SessionID != "s-1" || tg.PID != 7 {
		t.Fatalf("target = %+v", tg)
	}
	if tg.Status != proto.StatusUnsupported || tg.Code != proto.CodeRequiresRestart ||
		tg.Mechanism != "relaunch" || !strings.Contains(tg.Hint, "--remote-control") {
		t.Fatalf("target = %+v", tg)
	}
}

func TestSessionCommandMapsHubErrorsToStatuses(t *testing.T) {
	cases := []struct {
		err  error
		code int
	}{
		{hub.ErrUnknownCommand, http.StatusBadRequest},
		{hub.ErrBadScope, http.StatusBadRequest},
		{hub.ErrNameRequired, http.StatusBadRequest},
		{hub.ErrNameNotAllowed, http.StatusBadRequest},
		{hub.ErrConfirmRequired, http.StatusConflict},
		{hub.ErrNoSuchSession, http.StatusNotFound},
		{hub.ErrNoCommandTargets, http.StatusConflict},
		{hub.ErrTooManyCommandTargets, http.StatusConflict},
		{hub.ErrUnknownHost, http.StatusNotFound},
		{hub.ErrAgentOffline, http.StatusConflict},
	}
	for _, c := range cases {
		r := newRig(t)
		r.fh.commandErr = c.err
		s := r.login()
		w := r.do(http.MethodPost, "/api/sessions/command",
			`{"command":"reload_plugins","scope":"session","host":"h-1","session":"s-1"}`, s, s.csrf)
		if w.Code != c.code {
			t.Errorf("%v: %d, want %d (%s)", c.err, w.Code, c.code, w.Body.String())
		}
	}
}

func TestSessionCommandIsRateLimited(t *testing.T) {
	r := newRig(t)
	r.fh.commandView = sampleView()
	s := r.login()
	body := `{"command":"reload_plugins","scope":"session","host":"h-1","session":"s-1"}`
	for i := 0; i < maxCommandRequests; i++ {
		if w := r.do(http.MethodPost, "/api/sessions/command", body, s, s.csrf); w.Code != http.StatusAccepted {
			t.Fatalf("request %d: %d %s", i, w.Code, w.Body.String())
		}
	}
	w := r.do(http.MethodPost, "/api/sessions/command", body, s, s.csrf)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("over the budget: %d", w.Code)
	}
	if n := len(r.fh.commands()); n != maxCommandRequests {
		t.Fatalf("%d commands reached the hub, want %d", n, maxCommandRequests)
	}
	// The window moves on and the budget comes back.
	r.now = r.now.Add(commandWindow + time.Second)
	if w := r.do(http.MethodPost, "/api/sessions/command", body, s, s.csrf); w.Code != http.StatusAccepted {
		t.Fatalf("after the window: %d %s", w.Code, w.Body.String())
	}
}

func TestSessionCommandRejectsAnUnknownBodyFieldAndOversizeText(t *testing.T) {
	r := newRig(t)
	r.fh.commandView = sampleView()
	s := r.login()
	bodies := []string{
		`{"command":"reload_plugins","scope":"session","host":"h-1","session":"s-1","extra":true}`,
		`{"command":"rename_remote","scope":"session","host":"h-1","session":"s-1","name":"` + strings.Repeat("x", 600) + `"}`,
		`{"command":"reload_plugins","scope":"session","requestId":"` + strings.Repeat("r", 200) + `"}`,
	}
	for _, b := range bodies {
		if w := r.do(http.MethodPost, "/api/sessions/command", b, s, s.csrf); w.Code != http.StatusBadRequest {
			t.Errorf("%.60s: %d %s", b, w.Code, w.Body.String())
		}
	}
}

func TestHostsPollCarriesCommandStatus(t *testing.T) {
	r := newRig(t)
	r.fh.hosts = []hub.HostView{{HostID: "h-1", Name: "box", OS: "linux", Online: true,
		Sessions: []hub.SessionView{{
			Session:     proto.Session{PID: 7, ID: "s-1", Name: "alpha", Cwd: "/w", StartedAt: fixedNow},
			NeedsReload: true,
			Commands: []hub.CommandTargetView{{ID: "cmd-1-0-0", Command: proto.CmdRemoteControlEnable,
				Status: proto.StatusUnsupported, Code: proto.CodeRequiresRestart, Mechanism: "relaunch",
				Hint: "claude --resume s-1 --remote-control alpha", CreatedAt: fixedNow, UpdatedAt: fixedNow}},
		}}}}
	s := r.login()
	w := r.do(http.MethodGet, "/api/hosts", "", s, "")
	if w.Code != http.StatusOK {
		t.Fatalf("%d", w.Code)
	}
	var out []hostJSON
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%v: %s", err, w.Body.String())
	}
	if len(out) != 1 || len(out[0].Sessions) != 1 {
		t.Fatalf("out = %+v", out)
	}
	cs := out[0].Sessions[0].Commands
	if len(cs) != 1 {
		t.Fatalf("commands = %+v", cs)
	}
	if cs[0].Status != proto.StatusUnsupported || cs[0].Code != proto.CodeRequiresRestart ||
		cs[0].Mechanism != "relaunch" || !strings.Contains(cs[0].Hint, "--remote-control") {
		t.Fatalf("command = %+v", cs[0])
	}
	// A session with no commands must not grow a key, so an older UI sees the old shape.
	r.fh.hosts[0].Sessions[0].Commands = nil
	w = r.do(http.MethodGet, "/api/hosts", "", s, "")
	if strings.Contains(w.Body.String(), `"commands"`) {
		t.Fatalf("empty commands should be omitted: %s", w.Body.String())
	}
}

// No credential block, token or vault secret may appear in a command response.
func TestSessionCommandResponseCarriesNoSecret(t *testing.T) {
	r := newRig(t)
	r.seed("acct-a", "Account A")
	v := sampleView()
	v.Targets[0].Hint = "safe hint"
	r.fh.commandView = v
	s := r.login()
	w := r.do(http.MethodPost, "/api/sessions/command",
		`{"command":"reload_plugins","scope":"session","host":"h-1","session":"s-1"}`, s, s.csrf)
	if strings.Contains(w.Body.String(), blockSecret) {
		t.Fatalf("leaked the vault block: %s", w.Body.String())
	}
}

// The rate-limit table is bounded, so a spray from many addresses cannot grow it without end.
func TestSessionCommandRateLimitTableIsBounded(t *testing.T) {
	now := fixedNow
	s := &server{now: func() time.Time { return now }, sessions: map[string]sess{},
		failures: map[string][]time.Time{}, commandHits: map[string][]time.Time{}}
	for i := 0; i < maxTrackedIPs+500; i++ {
		s.overCommandLimit(fmt.Sprintf("10.1.%d.%d", i/256, i%256))
	}
	s.mu.Lock()
	n := len(s.commandHits)
	s.mu.Unlock()
	if n > maxTrackedIPs {
		t.Fatalf("%d tracked addresses, bound is %d", n, maxTrackedIPs)
	}
	// An address already tracked keeps being counted even once the table is full.
	for i := 0; i < maxCommandRequests; i++ {
		s.overCommandLimit("10.1.0.0")
	}
	if !s.overCommandLimit("10.1.0.0") {
		t.Fatal("a tracked address escaped its budget once the table filled")
	}
}
