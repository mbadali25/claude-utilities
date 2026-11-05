package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
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
		`{"command":"rename_remote","scope":"session","host":"h-1","session":"s-1","name":"` +
			strings.Repeat("x", proto.MaxRemoteName*4+1) + `"}`,
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

// The Hosts tab is where session control is driven from, so the served page has to carry the
// whole control surface: the per-session asks, the two host-wide asks behind a confirm step, the
// estate-wide repair, the live status chips, and the dialogs that keep Esc, the focus trap and
// focus return for free.
func TestPageCarriesSessionControlSurface(t *testing.T) {
	r := newRig(t)
	p := page(r, r.login())

	for _, want := range []string{
		// The one route and every field the hub reads off the body.
		"/api/sessions/command", "'reload_plugins'", "'remote_control_enable'", "'rename_remote'",
		"'repair'", "scope: 'session'", "scope: 'host'", "scope: 'all'",
		"onlyNeedsReload: true", "confirm: true", "requestId",
		// Status comes off the existing poll, under commands[].
		"s.commands", "commandList",
		// The per-session asks, the host-wide pair and the estate-wide repair.
		"'Reload plugins'", "'Enable remote'", "'Fix name'",
		"'Reload all'", "'Enable remote on all'", "Apply to all needs-reload sessions",
		// The regions they live in.
		`id="ctl-repair"`, `id="ctl-repair-go"`, `id="ctl-repair-sub"`, `id="ctl-summary"`,
		`id="st-attn-go"`, "selectTab($('#tab-hosts'), false)",
		`id="ctl-confirm"`, `id="ctl-confirm-h"`, `id="ctl-confirm-body"`, `id="ctl-confirm-note"`,
		`id="ctl-confirm-msg"`, `id="ctl-confirm-go"`,
		`id="ctl-name"`, `id="ctl-name-form"`, `id="ctl-name-input"`, `id="ctl-name-hint"`,
		`id="ctl-name-msg"`, `id="ctl-name-go"`, `id="ctl-name-for"`,
	} {
		if !strings.Contains(p, want) {
			t.Errorf("index.html lacks %q", want)
		}
	}

	// Every status the hub can report has a word of its own, so a chip never means something by
	// colour alone, and the two statuses no mechanism reaches are still rendered honestly.
	for _, st := range []string{proto.StatusQueued, proto.StatusDelivered, proto.StatusDone,
		proto.StatusFailed, proto.StatusUnsupported} {
		if !strings.Contains(p, st+": {") {
			t.Errorf("the status map has no entry for %q", st)
		}
	}
	for _, want := range []string{
		"Delivered: the session runs it at its next prompt.",
		"Restart required: cannot be done on a running session.",
		"Queued: nothing has reached the session yet.",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("index.html lacks the honest wording %q", want)
		}
	}
	// A confirm step for anything wider than one session, and it says what is not done.
	if !strings.Contains(p, "No session is stopped, killed or restarted.") {
		t.Error("the confirm dialogs do not say that nothing is killed")
	}
	// The hint can carry the relaunch command, so it gets a Copy button of its own.
	if !strings.Contains(p, "Copy the relaunch command for ") {
		t.Error("a relaunch hint has no labelled Copy button")
	}
	// Buttons go disabled for the round trip and come back: a 202 means queued, not done.
	for _, want := range []string{"b.disabled = true;", "b.disabled = false;"} {
		if !strings.Contains(p, want) {
			t.Errorf("index.html lacks %q, so a button cannot be disabled in flight", want)
		}
	}
}

// THE requirement for the restart action: the confirm dialog NAMES the sessions. The names are
// filled in by the poll, so the served page can only be held to the element that holds them - but
// it can be held to that absolutely, because a dialog with no list element cannot name anything.
// The names themselves are proved in the browser run (docs/runbooks/claude-swap-e2e.md).
func TestRestartConfirmDialogListsTheSessionsItWouldRestart(t *testing.T) {
	r := newRig(t)
	p := page(r, r.login())

	if !strings.Contains(p, `<dialog class="modal" id="ctl-restart"`) {
		t.Fatal("there is no restart confirm dialog")
	}
	dlg := element(t, p, `id="ctl-restart"`, "</dialog>")
	for _, want := range []string{
		// The element the session names go into, and the one that counts them.
		`id="ctl-restart-list"`, `id="ctl-restart-sub"`,
		// The promise, stated where the operator is about to act, not only in the docs.
		"Nothing is stopped, killed or restarted",
		// The no-op, labelled as local so it cannot be read as having restarted anything.
		`id="ctl-restart-mark"`,
		// A cancel path and an inline alert, like every other control dialog.
		`data-close="ctl-restart"`, `id="ctl-restart-msg"`,
	} {
		if !strings.Contains(dlg, want) {
			t.Errorf("the restart confirm dialog lacks %q", want)
		}
	}
	if msg := element(t, p, `id="ctl-restart-msg"`, ">"); !strings.Contains(msg, `role="alert"`) {
		t.Errorf("ctl-restart-msg is not an alert: %q", msg)
	}
	// The list is built from the sessions the ask would reach, each one named, and the exact
	// relaunch command is offered to copy rather than run.
	for _, want := range []string{
		"function restartTargets(", "openRestartDialog(", "$('#ctl-restart-list')",
		"Copy the relaunch command for ", "markRestartedLocally(",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("index.html lacks %q", want)
		}
	}
	// The wire shape: a restart always carries confirm:true, because the hub refuses it otherwise
	// at every scope.
	if !strings.Contains(p, "command: 'restart_sessions'") {
		t.Error("index.html never asks for restart_sessions")
	}
	i := strings.Index(p, "command: 'restart_sessions'")
	if j := strings.Index(p[i:], "}"); j < 0 || !strings.Contains(p[i:i+j], "confirm: true") {
		t.Error("the restart ask does not carry confirm: true")
	}
	// The dialog and the callout above it must count the same sessions. restartTargets therefore
	// does NOT skip an offline host: staleSessions() does not either, and a dialog that quietly
	// listed fewer sessions than the callout counts would put two numbers on one screen that
	// disagree. The row says the host is offline instead.
	rt := p[strings.Index(p, "function restartTargets("):]
	rt = rt[:strings.Index(rt, "\n  function ")]
	if strings.Contains(rt, "if (!h.online) return") {
		t.Error("restartTargets drops offline hosts, so its count can disagree with the callout's")
	}
	if !strings.Contains(p, "host offline, so the ask will not reach it") {
		t.Error("a session on an offline host is listed without saying the ask cannot reach it")
	}
	// Nothing in the page may terminate or kill anything, and no confirm token exists to unlock
	// one: the decision is copy-only (docs/runbooks/session-control.md).
	for _, bad := range []string{"'terminate'", "'kill'", "confirmToken", "confirm_token"} {
		if strings.Contains(p, bad) {
			t.Errorf("index.html carries %q: the restart action is copy-only", bad)
		}
	}
}

// A second `function sessKey` in the page's one scope silently replaced the per-host disclosure
// key, and every host card threw on the first render - a whole tab blank, with nothing in the Go
// tests or the linter to catch it. Nothing in this page may declare the same top-level function
// name twice.
func TestPageDeclaresNoFunctionNameTwice(t *testing.T) {
	r := newRig(t)
	p := page(r, r.login())

	// This covers top-level `function NAME(` declarations only. A duplicate `var` at the same
	// scope, or a `var f = function`, fails the same way and is NOT caught here.
	//
	// Exactly two spaces of indent is the page's one shared scope, the body of its IIFE. A helper
	// nested inside another function is indented further and has a scope of its own, so two of
	// those may share a name (`mk` does) without replacing anything.
	seen := map[string]int{}
	for _, m := range regexp.MustCompile(`(?m)^  function ([A-Za-z_$][\w$]*)\s*\(`).FindAllStringSubmatch(p, -1) {
		seen[m[1]]++
	}
	if len(seen) < 20 {
		t.Fatalf("only %d function declarations found; the pattern no longer matches the page", len(seen))
	}
	for name, n := range seen {
		if n > 1 {
			t.Errorf("function %s is declared %d times; the later one replaces the earlier", name, n)
		}
	}
}

// Three labels an operator has to be able to tell apart: a restart-type decline, any other
// decline, and an instruction that only reached the session.
func TestStatusLabelsSeparateRestartRequiredFromUnsupported(t *testing.T) {
	r := newRig(t)
	p := page(r, r.login())

	for _, want := range []string{
		"Restart required", "Unsupported", "Delivered",
		"Delivered: the session runs it at its next prompt.",
		"Restart required: cannot be done on a running session.",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("index.html lacks the label %q", want)
		}
	}
	// The split is on the reason code, not on the status: an unsupported that is NOT a
	// requires-restart (an unproven inbox, a missing mechanism) must not read as "restart".
	if !strings.Contains(p, proto.CodeRequiresRestart) {
		t.Errorf("index.html never reads the %q code, so it cannot tell the two declines apart", proto.CodeRequiresRestart)
	}
	if !strings.Contains(p, "stOf(c.status, c.code)") {
		t.Error("the chip is not built from the status AND the code")
	}
}

func TestSessionControlRegionsAnnounceAndValidate(t *testing.T) {
	r := newRig(t)
	p := page(r, r.login())

	// The repair bar sits inside the Hosts panel, above the host list, and ships hidden: it is
	// offered only once a swap has left something for it to do.
	panel := element(t, p, `id="panel-hosts"`, "</main>")
	for _, want := range []string{`id="ctl-repair"`, `id="ctl-summary"`, `id="hosts"`} {
		if !strings.Contains(panel, want) {
			t.Errorf("the Hosts panel lacks %q", want)
		}
	}
	if i, j := strings.Index(panel, `id="ctl-repair"`), strings.Index(panel, `id="hosts"`); i > j {
		t.Errorf("the repair bar is below the host list (%d > %d)", i, j)
	}
	if !strings.Contains(element(t, p, `id="ctl-repair"`, ">"), "hidden") {
		t.Error("the repair bar does not ship hidden")
	}

	// The counts summary is announced, and every inline error region is an alert, so a refusal
	// reaches a screen reader where the operator is working instead of only in the page status.
	if sum := element(t, p, `id="ctl-summary"`, ">"); !strings.Contains(sum, `role="status"`) ||
		!strings.Contains(sum, `aria-live="polite"`) {
		t.Errorf("the counts summary is not a live region: %q", sum)
	}
	for _, id := range []string{"ctl-confirm-msg", "ctl-name-msg"} {
		if msg := element(t, p, `id="`+id+`"`, ">"); !strings.Contains(msg, `role="alert"`) {
			t.Errorf("%s is not an alert: %q", id, msg)
		}
	}
	if !strings.Contains(p, `var msg = el('div', '', 'msg'); msg.setAttribute('role', 'alert');`) {
		t.Error("the per-session and per-host controls carry no inline alert region")
	}

	// Fix name: a labelled field, prefilled, with the wire limit enforced in runes as well as by
	// maxlength, which counts UTF-16 units.
	name := element(t, p, `id="ctl-name"`, "</dialog>")
	for _, want := range []string{"Remote name", `maxlength="256"`, `aria-describedby="ctl-name-hint"`,
		`class="fld"`} {
		if !strings.Contains(name, want) {
			t.Errorf("the fix-name dialog lacks %q", want)
		}
	}
	for _, want := range []string{"MAX_NAME = 256", "runeLen(name)", "the limit is "} {
		if !strings.Contains(p, want) {
			t.Errorf("index.html lacks the name validation %q", want)
		}
	}

	// Both control dialogs are native, so Esc, the focus trap and focus return are the browser's.
	for _, id := range []string{"ctl-confirm", "ctl-name"} {
		if !strings.Contains(p, `<dialog class="modal" id="`+id+`"`) {
			t.Errorf("%s is not a native <dialog>", id)
		}
		if !strings.Contains(p, `data-close="`+id+`"`) {
			t.Errorf("%s has no cancel path", id)
		}
	}
	// A host-wide or estate-wide ask must never fall back to window.confirm: that dialog cannot
	// state a count and is not styleable.
	if strings.Contains(p, "confirm('Reload") || strings.Contains(p, "confirm('Apply") {
		t.Error("a session-control ask uses window.confirm instead of the confirm dialog")
	}
	// Nothing in the control path renders agent text as markup.
	for _, bad := range []string{".innerHTML", "insertAdjacentHTML", "outerHTML"} {
		if strings.Contains(p, bad) {
			t.Errorf("index.html assigns HTML (%q): a hint and a name arrive from the agent", bad)
		}
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
