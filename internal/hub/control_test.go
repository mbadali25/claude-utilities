package hub

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"claude-utilities/internal/proto"
)

// report sends one report and waits until the hub has taken it in.
func (f *fixture) report(a *agent, hostID string, rep proto.Report) {
	f.t.Helper()
	rep.HostID = hostID
	a.send(proto.TypeReport, "", rep)
	eventually(f.t, func() bool {
		for _, hv := range f.h.Hosts() {
			if hv.HostID == hostID && len(hv.Sessions) == len(rep.Sessions) {
				return true
			}
		}
		return false
	})
}

func sess(id, name string, pid int) proto.Session {
	return proto.Session{PID: pid, ID: id, Name: name, Cwd: "/w", StartedAt: time.Unix(1, 0)}
}

// answerCommands replies to n command_req frames with the given result.
func (a *agent) answerCommands(n int, res proto.CommandRes) []proto.CommandReq {
	a.t.Helper()
	out := make([]proto.CommandReq, 0, n)
	for i := 0; i < n; i++ {
		env := a.recv(proto.TypeCommandReq)
		var req proto.CommandReq
		if err := json.Unmarshal(env.Body, &req); err != nil {
			a.t.Fatal(err)
		}
		out = append(out, req)
		r := res
		r.CommandID = req.CommandID
		a.send(proto.TypeCommandRes, env.ID, r)
	}
	return out
}

func (f *fixture) waitStatus(id string, want func(CommandView) bool) CommandView {
	f.t.Helper()
	var v CommandView
	eventually(f.t, func() bool {
		got, err := f.h.CommandStatus(id)
		if err != nil {
			return false
		}
		v = got
		return want(got)
	})
	return v
}

func TestCommandSessionScopeReachesOneSession(t *testing.T) {
	f := newFixture(t)
	a, _, hostID := f.enrol("box")
	f.report(a, hostID, proto.Report{Sessions: []proto.Session{sess("s-1", "alpha", 11), sess("s-2", "beta", 12)}})

	v, err := f.h.Command(context.Background(), CommandRequest{
		Command: proto.CmdReloadPlugins, Scope: ScopeSession, HostID: hostID, SessionID: "s-2"})
	if err != nil {
		t.Fatal(err)
	}
	if v.Counts.Total != 1 || v.Counts.Queued != 1 {
		t.Fatalf("counts = %+v", v.Counts)
	}
	reqs := a.answerCommands(1, proto.CommandRes{Status: proto.StatusQueued, Mechanism: "hook-queue"})
	if reqs[0].SessionID != "s-2" || reqs[0].Command != proto.CmdReloadPlugins {
		t.Fatalf("req = %s %s", reqs[0].SessionID, reqs[0].Command)
	}
	got := f.waitStatus(v.ID, func(x CommandView) bool { return x.Targets[0].Mechanism == "hook-queue" })
	if got.Targets[0].Status != proto.StatusQueued {
		t.Fatalf("status = %s", got.Targets[0].Status)
	}
}

func TestCommandHostScopeNeedsConfirm(t *testing.T) {
	f := newFixture(t)
	a, _, hostID := f.enrol("box")
	f.report(a, hostID, proto.Report{Sessions: []proto.Session{sess("s-1", "alpha", 11)}})

	for _, scope := range []CommandScope{ScopeHost, ScopeAll} {
		_, err := f.h.Command(context.Background(), CommandRequest{
			Command: proto.CmdReloadPlugins, Scope: scope, HostID: hostID})
		if err != ErrConfirmRequired {
			t.Fatalf("scope %s: err = %v, want ErrConfirmRequired", scope, err)
		}
	}
	v, err := f.h.Command(context.Background(), CommandRequest{
		Command: proto.CmdReloadPlugins, Scope: ScopeHost, HostID: hostID, Confirm: true})
	if err != nil {
		t.Fatal(err)
	}
	if v.Counts.Total != 1 {
		t.Fatalf("counts = %+v", v.Counts)
	}
	a.answerCommands(1, proto.CommandRes{Status: proto.StatusQueued})
}

func TestCommandAllScopeCoversEveryHost(t *testing.T) {
	f := newFixture(t)
	a1, _, h1 := f.enrol("box1")
	a2, _, h2 := f.enrol("box2")
	f.report(a1, h1, proto.Report{Sessions: []proto.Session{sess("s-1", "a", 1)}})
	f.report(a2, h2, proto.Report{Sessions: []proto.Session{sess("s-2", "b", 2), sess("s-3", "c", 3)}})

	v, err := f.h.Command(context.Background(), CommandRequest{
		Command: proto.CmdReloadPlugins, Scope: ScopeAll, Confirm: true})
	if err != nil {
		t.Fatal(err)
	}
	if v.Counts.Total != 3 {
		t.Fatalf("counts = %+v", v.Counts)
	}
	a1.answerCommands(1, proto.CommandRes{Status: proto.StatusQueued})
	a2.answerCommands(2, proto.CommandRes{Status: proto.StatusQueued})
	f.waitStatus(v.ID, func(x CommandView) bool { return x.Counts.Queued == 3 })
}

func TestCommandOnlyNeedsReloadNarrowsTheScope(t *testing.T) {
	f := newFixture(t)
	a, _, hostID := f.enrol("box")
	f.report(a, hostID, proto.Report{Sessions: []proto.Session{sess("s-1", "a", 1), sess("s-2", "b", 2)}})
	// Mark what a swap would mark: every session reported at that moment.
	f.h.mu.Lock()
	f.h.hosts[hostID].markReloadLocked()
	f.h.mu.Unlock()
	// A session that starts afterwards is not stale.
	f.report(a, hostID, proto.Report{Sessions: []proto.Session{sess("s-1", "a", 1), sess("s-2", "b", 2), sess("s-3", "c", 3)}})

	v, err := f.h.Command(context.Background(), CommandRequest{
		Command: proto.CmdReloadPlugins, Scope: ScopeHost, HostID: hostID, Confirm: true, OnlyNeedsReload: true})
	if err != nil {
		t.Fatal(err)
	}
	if v.Counts.Total != 2 {
		t.Fatalf("counts = %+v (want the two stale sessions)", v.Counts)
	}
	for _, tv := range v.Targets {
		if tv.SessionID == "s-3" {
			t.Fatalf("fresh session targeted: %+v", tv)
		}
	}
	a.answerCommands(2, proto.CommandRes{Status: proto.StatusQueued})
	f.waitStatus(v.ID, func(x CommandView) bool { return x.Counts.Queued == 2 })
}

func TestRepairExpandsToThreeStepsNamedAfterTheSession(t *testing.T) {
	f := newFixture(t)
	a, _, hostID := f.enrol("box")
	f.report(a, hostID, proto.Report{Sessions: []proto.Session{sess("s-1", "alpha work", 11)}})

	v, err := f.h.Command(context.Background(), CommandRequest{
		Command: proto.CmdRepair, Scope: ScopeHost, HostID: hostID, Confirm: true})
	if err != nil {
		t.Fatal(err)
	}
	if v.Counts.Total != 3 {
		t.Fatalf("counts = %+v", v.Counts)
	}
	want := []string{proto.CmdReloadPlugins, proto.CmdRemoteControlEnable, proto.CmdRenameRemote}
	for i, tv := range v.Targets {
		if tv.Command != want[i] {
			t.Fatalf("target %d = %s, want %s", i, tv.Command, want[i])
		}
	}
	reqs := a.answerCommands(3, proto.CommandRes{Status: proto.StatusUnsupported, Code: proto.CodeRequiresRestart})
	if reqs[2].Name != "alpha work" {
		t.Fatalf("rename name = %q, want the session's own name", reqs[2].Name)
	}
	if reqs[0].Name != "" {
		t.Fatalf("reload_plugins should carry no name, got %q", reqs[0].Name)
	}
}

// The name to latch is the session's own name, never the stale remote title the operator is
// replacing: naming a session after its latched title would be a no-op by construction.
func TestRepairNamesTheSessionAfterItsOwnNameNotItsRemoteName(t *testing.T) {
	f := newFixture(t)
	a, _, hostID := f.enrol("box")
	s := sess("s-1", "alpha", 11)
	s.RemoteName = "stale latched title"
	f.report(a, hostID, proto.Report{Sessions: []proto.Session{s}})

	v, err := f.h.Command(context.Background(), CommandRequest{
		Command: proto.CmdRepair, Scope: ScopeHost, HostID: hostID, Confirm: true})
	if err != nil {
		t.Fatal(err)
	}
	reqs := a.answerCommands(3, proto.CommandRes{Status: proto.StatusUnsupported, Code: proto.CodeRequiresRestart})
	if reqs[2].Name != "alpha" {
		t.Fatalf("rename name = %q, want the session's own name", reqs[2].Name)
	}
	f.waitStatus(v.ID, func(x CommandView) bool { return x.Counts.Unsupported == 3 })
}

// Two sessions with no id on one host must not share a command bucket, or each would show the
// other's commands in the state poll.
func TestIdlessSessionsDoNotShareACommandBucket(t *testing.T) {
	f := newFixture(t)
	a, _, hostID := f.enrol("box")
	f.report(a, hostID, proto.Report{Sessions: []proto.Session{sess("", "a", 11), sess("", "b", 12)}})

	v, err := f.h.Command(context.Background(), CommandRequest{
		Command: proto.CmdReloadPlugins, Scope: ScopeHost, HostID: hostID, Confirm: true})
	if err != nil {
		t.Fatal(err)
	}
	if v.Counts.Total != 2 {
		t.Fatalf("counts = %+v", v.Counts)
	}
	a.answerCommands(2, proto.CommandRes{Status: proto.StatusFailed, Code: proto.CodeBadSessionID})
	f.waitStatus(v.ID, func(x CommandView) bool { return x.Counts.Failed == 2 })
	for _, hv := range f.h.Hosts() {
		for _, sv := range hv.Sessions {
			if len(sv.Commands) != 1 {
				t.Fatalf("pid %d has %d commands, want its own one", sv.PID, len(sv.Commands))
			}
		}
	}
}

func TestRepairFailsARenameWithNoName(t *testing.T) {
	f := newFixture(t)
	a, _, hostID := f.enrol("box")
	f.report(a, hostID, proto.Report{Sessions: []proto.Session{sess("s-1", "", 11)}})

	v, err := f.h.Command(context.Background(), CommandRequest{
		Command: proto.CmdRepair, Scope: ScopeHost, HostID: hostID, Confirm: true})
	if err != nil {
		t.Fatal(err)
	}
	var rename CommandTargetView
	for _, tv := range v.Targets {
		if tv.Command == proto.CmdRenameRemote {
			rename = tv
		}
	}
	if rename.Status != proto.StatusFailed || rename.Code != proto.CodeNoName {
		t.Fatalf("rename target = %s/%s, want failed/%s", rename.Status, rename.Code, proto.CodeNoName)
	}
	// The other two still go out: a nameless session can still reload and bind.
	a.answerCommands(2, proto.CommandRes{Status: proto.StatusUnsupported, Code: proto.CodeRequiresRestart})
	f.waitStatus(v.ID, func(x CommandView) bool { return x.Counts.Unsupported == 2 })
}

func TestCommandRejectsBadRequests(t *testing.T) {
	f := newFixture(t)
	a, _, hostID := f.enrol("box")
	f.report(a, hostID, proto.Report{Sessions: []proto.Session{sess("s-1", "a", 1)}})
	cases := []struct {
		name string
		req  CommandRequest
		want error
	}{
		{"unknown command", CommandRequest{Command: "nope", Scope: ScopeSession, HostID: hostID, SessionID: "s-1"}, ErrUnknownCommand},
		{"bad scope", CommandRequest{Command: proto.CmdReloadPlugins, Scope: "world", HostID: hostID}, ErrBadScope},
		{"rename with no name", CommandRequest{Command: proto.CmdRenameRemote, Scope: ScopeSession, HostID: hostID, SessionID: "s-1"}, ErrNameRequired},
		{"one name for many sessions", CommandRequest{Command: proto.CmdRenameRemote, Scope: ScopeHost, HostID: hostID, Name: "x", Confirm: true}, ErrNameNotAllowed},
		{"unknown host", CommandRequest{Command: proto.CmdReloadPlugins, Scope: ScopeHost, HostID: "nope", Confirm: true}, ErrUnknownHost},
		{"unknown session", CommandRequest{Command: proto.CmdReloadPlugins, Scope: ScopeSession, HostID: hostID, SessionID: "nope"}, ErrNoSuchSession},
	}
	for _, c := range cases {
		if _, err := f.h.Command(context.Background(), c.req); err != c.want {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}

func TestCommandIsIdempotentPerRequestID(t *testing.T) {
	f := newFixture(t)
	a, _, hostID := f.enrol("box")
	f.report(a, hostID, proto.Report{Sessions: []proto.Session{sess("s-1", "a", 1)}})

	req := CommandRequest{Command: proto.CmdReloadPlugins, Scope: ScopeSession,
		HostID: hostID, SessionID: "s-1", RequestID: "idem-1"}
	first, err := f.h.Command(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.h.Command(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID {
		t.Fatalf("ids %s and %s differ: the repeat dispatched again", first.ID, second.ID)
	}
	a.answerCommands(1, proto.CommandRes{Status: proto.StatusQueued})
	if _, err := a.recvWithin(150 * time.Millisecond); err == nil {
		t.Fatal("a second command_req went out for the same request id")
	}
}

func TestReportUpgradesQueuedToDelivered(t *testing.T) {
	f := newFixture(t)
	a, _, hostID := f.enrol("box")
	f.report(a, hostID, proto.Report{Sessions: []proto.Session{sess("s-1", "a", 1)}})
	v, err := f.h.Command(context.Background(), CommandRequest{
		Command: proto.CmdReloadPlugins, Scope: ScopeSession, HostID: hostID, SessionID: "s-1"})
	if err != nil {
		t.Fatal(err)
	}
	reqs := a.answerCommands(1, proto.CommandRes{Status: proto.StatusQueued, Mechanism: "hook-queue"})
	f.waitStatus(v.ID, func(x CommandView) bool { return x.Targets[0].Mechanism == "hook-queue" })

	f.report(a, hostID, proto.Report{Sessions: []proto.Session{sess("s-1", "a", 1)},
		Commands: []proto.SessionCommandStatus{{CommandID: reqs[0].CommandID, Status: proto.StatusDelivered}}})
	got := f.waitStatus(v.ID, func(x CommandView) bool { return x.Targets[0].Status == proto.StatusDelivered })
	if got.Counts.Delivered != 1 {
		t.Fatalf("counts = %+v", got.Counts)
	}
	// A later queued status must not walk it backwards, and nothing claims done on its own.
	f.report(a, hostID, proto.Report{Sessions: []proto.Session{sess("s-1", "a", 1)},
		Commands: []proto.SessionCommandStatus{{CommandID: reqs[0].CommandID, Status: proto.StatusQueued}}})
	if got, _ := f.h.CommandStatus(v.ID); got.Targets[0].Status != proto.StatusDelivered {
		t.Fatalf("status went backwards to %s", got.Targets[0].Status)
	}
}

func TestReportStatusForAnotherHostIsIgnored(t *testing.T) {
	f := newFixture(t)
	a1, _, h1 := f.enrol("box1")
	a2, _, h2 := f.enrol("box2")
	f.report(a1, h1, proto.Report{Sessions: []proto.Session{sess("s-1", "a", 1)}})
	f.report(a2, h2, proto.Report{Sessions: []proto.Session{sess("s-2", "b", 2)}})
	v, err := f.h.Command(context.Background(), CommandRequest{
		Command: proto.CmdReloadPlugins, Scope: ScopeSession, HostID: h1, SessionID: "s-1"})
	if err != nil {
		t.Fatal(err)
	}
	reqs := a1.answerCommands(1, proto.CommandRes{Status: proto.StatusQueued})
	f.waitStatus(v.ID, func(x CommandView) bool { return x.Targets[0].Status == proto.StatusQueued })

	f.report(a2, h2, proto.Report{Sessions: []proto.Session{sess("s-2", "b", 2)},
		Commands: []proto.SessionCommandStatus{{CommandID: reqs[0].CommandID, Status: proto.StatusDone}}})
	if got, _ := f.h.CommandStatus(v.ID); got.Targets[0].Status != proto.StatusQueued {
		t.Fatalf("another host moved the target to %s", got.Targets[0].Status)
	}
}

func TestCommandTimesOutWithoutAVerdict(t *testing.T) {
	f := newFixture(t)
	a, _, hostID := f.enrol("box")
	f.report(a, hostID, proto.Report{Sessions: []proto.Session{sess("s-1", "a", 1)}})
	v, err := f.h.Command(context.Background(), CommandRequest{
		Command: proto.CmdReloadPlugins, Scope: ScopeSession, HostID: hostID, SessionID: "s-1"})
	if err != nil {
		t.Fatal(err)
	}
	a.recv(proto.TypeCommandReq) // received and deliberately never answered
	f.clk.Advance(commandTimeout + time.Second)
	got, err := f.h.CommandStatus(v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Targets[0].Status != proto.StatusFailed || got.Targets[0].Code != proto.CodeTimeout {
		t.Fatalf("target = %s/%s", got.Targets[0].Status, got.Targets[0].Code)
	}
}

func TestOfflineHostFailsTheTarget(t *testing.T) {
	f := newFixture(t)
	a, _, hostID := f.enrol("box")
	f.report(a, hostID, proto.Report{Sessions: []proto.Session{sess("s-1", "a", 1)}})
	f.h.mu.Lock()
	f.h.hosts[hostID].c = nil // the socket went away between the match and the send
	f.h.mu.Unlock()
	v, err := f.h.Command(context.Background(), CommandRequest{
		Command: proto.CmdReloadPlugins, Scope: ScopeSession, HostID: hostID, SessionID: "s-1"})
	if err != nil {
		t.Fatal(err)
	}
	got := f.waitStatus(v.ID, func(x CommandView) bool { return x.Targets[0].Status == proto.StatusFailed })
	if got.Targets[0].Code != proto.CodeAgentOffline {
		t.Fatalf("code = %s", got.Targets[0].Code)
	}
}

func TestHostsViewCarriesTheSessionsCommands(t *testing.T) {
	f := newFixture(t)
	a, _, hostID := f.enrol("box")
	f.report(a, hostID, proto.Report{Sessions: []proto.Session{sess("s-1", "a", 1)}})
	v, err := f.h.Command(context.Background(), CommandRequest{
		Command: proto.CmdRemoteControlEnable, Scope: ScopeSession, HostID: hostID, SessionID: "s-1"})
	if err != nil {
		t.Fatal(err)
	}
	a.answerCommands(1, proto.CommandRes{Status: proto.StatusUnsupported, Code: proto.CodeRequiresRestart,
		Mechanism: "relaunch", Hint: "claude --resume s-1 --remote-control alpha"})
	f.waitStatus(v.ID, func(x CommandView) bool { return x.Counts.Unsupported == 1 })

	var found CommandTargetView
	for _, hv := range f.h.Hosts() {
		for _, sv := range hv.Sessions {
			if len(sv.Commands) == 1 {
				found = sv.Commands[0]
			}
		}
	}
	if found.Status != proto.StatusUnsupported || !strings.Contains(found.Hint, "--remote-control") {
		t.Fatalf("session command view = %+v", found)
	}
}

// Agent text reaches the browser, so the hub caps it and runs it through the redactor first.
func TestAgentReplyTextIsCappedAndRedacted(t *testing.T) {
	f := newFixture(t)
	a, _, hostID := f.enrol("box")
	f.report(a, hostID, proto.Report{Sessions: []proto.Session{sess("s-1", "a", 1)}})
	v, err := f.h.Command(context.Background(), CommandRequest{
		Command: proto.CmdReloadPlugins, Scope: ScopeSession, HostID: hostID, SessionID: "s-1"})
	if err != nil {
		t.Fatal(err)
	}
	a.answerCommands(1, proto.CommandRes{Status: proto.StatusFailed,
		Code: strings.Repeat("c", 200), Hint: strings.Repeat("h", 900) + " token=SECRETVALUE"})
	got := f.waitStatus(v.ID, func(x CommandView) bool { return x.Targets[0].Status == proto.StatusFailed })
	if len(got.Targets[0].Code) > proto.MaxCommandCode || len(got.Targets[0].Hint) > proto.MaxCommandHint {
		t.Fatalf("not capped: code %d hint %d", len(got.Targets[0].Code), len(got.Targets[0].Hint))
	}
	if strings.Contains(got.Targets[0].Hint, "SECRETVALUE") {
		t.Fatal("hint was not redacted")
	}
}

// Nothing a command touches may put a session name, a cwd or a hint in the log.
func TestCommandLogsCarryNoNameCwdOrHint(t *testing.T) {
	f := newFixture(t)
	a, _, hostID := f.enrol("box")
	f.report(a, hostID, proto.Report{Sessions: []proto.Session{
		{PID: 1, ID: "s-1", Name: "Jane's laptop", Cwd: "/home/jane/secret-project", StartedAt: time.Unix(1, 0)}}})
	v, err := f.h.Command(context.Background(), CommandRequest{
		Command: proto.CmdRepair, Scope: ScopeHost, HostID: hostID, Confirm: true})
	if err != nil {
		t.Fatal(err)
	}
	a.answerCommands(3, proto.CommandRes{Status: proto.StatusUnsupported, Code: proto.CodeRequiresRestart,
		Mechanism: "relaunch", Hint: "claude --resume s-1 --remote-control \"Jane's laptop\""})
	f.waitStatus(v.ID, func(x CommandView) bool { return x.Counts.Unsupported == 3 })
	logs := f.logs.String()
	for _, leak := range []string{"Jane", "secret-project", "--resume"} {
		if strings.Contains(logs, leak) {
			t.Fatalf("log leaked %q: %s", leak, logs)
		}
	}
	if !strings.Contains(logs, `"command":"repair"`) || !strings.Contains(logs, `"mechanism":"relaunch"`) {
		t.Fatalf("audit fields missing: %s", logs)
	}
}

func TestCommandHistoryIsBounded(t *testing.T) {
	f := newFixture(t)
	a, _, hostID := f.enrol("box")
	f.report(a, hostID, proto.Report{Sessions: []proto.Session{sess("s-1", "a", 1)}})
	f.h.mu.Lock()
	f.h.hosts[hostID].c = nil // every request fails at once, so each one finishes
	f.h.mu.Unlock()
	for i := 0; i < maxCommands+5; i++ {
		if _, err := f.h.Command(context.Background(), CommandRequest{
			Command: proto.CmdReloadPlugins, Scope: ScopeSession, HostID: hostID, SessionID: "s-1"}); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, func() bool {
		f.h.mu.Lock()
		defer f.h.mu.Unlock()
		return len(f.h.cmds) <= maxCommands
	})
	f.h.mu.Lock()
	cmds, byID, perSession := len(f.h.cmds), len(f.h.cmdByID), len(f.h.cmdBySession["box|s-1"])
	f.h.mu.Unlock()
	if cmds > maxCommands || byID > maxCommands || perSession > maxSessionCommands {
		t.Fatalf("unbounded: cmds %d byID %d perSession %d", cmds, byID, perSession)
	}
}

func TestCommandFanOutIsBounded(t *testing.T) {
	f := newFixture(t)
	a, _, hostID := f.enrol("box")
	ss := make([]proto.Session, 0, 200)
	for i := 0; i < 200; i++ {
		ss = append(ss, sess("s-"+string(rune('a'+i%26))+string(rune('a'+i/26)), "n", i+1))
	}
	f.report(a, hostID, proto.Report{Sessions: ss})
	if _, err := f.h.Command(context.Background(), CommandRequest{
		Command: proto.CmdRepair, Scope: ScopeHost, HostID: hostID, Confirm: true}); err != ErrTooManyCommandTargets {
		t.Fatalf("err = %v, want ErrTooManyCommandTargets", err)
	}
}
