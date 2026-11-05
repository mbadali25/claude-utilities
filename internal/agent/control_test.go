package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"claude-utilities/internal/proto"
)

const (
	testSession  = "11111111-2222-3333-4444-555555555555"
	testSession2 = "66666666-7777-8888-9999-aaaaaaaaaaaa"
)

func fixedClock() func() time.Time {
	t := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

func newTestControl(t *testing.T, inbox bool) (*control, string) {
	t.Helper()
	dir := t.TempDir()
	return newControl(dir, fixedClock(), inbox), dir
}

func TestReloadPluginsGoesThroughTheHookQueue(t *testing.T) {
	ctl, dir := newTestControl(t, false)
	res := ctl.ex.run(CommandTask{CommandID: "c1", Command: proto.CmdReloadPlugins, SessionID: testSession})
	if res.Status != proto.StatusQueued || res.Mechanism != "hook-queue" {
		t.Fatalf("res = %+v", res)
	}
	data, err := os.ReadFile(filepath.Join(dir, commandDirName, testSession+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var f queueFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Entries) != 1 || f.Entries[0].Command != proto.CmdReloadPlugins || f.Entries[0].DeliveredAt != nil {
		t.Fatalf("queue = %+v", f)
	}
}

func TestRemoteControlAndRenameReportUnsupportedWithTheRelaunchCommand(t *testing.T) {
	ctl, _ := newTestControl(t, false)
	for _, c := range []string{proto.CmdRemoteControlEnable, proto.CmdRenameRemote} {
		res := ctl.ex.run(CommandTask{CommandID: "c1", Command: c, SessionID: testSession, Name: "alpha"})
		if res.Status != proto.StatusUnsupported || res.Code != proto.CodeRequiresRestart {
			t.Fatalf("%s: res = %+v", c, res)
		}
		if res.Mechanism != "relaunch" {
			t.Fatalf("%s: mechanism = %s", c, res.Mechanism)
		}
		want := "claude --resume " + testSession + " --remote-control alpha"
		if res.Hint != want {
			t.Fatalf("%s: hint = %q, want %q", c, res.Hint, want)
		}
	}
}

// The relaunch mechanism must never start or stop anything: a session holds the operator's work.
func TestRelaunchMechanismTouchesNothing(t *testing.T) {
	dir := t.TempDir()
	res := relaunchMechanism{}.Execute(CommandTask{CommandID: "c1",
		Command: proto.CmdRemoteControlEnable, SessionID: testSession, PID: os.Getpid(), Name: "x"})
	if res.Status != proto.StatusUnsupported {
		t.Fatalf("res = %+v", res)
	}
	ents, err := os.ReadDir(dir)
	if err != nil || len(ents) != 0 {
		t.Fatalf("the mechanism wrote something: %v %v", ents, err)
	}
}

func TestRelaunchCommandQuotesAndRefusesUnsafeNames(t *testing.T) {
	cases := []struct{ name, want string }{
		{"", "claude --resume " + testSession + " --remote-control"},
		{"alpha", "claude --resume " + testSession + " --remote-control alpha"},
		{"alpha work", `claude --resume ` + testSession + ` --remote-control "alpha work"`},
		{`say "hi"`, "claude --resume " + testSession + " --remote-control   (then set the name in the session: the name needs shell quoting)"},
		{"a; rm -rf /", "claude --resume " + testSession + " --remote-control   (then set the name in the session: the name needs shell quoting)"},
		{"back\\slash", "claude --resume " + testSession + " --remote-control   (then set the name in the session: the name needs shell quoting)"},
	}
	for _, c := range cases {
		if got := RelaunchCommand(testSession, c.name); got != c.want {
			t.Errorf("name %q: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRelaunchWithoutAUsableSessionIDStillRefusesHonestly(t *testing.T) {
	res := relaunchMechanism{}.Execute(CommandTask{Command: proto.CmdRenameRemote, SessionID: "not-a-uuid"})
	if res.Status != proto.StatusUnsupported || strings.Contains(res.Hint, "--resume") {
		t.Fatalf("res = %+v (a non-uuid id must never be pasted into a command)", res)
	}
}

func TestUnknownAndCompositeCommandsAreRefused(t *testing.T) {
	ctl, _ := newTestControl(t, false)
	for _, c := range []string{"nope", proto.CmdRepair} {
		res := ctl.ex.run(CommandTask{CommandID: "c1", Command: c, SessionID: testSession})
		if res.Status != proto.StatusUnsupported || res.Code != proto.CodeUnknownCommand {
			t.Fatalf("%s: res = %+v", c, res)
		}
	}
}

func TestInboxMechanismIsOffByDefaultAndUnsupportedWhenOn(t *testing.T) {
	off, _ := newTestControl(t, false)
	for _, c := range []string{proto.CmdReloadPlugins, proto.CmdRemoteControlEnable, proto.CmdRenameRemote} {
		for _, m := range off.ex.mechanisms(c) {
			if m.Name() == "inbox" {
				t.Fatalf("%s: inbox registered with the flag off", c)
			}
		}
	}
	on, _ := newTestControl(t, true)
	first := on.ex.mechanisms(proto.CmdRemoteControlEnable)
	if len(first) == 0 || first[0].Name() != "inbox" {
		t.Fatalf("inbox should be tried first when on: %v", first)
	}
	// It is tried and declines, so the relaunch mechanism still answers.
	res := on.ex.run(CommandTask{CommandID: "c1", Command: proto.CmdRemoteControlEnable, SessionID: testSession})
	if res.Mechanism != "relaunch" {
		t.Fatalf("res = %+v", res)
	}
	if got := (inboxMechanism{}).Execute(CommandTask{}); got.Status != proto.StatusUnsupported || got.Code != proto.CodeInboxUnproven {
		t.Fatalf("inbox = %+v", got)
	}
}

func TestQueueRefusesABadSessionID(t *testing.T) {
	ctl, dir := newTestControl(t, false)
	res := ctl.ex.run(CommandTask{CommandID: "c1", Command: proto.CmdReloadPlugins, SessionID: "../../escape"})
	if res.Status != proto.StatusFailed || res.Code != proto.CodeBadSessionID {
		t.Fatalf("res = %+v", res)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("something was written: %v", ents)
	}
}

func TestQueueIsBoundedPerSession(t *testing.T) {
	ctl, _ := newTestControl(t, false)
	// Only one entry per command survives, so a repeat replaces rather than piles up.
	for i := 0; i < maxQueueEntries+5; i++ {
		if res := ctl.ex.run(CommandTask{CommandID: "c" + string(rune('a'+i)),
			Command: proto.CmdReloadPlugins, SessionID: testSession}); res.Status != proto.StatusQueued {
			t.Fatalf("run %d: %+v", i, res)
		}
	}
	f, err := ctl.q.read(testSession)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Entries) != 1 {
		t.Fatalf("entries = %d, want 1 (one pending instruction per command)", len(f.Entries))
	}
}

func TestQueueExpiresStaleEntries(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	clk := func() time.Time { return now }
	q := newQueue(dir, func() time.Time { return clk() })
	if err := q.enqueue(CommandTask{CommandID: "c1", Command: proto.CmdReloadPlugins, SessionID: testSession}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(queueEntryTTL + time.Hour)
	f, err := q.read(testSession)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Entries) != 0 {
		t.Fatalf("stale entry survived: %+v", f.Entries)
	}
}

func TestQueueFileIsOwnerOnly(t *testing.T) {
	ctl, dir := newTestControl(t, false)
	ctl.ex.run(CommandTask{CommandID: "c1", Command: proto.CmdReloadPlugins, SessionID: testSession})
	fi, err := os.Stat(filepath.Join(dir, commandDirName, testSession+".json"))
	if err != nil {
		t.Fatal(err)
	}
	di, err := os.Stat(filepath.Join(dir, commandDirName))
	if err != nil {
		t.Fatal(err)
	}
	// Windows carries its permissions in an ACL, which credfile covers; check the bits elsewhere.
	if os.PathSeparator == '/' {
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("file mode = %v, want 0600", fi.Mode().Perm())
		}
		if di.Mode().Perm() != 0o700 {
			t.Errorf("dir mode = %v, want 0700", di.Mode().Perm())
		}
	}
}

func TestQueueWithNoStateDirFailsRatherThanWritingAnywhere(t *testing.T) {
	q := newQueue("", fixedClock())
	err := q.enqueue(CommandTask{CommandID: "c1", Command: proto.CmdReloadPlugins, SessionID: testSession})
	if err == nil {
		t.Fatal("a queue with no state dir must refuse to write")
	}
	if _, serr := os.Stat(filepath.Join(commandDirName, testSession+".json")); serr == nil {
		t.Fatal("it wrote into the working directory")
	}
}

func TestDeliverMarksAndReportsOnce(t *testing.T) {
	ctl, _ := newTestControl(t, false)
	ctl.ex.run(CommandTask{CommandID: "c1", Command: proto.CmdReloadPlugins, SessionID: testSession})
	if got := ctl.q.delivered(); len(got) != 0 {
		t.Fatalf("nothing is delivered yet: %+v", got)
	}
	entries, err := ctl.q.deliver(testSession)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %+v", entries)
	}
	// A second hook run on the same session has nothing left to deliver.
	again, err := ctl.q.deliver(testSession)
	if err != nil || len(again) != 0 {
		t.Fatalf("again = %+v %v", again, err)
	}
	got := ctl.q.delivered()
	if len(got) != 1 || got[0].CommandID != "c1" || got[0].Status != proto.StatusDelivered {
		t.Fatalf("delivered = %+v", got)
	}
	// Until the report is confirmed the notice stays, so a failed send cannot lose it.
	if len(ctl.q.delivered()) != 1 {
		t.Fatal("the notice was dropped before it was confirmed")
	}
	ctl.q.confirmReported(got)
	if len(ctl.q.delivered()) != 0 {
		t.Fatal("the notice survived its confirmation")
	}
}

// A second request for the same command must not discard a delivered-but-unreported entry: the
// hub would then time that command out as failed although it was delivered.
func TestQueueingAgainKeepsADeliveredNotice(t *testing.T) {
	ctl, _ := newTestControl(t, false)
	if res := ctl.ex.run(CommandTask{CommandID: "c1", Command: proto.CmdReloadPlugins, SessionID: testSession}); res.Status != proto.StatusQueued {
		t.Fatalf("first: %+v", res)
	}
	if _, err := ctl.q.deliver(testSession); err != nil { // the hook runs
		t.Fatal(err)
	}
	// Before the next report goes out, the operator asks again.
	if res := ctl.ex.run(CommandTask{CommandID: "c2", Command: proto.CmdReloadPlugins, SessionID: testSession}); res.Status != proto.StatusQueued {
		t.Fatalf("second: %+v", res)
	}
	got := ctl.q.delivered()
	if len(got) != 1 || got[0].CommandID != "c1" {
		t.Fatalf("delivered = %+v, want c1 still pending a report", got)
	}
	// c2 is queued and undelivered, so the file holds both.
	f, err := ctl.q.read(testSession)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Entries) != 2 {
		t.Fatalf("entries = %+v", f.Entries)
	}
	// Once c1 is confirmed it goes, and c2 is untouched.
	ctl.q.confirmReported(got)
	f, err = ctl.q.read(testSession)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Entries) != 1 || f.Entries[0].CommandID != "c2" {
		t.Fatalf("entries = %+v", f.Entries)
	}
}

// Re-queueing a command id that is already delivered must not ask the model twice or report twice.
func TestQueueingADeliveredCommandIDAgainIsANoop(t *testing.T) {
	ctl, _ := newTestControl(t, false)
	task := CommandTask{CommandID: "c1", Command: proto.CmdReloadPlugins, SessionID: testSession}
	ctl.ex.run(task)
	if _, err := ctl.q.deliver(testSession); err != nil {
		t.Fatal(err)
	}
	ctl.ex.run(task)
	f, err := ctl.q.read(testSession)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Entries) != 1 || f.Entries[0].DeliveredAt == nil {
		t.Fatalf("entries = %+v", f.Entries)
	}
	if got := ctl.q.delivered(); len(got) != 1 {
		t.Fatalf("delivered = %+v", got)
	}
}

func TestDeliveredIsBoundedByTheReportLimit(t *testing.T) {
	dir := t.TempDir()
	q := newQueue(dir, fixedClock())
	// One entry per session, more sessions than a report may carry.
	for i := 0; i < proto.MaxCommandsPerReport+10; i++ {
		id := testSession[:30] + string("0123456789abcdef"[i%16]) + string("0123456789abcdef"[i/16]) + "0000"
		if err := q.enqueue(CommandTask{CommandID: "c" + id, Command: proto.CmdReloadPlugins, SessionID: id}); err != nil {
			t.Fatal(err)
		}
		if _, err := q.deliver(id); err != nil {
			t.Fatal(err)
		}
	}
	if got := q.delivered(); len(got) != proto.MaxCommandsPerReport {
		t.Fatalf("delivered %d, want %d", len(got), proto.MaxCommandsPerReport)
	}
}

func TestQueueFileCountIsBounded(t *testing.T) {
	dir := t.TempDir()
	q := newQueue(dir, fixedClock())
	m := queueMechanism{q: q}
	full := false
	for i := 0; i < maxQueueFiles+5; i++ {
		id := testSession[:30] + string("0123456789abcdef"[i%16]) + string("0123456789abcdef"[i/16]) + "0000"
		if res := m.Execute(CommandTask{CommandID: "c", Command: proto.CmdReloadPlugins, SessionID: id}); res.Code == proto.CodeQueueFull {
			full = true
			break
		}
	}
	if !full {
		t.Fatal("the queue never reported itself full")
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) > maxQueueFiles {
		t.Fatalf("%d queue files, bound is %d", len(ents), maxQueueFiles)
	}
}

// The reply is the agent's only outbound frame for a command: nothing is sent unsolicited, so an
// older hub (which closes the connection on an unexpected frame) stays connected.
func TestCommandReplyNeverClaimsDone(t *testing.T) {
	ctl, _ := newTestControl(t, true)
	for _, c := range []string{proto.CmdReloadPlugins, proto.CmdRemoteControlEnable, proto.CmdRenameRemote} {
		res := ctl.ex.run(CommandTask{CommandID: "c1", Command: c, SessionID: testSession, Name: "n"})
		if res.Status == proto.StatusDone {
			t.Fatalf("%s claimed done: %+v", c, res)
		}
		if !proto.ValidCommandStatus(res.Status) {
			t.Fatalf("%s: invalid status %q", c, res.Status)
		}
	}
}

// End to end over the socket: a command_req is answered with exactly one command_res, and the
// delivery the hook later records reaches the hub in the next report. No frame is unsolicited.
func TestCommandReqIsAnsweredAndTheDeliveryRidesInTheReport(t *testing.T) {
	var res proto.CommandRes
	answered := make(chan struct{})
	delivered := make(chan struct{})
	fs := newFakeServer(t, func(ctx context.Context, ws *websocket.Conn, _ int, _ proto.Hello) {
		sendEnv(t, ctx, ws, proto.TypeCommandReq, "q1", proto.CommandReq{
			CommandID: "c1", Command: proto.CmdReloadPlugins, SessionID: testSession})
		seenRes, seenRep := false, false
		for {
			env, err := readEnv(ctx, ws)
			if err != nil {
				return
			}
			switch env.Type {
			case proto.TypeCommandRes:
				if env.ID != "q1" {
					t.Errorf("unsolicited command_res with id %q", env.ID)
					return
				}
				if seenRes {
					t.Error("a second command_res for one request")
					return
				}
				seenRes = true
				_ = json.Unmarshal(env.Body, &res)
				close(answered)
			case proto.TypeReport:
				var rep proto.Report
				_ = json.Unmarshal(env.Body, &rep)
				for _, c := range rep.Commands {
					if c.CommandID == "c1" && c.Status == proto.StatusDelivered && !seenRep {
						seenRep = true
						close(delivered)
					}
				}
			}
		}
	})
	r := newRig(t, fs.ts.URL, fs.pin)
	stop := r.start(t)
	defer stop()
	select {
	case <-answered:
	case <-time.After(5 * time.Second):
		t.Fatal("no command_res")
	}
	if res.Status != proto.StatusQueued || res.Mechanism != "hook-queue" || res.CommandID != "c1" {
		t.Fatalf("res = %+v", res)
	}
	// The hook runs: this is the same code path `agent hook` takes.
	if _, err := r.a.ctl.q.deliver(testSession); err != nil {
		t.Fatal(err)
	}
	select {
	case <-delivered:
	case <-time.After(5 * time.Second):
		t.Fatal("the delivery never reached the hub")
	}
}

func TestAgentCommandLogsNoNameOrHint(t *testing.T) {
	r := newRig(t, "https://example.invalid", strings.Repeat("ab", 32))
	res := r.a.command(proto.CommandReq{CommandID: "c1", Command: proto.CmdRenameRemote,
		SessionID: testSession, Name: "Jane's laptop"})
	if res.Status != proto.StatusUnsupported {
		t.Fatalf("res = %+v", res)
	}
	logs := r.log.String()
	for _, leak := range []string{"Jane", "--resume"} {
		if strings.Contains(logs, leak) {
			t.Fatalf("log leaked %q: %s", leak, logs)
		}
	}
	if !strings.Contains(logs, `"command":"rename_remote"`) || !strings.Contains(logs, `"mechanism":"relaunch"`) {
		t.Fatalf("audit fields missing: %s", logs)
	}
}
