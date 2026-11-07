package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"claude-utilities/internal/proto"
)

// None of these tests may start a real claude or stop a real process. Every side effect goes
// through a seam on relaunchProcMechanism, and the fakes below record what they were asked.

type relaunchFixture struct {
	t        *testing.T
	sessions string // fake ~/.claude/sessions
	cwd      string
	mu       sync.Mutex
	dead     map[int]bool
	kills    []int
	starts   []relaunchSpec
	events   []string
	// onStart lets a test decide what the "new process" publishes.
	onStart  func(f *relaunchFixture, spec relaunchSpec) error
	killErr  error
	noExit   bool // the killed pid never dies
	noClaude bool
	m        *relaunchProcMechanism
}

const (
	relOldPID    = 4242
	relNewPID    = 5151
	relOldBridge = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	relNewBridge = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
)

func newRelaunchFixture(t *testing.T) *relaunchFixture {
	t.Helper()
	f := &relaunchFixture{t: t, sessions: t.TempDir(), dead: map[int]bool{},
		cwd: filepath.Join(t.TempDir(), "проект-日本語 work")}
	if err := os.MkdirAll(f.cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	f.onStart = func(f *relaunchFixture, _ relaunchSpec) error {
		f.writeSession(relNewPID, testSession, "idle", f.cwd, relNewBridge)
		return nil
	}
	f.m = &relaunchProcMechanism{
		dir:   func() (string, error) { return f.sessions, nil },
		alive: func(pid int, _ string) bool { f.mu.Lock(); defer f.mu.Unlock(); return !f.dead[pid] },
		lookPath: func(string) (string, error) {
			if f.noClaude {
				return "", errors.New("not found")
			}
			return "/fake/bin/claude", nil
		},
		kill: func(pid int) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.events = append(f.events, "kill")
			f.kills = append(f.kills, pid)
			if f.killErr != nil {
				return f.killErr
			}
			if !f.noExit {
				f.dead[pid] = true
			}
			return nil
		},
		start: func(spec relaunchSpec) error {
			f.mu.Lock()
			f.events = append(f.events, "start")
			f.starts = append(f.starts, spec)
			f.mu.Unlock()
			return f.onStart(f, spec)
		},
		getenv:        func(k string) string { return map[string]string{"CLAUDE_CONFIG_DIR": "/cfg/claude"}[k] },
		environ:       func() []string { return []string{"PATH=/bin", "CLAUDE_CONFIG_DIR=/old", "HOME=/h"} },
		sleep:         func(time.Duration) {},
		pollEvery:     time.Millisecond,
		exitPolls:     3,
		readBackPolls: 3,
	}
	return f
}

func (f *relaunchFixture) writeSession(pid int, id, status, cwd, bridge string) {
	f.t.Helper()
	rec := map[string]any{"pid": pid, "sessionId": id, "status": status, "cwd": cwd,
		"procStart": "1", "name": "alpha"}
	if bridge != "" {
		rec["bridgeSessionId"] = bridge
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.sessions, strconv.Itoa(pid)+".json"), raw, 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *relaunchFixture) task() CommandTask {
	return CommandTask{CommandID: "c1", Command: proto.CmdRelaunchRemote, SessionID: testSession,
		PID: relOldPID, Name: "alpha"}
}

func (f *relaunchFixture) old(status string) {
	f.writeSession(relOldPID, testSession, status, f.cwd, relOldBridge)
}

func (f *relaunchFixture) untouched(res CommandResult, code string) {
	f.t.Helper()
	if res.Status != proto.StatusFailed || res.Code != code {
		f.t.Fatalf("res = %+v, want failed/%s", res, code)
	}
	if len(f.kills) != 0 || len(f.starts) != 0 {
		f.t.Fatalf("refused ask still acted: kills=%v starts=%v", f.kills, f.starts)
	}
}

func TestRelaunchHappyPathKillsThenStartsAndReportsRelaunchedOnlyAfterANewBridge(t *testing.T) {
	f := newRelaunchFixture(t)
	f.old("idle")
	res := f.m.Execute(f.task())
	if res.Status != proto.StatusDone || res.Code != proto.CodeRelaunched || res.Mechanism != "relaunch-process" {
		t.Fatalf("res = %+v", res)
	}
	if len(f.kills) != 1 || f.kills[0] != relOldPID {
		t.Fatalf("kills = %v", f.kills)
	}
	if strings.Join(f.events, ",") != "kill,start" {
		t.Fatalf("order = %v, want kill then start", f.events)
	}
	spec := f.starts[0]
	if spec.Exe != "/fake/bin/claude" || spec.Dir != f.cwd {
		t.Fatalf("spec = %+v", spec)
	}
	if got := strings.Join(spec.Args, " "); got != "--resume "+testSession+" --remote-control" {
		t.Fatalf("args = %q", got)
	}
	// Same config dir: the agent's own value wins and appears exactly once.
	n := 0
	for _, e := range spec.Env {
		if strings.HasPrefix(e, "CLAUDE_CONFIG_DIR=") {
			n++
			if e != "CLAUDE_CONFIG_DIR=/cfg/claude" {
				t.Fatalf("env = %q", e)
			}
		}
	}
	if n != 1 {
		t.Fatalf("CLAUDE_CONFIG_DIR appears %d times in %v", n, spec.Env)
	}
}

// The status stays unsupported-requires-restart until a read-back SEES a new bridge. A start that
// succeeded is not evidence of one.
func TestRelaunchWithoutANewBridgeStaysUnsupportedRequiresRestart(t *testing.T) {
	cases := map[string]func(f *relaunchFixture, _ relaunchSpec) error{
		"nothing published": func(*relaunchFixture, relaunchSpec) error { return nil },
		"no bridge bound": func(f *relaunchFixture, _ relaunchSpec) error {
			f.writeSession(relNewPID, testSession, "idle", f.cwd, "")
			return nil
		},
		"same bridge id as before": func(f *relaunchFixture, _ relaunchSpec) error {
			f.writeSession(relNewPID, testSession, "idle", f.cwd, relOldBridge)
			return nil
		},
		"another session's bridge": func(f *relaunchFixture, _ relaunchSpec) error {
			f.writeSession(relNewPID, testSession2, "idle", f.cwd, relNewBridge)
			return nil
		},
		"new bridge but process not alive": func(f *relaunchFixture, _ relaunchSpec) error {
			f.writeSession(relNewPID, testSession, "idle", f.cwd, relNewBridge)
			f.dead[relNewPID] = true
			return nil
		},
	}
	for name, onStart := range cases {
		t.Run(name, func(t *testing.T) {
			f := newRelaunchFixture(t)
			f.old("idle")
			f.onStart = onStart
			res := f.m.Execute(f.task())
			if res.Status != proto.StatusUnsupported || res.Code != proto.CodeRequiresRestart {
				t.Fatalf("res = %+v", res)
			}
			if !strings.Contains(res.Hint, "claude --resume "+testSession) {
				t.Fatalf("hint should carry the manual command: %q", res.Hint)
			}
			if len(f.kills) != 1 || len(f.starts) != 1 {
				t.Fatalf("kills=%v starts=%v", f.kills, f.starts)
			}
		})
	}
}

func TestRelaunchRefusesASessionThatIsNotIdle(t *testing.T) {
	for _, status := range []string{"busy", "", "waiting", "IDLE ", "running"} {
		t.Run("status="+status, func(t *testing.T) {
			f := newRelaunchFixture(t)
			f.old(status)
			f.untouched(f.m.Execute(f.task()), proto.CodeNotIdle)
		})
	}
}

func TestRelaunchRefusesWhatItCannotPinToTheSessionAskedFor(t *testing.T) {
	t.Run("unknown session: no file", func(t *testing.T) {
		f := newRelaunchFixture(t)
		f.untouched(f.m.Execute(f.task()), proto.CodeSessionGone)
	})
	t.Run("pid file belongs to another session id", func(t *testing.T) {
		f := newRelaunchFixture(t)
		f.writeSession(relOldPID, testSession2, "idle", f.cwd, relOldBridge)
		f.untouched(f.m.Execute(f.task()), proto.CodeSessionGone)
	})
	t.Run("pid already gone", func(t *testing.T) {
		f := newRelaunchFixture(t)
		f.old("idle")
		f.dead[relOldPID] = true
		f.untouched(f.m.Execute(f.task()), proto.CodeSessionGone)
	})
	t.Run("no pid in the task", func(t *testing.T) {
		f := newRelaunchFixture(t)
		f.old("idle")
		task := f.task()
		task.PID = 0
		f.untouched(f.m.Execute(task), proto.CodeSessionGone)
	})
	t.Run("sessions dir unresolvable", func(t *testing.T) {
		f := newRelaunchFixture(t)
		f.m.dir = func() (string, error) { return "", errors.New("no home") }
		f.untouched(f.m.Execute(f.task()), proto.CodeSessionGone)
	})
}

func TestRelaunchRefusesASessionIDThatIsNotAUUID(t *testing.T) {
	for _, id := range []string{"", "../../etc/passwd", "$(id)", "a; rm -rf /", testSession + " --x",
		strings.ToUpper(testSession) + "\n", "11111111-2222-3333-4444-55555555555z", "ünï-çödé"} {
		f := newRelaunchFixture(t)
		f.old("idle")
		task := f.task()
		task.SessionID = id
		res := f.m.Execute(task)
		if res.Status != proto.StatusFailed || res.Code != proto.CodeBadSessionID {
			t.Fatalf("id %q: res = %+v", id, res)
		}
		f.untouched(res, proto.CodeBadSessionID)
	}
}

func TestRelaunchRefusesACwdItCannotUse(t *testing.T) {
	f0 := newRelaunchFixture(t)
	file := filepath.Join(f0.cwd, "afile")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"missing":  filepath.Join(f0.cwd, "gone"),
		"empty":    "",
		"relative": "some/where",
		"a file":   file,
		"NUL":      f0.cwd + "\x00/x",
		"newline":  f0.cwd + "\n",
	}
	for name, cwd := range cases {
		t.Run(name, func(t *testing.T) {
			f := newRelaunchFixture(t)
			f.writeSession(relOldPID, testSession, "idle", cwd, relOldBridge)
			f.untouched(f.m.Execute(f.task()), proto.CodeBadCwd)
		})
	}
}

func TestRelaunchChecksForClaudeBeforeKillingAnything(t *testing.T) {
	f := newRelaunchFixture(t)
	f.old("idle")
	f.noClaude = true
	f.untouched(f.m.Execute(f.task()), proto.CodeNoClaude)
}

func TestRelaunchKillFailureStartsNothing(t *testing.T) {
	t.Run("kill errors", func(t *testing.T) {
		f := newRelaunchFixture(t)
		f.old("idle")
		f.killErr = errors.New("access denied")
		res := f.m.Execute(f.task())
		if res.Status != proto.StatusFailed || res.Code != proto.CodeKillFailed {
			t.Fatalf("res = %+v", res)
		}
		if len(f.starts) != 0 {
			t.Fatalf("started a second process while the first may be alive: %v", f.starts)
		}
		if strings.Contains(res.Hint, "access denied") {
			t.Fatalf("raw error text leaked into the hint: %q", res.Hint)
		}
	})
	t.Run("kill returns but the process never exits", func(t *testing.T) {
		f := newRelaunchFixture(t)
		f.old("idle")
		f.noExit = true
		res := f.m.Execute(f.task())
		if res.Status != proto.StatusFailed || res.Code != proto.CodeKillFailed || len(f.starts) != 0 {
			t.Fatalf("res = %+v starts=%v", res, f.starts)
		}
	})
}

func TestRelaunchStartFailureAfterTheKillSaysSoAndGivesTheManualCommand(t *testing.T) {
	f := newRelaunchFixture(t)
	f.old("idle")
	f.onStart = func(*relaunchFixture, relaunchSpec) error { return errors.New("exec: boom") }
	res := f.m.Execute(f.task())
	if res.Status != proto.StatusFailed || res.Code != proto.CodeStartFailed {
		t.Fatalf("res = %+v", res)
	}
	if !strings.Contains(res.Hint, "claude --resume "+testSession+" --remote-control") {
		t.Fatalf("hint = %q", res.Hint)
	}
	if strings.Contains(res.Hint, "boom") {
		t.Fatalf("raw error leaked: %q", res.Hint)
	}
}

func TestRelaunchRunsConcurrentAsksSeriallyAndKillsEachSessionOnce(t *testing.T) {
	f := newRelaunchFixture(t)
	const n = 8
	for i := 0; i < n; i++ {
		f.writeSession(1000+i, testSession, "idle", f.cwd, relOldBridge)
	}
	// every new process publishes a fresh bridge for the id asked
	f.onStart = func(f *relaunchFixture, spec relaunchSpec) error {
		f.writeSession(9000+len(f.starts), testSession, "idle", f.cwd, relNewBridge)
		return nil
	}
	var wg sync.WaitGroup
	results := make([]CommandResult, n+4)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			task := f.task()
			task.PID = 1000 + i
			results[i] = f.m.Execute(task)
		}()
	}
	// The same pid asked for four times at once must be killed once; the rest see it gone.
	f2 := newRelaunchFixture(t)
	f2.old("idle")
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results[n+i] = f2.m.Execute(f2.task()) }()
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		if results[i].Status != proto.StatusDone {
			t.Fatalf("task %d: %+v", i, results[i])
		}
	}
	if len(f.kills) != n {
		t.Fatalf("kills = %v, want %d", f.kills, n)
	}
	if len(f2.kills) != 1 {
		t.Fatalf("same pid killed %d times: %v", len(f2.kills), f2.kills)
	}
}

func TestRelaunchIsRegisteredOnlyForItsOwnCommandAndNeverTheInbox(t *testing.T) {
	for _, inbox := range []bool{false, true} {
		ctl, _ := newTestControl(t, inbox)
		ms := ctl.ex.mechanisms(proto.CmdRelaunchRemote)
		if len(ms) != 1 || ms[0].Name() != "relaunch-process" {
			t.Fatalf("inbox=%v: mechanisms = %v", inbox, ms)
		}
		// and the process-killing mechanism is registered for nothing else
		for _, c := range []string{proto.CmdReloadPlugins, proto.CmdRemoteControlEnable,
			proto.CmdRenameRemote, proto.CmdRestartSessions} {
			for _, m := range ctl.ex.mechanisms(c) {
				if m.Name() == "relaunch-process" {
					t.Fatalf("%s must not be able to kill a session", c)
				}
			}
		}
	}
}

// The default mechanism points at the real seams. Asking it about a pid with no session file must
// refuse before anything is killed or started - this is the safety net for a wiring mistake.
func TestRelaunchDefaultMechanismRefusesAnUnknownSessionWithoutActing(t *testing.T) {
	ctl, _ := newTestControl(t, false)
	res := ctl.ex.run(CommandTask{CommandID: "c1", Command: proto.CmdRelaunchRemote,
		SessionID: testSession, PID: 0})
	if res.Status != proto.StatusFailed || res.Code != proto.CodeSessionGone {
		t.Fatalf("res = %+v", res)
	}
}

func TestWithConfigDirReplacesAnExistingValueOrAddsOne(t *testing.T) {
	got := withConfigDir([]string{"A=1", "CLAUDE_CONFIG_DIR=/old", "B=2"}, "/new")
	if strings.Join(got, ";") != "A=1;CLAUDE_CONFIG_DIR=/new;B=2" {
		t.Fatalf("got %v", got)
	}
	got = withConfigDir([]string{"A=1"}, "/new")
	if strings.Join(got, ";") != "A=1;CLAUDE_CONFIG_DIR=/new" {
		t.Fatalf("got %v", got)
	}
	got = withConfigDir([]string{"A=1", "CLAUDE_CONFIG_DIR=/old"}, "")
	if strings.Join(got, ";") != "A=1;CLAUDE_CONFIG_DIR=/old" {
		t.Fatalf("an unset value must leave the environment alone: %v", got)
	}
}
