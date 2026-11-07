package agent

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"claude-utilities/internal/proto"
	"claude-utilities/internal/sessions"
)

// relaunch_remote: the ONE mechanism on a host that stops a process.
//
// It exists because a relaunch is the only thing that binds Remote Control to a running session
// (docs/runbooks/session-control.md), and the operator asked for it behind a confirm that names
// the cost. The guards are all here, in the agent, so a hub bug cannot widen them:
//
//   - the session id is a UUID, matched before it reaches a file name or an argument;
//   - the pid's own session file must carry that same id, and the pid must be alive with the
//     recorded start time (sessions.Alive), so a reused pid is never signalled;
//   - the session must be "idle" in its own file, checked here and not trusted from the hub;
//   - the cwd must be an absolute existing directory, and claude must be found, BEFORE the kill:
//     once the old process is gone there is no way back to it;
//   - the new process is started with exec arguments only, never a shell, so nothing from a file
//     is interpolated into a command line.
//
// The result stays unsupported/requires-restart until a read-back sees the resumed session publish
// a bridgeSessionId different from the one it had. A successful start proves nothing about that.
// Whether `--resume` re-enables the bridge for a session that had none is unproven.

const (
	relaunchMechName = "relaunch-process"
	idleStatus       = "idle"
	// Real timings: 12 x 250 ms for the old process to exit, 40 x 250 ms for the new bridge. The
	// agent handles hub frames serially, so the worst case holds up the connection for ~13 s; the
	// hub's per-target deadline is 60 s and this command is session-scoped, one target.
	defaultPollEvery     = 250 * time.Millisecond
	defaultExitPolls     = 12
	defaultReadBackPolls = 40
)

// relaunchSpec is everything the new process is started with. There is no shell string.
type relaunchSpec struct {
	Exe  string
	Args []string
	Dir  string
	Env  []string
}

// relaunchProcMechanism carries out relaunch_remote. Every side effect is a seam, so tests never
// start a real claude or stop a real process.
type relaunchProcMechanism struct {
	mu            sync.Mutex // relaunches run one at a time: two asks must not race one pid
	dir           func() (string, error)
	alive         func(pid int, procStart string) bool
	lookPath      func(string) (string, error)
	kill          func(pid int) error
	start         func(relaunchSpec) error
	getenv        func(string) string
	environ       func() []string
	sleep         func(time.Duration)
	pollEvery     time.Duration
	exitPolls     int
	readBackPolls int
}

func newRelaunchProcMechanism() *relaunchProcMechanism {
	return &relaunchProcMechanism{
		dir: sessions.Dir, alive: sessions.Alive, lookPath: lookClaude,
		kill: killProcess, start: startDetached,
		getenv: os.Getenv, environ: os.Environ, sleep: time.Sleep,
		pollEvery: defaultPollEvery, exitPolls: defaultExitPolls, readBackPolls: defaultReadBackPolls,
	}
}

func (*relaunchProcMechanism) Name() string { return relaunchMechName }

// validCwd accepts only an absolute path to an existing directory with no control characters.
func validCwd(cwd string) bool {
	if cwd == "" || !filepath.IsAbs(cwd) {
		return false
	}
	for _, r := range cwd {
		if unicode.IsControl(r) {
			return false
		}
	}
	st, err := os.Stat(filepath.Clean(cwd))
	return err == nil && st.IsDir()
}

// withConfigDir returns env with CLAUDE_CONFIG_DIR set to cfg (replacing any existing entry), or
// env unchanged when cfg is empty.
func withConfigDir(env []string, cfg string) []string {
	if cfg == "" {
		return env
	}
	const key = "CLAUDE_CONFIG_DIR="
	out := make([]string, 0, len(env)+1)
	set := false
	for _, e := range env {
		if strings.HasPrefix(e, key) {
			if !set {
				out = append(out, key+cfg)
				set = true
			}
			continue
		}
		out = append(out, e)
	}
	if !set {
		out = append(out, key+cfg)
	}
	return out
}

func (m *relaunchProcMechanism) Execute(task CommandTask) CommandResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	fail := func(code, hint string) CommandResult { return failed(relaunchMechName, code, hint) }

	if !sessionIDRe.MatchString(task.SessionID) {
		return fail(proto.CodeBadSessionID, "")
	}
	dir, err := m.dir()
	if err != nil || task.PID <= 0 {
		return fail(proto.CodeSessionGone, "")
	}
	sf, err := readSessionFile(dir, task.PID)
	if err != nil || sf.SessionID != task.SessionID || !m.alive(sf.PID, string(sf.ProcStart)) {
		return fail(proto.CodeSessionGone, "")
	}
	if sf.Status != idleStatus {
		return fail(proto.CodeNotIdle, "only an idle session is relaunched: a running turn would be lost")
	}
	if !validCwd(sf.Cwd) {
		return fail(proto.CodeBadCwd, "")
	}
	exe, err := m.lookPath("claude")
	if err != nil || exe == "" {
		return fail(proto.CodeNoClaude, "claude was not found on this host's PATH; nothing was stopped")
	}
	manual := RelaunchCommand(task.SessionID, task.Name)

	if err := m.kill(sf.PID); err != nil {
		return fail(proto.CodeKillFailed, "the session could not be stopped, so nothing was started")
	}
	if !m.waitGone(sf) {
		return fail(proto.CodeKillFailed, "the session did not exit, so nothing was started")
	}
	spec := relaunchSpec{Exe: exe, Dir: filepath.Clean(sf.Cwd),
		Args: []string{"--resume", task.SessionID, "--remote-control"},
		Env:  withConfigDir(m.environ(), m.getenv("CLAUDE_CONFIG_DIR"))}
	if err := m.start(spec); err != nil {
		return fail(proto.CodeStartFailed,
			"the old session was stopped and the new one did not start. Run it yourself: "+manual)
	}
	if m.sawNewBridge(dir, task.SessionID, sf) {
		return CommandResult{Status: proto.StatusDone, Code: proto.CodeRelaunched, Mechanism: relaunchMechName,
			Hint: "the session was relaunched and published a new remote-control bridge"}
	}
	return unsupported(relaunchMechName, proto.CodeRequiresRestart,
		"a relaunch was started but no new remote-control bridge was seen yet (it may need a terminal, "+
			"or resume may not enable the bridge). To do it by hand: "+manual)
}

// waitGone polls until the old process is no longer alive.
func (m *relaunchProcMechanism) waitGone(sf sessionFile) bool {
	for i := 0; ; i++ {
		if !m.alive(sf.PID, string(sf.ProcStart)) {
			return true
		}
		if i >= m.exitPolls {
			return false
		}
		m.sleep(m.pollEvery)
	}
}

// sawNewBridge polls the sessions dir for the resumed session: same session id, a different live
// process, and a bridgeSessionId that is set and differs from the old session's.
func (m *relaunchProcMechanism) sawNewBridge(dir, sessionID string, old sessionFile) bool {
	for i := 0; ; i++ {
		if m.resumedWithNewBridge(dir, sessionID, old) {
			return true
		}
		if i >= m.readBackPolls {
			return false
		}
		m.sleep(m.pollEvery)
	}
}

func (m *relaunchProcMechanism) resumedWithNewBridge(dir, sessionID string, old sessionFile) bool {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range ents {
		name := e.Name()
		// only "<pid>.json": exactly one dot, so "<pid>.<hash>.key" (a secret) is never opened
		if e.IsDir() || !strings.HasSuffix(name, ".json") || strings.Count(name, ".") != 1 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSuffix(name, ".json"))
		if err != nil || pid <= 0 || pid == old.PID {
			continue
		}
		sf, err := readSessionFile(dir, pid)
		if err != nil || sf.SessionID != sessionID {
			continue
		}
		b := strings.TrimSpace(sf.BridgeSessionID)
		if b != "" && b != strings.TrimSpace(old.BridgeSessionID) && m.alive(sf.PID, string(sf.ProcStart)) {
			return true
		}
	}
	return false
}
