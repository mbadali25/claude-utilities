package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"claude-utilities/internal/credfile"
	"claude-utilities/internal/proto"
)

// Session control on the host. The hub says WHAT to do; this file decides HOW, through a registry
// of mechanisms per command. A mechanism that cannot do a thing reports StatusUnsupported with a
// reason code rather than claiming a success nobody can see:
//
//   - inbox: the per-session message socket, the one channel from outside that reaches a RUNNING
//     session. It renames, and that is all it does: it has no action that enables Remote Control,
//     and injecting slash-command text would cost an API turn without running the command. Off
//     unless CLAUDESWAP_EXPERIMENTAL_INBOX=1, real when on. Ceiling: "delivered". See inbox.go.
//   - relaunch: Remote Control cannot be turned on from outside a running session at all, and a
//     session with no bridge bound has nothing a rename could push a title to, so both of those
//     end here. The mechanism returns the exact command for an operator to run. It never starts
//     or stops a process: killing a session would throw away the operator's work.
//   - hook-queue: an instruction file per session, read by the `agent hook` subcommand installed
//     as a SessionStart/UserPromptSubmit hook. A hook can only put text in front of the model
//     (spike G), so this mechanism can honestly reach "delivered" and never "done".
//
// docs/runbooks/session-control.md has the whole picture.

// ExperimentalInboxEnv turns the inbox mechanism on. It is off by default - Matthew has not
// enabled it - and when it is off nothing in this program connects to a session's socket.
const ExperimentalInboxEnv = "CLAUDESWAP_EXPERIMENTAL_INBOX"

const (
	// commandDirName holds one instruction queue file per session, under the agent's state dir.
	commandDirName = "commands"
	// maxQueueEntries bounds one session's queue.
	maxQueueEntries = 16
	// maxQueueFiles bounds how many sessions may have a queue at once.
	maxQueueFiles = 64
	// queueEntryTTL is how long an undelivered instruction stays worth injecting. Past it the
	// session has almost certainly been restarted and the instruction is stale.
	queueEntryTTL = 24 * time.Hour
)

// sessionIDRe matches the 36-character session id `claude --resume` takes. Anything else is
// refused: the id names a file on disk and goes into a command string an operator may paste.
var sessionIDRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// CommandTask is one command for one session, as the hub asked for it.
type CommandTask struct {
	CommandID string
	Command   string
	SessionID string
	PID       int
	// Name is the remote title a rename should set. It may name a person: never log it.
	Name string
}

// CommandResult is what a mechanism can honestly claim.
type CommandResult struct {
	Status    string
	Code      string
	Mechanism string
	// Hint is operator-facing text (for example the relaunch command). Never logged.
	Hint string
}

func unsupported(mechanism, code, hint string) CommandResult {
	return CommandResult{Status: proto.StatusUnsupported, Code: code, Mechanism: mechanism, Hint: hint}
}

func failed(mechanism, code, hint string) CommandResult {
	return CommandResult{Status: proto.StatusFailed, Code: code, Mechanism: mechanism, Hint: hint}
}

// Mechanism carries out one session command. Execute must never block for long: the hub is waiting
// on the reply, and a slow mechanism stalls every later target on this host.
type Mechanism interface {
	// Name is the mechanism's wire name, reported to the hub and shown to the operator.
	Name() string
	// Execute carries the task out as far as it honestly can.
	Execute(task CommandTask) CommandResult
}

// executor routes a command to the mechanisms registered for it, in order. The first result that
// is not "unsupported" wins; if every mechanism declines, the last decline is returned, so the
// operator sees a real reason code instead of a generic refusal.
type executor struct {
	mechs map[string][]Mechanism
}

func newExecutor() *executor { return &executor{mechs: map[string][]Mechanism{}} }

func (e *executor) register(command string, m Mechanism) {
	e.mechs[command] = append(e.mechs[command], m)
}

// mechanisms returns the mechanisms registered for a command, in order.
func (e *executor) mechanisms(command string) []Mechanism { return e.mechs[command] }

func (e *executor) run(task CommandTask) CommandResult {
	if !proto.ValidCommand(task.Command) || task.Command == proto.CmdRepair {
		// repair is a hub-side composite: it is expanded there and never arrives as one command.
		return unsupported("", proto.CodeUnknownCommand, "")
	}
	ms := e.mechs[task.Command]
	if len(ms) == 0 {
		return unsupported("", proto.CodeNoMechanism, "")
	}
	var last CommandResult
	for _, m := range ms {
		res := m.Execute(task)
		if res.Mechanism == "" {
			res.Mechanism = m.Name()
		}
		if res.Status != proto.StatusUnsupported {
			return res
		}
		last = res
	}
	return last
}

// --- relaunch ---

// relaunchMechanism reports the one thing that always works: an operator relaunching the session
// with Remote Control bound and the name given at bind time. It changes nothing on the host.
//
// For rename_remote it is the FALLBACK, not the mechanism: a rename reaches a running,
// bridge-bound session over its own inbox. Relaunch is what answers when there is no bridge bound
// to push a title to, or when the inbox is off.
type relaunchMechanism struct{}

func (relaunchMechanism) Name() string { return "relaunch" }

func (relaunchMechanism) Execute(task CommandTask) CommandResult {
	if !sessionIDRe.MatchString(task.SessionID) {
		return unsupported("relaunch", proto.CodeRequiresRestart,
			"restart this session by hand: nothing outside it can enable Remote Control, "+
				"and a session with no bridge bound cannot be given a remote title")
	}
	return unsupported("relaunch", proto.CodeRequiresRestart, RelaunchCommand(task.SessionID, task.Name))
}

// safeNameRe matches a name that can be pasted into a shell inside double quotes with nothing to
// escape. A name with a quote, a backslash or a shell metacharacter is left out of the command
// instead of being mangled, and the operator is told to set it after the relaunch.
var safeNameRe = regexp.MustCompile(`^[\p{L}\p{N} ._\-+/:@#]+$`)

// RelaunchCommand is the command an operator runs to restart a session with Remote Control bound
// and, when the name is safe to quote, that name set at bind. The returned string is for a human
// to read and paste; nothing in this program ever executes it.
func RelaunchCommand(sessionID, name string) string {
	cmd := "claude --resume " + sessionID + " --remote-control"
	name = proto.CleanRemoteName(name)
	if name == "" {
		return cmd
	}
	if !safeNameRe.MatchString(name) {
		return cmd + "   (then set the name in the session: the name needs shell quoting)"
	}
	if strings.ContainsRune(name, ' ') {
		return cmd + ` "` + name + `"`
	}
	return cmd + " " + name
}

// --- hook queue ---

// queueEntry is one instruction waiting for the session to notice it. It holds no secret.
type queueEntry struct {
	CommandID string    `json:"commandId"`
	Command   string    `json:"command"`
	Name      string    `json:"name,omitempty"`
	QueuedAt  time.Time `json:"queuedAt"`
	// DeliveredAt is set by the hook once the instruction has been put in front of the model.
	DeliveredAt *time.Time `json:"deliveredAt,omitempty"`
}

// queueFile is one session's instruction queue.
type queueFile struct {
	SessionID string       `json:"sessionId"`
	Entries   []queueEntry `json:"entries"`
}

// queue is the on-disk instruction queue. The directory is owner-only and every write is atomic.
type queue struct {
	dir string
	now func() time.Time
	mu  sync.Mutex
}

func newQueue(stateDir string, now func() time.Time) *queue {
	return &queue{dir: filepath.Join(stateDir, commandDirName), now: now}
}

func (q *queue) path(sessionID string) string { return filepath.Join(q.dir, sessionID+".json") }

// ErrBadSessionID means a session id is not the shape the queue will put in a file name.
var ErrBadSessionID = errors.New("agent: session id is not a session id")

func (q *queue) read(sessionID string) (queueFile, error) {
	if !sessionIDRe.MatchString(sessionID) {
		return queueFile{}, ErrBadSessionID
	}
	// #nosec G304 -- the path is the queue dir plus a session id matched against sessionIDRe
	data, err := os.ReadFile(filepath.Clean(q.path(sessionID)))
	if errors.Is(err, os.ErrNotExist) {
		return queueFile{SessionID: sessionID}, nil
	}
	if err != nil {
		return queueFile{}, fmt.Errorf("agent: read command queue: %w", err)
	}
	var f queueFile
	if err := json.Unmarshal(data, &f); err != nil {
		// A corrupt queue is dropped rather than left to block every later instruction.
		return queueFile{SessionID: sessionID}, nil
	}
	f.SessionID = sessionID
	f.Entries = q.fresh(f.Entries)
	return f, nil
}

// fresh drops entries past the TTL: a session that never read them has almost certainly restarted.
func (q *queue) fresh(in []queueEntry) []queueEntry {
	cut := q.now().Add(-queueEntryTTL)
	out := make([]queueEntry, 0, len(in))
	for _, e := range in {
		if e.QueuedAt.After(cut) {
			out = append(out, e)
		}
	}
	return out
}

func (q *queue) write(f queueFile) error {
	if !sessionIDRe.MatchString(f.SessionID) {
		return ErrBadSessionID
	}
	if q.dir == commandDirName {
		// newQueue was given no state dir, so there is nowhere safe to write: a relative path
		// would land in whatever directory the agent happens to be running in.
		return errors.New("agent: no state dir for the command queue")
	}
	if len(f.Entries) == 0 {
		if err := os.Remove(q.path(f.SessionID)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("agent: clear command queue: %w", err)
		}
		return nil
	}
	if err := os.MkdirAll(q.dir, 0o700); err != nil {
		return fmt.Errorf("agent: command queue dir: %w", err)
	}
	if err := credfile.RestrictDir(q.dir); err != nil {
		return fmt.Errorf("agent: restrict command queue dir: %w", err)
	}
	data, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("agent: marshal command queue: %w", err)
	}
	return writePrivate(q.path(f.SessionID), data)
}

// enqueue adds one instruction for a session, replacing an earlier entry with the same command id.
func (q *queue) enqueue(task CommandTask) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	f, err := q.read(task.SessionID)
	if err != nil {
		return err
	}
	if len(f.Entries) == 0 && q.atFileBound(task.SessionID) {
		return errQueueFull
	}
	keep := make([]queueEntry, 0, len(f.Entries)+1)
	have := false
	for _, e := range f.Entries {
		switch {
		case e.DeliveredAt != nil:
			// A delivered entry is not pending any more, and dropping it would throw away the
			// notice the next report owes the hub - which would make the hub time a command out
			// as failed although it was delivered. confirmReported is the only thing that may
			// remove one.
			keep = append(keep, e)
			have = have || e.CommandID == task.CommandID
		case e.CommandID == task.CommandID || e.Command == task.Command:
			// One PENDING instruction per command per session: a repeat replaces it rather than
			// asking the model twice for the same thing.
		default:
			keep = append(keep, e)
		}
	}
	if have {
		// This very command has already been delivered; queueing it again would ask twice and
		// report twice. Write back whatever pending duplicates were folded away and stop.
		f.Entries = keep
		return q.write(f)
	}
	if len(keep) >= maxQueueEntries {
		return errQueueFull
	}
	f.Entries = append(keep, queueEntry{CommandID: task.CommandID, Command: task.Command,
		Name: task.Name, QueuedAt: q.now()})
	return q.write(f)
}

var errQueueFull = errors.New("agent: command queue is full")

// atFileBound reports whether adding a queue for a new session would pass maxQueueFiles.
func (q *queue) atFileBound(sessionID string) bool {
	ents, err := os.ReadDir(q.dir)
	if err != nil {
		return false
	}
	n := 0
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") && e.Name() != sessionID+".json" {
			n++
		}
	}
	return n >= maxQueueFiles
}

// deliver marks every undelivered entry for a session as delivered and returns them, so the hook
// can tell the model about them. It is called from the short-lived `agent hook` process.
func (q *queue) deliver(sessionID string) ([]queueEntry, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	f, err := q.read(sessionID)
	if err != nil {
		return nil, err
	}
	now := q.now()
	var out []queueEntry
	for i := range f.Entries {
		if f.Entries[i].DeliveredAt == nil {
			t := now
			f.Entries[i].DeliveredAt = &t
			out = append(out, f.Entries[i])
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	if err := q.write(f); err != nil {
		return nil, err
	}
	return out, nil
}

// delivered lists the delivered entries across every session's queue, oldest first, capped at
// proto.MaxCommandsPerReport. These are what the agent tells the hub about on its next report.
func (q *queue) delivered() []proto.SessionCommandStatus {
	q.mu.Lock()
	defer q.mu.Unlock()
	ents, err := os.ReadDir(q.dir)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, strings.TrimSuffix(e.Name(), ".json"))
		}
	}
	sort.Strings(names)
	type stamped struct {
		at time.Time
		s  proto.SessionCommandStatus
	}
	var all []stamped
	for _, id := range names {
		f, err := q.read(id)
		if err != nil {
			continue
		}
		for _, e := range f.Entries {
			if e.DeliveredAt != nil {
				all = append(all, stamped{at: *e.DeliveredAt,
					s: proto.SessionCommandStatus{CommandID: e.CommandID, Status: proto.StatusDelivered}})
			}
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
	out := make([]proto.SessionCommandStatus, 0, len(all))
	for _, x := range all {
		if len(out) == proto.MaxCommandsPerReport {
			break
		}
		out = append(out, x.s)
	}
	return out
}

// confirmReported drops entries the hub has now been told about. It runs only after the report was
// written to the socket, so a failed send keeps the entry and the next report repeats it.
func (q *queue) confirmReported(ss []proto.SessionCommandStatus) {
	if len(ss) == 0 {
		return
	}
	done := make(map[string]bool, len(ss))
	for _, s := range ss {
		done[s.CommandID] = true
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	ents, err := os.ReadDir(q.dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		f, err := q.read(id)
		if err != nil {
			continue
		}
		keep := make([]queueEntry, 0, len(f.Entries))
		for _, x := range f.Entries {
			if x.DeliveredAt == nil || !done[x.CommandID] {
				keep = append(keep, x)
			}
		}
		if len(keep) != len(f.Entries) {
			f.Entries = keep
			_ = q.write(f)
		}
	}
}

// queueMechanism writes an instruction the session's hook will put in front of the model. Its
// ceiling is "delivered": a hook cannot run a slash command (spike G), so nothing here can prove
// the command ran, and it must never claim "done".
type queueMechanism struct{ q *queue }

func (queueMechanism) Name() string { return "hook-queue" }

func (m queueMechanism) Execute(task CommandTask) CommandResult {
	switch err := m.q.enqueue(task); {
	case err == nil:
	case errors.Is(err, ErrBadSessionID):
		return failed("hook-queue", proto.CodeBadSessionID, "")
	case errors.Is(err, errQueueFull):
		return failed("hook-queue", proto.CodeQueueFull, "")
	default:
		return failed("hook-queue", proto.CodeQueueWriteFailed, "")
	}
	return CommandResult{Status: proto.StatusQueued, Mechanism: "hook-queue",
		Hint: "queued for this session's hook; it asks the session to run /" +
			strings.ReplaceAll(task.Command, "_", "-") +
			" the next time the session reads a hook, which cannot be proved to have run"}
}

// --- the agent's own wiring ---

// control holds the host's command machinery.
type control struct {
	q  *queue
	ex *executor
}

// newControl builds the registry. The order inside each command is the order mechanisms are tried.
func newControl(stateDir string, now func() time.Time, inboxEnabled bool) *control {
	return newControlWith(stateDir, now, inboxEnabled, newInboxMechanism())
}

// newControlWith is newControl with the inbox mechanism supplied, so tests can register a fake
// socket instead of reaching a real session.
func newControlWith(stateDir string, now func() time.Time, inboxEnabled bool, inbox Mechanism) *control {
	q := newQueue(stateDir, now)
	ex := newExecutor()
	// reload_plugins: a hook can ask the model to run /reload-plugins. Nothing else can, and in
	// particular the inbox cannot: its enqueue path sets skipSlashCommands, so "/reload-plugins"
	// would arrive as literal text, cost an API turn and run nothing. hook-queue is the ONLY
	// mechanism registered here, flag or no flag.
	ex.register(proto.CmdReloadPlugins, queueMechanism{q: q})
	// rename_remote: the inbox is the mechanism. A rename frame reaches a running, bridge-bound
	// session's own rename handler, which pushes the title to the bridge. relaunch is the
	// FALLBACK, for a session with no bridge bound - and the only answer when the flag is off.
	if inboxEnabled {
		ex.register(proto.CmdRenameRemote, inbox)
	}
	ex.register(proto.CmdRenameRemote, relaunchMechanism{})
	// remote_control_enable: nothing outside a running session can bind its bridge. The inbox has
	// no action for it - the handler it would need is dead code in the session - so when the flag
	// is on it declines with no-mechanism, and relaunch answers with the command that does work.
	if inboxEnabled {
		ex.register(proto.CmdRemoteControlEnable, inbox)
	}
	ex.register(proto.CmdRemoteControlEnable, relaunchMechanism{})
	// restart_sessions: COPY-ONLY, and deliberately so. relaunch is its ONLY mechanism, and
	// relaunch starts and stops nothing - it returns the command for a human to run. Nothing on
	// this host can terminate a session, which is why no confirm token needs to exist to stop one.
	// The inbox is NOT registered here even when it is enabled: its whole accepted surface is a
	// rename and six notification actions, none of which stops a session, so offering it would
	// imply a kill path that does not and must not exist.
	// docs/runbooks/session-control.md records the decision.
	ex.register(proto.CmdRestartSessions, relaunchMechanism{})
	// relaunch_remote: the ONE command that stops a process. Its mechanism is registered for it
	// alone (never the inbox, never another command), is session-scoped and idle-only at the hub
	// and re-checked in the agent. See relaunch.go.
	ex.register(proto.CmdRelaunchRemote, newRelaunchProcMechanism())
	return &control{q: q, ex: ex}
}

// command runs one hub request and builds the reply.
func (a *agent) command(req proto.CommandReq) proto.CommandRes {
	task := CommandTask{CommandID: req.CommandID, Command: req.Command,
		SessionID: req.SessionID, PID: req.PID, Name: proto.CleanRemoteName(req.Name)}
	res := a.ctl.ex.run(task)
	// Only the command, the mechanism and the codes are logged: the name and the hint can carry a
	// person's name or a path.
	a.log.Info("session command", "action", "command", "command", task.Command,
		"mechanism", res.Mechanism, "result", res.Status, "reason", res.Code)
	return proto.CommandRes{CommandID: req.CommandID, Status: res.Status, Code: res.Code,
		Mechanism: res.Mechanism, Hint: res.Hint}
}
