package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"claude-utilities/internal/proto"
	"claude-utilities/internal/sessions"
)

// The per-session message inbox: the one channel from outside that reaches a RUNNING session.
//
// Wire protocol, decoded from Claude Code 2.1.318 (build ca1fa9de) and exercised live against a
// throwaway session on 2026-11-05:
//
//	connect  \\.\pipe\LOCAL\cc-msg-<32hex>          (Windows; a unix socket path off Windows)
//	send     {"type":"auth","token":"<peerToken>"}\n
//	send     {"type":"control","session_id":"<that session's OWN id>","action":"rename","name":"…"}\n
//
// The parts that matter, each one load-bearing:
//
//   - NDJSON. One JSON object per line, '\n'-terminated, no length prefix.
//   - The auth line is FIRST and is mandatory on Windows (the server sets requireAuth from the
//     platform). A control line on an unauthenticated connection is dropped and the connection is
//     closed. The token is the `peerToken` in that session's OWN <pid>.<64hex>.key file.
//   - A connection that sends no complete line within 30 s is closed, so both lines go out in one
//     write and the connection is closed straight after.
//   - session_id is ALWAYS set. The server drops a frame whose session_id is not its own
//     ("Dropping control message: session_id mismatch"), and that is the interlock this whole
//     feature leans on: a misdirected frame is a logged no-op in somebody else's session rather
//     than a rename of it.
//
// What the inbox CANNOT do, both proven rather than assumed:
//
//   - It cannot enable Remote Control. `onEnableRemoteControl` is dead code - its setter has
//     exactly one occurrence in the whole binary, its own definition, and the dispatcher never
//     reads the field. Live, `action:"enable_remote_control"` logs
//     "[uds-messaging] Unhandled control action: enable_remote_control". The
//     uds_enable_remote_control telemetry string exists with no reachable call site, so it proves
//     nothing. remote_control_enable therefore answers no-mechanism here.
//   - It cannot run a slash command. The user-message path sets skipSlashCommands, so "/x" is
//     enqueued as literal text: it costs an API turn and puts a visible user turn in somebody's
//     conversation without running anything. The inbox is deliberately NOT registered for
//     reload_plugins; hook-queue stays its only mechanism.
//
// The ceiling for a rename is `delivered`, never `done`. The host->bridge push inside Claude Code
// is `titleWriter.update(bridgeSessionId, name, …).catch(()=>{})` - fire and forget, its result
// discarded - so nothing on this host can observe whether the title on claude.ai changed. No code
// path here returns StatusDone for rename_remote.
//
// docs/runbooks/session-control.md carries the whole picture and what is still unverified.

const (
	// inboxSendTimeout bounds the whole dial-write-close, which runs off the calling goroutine. It
	// is the only bound on Windows, where opening a pipe client either succeeds or fails at once.
	inboxSendTimeout = 3 * time.Second
	// inboxVerifyWindow and inboxVerifyPoll bound the read-back of the session's own name.
	//
	// The arithmetic matters, because the agent handles hub frames SERIALLY on one connection: a
	// slow command does not just delay its own reply, it holds up every later target and the
	// heartbeat behind it. The hub fans out at most 256 targets per request (maxCommandTargets)
	// and fails a target with no verdict 60 s after dispatch, so the whole burst has 60 s. A
	// repair is three steps per session, which caps one burst at about 85 renames; at 400 ms each
	// that is a ~34 s tail, inside the deadline with room for the other 170 targets.
	//
	// The window is only paid in full when the rename FAILED. The loop reads before it sleeps and
	// polls every 25 ms, and the session processes a rename frame immediately rather than behind
	// its queued messages, so a rename that works is normally confirmed in a poll or two.
	inboxVerifyWindow = 400 * time.Millisecond
	inboxVerifyPoll   = 25 * time.Millisecond
	// maxSessionFileBytes bounds a <pid>.json read.
	maxSessionFileBytes = 1 << 16
	// maxKeyFileBytes mirrors the 4096-byte bound Claude Code itself puts on a key file.
	maxKeyFileBytes = 4096
)

// errNotAnInboxPath means the socket path in a session file is not a shape this agent will dial.
var errNotAnInboxPath = errors.New("not a session inbox path")

// peerTokenRe is the published token's shape, as Claude Code validates it: 32 lowercase hex.
var peerTokenRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// keyFileRe mirrors Claude Code's own key-file name pattern, `<pid>.<64hex>.key`.
var keyFileRe = regexp.MustCompile(`^(\d+)\.[0-9a-f]{64}\.key$`)

// looseString decodes a JSON string or number into a string. The key file's procStartFt was
// observed as a string, but a FILETIME is just as plausible a JSON number, and a type mismatch
// must not make the whole file unreadable.
type looseString string

func (s *looseString) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*s = ""
		return nil
	}
	if b[0] == '"' {
		var v string
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		*s = looseString(v)
		return nil
	}
	*s = looseString(b)
	return nil
}

// sessionFile is the part of ~/.claude/sessions/<pid>.json the inbox needs. internal/sessions owns
// the same file for the host report; this decodes the extra fields only the inbox cares about.
type sessionFile struct {
	PID                 int         `json:"pid"`
	SessionID           string      `json:"sessionId"`
	Name                string      `json:"name"`
	NameSource          string      `json:"nameSource"`
	ProcStart           looseString `json:"procStart"`
	PidDomain           string      `json:"pidDomain"`
	BridgeSessionID     string      `json:"bridgeSessionId"`
	MessagingSocketPath string      `json:"messagingSocketPath"`
}

// inboxKey is the published auth key beside a session's socket.
//
// PeerToken IS A SECRET. It authenticates anything on this machine to that session's inbox. It is
// never logged, never put in a hint, never wrapped into an error and never returned to the hub.
type inboxKey struct {
	PeerToken   string      `json:"peerToken"`
	ProcStart   looseString `json:"procStart"`
	ProcStartFt looseString `json:"procStartFt"`
	PidDomain   string      `json:"pidDomain"`
}

// readJSONFile reads at most max bytes of path into v.
func readJSONFile(path string, max int64, v any) error {
	// #nosec G304 -- callers build the path from the sessions dir plus a name matched against a
	// regexp (a decimal pid, or <pid>.<64hex>.key); no caller text reaches it.
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, max))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// readSessionFile loads one session's <pid>.json out of dir.
func readSessionFile(dir string, pid int) (sessionFile, error) {
	if pid <= 0 {
		return sessionFile{}, errors.New("agent: session pid is not a pid")
	}
	var sf sessionFile
	if err := readJSONFile(filepath.Join(dir, strconv.Itoa(pid)+".json"), maxSessionFileBytes, &sf); err != nil {
		return sessionFile{}, fmt.Errorf("agent: read session file: %w", err)
	}
	return sf, nil
}

// readInboxKey loads the <pid>.<64hex>.key beside a session's socket and checks the token's shape.
//
// Exactly one key file may name the pid. Two would mean one of them is an orphan from a killed
// session whose pid has been reused, and there is no way to tell which, so the honest answer is to
// refuse rather than pick.
func readInboxKey(dir string, pid int) (inboxKey, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return inboxKey{}, fmt.Errorf("agent: read sessions dir: %w", err)
	}
	want := strconv.Itoa(pid)
	var found string
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		m := keyFileRe.FindStringSubmatch(e.Name())
		if m == nil || m[1] != want {
			continue
		}
		if found != "" {
			return inboxKey{}, errors.New("agent: more than one inbox key names this pid")
		}
		found = e.Name()
	}
	if found == "" {
		return inboxKey{}, errors.New("agent: no inbox key for this session")
	}
	var k inboxKey
	if err := readJSONFile(filepath.Join(dir, found), maxKeyFileBytes, &k); err != nil {
		// The error could quote the file's contents, which is the token. Replace it.
		return inboxKey{}, errors.New("agent: inbox key is unreadable")
	}
	if !peerTokenRe.MatchString(k.PeerToken) {
		return inboxKey{}, errors.New("agent: inbox key carries no usable peer token")
	}
	return k, nil
}

// liveOwner reports whether the key really belongs to the live process behind this session file.
//
// A key file on disk proves NOTHING on its own. A cleanly exited session unlinks its socket and
// its key; a session killed with `taskkill /F` leaves the key behind for a pid that no longer
// exists, and pids get reused. Claude Code models this itself - its own lookup takes
// requireLiveOwner and answers "dead-owner" when the owning pid is gone or its start time no
// longer matches - and this is the same check:
//
//   - the pid must be a live Claude Code session process whose recorded start time matches
//     (sessions.Alive, the same gate the host report already uses);
//   - the key's procStartFt must ALSO match that live pid, when the key carries one. This is the
//     check that rules out an orphan key whose pid has been handed to a new session;
//   - the key's pidDomain must agree with the session file's, when both carry one: the two files
//     are written by the same process, so a disagreement means one of them is somebody else's.
//
// What is NOT checked: this host's own pid domain is not reconstructed, because its format
// ("win32:<hostname>") would be a guess. The two files agreeing, plus the live-pid start-time
// match, is what the dial is allowed to rest on.
func liveOwner(sf sessionFile, k inboxKey, alive func(pid int, procStart string) bool) bool {
	if sf.PID <= 0 || !alive(sf.PID, string(sf.ProcStart)) {
		return false
	}
	if ft := strings.TrimSpace(string(k.ProcStartFt)); ft != "" && !alive(sf.PID, ft) {
		return false
	}
	if ps := strings.TrimSpace(string(k.ProcStart)); ps != "" && !alive(sf.PID, ps) {
		return false
	}
	if k.PidDomain != "" && sf.PidDomain != "" && k.PidDomain != sf.PidDomain {
		return false
	}
	return true
}

// inboxFrames builds the two NDJSON lines, auth first. The token never leaves this buffer.
func inboxFrames(token, sessionID, name string) ([]byte, error) {
	auth, err := json.Marshal(map[string]string{"type": "auth", "token": token})
	if err != nil {
		return nil, errors.New("agent: encode auth frame")
	}
	ctl, err := json.Marshal(map[string]string{
		"type": "control", "session_id": sessionID, "action": "rename", "name": name})
	if err != nil {
		return nil, fmt.Errorf("agent: encode control frame: %w", err)
	}
	var b bytes.Buffer
	b.Grow(len(auth) + len(ctl) + 2)
	b.Write(auth)
	b.WriteByte('\n')
	b.Write(ctl)
	b.WriteByte('\n')
	return b.Bytes(), nil
}

// nameMatches reports whether the session's own name is the one that was asked for.
//
// Check `name` and ONLY `name`. nameSource is not a discriminator: a rename arriving over the
// inbox has source "peer", but Claude Code records it in the session file as "user" (or
// "collision" when the name had to be uniquified) and never as "peer". Code that waited for
// nameSource "peer" would read every success as a failure.
//
// A collision takes a uniquifying suffix, so a name that starts with the one asked for counts.
func nameMatches(got, want string) bool {
	got, want = proto.CleanRemoteName(got), proto.CleanRemoteName(want)
	if want == "" {
		return false
	}
	return got == want || (len(got) > len(want) && strings.HasPrefix(got, want))
}

// inboxMechanism sends one frame into a running session's own inbox.
type inboxMechanism struct {
	// dir resolves the sessions directory. It is the SAME directory the host report scans, so the
	// agent can never report a session from one place and dial a pipe named in another.
	dir func() (string, error)
	// dial opens the socket; the platform build decides how.
	dial func(path string) (io.WriteCloser, error)
	// alive is the live-pid gate, injected so tests never need a real process.
	alive func(pid int, procStart string) bool
	// sleep paces the read-back, injected so tests do not wait.
	sleep func(time.Duration)
}

func newInboxMechanism() inboxMechanism {
	return inboxMechanism{dir: sessions.Dir, dial: dialInbox, alive: sessions.Alive, sleep: time.Sleep}
}

func (inboxMechanism) Name() string { return "inbox" }

func (m inboxMechanism) Execute(task CommandTask) CommandResult {
	switch task.Command {
	case proto.CmdRenameRemote:
		return m.rename(task)
	case proto.CmdRemoteControlEnable:
		// Not "unproven": proven absent. The handler the feature would need is dead code and the
		// action is logged as unhandled by the session itself.
		return unsupported("inbox", proto.CodeNoMechanism,
			"the session inbox has no action that enables Remote Control; nothing was sent")
	default:
		return unsupported("inbox", proto.CodeNoMechanism, "")
	}
}

// rename pushes a name into a running session. Steps 0 to 2 of the recommended order in
// docs/runbooks/session-control.md; every decline leaves the relaunch fallback to answer.
func (m inboxMechanism) rename(task CommandTask) CommandResult {
	name := proto.CleanRemoteName(task.Name)
	if name == "" {
		return unsupported("inbox", proto.CodeNoName, "")
	}
	if !sessionIDRe.MatchString(task.SessionID) {
		return unsupported("inbox", proto.CodeBadSessionID, "")
	}
	dir, err := m.dir()
	if err != nil {
		return unsupported("inbox", proto.CodeNoInbox, "this host has no readable sessions directory")
	}
	sf, err := readSessionFile(dir, task.PID)
	if err != nil {
		return unsupported("inbox", proto.CodeNoInbox, "this session publishes no session file to read")
	}
	// The frame must carry the session's OWN id, and the id the hub asked about must be that one.
	// Sending any other id would be relying on the server's mismatch drop instead of on knowing
	// which session is being renamed.
	if sf.SessionID != task.SessionID {
		return unsupported("inbox", proto.CodeNoInbox,
			"this session's own file names a different session; nothing was sent")
	}
	key, err := readInboxKey(dir, task.PID)
	if err != nil {
		return unsupported("inbox", proto.CodeNoInbox, "this session publishes no usable inbox key")
	}
	if !liveOwner(sf, key, m.alive) {
		// An orphan key from a killed session, or a pid now owned by something else. Dialling on
		// the strength of the file alone would be dialling a pipe whose name has been reused.
		return unsupported("inbox", proto.CodeNoInbox,
			"this session's inbox key does not belong to a live process; nothing was sent")
	}
	if strings.TrimSpace(sf.BridgeSessionID) == "" {
		// With no bridge bound there is nothing to push a remote title to: Claude Code's own push
		// returns early without a bridgeSessionId. A relaunch is the honest answer, and it is the
		// next mechanism in the registry.
		return unsupported("inbox", proto.CodeNoBridge,
			"no Remote Control bridge is bound to this session, so no remote title can be set on it")
	}
	if nameMatches(sf.Name, name) {
		// Already carries it. Claude Code's own rename handler is a no-op for a name it already
		// has, so connecting would achieve nothing; not connecting is the smaller act.
		return CommandResult{Status: proto.StatusDelivered, Mechanism: "inbox",
			Hint: "this session already carries that name; nothing was sent"}
	}
	frames, err := inboxFrames(key.PeerToken, sf.SessionID, name)
	if err != nil {
		return failed("inbox", proto.CodeInboxSendFailed, "")
	}
	if err := m.send(sf.MessagingSocketPath, frames); err != nil {
		if errors.Is(err, errNotAnInboxPath) {
			return unsupported("inbox", proto.CodeNoInbox,
				"this session publishes no inbox socket this agent will dial")
		}
		return failed("inbox", proto.CodeInboxSendFailed,
			"the session's inbox would not take the frame; nothing reached the session")
	}
	if !m.changed(dir, task.PID, name) {
		// The frame went out and the session's own name did not follow it, so nothing can be
		// claimed. Declining hands the operator the relaunch, which is the thing that does work.
		return unsupported("inbox", proto.CodeInboxNoChange,
			"the frame was sent and this session's own name did not change; nothing can be claimed")
	}
	return CommandResult{Status: proto.StatusDelivered, Mechanism: "inbox",
		Hint: "sent into the session, which took the name locally. Whether the title on claude.ai " +
			"followed is not observable from this host, so this is 'delivered' and never 'done'."}
}

// send dials, writes both frames in one write, and closes BEFORE reporting.
//
// The connection is closed before the result is reported, not in a defer that would run after it:
// the caller reads the session's own file next, and the session should have seen the end of the
// connection by then. A close error after a successful write is not failure - the write goes
// straight to the pipe, with nothing buffered to lose.
//
// The whole thing runs on its own goroutine so a wedged endpoint cannot hold the hub's reply. The
// goroutine owns the connection and closes it itself, so a timeout here leaves nothing open; it
// does leave the goroutine to finish on its own, which is bounded by the endpoint.
//
// The buffer holds the auth token, so no error leaving this function may quote it.
func (m inboxMechanism) send(path string, frames []byte) error {
	done := make(chan error, 1)
	go func() {
		c, err := m.dial(path)
		if err != nil {
			done <- err
			return
		}
		_, werr := c.Write(frames)
		_ = c.Close()
		if werr != nil {
			done <- errors.New("agent: write session inbox frame")
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(inboxSendTimeout):
		return errors.New("agent: session inbox did not take the frame in time")
	}
}

// changed polls the session's own file for the new name, briefly. It reads `name` and nothing else.
func (m inboxMechanism) changed(dir string, pid int, name string) bool {
	for waited := time.Duration(0); ; waited += inboxVerifyPoll {
		if sf, err := readSessionFile(dir, pid); err == nil && nameMatches(sf.Name, name) {
			return true
		}
		if waited >= inboxVerifyWindow {
			return false
		}
		m.sleep(inboxVerifyPoll)
	}
}
