package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"claude-utilities/internal/proto"
)

// NOTHING in this file reaches a real session, a real pipe or a real process. The socket is a fake
// writer, the liveness check is injected, and every file is written under t.TempDir().

const (
	testPeerToken = "0123456789abcdef0123456789abcdef"
	testKeyHash   = "aa11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff00112233"
	testProcStart = "133700000000000000"
	testPidDomain = "win32:test-host"
)

// fakeSocket records what was written and whether it was closed.
type fakeSocket struct {
	bytes.Buffer
	closed   bool
	writeErr error
}

func (f *fakeSocket) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return f.Buffer.Write(p)
}

func (f *fakeSocket) Close() error { f.closed = true; return nil }

// inboxFixture is one fake session on disk plus the mechanism aimed at it.
type inboxFixture struct {
	dir  string
	pid  int
	sock *fakeSocket
	m    inboxMechanism
	// dialled is the path the mechanism asked for.
	dialled string
	// dialErr, when set, is what the dial returns instead of sock.
	dialErr error
	// renameOnSend makes the fake session write the name into its session file, as a real session
	// that honoured the frame would.
	renameOnSend string
}

const testSocketPath = `\\.\pipe\LOCAL\cc-msg-d8d3f9dd3b1bc77ec3b4e2b656afa3b9`

func newInboxFixture(t *testing.T, mutate func(sf *sessionFile)) *inboxFixture {
	t.Helper()
	f := &inboxFixture{dir: t.TempDir(), pid: 4242, sock: &fakeSocket{}}
	sf := sessionFile{PID: f.pid, SessionID: testSession, Name: "work-39", NameSource: "derived",
		ProcStart: testProcStart, PidDomain: testPidDomain, BridgeSessionID: "bridge-1",
		MessagingSocketPath: testSocketPath}
	if mutate != nil {
		mutate(&sf)
	}
	f.writeSession(t, sf)
	f.writeKey(t, inboxKey{PeerToken: testPeerToken, ProcStartFt: testProcStart, PidDomain: testPidDomain})
	f.m = inboxMechanism{
		dir:   func() (string, error) { return f.dir, nil },
		alive: func(pid int, procStart string) bool { return pid == f.pid && procStart == testProcStart },
		sleep: func(time.Duration) {},
		dial: func(path string) (io.WriteCloser, error) {
			f.dialled = path
			if f.dialErr != nil {
				return nil, f.dialErr
			}
			if f.renameOnSend != "" {
				cur := f.readSession(t)
				cur.Name = f.renameOnSend
				cur.NameSource = "user" // never "peer": that is the whole point of name-only checks
				f.writeSession(t, cur)
			}
			return f.sock, nil
		},
	}
	return f
}

func (f *inboxFixture) sessionPath() string {
	return filepath.Join(f.dir, strconv.Itoa(f.pid)+".json")
}

func (f *inboxFixture) writeSession(t *testing.T, sf sessionFile) {
	t.Helper()
	data, err := json.Marshal(sf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.sessionPath(), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *inboxFixture) readSession(t *testing.T) sessionFile {
	t.Helper()
	sf, err := readSessionFile(f.dir, f.pid)
	if err != nil {
		t.Fatal(err)
	}
	return sf
}

func (f *inboxFixture) writeKey(t *testing.T, k inboxKey) {
	t.Helper()
	data, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	// Claude Code publishes the real key at 0400; these fixtures stay writable so a case can
	// rewrite one, which a read-only file refuses on Windows.
	name := strconv.Itoa(f.pid) + "." + testKeyHash + ".key"
	if err := os.WriteFile(filepath.Join(f.dir, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *inboxFixture) task(name string) CommandTask {
	return CommandTask{CommandID: "c1", Command: proto.CmdRenameRemote,
		SessionID: testSession, PID: f.pid, Name: name}
}

// lines splits what the fake socket received into NDJSON lines, insisting every one is terminated.
func (f *inboxFixture) lines(t *testing.T) []map[string]any {
	t.Helper()
	raw := f.sock.String()
	if raw == "" {
		return nil
	}
	if !strings.HasSuffix(raw, "\n") {
		t.Fatalf("the last frame was not newline-terminated: %q", raw)
	}
	out := []map[string]any{}
	for _, l := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("frame %q is not one JSON object per line: %v", l, err)
		}
		out = append(out, m)
	}
	return out
}

// The proven wire sequence: auth FIRST with this session's own peerToken, then one control rename
// carrying this session's OWN session_id. Both lines newline-terminated, nothing else sent.
func TestInboxRenameSendsTheAuthLineFirstThenTheRenameFrame(t *testing.T) {
	f := newInboxFixture(t, nil)
	f.renameOnSend = "spike2-after-fix"
	res := f.m.Execute(f.task("spike2-after-fix"))
	if res.Status != proto.StatusDelivered || res.Mechanism != "inbox" {
		t.Fatalf("res = %+v", res)
	}
	if f.dialled != testSocketPath {
		t.Fatalf("dialled %q, want the path from the session's own file", f.dialled)
	}
	if !f.sock.closed {
		t.Fatal("the connection was left open")
	}
	ls := f.lines(t)
	if len(ls) != 2 {
		t.Fatalf("sent %d frames, want exactly 2: %v", len(ls), ls)
	}
	if ls[0]["type"] != "auth" || ls[0]["token"] != testPeerToken {
		t.Fatalf("first frame = %v, want the auth frame with this session's peerToken", ls[0])
	}
	if ls[1]["type"] != "control" || ls[1]["action"] != "rename" || ls[1]["name"] != "spike2-after-fix" {
		t.Fatalf("second frame = %v", ls[1])
	}
	// The interlock: a frame whose session_id is not the session's own is dropped by the session,
	// so the id is ALWAYS set and is always the session's own.
	if ls[1]["session_id"] != testSession {
		t.Fatalf("session_id = %v, want %q (always set, always the session's own)", ls[1]["session_id"], testSession)
	}
}

// The ceiling is "delivered". The bridge push inside Claude Code is fire-and-forget, so nothing on
// the host can see the remote title change and no code path may answer "done".
func TestInboxRenameNeverClaimsDone(t *testing.T) {
	f := newInboxFixture(t, nil)
	f.renameOnSend = "renamed"
	if res := f.m.Execute(f.task("renamed")); res.Status == proto.StatusDone {
		t.Fatalf("res = %+v: nothing may claim done for a rename", res)
	}
	if strings.Contains(strings.ToLower(f.m.Execute(f.task("renamed")).Hint), "verified") {
		t.Fatal("the hint claims verification the host cannot do")
	}
}

// Verification reads `name` and only `name`. A peer rename is recorded as nameSource "user" or
// "collision" and NEVER "peer", so code that waited for "peer" would read success as failure.
func TestInboxRenameVerifiesTheNameAndNeverWaitsForPeerNameSource(t *testing.T) {
	for _, src := range []string{"user", "collision"} {
		f := newInboxFixture(t, nil)
		f.renameOnSend = "beta"
		f.m.dial = func(path string) (io.WriteCloser, error) {
			cur := f.readSession(t)
			cur.Name, cur.NameSource = "beta", src
			f.writeSession(t, cur)
			return f.sock, nil
		}
		if res := f.m.Execute(f.task("beta")); res.Status != proto.StatusDelivered {
			t.Fatalf("nameSource %q: res = %+v", src, res)
		}
	}
	// A collision suffix still counts: the session took the name and uniquified it.
	f := newInboxFixture(t, nil)
	f.renameOnSend = "beta-2"
	if res := f.m.Execute(f.task("beta")); res.Status != proto.StatusDelivered {
		t.Fatalf("collision suffix: res = %+v", res)
	}
}

// Nothing is claimed when the session's own name did not follow the frame: the decline hands the
// operator the relaunch fallback instead of a success nobody observed.
func TestInboxRenameDeclinesWhenTheNameDoesNotChange(t *testing.T) {
	f := newInboxFixture(t, nil)
	res := f.m.Execute(f.task("gamma"))
	if res.Status != proto.StatusUnsupported || res.Code != proto.CodeInboxNoChange {
		t.Fatalf("res = %+v", res)
	}
	if len(f.lines(t)) != 2 {
		t.Fatal("the frame should still have been sent before the read-back")
	}
}

// A key file proves nothing: a killed session leaves an orphan <pid>.<64hex>.key behind for a pid
// that may since have been handed to another process. The owner must be live, and the key's own
// procStartFt must match that live pid, BEFORE anything is dialled.
func TestInboxRenameRefusesADeadOwnerWithoutDialling(t *testing.T) {
	cases := []struct {
		name  string
		setup func(f *inboxFixture, t *testing.T)
	}{
		{"pid is gone", func(f *inboxFixture, t *testing.T) {
			f.m.alive = func(int, string) bool { return false }
		}},
		{"key procStartFt names another process start", func(f *inboxFixture, t *testing.T) {
			f.writeKey(t, inboxKey{PeerToken: testPeerToken, ProcStartFt: "133799999999999999",
				PidDomain: testPidDomain})
		}},
		{"key procStart names another process start", func(f *inboxFixture, t *testing.T) {
			f.writeKey(t, inboxKey{PeerToken: testPeerToken, ProcStart: "133799999999999999",
				PidDomain: testPidDomain})
		}},
		{"key belongs to another pid domain", func(f *inboxFixture, t *testing.T) {
			f.writeKey(t, inboxKey{PeerToken: testPeerToken, ProcStartFt: testProcStart,
				PidDomain: "win32:someone-else"})
		}},
		{"no key file at all", func(f *inboxFixture, t *testing.T) {
			name := strconv.Itoa(f.pid) + "." + testKeyHash + ".key"
			if err := os.Remove(filepath.Join(f.dir, name)); err != nil {
				t.Fatal(err)
			}
		}},
		{"key carries no usable token", func(f *inboxFixture, t *testing.T) {
			f.writeKey(t, inboxKey{PeerToken: "nope", ProcStartFt: testProcStart})
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newInboxFixture(t, nil)
			c.setup(f, t)
			res := f.m.Execute(f.task("delta"))
			if res.Status != proto.StatusUnsupported || res.Code != proto.CodeNoInbox {
				t.Fatalf("res = %+v, want unsupported/%s", res, proto.CodeNoInbox)
			}
			if f.dialled != "" {
				t.Fatalf("dialled %q: nothing may be connected to before the owner is proven live", f.dialled)
			}
		})
	}
}

// With no bridge bound there is nothing for a title to be pushed to, so the inbox declines and the
// relaunch fallback is what answers. This is the ONLY reason relaunch still handles a rename.
func TestInboxRenameDeclinesWithNoBridgeBoundSoRelaunchAnswers(t *testing.T) {
	f := newInboxFixture(t, func(sf *sessionFile) { sf.BridgeSessionID = "" })
	res := f.m.Execute(f.task("eps"))
	if res.Status != proto.StatusUnsupported || res.Code != proto.CodeNoBridge {
		t.Fatalf("res = %+v", res)
	}
	if f.dialled != "" {
		t.Fatal("a session with no bridge was still connected to")
	}
	// And through the registry the operator gets the relaunch command.
	ctl := newControlWith(t.TempDir(), fixedClock(), true, f.m)
	got := ctl.ex.run(f.task("eps"))
	if got.Mechanism != "relaunch" || got.Code != proto.CodeRequiresRestart {
		t.Fatalf("registry res = %+v, want the relaunch fallback", got)
	}
}

// The session file must name the session the hub asked about. Sending any other id would be
// leaning on the server's mismatch drop instead of knowing which session is being renamed.
func TestInboxRenameRefusesWhenTheSessionFileNamesAnotherSession(t *testing.T) {
	f := newInboxFixture(t, func(sf *sessionFile) { sf.SessionID = testSession2 })
	res := f.m.Execute(f.task("zeta"))
	if res.Status != proto.StatusUnsupported || res.Code != proto.CodeNoInbox || f.dialled != "" {
		t.Fatalf("res = %+v dialled = %q", res, f.dialled)
	}
}

// A name the session already carries is a no-op inside Claude Code, so the smaller act is not to
// connect at all.
func TestInboxRenameSendsNothingWhenTheNameAlreadyMatches(t *testing.T) {
	f := newInboxFixture(t, func(sf *sessionFile) { sf.Name = "already" })
	res := f.m.Execute(f.task("already"))
	if res.Status != proto.StatusDelivered || f.dialled != "" {
		t.Fatalf("res = %+v dialled = %q", res, f.dialled)
	}
}

func TestInboxRenameReportsASendFailure(t *testing.T) {
	f := newInboxFixture(t, nil)
	f.sock.writeErr = errors.New("pipe is gone")
	res := f.m.Execute(f.task("eta"))
	if res.Status != proto.StatusFailed || res.Code != proto.CodeInboxSendFailed {
		t.Fatalf("res = %+v", res)
	}
	// A path the platform will not dial is a different answer: there is no inbox here to fail at.
	f2 := newInboxFixture(t, nil)
	f2.dialErr = errNotAnInboxPath
	if res := f2.m.Execute(f2.task("eta")); res.Status != proto.StatusUnsupported || res.Code != proto.CodeNoInbox {
		t.Fatalf("bad path: res = %+v", res)
	}
}

// remote_control_enable is no-mechanism, not "unproven": the handler it would need is dead code in
// the session (its setter has one whole-binary occurrence, its own definition) and the session logs
// the action as unhandled. The hint must not promise a mechanism.
func TestInboxHasNoMechanismForRemoteControlEnable(t *testing.T) {
	f := newInboxFixture(t, nil)
	res := f.m.Execute(CommandTask{CommandID: "c1", Command: proto.CmdRemoteControlEnable,
		SessionID: testSession, PID: f.pid})
	if res.Status != proto.StatusUnsupported || res.Code != proto.CodeNoMechanism {
		t.Fatalf("res = %+v, want unsupported/%s", res, proto.CodeNoMechanism)
	}
	if f.dialled != "" {
		t.Fatal("a session was connected to for a command the inbox cannot carry")
	}
	for _, bad := range []string{"unproven", "telemetry", "would enable", "may enable"} {
		if strings.Contains(strings.ToLower(res.Hint), bad) {
			t.Fatalf("hint %q still implies a mechanism (%q)", res.Hint, bad)
		}
	}
}

// Nothing the inbox sends or reads may carry the peer token out of the frame buffer.
func TestInboxNeverLeaksThePeerToken(t *testing.T) {
	f := newInboxFixture(t, nil)
	f.sock.writeErr = errors.New("boom")
	res := f.m.Execute(f.task("theta"))
	for _, s := range []string{res.Hint, res.Code, res.Mechanism, res.Status} {
		if strings.Contains(s, testPeerToken) {
			t.Fatalf("a result field carries the peer token: %q", s)
		}
	}
	// A corrupt key file's error must not quote the file either.
	if err := os.WriteFile(filepath.Join(f.dir, strconv.Itoa(f.pid)+"."+testKeyHash+".key"),
		[]byte(`{"peerToken":"`+testPeerToken+`"`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readInboxKey(f.dir, f.pid); err == nil || strings.Contains(err.Error(), testPeerToken) {
		t.Fatalf("err = %v", err)
	}
}

// Two key files naming one pid means one is an orphan and there is no way to tell which.
func TestInboxRefusesTwoKeyFilesForOnePid(t *testing.T) {
	f := newInboxFixture(t, nil)
	other := strconv.Itoa(f.pid) + ".bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff001122334455.key"
	if err := os.WriteFile(filepath.Join(f.dir, other), []byte(`{"peerToken":"`+testPeerToken+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readInboxKey(f.dir, f.pid); err == nil {
		t.Fatal("two keys for one pid were accepted")
	}
}

func TestInboxKeyDecodesAStringOrNumberProcStart(t *testing.T) {
	for _, raw := range []string{
		`{"peerToken":"` + testPeerToken + `","procStartFt":"133700000000000000"}`,
		`{"peerToken":"` + testPeerToken + `","procStartFt":133700000000000000}`,
		`{"peerToken":"` + testPeerToken + `","procStartFt":null}`,
	} {
		var k inboxKey
		if err := json.Unmarshal([]byte(raw), &k); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
	}
}

func TestInboxFramesAreOneJSONObjectPerLine(t *testing.T) {
	b, err := inboxFrames(testPeerToken, testSession, "a name")
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(b, []byte("\n")); n != 2 {
		t.Fatalf("newlines = %d, want 2 (NDJSON, every line terminated)", n)
	}
	if !bytes.HasSuffix(b, []byte("\n")) {
		t.Fatal("the last frame is not terminated, so the session would wait for its deadline")
	}
}
