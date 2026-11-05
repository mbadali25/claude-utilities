package agent

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"claude-utilities/internal/proto"
)

// A FAKE inbox server, never a real session. It reimplements the three dispatcher rules this
// agent's frames have to satisfy, so the frames are checked against a real socket and a real
// reader rather than only against a buffer:
//
//  1. the FIRST line must be {"type":"auth","token":<the published peerToken>}; anything else on
//     an unauthenticated connection is dropped and the connection closed;
//  2. a control frame whose session_id is not this session's own is dropped (the interlock);
//  3. an accepted rename calls the session's rename handler.
//
// Unix sockets are used because the standard library can LISTEN on one on every platform this
// program builds for, Windows included. The production Windows transport is a named pipe, which
// the standard library can dial but not serve; see dialInbox for how that one was proven.
type fakeInbox struct {
	mu        sync.Mutex
	token     string
	sessionID string
	// renamed is every name the dispatcher accepted, in order.
	renamed []string
	// dropped is every reason a frame was refused, in order.
	dropped []string
	ln      net.Listener
}

func newFakeInbox(t *testing.T, token, sessionID string) *fakeInbox {
	t.Helper()
	// os.MkdirTemp, not t.TempDir: a unix socket path is length-bounded and a test name is long.
	dir, err := os.MkdirTemp("", "ccmsg")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", filepath.Join(dir, "cc-msg-0123456789abcdef0123456789abcdef"))
	if err != nil {
		_ = os.RemoveAll(dir)
		t.Skipf("no unix socket support here: %v", err)
	}
	s := &fakeInbox{token: token, sessionID: sessionID, ln: ln}
	t.Cleanup(func() { _ = ln.Close(); _ = os.RemoveAll(dir) })
	go s.serve()
	return s
}

func (s *fakeInbox) path() string { return s.ln.Addr().String() }

func (s *fakeInbox) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *fakeInbox) note(field *[]string, v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	*field = append(*field, v)
}

func (s *fakeInbox) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	sc := bufio.NewScanner(c)
	authed := false
	for sc.Scan() {
		var f struct {
			Type      string `json:"type"`
			Token     string `json:"token"`
			SessionID string `json:"session_id"`
			Action    string `json:"action"`
			Name      string `json:"name"`
		}
		if err := json.Unmarshal(sc.Bytes(), &f); err != nil {
			s.note(&s.dropped, "unparseable line")
			return
		}
		if !authed {
			if f.Type != "auth" {
				s.note(&s.dropped, "did not authenticate: "+f.Type)
				return
			}
			if f.Token != s.token {
				s.note(&s.dropped, "bad auth frame")
				return
			}
			authed = true
			continue
		}
		if f.Type != "control" {
			s.note(&s.dropped, "unhandled message type: "+f.Type)
			continue
		}
		if f.SessionID != s.sessionID {
			s.note(&s.dropped, "session_id mismatch")
			continue
		}
		if f.Action != "rename" {
			s.note(&s.dropped, "unhandled control action: "+f.Action)
			continue
		}
		s.note(&s.renamed, f.Name)
	}
}

func (s *fakeInbox) saw() ([]string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.renamed...), append([]string(nil), s.dropped...)
}

// wait gives the server a moment to finish reading the connection the agent has already closed.
func (s *fakeInbox) wait(want int) {
	for i := 0; i < 200; i++ {
		if r, d := s.saw(); len(r)+len(d) >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// End to end over a real socket: the frames this agent writes are accepted by a dispatcher that
// enforces auth-first and the session_id interlock, and the rename arrives exactly once.
func TestInboxRenameIsAcceptedByARealSocketServer(t *testing.T) {
	f := newInboxFixture(t, nil)
	srv := newFakeInbox(t, testPeerToken, testSession)
	f.m.dial = func(path string) (io.WriteCloser, error) {
		if path != srv.path() {
			t.Errorf("dialled %q, want %q", path, srv.path())
		}
		// The fake session takes the name, the way a real one writes its session file.
		cur := f.readSession(t)
		cur.Name, cur.NameSource = "over-the-wire", "user"
		f.writeSession(t, cur)
		return net.Dial("unix", path)
	}
	f.writeSession(t, func() sessionFile {
		sf := f.readSession(t)
		sf.MessagingSocketPath = srv.path()
		return sf
	}())

	res := f.m.Execute(f.task("over-the-wire"))
	if res.Status != proto.StatusDelivered || res.Mechanism != "inbox" {
		t.Fatalf("res = %+v", res)
	}
	srv.wait(1)
	renamed, dropped := srv.saw()
	if len(renamed) != 1 || renamed[0] != "over-the-wire" {
		t.Fatalf("renamed = %v, want exactly one accepted rename", renamed)
	}
	if len(dropped) != 0 {
		t.Fatalf("the server refused a frame: %v", dropped)
	}
}

// The same server, told to expect a different session: the frame is dropped on the mismatch and
// nothing is renamed. This is the interlock the whole feature leans on, exercised rather than
// asserted from a comment.
func TestInboxFrameIsDroppedOnASessionIDMismatch(t *testing.T) {
	f := newInboxFixture(t, nil)
	srv := newFakeInbox(t, testPeerToken, testSession2) // the server is a DIFFERENT session
	f.writeSession(t, func() sessionFile {
		sf := f.readSession(t)
		sf.MessagingSocketPath = srv.path()
		return sf
	}())
	f.m.dial = func(path string) (io.WriteCloser, error) { return net.Dial("unix", path) }

	res := f.m.Execute(f.task("wrong-session"))
	// The write succeeds, the session drops the frame, and the name never changes - so the agent
	// declines rather than claiming anything.
	if res.Status != proto.StatusUnsupported || res.Code != proto.CodeInboxNoChange {
		t.Fatalf("res = %+v", res)
	}
	srv.wait(1)
	renamed, dropped := srv.saw()
	if len(renamed) != 0 {
		t.Fatalf("a mismatched frame renamed something: %v", renamed)
	}
	if len(dropped) != 1 || dropped[0] != "session_id mismatch" {
		t.Fatalf("dropped = %v, want one session_id mismatch", dropped)
	}
}

// A wrong token closes the connection without the control frame ever being dispatched.
func TestInboxFrameIsRefusedByAServerThatChecksTheToken(t *testing.T) {
	f := newInboxFixture(t, nil)
	srv := newFakeInbox(t, "ffffffffffffffffffffffffffffffff", testSession)
	f.writeSession(t, func() sessionFile {
		sf := f.readSession(t)
		sf.MessagingSocketPath = srv.path()
		return sf
	}())
	f.m.dial = func(path string) (io.WriteCloser, error) { return net.Dial("unix", path) }

	if res := f.m.Execute(f.task("nope")); res.Status != proto.StatusUnsupported {
		t.Fatalf("res = %+v", res)
	}
	srv.wait(1)
	renamed, dropped := srv.saw()
	if len(renamed) != 0 || len(dropped) != 1 || dropped[0] != "bad auth frame" {
		t.Fatalf("renamed = %v dropped = %v", renamed, dropped)
	}
}
