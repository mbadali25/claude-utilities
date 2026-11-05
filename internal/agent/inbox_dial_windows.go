//go:build windows

package agent

import (
	"fmt"
	"io"
	"os"
	"regexp"
)

// windowsInboxPathRe is the only socket path this agent will dial on Windows: the exact shape
// Claude Code 2.1.318 publishes, `\\.\pipe\LOCAL\cc-msg-<32 lowercase hex>`. The path arrives out
// of a file on disk, so it is matched whole rather than merely prefix-checked: a value of any other
// shape is refused instead of handed to the filesystem.
var windowsInboxPathRe = regexp.MustCompile(`^\\\\\.\\pipe\\LOCAL\\cc-msg-[0-9a-f]{32}$`)

// dialInbox opens one session's inbox pipe for writing.
//
// A Windows named pipe is NOT reachable through net.Dial, and this program takes no dependency to
// reach one. It does not need to: a pipe client is opened with CreateFile exactly as a file is, and
// os.OpenFile is CreateFile. The pipe server (Node's net.createServer) creates it duplex, so
// O_RDWR opens, and the frames this agent writes are small enough to leave in one Write.
//
// Verified by hand on 2026-11-05 against a real named-pipe server on this build of Go
// (go1.27.3 windows/amd64): open, two NDJSON lines in one write, close, and the server read both
// lines intact. There is no unit test for this function, because creating a named pipe SERVER is
// what the standard library lacks; the framing and ordering are tested through an injected dialer
// and over a real socket instead. See docs/runbooks/session-control.md.
func dialInbox(path string) (io.WriteCloser, error) {
	if !windowsInboxPathRe.MatchString(path) {
		return nil, fmt.Errorf("agent: %w", errNotAnInboxPath)
	}
	// #nosec G304 -- the path is matched whole against windowsInboxPathRe above, so it can only
	// ever be a \\.\pipe\LOCAL\cc-msg-<32hex> pipe name and never a path into the filesystem.
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		// The error text carries the pipe name, which is not a secret but is not worth logging
		// either; callers turn this into a reason code and never log the text.
		return nil, fmt.Errorf("agent: open session inbox: %w", err)
	}
	return f, nil
}
