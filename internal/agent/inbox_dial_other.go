//go:build !windows

package agent

import (
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"time"
)

// inboxDialTimeout bounds the connect. inboxSendTimeout bounds the whole send around it; this is
// the inner bound, so a socket nobody is accepting on fails before that outer one fires.
const inboxDialTimeout = 2 * time.Second

// dialInbox connects to one session's inbox socket.
//
// Off Windows the inbox is a unix socket whose path the session publishes in its own session file.
// Claude Code's own injection recipe says a Windows pipe "is not reachable via socat/AF_UNIX", so
// the two transports are genuinely different and only the frames are shared.
//
// The path is NOT verified on Linux: the spike ran on Windows and never saw a Linux session
// publish one, so the only checks made here are the ones that hold for any unix socket - an
// absolute path, and a base name of the shape Claude Code uses. Re-check the shape the first time
// a Linux session is observed.
func dialInbox(path string) (io.WriteCloser, error) {
	if !filepath.IsAbs(path) || strings.ContainsRune(path, 0) ||
		!strings.HasPrefix(filepath.Base(path), "cc-msg-") {
		return nil, fmt.Errorf("agent: %w", errNotAnInboxPath)
	}
	c, err := net.DialTimeout("unix", path, inboxDialTimeout)
	if err != nil {
		return nil, fmt.Errorf("agent: open session inbox: %w", err)
	}
	return c, nil
}
