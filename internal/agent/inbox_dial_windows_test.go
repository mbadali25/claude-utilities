//go:build windows

package agent

import (
	"errors"
	"path/filepath"
	"testing"
)

// The socket path comes out of a file on disk, so the dial refuses anything that is not the exact
// pipe shape Claude Code publishes. Nothing here opens a real pipe: every case must be rejected
// before the filesystem is touched, which is the point.
func TestWindowsDialRefusesAnythingThatIsNotASessionPipe(t *testing.T) {
	bad := []string{
		"",
		`C:\Windows\System32\config\SAM`,
		`\\.\pipe\LOCAL\cc-msg-notlongenough`,
		`\\.\pipe\LOCAL\cc-msg-D8D3F9DD3B1BC77EC3B4E2B656AFA3B9`,  // uppercase: not the shape
		`\\.\pipe\cc-msg-d8d3f9dd3b1bc77ec3b4e2b656afa3b9`,        // missing the LOCAL\ segment
		`\\.\pipe\LOCAL\cc-msg-d8d3f9dd3b1bc77ec3b4e2b656afa3b9 `, // trailing space
		`\\.\pipe\LOCAL\cc-msg-d8d3f9dd3b1bc77ec3b4e2b656afa3b9\..\other`,
		`\\evil-host\pipe\LOCAL\cc-msg-d8d3f9dd3b1bc77ec3b4e2b656afa3b9`, // another machine
		filepath.Join(t.TempDir(), "plain.txt"),
	}
	for _, p := range bad {
		c, err := dialInbox(p)
		if err == nil {
			_ = c.Close()
			t.Fatalf("dialInbox(%q) opened something", p)
		}
		if !errors.Is(err, errNotAnInboxPath) {
			t.Fatalf("dialInbox(%q) err = %v, want errNotAnInboxPath (refused before any open)", p, err)
		}
	}
	// The real shape gets as far as the open, which fails because no such pipe exists here. The
	// distinguishing part is that it is NOT errNotAnInboxPath.
	good := `\\.\pipe\LOCAL\cc-msg-00112233445566778899aabbccddeeff`
	if _, err := dialInbox(good); err == nil || errors.Is(err, errNotAnInboxPath) {
		t.Fatalf("dialInbox(%q) err = %v, want an open failure and not a shape refusal", good, err)
	}
}
