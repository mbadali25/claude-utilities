package agent

import (
	"os"
	"os/user"
	"strings"
)

// maxRunAsLen caps the reported username. A login name is far shorter than this on every
// platform; the cap exists so a hostile environment cannot push an arbitrary string into the
// hello, and the hub clips again on arrival.
const maxRunAsLen = 64

// runAsUser reports the local account this agent process runs as: a username and nothing
// else. No home directory, no uid, no domain — the installer resolves the home itself and
// the UI only needs the name to answer "who does this agent swap for".
//
// os/user.Current works with CGO disabled (it parses /etc/passwd on Unix), but it can still
// fail in a container with no passwd entry, so the environment is the fallback. An empty
// result is fine: RunAs is omitempty and the UI simply says nothing.
func runAsUser() string {
	name := ""
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	if name == "" {
		name = os.Getenv("USER")
	}
	if name == "" {
		name = os.Getenv("LOGNAME")
	}
	if name == "" {
		name = os.Getenv("USERNAME")
	}
	// Windows reports DOMAIN\name; keep the bare login name.
	if i := strings.LastIndexAny(name, `\/`); i >= 0 {
		name = name[i+1:]
	}
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(name))
	if rs := []rune(name); len(rs) > maxRunAsLen {
		name = string(rs[:maxRunAsLen])
	}
	return name
}
