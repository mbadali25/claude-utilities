//go:build !windows

package tunnel

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// nullDevice is what -F and GlobalKnownHostsFile point at so no ssh_config on this machine can
// contribute a forward or a ProxyCommand.
const nullDevice = "/dev/null"

// sshImageName is the executable a reaped pid must be running before it is signalled.
const sshImageName = "ssh"

// hardenedEnv is the child's environment: nothing inherited. ssh needs no variable to do this
// job here, and this process holds the vault passphrase in its own environment.
func hardenedEnv() []string { return []string{} }

// killIfSSH signals pid only if it is really an ssh process, and reports whether it did. A
// journal entry outlives the process it names and pids are reused, so a recorded pid is never
// killed blind. /proc is the cheap check where it exists; without it the process is left alone
// rather than killed on a guess.
func killIfSSH(pid int) (bool, error) {
	if pid <= 0 {
		return false, nil
	}
	comm, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil // the process, or /proc itself, is not there
		}
		return false, err
	}
	if strings.TrimSpace(string(comm)) != sshImageName {
		return false, errors.New("tunnel: pid is not " + sshImageName)
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false, nil
	}
	if err := p.Signal(syscall.SIGTERM); err != nil {
		return false, p.Kill()
	}
	return true, nil
}
