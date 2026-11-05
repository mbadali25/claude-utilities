//go:build windows

package tunnel

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// nullDevice is what -F and GlobalKnownHostsFile point at so no ssh_config on this machine can
// contribute a forward or a ProxyCommand. On Windows that is NUL, not /dev/null.
const nullDevice = "NUL"

// sshImageName is the executable a reaped pid must be running before it is terminated.
const sshImageName = "ssh.exe"

// hardenedEnv is the child's environment: a short allowlist, nothing else inherited.
//
// It is not empty, and that is not laziness. Windows resolves winsock and the DNS resolver DLLs
// relative to SystemRoot, so a child started with a truly empty environment block cannot resolve
// a name or, often, open a socket at all - and the failure looks like an unreachable host, not a
// misconfiguration. Nothing secret is on this list.
func hardenedEnv() []string {
	out := make([]string, 0, 3)
	for _, k := range []string{"SystemRoot", "windir", "SystemDrive"} {
		if v := os.Getenv(k); v != "" {
			out = append(out, k+"="+v)
		}
	}
	return out
}

// killIfSSH terminates pid only if it is really an ssh process, and reports whether it did. A
// journal entry outlives the process it names, and Windows reuses pids, so killing a recorded pid
// blind could kill something unrelated. The image name is checked first, with the handle opened
// for query and terminate in one go so the check and the kill cannot race onto a different
// process.
func killIfSSH(pid int) (bool, error) {
	if pid <= 0 {
		return false, nil
	}
	h, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE, false, uint32(pid)) // #nosec G115 -- pid comes from our own journal and is checked positive
	if err != nil {
		return false, nil // already gone, or not ours to touch: nothing to reap either way
	}
	defer func() { _ = windows.CloseHandle(h) }()
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf)) // #nosec G115 -- MAX_LONG_PATH is a small constant, not input
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return false, nil
	}
	image := windows.UTF16ToString(buf[:size])
	if !strings.EqualFold(filepath.Base(image), sshImageName) {
		return false, fmt.Errorf("tunnel: pid is not %s", sshImageName)
	}
	if err := windows.TerminateProcess(h, 1); err != nil {
		return false, err
	}
	return true, nil
}
