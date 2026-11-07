//go:build windows

package agent

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// lookClaude resolves the claude executable on PATH.
func lookClaude(name string) (string, error) { return exec.LookPath(name) }

// killProcess terminates a session process. The caller has just proved, through sessions.Alive,
// that the pid is the live session with the recorded start time.
func killProcess(pid int) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid)) // #nosec G115 -- pid is checked positive by the caller
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	return windows.TerminateProcess(h, 1)
}

// startDetached starts the new claude in its own console and process group so it outlives this
// agent. Arguments are an exec vector; there is no shell. An interactive claude needs a terminal,
// so it gets a new console window.
func startDetached(spec relaunchSpec) error {
	// #nosec G204 -- Exe comes from exec.LookPath("claude"); Args are constants plus a session id
	// matched against sessionIDRe; there is no shell.
	cmd := exec.Command(spec.Exe, spec.Args...)
	cmd.Dir = spec.Dir
	cmd.Env = spec.Env
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_CONSOLE | windows.CREATE_NEW_PROCESS_GROUP,
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }() // reap it; the result is not ours to read
	return nil
}
