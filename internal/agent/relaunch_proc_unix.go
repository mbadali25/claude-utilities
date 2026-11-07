//go:build !windows

package agent

import (
	"os"
	"os/exec"
	"syscall"
)

// lookClaude resolves the claude executable on PATH.
func lookClaude(name string) (string, error) { return exec.LookPath(name) }

// killProcess asks a session process to exit. The caller has just proved, through sessions.Alive,
// that the pid is the live session with the recorded start time.
func killProcess(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Signal(syscall.SIGTERM)
}

// startDetached starts the new claude in its own session (setsid) so it outlives this agent and
// is not tied to its process group. Arguments are an exec vector; there is no shell. stdio is
// /dev/null: an interactive claude needs a terminal, which is the cost the operator confirmed.
func startDetached(spec relaunchSpec) error {
	// #nosec G204 -- Exe comes from exec.LookPath("claude"); Args are constants plus a session id
	// matched against sessionIDRe; there is no shell.
	cmd := exec.Command(spec.Exe, spec.Args...)
	cmd.Dir = spec.Dir
	cmd.Env = spec.Env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }() // reap it; the result is not ours to read
	return nil
}
