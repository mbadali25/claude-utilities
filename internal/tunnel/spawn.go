package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"claude-utilities/internal/credfile"
)

// Runner starts one tunnel child. It is the single platform seam: a Linux-hosted server swaps the
// exec runner's null device and key-file mode and nothing above this interface changes. Tests
// supply a fake, or the fake ssh binary in testdata, so no test needs a network or a real host.
type Runner interface {
	Start(ctx context.Context, s Spec, keyPath, knownHosts string) (Proc, error)
}

// Proc is a running tunnel child.
type Proc interface {
	Pid() int
	// Wait blocks until the child exits and returns its exit code. A signalled or killed child
	// reports a negative code.
	Wait() int
	Kill() error
	// Stderr returns everything the child wrote to stderr. It is passed to Classify and then
	// dropped: it carries the host address and the username, so it is never stored or logged.
	Stderr() string
}

// SSHName is the ssh client this package starts. Windows ships it as ssh.exe on PATH with the
// OpenSSH client feature; exec.LookPath adds the .exe itself.
const SSHName = "ssh"

// Args builds the whole argv for one tunnel, after the program name.
//
// The hardening here is load-bearing and every line of it is deliberate:
//
//   - -F <null> ignores the user's ssh_config AND the system one, so no DynamicForward,
//     LocalForward, ProxyCommand or ControlMaster can leak in from a file this process never
//     chose. Matthew has other network traffic on this machine; a config-sourced forward would
//     be invisible here.
//   - the one -R below is the ONLY forward this process may ever carry. No -L, no -D, ever.
//   - StrictHostKeyChecking=yes fails rather than prompts on an unknown key, so the app owns
//     known_hosts explicitly and GlobalKnownHostsFile is pointed at the null device. Never
//     "no", and never "accept-new" for a key the operator has not confirmed.
//   - BatchMode and IdentitiesOnly keep ssh from prompting or from trying any other identity,
//     including one an agent might offer.
//   - ExitOnForwardFailure turns a refused forward into an exit the supervisor can classify,
//     rather than a live session with no tunnel in it.
func Args(s Spec, keyPath, knownHosts string) []string {
	fwd := fmt.Sprintf("127.0.0.1:%d:127.0.0.1:%d", s.Port, s.Port)
	return []string{
		"-F", nullDevice,
		"-i", keyPath,
		"-N",
		"-o", "ForwardAgent=no",
		"-o", "ForwardX11=no",
		"-o", "PermitLocalCommand=no",
		"-o", "IdentitiesOnly=yes",
		"-o", "BatchMode=yes",
		"-o", "PubkeyAuthentication=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "ExitOnForwardFailure=yes",
		"-o", "ServerAliveInterval=30",
		"-o", "ServerAliveCountMax=3",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + knownHosts,
		"-o", "GlobalKnownHostsFile=" + nullDevice,
		"-o", "ConnectTimeout=15",
		"-R", fwd,
		s.target(),
	}
}

// ExecRunner starts a real ssh child. Path is the ssh binary; empty means look it up on PATH.
type ExecRunner struct{ Path string }

// Start launches ssh with the argv from Args. Arguments are passed as a slice, never a joined
// string, so nothing can be mis-quoted; the manual quoting the PowerShell supervisor needs is a
// Windows PowerShell 5.1 constraint that does not apply here.
func (e ExecRunner) Start(ctx context.Context, s Spec, keyPath, knownHosts string) (Proc, error) {
	if err := Validate(s); err != nil {
		return nil, err
	}
	bin := e.Path
	if bin == "" {
		p, err := exec.LookPath(SSHName)
		if err != nil {
			return nil, fmt.Errorf("%w: %s not on PATH", errExec, SSHName)
		}
		bin = p
	}
	// #nosec G204 -- bin is a fixed binary name resolved on PATH, and every Spec field in the
	// argv passed Validate: no whitespace, quote, metacharacter or leading dash survives it.
	cmd := exec.Command(bin, Args(s, keyPath, knownHosts)...)
	var errBuf lockedBuf
	cmd.Stderr = &errBuf
	cmd.Stdout = nil
	// A key with no passphrase must never fall back to a prompt of any kind, and the child gets
	// no inherited environment: this process holds the vault passphrase in its own, and an
	// inherited SSH_AUTH_SOCK or SSH_ASKPASS has no business in a tunnel child.
	cmd.Env = append(hardenedEnv(), "SSH_ASKPASS_REQUIRE=never")
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%w: %s", errExec, err)
	}
	return &execProc{cmd: cmd, err: &errBuf}, nil
}

// errExec marks a failure to start ssh at all, which Classify maps to exec_failed.
var errExec = errors.New("tunnel: cannot start ssh")

type execProc struct {
	cmd  *exec.Cmd
	err  *lockedBuf
	once sync.Once
	code int
}

func (p *execProc) Pid() int { return p.cmd.Process.Pid }

func (p *execProc) Wait() int {
	p.once.Do(func() {
		err := p.cmd.Wait()
		p.code = p.cmd.ProcessState.ExitCode()
		if err != nil && p.code == 0 {
			p.code = -1
		}
	})
	return p.code
}

func (p *execProc) Kill() error {
	if p.cmd.Process == nil {
		return nil
	}
	return p.cmd.Process.Kill()
}

func (p *execProc) Stderr() string { return p.err.String() }

// lockedBuf is an io.Writer safe for the goroutine exec uses to copy stderr while another reads it.
type lockedBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Cap what is held: stderr is classified and dropped, so there is no reason to keep more than
	// enough to recognise a banner, and a chatty child must not grow this without bound.
	if b.buf.Len() > maxStderr {
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *lockedBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// maxStderr bounds the stderr kept per child.
const maxStderr = 8 << 10

// keyDirName is the subdirectory of the data dir that holds the ephemeral key files.
const keyDirName = "tunnel-keys"

// keyDir returns the restricted directory the ephemeral key files live in, creating it with an
// owner-only mode (0700 on Unix, an inheritable owner-only ACL on Windows).
func keyDir(dataDir string) (string, error) {
	d := filepath.Join(dataDir, keyDirName)
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", fmt.Errorf("tunnel: key dir: %w", err)
	}
	// MkdirAll leaves an existing directory's mode alone, so tighten it explicitly.
	if err := credfile.RestrictDir(d); err != nil {
		return "", fmt.Errorf("tunnel: restrict key dir: %w", err)
	}
	return d, nil
}

// writeKeyFile writes an OpenSSH private key for ssh to read with -i. ssh will not take a key on
// stdin, so this is the exposure window the addendum accepts for v1: one child's lifetime, in a
// directory that is already owner-only, with the file itself restricted again, deleted when the
// child exits and reaped at start if a hard kill left one behind.
//
// NOT VERIFIED: exactly what Windows ssh.exe demands of this file's ACL. It refuses a key it
// judges too permissive and the error is unhelpful. This uses the same owner-only ACL as the
// credentials file and the runbook's icacls recipe, which is the best available guess.
func writeKeyFile(dir, hostID string, seed []byte) (string, error) {
	pem, err := encodePrivateKey(seed)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "tun-"+safeName(hostID))
	// O_EXCL so a leftover file is never written through: the caller removes it first.
	removeQuiet(path)
	// #nosec G304 -- path is built here from the data dir and safeName(hostID), which keeps only
	// [A-Za-z0-9_-]; no caller-supplied string reaches it.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("tunnel: key file: %w", err)
	}
	if err := credfile.RestrictFile(path); err != nil {
		_ = f.Close()
		removeQuiet(path)
		return "", fmt.Errorf("tunnel: restrict key file: %w", err)
	}
	if _, err := f.Write(pem); err != nil {
		_ = f.Close()
		removeQuiet(path)
		return "", fmt.Errorf("tunnel: key file write: %w", err)
	}
	if err := f.Close(); err != nil {
		removeQuiet(path)
		return "", fmt.Errorf("tunnel: key file close: %w", err)
	}
	return path, nil
}

// safeName reduces an id to characters that are safe in a file name.
func safeName(id string) string {
	out := make([]rune, 0, len(id))
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "unnamed"
	}
	if len(out) > 48 {
		out = out[:48]
	}
	return string(out)
}

func removeQuiet(p string) { _ = os.Remove(p) }
