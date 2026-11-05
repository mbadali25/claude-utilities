package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"claude-utilities/internal/credfile"
	"claude-utilities/internal/logx"
	"claude-utilities/internal/proto"
)

// Add-account sign-in. The agent runs Anthropic's own `claude auth login` in a throwaway config
// dir, relays the printed sign-in URL to the hub, writes back the one-time code the owner pastes,
// and returns the resulting login. The host's live credentials are never read or written here.
//
// Nothing this file handles is logged: not the URL (it carries PKCE state), not the code, not the
// block, not the identity, and not the CLI's output. Failures log a fixed reason only.

const (
	loginDirPrefix     = "login-"
	defaultURLTimeout  = 15 * time.Second
	defaultJobTimeout  = 10 * time.Minute
	defaultExitTimeout = 60 * time.Second
	killGrace          = 2 * time.Second
	maxLoginOutput     = 64 << 10
	maxLoginCode       = 2048
)

var (
	errNeedMore = errors.New("agent: sign-in URL not complete yet")
	// errNoCLI is what a loginRunner returns when the claude executable is not on PATH.
	errNoCLI = errors.New("agent: claude CLI not found")

	// jobIDRe is the shape of a hub-generated job id; it names a directory, so nothing else passes.
	jobIDRe = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

// loginRunner is the test seam for the child process.
type loginRunner interface {
	Start(ctx context.Context, configDir string) (stdout io.Reader, stdin io.WriteCloser, wait func() error, kill func(), err error)
}

type loginJob struct {
	id        string
	cancel    context.CancelFunc
	cancelled atomic.Bool
	codeCh    chan []byte
}

// extractLoginURL returns the first URL in the child's stdout. The URL may sit inside an OSC-8
// hyperlink and appear twice, so it is taken from the raw bytes and ends at the first control or
// space byte (ESC, BEL, newline). A URL without a terminator yet is errNeedMore; a URL that fails
// validation, or never ends within the size bound, is an error.
func extractLoginURL(out []byte) (string, error) {
	idx := -1
	for _, p := range []string{"https://", "http://"} {
		if i := bytes.Index(out, []byte(p)); i >= 0 && (idx < 0 || i < idx) {
			idx = i
		}
	}
	if idx < 0 {
		return "", errNeedMore
	}
	rest := out[idx:]
	end := bytes.IndexFunc(rest, func(r rune) bool { return r <= ' ' || r == 0x7f })
	if end < 0 {
		if len(rest) > proto.MaxLoginURL {
			return "", errors.New("agent: sign-in URL too long")
		}
		return "", errNeedMore
	}
	u := string(rest[:end])
	if err := proto.ValidateLoginURL(u); err != nil {
		return "", err
	}
	return u, nil
}

// cleanStaleLogins removes login-* directories a crashed run left in the state dir.
func cleanStaleLogins(stateDir string) {
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), loginDirPrefix) {
			_ = os.RemoveAll(filepath.Join(stateDir, e.Name()))
		}
	}
}

// startLogin registers the job and runs it in the background so the read loop never blocks.
func (a *agent) startLogin(ctx context.Context, s *sess, id string) {
	if !jobIDRe.MatchString(id) {
		a.loginReply(ctx, s, id, "bad job id")
		a.log.Warn("login refused", "action", "login_start", "result", "refused", "reason", "bad_id")
		return
	}
	a.loginMu.Lock()
	if len(a.logins) > 0 {
		a.loginMu.Unlock()
		a.loginReply(ctx, s, id, "another sign-in is already running")
		a.log.Warn("login refused", "action", "login_start", "result", "refused", "reason", "busy")
		return
	}
	jctx, cancel := context.WithTimeout(ctx, a.jobTimeout)
	job := &loginJob{id: id, cancel: cancel, codeCh: make(chan []byte, 1)}
	a.logins[id] = job
	a.loginWG.Add(1) // handle runs on the read loop, which ends before session waits
	a.loginMu.Unlock()
	a.log.Info("login started", "action", "login_start", "result", "ok")
	go a.runLogin(jctx, ctx, s, job)
}

func (a *agent) loginReply(ctx context.Context, s *sess, id, msg string) {
	if err := s.send(ctx, proto.TypeLoginDone, id, proto.LoginDone{Err: msg}); err != nil {
		a.log.Warn("login reply failed", "action", "login_done", "result", "send_failed", logx.Err(err))
	}
}

// loginCode hands the owner's code to the waiting job. The code is held in memory only.
func (a *agent) loginCode(id, code string) error {
	code = strings.TrimSpace(code)
	if code == "" || len(code) > maxLoginCode || strings.ContainsFunc(code, func(r rune) bool { return r < ' ' || r == 0x7f }) {
		return errors.New("agent: bad sign-in code")
	}
	a.loginMu.Lock()
	job := a.logins[id]
	a.loginMu.Unlock()
	if job == nil {
		return errors.New("agent: no such sign-in")
	}
	select {
	case job.codeCh <- []byte(code):
		a.log.Info("login code received", "action", "login_code", "result", "ok")
		return nil
	default:
		return errors.New("agent: a code was already given")
	}
}

func (a *agent) cancelLogin(id string) {
	a.loginMu.Lock()
	job := a.logins[id]
	a.loginMu.Unlock()
	if job == nil {
		return
	}
	job.cancelled.Store(true)
	job.cancel()
	a.log.Info("login cancelled", "action", "login_cancel", "result", "ok")
}

func (a *agent) runLogin(jctx, ctx context.Context, s *sess, job *loginJob) {
	defer a.loginWG.Done()
	defer func() {
		job.cancel()
		a.loginMu.Lock()
		delete(a.logins, job.id)
		a.loginMu.Unlock()
	}()
	start := time.Now()
	dir := filepath.Join(a.cfg.StateDir, loginDirPrefix+job.id)
	done, why, report := a.loginFlow(jctx, ctx, s, job, dir) // its defers kill the child and remove dir
	ms := time.Since(start).Milliseconds()
	if why == "ok" {
		a.log.Info("login finished", "action", "login_done", "result", "ok", "durationms", ms)
	} else {
		a.log.Warn("login finished", "action", "login_done", "result", "failed", "reason", why, "durationms", ms)
	}
	if !report {
		return
	}
	if err := s.send(ctx, proto.TypeLoginDone, job.id, done); err != nil {
		a.log.Warn("login reply failed", "action", "login_done", "result", "send_failed", logx.Err(err))
	}
}

// loginFlow runs one sign-in. report is false when the hub no longer wants an answer (cancelled,
// or the session ended). why is a fixed reason code, never CLI output.
func (a *agent) loginFlow(jctx, ctx context.Context, s *sess, job *loginJob, dir string) (done proto.LoginDone, why string, report bool) {
	fail := func(msg, reason string) (proto.LoginDone, string, bool) {
		return proto.LoginDone{Err: msg}, reason, true
	}
	stopped := func() (proto.LoginDone, string, bool) {
		switch {
		case job.cancelled.Load():
			return proto.LoginDone{}, "cancelled", false
		case ctx.Err() == nil && errors.Is(jctx.Err(), context.DeadlineExceeded):
			return fail("timed out", "timeout")
		}
		return proto.LoginDone{}, "shutdown", false
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fail("could not prepare the sign-in directory", "mkdir")
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := credfile.RestrictDir(dir); err != nil {
		return fail("could not prepare the sign-in directory", "restrict")
	}

	stdout, stdin, wait, kill, err := a.login.Start(jctx, dir)
	if err != nil {
		if errors.Is(err, errNoCLI) {
			return fail("claude CLI not found on host", "no_cli")
		}
		return fail("could not start the claude CLI", "start_failed")
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- wait() }()
	exited := false
	defer func() {
		kill()
		_ = stdin.Close()
		if !exited {
			select {
			case werr := <-waitCh:
				_ = werr // the kill is deliberate: its exit status says nothing
			case <-time.After(killGrace):
			}
		}
	}()

	chunks := make(chan []byte, 16)
	go func() {
		defer close(chunks)
		buf := make([]byte, 4096)
		for {
			n, rerr := stdout.Read(buf)
			if n > 0 {
				chunks <- append([]byte(nil), buf[:n]...)
			}
			if rerr != nil {
				return
			}
		}
	}()
	// Keep reading after the URL (and on early return) so the child never blocks on a full pipe.
	drain := sync.OnceFunc(func() {
		go func() {
			for range chunks { //nolint:revive // drain
			}
		}()
	})
	defer drain()

	var out []byte
	var url string
	timer := time.NewTimer(a.urlTimeout)
	defer timer.Stop()
	for url == "" {
		select {
		case c, ok := <-chunks:
			if !ok {
				return fail("sign-in ended before a URL appeared", "child_exit")
			}
			out = append(out, c...)
			if len(out) > maxLoginOutput {
				return fail("no sign-in URL appeared", "no_url")
			}
			u, xerr := extractLoginURL(out)
			switch {
			case xerr == nil:
				url = u
			case errors.Is(xerr, errNeedMore):
			default:
				return fail("bad sign-in URL", "bad_url")
			}
		case <-timer.C:
			return fail("no sign-in URL appeared", "no_url")
		case <-jctx.Done():
			return stopped()
		}
	}
	drain()
	if err := s.send(ctx, proto.TypeLoginURL, job.id, proto.LoginURL{URL: url}); err != nil {
		return proto.LoginDone{}, "send_failed", false
	}
	a.log.Info("login url sent", "action", "login_url", "result", "ok")

	var code []byte
	select {
	case code = <-job.codeCh:
	case werr := <-waitCh:
		_ = werr
		exited = true
		return fail("sign-in ended before a code was entered", "child_exit")
	case <-jctx.Done():
		return stopped()
	}
	line := make([]byte, len(code)+1)
	copy(line, code)
	line[len(code)] = '\n'
	_, _ = stdin.Write(line) // a dead child shows up as its exit status below
	clear(line)
	clear(code)

	exitTimer := time.NewTimer(a.exitTimeout)
	defer exitTimer.Stop()
	select {
	case werr := <-waitCh:
		exited = true
		if werr != nil {
			return fail("sign-in rejected", "child_exit")
		}
	case <-exitTimer.C:
		return fail("timed out", "timeout")
	case <-jctx.Done():
		return stopped()
	}

	block, err := credfile.ReadBlock(filepath.Join(dir, ".credentials.json"))
	if err != nil {
		return fail("no credentials after sign-in", "no_credentials")
	}
	ident := readIdentity(filepath.Join(dir, ".claude.json"))
	if ident == "" {
		return fail("no signed-in identity after sign-in", "no_identity")
	}
	return proto.LoginDone{Block: block, Identity: ident}, "ok", true
}

// execRunner runs the real CLI.
type execRunner struct{}

func (execRunner) Start(ctx context.Context, configDir string) (io.Reader, io.WriteCloser, func() error, func(), error) {
	cmd := exec.CommandContext(ctx, "claude", "auth", "login", "--claudeai") //nolint:gosec // fixed arguments
	cmd.Dir = configDir
	cmd.Env = loginEnv(configDir)
	cmd.WaitDelay = killGrace
	pr, pw := io.Pipe()
	cmd.Stdout = pw // stderr stays nil (discarded): the CLI output is never kept
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("agent: login stdin: %w", err)
	}
	if err := cmd.Start(); err != nil {
		_ = pw.Close()
		if errors.Is(err, exec.ErrNotFound) {
			return nil, nil, nil, nil, errNoCLI
		}
		return nil, nil, nil, nil, fmt.Errorf("agent: start claude: %w", err)
	}
	wait := func() error {
		werr := cmd.Wait()
		_ = pw.Close()
		return werr
	}
	kill := func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}
	return pr, stdin, wait, kill, nil
}

// loginEnv is the parent environment with CLAUDE_CONFIG_DIR pointed at the throwaway dir and
// BROWSER pointed at an inert stub, so the sign-in link shows only in the UI.
func loginEnv(configDir string) []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.EqualFold(k, "CLAUDE_CONFIG_DIR") || strings.EqualFold(k, "BROWSER") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "CLAUDE_CONFIG_DIR="+configDir)
	if stub := writeBrowserStub(configDir); stub != "" {
		env = append(env, "BROWSER="+stub)
	}
	return env
}

func writeBrowserStub(dir string) string {
	name, body := "browser-stub.sh", "#!/bin/sh\nexit 0\n"
	if runtime.GOOS == "windows" {
		name, body = "browser-stub.cmd", "@exit /b 0\r\n"
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o700); err != nil { //nolint:gosec // an executable stub in a private temp dir
		return ""
	}
	return p
}
