package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"

	"github.com/coder/websocket"

	"claude-utilities/internal/credfile"
	"claude-utilities/internal/logx"
	"claude-utilities/internal/proto"
)

const (
	// approvalTimeout is how long enrolment waits for the owner.
	approvalTimeout = 10 * time.Minute
	deniedFileName  = "enrol-denied.json"
	maxRetryAfter   = 24 * time.Hour
	maxReasonLen    = 120
)

var (
	// ErrDenied means the owner (or the server) refused this host. The CLI exits 2.
	ErrDenied = errors.New("agent: enrolment denied")
	// ErrApprovalTimeout means nobody approved the host within 10 minutes.
	ErrApprovalTimeout = errors.New("agent: enrolment not approved in time")
	// ErrFingerprintMismatch means the server's pending fingerprint differs from the one computed
	// locally from the hello, so the owner would be matching the wrong host.
	ErrFingerprintMismatch = errors.New("agent: server fingerprint does not match this host's hello")
)

func init() {
	// The fingerprint is public by design: the owner reads it off the console and the UI.
	logx.Allow("fingerprint")
}

// enrolOpts carries the seams Enrol fixes to real values.
type enrolOpts struct {
	StateDir  string
	CredsPath string
	HostName  string
	Now       func() time.Time
	After     func(time.Duration) <-chan time.Time
	Log       *slog.Logger
}

// Enrol registers this host with the server (spec Decision 13). It sends one tokenless hello
// with a fresh nonce, prints "Fingerprint: <8 chars>" for the owner to match in the web UI,
// and waits up to 10 minutes for Approved. A non-empty code takes the pre-approved path. On
// approval it writes <StateDir>/agent.json (0600) and returns the config.
func Enrol(ctx context.Context, serverURL, pin, hostName, code string, out io.Writer) (Config, error) {
	dir, err := DefaultStateDir()
	if err != nil {
		return Config{}, err
	}
	creds, err := credfile.ResolvePath()
	if err != nil {
		return Config{}, err
	}
	if hostName == "" {
		hostName, _ = os.Hostname()
	}
	return enrol(ctx, enrolOpts{
		StateDir: dir, CredsPath: creds, HostName: hostName, Now: time.Now, After: time.After, Log: logx.New(os.Stderr),
	}, serverURL, pin, code, out)
}

type frame struct {
	env proto.Envelope
	err error
}

func enrol(ctx context.Context, o enrolOpts, serverURL, pin, code string, out io.Writer) (Config, error) {
	log := o.Log.With("component", "enrol")
	normPinned, ok := normPin(pin)
	if !ok {
		return Config{}, ErrBadPin
	}
	target := targetKey(serverURL, normPinned)
	if err := checkDenied(o, target); err != nil {
		return Config{}, err
	}
	nonce, err := randHex(16)
	if err != nil {
		return Config{}, err
	}
	hello := proto.Hello{Code: code, HostName: o.HostName, OS: runtime.GOOS, Nonce: nonce}
	fp := proto.Fingerprint(hello)

	ws, err := dialPinned(ctx, serverURL, normPinned)
	if err != nil {
		return Config{}, err
	}
	defer func() { _ = ws.CloseNow() }()
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()

	b, err := proto.Encode(proto.TypeHello, "", hello)
	if err != nil {
		return Config{}, err
	}
	wctx, wcancel := context.WithTimeout(rctx, writeWait)
	err = ws.Write(wctx, websocket.MessageText, b)
	wcancel()
	if err != nil {
		return Config{}, fmt.Errorf("agent: send hello: %w", err)
	}

	frames := make(chan frame)
	go func() {
		for {
			_, data, err := ws.Read(rctx)
			f := frame{err: err}
			if err == nil {
				f.env, f.err = proto.Decode(data)
			}
			select {
			case frames <- f:
			case <-rctx.Done():
				return
			}
			if f.err != nil {
				return
			}
		}
	}()

	timeout := o.After(approvalTimeout)
	for {
		select {
		case <-ctx.Done():
			return Config{}, ctx.Err()
		case <-timeout:
			_, _ = fmt.Fprintln(out, "Enrolment timed out: no one approved this host within 10 minutes.")
			log.Warn("enrolment timed out", "action", "enrol", "result", "timeout")
			return Config{}, ErrApprovalTimeout
		case f := <-frames:
			if f.err != nil {
				return Config{}, fmt.Errorf("agent: connection closed before approval: %s", logx.Redact(f.err.Error()))
			}
			switch f.env.Type {
			case proto.TypePending:
				var p proto.Pending
				if err := json.Unmarshal(f.env.Body, &p); err != nil {
					return Config{}, errors.New("agent: bad pending message")
				}
				if p.Fingerprint != fp {
					return Config{}, ErrFingerprintMismatch
				}
				_, _ = fmt.Fprintf(out, "Fingerprint: %s\n", fp)
				_, _ = fmt.Fprintf(out, "Match it, then approve this host in the web UI (expires %s).\n", p.ExpiresAt.Local().Format(time.RFC3339))
				log.Info("waiting for approval", "action", "enrol", "result", "pending", "fingerprint", fp)
			case proto.TypeApproved:
				var ap proto.Approved
				if err := json.Unmarshal(f.env.Body, &ap); err != nil || ap.Token == "" {
					return Config{}, errors.New("agent: bad approval message")
				}
				cfg := Config{ServerURL: serverURL, Token: ap.Token, Pin: normPinned, CredsPath: o.CredsPath, StateDir: o.StateDir}
				if err := SaveConfig(cfg); err != nil {
					return Config{}, err
				}
				_ = os.Remove(deniedPath(o))
				_, _ = fmt.Fprintln(out, "Enrolled. Start the agent with: agent run")
				log.Info("enrolled", "action", "enrol", "result", "approved")
				return cfg, nil
			case proto.TypeDenied:
				var d proto.Denied
				if err := json.Unmarshal(f.env.Body, &d); err != nil {
					return Config{}, errors.New("agent: bad denial message")
				}
				return Config{}, denied(o, log, out, d, target)
			default:
				return Config{}, fmt.Errorf("agent: unexpected %q message during enrolment", logx.Redact(f.env.Type))
			}
		}
	}
}

// printable strips control characters and clips server-supplied text before it reaches a terminal.
func printable(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
	if rs := []rune(s); len(rs) > maxReasonLen {
		s = string(rs[:maxReasonLen])
	}
	return logx.Redact(s)
}

type deniedFile struct {
	Until time.Time `json:"until"`
	// Target is a digest of the server URL and pin the denial came from, so a denial by one
	// server never blocks enrolment with another.
	Target string `json:"target"`
}

// targetKey digests server URL + pin; the URL itself is not stored.
func targetKey(serverURL, pin string) string {
	sum := sha256.Sum256([]byte(strings.TrimRight(serverURL, "/") + "\x00" + pin))
	return hex.EncodeToString(sum[:])
}

func deniedPath(o enrolOpts) string { return filepath.Join(o.StateDir, deniedFileName) }

// denied prints the reason, records when a retry is allowed and returns ErrDenied.
func denied(o enrolOpts, log *slog.Logger, out io.Writer, d proto.Denied, target string) error {
	reason := printable(d.Reason)
	if reason == "" {
		reason = "no reason given"
	}
	_, _ = fmt.Fprintf(out, "Denied: %s\n", reason)
	log.Warn("enrolment denied", "action", "enrol", "result", "denied", "reason", reason)
	if d.RetryAfter > 0 {
		wait := min(d.RetryAfter, maxRetryAfter)
		if err := os.MkdirAll(o.StateDir, 0o700); err == nil {
			_ = credfile.RestrictDir(o.StateDir)
			if data, merr := json.Marshal(deniedFile{Until: o.Now().Add(wait), Target: target}); merr == nil {
				if werr := writePrivate(deniedPath(o), data); werr != nil {
					log.Warn("could not record retry-after", "action", "enrol", "result", "failed", logx.Err(werr))
				}
			}
		}
		_, _ = fmt.Fprintf(out, "Do not retry for %s.\n", wait.Round(time.Second))
	}
	return fmt.Errorf("%w: %s", ErrDenied, reason)
}

// checkDenied refuses to dial while a recorded RetryAfter is still in the future.
func checkDenied(o enrolOpts, target string) error {
	data, err := os.ReadFile(deniedPath(o))
	if err != nil {
		return nil
	}
	var df deniedFile
	if json.Unmarshal(data, &df) != nil || df.Target != target {
		return nil // unreadable, or another server's denial
	}
	if now := o.Now(); now.Before(df.Until) {
		return fmt.Errorf("%w: retry in %s", ErrDenied, df.Until.Sub(now).Round(time.Second))
	}
	_ = os.Remove(deniedPath(o))
	return nil
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("agent: random: %w", err)
	}
	return hex.EncodeToString(b), nil
}
