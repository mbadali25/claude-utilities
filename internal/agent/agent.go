// Package agent runs on each host. It dials out to the server over a certificate-pinned
// WebSocket, reports live sessions as a heartbeat, exports the host's login block on request
// and applies a swap with a journal, read-back check and rollback.
//
// It never logs or prints a token or a credential block.
package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"claude-utilities/internal/credfile"
	"claude-utilities/internal/install"
	"claude-utilities/internal/logx"
	"claude-utilities/internal/proto"
	"claude-utilities/internal/sessions"
)

const (
	configName = "agent.json"
	wsPath     = "/ws"
	// HeartbeatInterval is how often the agent reports; the server marks a host offline after 45 s.
	HeartbeatInterval = 15 * time.Second
	// stableAfter is how long a connection must last before the reconnect backoff resets.
	stableAfter = 30 * time.Second
	dialTimeout = 15 * time.Second
	writeWait   = 10 * time.Second
	maxIdentity = 256

	reasonExpired = "refresh token expired"
)

var (
	// ErrInsecureURL means the server URL is not https/wss: the hello carries a token.
	ErrInsecureURL = errors.New("agent: server URL must be https")
	// ErrBadPin means the configured certificate pin is not a SHA-256 hex digest.
	ErrBadPin = errors.New("agent: certificate pin must be 64 hex characters (SHA-256)")
	// ErrPinMismatch means the server presented a certificate that is not the pinned one.
	ErrPinMismatch = errors.New("agent: server certificate does not match the pin")
	// ErrNotEnrolled means the config holds no token.
	ErrNotEnrolled = errors.New("agent: not enrolled (no token); run enrol first")
)

// Config is the agent's persisted settings. Token is a secret: the type never prints it.
type Config struct {
	ServerURL string `json:"serverUrl"`
	Token     string `json:"token"`
	Pin       string `json:"pin"`
	CredsPath string `json:"credsPath,omitempty"`
	StateDir  string `json:"-"`
}

const mask = "[redacted]"

func (c Config) String() string {
	return fmt.Sprintf("Config{ServerURL:%s Token:%s Pin:%s CredsPath:%s StateDir:%s}",
		logx.Redact(c.ServerURL), mask, c.Pin, logx.Redact(c.CredsPath), logx.Redact(c.StateDir))
}
func (c Config) GoString() string { return c.String() }
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(slog.String("token", mask))
}

// DefaultStateDir is where agent.json and the swap journal live.
func DefaultStateDir() (string, error) {
	if d := os.Getenv(install.StateDirEnv); d != "" {
		return d, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("agent: state dir: %w", err)
	}
	return filepath.Join(base, "claude-swap-agent"), nil
}

// SaveConfig writes <StateDir>/agent.json owner-only.
func SaveConfig(c Config) error {
	if c.StateDir == "" {
		return errors.New("agent: no state dir")
	}
	if err := os.MkdirAll(c.StateDir, 0o700); err != nil {
		return fmt.Errorf("agent: state dir: %w", err)
	}
	if err := credfile.RestrictDir(c.StateDir); err != nil {
		return fmt.Errorf("agent: restrict state dir: %w", err)
	}
	data, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("agent: marshal config: %w", err)
	}
	return writePrivate(filepath.Join(c.StateDir, configName), data)
}

// LoadConfig reads <stateDir>/agent.json.
func LoadConfig(stateDir string) (Config, error) {
	data, err := os.ReadFile(filepath.Join(stateDir, configName))
	if err != nil {
		return Config{}, fmt.Errorf("agent: read config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return Config{}, errors.New("agent: config unreadable")
	}
	c.StateDir = stateDir
	return c, nil
}

// normPin lowercases a pin and drops ':' and spaces; ok is false unless it is 64 hex chars.
func normPin(p string) (string, bool) {
	p = strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(p))
	b, err := hex.DecodeString(p)
	return p, err == nil && len(b) == sha256.Size
}

// dialPinned opens the WebSocket. It accepts only https/wss, and trusts exactly the server
// certificate whose SHA-256 digest equals pin: no name or chain check, no fallback.
func dialPinned(ctx context.Context, serverURL, pin string) (*websocket.Conn, error) {
	u, err := url.Parse(serverURL)
	if err != nil || u.Host == "" {
		return nil, errors.New("agent: bad server URL")
	}
	if u.Scheme != "https" && u.Scheme != "wss" {
		return nil, ErrInsecureURL
	}
	u.Scheme = "wss"
	if u.Path == "" || u.Path == "/" {
		u.Path = wsPath
	}
	want, ok := normPin(pin)
	if !ok {
		return nil, ErrBadPin
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// The pin replaces chain verification; VerifyPeerCertificate below is mandatory.
		InsecureSkipVerify: true, //nolint:gosec
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return ErrPinMismatch
			}
			sum := sha256.Sum256(raw[0])
			if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(want)) != 1 {
				return ErrPinMismatch
			}
			return nil
		},
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	ws, _, err := websocket.Dial(dctx, u.String(), &websocket.DialOptions{HTTPClient: client})
	if err != nil {
		if errors.Is(err, ErrPinMismatch) {
			return nil, ErrPinMismatch
		}
		return nil, fmt.Errorf("agent: dial: %w", err)
	}
	ws.SetReadLimit(proto.MaxMessageSize)
	return ws, nil
}

// agent holds the running state; the func fields are test seams.
type agent struct {
	cfg Config
	log *slog.Logger
	mu  sync.Mutex // serialises swaps against recovery

	hostName  string
	heartbeat time.Duration
	delay     func(attempt int) time.Duration
	identity  func() string
	scan      func(context.Context) ([]proto.Session, error)
	readBack  func(path string) (json.RawMessage, error)
}

func newAgent(c Config, log *slog.Logger) *agent {
	name, _ := os.Hostname()
	return &agent{
		cfg: c, log: log.With("component", "agent"), hostName: name, heartbeat: HeartbeatInterval,
		delay: NextDelay, identity: func() string { return readIdentity(claudeJSONPath()) },
		scan: sessions.Scan, readBack: credfile.ReadBlock,
	}
}

// Run connects, reports and serves swap requests until ctx ends. It redials with NextDelay
// backoff after any drop, and finishes or rolls back an interrupted swap first.
func Run(ctx context.Context, c Config) error {
	if c.Token == "" {
		return ErrNotEnrolled
	}
	if c.CredsPath == "" {
		p, err := credfile.ResolvePath()
		if err != nil {
			return err
		}
		c.CredsPath = p
	}
	if c.StateDir == "" {
		d, err := DefaultStateDir()
		if err != nil {
			return err
		}
		c.StateDir = d
	}
	if err := os.MkdirAll(c.StateDir, 0o700); err != nil {
		return fmt.Errorf("agent: state dir: %w", err)
	}
	return newAgent(c, logx.New(os.Stderr)).run(ctx)
}

func (a *agent) run(ctx context.Context) error {
	if err := a.recoverJournal(); err != nil {
		a.log.Error("swap recovery failed", "action", "recover", "result", "failed", logx.Err(err))
	}
	attempt := 0
	for {
		start := time.Now()
		err := a.session(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Since(start) >= stableAfter {
			attempt = 0
		}
		d := a.delay(attempt)
		attempt++
		a.log.Warn("disconnected", "action", "reconnect", "attempt", attempt, "durationms", d.Milliseconds(), logx.Err(err))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
		}
	}
}

// sess is one live connection; writes are serialised.
type sess struct {
	ws *websocket.Conn
	mu sync.Mutex
}

func (s *sess) send(ctx context.Context, typ, id string, body any) error {
	b, err := proto.Encode(typ, id, body)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	wctx, cancel := context.WithTimeout(ctx, writeWait)
	defer cancel()
	return s.ws.Write(wctx, websocket.MessageText, b)
}

func (a *agent) session(ctx context.Context) error {
	ws, err := dialPinned(ctx, a.cfg.ServerURL, a.cfg.Pin)
	if err != nil {
		return err
	}
	defer ws.CloseNow()
	s := &sess{ws: ws}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := s.send(sctx, proto.TypeHello, "", proto.Hello{Token: a.cfg.Token, HostName: a.hostName, OS: runtime.GOOS}); err != nil {
		return err
	}
	if err := s.send(sctx, proto.TypeReport, "", a.report(sctx)); err != nil {
		return err
	}
	a.log.Info("connected", "action", "connect", "result", "ok")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.beat(sctx, s)
	}()
	defer wg.Wait()
	defer cancel()

	for {
		_, data, err := ws.Read(sctx)
		if err != nil {
			return err
		}
		env, err := proto.Decode(data)
		if err != nil {
			return err
		}
		if err := a.handle(sctx, s, env); err != nil {
			return err
		}
	}
}

// beat sends a report every heartbeat; the server treats any frame as proof of life.
func (a *agent) beat(ctx context.Context, s *sess) {
	t := time.NewTicker(a.heartbeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.send(ctx, proto.TypeReport, "", a.report(ctx)); err != nil {
				_ = s.ws.Close(websocket.StatusInternalError, "write failed")
				return
			}
		}
	}
}

func (a *agent) handle(ctx context.Context, s *sess, env proto.Envelope) error {
	switch env.Type {
	case proto.TypeExportReq, proto.TypeSwapReq:
		if env.ID == "" {
			a.log.Warn("request without id", "action", env.Type, "result", "ignored")
			return nil
		}
	default:
		a.log.Debug("unhandled message", "action", logx.Redact(env.Type), "result", "ignored")
		return nil
	}
	if env.Type == proto.TypeExportReq {
		return s.send(ctx, proto.TypeExportRes, env.ID, a.export())
	}
	var req proto.SwapReq
	if err := json.Unmarshal(env.Body, &req); err != nil {
		return s.send(ctx, proto.TypeSwapRes, env.ID, proto.SwapRes{Reason: "bad swap request"})
	}
	return s.send(ctx, proto.TypeSwapRes, env.ID, a.applySwap(req))
}

// report describes this host. A missing or block-less credentials file is CredsPresent=false.
func (a *agent) report(ctx context.Context) proto.Report {
	sessions, err := a.scan(ctx)
	if err != nil || sessions == nil {
		sessions = []proto.Session{}
	}
	rep := proto.Report{Sessions: sessions}
	if _, err := credfile.ReadBlock(a.cfg.CredsPath); err == nil {
		rep.CredsPresent = true
		rep.ActiveIdentity = a.identity()
	}
	return rep
}

// export returns the live claudeAiOauth block. The block is never logged.
func (a *agent) export() proto.ExportRes {
	block, err := credfile.ReadBlock(a.cfg.CredsPath)
	switch {
	case errors.Is(err, credfile.ErrNoBlock), errors.Is(err, os.ErrNotExist):
		return proto.ExportRes{Err: "no login on this host"}
	case err != nil:
		a.log.Warn("export failed", "action", "export", "result", "unreadable", logx.Err(err))
		return proto.ExportRes{Err: "credentials unreadable"}
	}
	a.log.Info("exported", "action", "export", "result", "ok")
	return proto.ExportRes{Block: block, Identity: a.identity()}
}

// applySwap replaces the claudeAiOauth block. Order: validate, journal, Replace, read-back,
// then clear the journal; a failed read-back restores the backup.
func (a *agent) applySwap(req proto.SwapReq) proto.SwapRes {
	a.mu.Lock()
	defer a.mu.Unlock()
	fail := func(reason string, err error) proto.SwapRes {
		a.log.Warn("swap refused", "action", "swap", "account", logx.Redact(req.Account), "result", reason, logx.Err(err))
		return proto.SwapRes{Reason: logx.Redact(reason)}
	}
	if err := credfile.ValidateBlock(req.Block); err != nil {
		if errors.Is(err, credfile.ErrRefreshExpired) {
			return fail(reasonExpired, nil)
		}
		return fail("invalid login block", err)
	}
	// An earlier swap that never finished must be settled before a new one starts.
	if err := a.recoverJournal(); err != nil {
		return fail("unfinished earlier swap", err)
	}

	path := a.cfg.CredsPath
	var prev json.RawMessage
	switch b, err := credfile.ReadBlock(path); {
	case err == nil:
		prev = b
	case errors.Is(err, credfile.ErrNoBlock), errors.Is(err, os.ErrNotExist):
	default:
		return fail("credentials unreadable", err)
	}
	j := journal{State: journalSwap, PrevHash: hashBlock(prev)}
	if err := writeJournal(a.cfg.StateDir, j); err != nil {
		return fail("cannot write journal", err)
	}

	backup, err := credfile.Replace(path, req.Block)
	if err != nil {
		// Replace may have failed after the backup (rename), so settle through the journal.
		if rerr := a.recoverJournal(); rerr != nil {
			return fail("swap failed and rollback incomplete", errors.Join(err, rerr))
		}
		switch {
		case errors.Is(err, credfile.ErrBusy):
			return fail("credentials file busy", err)
		case errors.Is(err, credfile.ErrChangedDuringSwap):
			return fail("credentials file changed during swap", err)
		}
		return fail("swap failed", err)
	}
	j.BackupPath = backup
	if err := writeJournal(a.cfg.StateDir, j); err != nil {
		a.log.Warn("journal update failed", "action", "swap", "result", "continuing", logx.Err(err))
	}

	got, rerr := a.readBack(path)
	if rerr != nil || !sameBlock(got, req.Block) {
		if err := a.recoverJournal(); err != nil {
			return fail("read-back failed and rollback incomplete", errors.Join(rerr, err))
		}
		return fail("read-back mismatch, rolled back", rerr)
	}
	if err := clearJournal(a.cfg.StateDir); err != nil {
		a.log.Warn("journal clear failed", "action", "swap", "result", "continuing", logx.Err(err))
	}
	a.log.Info("swap applied", "action", "swap", "account", logx.Redact(req.Account), "result", "ok")
	return proto.SwapRes{OK: true}
}

func sameBlock(a, b json.RawMessage) bool {
	var ca, cb bytes.Buffer
	if json.Compact(&ca, a) != nil || json.Compact(&cb, b) != nil {
		return false
	}
	return bytes.Equal(ca.Bytes(), cb.Bytes())
}

// recoverJournal settles an unfinished swap. If the live block still hashes to the pre-swap
// block nothing landed and the journal is dropped; otherwise the backup of the pre-swap block
// is restored. With no usable backup the journal is kept and an error returned.
func (a *agent) recoverJournal() error {
	j, err := readJournal(a.cfg.StateDir)
	if err != nil {
		return err
	}
	if j == nil {
		return nil
	}
	path := a.cfg.CredsPath
	if currentHash(path) != j.PrevHash {
		backup, ok := findBackup(path, j.BackupPath, j.PrevHash)
		if !ok {
			return errors.New("agent: interrupted swap and no matching backup")
		}
		if err := credfile.Restore(path, backup); err != nil {
			return fmt.Errorf("agent: restore: %w", err)
		}
		a.log.Warn("interrupted swap rolled back", "action", "recover", "result", "restored")
	}
	return clearJournal(a.cfg.StateDir)
}

// claudeJSONPath locates Claude Code's global state file, which names the signed-in account.
func claudeJSONPath() string {
	if d := os.Getenv("CLAUDE_CONFIG_DIR"); d != "" {
		return filepath.Join(d, ".claude.json")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".claude.json")
}

// readIdentity returns the signed-in account's email, else its account uuid, else "".
// The value may be an email address: callers must not log it.
func readIdentity(path string) string {
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var f struct {
		OAuthAccount struct {
			Email string `json:"emailAddress"`
			UUID  string `json:"accountUuid"`
		} `json:"oauthAccount"`
	}
	if json.Unmarshal(data, &f) != nil {
		return ""
	}
	id := f.OAuthAccount.Email
	if id == "" {
		id = f.OAuthAccount.UUID
	}
	if len(id) > maxIdentity {
		return ""
	}
	return id
}
