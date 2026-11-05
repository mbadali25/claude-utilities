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
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"claude-utilities/internal/credfile"
	"claude-utilities/internal/install"
	"claude-utilities/internal/logx"
	"claude-utilities/internal/proto"
	"claude-utilities/internal/sessions"
)

func init() {
	// Session-control audit fields (control.go). "command" and "mechanism" are fixed names from
	// a small set; neither carries a secret, a name or a path. A session's name, its cwd and the
	// operator-facing hint are never logged, so they get no key.
	logx.Allow("command", "mechanism")
}

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
	// ErrBadURL means the server URL is unparseable or carries credentials (user:pass@).
	ErrBadURL = errors.New("agent: bad server URL")
	// ErrRejected means the server closed the connection because the token is bad or revoked.
	// Redialling cannot help and counts against the server's per-IP rate limit.
	ErrRejected = errors.New("agent: server rejected the token (bad or revoked); enrol again")
)

// fatal reports errors that no redial can fix: they end Run.
func fatal(err error) bool {
	return errors.Is(err, ErrBadURL) || errors.Is(err, ErrInsecureURL) || errors.Is(err, ErrBadPin) ||
		errors.Is(err, ErrPinMismatch) || errors.Is(err, ErrRejected)
}

// rejection maps a server close for a bad or revoked token to ErrRejected.
func rejection(err error) error {
	var ce websocket.CloseError
	if errors.As(err, &ce) && ce.Code == websocket.StatusPolicyViolation && (ce.Reason == "bad token" || ce.Reason == "revoked") {
		return ErrRejected
	}
	return err
}

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
	d, err := install.TaskStateDir()
	if err != nil {
		return "", fmt.Errorf("agent: state dir: %w", err)
	}
	return d, nil
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
	data, err := os.ReadFile(filepath.Clean(filepath.Join(stateDir, configName)))
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
	if err != nil || u.Host == "" || u.User != nil {
		return nil, ErrBadURL
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
		// The pin replaces chain verification; VerifyConnection below is mandatory (it also runs on resumed sessions).
		InsecureSkipVerify: true, //nolint:gosec
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return ErrPinMismatch
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
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

	blocked atomic.Bool // an unfinished swap could not be settled; reported to the server

	hostName  string
	heartbeat time.Duration
	delay     func(attempt int) time.Duration
	// identity probes the signed-in account: its id, else "" and a proto.Reason* code (identity.go).
	identity func() (string, string)
	// ident caches the last probe, so every report says the same thing and a change is logged once.
	ident *identityCache
	// identityEvery, tick and hup drive the identity refresh; tick and hup are test seams.
	identityEvery time.Duration
	tick          func(time.Duration) (<-chan time.Time, func())
	hup           func() (<-chan os.Signal, func())
	scan          func(context.Context) ([]proto.Session, error)
	readBack      func(path string) (json.RawMessage, error)
	replace       func(path string, block json.RawMessage, onPrev func(json.RawMessage) error) (string, error)

	// Session control (control.go): the instruction queue and the mechanism registry.
	ctl *control

	// Add-account sign-in (login.go). At most one job is live.
	login                               loginRunner
	urlTimeout, jobTimeout, exitTimeout time.Duration
	loginMu                             sync.Mutex
	logins                              map[string]*loginJob
	loginWG                             sync.WaitGroup
}

func newAgent(c Config, log *slog.Logger) *agent {
	name, _ := os.Hostname()
	lg := log.With("component", "agent")
	a := &agent{
		cfg: c, log: lg, hostName: name, heartbeat: HeartbeatInterval,
		delay: NextDelay, identity: newIdentityProbe().run,
		identityEvery: identityRefresh, tick: realTicker, hup: hupSignal,
		scan: sessions.Scan, readBack: credfile.ReadBlock,
		replace: credfile.ReplaceWith,
		login:   execRunner{}, logins: map[string]*loginJob{},
		urlTimeout: defaultURLTimeout, jobTimeout: defaultJobTimeout, exitTimeout: defaultExitTimeout,
		ctl: newControl(c.StateDir, time.Now, os.Getenv(ExperimentalInboxEnv) == "1"),
	}
	// Through a.identity, so a test that replaces the seam after newAgent is still the one probed.
	a.ident = &identityCache{probe: func() (string, string) { return a.identity() }, log: lg}
	return a
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
	// MkdirAll leaves an existing directory's mode alone, so tighten it explicitly.
	if err := credfile.RestrictDir(c.StateDir); err != nil {
		return fmt.Errorf("agent: restrict state dir: %w", err)
	}
	return newAgent(c, logx.New(os.Stderr)).run(ctx)
}

func (a *agent) run(ctx context.Context) error {
	cleanStaleLogins(a.cfg.StateDir) // a crash can leave a throwaway sign-in dir behind
	if err := a.recoverJournal(); err != nil {
		a.log.Error("swap recovery failed", "action", "recover", "result", "failed", logx.Err(err))
	}
	// The identity watcher outlives any one connection: a sign-in while the agent is disconnected
	// is still in the first report after it reconnects. It ends when run does, including on a
	// fatal error, so run never waits on it.
	wctx, stopWatch := context.WithCancel(ctx)
	var idwg sync.WaitGroup
	idwg.Add(1)
	go func() {
		defer idwg.Done()
		a.watchIdentity(wctx)
	}()
	defer idwg.Wait()
	defer stopWatch()
	attempt := 0
	for {
		start := time.Now()
		err := a.session(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err = rejection(err); fatal(err) {
			a.log.Error("agent stopping", "action", "reconnect", "result", "fatal", logx.Err(err))
			return err
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
	defer func() { _ = ws.CloseNow() }()
	s := &sess{ws: ws}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := s.send(sctx, proto.TypeHello, "", proto.Hello{Token: a.cfg.Token, HostName: a.hostName, OS: runtime.GOOS}); err != nil {
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
	defer a.loginWG.Wait() // sign-in jobs kill their child and remove their dir before the session returns
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

// beat sends a report at once, then every heartbeat; the server treats any frame as proof of
// life. The first report runs here so a slow process scan never delays the read loop.
func (a *agent) beat(ctx context.Context, s *sess) {
	t := time.NewTicker(a.heartbeat)
	defer t.Stop()
	for {
		rep := a.report(ctx)
		if err := s.send(ctx, proto.TypeReport, "", rep); err != nil {
			_ = s.ws.Close(websocket.StatusInternalError, "write failed")
			return
		}
		// Only now that the report is on the wire: a failed send must leave the delivery notices
		// in the queue so the next report repeats them.
		a.ctl.q.confirmReported(rep.Commands)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (a *agent) handle(ctx context.Context, s *sess, env proto.Envelope) error {
	switch env.Type {
	case proto.TypeExportReq, proto.TypeSwapReq, proto.TypeCommandReq,
		proto.TypeLoginStart, proto.TypeLoginCode, proto.TypeLoginCancel:
		if env.ID == "" {
			a.log.Warn("request without id", "action", env.Type, "result", "ignored")
			return nil
		}
	default:
		a.log.Debug("unhandled message", "action", logx.Redact(env.Type), "result", "ignored")
		return nil
	}
	switch env.Type {
	case proto.TypeLoginStart:
		a.startLogin(ctx, s, env.ID)
		return nil
	case proto.TypeLoginCode:
		var lc proto.LoginCode
		if json.Unmarshal(env.Body, &lc) != nil || a.loginCode(env.ID, lc.Code) != nil {
			a.loginReply(ctx, s, env.ID, "no sign-in is waiting for a code")
		}
		return nil
	case proto.TypeLoginCancel:
		a.cancelLogin(env.ID)
		return nil
	case proto.TypeCommandReq:
		var cr proto.CommandReq
		if err := json.Unmarshal(env.Body, &cr); err != nil {
			return s.send(ctx, proto.TypeCommandRes, env.ID,
				proto.CommandRes{Status: proto.StatusFailed, Code: proto.CodeBadReply})
		}
		return s.send(ctx, proto.TypeCommandRes, env.ID, a.command(cr))
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

// maxNameRunes bounds a session name on the wire. An unbounded name could push a report past
// proto.MaxMessageSize, and Decode would then reject the host's whole report.
const maxNameRunes = 256

// capRunes truncates s to at most n runes without splitting one.
func capRunes(s string, n int) string {
	if len(s) <= n { // fewer bytes than the cap means fewer runes too
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// report describes this host. A missing or block-less credentials file is CredsPresent=false.
//
// IdentityReason is set whenever ActiveIdentity is empty, and only then: a host that was never
// signed in has no credentials file either, so the reason must not be computed inside the
// credentials branch, or the one host that needs the explanation never gets it.
func (a *agent) report(ctx context.Context) proto.Report {
	sessions, err := a.scan(ctx)
	if err != nil || sessions == nil {
		sessions = []proto.Session{}
	}
	for i := range sessions {
		sessions[i].Name = capRunes(sessions[i].Name, maxNameRunes)
		sessions[i].RemoteName = capRunes(sessions[i].RemoteName, maxNameRunes)
	}
	rep := proto.Report{Sessions: sessions, SwapBlocked: a.blocked.Load(), Commands: a.ctl.q.delivered()}
	id, reason := a.ident.current()
	switch _, err := credfile.ReadBlock(a.cfg.CredsPath); {
	case err == nil:
		rep.CredsPresent = true
		rep.ActiveIdentity, rep.IdentityReason = id, reason
	case reason != "": // no login and nothing names an account: the identity reason is the answer
		rep.IdentityReason = reason
	case errors.Is(err, credfile.ErrNoBlock), errors.Is(err, os.ErrNotExist):
		rep.IdentityReason = proto.ReasonNoCredentials
	default:
		rep.IdentityReason = proto.ReasonUnreadable
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
	id, _ := a.ident.current()
	return proto.ExportRes{Block: block, Identity: id}
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
	switch _, err := credfile.ReadBlock(path); {
	case err == nil:
	case errors.Is(err, credfile.ErrNoBlock), errors.Is(err, os.ErrNotExist):
	default:
		return fail("credentials unreadable", err)
	}
	// The journal is written from inside Replace's lock, with the digest of the block it is about
	// to back up, so a Claude Code refresh between the read above and the lock cannot leave the
	// journal pointing at a block no backup holds.
	j := journal{State: journalSwap, NewHash: hashBlock(req.Block)}
	backup, err := a.replace(path, req.Block, func(prev json.RawMessage) error {
		j.PrevHash = hashBlock(prev)
		return writeJournal(a.cfg.StateDir, j)
	})
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

// recoverJournal settles an unfinished swap and records whether it is still blocked. It only
// ever rolls back, and only when the live block is the swap's incoming block:
//   - live == pre-swap block: nothing landed (or Replace aborted); drop the journal.
//   - live == incoming block: the swap landed; restore the pre-swap backup. With no usable
//     backup the journal is kept and an error returned.
//   - anything else: another writer (Claude Code refreshing its tokens) changed the file since;
//     leave it alone and drop the journal.
//
// A journal that cannot be parsed is quarantined so it cannot block swaps for ever.
func (a *agent) recoverJournal() error {
	err := a.settleJournal()
	a.blocked.Store(err != nil)
	return err
}

func (a *agent) settleJournal() error {
	j, err := readJournal(a.cfg.StateDir)
	if errors.Is(err, errJournalCorrupt) {
		if qerr := quarantineJournal(a.cfg.StateDir); qerr != nil {
			return qerr
		}
		a.log.Warn("corrupt swap journal quarantined", "action", "recover", "result", "quarantined")
		return nil
	}
	if err != nil {
		return err
	}
	if j == nil {
		return nil
	}
	path := a.cfg.CredsPath
	cur := currentHash(path)
	switch {
	case cur == "":
		return errors.New("agent: credentials unreadable during recovery")
	case cur == j.PrevHash:
	case j.NewHash != "" && cur == j.NewHash:
		backup, ok := findBackup(path, j.BackupPath, j.PrevHash)
		if !ok {
			return errors.New("agent: interrupted swap and no matching backup")
		}
		if err := credfile.Restore(path, backup); err != nil {
			return fmt.Errorf("agent: restore: %w", err)
		}
		a.log.Warn("interrupted swap rolled back", "action", "recover", "result", "restored")
	default:
		a.log.Warn("credentials changed since swap began; left as found", "action", "recover", "result", "left-alone")
	}
	return clearJournal(a.cfg.StateDir)
}

// readIdentity returns the signed-in account's email, else its account uuid, else "".
// The value may be an email address: callers must not log it. Why it is empty is identity.go's
// job (identityProbe.run); this is the plain read a finished sign-in needs.
func readIdentity(path string) string {
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return ""
	}
	id, _ := parseIdentity(data)
	return id
}
