// Package hub owns the agent connections: enrolment, heartbeat, host state and swap orchestration.
package hub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/coder/websocket"

	"claude-utilities/internal/logx"
	"claude-utilities/internal/ownership"
	"claude-utilities/internal/proto"
	"claude-utilities/internal/vault"
)

func init() {
	// Audit and operational fields; none carries a secret, an email or a payload.
	// namedCount and remoteCount are counts of sessions, never a session's name or cwd:
	// those may carry a person's name or a path and are never logged. (sessionCount is
	// allowlisted by logx itself.)
	// "holder" is the host id of the host that blocked a swap.
	logx.Allow("host_name", "os", "source_ip", "fingerprint", "namedCount", "remoteCount", "holder")
}

const (
	// HeartbeatInterval is how often an agent is expected to send a frame.
	HeartbeatInterval = 15 * time.Second
	// OfflineAfter is the silence after which a host counts as offline.
	OfflineAfter = 45 * time.Second
	// EnrolCodeTTL is the lifetime of a pre-approved enrolment code.
	EnrolCodeTTL = 10 * time.Minute

	helloTimeout  = 10 * time.Second
	writeTimeout  = 10 * time.Second
	requestTimout = 30 * time.Second
	maxFieldLen   = 64
	// helloMaxSize bounds the first frame of an unauthenticated connection.
	helloMaxSize = 16 << 10
)

var (
	ErrAgentOffline       = errors.New("hub: agent offline")
	ErrUnknownLiveAccount = errors.New("hub: the host's live login matches no stored account; import it first")
	ErrBadCode            = errors.New("hub: bad or expired enrolment code")
	ErrRevoked            = errors.New("hub: agent token revoked")
	ErrBadToken           = errors.New("hub: unknown agent token")
	ErrUnknownHost        = errors.New("hub: unknown host")
	ErrUnknownAccount     = errors.New("hub: unknown account")
	ErrAlreadyStored      = errors.New("hub: the host's live login is already stored as an account")
	// ErrSwapOutcomeUnknown means the swap request went out but no verdict came back, so the host
	// may or may not have applied it. Ownership is left unchanged and the host's identity is
	// cleared until its next report.
	ErrSwapOutcomeUnknown = errors.New("hub: swap outcome unknown")
	// ErrHeldElsewhere means the target account's refresh token is live on another online host, so
	// swapping it in would put one refresh token on two holders and the first refresh would
	// invalidate the other. It is always a *HeldError.
	ErrHeldElsewhere = errors.New("hub: account held by another host")
	// ErrSignInAgain means the account's stored login was rejected (usage state "unauthorized"), so
	// swapping it onto a host would only sign that host out.
	ErrSignInAgain = errors.New("sign in again first: the stored login for this account was rejected")
)

// HeldError is ErrHeldElsewhere with the holder's name. Host is agent-supplied text; the message
// redacts it and the log never carries it (only the host id).
type HeldError struct{ Host string }

func (e *HeldError) Error() string {
	return "Held by " + logx.Redact(e.Host) + ": swap that host to another account first, or sign in again"
}
func (e *HeldError) Is(target error) bool { return target == ErrHeldElsewhere }

// Swap warning codes. A warning never blocks a swap; the UI shows it beside the result.
const (
	// WarnStaleCopy: the stored login is older than StaleAfter, so its access token has probably
	// expired. The refresh token may still be good, which is why this only warns.
	WarnStaleCopy = "stale_copy"
	// WarnHolderOffline: an offline host last held this account's lineage and may still hold it.
	WarnHolderOffline = "holder_offline"
)

// DefaultStaleAfter is how old a stored login may be before it is flagged. Access tokens last
// about eight hours, so six leaves margin.
const DefaultStaleAfter = 6 * time.Hour

// SwapWarning is one non-blocking caution on a successful swap.
type SwapWarning struct {
	Code string
	// Host names the offline holder for WarnHolderOffline.
	Host string
	// AgeHours is the stored login's age in whole hours for WarnStaleCopy.
	AgeHours int
}

// SwapResult is what a swap reports: the outcome, the cautions, and the agent's home code.
type SwapResult struct {
	Outcome  SwapOutcome
	Warnings []SwapWarning
	// Home is the proto.Home* code the agent reported; empty from an older agent.
	Home string
}

type connState int

const (
	stateNew connState = iota
	statePending
	stateEnrolled
	stateClosed
)

// conn is one agent websocket. state, fp and hostID are guarded by Hub.mu.
type conn struct {
	ws     *websocket.Conn
	ip     string
	hello  proto.Hello
	fp     string
	hostID string
	state  connState

	wmu  sync.Mutex // serialises writes
	done chan struct{}

	closeOnce sync.Once

	wtMu    sync.Mutex
	waiters map[string]chan proto.Envelope
}

func newConn(ws *websocket.Conn, ip string) *conn {
	return &conn{ws: ws, ip: ip, done: make(chan struct{}), waiters: map[string]chan proto.Envelope{}}
}

func (c *conn) writeLocked(typ, id string, body any) error {
	b, err := proto.Encode(typ, id, body)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	return c.ws.Write(ctx, websocket.MessageText, b)
}

func (c *conn) send(typ, id string, body any) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.writeLocked(typ, id, body)
}

// close starts the close handshake without blocking the caller (safe under Hub.mu).
func (c *conn) close(code websocket.StatusCode, reason string) {
	c.closeOnce.Do(func() {
		go func() { _ = c.ws.Close(code, reason) }()
	})
}

func (c *conn) addWaiter(id string, ch chan proto.Envelope) {
	c.wtMu.Lock()
	c.waiters[id] = ch
	c.wtMu.Unlock()
}

func (c *conn) delWaiter(id string) {
	c.wtMu.Lock()
	delete(c.waiters, id)
	c.wtMu.Unlock()
}

func (c *conn) deliver(env proto.Envelope) {
	c.wtMu.Lock()
	ch := c.waiters[env.ID]
	c.wtMu.Unlock()
	if ch != nil {
		select {
		case ch <- env:
		default:
		}
	}
}

// host is a persisted enrolment plus its live connection state.
type host struct {
	hostRec
	swapMu   sync.Mutex
	c        *conn
	lastSeen time.Time
	report   proto.Report
	// reloadIDs holds the sessions that were running when a swap happened; they still hold the old
	// login. Keyed by session, not by time, so cross-host clock skew cannot matter. In memory only.
	reloadIDs map[string]struct{}
	identity  string // last known live identity (from a report or a successful swap)
	// runAs is the local account the agent process runs as, from its last hello. Refreshed on
	// every hello, so a reconfigured host shows its new user without re-enrolling. In memory
	// only: after a server restart it is empty until the agent dials in again.
	runAs string
	// identReason is why the host names no identity: one of the known proto.Reason* codes, or ""
	// when the identity is known or the agent sent a code this hub does not know. In memory only.
	identReason string
	// A swap rewrites the login but never ~/.claude.json, so the agent keeps reporting the identity
	// it had before the swap. swapFrom is that stale identity, swapTarget the account swapped in and
	// swapIdent its identity; while reports still say swapFrom, the login is swapTarget's. In memory only.
	swapFrom, swapTarget, swapIdent string
	// tally is the last logged session census, so a report that changes nothing logs nothing:
	// reports arrive on every heartbeat. In memory only.
	tally sessionTally
	// lineage is the SHA-256 of the refresh token this host last held, as far as the hub knows: set
	// from an export and from a swap the host accepted, cleared when a swap's outcome is unknown.
	// It survives a disconnect, which is how an offline holder is still named. A hash, never the
	// token. In memory only: after a server restart nothing is known until the next export.
	lineage string
}

// lineageHash fingerprints a login block's refresh token; "" when it has none.
func lineageHash(block json.RawMessage) string {
	rt := refreshToken(block)
	if rt == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(rt))
	return hex.EncodeToString(sum[:])
}

// sessionTally counts a host's reported sessions. Counts only: a session's name and cwd may
// carry a person's name or a path, so neither is ever logged.
type sessionTally struct {
	total, named, remote int
	// set is false on a host that has not reported yet, so the first report always logs.
	set bool
}

func tallySessions(ss []proto.Session) sessionTally {
	t := sessionTally{set: true, total: len(ss)}
	for _, s := range ss {
		if s.Name != "" || s.RemoteName != "" {
			t.named++
		}
		if s.RemoteControl {
			t.remote++
		}
	}
	return t
}

// noteSwapLocked remembers that account (identity ident) was put on the host while the agent
// reported from. Callers hold h.mu.
func (ho *host) noteSwapLocked(from, account, ident string) {
	ho.swapFrom, ho.swapTarget, ho.swapIdent = from, account, ident
}

func (ho *host) forgetSwapLocked() { ho.swapFrom, ho.swapTarget, ho.swapIdent = "", "", "" }

func sessionKey(s proto.Session) string { return fmt.Sprintf("%d:%s", s.PID, s.ID) }

// markReloadLocked flags every currently reported session as needing a reload. Callers hold h.mu.
func (ho *host) markReloadLocked() {
	if ho.reloadIDs == nil {
		ho.reloadIDs = map[string]struct{}{}
	}
	for _, s := range ho.report.Sessions {
		ho.reloadIDs[sessionKey(s)] = struct{}{}
	}
}

// Hub tracks agents. The zero value is not usable; call New.
type Hub struct {
	vault      *vault.Vault
	reg        *ownership.Registry
	tokensPath string
	log        *slog.Logger

	now        func() time.Time
	reqTimeout time.Duration
	ipOf       func(*http.Request) string
	// onReject is a test hook that observes why a hello was refused.
	onReject func(error)
	// onSwap is told when an account lands on a host (SetOnSwap).
	onSwap func(accountID string)
	// onReplaced is told when an account's stored login was replaced (SetOnReplaced).
	onReplaced func(accountID string)
	// unauthorized says an account's stored login was rejected (SetUnauthorized); nil means never.
	unauthorized func(accountID string) bool
	// staleAfter is the age past which a stored login is flagged (SetStaleAfter).
	staleAfter time.Duration

	mu         sync.Mutex
	hosts      map[string]*host
	byHash     map[string]string // token hash -> host id
	codes      map[string]time.Time
	pending    map[string]*pendEntry
	suppressed map[string]time.Time
	expired    map[string]time.Time
	ipHits     map[string][]time.Time
	badHits    map[string][]time.Time // failed token or code hellos per source IP
	adds       map[string]*addJob     // add-account jobs by id (addaccount.go)
	// Session control (control.go): requests by id, every target by its own id, each session's
	// recent targets, and the idempotency keys already spent.
	cmds         map[string]*cmdBatch
	cmdByID      map[string]*cmdTarget
	cmdBySession map[string][]*cmdTarget
	cmdReqIDs    map[string]string
}

// New returns a Hub that keeps enrolled hosts (token hashes only) in tokensPath.
func New(v *vault.Vault, r *ownership.Registry, tokensPath string, log *slog.Logger) *Hub {
	h := &Hub{
		vault: v, reg: r, tokensPath: tokensPath, log: log.With("component", "hub"),
		now: time.Now, reqTimeout: requestTimout, staleAfter: DefaultStaleAfter,
		ipOf: func(r *http.Request) string {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				return r.RemoteAddr
			}
			return host
		},
		hosts: map[string]*host{}, byHash: map[string]string{}, codes: map[string]time.Time{},
		pending: map[string]*pendEntry{}, suppressed: map[string]time.Time{},
		expired: map[string]time.Time{}, ipHits: map[string][]time.Time{},
		badHits: map[string][]time.Time{}, adds: map[string]*addJob{},
		cmds: map[string]*cmdBatch{}, cmdByID: map[string]*cmdTarget{},
		cmdBySession: map[string][]*cmdTarget{}, cmdReqIDs: map[string]string{},
	}
	if err := h.load(); err != nil {
		h.log.Error("load enrolled hosts failed", logx.Err(err))
	}
	return h
}

// SetOnSwap registers a callback told, after ownership changes, which account just landed on a host.
// The usage poller uses it to give that account one prompt poll. Call before serving.
func (h *Hub) SetOnSwap(fn func(accountID string)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.onSwap = fn
}

// SetOnReplaced registers a callback told which account just had its stored login replaced ("sign in
// again"). The usage poller uses it to reset that account's backoff. Call before serving.
func (h *Hub) SetOnReplaced(fn func(accountID string)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.onReplaced = fn
}

func (h *Hub) noteSwap(accountID string) {
	h.mu.Lock()
	fn := h.onSwap
	h.mu.Unlock()
	if fn != nil {
		fn(accountID)
	}
}

// Run sweeps expired state until ctx ends. The server MUST start it (go hub.Run(ctx)): heartbeat
// timeouts, pending and code expiry otherwise happen only when something polls Hosts or Pending.
//
// Authorisation: the exported control methods (Allow, Deny, Revoke, NewEnrolCode, Swap, Pending,
// Hosts) perform no caller authentication. Every HTTP route that reaches them must authenticate the
// owner first. ServeWS is unauthenticated by design; the hello gate is its only control. The UI must
// HTML-escape HostName, OS, RunAs and SourceIP, which are agent-controlled.
func (h *Hub) Run(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.mu.Lock()
			h.sweepLocked(h.now())
			h.sweepAddsLocked(h.now())
			h.sweepCommandsLocked(h.now())
			h.mu.Unlock()
		}
	}
}

func clip(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
	if rs := []rune(s); len(rs) > maxFieldLen {
		s = string(rs[:maxFieldLen])
	}
	return s
}

func sanitizeHello(hl proto.Hello) proto.Hello {
	hl.HostName, hl.OS, hl.Nonce = clip(hl.HostName), clip(hl.OS), clip(hl.Nonce)
	hl.RunAs = clip(hl.RunAs)
	if len(hl.Token) > 256 {
		hl.Token = hl.Token[:256]
	}
	if len(hl.Code) > 256 {
		hl.Code = hl.Code[:256]
	}
	return hl
}

// ServeWS upgrades the request and runs the connection until it ends.
func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	ws.SetReadLimit(helloMaxSize) // raised after the hello is admitted
	c := newConn(ws, h.ipOf(r))
	defer close(c.done)
	defer h.dropConn(c)
	ctx := r.Context()

	hctx, cancel := context.WithTimeout(ctx, helloTimeout)
	_, data, err := ws.Read(hctx)
	cancel()
	if err != nil {
		_ = ws.Close(websocket.StatusPolicyViolation, "no hello")
		return
	}
	env, err := proto.Decode(data)
	if err != nil || env.Type != proto.TypeHello {
		_ = ws.Close(websocket.StatusPolicyViolation, "expected hello")
		return
	}
	var hello proto.Hello
	if err := json.Unmarshal(env.Body, &hello); err != nil {
		_ = ws.Close(websocket.StatusPolicyViolation, "bad hello")
		return
	}
	// The agent fingerprints its own raw hello, so compute ours before sanitising for display.
	c.fp = proto.Fingerprint(hello)
	hello = sanitizeHello(hello)
	c.hello = hello

	switch {
	case hello.Token != "":
		err = h.admitToken(c)
	case hello.Code != "":
		err = h.admitCode(c)
	default:
		err = h.admitPending(c)
	}
	if err != nil {
		h.reject(c, err)
		return
	}
	h.mu.Lock()
	pending := c.state == statePending
	h.mu.Unlock()
	if !pending { // a pending socket keeps the hello limit until Allow promotes it
		ws.SetReadLimit(proto.MaxMessageSize)
	}
	h.readLoop(ctx, c)
}

func closeReason(err error) string {
	switch {
	case errors.Is(err, ErrBadToken):
		return "bad token"
	case errors.Is(err, ErrRevoked):
		return "revoked"
	case errors.Is(err, ErrBadCode):
		return "bad code"
	case errors.Is(err, ErrRateLimited):
		return "rate limited"
	case errors.Is(err, ErrPendingFull):
		return "queue full"
	case errors.Is(err, ErrEmptyNonce):
		return "nonce required"
	case errors.Is(err, ErrFingerprintInUse):
		return "fingerprint in use"
	case errors.Is(err, ErrSuppressed):
		return "suppressed"
	}
	return "rejected"
}

func (h *Hub) reject(c *conn, err error) {
	if h.onReject != nil {
		h.onReject(err)
	}
	reason := closeReason(err)
	if errors.Is(err, ErrBadToken) || errors.Is(err, ErrBadCode) {
		h.mu.Lock()
		h.badHits[c.ip] = append(h.badHits[c.ip], h.now())
		h.mu.Unlock()
	}
	if errors.Is(err, ErrRateLimited) {
		// A flooding address must not also flood the log.
		h.log.Debug("hello rejected", "action", "reject", "result", reason, "source_ip", c.ip)
	} else {
		h.log.Warn("hello rejected", "action", "reject", "result", reason,
			"host_name", c.hello.HostName, "os", c.hello.OS, "source_ip", c.ip)
	}
	_ = c.ws.Close(websocket.StatusPolicyViolation, reason)
}

// readLoop serves an admitted connection. A pending connection may send nothing after its hello.
func (h *Hub) readLoop(ctx context.Context, c *conn) {
	for {
		_, data, err := c.ws.Read(ctx)
		if err != nil {
			return
		}
		h.mu.Lock()
		st := c.state
		h.mu.Unlock()
		if st != stateEnrolled {
			h.dropPending(c)
			return
		}
		env, err := proto.Decode(data)
		if err != nil {
			h.log.Warn("bad frame", "result", "closed", "host_id", c.hostID, logx.Err(err))
			c.close(websocket.StatusProtocolError, "bad frame")
			return
		}
		if !h.dispatch(c, env) {
			c.close(websocket.StatusPolicyViolation, "unexpected message")
			return
		}
	}
}

// dispatch handles one enrolled-agent frame; false means a protocol violation.
func (h *Hub) dispatch(c *conn, env proto.Envelope) bool {
	switch env.Type {
	case proto.TypeHeartbeat:
		h.touch(c, nil)
	case proto.TypeReport:
		var rep proto.Report
		if err := json.Unmarshal(env.Body, &rep); err != nil {
			return false
		}
		h.touch(c, &rep)
	case proto.TypeExportRes, proto.TypeSwapRes, proto.TypeCommandRes:
		if env.ID == "" {
			return false
		}
		h.touch(c, nil)
		c.deliver(env)
	case proto.TypeLoginURL, proto.TypeLoginDone:
		// Unsolicited and long-lived: routed to the add-account job, not to a request waiter.
		if env.ID == "" {
			return false
		}
		h.touch(c, nil)
		h.addFrame(c, env)
	default:
		return false
	}
	return true
}

func (h *Hub) touch(c *conn, rep *proto.Report) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ho := h.hosts[c.hostID]
	if ho == nil || ho.c != c {
		return
	}
	ho.lastSeen = h.now()
	if rep == nil {
		return
	}
	ho.report = *rep
	ho.identity = rep.ActiveIdentity
	if ho.swapTarget != "" {
		if rep.ActiveIdentity == ho.swapFrom {
			ho.identity = ho.swapIdent // stale: the swap did not rewrite ~/.claude.json
		} else {
			ho.forgetSwapLocked() // the identity changed since (a manual login): trust it again
		}
	}
	// Why the host names no account. The code is agent-supplied, so only a code this hub knows is
	// kept: that is what stops a host putting text of its own in front of an operator. A reason
	// beside a known identity is noise, so it is dropped (a swap synthesises one above).
	reason := ""
	if ho.identity == "" && proto.KnownIdentityReason(rep.IdentityReason) {
		reason = rep.IdentityReason
	}
	if reason != ho.identReason { // reports arrive every heartbeat: log the change, not the state
		ho.identReason = reason
		if reason != "" {
			h.log.Warn("host has no signed-in account", "host_id", ho.ID, "action", "report",
				"result", "no_identity", "reason", reason)
		} else {
			h.log.Info("host names a signed-in account again", "host_id", ho.ID, "action", "report", "result", "identity")
		}
	}
	// Reports arrive on every heartbeat, so the census is logged only when it changes.
	if t := tallySessions(rep.Sessions); t != ho.tally {
		ho.tally = t
		h.log.Info("host sessions changed", "host_id", ho.ID, "action", "report",
			"sessionCount", t.total, "namedCount", t.named, "remoteCount", t.remote)
	}
	h.applyCommandStatusesLocked(ho.ID, rep.Commands)
	live := map[string]struct{}{}
	for _, s := range rep.Sessions {
		live[sessionKey(s)] = struct{}{}
	}
	for k := range ho.reloadIDs { // forget sessions that ended
		if _, ok := live[k]; !ok {
			delete(ho.reloadIDs, k)
		}
	}
}

// sameLineage reports whether two login blocks carry the same non-empty refresh token, i.e. the
// exported login is demonstrably the stored account's. Identity in a report is only a claim.
func sameLineage(a, b json.RawMessage) bool {
	x := refreshToken(a)
	return x != "" && x == refreshToken(b)
}

func refreshToken(raw json.RawMessage) string {
	var v struct {
		RefreshToken string `json:"refreshToken"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return ""
	}
	return v.RefreshToken
}

// lineageConflict reports whether both blocks carry a refresh token and the tokens differ, i.e. the
// two logins are demonstrably different. A block with no refresh token proves nothing either way.
func lineageConflict(a, b json.RawMessage) bool {
	x, y := refreshToken(a), refreshToken(b)
	return x != "" && y != "" && x != y
}

type liveHow int

const (
	liveByLineage  liveHow = iota // the exported login's refresh token matches a stored login
	liveBySwap                    // the hub swapped that account in and the agent's identity is still the old one
	liveByIdentity                // only the agent-reported identity names it
)

// liveAccount decides which vault account the host is logged in as. The login (refresh-token
// lineage) outranks the agent's identity, because a swap never rewrites ~/.claude.json and the
// identity it reports goes stale. Next comes the hub's own record of its last swap, then the bare
// identity. It returns nil when none applies.
func (h *Hub) liveAccount(ho *host, identity string, block json.RawMessage) (*vault.Account, liveHow) {
	accts := h.vault.List()
	var byLineage *vault.Account
	for i := range accts {
		if !sameLineage(block, accts[i].Block) {
			continue
		}
		if byLineage == nil || (identity != "" && accts[i].Identity == identity) {
			byLineage = &accts[i]
		}
	}
	if byLineage != nil {
		return byLineage, liveByLineage
	}
	h.mu.Lock()
	from, target := ho.swapFrom, ho.swapTarget
	h.mu.Unlock()
	if target != "" && identity == from {
		if a, ok := h.vault.Get(target); ok {
			return &a, liveBySwap
		}
	}
	if identity == "" {
		return nil, liveByIdentity
	}
	for i := range accts {
		if accts[i].Identity == identity {
			return &accts[i], liveByIdentity
		}
	}
	return nil, liveByIdentity
}

// dropConn runs when a connection's handler exits.
func (h *Hub) dropConn(c *conn) {
	h.mu.Lock()
	switch c.state {
	case statePending:
		if e := h.pending[c.fp]; e != nil && e.c == c {
			delete(h.pending, c.fp)
		}
	case stateEnrolled:
		h.failAddsOnDropLocked(c)
		if ho := h.hosts[c.hostID]; ho != nil && ho.c == c {
			ho.c = nil
			ho.report = proto.Report{}
			h.reg.HostLost(ho.ID)
			h.log.Info("agent disconnected", "host_id", ho.ID, "result", "offline")
		}
	}
	c.state = stateClosed
	h.mu.Unlock()
}

// SessionView is a running Claude session plus whether a swap since its start needs a reload and
// the session-control commands recently aimed at it (control.go), oldest first.
type SessionView struct {
	proto.Session
	NeedsReload bool
	Commands    []CommandTargetView
}

// HostView is the UI-safe view of an enrolled host.
type HostView struct {
	HostID, Name, OS string
	// RunAs is the local account the agent runs as, from its last hello. Empty for a host that
	// has not dialled in since the server started, or an agent too old to send it.
	// Agent-controlled text: the UI must escape it.
	RunAs         string
	Online        bool
	ActiveAccount string
	// IdentityReason is why the host names no signed-in account: one of the known proto.Reason*
	// codes, or "" when it does name one. The UI turns the code into a sentence and a fix.
	IdentityReason string
	// SwapBlocked mirrors the agent's report: an unfinished earlier swap blocks every new one.
	SwapBlocked bool
	Sessions    []SessionView
}

// Hosts lists enrolled, unrevoked hosts ordered by name.
func (h *Hub) Hosts() []HostView {
	accts := h.vault.List()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweepLocked(h.now())
	h.sweepCommandsLocked(h.now())
	out := make([]HostView, 0, len(h.hosts))
	for _, ho := range h.hosts {
		if ho.Revoked {
			continue
		}
		v := HostView{HostID: ho.ID, Name: ho.Name, OS: ho.OS, RunAs: ho.runAs, Online: ho.c != nil,
			IdentityReason: ho.identReason, SwapBlocked: ho.report.SwapBlocked, Sessions: []SessionView{}}
		for _, a := range accts {
			if ho.identity != "" && a.Identity == ho.identity {
				v.ActiveAccount = a.ID
				break
			}
		}
		for _, s := range ho.report.Sessions {
			_, stale := ho.reloadIDs[sessionKey(s)]
			v.Sessions = append(v.Sessions, SessionView{Session: s, NeedsReload: stale,
				Commands: h.sessionCommandsLocked(ho.ID, s)})
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].HostID < out[j].HostID
	})
	return out
}

func (h *Hub) request(ctx context.Context, c *conn, typ, want string, body any) (json.RawMessage, error) {
	id, err := randHex(8)
	if err != nil {
		return nil, err
	}
	ch := make(chan proto.Envelope, 1)
	c.addWaiter(id, ch)
	defer c.delWaiter(id)
	tctx, cancel := context.WithTimeout(ctx, h.reqTimeout)
	defer cancel()
	if err := c.send(typ, id, body); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAgentOffline, logx.Redact(err.Error()))
	}
	select {
	case env := <-ch:
		if env.Type != want {
			return nil, unexpectedReply(env.Type, typ)
		}
		return env.Body, nil
	case <-c.done:
		return nil, ErrAgentOffline
	case <-tctx.Done():
		return nil, fmt.Errorf("hub: %s timed out: %w", typ, tctx.Err())
	}
}

// ErrUnexpectedReply means the agent answered a request with the wrong message type.
var ErrUnexpectedReply = errors.New("hub: unexpected reply from the agent")

const maxTypeLog = 32

// unexpectedReply builds the error for a wrong reply type. The type is agent-supplied, so it is
// redacted and capped before it can reach an error string or a log line.
func unexpectedReply(got, sent string) error {
	g := logx.Redact(got)
	if len(g) > maxTypeLog {
		g = g[:maxTypeLog] + "..."
	}
	return fmt.Errorf("%w: got %q for %s", ErrUnexpectedReply, g, sent)
}

// oauthBlock validates an agent-supplied login block and returns only the claudeAiOauth object.
// A whole credentials file is narrowed to that block; anything carrying mcpOAuth without it is
// refused so MCP credentials never reach the vault or another host.
func oauthBlock(raw json.RawMessage) (json.RawMessage, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil || len(top) == 0 {
		return nil, errors.New("hub: exported login block is not a JSON object")
	}
	if inner, ok := top["claudeAiOauth"]; ok {
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(inner, &probe); err != nil || len(probe) == 0 {
			return nil, errors.New("hub: exported claudeAiOauth is not a JSON object")
		}
		return inner, nil
	}
	if _, ok := top["mcpOAuth"]; ok {
		return nil, errors.New("hub: exported login block carries mcpOAuth and no claudeAiOauth")
	}
	return raw, nil
}

// SwapOutcome says which of Swap's two successes happened. A swap that changes nothing is not an
// error, but it is not a swap either, and the admin UI has to tell the operator which it was.
type SwapOutcome string

const (
	// SwapDone means the target login was written to the host.
	SwapDone SwapOutcome = "swapped"
	// SwapAlreadyActive means the host already held the target account, so nothing was written.
	SwapAlreadyActive SwapOutcome = "already-active"
)

// Swap makes hostID use accountID. Order: offline check, export the live block, match it to a
// vault account (else ErrUnknownLiveAccount, nothing sent), write it back to the vault, then
// send the target block. Ownership changes only after the agent reports success. On any error the
// outcome is empty: a caller must never read one off a failure.
func (h *Hub) Swap(ctx context.Context, hostID, accountID string) (SwapOutcome, error) {
	var out SwapResult
	return h.swap(ctx, hostID, accountID, &out)
}

// SwapEx is Swap plus the cautions and the agent's home code. On an error the result is empty.
func (h *Hub) SwapEx(ctx context.Context, hostID, accountID string) (SwapResult, error) {
	var out SwapResult
	o, err := h.swap(ctx, hostID, accountID, &out)
	if err != nil {
		return SwapResult{}, err
	}
	out.Outcome = o
	return out, nil
}

// SetUnauthorized installs the check for an account whose stored login the usage endpoint
// rejected. Swapping onto such an account is refused with ErrSignInAgain.
func (h *Hub) SetUnauthorized(fn func(accountID string) bool) {
	h.mu.Lock()
	h.unauthorized = fn
	h.mu.Unlock()
}

// SetStaleAfter sets the age past which a stored login is flagged; d <= 0 restores the default.
func (h *Hub) SetStaleAfter(d time.Duration) {
	if d <= 0 {
		d = DefaultStaleAfter
	}
	h.mu.Lock()
	h.staleAfter = d
	h.mu.Unlock()
}

// StaleAfter is the age past which a stored login is flagged.
func (h *Hub) StaleAfter() time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.staleAfter
}

// holdersLocked names the other hosts that may hold target's refresh-token lineage: those whose
// last known lineage is the target's, and those with no known lineage that ownership still lists as
// the target's Active holder. A host the hub swapped to another account is neither, even though
// ownership keeps listing it (see the comment above SwapIn in Swap). Callers hold h.mu.
func (h *Hub) holdersLocked(self string, target vault.Account) (online, offline []*host) {
	tl := lineageHash(target.Block)
	using := h.reg.HostsUsing(target.ID)
	for _, ho := range h.hosts {
		if ho.ID == self || ho.Revoked {
			continue
		}
		held := tl != "" && ho.lineage == tl
		if st, listed := using[ho.ID]; ho.lineage == "" && listed && st == ownership.Active {
			held = true
		}
		switch {
		case !held:
		case ho.c != nil:
			online = append(online, ho)
		default:
			offline = append(offline, ho)
		}
	}
	byName := func(s []*host) {
		sort.Slice(s, func(i, j int) bool { return s[i].Name < s[j].Name || (s[i].Name == s[j].Name && s[i].ID < s[j].ID) })
	}
	byName(online)
	byName(offline)
	return online, offline
}

func (h *Hub) swap(ctx context.Context, hostID, accountID string, out *SwapResult) (SwapOutcome, error) {
	h.mu.Lock()
	h.sweepLocked(h.now())
	ho := h.hosts[hostID]
	known := ho != nil && !ho.Revoked
	h.mu.Unlock()
	if !known {
		return "", ErrUnknownHost
	}
	ho.swapMu.Lock()
	defer ho.swapMu.Unlock()

	h.mu.Lock()
	c := ho.c
	h.mu.Unlock()
	if c == nil {
		return "", ErrAgentOffline
	}
	target, ok := h.vault.Get(accountID)
	if !ok {
		return "", ErrUnknownAccount
	}
	if len(target.Block) == 0 {
		return "", fmt.Errorf("%w: account has no stored login", ErrUnknownAccount)
	}

	raw, err := h.request(ctx, c, proto.TypeExportReq, proto.TypeExportRes, nil)
	if err != nil {
		return "", err
	}
	var exp proto.ExportRes
	if err := json.Unmarshal(raw, &exp); err != nil {
		return "", fmt.Errorf("hub: bad export reply: %w", err)
	}
	if exp.Err != "" {
		return "", fmt.Errorf("hub: export failed: %s", logx.Redact(exp.Err))
	}
	block, err := oauthBlock(exp.Block)
	if err != nil {
		return "", err
	}
	h.mu.Lock()
	if l := lineageHash(block); l != "" {
		ho.lineage = l
	}
	h.mu.Unlock()
	live, how := h.liveAccount(ho, exp.Identity, block)
	if live == nil {
		h.log.Warn("swap refused", "action", "swap", "host_id", hostID, "result", "unknown live account")
		return "", ErrUnknownLiveAccount
	}
	if live.ID == target.ID {
		// Already active: nothing is written to the vault, not even a fresher block.
		if _, holds := h.reg.HostsUsing(live.ID)[hostID]; !holds && h.reg.OwnerOf(live.ID).Server && sameLineage(block, live.Block) {
			h.reg.SwapIn(live.ID, hostID) // exported login matches the stored one: record the holder
		}
		h.mu.Lock()
		ho.identity = target.Identity
		ho.noteSwapLocked(exp.Identity, target.ID, target.Identity)
		h.mu.Unlock()
		h.log.Info("swap no-op", "action", "swap", "host_id", hostID, "account", accountID, "result", "already active")
		return SwapAlreadyActive, nil
	}

	// Guards, in order of how certain the refusal is. A rejected stored login would only sign the
	// host out. A refresh token live on another online host would end up on two holders, and the
	// first refresh invalidates the other. Neither check logs a token, an identity or a host name.
	h.mu.Lock()
	unauth, staleAfter := h.unauthorized, h.staleAfter
	h.mu.Unlock()
	if unauth != nil && unauth(target.ID) {
		h.log.Warn("swap refused", "action", "swap", "host_id", hostID, "account", accountID, "result", "refused", "reason", "unauthorized")
		return "", ErrSignInAgain
	}
	h.mu.Lock()
	online, offline := h.holdersLocked(hostID, target)
	h.mu.Unlock()
	if len(online) > 0 {
		h.log.Warn("swap refused", "action", "swap", "host_id", hostID, "account", accountID, "result", "refused",
			"reason", "held_elsewhere", "holder", online[0].ID)
		return "", &HeldError{Host: online[0].Name}
	}
	for _, ho2 := range offline[:min(len(offline), 1)] {
		out.Warnings = append(out.Warnings, SwapWarning{Code: WarnHolderOffline, Host: ho2.Name})
	}
	if !target.Updated.IsZero() {
		if age := h.now().Sub(target.Updated); age > staleAfter {
			out.Warnings = append(out.Warnings, SwapWarning{Code: WarnStaleCopy, AgeHours: int(age / time.Hour)})
		}
	}

	// Write back only what this host may speak for: the Active holder. A Shared or Stale holder
	// has a possibly rotated-out copy, and a host that merely claims an account (identity is
	// agent-supplied, the block carries none) must not overwrite it, even when the server owns it.
	// A slot is never overwritten with a login of a different lineage; that is how a stale identity
	// used to put one account's tokens into another's slot.
	state, holds := h.reg.HostsUsing(live.ID)[hostID]
	switch {
	case !holds || state != ownership.Active:
		h.log.Warn("writeback skipped", "action", "swap", "host_id", hostID, "account", live.ID,
			"result", "host does not own the live login")
	case how == liveByIdentity && lineageConflict(block, live.Block):
		h.log.Warn("writeback skipped", "action", "swap", "host_id", hostID, "account", live.ID,
			"result", "live login has a different lineage than the stored one")
	default:
		live.Block = block
		live.Updated = h.now()
		if err := h.vault.Put(*live); err != nil {
			return "", fmt.Errorf("hub: write back live login: %w", err)
		}
	}

	raw, err = h.request(ctx, c, proto.TypeSwapReq, proto.TypeSwapRes, proto.SwapReq{Block: target.Block, Account: accountID})
	if err != nil {
		// The request may have been applied: say so, flag the sessions and forget the identity.
		h.mu.Lock()
		ho.markReloadLocked()
		ho.identity = ""
		ho.lineage = "" // the host may hold either login now
		ho.forgetSwapLocked()
		h.mu.Unlock()
		h.log.Warn("swap outcome unknown", "action", "swap", "host_id", hostID, "account", accountID,
			"result", "unknown", logx.Err(err))
		return "", fmt.Errorf("%w: %w", ErrSwapOutcomeUnknown, err)
	}
	var res proto.SwapRes
	if err := json.Unmarshal(raw, &res); err != nil {
		return "", fmt.Errorf("hub: bad swap reply: %w", err)
	}
	if !res.OK {
		h.log.Warn("swap failed", "action", "swap", "host_id", hostID, "account", accountID, "result", "agent refused", "reason", res.Reason)
		return "", fmt.Errorf("hub: agent refused swap: %s", logx.Redact(res.Reason))
	}
	// No SwapAway on the old account: it would promote the previous holder to Active with a
	// possibly rotated-out copy. The vault already holds this host's fresh block, so the host stays
	// the recorded owner until another host swaps in or the host is lost.
	h.reg.SwapIn(accountID, hostID)
	h.noteSwap(accountID)
	out.Home = res.Home
	h.mu.Lock()
	ho.markReloadLocked()
	ho.lineage = lineageHash(target.Block)
	ho.identity = target.Identity
	ho.noteSwapLocked(exp.Identity, target.ID, target.Identity)
	h.mu.Unlock()
	h.log.Info("swap done", "action", "swap", "host_id", hostID, "account", accountID, "result", "ok")
	return SwapDone, nil
}
