// Package hub owns the agent connections: enrolment, heartbeat, host state and swap orchestration.
package hub

import (
	"context"
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
	logx.Allow("host_name", "os", "source_ip", "fingerprint")
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
)

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
	// A swap rewrites the login but never ~/.claude.json, so the agent keeps reporting the identity
	// it had before the swap. swapFrom is that stale identity, swapTarget the account swapped in and
	// swapIdent its identity; while reports still say swapFrom, the login is swapTarget's. In memory only.
	swapFrom, swapTarget, swapIdent string
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
}

// New returns a Hub that keeps enrolled hosts (token hashes only) in tokensPath.
func New(v *vault.Vault, r *ownership.Registry, tokensPath string, log *slog.Logger) *Hub {
	h := &Hub{
		vault: v, reg: r, tokensPath: tokensPath, log: log.With("component", "hub"),
		now: time.Now, reqTimeout: requestTimout,
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
	}
	if err := h.load(); err != nil {
		h.log.Error("load enrolled hosts failed", logx.Err(err))
	}
	return h
}

// Run sweeps expired state until ctx ends. The server MUST start it (go hub.Run(ctx)): heartbeat
// timeouts, pending and code expiry otherwise happen only when something polls Hosts or Pending.
//
// Authorisation: the exported control methods (Allow, Deny, Revoke, NewEnrolCode, Swap, Pending,
// Hosts) perform no caller authentication. Every HTTP route that reaches them must authenticate the
// owner first. ServeWS is unauthenticated by design; the hello gate is its only control. The UI must
// HTML-escape HostName, OS and SourceIP, which are agent-controlled.
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
	case proto.TypeExportRes, proto.TypeSwapRes:
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

// SessionView is a running Claude session plus whether a swap since its start needs a reload.
type SessionView struct {
	proto.Session
	NeedsReload bool
}

// HostView is the UI-safe view of an enrolled host.
type HostView struct {
	HostID, Name, OS string
	Online           bool
	ActiveAccount    string
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
	out := make([]HostView, 0, len(h.hosts))
	for _, ho := range h.hosts {
		if ho.Revoked {
			continue
		}
		v := HostView{HostID: ho.ID, Name: ho.Name, OS: ho.OS, Online: ho.c != nil, SwapBlocked: ho.report.SwapBlocked, Sessions: []SessionView{}}
		for _, a := range accts {
			if ho.identity != "" && a.Identity == ho.identity {
				v.ActiveAccount = a.ID
				break
			}
		}
		for _, s := range ho.report.Sessions {
			_, stale := ho.reloadIDs[sessionKey(s)]
			v.Sessions = append(v.Sessions, SessionView{Session: s, NeedsReload: stale})
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

// Swap makes hostID use accountID. Order: offline check, export the live block, match it to a
// vault account (else ErrUnknownLiveAccount, nothing sent), write it back to the vault, then
// send the target block. Ownership changes only after the agent reports success.
func (h *Hub) Swap(ctx context.Context, hostID, accountID string) error {
	h.mu.Lock()
	h.sweepLocked(h.now())
	ho := h.hosts[hostID]
	known := ho != nil && !ho.Revoked
	h.mu.Unlock()
	if !known {
		return ErrUnknownHost
	}
	ho.swapMu.Lock()
	defer ho.swapMu.Unlock()

	h.mu.Lock()
	c := ho.c
	h.mu.Unlock()
	if c == nil {
		return ErrAgentOffline
	}
	target, ok := h.vault.Get(accountID)
	if !ok {
		return ErrUnknownAccount
	}
	if len(target.Block) == 0 {
		return fmt.Errorf("%w: account has no stored login", ErrUnknownAccount)
	}

	raw, err := h.request(ctx, c, proto.TypeExportReq, proto.TypeExportRes, nil)
	if err != nil {
		return err
	}
	var exp proto.ExportRes
	if err := json.Unmarshal(raw, &exp); err != nil {
		return fmt.Errorf("hub: bad export reply: %w", err)
	}
	if exp.Err != "" {
		return fmt.Errorf("hub: export failed: %s", logx.Redact(exp.Err))
	}
	block, err := oauthBlock(exp.Block)
	if err != nil {
		return err
	}
	live, how := h.liveAccount(ho, exp.Identity, block)
	if live == nil {
		h.log.Warn("swap refused", "action", "swap", "host_id", hostID, "result", "unknown live account")
		return ErrUnknownLiveAccount
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
		return nil
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
			return fmt.Errorf("hub: write back live login: %w", err)
		}
	}

	raw, err = h.request(ctx, c, proto.TypeSwapReq, proto.TypeSwapRes, proto.SwapReq{Block: target.Block, Account: accountID})
	if err != nil {
		// The request may have been applied: say so, flag the sessions and forget the identity.
		h.mu.Lock()
		ho.markReloadLocked()
		ho.identity = ""
		ho.forgetSwapLocked()
		h.mu.Unlock()
		h.log.Warn("swap outcome unknown", "action", "swap", "host_id", hostID, "account", accountID,
			"result", "unknown", logx.Err(err))
		return fmt.Errorf("%w: %w", ErrSwapOutcomeUnknown, err)
	}
	var res proto.SwapRes
	if err := json.Unmarshal(raw, &res); err != nil {
		return fmt.Errorf("hub: bad swap reply: %w", err)
	}
	if !res.OK {
		h.log.Warn("swap failed", "action", "swap", "host_id", hostID, "account", accountID, "result", "agent refused", "reason", res.Reason)
		return fmt.Errorf("hub: agent refused swap: %s", logx.Redact(res.Reason))
	}
	// No SwapAway on the old account: it would promote the previous holder to Active with a
	// possibly rotated-out copy. The vault already holds this host's fresh block, so the host stays
	// the recorded owner until another host swaps in or the host is lost.
	h.reg.SwapIn(accountID, hostID)
	h.mu.Lock()
	ho.markReloadLocked()
	ho.identity = target.Identity
	ho.noteSwapLocked(exp.Identity, target.ID, target.Identity)
	h.mu.Unlock()
	h.log.Info("swap done", "action", "swap", "host_id", hostID, "account", accountID, "result", "ok")
	return nil
}
