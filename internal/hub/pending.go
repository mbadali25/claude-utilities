package hub

import (
	"errors"
	"sort"
	"time"

	"github.com/coder/websocket"

	"claude-utilities/internal/logx"
	"claude-utilities/internal/proto"
)

const (
	// PendingCap is the most unapproved connections held at once.
	PendingCap = 20
	// PendingTTL is how long an unapproved connection waits for the owner.
	PendingTTL = 10 * time.Minute
	// DenySuppress is how long a denied fingerprint is refused.
	DenySuppress = time.Hour
	// PendingPerIP is the most pending hellos one source IP may add per PendingPerIPWindow.
	PendingPerIP       = 3
	PendingPerIPWindow = 10 * time.Minute
	// BadHelloPerIP is the most failed token or code hellos one source IP may make per PendingPerIPWindow.
	BadHelloPerIP = 20
)

var (
	ErrNotPending     = errors.New("hub: no such pending connection")
	ErrPendingExpired = errors.New("hub: pending connection expired")
	ErrPendingFull    = errors.New("hub: pending queue full")
	ErrSuppressed     = errors.New("hub: fingerprint recently denied")
	ErrRateLimited    = errors.New("hub: too many pending hellos from this address")
	ErrEmptyNonce     = errors.New("hub: pending hello without a nonce")
	// ErrFingerprintInUse means another address already queued this fingerprint.
	ErrFingerprintInUse = errors.New("hub: fingerprint already pending from another address")
)

// PendingView is one unapproved connection as the owner sees it.
type PendingView struct {
	Fingerprint, HostName, OS, SourceIP string
	Since, ExpiresAt                    time.Time
}

type pendEntry struct {
	c              *conn
	hello          proto.Hello
	since, expires time.Time
}

// sweepLocked evicts expired state and silent hosts. Callers hold h.mu.
func (h *Hub) sweepLocked(now time.Time) {
	for fp, e := range h.pending {
		if !now.Before(e.expires) {
			delete(h.pending, fp)
			h.expired[fp] = now.Add(PendingTTL)
			e.c.state = stateClosed
			e.c.close(websocket.StatusPolicyViolation, "expired")
			h.log.Info("pending expired", "action", "expire", "fingerprint", fp, "host_name", e.hello.HostName,
				"os", e.hello.OS, "source_ip", e.c.ip, "result", "expired")
		}
	}
	for fp, until := range h.suppressed {
		if !now.Before(until) {
			delete(h.suppressed, fp)
		}
	}
	for fp, until := range h.expired {
		if !now.Before(until) {
			delete(h.expired, fp)
		}
	}
	for code, exp := range h.codes {
		if !now.Before(exp) {
			delete(h.codes, code)
		}
	}
	for ip, hits := range h.ipHits {
		if kept := pruneHits(hits, now); len(kept) == 0 {
			delete(h.ipHits, ip)
		} else {
			h.ipHits[ip] = kept
		}
	}
	for ip, hits := range h.badHits {
		if kept := pruneHits(hits, now); len(kept) == 0 {
			delete(h.badHits, ip)
		} else {
			h.badHits[ip] = kept
		}
	}
	for _, ho := range h.hosts {
		if ho.c != nil && now.Sub(ho.lastSeen) > OfflineAfter {
			c := ho.c
			ho.c = nil
			ho.report = proto.Report{}
			c.state = stateClosed
			c.close(websocket.StatusGoingAway, "heartbeat timeout")
			h.reg.HostLost(ho.ID)
			h.log.Warn("agent silent", "action", "timeout", "host_id", ho.ID, "result", "offline")
		}
	}
}

func pruneHits(hits []time.Time, now time.Time) []time.Time {
	kept := hits[:0]
	for _, t := range hits {
		if now.Sub(t) < PendingPerIPWindow {
			kept = append(kept, t)
		}
	}
	return kept
}

// admitPending queues a tokenless, codeless hello and tells the agent it is pending.
func (h *Hub) admitPending(c *conn) error {
	if c.hello.Nonce == "" {
		// Without a nonce the fingerprint is host|os only, which any LAN device can predict.
		return ErrEmptyNonce
	}
	fp := proto.Fingerprint(c.hello)
	// Hold the write lock across registration so Pending is always the first frame the agent
	// reads, even if the owner clicks Allow immediately.
	c.wmu.Lock()
	defer c.wmu.Unlock()

	h.mu.Lock()
	now := h.now()
	h.sweepLocked(now)
	if until, ok := h.suppressed[fp]; ok {
		h.mu.Unlock()
		_ = c.writeLocked(proto.TypeDenied, "", proto.Denied{Reason: "recently denied", RetryAfter: until.Sub(now)})
		return ErrSuppressed
	}
	if len(h.ipHits[c.ip]) >= PendingPerIP {
		h.mu.Unlock()
		return ErrRateLimited
	}
	old := h.pending[fp]
	switch {
	case old != nil && old.c.ip != c.ip:
		// Only the address that queued an attempt may replace it; a 40-bit fingerprint is grindable.
		h.mu.Unlock()
		return ErrFingerprintInUse
	case old == nil && len(h.pending) >= PendingCap:
		// A refused hello does not consume the address's quota.
		h.mu.Unlock()
		return ErrPendingFull
	}
	h.ipHits[c.ip] = append(h.ipHits[c.ip], now) // a same-address replace still counts
	if old != nil {                              // same attempt redialled: the new connection replaces it
		delete(h.pending, fp)
		old.c.state = stateClosed
		old.c.close(websocket.StatusPolicyViolation, "replaced")
	}
	e := &pendEntry{c: c, hello: c.hello, since: now, expires: now.Add(PendingTTL)}
	h.pending[fp] = e
	c.fp, c.state = fp, statePending
	h.mu.Unlock()

	if err := c.writeLocked(proto.TypePending, "", proto.Pending{Fingerprint: fp, ExpiresAt: e.expires}); err != nil {
		return err
	}
	h.log.Info("pending listed", "action", "pending", "fingerprint", fp, "host_name", c.hello.HostName,
		"os", c.hello.OS, "source_ip", c.ip, "result", "listed")
	return nil
}

// dropPending closes a pending connection that sent something after its hello.
func (h *Hub) dropPending(c *conn) {
	h.mu.Lock()
	if e := h.pending[c.fp]; e != nil && e.c == c {
		delete(h.pending, c.fp)
	}
	c.state = stateClosed
	h.mu.Unlock()
	h.log.Warn("pending connection dropped", "action", "drop", "fingerprint", c.fp, "host_name", c.hello.HostName,
		"os", c.hello.OS, "source_ip", c.ip, "result", "unexpected message")
	c.close(websocket.StatusPolicyViolation, "unexpected message")
}

// Pending lists unapproved connections, oldest first.
func (h *Hub) Pending() []PendingView {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweepLocked(h.now())
	out := make([]PendingView, 0, len(h.pending))
	for fp, e := range h.pending {
		out = append(out, PendingView{Fingerprint: fp, HostName: e.hello.HostName, OS: e.hello.OS,
			SourceIP: e.c.ip, Since: e.since, ExpiresAt: e.expires})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Since.Equal(out[j].Since) {
			return out[i].Since.Before(out[j].Since)
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})
	return out
}

func (h *Hub) pendingLocked(fp string) (*pendEntry, error) {
	h.sweepLocked(h.now())
	if e := h.pending[fp]; e != nil {
		return e, nil
	}
	if _, ok := h.expired[fp]; ok {
		return nil, ErrPendingExpired
	}
	return nil, ErrNotPending
}

// Allow approves a pending connection: it mints the token, sends Approved over that same
// connection and enrols the host.
func (h *Hub) Allow(fingerprint string) (hostID string, err error) {
	h.mu.Lock()
	e, err := h.pendingLocked(fingerprint)
	if err != nil {
		h.mu.Unlock()
		return "", err
	}
	// Mint first: if persistence fails the entry stays listed so the owner can retry.
	id, token, err := h.mintLocked(e.hello, e.c)
	if err != nil {
		h.mu.Unlock()
		h.log.Error("allow failed", "action", "allow", "fingerprint", fingerprint, "result", "persist failed", logx.Err(err))
		return "", err
	}
	delete(h.pending, fingerprint)
	h.mu.Unlock()
	if err := e.c.send(proto.TypeApproved, "", proto.Approved{Token: token}); err != nil {
		h.mu.Lock()
		h.forgetLocked(id)
		e.c.state = stateClosed
		h.mu.Unlock()
		e.c.close(websocket.StatusInternalError, "approve failed")
		h.audit("allow", fingerprint, e, "send failed")
		return "", err
	}
	h.audit("allow", fingerprint, e, "ok")
	return id, nil
}

// Deny refuses a pending connection and suppresses its fingerprint for DenySuppress.
func (h *Hub) Deny(fingerprint string) error {
	h.mu.Lock()
	e, err := h.pendingLocked(fingerprint)
	if err != nil {
		h.mu.Unlock()
		return err
	}
	delete(h.pending, fingerprint)
	h.suppressed[fingerprint] = h.now().Add(DenySuppress)
	e.c.state = stateClosed
	h.mu.Unlock()
	_ = e.c.send(proto.TypeDenied, "", proto.Denied{Reason: "denied", RetryAfter: DenySuppress})
	e.c.close(websocket.StatusPolicyViolation, "denied")
	h.audit("deny", fingerprint, e, "ok")
	return nil
}

func (h *Hub) audit(action, fp string, e *pendEntry, result string) {
	h.log.Info("pending decision", "action", action, "fingerprint", fp, "host_name", e.hello.HostName,
		"os", e.hello.OS, "source_ip", e.c.ip, "result", result)
}
