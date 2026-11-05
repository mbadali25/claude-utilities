package hub

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"claude-utilities/internal/logx"
	"claude-utilities/internal/proto"
	"claude-utilities/internal/vault"
)

// Add account: one agent host runs `claude auth login` in a throwaway config dir; the owner signs
// in on Anthropic's own page and pastes the one-time code back. The result enters the vault through
// storeLogin, the same rules as Import, but ownership is not claimed: the host's live login did not
// change, so the account is stored free.
//
// Never logged or returned in an error: the sign-in URL (it carries PKCE state), the code, the
// block, the identity.

const (
	addJobLimit = 10 * time.Minute // a job older than this fails and its agent is told to stop
	addKeep     = 15 * time.Minute // a finished job stays readable this long
	addMaxJobs  = 8                // bound on the job map
	maxCodeLen  = 2048
	maxAddErr   = 200
)

var (
	ErrAddBusy         = errors.New("hub: an add-account sign-in is already running")
	ErrNoAdd           = errors.New("hub: no such add-account sign-in")
	ErrNotAwaitingCode = errors.New("hub: the sign-in is not waiting for a code")
)

// AddState is where an add-account job stands.
type AddState string

const (
	AddStarting     AddState = "starting"
	AddAwaitingCode AddState = "awaiting_code"
	AddFinishing    AddState = "finishing"
	AddDone         AddState = "done"
	AddFailed       AddState = "failed"
	AddCancelled    AddState = "cancelled"
)

// AddView is the UI-safe view of a job. URL is set only while awaiting_code; Account only when
// done, and its Block is always nil.
type AddView struct {
	ID      string
	State   AddState
	URL     string
	Account *vault.Account
	Error   string
}

// addJob is guarded by Hub.mu.
type addJob struct {
	id, hostID, label string
	c                 *conn
	state             AddState
	url               string
	account           *vault.Account
	err               string
	storing           bool
	started, ended    time.Time
}

func (j *addJob) live() bool {
	return j.state == AddStarting || j.state == AddAwaitingCode || j.state == AddFinishing
}

// endAddLocked moves a live job to a final state. Callers hold h.mu.
func (h *Hub) endAddLocked(j *addJob, state AddState, msg string, now time.Time) {
	if !j.live() {
		return
	}
	j.state, j.err, j.url, j.ended = state, msg, "", now
}

// cancelAgent tells the agent to stop the job. It runs off the lock and ignores a dead connection.
func cancelAgent(j *addJob) {
	c, id := j.c, j.id
	go func() { _ = c.send(proto.TypeLoginCancel, id, nil) }()
}

// sweepAddsLocked expires overlong jobs and forgets old finished ones. Callers hold h.mu.
func (h *Hub) sweepAddsLocked(now time.Time) {
	for id, j := range h.adds {
		switch {
		case j.live() && now.Sub(j.started) > addJobLimit:
			h.endAddLocked(j, AddFailed, "timed out", now)
			cancelAgent(j)
			h.log.Warn("add account expired", "action", "login_cancel", "host_id", j.hostID, "result", "failed", "reason", "timeout")
		case !j.live() && now.Sub(j.ended) > addKeep:
			delete(h.adds, id)
		}
	}
}

// AddAccount starts a sign-in on hostID and returns the job id. At most one job is live.
func (h *Hub) AddAccount(ctx context.Context, hostID, label string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	label = strings.TrimSpace(label)
	if label == "" || len(label) > maxFieldLen {
		return "", errors.New("hub: label must be 1-64 characters")
	}
	for _, a := range h.vault.List() {
		if strings.EqualFold(a.Label, label) {
			return "", vault.ErrLabelTaken
		}
	}
	id, err := randHex(8)
	if err != nil {
		return "", err
	}
	h.mu.Lock()
	now := h.now()
	h.sweepLocked(now)
	h.sweepAddsLocked(now)
	ho := h.hosts[hostID]
	switch {
	case ho == nil || ho.Revoked:
		h.mu.Unlock()
		return "", ErrUnknownHost
	case ho.c == nil:
		h.mu.Unlock()
		return "", ErrAgentOffline
	}
	for _, j := range h.adds {
		if j.live() {
			h.mu.Unlock()
			return "", ErrAddBusy
		}
	}
	for len(h.adds) >= addMaxJobs { // all finished: drop the oldest
		var oldID string
		var oldAt time.Time
		for k, j := range h.adds {
			if oldID == "" || j.ended.Before(oldAt) {
				oldID, oldAt = k, j.ended
			}
		}
		delete(h.adds, oldID)
	}
	c := ho.c
	h.adds[id] = &addJob{id: id, hostID: hostID, label: label, c: c, state: AddStarting, started: now}
	h.mu.Unlock()

	if err := c.send(proto.TypeLoginStart, id, proto.LoginStart{}); err != nil {
		h.mu.Lock()
		delete(h.adds, id)
		h.mu.Unlock()
		return "", ErrAgentOffline
	}
	h.log.Info("add account started", "action", "login_start", "host_id", hostID, "result", "ok")
	return id, nil
}

// AddStatus reports a job. The URL appears only while it awaits the code.
func (h *Hub) AddStatus(id string) (AddView, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweepAddsLocked(h.now())
	j := h.adds[id]
	if j == nil {
		return AddView{}, ErrNoAdd
	}
	v := AddView{ID: j.id, State: j.state, Error: j.err}
	if j.state == AddAwaitingCode {
		v.URL = j.url
	}
	if j.account != nil {
		a := *j.account
		a.Block = nil
		v.Account = &a
	}
	return v, nil
}

// AddCode forwards the owner's one-time code to the agent.
func (h *Hub) AddCode(id, code string) error {
	code = strings.TrimSpace(code)
	h.mu.Lock()
	h.sweepAddsLocked(h.now())
	j := h.adds[id]
	switch {
	case j == nil:
		h.mu.Unlock()
		return ErrNoAdd
	case j.state != AddAwaitingCode:
		h.mu.Unlock()
		return ErrNotAwaitingCode
	case code == "" || len(code) > maxCodeLen || strings.ContainsFunc(code, func(r rune) bool { return r < ' ' || r == 0x7f }):
		h.mu.Unlock()
		return errors.New("hub: bad sign-in code")
	}
	j.state = AddFinishing
	c := j.c
	h.mu.Unlock()
	if err := c.send(proto.TypeLoginCode, id, proto.LoginCode{Code: code}); err != nil {
		h.mu.Lock()
		h.endAddLocked(j, AddFailed, "agent offline", h.now())
		h.mu.Unlock()
		return ErrAgentOffline
	}
	h.log.Info("add account code sent", "action", "login_code", "host_id", j.hostID, "result", "ok")
	return nil
}

// AddCancel stops a live job; cancelling a finished one does nothing.
func (h *Hub) AddCancel(id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	j := h.adds[id]
	if j == nil {
		return ErrNoAdd
	}
	if j.live() {
		h.endAddLocked(j, AddCancelled, "", h.now())
		cancelAgent(j)
		h.log.Info("add account cancelled", "action", "login_cancel", "host_id", j.hostID, "result", "ok")
	}
	return nil
}

// failAddsOnDropLocked fails every live job that ran over a connection that just closed.
func (h *Hub) failAddsOnDropLocked(c *conn) {
	for _, j := range h.adds {
		if j.c == c && j.live() {
			h.endAddLocked(j, AddFailed, "agent offline", h.now())
			h.log.Warn("add account failed", "action", "login_done", "host_id", j.hostID, "result", "failed", "reason", "agent_offline")
		}
	}
}

// addFrame routes an unsolicited login_url or login_done from an agent to its job. Frames for an
// unknown or finished job, or from another connection, are ignored.
func (h *Hub) addFrame(c *conn, env proto.Envelope) {
	h.mu.Lock()
	j := h.adds[env.ID]
	if j == nil || j.c != c || !j.live() {
		h.mu.Unlock()
		h.log.Debug("login frame ignored", "action", env.Type, "result", "ignored")
		return
	}
	now := h.now()
	switch env.Type {
	case proto.TypeLoginURL:
		var lu proto.LoginURL
		if j.state != AddStarting {
			h.mu.Unlock()
			return
		}
		if json.Unmarshal(env.Body, &lu) != nil || proto.ValidateLoginURL(lu.URL) != nil {
			h.endAddLocked(j, AddFailed, "the agent sent an invalid sign-in URL", now)
			cancelAgent(j)
			h.mu.Unlock()
			h.log.Warn("add account failed", "action", "login_url", "host_id", j.hostID, "result", "failed", "reason", "bad_url")
			return
		}
		j.url, j.state = lu.URL, AddAwaitingCode
		h.mu.Unlock()
		h.log.Info("add account url", "action", "login_url", "host_id", j.hostID, "result", "ok")
	case proto.TypeLoginDone:
		var ld proto.LoginDone
		if err := json.Unmarshal(env.Body, &ld); err != nil {
			h.endAddLocked(j, AddFailed, "the agent sent an unreadable reply", now)
			h.mu.Unlock()
			return
		}
		if ld.Err != "" {
			msg := logx.Redact(ld.Err)
			if len(msg) > maxAddErr {
				msg = msg[:maxAddErr]
			}
			h.endAddLocked(j, AddFailed, msg, now)
			h.mu.Unlock()
			h.log.Warn("add account failed", "action", "login_done", "host_id", j.hostID, "result", "failed", "reason", "agent_error")
			return
		}
		if j.state != AddFinishing || j.storing {
			h.mu.Unlock() // a login nobody asked for, or a repeat
			return
		}
		j.storing = true
		hostID, label := j.hostID, j.label
		h.mu.Unlock()
		acct, err := h.storeLogin(label, ld.Identity, ld.Block)
		h.mu.Lock()
		defer h.mu.Unlock()
		if err != nil {
			h.endAddLocked(j, AddFailed, addErrText(err), h.now())
			h.log.Warn("add account failed", "action", "login_done", "host_id", hostID, "result", "failed", "reason", "store_refused")
			return
		}
		j.account = &acct
		h.endAddLocked(j, AddDone, "", h.now())
		h.log.Info("add account done", "action", "login_done", "host_id", hostID, "account", acct.ID, "result", "ok")
	}
}

// addErrText is the owner-facing reason for a refused login. Hub-authored errors already carry no
// secret; anything else gets a generic line.
func addErrText(err error) string {
	switch {
	case errors.Is(err, ErrAlreadyStored):
		return "that login is already stored as an account"
	case errors.Is(err, vault.ErrLabelTaken):
		return "an account with that label already exists"
	case strings.HasPrefix(err.Error(), "hub: "):
		return logx.Redact(strings.TrimPrefix(err.Error(), "hub: "))
	}
	return "could not store the login"
}
