package web

import (
	"errors"
	"net/http"
	"time"

	"claude-utilities/internal/hub"
	"claude-utilities/internal/logx"
	"claude-utilities/internal/proto"
)

// POST /api/sessions/command: the one route that asks a session to do something. It needs a
// signed-in admin session and a CSRF token (authPost), it is rate limited per source address, and
// a scope wider than one session needs confirm:true in the body.
//
// Status comes back two ways and no third: the response to this POST, and the sessions in the
// existing GET /api/hosts poll. There is no separate status endpoint.

const (
	// maxCommandRequests is how many command requests one source may make per window.
	maxCommandRequests  = 30
	commandWindow       = time.Minute
	maxCommandRequestID = 64
)

// commandJSON is one command aimed at a session. code and mechanism are short machine strings;
// hint is operator-facing text that may carry a session id and a session name, so it goes to the
// browser (written with textContent) and nowhere else.
type commandJSON struct {
	ID        string    `json:"id"`
	Command   string    `json:"command"`
	Status    string    `json:"status"`
	Code      string    `json:"code,omitempty"`
	Mechanism string    `json:"mechanism,omitempty"`
	Hint      string    `json:"hint,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// commandTargetJSON is commandJSON plus which session it is aimed at, for the POST response where
// the caller does not yet know the targets.
type commandTargetJSON struct {
	commandJSON
	HostID    string `json:"hostId"`
	SessionID string `json:"sessionId"`
	PID       int    `json:"pid,omitempty"`
}

type commandCountsJSON struct {
	Total       int `json:"total"`
	Queued      int `json:"queued"`
	Delivered   int `json:"delivered"`
	Done        int `json:"done"`
	Failed      int `json:"failed"`
	Unsupported int `json:"unsupported"`
}

// commandViewJSON is one dispatched request.
type commandViewJSON struct {
	ID        string              `json:"id"`
	Command   string              `json:"command"`
	Scope     string              `json:"scope"`
	CreatedAt time.Time           `json:"createdAt"`
	Counts    commandCountsJSON   `json:"counts"`
	Targets   []commandTargetJSON `json:"targets"`
}

func commandView(v hub.CommandTargetView) commandJSON {
	return commandJSON{ID: v.ID, Command: v.Command, Status: v.Status, Code: v.Code,
		Mechanism: v.Mechanism, Hint: v.Hint, CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt}
}

func commandsView(vs []hub.CommandTargetView) []commandJSON {
	if len(vs) == 0 {
		return nil
	}
	out := make([]commandJSON, 0, len(vs))
	for _, v := range vs {
		out = append(out, commandView(v))
	}
	return out
}

func requestView(v hub.CommandView) commandViewJSON {
	out := commandViewJSON{ID: v.ID, Command: v.Command, Scope: string(v.Scope), CreatedAt: v.CreatedAt,
		Counts: commandCountsJSON{Total: v.Counts.Total, Queued: v.Counts.Queued,
			Delivered: v.Counts.Delivered, Done: v.Counts.Done, Failed: v.Counts.Failed,
			Unsupported: v.Counts.Unsupported},
		Targets: make([]commandTargetJSON, 0, len(v.Targets))}
	for _, t := range v.Targets {
		out.Targets = append(out.Targets, commandTargetJSON{commandJSON: commandView(t),
			HostID: t.HostID, SessionID: t.SessionID, PID: t.PID})
	}
	return out
}

// overCommandLimit records one command request and reports whether this source is over its budget.
// The tracked-address table is bounded, so a spray cannot grow it without end.
func (s *server) overCommandLimit(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := s.now().Add(-commandWindow)
	keep := s.commandHits[ip][:0]
	for _, t := range s.commandHits[ip] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	if len(keep) >= maxCommandRequests {
		s.commandHits[ip] = keep
		return true
	}
	if len(s.commandHits) < maxTrackedIPs || s.commandHits[ip] != nil {
		s.commandHits[ip] = append(keep, s.now())
	} else {
		s.commandHits[ip] = keep
	}
	if len(s.commandHits[ip]) == 0 {
		delete(s.commandHits, ip)
	}
	return false
}

// commandError maps a request-shaping error to a status an operator can act on.
func commandError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, hub.ErrUnknownCommand), errors.Is(err, hub.ErrBadScope),
		errors.Is(err, hub.ErrNameRequired), errors.Is(err, hub.ErrNameNotAllowed):
		writeErr(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, hub.ErrConfirmRequired):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.Is(err, hub.ErrNoSuchSession):
		writeErr(w, http.StatusNotFound, err.Error())
	case errors.Is(err, hub.ErrNoCommandTargets), errors.Is(err, hub.ErrTooManyCommandTargets):
		writeErr(w, http.StatusConflict, err.Error())
	default:
		hubError(w, err)
	}
}

func (s *server) sessionCommand(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Command         string `json:"command"`
		Scope           string `json:"scope"`
		Host            string `json:"host"`
		Session         string `json:"session"`
		Name            string `json:"name"`
		OnlyNeedsReload bool   `json:"onlyNeedsReload"`
		Confirm         bool   `json:"confirm"`
		RequestID       string `json:"requestId"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	ip := clientIP(r)
	if s.overCommandLimit(ip) {
		logger.Warn("session command refused", "action", "command", "result", "refused",
			"reason", "too many requests", "source_ip", ip)
		writeErr(w, http.StatusTooManyRequests, "too many command requests; wait a minute")
		return
	}
	if len(in.Name) > proto.MaxRemoteName*4 || len(in.RequestID) > maxCommandRequestID {
		writeErr(w, http.StatusBadRequest, "name or requestId too long")
		return
	}
	v, err := s.hub.Command(r.Context(), hub.CommandRequest{
		Command: in.Command, Scope: hub.CommandScope(in.Scope), HostID: in.Host,
		SessionID: in.Session, Name: in.Name, OnlyNeedsReload: in.OnlyNeedsReload,
		Confirm: in.Confirm, RequestID: in.RequestID})
	if err != nil {
		commandError(w, err)
		return
	}
	// The hub logs the dispatch itself with the same audit fields, so this route logs only what
	// the hub never sees: which address asked, at debug level so an operator polling a UI does
	// not drown the log.
	logger.Debug("session command accepted", "action", "command", "command", v.Command,
		"scope", string(v.Scope), "targetCount", v.Counts.Total, "result", "accepted", "source_ip", ip)
	writeJSON(w, http.StatusAccepted, requestView(v))
}

func init() {
	// The web layer logs the same audit fields as the hub; logx.Allow is idempotent.
	logx.Allow("command", "scope", "targetCount", "queuedCount", "failedCount", "source_ip")
}
