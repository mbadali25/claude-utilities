package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"claude-utilities/internal/logx"
	"claude-utilities/internal/proto"
)

// Session control: the hub fans one operator request out to the sessions it names, one
// proto.CommandReq per target, and keeps the per-target verdict in memory. It never decides HOW a
// command is carried out - that is the agent's mechanism registry - so a command the spike has not
// proven comes back "unsupported" with a reason code instead of a false success.
//
// Never logged here: a session's name, its cwd, or the operator-facing hint (it can carry both a
// session id and a session name). Counts, opaque ids, the command, the scope, the mechanism and
// the result code are logged.

func init() {
	// Audit fields for session control. None carries a secret, an email, a path or a name:
	// "target" is an opaque session id, the counts are counts, and "mechanism" is one of a fixed
	// set of mechanism names.
	logx.Allow("command", "scope", "mechanism", "target", "targetCount", "queuedCount",
		"deliveredCount", "doneCount", "failedCount", "unsupportedCount")
}

// CommandScope selects which sessions one request targets. It is orthogonal to the command: every
// command works at every scope, and OnlyNeedsReload narrows any of them to the sessions a swap has
// left holding an old login.
type CommandScope string

const (
	// ScopeSession is one session on one host.
	ScopeSession CommandScope = "session"
	// ScopeHost is every reported session on one host.
	ScopeHost CommandScope = "host"
	// ScopeAll is every reported session on every connected host.
	ScopeAll CommandScope = "all"
)

const (
	// commandTimeout is how long a target may sit without a verdict before it fails.
	commandTimeout = 60 * time.Second
	// commandKeep is how long a finished request stays readable.
	commandKeep = 15 * time.Minute
	// maxCommands bounds the request history.
	maxCommands = 64
	// maxCommandTargets bounds one request's fan-out.
	maxCommandTargets = 256
	// maxSessionCommands bounds how many recent targets one session carries in the state poll.
	maxSessionCommands = 8
	// maxRequestID bounds a caller-supplied idempotency key.
	maxRequestID = 64
)

var (
	// ErrUnknownCommand means the command name is not one this build defines.
	ErrUnknownCommand = errors.New("hub: unknown session command")
	// ErrBadScope means the scope is not session, host or all.
	ErrBadScope = errors.New("hub: unknown command scope")
	// ErrConfirmRequired means a host-wide or all-hosts command needs an explicit confirmation.
	ErrConfirmRequired = errors.New("hub: a host-wide or all-hosts command needs confirm")
	// ErrNameRequired means rename_remote was asked for one session without a name.
	ErrNameRequired = errors.New("hub: rename_remote needs a name")
	// ErrNameNotAllowed means a rename beyond one session cannot take a single name: every
	// session would end up with the same title. The repair command derives each name instead.
	ErrNameNotAllowed = errors.New("hub: a host-wide or all-hosts rename cannot take one name; use the repair command")
	// ErrNoSuchSession means the host reports no session with that id.
	ErrNoSuchSession = errors.New("hub: no such session on that host")
	// ErrNoCommandTargets means the request matched no session.
	ErrNoCommandTargets = errors.New("hub: the command matched no session")
	// ErrTooManyCommandTargets means the request matched more sessions than one request may carry.
	ErrTooManyCommandTargets = errors.New("hub: the command matched too many sessions")
	// ErrRelaunchScope means relaunch_remote was asked at host or all scope. It stops a process,
	// so it takes exactly one named session.
	ErrRelaunchScope = errors.New("hub: relaunch_remote takes exactly one session")
	// ErrSessionNotIdle means the session is not reported idle, so a relaunch would throw away a
	// running turn. Nothing was sent.
	ErrSessionNotIdle = errors.New("hub: the session is not idle; a relaunch would lose its running work")
	// ErrNoCommand means no such command request is on record.
	ErrNoCommand = errors.New("hub: no such session command")
)

// cmdTarget is one command for one session. Guarded by Hub.mu.
type cmdTarget struct {
	id, hostID, sessionID string
	pid                   int
	command, name         string
	status, code          string
	mechanism, hint       string
	created, updated      time.Time
}

func (t *cmdTarget) terminal() bool {
	return t.status == proto.StatusDone || t.status == proto.StatusFailed || t.status == proto.StatusUnsupported
}

// statusRank orders the non-terminal progression so a late report cannot walk a target backwards.
func statusRank(s string) int {
	switch s {
	case proto.StatusQueued:
		return 0
	case proto.StatusDelivered:
		return 1
	}
	return 2
}

// setLocked applies a verdict if it is an advance. A terminal status is final: a later report
// never reopens it, and a delivered target never falls back to queued. Callers hold h.mu.
func (t *cmdTarget) setLocked(status, code, mechanism, hint string, now time.Time) bool {
	if !proto.ValidCommandStatus(status) || t.terminal() {
		return false
	}
	if statusRank(status) < statusRank(t.status) {
		return false
	}
	t.status, t.updated = status, now
	if code != "" {
		t.code = clipText(code, proto.MaxCommandCode)
	}
	if mechanism != "" {
		t.mechanism = clipText(mechanism, proto.MaxCommandCode)
	}
	if hint != "" {
		t.hint = clipText(hint, proto.MaxCommandHint)
	}
	return true
}

// clipText trims agent-supplied text to n bytes on a safe boundary. The value is redacted first: these
// fields reach the browser, and nothing an agent sends is trusted.
func clipText(s string, n int) string {
	s = logx.Redact(strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return ' '
		}
		return r
	}, s))
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xc0 == 0x80 {
		n--
	}
	return s[:n]
}

// cmdBatch is one operator request. Guarded by Hub.mu.
type cmdBatch struct {
	id, command, requestID string
	scope                  CommandScope
	created, deadline      time.Time
	targets                []*cmdTarget
}

func (b *cmdBatch) live() bool {
	for _, t := range b.targets {
		if !t.terminal() {
			return true
		}
	}
	return false
}

// CommandRequest is one operator request. RequestID is an optional idempotency key: a repeat of
// the same key returns the first request's view instead of dispatching again.
type CommandRequest struct {
	Command         string
	Scope           CommandScope
	HostID          string
	SessionID       string
	Name            string
	OnlyNeedsReload bool
	Confirm         bool
	RequestID       string
}

// CommandTargetView is one session's command and its verdict.
type CommandTargetView struct {
	ID        string
	HostID    string
	SessionID string
	PID       int
	Command   string
	Status    string
	Code      string
	Mechanism string
	Hint      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// CommandCounts summarises a request's targets by status.
type CommandCounts struct {
	Total, Queued, Delivered, Done, Failed, Unsupported int
}

// CommandView is the UI-safe view of one request.
type CommandView struct {
	ID        string
	Command   string
	Scope     CommandScope
	CreatedAt time.Time
	Counts    CommandCounts
	Targets   []CommandTargetView
}

func (t *cmdTarget) view() CommandTargetView {
	return CommandTargetView{ID: t.id, HostID: t.hostID, SessionID: t.sessionID, PID: t.pid,
		Command: t.command, Status: t.status, Code: t.code, Mechanism: t.mechanism, Hint: t.hint,
		CreatedAt: t.created, UpdatedAt: t.updated}
}

func (b *cmdBatch) view() CommandView {
	v := CommandView{ID: b.id, Command: b.command, Scope: b.scope, CreatedAt: b.created,
		Targets: make([]CommandTargetView, 0, len(b.targets))}
	for _, t := range b.targets {
		v.Targets = append(v.Targets, t.view())
		v.Counts.Total++
		switch t.status {
		case proto.StatusQueued:
			v.Counts.Queued++
		case proto.StatusDelivered:
			v.Counts.Delivered++
		case proto.StatusDone:
			v.Counts.Done++
		case proto.StatusFailed:
			v.Counts.Failed++
		case proto.StatusUnsupported:
			v.Counts.Unsupported++
		}
	}
	return v
}

// repairSteps is what the composite command expands to per session, in order: activate pending
// plugin changes, bind a Remote Control bridge, then set the remote title.
var repairSteps = []string{proto.CmdReloadPlugins, proto.CmdRemoteControlEnable, proto.CmdRenameRemote}

// validateCommandRequest checks everything that does not need the host table.
func validateCommandRequest(req *CommandRequest) error {
	if !proto.ValidCommand(req.Command) {
		return ErrUnknownCommand
	}
	switch req.Scope {
	case ScopeSession, ScopeHost, ScopeAll:
	default:
		return ErrBadScope
	}
	if len(req.RequestID) > maxRequestID {
		return errors.New("hub: request id too long")
	}
	req.Name = proto.CleanRemoteName(req.Name)
	if req.Command == proto.CmdRenameRemote {
		switch {
		case req.Scope != ScopeSession:
			// One name for many sessions would give them all the same title, and no name at all
			// would fail every target. Either way the composite is what the operator wants.
			return ErrNameNotAllowed
		case req.Name == "":
			return ErrNameRequired
		}
	}
	if req.Command != proto.CmdRenameRemote {
		req.Name = "" // only a rename carries a name
	}
	if req.Command == proto.CmdRelaunchRemote && req.Scope != ScopeSession {
		return ErrRelaunchScope
	}
	if req.Scope == ScopeSession && (req.HostID == "" || req.SessionID == "") {
		return fmt.Errorf("%w: a session-scoped command needs a host and a session", ErrNoSuchSession)
	}
	if req.Scope == ScopeHost && req.HostID == "" {
		return ErrUnknownHost
	}
	// A command that reaches every session on a host, or every host, is confirmed explicitly.
	// A restart-type command is confirmed at EVERY scope, session scope included: the confirm is
	// what proves the operator was shown the names of the sessions it reaches, and one session is
	// still somebody's work. This is not a UI-only guard; the hub refuses it here.
	if (req.Scope != ScopeSession || proto.IsRestartCommand(req.Command)) && !req.Confirm {
		return ErrConfirmRequired
	}
	return nil
}

// sessionTarget is one matched session before it becomes targets.
type sessionTarget struct {
	hostID, sessionID, name, status string
	pid                             int
}

// matchSessionsLocked returns the sessions a request names, ordered by host then session, and the
// connection each one's host is reachable over. Callers hold h.mu.
func (h *Hub) matchSessionsLocked(req CommandRequest) ([]sessionTarget, map[string]*conn, error) {
	conns := map[string]*conn{}
	var out []sessionTarget
	ids := make([]string, 0, len(h.hosts))
	for id := range h.hosts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		ho := h.hosts[id]
		if ho.Revoked {
			continue
		}
		if req.Scope != ScopeAll && id != req.HostID {
			continue
		}
		for _, s := range ho.report.Sessions {
			if req.Scope == ScopeSession && s.ID != req.SessionID {
				continue
			}
			if _, stale := ho.reloadIDs[sessionKey(s)]; req.OnlyNeedsReload && !stale {
				continue
			}
			// The name to set is the session's OWN name, as `/rename` set it. RemoteName is
			// the stale remote title the operator is trying to replace, so naming a session
			// after it would be a no-op by construction the day Claude Code starts writing it.
			out = append(out, sessionTarget{hostID: id, sessionID: s.ID, pid: s.PID,
				name: proto.CleanRemoteName(s.Name), status: s.Status})
			conns[id] = ho.c
		}
	}
	if req.Scope != ScopeAll {
		if ho := h.hosts[req.HostID]; ho == nil || ho.Revoked {
			return nil, nil, ErrUnknownHost
		}
		if req.Scope == ScopeSession && len(out) == 0 {
			return nil, nil, ErrNoSuchSession
		}
	}
	if len(out) == 0 {
		return nil, nil, ErrNoCommandTargets
	}
	return out, conns, nil
}

// Command fans one operator request out to the sessions it names and returns the request's view
// with every target queued. The verdicts arrive asynchronously: poll CommandStatus, or read the
// per-session view in Hosts(). The caller is NOT authenticated here; the HTTP route must do that.
func (h *Hub) Command(ctx context.Context, req CommandRequest) (CommandView, error) {
	if err := ctx.Err(); err != nil {
		return CommandView{}, err
	}
	if err := validateCommandRequest(&req); err != nil {
		return CommandView{}, err
	}
	id, err := randHex(8)
	if err != nil {
		return CommandView{}, err
	}

	h.mu.Lock()
	now := h.now()
	h.sweepLocked(now)
	h.sweepCommandsLocked(now)
	if req.RequestID != "" {
		if prev := h.cmdReqIDs[req.RequestID]; prev != "" {
			if b := h.cmds[prev]; b != nil {
				v := b.view()
				h.mu.Unlock()
				return v, nil
			}
		}
	}
	matched, conns, err := h.matchSessionsLocked(req)
	if err != nil {
		h.mu.Unlock()
		return CommandView{}, err
	}
	if req.Command == proto.CmdRelaunchRemote {
		// Session scope matched one session. Only a session the host reports idle may be killed;
		// the agent re-checks this from the session's own file.
		for _, m := range matched {
			if m.status != "idle" {
				h.mu.Unlock()
				return CommandView{}, ErrSessionNotIdle
			}
		}
	}
	steps := []string{req.Command}
	if req.Command == proto.CmdRepair {
		steps = repairSteps
	}
	if len(matched)*len(steps) > maxCommandTargets {
		h.mu.Unlock()
		return CommandView{}, ErrTooManyCommandTargets
	}
	b := &cmdBatch{id: id, command: req.Command, requestID: req.RequestID, scope: req.Scope,
		created: now, deadline: now.Add(commandTimeout)}
	byHost := map[string][]*cmdTarget{}
	for i, m := range matched {
		for j, step := range steps {
			tid := fmt.Sprintf("%s-%d-%d", id, i, j)
			name := req.Name
			if req.Command == proto.CmdRepair && step == proto.CmdRenameRemote {
				name = m.name // the composite names each session after itself
			}
			if proto.IsRestartCommand(step) {
				// The relaunch command the agent builds gives the name at bind, so it has to be
				// the session's OWN name: validateCommandRequest cleared req.Name for anything but
				// a rename, which would otherwise leave the operator a nameless relaunch.
				name = m.name
			}
			t := &cmdTarget{id: tid, hostID: m.hostID, sessionID: m.sessionID, pid: m.pid,
				command: step, name: name, status: proto.StatusQueued, created: now, updated: now}
			if step == proto.CmdRenameRemote && name == "" {
				t.status, t.code, t.updated = proto.StatusFailed, proto.CodeNoName, now
			}
			b.targets = append(b.targets, t)
			h.cmdByID[tid] = t
			key := cmdSessionKey(m.hostID, m.pid, m.sessionID)
			list := append(h.cmdBySession[key], t)
			if len(list) > maxSessionCommands {
				list = list[len(list)-maxSessionCommands:]
			}
			h.cmdBySession[key] = list
			if !t.terminal() {
				byHost[m.hostID] = append(byHost[m.hostID], t)
			}
		}
	}
	h.cmds[id] = b
	if req.RequestID != "" {
		h.cmdReqIDs[req.RequestID] = id
	}
	h.pruneCommandsLocked()
	v := b.view()
	h.mu.Unlock()

	h.log.Info("session command dispatched", "action", "command", "command", req.Command,
		"scope", string(req.Scope), "targetCount", v.Counts.Total, "queuedCount", v.Counts.Queued,
		"failedCount", v.Counts.Failed, "result", "queued")

	// The fan-out deliberately outlives the caller's context, which dies as soon as the HTTP
	// response is written: WithoutCancel keeps the caller's values and drops its cancellation.
	// Each send still ends at h.reqTimeout, at the connection's close, or at the request's
	// deadline, which sweepCommandsLocked enforces.
	sendCtx := context.WithoutCancel(ctx)
	for hostID, targets := range byHost {
		// One goroutine per host, targets sent in order: a host's agent answers one at a time.
		go h.sendCommands(sendCtx, hostID, conns[hostID], targets)
	}
	return v, nil
}

// sendCommands sends one host's targets in order and records each verdict.
func (h *Hub) sendCommands(ctx context.Context, hostID string, c *conn, targets []*cmdTarget) {
	for _, t := range targets {
		if c == nil {
			h.finishTarget(t, proto.StatusFailed, proto.CodeAgentOffline, "", "")
			continue
		}
		h.mu.Lock()
		req := proto.CommandReq{CommandID: t.id, Command: t.command, SessionID: t.sessionID,
			PID: t.pid, Name: t.name}
		h.mu.Unlock()
		raw, err := h.request(ctx, c, proto.TypeCommandReq, proto.TypeCommandRes, req)
		if err != nil {
			code := proto.CodeTimeout
			if errors.Is(err, ErrAgentOffline) {
				code = proto.CodeAgentOffline
			}
			h.finishTarget(t, proto.StatusFailed, code, "", "")
			h.log.Warn("session command failed", "action", "command", "host_id", hostID,
				"command", t.command, "target", t.sessionID, "result", proto.StatusFailed, "reason", code)
			continue
		}
		var res proto.CommandRes
		if err := json.Unmarshal(raw, &res); err != nil || !proto.ValidCommandStatus(res.Status) {
			h.finishTarget(t, proto.StatusFailed, proto.CodeBadReply, "", "")
			continue
		}
		h.finishTarget(t, res.Status, res.Code, res.Mechanism, res.Hint)
		h.log.Info("session command answered", "action", "command", "host_id", hostID,
			"command", t.command, "target", t.sessionID, "mechanism", res.Mechanism,
			"result", res.Status, "reason", res.Code)
	}
}

func (h *Hub) finishTarget(t *cmdTarget, status, code, mechanism, hint string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	t.setLocked(status, code, mechanism, hint, h.now())
	// A verdict can be what makes the oldest request finished, so the history bound is applied
	// here too: otherwise requests that were all live at the last Command stay over the bound
	// until some reader happens to sweep.
	h.pruneCommandsLocked()
}

// applyCommandStatusesLocked folds a report's command statuses into the hub's records. A status
// for a target on another host, or for an unknown target, is ignored. Callers hold h.mu.
func (h *Hub) applyCommandStatusesLocked(hostID string, ss []proto.SessionCommandStatus) {
	if len(ss) > proto.MaxCommandsPerReport {
		ss = ss[:proto.MaxCommandsPerReport]
	}
	now := h.now()
	for _, s := range ss {
		t := h.cmdByID[s.CommandID]
		if t == nil || t.hostID != hostID {
			continue
		}
		if t.setLocked(s.Status, s.Code, "", "", now) {
			h.log.Info("session command progressed", "action", "command", "host_id", hostID,
				"command", t.command, "target", t.sessionID, "result", t.status, "reason", t.code)
		}
	}
	h.pruneCommandsLocked()
}

// sweepCommandsLocked fails targets past their request's deadline and forgets old requests.
// Callers hold h.mu.
func (h *Hub) sweepCommandsLocked(now time.Time) {
	for id, b := range h.cmds {
		if b.live() && now.After(b.deadline) {
			for _, t := range b.targets {
				if !t.terminal() {
					t.setLocked(proto.StatusFailed, proto.CodeTimeout, "", "", now)
				}
			}
			h.log.Warn("session command timed out", "action", "command", "command", b.command,
				"scope", string(b.scope), "targetCount", len(b.targets), "result", proto.StatusFailed,
				"reason", proto.CodeTimeout)
		}
		if !b.live() && now.Sub(b.created) > commandKeep {
			h.forgetCommandLocked(id, b)
		}
	}
	// Sweeping is the one path every reader shares, so the history bound is applied here too,
	// not only when a new request comes in.
	h.pruneCommandsLocked()
}

// pruneCommandsLocked drops the oldest finished requests once the history is over its bound.
// Callers hold h.mu.
func (h *Hub) pruneCommandsLocked() {
	for len(h.cmds) > maxCommands {
		var oldID string
		var oldAt time.Time
		for id, b := range h.cmds {
			if b.live() {
				continue
			}
			if oldID == "" || b.created.Before(oldAt) {
				oldID, oldAt = id, b.created
			}
		}
		if oldID == "" {
			return // every request is still live: the bound gives way rather than losing a verdict
		}
		h.forgetCommandLocked(oldID, h.cmds[oldID])
	}
}

func (h *Hub) forgetCommandLocked(id string, b *cmdBatch) {
	for _, t := range b.targets {
		delete(h.cmdByID, t.id)
		key := cmdSessionKey(t.hostID, t.pid, t.sessionID)
		keep := h.cmdBySession[key][:0]
		for _, x := range h.cmdBySession[key] {
			if x != t {
				keep = append(keep, x)
			}
		}
		if len(keep) == 0 {
			delete(h.cmdBySession, key)
		} else {
			h.cmdBySession[key] = keep
		}
	}
	if b.requestID != "" && h.cmdReqIDs[b.requestID] == id {
		delete(h.cmdReqIDs, b.requestID)
	}
	delete(h.cmds, id)
}

// CommandStatus returns one request's view.
func (h *Hub) CommandStatus(id string) (CommandView, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweepCommandsLocked(h.now())
	b := h.cmds[id]
	if b == nil {
		return CommandView{}, ErrNoCommand
	}
	return b.view(), nil
}

// Commands returns the most recent requests, newest first, at most limit of them.
func (h *Hub) Commands(limit int) []CommandView {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweepCommandsLocked(h.now())
	out := make([]CommandView, 0, len(h.cmds))
	for _, b := range h.cmds {
		out = append(out, b.view())
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// cmdSessionKey identifies one session's command bucket. It carries the pid as well as the id,
// because a session can report an empty id (sessions.NeedsReload allows for it) and two of those
// on one host would otherwise share a bucket and show each other's commands.
func cmdSessionKey(hostID string, pid int, sessionID string) string {
	return fmt.Sprintf("%s|%d:%s", hostID, pid, sessionID)
}

// sessionCommandsLocked returns one session's recent targets, oldest first. Callers hold h.mu.
func (h *Hub) sessionCommandsLocked(hostID string, s proto.Session) []CommandTargetView {
	list := h.cmdBySession[cmdSessionKey(hostID, s.PID, s.ID)]
	if len(list) == 0 {
		return nil
	}
	out := make([]CommandTargetView, 0, len(list))
	for _, t := range list {
		out = append(out, t.view())
	}
	return out
}
