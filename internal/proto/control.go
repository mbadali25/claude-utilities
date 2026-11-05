package proto

import (
	"fmt"
	"log/slog"
	"strings"
	"unicode"

	"claude-utilities/internal/logx"
)

// Session-control messages. Both are additive and both are strictly request/response:
//
//   - An older agent that does not know command_req logs an unhandled message and answers
//     nothing, so a newer hub times the target out instead of hanging.
//   - command_res is only ever sent in reply to a command_req. That matters because an older
//     hub's dispatcher closes the connection on an unexpected frame, so a newer agent must
//     never send one unsolicited. Delivery that happens long after the reply therefore rides
//     in Report.Commands, an additive field an older hub simply ignores.
const (
	TypeCommandReq = "command_req"
	TypeCommandRes = "command_res"
)

// Commands a session-control request may carry. See docs/runbooks/session-control.md for which
// mechanism each one ends up using and what it can honestly claim.
const (
	// CmdReloadPlugins asks a session to activate pending plugin changes (/reload-plugins).
	CmdReloadPlugins = "reload_plugins"
	// CmdRemoteControlEnable asks a session to bind a Remote Control bridge.
	CmdRemoteControlEnable = "remote_control_enable"
	// CmdRenameRemote asks a session to carry a given remote-visible title.
	CmdRenameRemote = "rename_remote"
	// CmdRepair is the composite: reload plugins, enable Remote Control and set the remote name.
	// It takes no name of its own; each target is named after the session's own name.
	CmdRepair = "repair"
)

// Per-target statuses. queued is the hub's own starting state; the other four come from an agent.
const (
	// StatusQueued means the hub has a target but no verdict yet.
	StatusQueued = "queued"
	// StatusDelivered means the instruction reached the session. It does NOT mean it ran.
	StatusDelivered = "delivered"
	// StatusDone means the command demonstrably ran. No mechanism can claim this today.
	StatusDone = "done"
	// StatusFailed means the attempt failed; Code says why.
	StatusFailed = "failed"
	// StatusUnsupported means no proven mechanism can do this; Code says why.
	StatusUnsupported = "unsupported"
)

// Reason codes. They are short, machine-readable and never carry agent free text.
const (
	// CodeRequiresRestart means only a relaunch can do it; the hint carries the command.
	CodeRequiresRestart = "unsupported-requires-restart"
	// CodeInboxUnproven means the experimental per-session inbox has an unproven wire frame.
	CodeInboxUnproven = "unsupported-inbox-unproven"
	// CodeNoMechanism means no mechanism is registered for the command.
	CodeNoMechanism = "no-mechanism"
	// CodeUnknownCommand means the command name is not one this build defines.
	CodeUnknownCommand = "unknown-command"
	// CodeBadSessionID means the session id is not a session id shape the agent will act on.
	CodeBadSessionID = "bad-session-id"
	// CodeNoName means a rename had no usable name.
	CodeNoName = "no-name"
	// CodeQueueFull means the instruction queue is at its bound.
	CodeQueueFull = "queue-full"
	// CodeQueueWriteFailed means the instruction queue could not be written.
	CodeQueueWriteFailed = "queue-write-failed"
	// CodeAgentOffline means the host's agent was not connected.
	CodeAgentOffline = "agent-offline"
	// CodeTimeout means no verdict arrived before the hub's deadline.
	CodeTimeout = "timeout"
	// CodeBadReply means the agent's reply could not be read.
	CodeBadReply = "bad-reply"
)

// MaxRemoteName is the longest remote title accepted, in runes. Claude Code normalises a name to
// 200 code points (spike E), so a longer one could never match what the session ends up carrying.
const MaxRemoteName = 200

// MaxCommandHint bounds the operator-facing hint an agent may return (bytes).
const MaxCommandHint = 400

// MaxCommandCode bounds a reason code (bytes).
const MaxCommandCode = 64

// MaxCommandsPerReport bounds how many command statuses one report may carry.
const MaxCommandsPerReport = 32

// ValidCommand reports whether c is a command this protocol version defines.
func ValidCommand(c string) bool {
	switch c {
	case CmdReloadPlugins, CmdRemoteControlEnable, CmdRenameRemote, CmdRepair:
		return true
	}
	return false
}

// ValidCommandStatus reports whether s is a per-target status this protocol version defines.
func ValidCommandStatus(s string) bool {
	switch s {
	case StatusQueued, StatusDelivered, StatusDone, StatusFailed, StatusUnsupported:
		return true
	}
	return false
}

// CleanRemoteName normalises a remote title the way Claude Code does: control, bidirectional and
// zero-width characters become single spaces, the ends are trimmed and the name is capped at
// MaxRemoteName runes. A name that is only whitespace comes back empty.
func CleanRemoteName(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '​' {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > MaxRemoteName {
		s = strings.TrimSpace(string(r[:MaxRemoteName]))
	}
	return s
}

// CommandReq (hub to agent) asks one session on this host to run one command. The envelope ID is
// the request id; CommandID names the command in the hub's records and comes back in the reply and
// in any later Report.Commands entry.
type CommandReq struct {
	CommandID string `json:"commandId"`
	Command   string `json:"command"`
	// SessionID is the session id the agent matches against the sessions it can see.
	SessionID string `json:"sessionId"`
	PID       int    `json:"pid,omitempty"`
	// Name is the remote title a rename should set. It is session- or operator-supplied text that
	// may name a person, so every String and log form masks it.
	Name string `json:"name,omitempty"`
}

// CommandRes (agent to hub) answers exactly one CommandReq.
type CommandRes struct {
	CommandID string `json:"commandId"`
	Status    string `json:"status"`
	// Code is a short machine reason, never agent free text.
	Code string `json:"code,omitempty"`
	// Mechanism names the agent mechanism that handled the command.
	Mechanism string `json:"mechanism,omitempty"`
	// Hint is operator-facing text, for example the exact relaunch command. It can carry a session
	// id and a session name, so it goes to the browser and is never logged.
	Hint string `json:"hint,omitempty"`
}

// SessionCommandStatus rides in Report so a delivery observed long after the reply reaches the hub
// without a new message type. It carries no name, cwd or payload.
type SessionCommandStatus struct {
	CommandID string `json:"commandId"`
	Status    string `json:"status"`
	Code      string `json:"code,omitempty"`
}

func (r CommandReq) String() string {
	return fmt.Sprintf("CommandReq{CommandID:%s Command:%s SessionID:%s PID:%d Name:%s}",
		logx.Redact(r.CommandID), logx.Redact(r.Command), logx.Redact(r.SessionID), r.PID, mask)
}
func (r CommandReq) GoString() string { return r.String() }
func (r CommandReq) LogValue() slog.Value {
	return slog.GroupValue(slog.String("command", logx.Redact(r.Command)), slog.String("name", mask))
}

func (r CommandRes) String() string {
	return fmt.Sprintf("CommandRes{CommandID:%s Status:%s Code:%s Mechanism:%s Hint:%s}",
		logx.Redact(r.CommandID), logx.Redact(r.Status), logx.Redact(r.Code), logx.Redact(r.Mechanism), mask)
}
func (r CommandRes) GoString() string { return r.String() }
func (r CommandRes) LogValue() slog.Value {
	return slog.GroupValue(slog.String("status", logx.Redact(r.Status)),
		slog.String("mechanism", logx.Redact(r.Mechanism)), slog.String("hint", mask))
}
