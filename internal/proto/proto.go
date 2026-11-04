// Package proto defines the wire envelope and message bodies.
package proto

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"claude-utilities/internal/logx"
)

const mask = "[redacted]"

// Version is the only protocol version accepted by Decode.
const Version = 1

const (
	TypeHello     = "hello"
	TypeHeartbeat = "heartbeat"
	TypeReport    = "report"
	TypeExportReq = "export_req"
	TypeExportRes = "export_res"
	TypeSwapReq   = "swap_req"
	TypeSwapRes   = "swap_res"
)

// Envelope wraps every message.
type Envelope struct {
	V    int             `json:"v"`
	Type string          `json:"type"`
	ID   string          `json:"id,omitempty"`
	Body json.RawMessage `json:"body,omitempty"`
}

type Hello struct {
	Token    string `json:"token"`
	HostName string `json:"hostName"`
	OS       string `json:"os"`
}

type Session struct {
	PID       int       `json:"pid"`
	ID        string    `json:"id"`
	Cwd       string    `json:"cwd"`
	StartedAt time.Time `json:"startedAt"`
}

type Report struct {
	HostID         string    `json:"hostId"`
	ActiveIdentity string    `json:"activeIdentity"`
	Sessions       []Session `json:"sessions"`
	CredsPresent   bool      `json:"credsPresent"`
}

type ExportRes struct {
	Block    json.RawMessage `json:"block,omitempty"`
	Identity string          `json:"identity,omitempty"`
	// Err goes on the wire as-is: callers must logx.Redact it before setting.
	Err string `json:"err,omitempty"`
}

type SwapReq struct {
	Block   json.RawMessage `json:"block"`
	Account string          `json:"account"`
}

// MarshalJSON emits an empty array, never null, for absent sessions.
func (r Report) MarshalJSON() ([]byte, error) {
	type plain Report
	p := plain(r)
	if p.Sessions == nil {
		p.Sessions = []Session{}
	}
	return json.Marshal(p)
}

// Credential-bearing types never print their secrets via fmt or slog.

// Identity-like strings (account, identity, host) may be email addresses, so they pass through logx.Redact.

func (e Envelope) String() string {
	return fmt.Sprintf("Envelope{V:%d Type:%s ID:%s Body:%s}", e.V, logx.Redact(e.Type), logx.Redact(e.ID), mask)
}
func (e Envelope) GoString() string { return e.String() }
func (e Envelope) LogValue() slog.Value {
	return slog.GroupValue(slog.Int("v", e.V), slog.String("type", logx.Redact(e.Type)),
		slog.String("id", logx.Redact(e.ID)), slog.String("body", mask))
}

func (h Hello) String() string {
	return fmt.Sprintf("Hello{HostName:%s OS:%s Token:%s}", logx.Redact(h.HostName), logx.Redact(h.OS), mask)
}
func (h Hello) GoString() string { return h.String() }
func (h Hello) LogValue() slog.Value {
	return slog.GroupValue(slog.String("hostName", logx.Redact(h.HostName)), slog.String("os", logx.Redact(h.OS)), slog.String("token", mask))
}

func (r ExportRes) String() string {
	return fmt.Sprintf("ExportRes{Identity:%s Block:%s Err:%s}", logx.Redact(r.Identity), mask, logx.Redact(r.Err))
}
func (r ExportRes) GoString() string { return r.String() }
func (r ExportRes) LogValue() slog.Value {
	return slog.GroupValue(slog.String("identity", logx.Redact(r.Identity)), slog.String("block", mask), slog.String("err", logx.Redact(r.Err)))
}

func (r SwapReq) String() string {
	return fmt.Sprintf("SwapReq{Account:%s Block:%s}", logx.Redact(r.Account), mask)
}
func (r SwapReq) GoString() string { return r.String() }
func (r SwapReq) LogValue() slog.Value {
	return slog.GroupValue(slog.String("account", logx.Redact(r.Account)), slog.String("block", mask))
}

// SwapRes deliberately has no credential field: results never echo secrets.
type SwapRes struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

// Encode marshals body into an envelope of the current Version.
func Encode(typ, id string, body any) ([]byte, error) {
	env := Envelope{V: Version, Type: typ, ID: id}
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode body: %w", err)
		}
		env.Body = raw
	}
	return json.Marshal(env)
}

// MaxMessageSize bounds a decoded frame (bytes).
const MaxMessageSize = 1 << 20

// Decode parses an envelope and rejects oversize frames and any version other than Version.
// It does not check ID presence: request/response dispatchers must reject an empty ID
// on export_req, export_res, swap_req and swap_res.
func Decode(b []byte) (Envelope, error) {
	if len(b) > MaxMessageSize {
		return Envelope{}, fmt.Errorf("message too large: %d bytes", len(b))
	}
	var env Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return Envelope{}, fmt.Errorf("decode envelope: %w", err)
	}
	if env.V != Version {
		return Envelope{}, fmt.Errorf("unsupported protocol version %d", env.V)
	}
	if env.Type == "" {
		return Envelope{}, errors.New("missing message type")
	}
	return env, nil
}
