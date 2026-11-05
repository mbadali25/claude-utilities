// Package sessions finds live Claude Code sessions on this host.
//
// Both platforms read ~/.claude/sessions/<pid>.json (spike S3) and keep a record
// only while the pid is alive and its process start time matches procStart.
// Windows compares procStart against the process creation FILETIME. Linux reads
// /proc/<pid>/stat for the starttime and also requires the process to look like
// Claude Code; the Linux procStart format is unverified, so see procAlive for
// what an unparseable value means. Other platforms return ErrNotImplemented.
package sessions

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"claude-utilities/internal/proto"
)

// ErrNotImplemented is returned by Scan on platforms other than Windows and Linux.
var ErrNotImplemented = errors.New("sessions: scan not implemented on this OS")

// Dir is the directory Claude Code writes its session files to. It is the one place the path is
// built, so anything that acts on a session - the host report here, the agent's inbox - reads the
// same files. CLAUDE_CONFIG_DIR is deliberately NOT honoured: a session file is keyed on a pid
// that lives on this host, and pointing only part of the agent at another config dir would let it
// report a session from one directory and act on a different one.
func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("sessions: home dir: %w", err)
	}
	return filepath.Join(home, ".claude", "sessions"), nil
}

// record is one session file. procStart is kept for liveness checks only.
//
// Name is the session's own name: Claude Code 2.1.318 writes it to the sessions file as
// "name" (with "nameSource" saying whether it came from `/rename` or was derived), so a
// name never requires reading a transcript. Only this file is read.
//
// RemoteName has no producer in 2.1.318 — the sessions file carries no remote-control name
// — so it decodes as empty; it is read so a future field surfaces without a parser change.
// BridgeSessionID is the one remote-control marker the file does carry. It may be JSON
// null, which leaves it empty, and only the derived boolean leaves the host.
type record struct {
	PID             int    `json:"pid"`
	SessionID       string `json:"sessionId"`
	Cwd             string `json:"cwd"`
	StartedAt       int64  `json:"startedAt"` // unix ms
	ProcStart       string `json:"procStart"`
	Name            string `json:"name"`
	RemoteName      string `json:"remoteName"`
	Status          string `json:"status"`
	BridgeSessionID string `json:"bridgeSessionId"`
}

func (r record) session() proto.Session {
	return proto.Session{
		PID: r.PID, ID: r.SessionID, Cwd: r.Cwd, StartedAt: time.UnixMilli(r.StartedAt),
		// A whitespace-only name is no name: the UI falls back to the pid rather than
		// rendering a blank, invisible row heading.
		Name:          strings.TrimSpace(r.Name),
		RemoteName:    strings.TrimSpace(r.RemoteName),
		Status:        strings.TrimSpace(r.Status),
		RemoteControl: strings.TrimSpace(r.BridgeSessionID) != "",
	}
}

func parseRecords(raw []byte) ([]record, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, nil
	}
	var recs []record
	if raw[0] == '{' {
		var r record
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("sessions: parse: %w", err)
		}
		recs = []record{r}
	} else if err := json.Unmarshal(raw, &recs); err != nil {
		return nil, fmt.Errorf("sessions: parse: %w", err)
	}
	out := recs[:0]
	for _, r := range recs {
		if r.PID > 0 {
			out = append(out, r)
		}
	}
	return out, nil
}

// parse decodes a session file (one object) or an array of them.
func parse(raw []byte) ([]proto.Session, error) {
	recs, err := parseRecords(raw)
	if err != nil {
		return nil, err
	}
	out := make([]proto.Session, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.session())
	}
	return out, nil
}

// scanDir reads <pid>.json files in dir and keeps live ones. Unreadable or
// corrupt entries are skipped; <pid>.<hash>.key files (secrets) are never read.
func scanDir(dir string, alive func(pid int, procStart string) bool) ([]proto.Session, error) {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return []proto.Session{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sessions: read dir: %w", err)
	}
	out := []proto.Session{}
	for _, e := range ents {
		name := e.Name()
		// only "<pid>.json": exactly one dot, so "<pid>.<hash>.key" never matches
		if e.IsDir() || !strings.HasSuffix(name, ".json") || strings.Count(name, ".") != 1 {
			continue
		}
		raw, err := os.ReadFile(filepath.Clean(filepath.Join(dir, name)))
		if err != nil {
			continue
		}
		recs, err := parseRecords(raw)
		if err != nil {
			continue
		}
		for _, r := range recs {
			if alive(r.PID, r.ProcStart) {
				out = append(out, r.session())
			}
		}
	}
	return out, nil
}

// NeedsReload returns ids of sessions started before swappedAt. A session with
// no id is keyed on its pid as "pid:<n>".
func NeedsReload(sessions []proto.Session, swappedAt time.Time) []string {
	out := []string{}
	for _, s := range sessions {
		if !s.StartedAt.Before(swappedAt) {
			continue
		}
		id := s.ID
		if id == "" {
			id = fmt.Sprintf("pid:%d", s.PID)
		}
		out = append(out, id)
	}
	return out
}
