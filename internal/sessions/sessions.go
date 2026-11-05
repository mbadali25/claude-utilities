// Package sessions finds live Claude Code sessions on this host.
//
// Windows reads ~/.claude/sessions/<pid>.json (spike S3) and keeps a record only
// while the pid is alive and its process start time matches procStart.
// The Linux scan is NOT implemented: the spike never observed a live Linux session.
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

// ErrNotImplemented is returned by Scan on platforms without a proven scan.
var ErrNotImplemented = errors.New("sessions: scan not implemented on this OS")

// record is one session file. procStart is kept for liveness checks only.
type record struct {
	PID       int    `json:"pid"`
	SessionID string `json:"sessionId"`
	Cwd       string `json:"cwd"`
	StartedAt int64  `json:"startedAt"` // unix ms
	ProcStart string `json:"procStart"`
}

func (r record) session() proto.Session {
	return proto.Session{PID: r.PID, ID: r.SessionID, Cwd: r.Cwd, StartedAt: time.UnixMilli(r.StartedAt)}
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
		raw, err := os.ReadFile(filepath.Join(dir, name))
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
