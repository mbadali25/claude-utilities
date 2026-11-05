package sessions

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// claudeMarker identifies a Claude Code process. Claude Code is a Node CLI, so
// /proc/<pid>/comm is usually "node" (and comm truncates at 15 bytes); the
// marker is matched against comm first and then the whole command line.
const claudeMarker = "claude"

// statStartTimeIndex is the index of starttime (stat field 22) in the fields
// that follow the parenthesised comm. Fields 1 and 2 are pid and comm, so
// field 22 lands at 22-3 = 19.
const statStartTimeIndex = 19

// procStat is the part of /proc/<pid>/stat this package uses.
type procStat struct {
	comm       string // field 2, without its parentheses; may contain spaces and ')'
	state      string // field 3
	startTicks uint64 // field 22, clock ticks since boot
}

// parseProcStat reads comm, state and starttime out of one /proc/<pid>/stat
// line. comm is delimited by the first '(' and the LAST ')', because a process
// name may itself contain parentheses and spaces.
func parseProcStat(s string) (procStat, error) {
	lo := strings.IndexByte(s, '(')
	hi := strings.LastIndexByte(s, ')')
	if lo < 0 || hi < lo {
		return procStat{}, fmt.Errorf("sessions: proc stat: no comm field")
	}
	rest := strings.Fields(s[hi+1:])
	if len(rest) <= statStartTimeIndex {
		return procStat{}, fmt.Errorf("sessions: proc stat: only %d fields after comm", len(rest))
	}
	ticks, err := strconv.ParseUint(rest[statStartTimeIndex], 10, 64)
	if err != nil {
		return procStat{}, fmt.Errorf("sessions: proc stat: starttime: %w", err)
	}
	return procStat{comm: s[lo+1 : hi], state: rest[0], startTicks: ticks}, nil
}

// readProcStat loads <root>/<pid>/stat.
func readProcStat(root string, pid int) (procStat, error) {
	// #nosec G304 -- the path is <root>/<pid>/stat: root is a fixed mount point and pid an int, never caller text
	raw, err := os.ReadFile(filepath.Join(root, strconv.Itoa(pid), "stat"))
	if err != nil {
		return procStat{}, fmt.Errorf("sessions: proc stat: %w", err)
	}
	return parseProcStat(string(raw))
}

// procAlive reports whether pid under root is a live Claude Code process.
//
// procStart is the producer's record of when the process started. Its Linux
// format is NOT verified (the spike only ever observed Windows sessions), so a
// value that does not parse as a decimal clock-tick count is treated as no
// evidence either way rather than as a dead process: an unknown format must not
// silently hide every session. A value that does parse must equal the pid's
// starttime, which is what rules out a reused pid.
//
// Liveness also requires the process to look like Claude Code, so an unrelated
// program that inherited the pid is never reported as a session.
func procAlive(root string, pid int, procStart string) bool {
	if pid <= 0 {
		return false
	}
	st, err := readProcStat(root, pid)
	if err != nil {
		return false
	}
	if st.state == "Z" || st.state == "X" { // reaped or dying: no session to reload
		return false
	}
	if want, err := strconv.ParseUint(strings.TrimSpace(procStart), 10, 64); err == nil && want != st.startTicks {
		return false // the pid was reused by a different process
	}
	return isClaudeProcess(root, pid, st.comm)
}

// isClaudeProcess matches claudeMarker in comm, else in <root>/<pid>/cmdline.
// Only comm and cmdline are read; /proc/<pid>/environ holds secrets and is not.
func isClaudeProcess(root string, pid int, comm string) bool {
	if hasClaudeMarker(comm) {
		return true
	}
	// #nosec G304 -- the path is <root>/<pid>/cmdline: root is a fixed mount point and pid an int, never caller text
	raw, err := os.ReadFile(filepath.Join(root, strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return false
	}
	return hasClaudeMarker(string(bytes.ReplaceAll(raw, []byte{0}, []byte{' '})))
}

func hasClaudeMarker(s string) bool {
	return strings.Contains(strings.ToLower(s), claudeMarker)
}
