//go:build windows

package sessions

import (
	"context"
	"math"
	"strconv"
	"syscall"

	"claude-utilities/internal/proto"
)

// Scan lists live sessions from ~/.claude/sessions.
func Scan(ctx context.Context) ([]proto.Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	return scanDir(dir, processAlive)
}

// Alive reports whether pid is a live process whose creation time matches procStart. It is the
// same gate Scan keeps a session on, exported so anything about to act on a session can insist on
// a live owner rather than on a file existing.
func Alive(pid int, procStart string) bool { return processAlive(pid, procStart) }

// processAlive is true when pid exists and its creation FILETIME equals procStart.
func processAlive(pid int, procStart string) bool {
	want, err := strconv.ParseUint(procStart, 10, 64)
	if err != nil {
		return false
	}
	if pid <= 0 || int64(pid) > math.MaxUint32 {
		return false
	}
	h, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer func() { _ = syscall.CloseHandle(h) }()
	var creation, exit, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return false
	}
	return uint64(creation.HighDateTime)<<32|uint64(creation.LowDateTime) == want
}
