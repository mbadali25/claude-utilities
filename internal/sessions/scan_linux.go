//go:build linux

package sessions

import (
	"context"

	"claude-utilities/internal/proto"
)

// procRoot is the procfs mount point. Tests inject a fake tree instead.
const procRoot = "/proc"

// Scan lists live sessions from ~/.claude/sessions, the same directory the
// Windows scan reads. A record is kept only while its pid is a live Claude Code
// process under /proc; see procAlive for how a reused pid is ruled out and what
// the unverified procStart format means here.
func Scan(ctx context.Context) ([]proto.Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	return scanDir(dir, Alive)
}

// Alive reports whether pid is a live Claude Code process whose starttime matches procStart. It is
// the same gate Scan keeps a session on, exported so anything about to act on a session can insist
// on a live owner rather than on a file existing.
func Alive(pid int, procStart string) bool { return procAlive(procRoot, pid, procStart) }
