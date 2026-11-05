//go:build linux

package sessions

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

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
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("sessions: home dir: %w", err)
	}
	return scanDir(filepath.Join(home, ".claude", "sessions"), func(pid int, procStart string) bool {
		return procAlive(procRoot, pid, procStart)
	})
}
