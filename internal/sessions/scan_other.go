//go:build !windows && !linux

package sessions

import (
	"context"

	"claude-utilities/internal/proto"
)

// Scan is an explicit stub: only the Windows and Linux scans are proven.
func Scan(_ context.Context) ([]proto.Session, error) {
	return nil, ErrNotImplemented
}

// Alive is false on a platform with no liveness check: nothing may act on a session here on the
// strength of a file, because there is no way to tell a live owner from an orphan.
func Alive(_ int, _ string) bool { return false }
