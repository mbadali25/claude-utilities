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
