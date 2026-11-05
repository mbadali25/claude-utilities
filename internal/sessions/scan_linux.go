//go:build linux

package sessions

import (
	"context"

	"claude-utilities/internal/proto"
)

// Scan is an explicit stub: the spike (S3) observed no live Linux session, so
// no Linux behaviour is proven yet.
func Scan(ctx context.Context) ([]proto.Session, error) {
	return nil, ErrNotImplemented
}
