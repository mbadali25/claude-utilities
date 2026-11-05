//go:build windows

package agent

import "os"

// hupSignal has nothing to deliver on Windows: there is no SIGHUP, so the identity is refreshed
// by the ticker alone. A nil channel blocks for ever in the watcher's select, which is what we
// want.
func hupSignal() (<-chan os.Signal, func()) { return nil, func() {} }
