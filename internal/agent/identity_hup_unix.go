//go:build !windows

package agent

import (
	"os"
	"os/signal"
	"syscall"
)

// hupSignal delivers SIGHUP, so `kill -HUP <agent pid>` makes the agent re-read the signed-in
// identity at once instead of waiting for the next refresh. The agent's shutdown signals are
// handled in cmd/agent (SIGINT, SIGTERM); SIGHUP is handled only here and never ends the process.
func hupSignal() (<-chan os.Signal, func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	return ch, func() { signal.Stop(ch) }
}
