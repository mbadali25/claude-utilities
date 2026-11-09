//go:build !linux

package service

import (
	"strconv"
	"time"
)

// This is the readiness half for every platform that is not Linux. Windows has no sd_notify: the
// service handler reports StartPending with a checkpoint and then Running through the SCM, which is
// slice 4b's `svc.Handler`, so the calls here are no-ops rather than errors. A console run on any
// platform takes the same path, which is why `server run` needs no build tag of its own.

// notifySocket is always empty off Linux: there is no notification socket to write to, and reading
// the variable would let an inherited NOTIFY_SOCKET make this build attempt a write it cannot make.
func notifySocket() string { return "" }

// NotifyReady does nothing and succeeds. A caller must still call it where the Linux build needs it
// - after the last thing that can fail - so one code path serves both.
func NotifyReady() error { return nil }

// NotifyStopping does nothing and succeeds.
func NotifyStopping() error { return nil }

// JournalStream is false off Linux: there is no journal to be the stream.
func JournalStream() bool { return false }

// stderrDevIno has no answer here. The pair exists in this build only so the shared test can ask
// for it and skip.
func stderrDevIno() (dev, ino uint64, ok bool) { return 0, 0, false }

// formatDevIno renders the pair the way systemd sets it. Defined in both builds so the shared test
// compiles; off Linux nothing produces a value to format.
func formatDevIno(dev, ino uint64) string {
	return strconv.FormatUint(dev, 10) + ":" + strconv.FormatUint(ino, 10)
}

// BootInstant is the zero instant here. Windows' reader is `now - GetTickCount64()` and it needs
// golang.org/x/sys/windows, which cannot be imported from a file this build shares with darwin and
// the BSDs; it lands with the Windows service handler in slice 4b, in internal/service/windows.go,
// where it is the only consumer that needs it.
//
// Until then the marker rule degrades honestly rather than wrongly: the same zero instant is
// written and read, so the boot condition holds and MarkerMaxAge alone bounds the refusal. The
// failure mode of the alternative - a reader that returned "now" - would be a marker that never
// matched and a restart loop that the marker was written to stop.
func BootInstant() time.Time { return time.Time{} }
