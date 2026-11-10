//go:build !linux && !windows

package service

import (
	"strconv"
	"time"
)

// This is the readiness half for every platform that is neither Linux nor Windows: the BSDs, darwin
// and anything else the gate builds. The same no-ops exist in windows.go, which owns the Windows
// half of this package, because Windows has no sd_notify at all - the service handler reports
// StartPending with a checkpoint and then Running through the SCM. A console run on any platform
// takes the same path, which is why `server run` needs no build tag of its own.
//
// Windows is excluded from this file rather than sharing it so BootInstant can have a real reader
// there: a reader that needs golang.org/x/sys/windows cannot live in a file darwin also compiles.

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

// BootInstant is the zero instant on these platforms: nothing here runs as a service, so no boot
// reader was written. Windows' reader lives in windows.go and Linux's in notify_linux.go.
//
// The marker rule degrades honestly rather than wrongly: the same zero instant is written and read,
// so the boot condition holds and MarkerMaxAge alone bounds the refusal. The failure mode of the
// alternative - a reader that returned "now" - would be a marker that never matched and a restart
// loop that the marker was written to stop.
func BootInstant() time.Time { return time.Time{} }
