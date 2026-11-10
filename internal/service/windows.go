//go:build windows

package service

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// This file is the Windows half of the package: the SCM state machine, the boot reader the marker
// rule compares against, and the readiness no-ops that have no meaning without sd_notify. They are
// together because they share one build constraint and one consumer; notify_other.go holds the same
// no-ops for every platform that is neither Linux nor Windows.

const (
	// DefaultStartWaitHint is what the handler asks the SCM for while starting. argon2id at
	// t=3/m=64 MiB plus CryptUnprotectData plus EnsureCert's key read and parse can exceed the
	// SCM's default patience, and a service that does not report in is killed as hung.
	DefaultStartWaitHint = 30 * time.Second

	// DefaultStopWaitHint covers the existing 5 s drain with margin. It is the hint, not a timeout:
	// the handler waits for the run to return.
	DefaultStopWaitHint = 10 * time.Second

	// DefaultKeepalive is how often the handler advances the checkpoint on its own while starting.
	// A stage that takes longer than the wait hint and reports no progress would otherwise be
	// killed; this is the floor under the per-stage progress calls, not a replacement for them.
	DefaultKeepalive = 10 * time.Second

	// ReadyStage is the progress stage that means "the server is up": the lock is held, the
	// certificate passed, the vault and keyring are open and the listener is bound. It is the same
	// point in the start-up the Linux half sends READY=1 at, so one ordering contract serves both -
	// the service host passes a progress function as the server's readiness seam.
	ReadyStage = "ready"

	// markerRefusedReason is the `reason` on the line a refused start logs. The marker is reporting
	// a PRIOR fatal, so the reason names the marker and not the original cause.
	markerRefusedReason = "last-fatal"
)

// EventLevel is how an event-log line is classified. The Application log is the only place an
// operator can read why a service never started, so start, stop and fatal all raise one.
type EventLevel int

const (
	// EventInfo is a normal lifecycle line: started, stopping, stopped.
	EventInfo EventLevel = iota
	// EventWarning is a line that needs attention but is not a failure.
	EventWarning
	// EventError is a fatal or a refused start.
	EventError
)

// IsWindowsService reports whether this process was started by the service control manager.
// `svc.Run` is entered only when it is true, so `server run` from a console - and every test
// process - behaves exactly as it does today. An error from the probe is treated as "not a
// service", which is the fail-safe direction: the worst case is a console run, never a process
// waiting for an SCM that is not listening.
func IsWindowsService() bool {
	is, err := svc.IsWindowsService()
	return err == nil && is
}

// BootInstant is this machine's boot instant: now minus the time since boot, rounded to the second.
// The marker's `boot` field is compared against it so a reboot always gets one honest start attempt
// however fresh the marker is.
//
// GetTickCount64 (windows.DurationSinceBoot) does not count time the machine spent suspended, so
// two readings across a sleep can differ by more than the rounding. BootSkew is 2 s, so a suspend
// makes a marker look like it came from a different boot - the fail-open direction: the start
// proceeds.
func BootInstant() time.Time {
	return time.Now().Add(-windows.DurationSinceBoot()).Truncate(time.Second)
}

// The readiness half on Windows. There is no notification socket: the handler below reports
// StartPending with a checkpoint and then Running through the SCM, which is what the SCM waits for.
// The functions exist so `server run` needs no build tag of its own.

// notifySocket is always empty: reading NOTIFY_SOCKET here would let an inherited value make this
// build attempt a write it cannot make.
func notifySocket() string { return "" }

// NotifyReady does nothing and succeeds. The service host replaces the server's readiness seam with
// one that calls the handler's progress function, so the ordering contract - readiness after the
// last thing that can fail - is the same on both OSes.
func NotifyReady() error { return nil }

// NotifyStopping does nothing and succeeds.
func NotifyStopping() error { return nil }

// JournalStream is false: there is no journal to be the stream.
func JournalStream() bool { return false }

// stderrDevIno has no answer here. The pair exists in this build only so the shared test can ask
// for it and skip.
func stderrDevIno() (dev, ino uint64, ok bool) { return 0, 0, false }

// formatDevIno renders the pair the way systemd sets it. Defined in every build so the shared test
// compiles; nothing on Windows produces a value to format.
func formatDevIno(dev, ino uint64) string {
	return strconv.FormatUint(dev, 10) + ":" + strconv.FormatUint(ino, 10)
}

// Handler is the service control manager's view of the server: one Execute that reports progress
// while starting, Running once the server is up, and a service-specific exit code when it is not.
//
// Run is the server's own entry point - the same function a console run calls - taking the context
// the console path cancels on SIGTERM and a progress function it calls at each slow stage and once
// at ReadyStage. Dir is the directory holding last-fatal.json, which is `<data-dir>\logs`, the same
// directory server.log lives in; passing the data dir instead would put the marker one level up and
// the refusal would silently never fire. Table is the binary's exit-code table, which decides which
// codes write a marker.
type Handler struct {
	// Run runs the server and returns its exit code.
	Run func(ctx context.Context, progress func(stage string)) int
	// Dir holds last-fatal.json: `<data-dir>\logs`.
	Dir string
	// Table is this binary's exit-code table.
	Table Table
	// Log receives one structured line per lifecycle event. nil discards them.
	Log *slog.Logger
	// Event raises an Application event-log line. nil skips it, which is what a test does.
	Event func(level EventLevel, text string)
	// Now and Boot are seams so the marker rule is testable without a clock or a platform.
	Now  func() time.Time
	Boot func() time.Time
	// StartWaitHint, StopWaitHint and Keepalive default to the constants above when zero.
	StartWaitHint time.Duration
	StopWaitHint  time.Duration
	Keepalive     time.Duration
}

// Execute is svc.Handler. It returns (serviceSpecific, code): svc.Run reports Stopped with
// ERROR_SERVICE_SPECIFIC_ERROR and that code, so the handler does not send a Stopped status itself
// and `sc query` shows the number rather than a bare 1066.
func (h *Handler) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	starting := svc.Status{
		State:      svc.StartPending,
		CheckPoint: 1,
		WaitHint:   millis(h.startHint()),
	}
	s <- starting

	// The marker refusal, first: revision 8 item 13. A refusal reports a PRIOR fatal, so it must not
	// start the server, must not write a new marker and must not look like a fresh failure to the
	// SCM's recovery chain - it reports the recorded code and stops.
	if m, refuse := ShouldRefuseStart(h.Dir, h.Table, h.now(), h.boot()); refuse {
		h.log(slog.LevelError, "start refused", "reason", markerRefusedReason, "exit", m.Exit)
		h.raise(EventError, "start refused reason="+markerRefusedReason+" exit="+strconv.Itoa(m.Exit))
		return true, uint32(m.Exit) // #nosec G115 -- ReadMarker refuses an exit outside 0-255
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan int, 1)
	progress := make(chan string, 16)
	go func() {
		done <- h.Run(ctx, func(stage string) {
			select {
			case progress <- stage:
			default: // a progress call must never block the server it is reporting on
			}
		})
	}()

	keepalive := time.NewTicker(h.keepalive())
	defer keepalive.Stop()

	running := false
	stopping := false
	current := starting
	for {
		select {
		case code := <-done:
			return h.finish(code, running)

		case stage := <-progress:
			if stage == ReadyStage && !running && !stopping {
				running = true
				keepalive.Stop()
				current = svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
				s <- current
				h.log(slog.LevelInfo, "service", "service", "started")
				h.raise(EventInfo, "started")
				continue
			}
			if !running && !stopping {
				starting.CheckPoint++
				current = starting
				s <- current
			}

		case <-keepalive.C:
			if !running && !stopping {
				starting.CheckPoint++
				current = starting
				s <- current
			}

		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- current
			case svc.Stop, svc.Shutdown:
				if stopping {
					continue
				}
				stopping = true
				keepalive.Stop()
				h.log(slog.LevelInfo, "service", "service", "stopping")
				h.raise(EventInfo, "stopping")
				cancel()
				current = svc.Status{State: svc.StopPending, CheckPoint: 1, WaitHint: millis(h.stopHint())}
				s <- current
			default:
				// Nothing else is in the accepted mask, so nothing else can arrive by request. An
				// unexpected control is answered with the current status rather than ignored.
				s <- current
			}
		}
	}
}

// finish records the fatal, if it is one, and renders Execute's return pair.
//
// A marker is written only for a code the table holds, which is exactly the set a restart cannot
// fix. Exit 1 is deliberately absent: it is the code a supervisor SHOULD retry, and a marker there
// would refuse a start the SCM was right to make.
func (h *Handler) finish(code int, wasRunning bool) (bool, uint32) {
	if code == 0 {
		h.log(slog.LevelInfo, "service", "service", "stopped", "exit", 0)
		h.raise(EventInfo, "stopped exit=0")
		return false, 0
	}
	reason := reasonForExit(code)
	if h.Table.IsNonRestarting(code) {
		if err := WriteMarker(h.Dir, Marker{Exit: code, Reason: reason, TS: h.now(), Boot: h.boot()}); err != nil {
			// The marker is a refusal for the NEXT start; failing to write it must not change this
			// exit code, or a fatal would be reported as something else because of a log directory.
			h.log(slog.LevelError, "service", "service", "marker-unwritten", "exit", code, "reason", reason)
		}
	}
	h.log(slog.LevelError, "service", "service", "fatal", "exit", code, "reason", reason)
	h.raise(EventError, "fatal exit="+strconv.Itoa(code)+" reason="+reason+" running="+strconv.FormatBool(wasRunning))
	return true, uint32(code) // #nosec G115 -- a process exit status is 0-255
}

// reasonForExit is the marker's reason token for one of the server's exit codes. The tokens are
// plain lower-case words so the marker stays something an operator can paste into a report, and
// every row of ServerTable has one - a row with no token would write UnspecifiedReason, which tells
// an operator nothing.
func reasonForExit(code int) string {
	switch code {
	case 2:
		return "usage"
	case 3:
		return "vault-locked"
	case 4:
		return "format"
	case 5:
		return "cert-refused"
	default:
		return "runtime"
	}
}

func (h *Handler) startHint() time.Duration {
	if h.StartWaitHint > 0 {
		return h.StartWaitHint
	}
	return DefaultStartWaitHint
}

func (h *Handler) stopHint() time.Duration {
	if h.StopWaitHint > 0 {
		return h.StopWaitHint
	}
	return DefaultStopWaitHint
}

func (h *Handler) keepalive() time.Duration {
	if h.Keepalive > 0 {
		return h.Keepalive
	}
	return DefaultKeepalive
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Handler) boot() time.Time {
	if h.Boot != nil {
		return h.Boot()
	}
	return BootInstant()
}

func (h *Handler) log(level slog.Level, msg string, args ...any) {
	if h.Log == nil {
		return
	}
	h.Log.Log(context.Background(), level, msg, args...)
}

func (h *Handler) raise(level EventLevel, text string) {
	if h.Event == nil {
		return
	}
	h.Event(level, text)
}

// millis renders a duration as the SCM's wait hint, which is milliseconds.
func millis(d time.Duration) uint32 {
	ms := d.Milliseconds()
	if ms < 0 {
		return 0
	}
	if ms > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(ms)
}
