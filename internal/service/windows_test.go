//go:build windows

package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"

	"claude-utilities/internal/logx"
)

// bootNow is the boot instant every handler test writes and reads, so the marker rule's boot
// condition holds without reading the real one.
func bootNow() time.Time { return time.Date(2026, 11, 8, 9, 0, 0, 0, time.UTC) }

// driver runs one Handler.Execute and gives the test the three things it has to be able to do:
// send change requests, make the server report progress, and make the server return.
type driver struct {
	req  chan svc.ChangeRequest
	st   chan svc.Status
	prog chan string
	ret  chan int

	cancelled chan struct{}
	finished  chan struct{}
	ssec      bool
	code      uint32
	log       *strings.Builder
	events    []string
}

// start builds a Handler whose Run is driven entirely from the test, and runs Execute in a
// goroutine. No SCM is involved: svc.ChangeRequest and svc.Status are plain values.
func start(t *testing.T, dir string, tune func(*Handler)) *driver {
	t.Helper()
	d := &driver{
		req:       make(chan svc.ChangeRequest, 8),
		st:        make(chan svc.Status, 256),
		prog:      make(chan string, 8),
		ret:       make(chan int, 2),
		cancelled: make(chan struct{}),
		finished:  make(chan struct{}),
		log:       &strings.Builder{},
	}
	h := &Handler{
		Dir:   dir,
		Table: ServerTable(),
		Log:   logx.New(d.log),
		Event: func(_ EventLevel, text string) { d.events = append(d.events, text) },
		Now:   func() time.Time { return bootNow().Add(time.Minute) },
		Boot:  bootNow,
		// Long enough that no test depends on the keepalive firing; the stage tests drive progress
		// themselves.
		Keepalive: time.Hour,
		Run: func(ctx context.Context, progress func(stage string)) int {
			for {
				select {
				case stage := <-d.prog:
					progress(stage)
				case code := <-d.ret:
					return code
				case <-ctx.Done():
					close(d.cancelled)
					select {
					case code := <-d.ret:
						return code
					case <-time.After(2 * time.Second):
						return 0
					}
				}
			}
		},
	}
	if tune != nil {
		tune(h)
	}
	go func() {
		d.ssec, d.code = h.Execute([]string{WindowsServiceName}, d.req, d.st)
		close(d.finished)
	}()
	return d
}

// wait blocks until Execute has returned, so the collected statuses are complete.
func (d *driver) wait(t *testing.T) {
	t.Helper()
	select {
	case <-d.finished:
	case <-time.After(10 * time.Second):
		t.Fatal("Execute did not return")
	}
}

// statuses drains every status Execute sent, in order.
func (d *driver) statuses(t *testing.T) []svc.Status {
	t.Helper()
	d.wait(t)
	var out []svc.Status
	for {
		select {
		case s := <-d.st:
			out = append(out, s)
		default:
			return out
		}
	}
}

// awaitState waits for a status in the given state to be sent, returning every status up to and
// including it. It is how a test gets past "starting" without a sleep.
func (d *driver) awaitState(t *testing.T, want svc.State) []svc.Status {
	t.Helper()
	var seen []svc.Status
	deadline := time.After(10 * time.Second)
	for {
		select {
		case s := <-d.st:
			seen = append(seen, s)
			if s.State == want {
				return seen
			}
		case <-deadline:
			t.Fatalf("no %v status arrived; saw %+v", want, seen)
		case <-d.finished:
			t.Fatalf("Execute returned (%v, %d) before a %v status; saw %+v", d.ssec, d.code, want, seen)
		}
		_ = seen
	}
}

// TestExecuteReportsStartPendingWithCheckpointOne: the SCM kills a service that does not report in,
// so the very first thing Execute does, before touching the marker or the vault, is claim the time
// it needs.
func TestExecuteReportsStartPendingWithCheckpointOne(t *testing.T) {
	d := start(t, t.TempDir(), nil)
	first := d.awaitState(t, svc.StartPending)[0]
	if first.State != svc.StartPending {
		t.Fatalf("the first status is %v, want StartPending", first.State)
	}
	if first.CheckPoint != 1 {
		t.Fatalf("the first checkpoint is %d, want 1", first.CheckPoint)
	}
	if first.WaitHint != uint32(DefaultStartWaitHint/time.Millisecond) {
		t.Fatalf("the first wait hint is %d ms, want %d ms", first.WaitHint,
			DefaultStartWaitHint/time.Millisecond)
	}
	d.ret <- 0
	d.wait(t)
}

// TestExecuteAdvancesTheCheckpointPerStage: three slow stages, three strictly increasing
// checkpoints, and the wait hint re-sent every time - a checkpoint that advances with no hint
// beside it does not extend the SCM's patience.
func TestExecuteAdvancesTheCheckpointPerStage(t *testing.T) {
	d := start(t, t.TempDir(), nil)
	d.awaitState(t, svc.StartPending)
	for _, stage := range []string{"argon2id", "machine-key", "certificate"} {
		d.prog <- stage
	}
	// Four StartPending statuses in all: the opening one plus one per stage.
	var pending []svc.Status
	deadline := time.After(10 * time.Second)
	for len(pending) < 3 {
		select {
		case s := <-d.st:
			if s.State == svc.StartPending {
				pending = append(pending, s)
			}
		case <-deadline:
			t.Fatalf("only %d further StartPending statuses arrived", len(pending))
		}
	}
	last := uint32(1)
	for _, s := range pending {
		if s.CheckPoint <= last {
			t.Fatalf("checkpoint %d did not advance past %d", s.CheckPoint, last)
		}
		if s.WaitHint == 0 {
			t.Fatalf("checkpoint %d was sent with no wait hint", s.CheckPoint)
		}
		last = s.CheckPoint
	}
	d.ret <- 0
	d.wait(t)
}

// TestExecuteAcceptsOnlyInterrogateWhileStarting: a Stop the SCM was never told the service accepts
// still has to be handled (the SCM sends it on shutdown), but the mask must advertise nothing while
// starting - an advertised Stop on a half-started service invites one before the vault is open.
func TestExecuteAcceptsOnlyInterrogateWhileStarting(t *testing.T) {
	d := start(t, t.TempDir(), nil)
	d.awaitState(t, svc.StartPending)
	d.req <- svc.ChangeRequest{Cmd: svc.Interrogate}
	// The interrogate answer is another StartPending with the same mask.
	deadline := time.After(10 * time.Second)
	got := 0
	for got < 1 {
		select {
		case s := <-d.st:
			if s.State != svc.StartPending {
				t.Fatalf("state %v while starting", s.State)
			}
			if s.Accepts != 0 {
				t.Fatalf("Accepts %#x while starting, want 0", s.Accepts)
			}
			got++
		case <-deadline:
			t.Fatal("the interrogate was never answered")
		}
	}
	d.ret <- 0
	for _, s := range d.statuses(t) {
		if s.State == svc.StartPending && s.Accepts != 0 {
			t.Fatalf("Accepts %#x on a StartPending status, want 0", s.Accepts)
		}
	}
}

// TestExecuteAcceptsStopAndShutdownOnlyWhenRunning: exactly those two bits. A paused server holding
// the data-dir lock is a state with no meaning here, so AcceptPauseAndContinue must not be in the
// mask - and neither must anything else that would make the SCM send a control the handler ignores.
func TestExecuteAcceptsStopAndShutdownOnlyWhenRunning(t *testing.T) {
	d := start(t, t.TempDir(), nil)
	d.awaitState(t, svc.StartPending)
	d.prog <- ReadyStage
	running := d.awaitState(t, svc.Running)
	last := running[len(running)-1]
	if want := svc.AcceptStop | svc.AcceptShutdown; last.Accepts != want {
		t.Fatalf("Accepts %#x when running, want %#x", last.Accepts, want)
	}
	if last.Accepts&svc.AcceptPauseAndContinue != 0 {
		t.Fatal("the running mask accepts pause and continue")
	}
	if last.CheckPoint != 0 || last.WaitHint != 0 {
		t.Fatalf("the running status carries checkpoint %d and hint %d; both must be zero once there "+
			"is no pending operation", last.CheckPoint, last.WaitHint)
	}
	d.ret <- 0
	d.wait(t)
}

// TestStopCancelsTheContextAndReportsStopPending: the same context the console path cancels on
// SIGTERM, and a StopPending whose hint covers the existing 5 s drain.
func TestStopCancelsTheContextAndReportsStopPending(t *testing.T) {
	d := start(t, t.TempDir(), nil)
	d.awaitState(t, svc.StartPending)
	d.prog <- ReadyStage
	d.awaitState(t, svc.Running)
	d.req <- svc.ChangeRequest{Cmd: svc.Stop}

	select {
	case <-d.cancelled:
	case <-time.After(10 * time.Second):
		t.Fatal("Stop did not cancel the run context")
	}
	d.ret <- 0
	all := d.statuses(t)
	var stopping *svc.Status
	for i := range all {
		if all[i].State == svc.StopPending {
			stopping = &all[i]
		}
	}
	if stopping == nil {
		t.Fatalf("no StopPending status was sent: %+v", all)
	}
	if stopping.WaitHint < uint32(DefaultStopWaitHint/time.Millisecond) {
		t.Fatalf("the stop hint is %d ms, too short to cover the drain (%d ms)",
			stopping.WaitHint, DefaultStopWaitHint/time.Millisecond)
	}
	if d.ssec || d.code != 0 {
		t.Fatalf("Execute returned (%v, %d) for a clean stop, want (false, 0)", d.ssec, d.code)
	}
}

// TestShutdownIsTreatedLikeStop: a machine shutting down gets the same drain, not a kill.
func TestShutdownIsTreatedLikeStop(t *testing.T) {
	d := start(t, t.TempDir(), nil)
	d.awaitState(t, svc.StartPending)
	d.prog <- ReadyStage
	d.awaitState(t, svc.Running)
	d.req <- svc.ChangeRequest{Cmd: svc.Shutdown}
	select {
	case <-d.cancelled:
	case <-time.After(10 * time.Second):
		t.Fatal("Shutdown did not cancel the run context")
	}
	d.ret <- 0
	d.wait(t)
	if d.ssec || d.code != 0 {
		t.Fatalf("Execute returned (%v, %d) for a shutdown, want (false, 0)", d.ssec, d.code)
	}
}

// TestFatalBeforeRunningReportsStoppedWithTheServiceSpecificCode: a vault no slot could unwrap is
// exit 3, and the SCM has to see it as a service-specific code or `sc query` shows 1066 with no
// number behind it. The marker is written so the next automatic start does not retry it.
func TestFatalBeforeRunningReportsStoppedWithTheServiceSpecificCode(t *testing.T) {
	dir := t.TempDir()
	d := start(t, dir, nil)
	d.awaitState(t, svc.StartPending)
	d.ret <- 3
	d.wait(t)
	if !d.ssec || d.code != 3 {
		t.Fatalf("Execute returned (%v, %d), want (true, 3)", d.ssec, d.code)
	}
	m, ok := ReadMarker(dir)
	if !ok {
		t.Fatal("no marker was written for a fatal before Running")
	}
	if m.Exit != 3 {
		t.Fatalf("the marker records exit %d, want 3", m.Exit)
	}
	if m.Reason != "vault-locked" {
		t.Fatalf("the marker reason is %q, want vault-locked", m.Reason)
	}
	if !m.Boot.Equal(bootNow()) {
		t.Fatalf("the marker boot is %s, want %s", m.Boot, bootNow())
	}
}

// TestARetryableFailureWritesNoMarker is the mutation check on the row above: exit 1 is the code a
// supervisor SHOULD retry, so a marker there would refuse a start the SCM was right to make.
func TestARetryableFailureWritesNoMarker(t *testing.T) {
	dir := t.TempDir()
	d := start(t, dir, nil)
	d.awaitState(t, svc.StartPending)
	d.ret <- 1
	d.wait(t)
	if !d.ssec || d.code != 1 {
		t.Fatalf("Execute returned (%v, %d), want (true, 1)", d.ssec, d.code)
	}
	if _, ok := ReadMarker(dir); ok {
		t.Fatal("a marker was written for exit 1, which a restart can fix")
	}
}

// TestAFatalAfterRunningStillWritesTheMarker: a vault that goes unreadable, or a listener that dies,
// after readiness is still a code a restart cannot fix.
func TestAFatalAfterRunningStillWritesTheMarker(t *testing.T) {
	dir := t.TempDir()
	d := start(t, dir, nil)
	d.awaitState(t, svc.StartPending)
	d.prog <- ReadyStage
	d.awaitState(t, svc.Running)
	d.ret <- 5
	d.wait(t)
	if !d.ssec || d.code != 5 {
		t.Fatalf("Execute returned (%v, %d), want (true, 5)", d.ssec, d.code)
	}
	m, ok := ReadMarker(dir)
	if !ok {
		t.Fatal("no marker was written for exit 5 after Running")
	}
	if m.Reason != "cert-refused" {
		t.Fatalf("the marker reason is %q, want cert-refused", m.Reason)
	}
}

// TestMarkerRefusalReportsStoppedAndIsNotAFreshFailure is revision 8 item 13: a refusal reports a
// PRIOR fatal. Run is never entered, the recorded code is reported again, the line says why, and
// the event log gets it - but nothing new is written, so the SCM's chain has nothing fresh to count.
func TestMarkerRefusalReportsStoppedAndIsNotAFreshFailure(t *testing.T) {
	dir := t.TempDir()
	if err := WriteMarker(dir, Marker{Exit: 4, Reason: "format", TS: bootNow().Add(30 * time.Second), Boot: bootNow()}); err != nil {
		t.Fatalf("WriteMarker: %v", err)
	}
	before, _ := ReadMarker(dir)

	ran := false
	d := start(t, dir, func(h *Handler) {
		h.Run = func(context.Context, func(string)) int { ran = true; return 0 }
	})
	d.wait(t)
	if ran {
		t.Fatal("Run was entered despite the marker refusal")
	}
	if !d.ssec || d.code != 4 {
		t.Fatalf("Execute returned (%v, %d), want (true, 4) - the recorded code", d.ssec, d.code)
	}
	after, ok := ReadMarker(dir)
	if !ok {
		t.Fatal("the refusal deleted the marker; the next start would then run")
	}
	if after != before {
		t.Fatalf("the refusal rewrote the marker: %+v then %+v", before, after)
	}
	line := d.log.String()
	if !strings.Contains(line, "start refused") || !strings.Contains(line, "last-fatal") {
		t.Fatalf("the log does not say the start was refused and why: %q", line)
	}
	if len(d.events) == 0 {
		t.Fatal("the refusal raised no event-log line")
	}
	if !strings.Contains(strings.Join(d.events, "\n"), "last-fatal") {
		t.Fatalf("the event does not name the reason: %q", d.events)
	}
}

// TestMarkerRefusalDoesNotFireAfterAReboot: the boot condition. A marker from the previous boot is
// deleted and the start proceeds, because a reboot always gets one honest attempt.
func TestMarkerRefusalDoesNotFireAfterAReboot(t *testing.T) {
	dir := t.TempDir()
	if err := WriteMarker(dir, Marker{Exit: 3, Reason: "vault-locked",
		TS: bootNow().Add(30 * time.Second), Boot: bootNow().Add(-24 * time.Hour)}); err != nil {
		t.Fatalf("WriteMarker: %v", err)
	}
	d := start(t, dir, nil)
	d.awaitState(t, svc.StartPending)
	d.ret <- 0
	d.wait(t)
	if d.ssec || d.code != 0 {
		t.Fatalf("Execute returned (%v, %d) after a previous-boot marker, want (false, 0)", d.ssec, d.code)
	}
}

// TestExecuteNeverLogsAValue: every line the handler writes goes through logx, so a key that is not
// on the allowlist renders as [dropped]. A handler that logged a path, an address or a passphrase
// would show up here as a dropped field rather than as a leak - and this test fails either way,
// because a dropped field is a line that was written wrong.
func TestExecuteNeverLogsAValue(t *testing.T) {
	dir := t.TempDir()
	if err := WriteMarker(dir, Marker{Exit: 2, Reason: "usage",
		TS: bootNow().Add(30 * time.Second), Boot: bootNow()}); err != nil {
		t.Fatalf("WriteMarker: %v", err)
	}
	d := start(t, dir, nil)
	d.wait(t)

	out := d.log.String()
	if strings.Contains(out, "[dropped]") {
		t.Fatalf("a log line carries a key that is not on the allowlist: %q", out)
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var fields map[string]any
		if err := json.Unmarshal([]byte(line), &fields); err != nil {
			t.Fatalf("the handler wrote a line that is not JSON: %q", line)
		}
		for k := range fields {
			if strings.Contains(strings.ToLower(k), "dir") && k != "datadir" {
				t.Fatalf("the line carries %q, which is a path key logx does not redact: %q", k, line)
			}
		}
	}
	if strings.Contains(out, dir) {
		t.Fatalf("a log line carries the data directory verbatim: %q", out)
	}
}

// TestIsWindowsServiceIsFalseUnderGoTest: `svc.Run` is entered only when this is true, so a test
// process - and a console `server run` - must take the console path. If this ever returned true
// under `go test`, the whole suite would try to talk to the SCM.
func TestIsWindowsServiceIsFalseUnderGoTest(t *testing.T) {
	if IsWindowsService() {
		t.Fatal("IsWindowsService is true in a test process")
	}
}

// TestBootInstantOnWindowsIsReal: the Windows reader is now - GetTickCount64(), rounded to the
// second, so the marker's boot condition compares something. The shared
// TestBootInstantIsZeroOrInThePast covers the bounds; this covers "not zero", which is what this
// slice changed.
func TestBootInstantOnWindowsIsReal(t *testing.T) {
	got := BootInstant()
	if got.IsZero() {
		t.Fatal("BootInstant is the zero instant on windows; the marker's boot condition is then vacuous")
	}
	if !got.Equal(got.Truncate(time.Second)) {
		t.Fatalf("boot instant %s is not rounded to the second", got)
	}
	if got.After(time.Now()) {
		t.Fatalf("boot instant %s is in the future", got)
	}
}

// TestReasonForExitCoversEveryNonRestartingRow: the marker's reason is a plain token, and every
// code the server's table holds needs one - UnspecifiedReason in a marker tells an operator
// nothing. The mutation this catches is a new row added to ServerTable with no token beside it.
func TestReasonForExitCoversEveryNonRestartingRow(t *testing.T) {
	for _, r := range ServerTable().Rows() {
		reason := reasonForExit(r.Code)
		if reason == UnspecifiedReason || reason == "" {
			t.Fatalf("exit %d has no reason token", r.Code)
		}
		if got := cleanReason(reason); got != reason {
			t.Fatalf("the reason %q for exit %d is not a plain token (became %q)", reason, r.Code, got)
		}
	}
}
