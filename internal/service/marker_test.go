package service

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- Task 4.1: the fatal marker ---

// bootFixture is a boot instant far enough from the zero value that a test confusing the two is
// visible, and rounded to the second as the marker stores it.
func bootFixture() time.Time {
	return time.Date(2026, 11, 8, 9, 0, 0, 0, time.UTC)
}

func TestMarkerRoundTrip(t *testing.T) {
	dir := t.TempDir()
	now := bootFixture().Add(90 * time.Second)
	want := Marker{Exit: 3, Reason: "vault-locked", TS: now, Boot: bootFixture()}
	if err := WriteMarker(dir, want); err != nil {
		t.Fatalf("WriteMarker: %v", err)
	}
	got, ok := ReadMarker(dir)
	if !ok {
		t.Fatal("ReadMarker found nothing after a write")
	}
	if got.Exit != want.Exit || got.Reason != want.Reason {
		t.Fatalf("got %+v, want exit %d reason %q", got, want.Exit, want.Reason)
	}
	if !got.TS.Equal(now.Truncate(time.Second)) || !got.Boot.Equal(bootFixture()) {
		t.Fatalf("times round-tripped as ts=%s boot=%s", got.TS, got.Boot)
	}
	if err := DeleteMarker(dir); err != nil {
		t.Fatalf("DeleteMarker: %v", err)
	}
	if _, ok := ReadMarker(dir); ok {
		t.Fatal("ReadMarker still finds a deleted marker")
	}
	// Deleting one that is not there is not a failure: every start path calls it.
	if err := DeleteMarker(dir); err != nil {
		t.Fatalf("DeleteMarker on an absent marker: %v", err)
	}
}

// TestMarkerIsWrittenOnceAndReplacedNotAppended: the handler writes one marker per fatal, and the
// next fatal replaces it. Two markers, or a file with two JSON objects in it, would make the rule
// unreadable.
func TestMarkerIsWrittenOnceAndReplacedNotAppended(t *testing.T) {
	dir := t.TempDir()
	for _, m := range []Marker{
		{Exit: 2, Reason: "lock-held", TS: bootFixture(), Boot: bootFixture()},
		{Exit: 5, Reason: "cert-refused", TS: bootFixture().Add(time.Minute), Boot: bootFixture()},
	} {
		if err := WriteMarker(dir, m); err != nil {
			t.Fatalf("WriteMarker: %v", err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != MarkerFileName {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("directory holds %v, want only %s (a temp file left behind is a leak)", names, MarkerFileName)
	}
	b, err := os.ReadFile(filepath.Join(dir, MarkerFileName))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var m Marker
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("the file is not one JSON object: %v: %s", err, b)
	}
	if m.Exit != 5 || m.Reason != "cert-refused" {
		t.Fatalf("got %+v, want the second write to have replaced the first", m)
	}
}

// TestMarkerRefusesOnlyWhenAllThreeConditionsHold walks the spec's rule: the marker parses, its
// exit is one the table holds, it is younger than ten minutes, and its boot is this boot.
func TestMarkerRefusesOnlyWhenAllThreeConditionsHold(t *testing.T) {
	boot := bootFixture()
	now := boot.Add(5 * time.Minute)
	cases := []struct {
		name   string
		marker Marker
		refuse bool
	}{
		{"all three hold", Marker{Exit: 3, Reason: "vault-locked", TS: now.Add(-time.Minute), Boot: boot}, true},
		{"just inside ten minutes", Marker{Exit: 3, Reason: "vault-locked", TS: now.Add(-9*time.Minute - 59*time.Second), Boot: boot}, true},
		{"boot within the two-second skew", Marker{Exit: 4, Reason: "format", TS: now, Boot: boot.Add(-2 * time.Second)}, true},
		{"older than ten minutes", Marker{Exit: 3, Reason: "vault-locked", TS: now.Add(-11 * time.Minute), Boot: boot}, false},
		{"exactly ten minutes old", Marker{Exit: 3, Reason: "vault-locked", TS: now.Add(-10 * time.Minute), Boot: boot}, false},
		{"a prior boot", Marker{Exit: 3, Reason: "vault-locked", TS: now, Boot: boot.Add(-time.Hour)}, false},
		{"boot just outside the skew", Marker{Exit: 3, Reason: "vault-locked", TS: now, Boot: boot.Add(-3 * time.Second)}, false},
		{"exit 1 is retryable", Marker{Exit: 1, Reason: "runtime", TS: now, Boot: boot}, false},
		{"exit 0 is a clean stop", Marker{Exit: 0, Reason: "clean", TS: now, Boot: boot}, false},
		{"exit 6 is in no table", Marker{Exit: 6, Reason: "unknown", TS: now, Boot: boot}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := WriteMarker(dir, c.marker); err != nil {
				t.Fatalf("WriteMarker: %v", err)
			}
			got, refused := ShouldRefuseStart(dir, ServerTable(), now, boot)
			if refused != c.refuse {
				t.Fatalf("refused=%v, want %v for %+v", refused, c.refuse, c.marker)
			}
			if refused && got.Exit != c.marker.Exit {
				t.Fatalf("refused with exit %d, want %d", got.Exit, c.marker.Exit)
			}
			if _, stillThere := ReadMarker(dir); stillThere != c.refuse {
				t.Fatalf("marker on disk=%v, want %v: a start that proceeds deletes it", stillThere, c.refuse)
			}
		})
	}
}

// TestMarkerOlderThanTenMinutesIsDeletedAndTheStartProceeds states the worst case the rule accepts:
// one short-lived attempt per ten minutes, never a tight loop.
func TestMarkerOlderThanTenMinutesIsDeletedAndTheStartProceeds(t *testing.T) {
	dir := t.TempDir()
	boot := bootFixture()
	m := Marker{Exit: 5, Reason: "cert-refused", TS: boot.Add(time.Minute), Boot: boot}
	if err := WriteMarker(dir, m); err != nil {
		t.Fatalf("WriteMarker: %v", err)
	}
	if _, refused := ShouldRefuseStart(dir, ServerTable(), boot.Add(12*time.Minute), boot); refused {
		t.Fatal("refused a start twelve minutes after the fatal")
	}
	if _, ok := ReadMarker(dir); ok {
		t.Fatal("the stale marker is still on disk")
	}
}

// TestMarkerFromAPriorBootIsDeletedAndTheStartProceeds: a reboot always gets one honest attempt.
func TestMarkerFromAPriorBootIsDeletedAndTheStartProceeds(t *testing.T) {
	dir := t.TempDir()
	oldBoot := bootFixture()
	if err := WriteMarker(dir, Marker{Exit: 2, Reason: "lock-held", TS: oldBoot.Add(time.Minute), Boot: oldBoot}); err != nil {
		t.Fatalf("WriteMarker: %v", err)
	}
	newBoot := oldBoot.Add(30 * time.Minute)
	// Seconds after a reboot, so the ten-minute window would otherwise still be open.
	if _, refused := ShouldRefuseStart(dir, ServerTable(), oldBoot.Add(time.Minute+30*time.Second), newBoot); refused {
		t.Fatal("refused the first start after a reboot")
	}
	if _, ok := ReadMarker(dir); ok {
		t.Fatal("the prior boot's marker is still on disk")
	}
}

// TestMarkerWithAnOutOfRangeExitIsDeleted: exit 1 or 0 is never a refusal reason, and the table
// decides, not the marker. The agent's table is asked for a code the server's holds to prove the
// caller's table is the one consulted.
func TestMarkerWithAnOutOfRangeExitIsDeleted(t *testing.T) {
	boot := bootFixture()
	for _, exit := range []int{0, 1, 6, 243, -1} {
		dir := t.TempDir()
		if err := WriteMarker(dir, Marker{Exit: exit, Reason: "whatever", TS: boot, Boot: boot}); err != nil {
			t.Fatalf("WriteMarker: %v", err)
		}
		if _, refused := ShouldRefuseStart(dir, ServerTable(), boot, boot); refused {
			t.Fatalf("exit %d refused a start", exit)
		}
		if _, ok := ReadMarker(dir); ok {
			t.Fatalf("exit %d: the marker survived", exit)
		}
	}
}

func TestUnparseableMarkerIsDeletedAndTheStartProceeds(t *testing.T) {
	boot := bootFixture()
	for _, body := range []string{
		"", "   ", "not json at all", `{"exit":3,`, `{"exit":"three","ts":"2026-11-08T09:00:00Z"}`,
		`{"exit":3,"reason":"vault-locked","ts":"not-a-time","boot":"2026-11-08T09:00:00Z"}`,
		`{"exit":3,"reason":"vault-locked","boot":"2026-11-08T09:00:00Z"}`, // no ts at all
		strings.Repeat("x", 9<<10),
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, MarkerFileName), []byte(body), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, ok := ReadMarker(dir); ok {
			t.Fatalf("ReadMarker accepted %.20q", body)
		}
		if _, refused := ShouldRefuseStart(dir, ServerTable(), boot, boot); refused {
			t.Fatalf("refused a start on %.20q", body)
		}
		if _, err := os.Stat(filepath.Join(dir, MarkerFileName)); !os.IsNotExist(err) {
			t.Fatalf("the unreadable marker survived %.20q (stat err %v)", body, err)
		}
	}
}

// TestMarkerHoldsNoValues: the file carries a code, a reason token, and two instants. A reason that
// arrives carrying a path, an address or an identity is reduced to a token rather than written out,
// because this file is read by an operator and copied into a report.
func TestMarkerHoldsNoValues(t *testing.T) {
	dir := t.TempDir()
	leaks := []string{
		`C:\ProgramData\claude-swap-server\vault.bin`, "matthew@example.com",
		"sk-ant-abc123", "192.0.2.10:8443",
	}
	if err := WriteMarker(dir, Marker{
		Exit:   3,
		Reason: "vault locked opening " + strings.Join(leaks, " for "),
		TS:     bootFixture(),
		Boot:   bootFixture(),
	}); err != nil {
		t.Fatalf("WriteMarker: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, MarkerFileName))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	for _, leak := range leaks {
		if strings.Contains(string(b), leak) {
			t.Fatalf("the marker carries %q: %s", leak, b)
		}
	}
	got, ok := ReadMarker(dir)
	if !ok {
		t.Fatal("ReadMarker rejected a marker written with a dirty reason")
	}
	if got.Reason != UnspecifiedReason {
		t.Fatalf("reason %q, want %q", got.Reason, UnspecifiedReason)
	}
	// A clean token is kept as it is: the refusal line is only useful if it names the cause.
	if err := WriteMarker(dir, Marker{Exit: 3, Reason: "vault-locked", TS: bootFixture(), Boot: bootFixture()}); err != nil {
		t.Fatalf("WriteMarker: %v", err)
	}
	if got, _ := ReadMarker(dir); got.Reason != "vault-locked" {
		t.Fatalf("reason %q, want vault-locked kept verbatim", got.Reason)
	}
}

// TestMarkerFileIsOwnerOnly: it lives beside the logs in the data dir, so it gets the same
// treatment as every other file this repo writes there.
func TestMarkerFileIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not the ACL on windows; credfile.RestrictFile covers it and has its own tests")
	}
	dir := t.TempDir()
	if err := WriteMarker(dir, Marker{Exit: 2, Reason: "lock-held", TS: bootFixture(), Boot: bootFixture()}); err != nil {
		t.Fatalf("WriteMarker: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dir, MarkerFileName))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode %04o, want 0600", perm)
	}
}

// TestMarkerWithNoBootInstantStillRefusesWithinTheWindow pins the fallback this slice ships on every
// platform but Linux: BootInstant returns the zero instant where the OS reader has not landed yet
// (Windows' GetTickCount64 arrives with the service handler in slice 4b), so writer and reader agree
// on the zero value, the boot condition holds, and the ten-minute window alone bounds the refusal.
// When slice 4b lands a real reader this test still passes - and a reader that returns the zero
// instant on a platform that has one will fail the reboot test above.
func TestMarkerWithNoBootInstantStillRefusesWithinTheWindow(t *testing.T) {
	dir := t.TempDir()
	var noBoot time.Time
	now := bootFixture()
	if err := WriteMarker(dir, Marker{Exit: 4, Reason: "format", TS: now, Boot: noBoot}); err != nil {
		t.Fatalf("WriteMarker: %v", err)
	}
	if _, refused := ShouldRefuseStart(dir, ServerTable(), now.Add(time.Minute), noBoot); !refused {
		t.Fatal("a marker with no boot instant did not refuse inside the window")
	}
	if _, refused := ShouldRefuseStart(dir, ServerTable(), now.Add(11*time.Minute), noBoot); refused {
		t.Fatal("a marker with no boot instant refused outside the window")
	}
}

// TestBootInstantIsZeroOrInThePast: whatever the OS reader returns, it is never a future instant
// and never a moment before this machine could have booted.
func TestBootInstantIsZeroOrInThePast(t *testing.T) {
	got := BootInstant()
	if got.IsZero() {
		if runtime.GOOS == "linux" {
			t.Fatal("linux reads /proc/uptime and must return a real instant")
		}
		return
	}
	if now := time.Now(); got.After(now.Add(2 * time.Second)) {
		t.Fatalf("boot instant %s is in the future (now %s)", got, now)
	}
	if !got.Equal(got.Truncate(time.Second)) {
		t.Fatalf("boot instant %s is not rounded to the second", got)
	}
	// Twice in a row must agree within the rounding, or every start would look like a new boot.
	if again := BootInstant(); again.Sub(got) > 2*time.Second || got.Sub(again) > 2*time.Second {
		t.Fatalf("two reads disagree: %s then %s", got, again)
	}
}

// TestMarkerIsSafeUnderConcurrentWritesAndReads: the handler and an operator's `service start` can
// touch the file at the same time, and a half-written marker must never be read as a refusal.
func TestMarkerIsSafeUnderConcurrentWritesAndReads(t *testing.T) {
	dir := t.TempDir()
	boot := bootFixture()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for n := 0; n < 20; n++ {
				_ = WriteMarker(dir, Marker{Exit: 2 + i%4, Reason: "lock-held", TS: boot, Boot: boot})
				if m, ok := ReadMarker(dir); ok && (m.Exit < 2 || m.Exit > 5 || m.Reason != "lock-held") {
					t.Errorf("read a torn marker: %+v", m)
					return
				}
				_ = DeleteMarker(dir)
			}
		}(i)
	}
	wg.Wait()
	if entries, err := os.ReadDir(dir); err != nil {
		t.Fatalf("ReadDir: %v", err)
	} else if len(entries) > 1 {
		t.Fatalf("%d files left in the data dir: a temp file leaked", len(entries))
	}
}

// --- Task 4.2: readiness (folded in here, as the plan's file budget says) ---

// notifyListener is a temp AF_UNIX datagram socket standing in for systemd's.
func notifyListener(t *testing.T) (*net.UnixConn, string) {
	t.Helper()
	// Short path: sun_path is about 108 bytes, and a long TMPDIR silently truncates.
	sock := filepath.Join(t.TempDir(), "n.sock")
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err != nil {
		t.Skipf("no unixgram socket here: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, sock
}

func readOne(t *testing.T, c *net.UnixConn) string {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read from the notify socket: %v", err)
	}
	return string(buf[:n])
}

func TestNotifyReadyWritesReadyOneToTheSocket(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("sd_notify is the Linux half; the other half is a no-op and has its own test")
	}
	c, sock := notifyListener(t)
	t.Setenv("NOTIFY_SOCKET", sock)
	if err := NotifyReady(); err != nil {
		t.Fatalf("NotifyReady: %v", err)
	}
	if got := readOne(t, c); got != "READY=1\n" {
		t.Fatalf("socket got %q, want %q", got, "READY=1\n")
	}
}

func TestNotifyStoppingWritesStoppingOne(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("sd_notify is the Linux half")
	}
	c, sock := notifyListener(t)
	t.Setenv("NOTIFY_SOCKET", sock)
	if err := NotifyStopping(); err != nil {
		t.Fatalf("NotifyStopping: %v", err)
	}
	if got := readOne(t, c); got != "STOPPING=1\n" {
		t.Fatalf("socket got %q, want %q", got, "STOPPING=1\n")
	}
}

// TestNotifySendsNoMainPID: the unit uses NotifyAccess=main, so MAINPID is neither needed nor sent.
// Sending one from a process that is not the main pid is how a notify unit ends up refused.
func TestNotifySendsNoMainPID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("sd_notify is the Linux half")
	}
	c, sock := notifyListener(t)
	t.Setenv("NOTIFY_SOCKET", sock)
	if err := NotifyReady(); err != nil {
		t.Fatalf("NotifyReady: %v", err)
	}
	if got := readOne(t, c); strings.Contains(got, "MAINPID") {
		t.Fatalf("the datagram carries MAINPID: %q", got)
	}
}

// TestNotifyIsANoOpWithNoSocket is the console case: `server run` from a shell has no
// NOTIFY_SOCKET, and readiness must not become an error path there.
func TestNotifyIsANoOpWithNoSocket(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if notifySocket() != "" {
		t.Fatalf("notifySocket() = %q with the variable empty", notifySocket())
	}
	if err := NotifyReady(); err != nil {
		t.Fatalf("NotifyReady with no socket: %v", err)
	}
	if err := NotifyStopping(); err != nil {
		t.Fatalf("NotifyStopping with no socket: %v", err)
	}
}

// TestNotifyOnNonLinuxIsANoOp: the !linux build sends nothing even when something that looks like a
// notify socket is in the environment.
func TestNotifyOnNonLinuxIsANoOp(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("this is the other build's behaviour")
	}
	t.Setenv("NOTIFY_SOCKET", filepath.Join(t.TempDir(), "n.sock"))
	if got := notifySocket(); got != "" {
		t.Fatalf("notifySocket() = %q off linux, want empty", got)
	}
	if err := NotifyReady(); err != nil {
		t.Fatalf("NotifyReady: %v", err)
	}
	if err := NotifyStopping(); err != nil {
		t.Fatalf("NotifyStopping: %v", err)
	}
	if JournalStream() {
		t.Fatal("JournalStream is true off linux")
	}
}

// TestJournalStreamComparesTheValueNotJustPresence: the systemd page requires the value to be
// compared against fstat of the stream, because a child that inherited the variable without the
// stream would otherwise switch its log format on a lie.
func TestJournalStreamComparesTheValueNotJustPresence(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("JOURNAL_STREAM is a Linux variable")
	}
	t.Setenv("JOURNAL_STREAM", "1:2")
	if JournalStream() {
		t.Fatal("a JOURNAL_STREAM naming another device and inode read as the journal")
	}
	for _, v := range []string{"", "nonsense", "1", "1:", ":2", "a:b", "1:2:3"} {
		t.Setenv("JOURNAL_STREAM", v)
		if JournalStream() {
			t.Fatalf("JOURNAL_STREAM=%q read as the journal", v)
		}
	}
	dev, ino, ok := stderrDevIno()
	if !ok {
		t.Skip("cannot fstat fd 2 here")
	}
	t.Setenv("JOURNAL_STREAM", formatDevIno(dev, ino))
	if !JournalStream() {
		t.Fatalf("JOURNAL_STREAM set to fd 2's own %d:%d did not match", dev, ino)
	}
}
