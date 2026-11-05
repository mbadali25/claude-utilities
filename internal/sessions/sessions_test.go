package sessions

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"claude-utilities/internal/proto"
)

func TestParseWindowsFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "sessions-windows.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("want 5 sessions, got %d", len(got))
	}
	s := got[0]
	if s.PID != 2001 || s.ID != "11111111-1111-4111-8111-111111111111" || s.Cwd != `C:\fixture\alpha` {
		t.Fatalf("unexpected session: %+v", s)
	}
	if !s.StartedAt.Equal(time.UnixMilli(1793716513843)) {
		t.Fatalf("startedAt: %v", s.StartedAt)
	}
}

func TestParseEmptyOutput(t *testing.T) {
	for _, in := range []string{"", "  \n", "[]"} {
		got, err := parse([]byte(in))
		if err != nil || len(got) != 0 {
			t.Fatalf("input %q: got %v, %v", in, got, err)
		}
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := parse([]byte("{not json")); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseSingleObjectAndMissingID(t *testing.T) {
	got, err := parse([]byte(`{"pid":7,"cwd":"x","startedAt":1000}`))
	if err != nil || len(got) != 1 || got[0].ID != "" || got[0].PID != 7 {
		t.Fatalf("got %v, %v", got, err)
	}
	// pid <= 0 is not a process: dropped.
	got, _ = parse([]byte(`[{"pid":0,"sessionId":"a"}]`))
	if len(got) != 0 {
		t.Fatalf("pid 0 kept: %v", got)
	}
}

func TestCwdWithUnicodeAndSpaces(t *testing.T) {
	got, err := parse([]byte(`[{"pid":9,"sessionId":"s","cwd":"C:\\repos\\my proj\\caf\u00e9 \u65e5\u672c","startedAt":5}]`))
	if err != nil || len(got) != 1 {
		t.Fatal(got, err)
	}
	if got[0].Cwd != "C:\\repos\\my proj\\café 日本" {
		t.Fatalf("cwd: %q", got[0].Cwd)
	}
}

// The session's name lives in the sessions file itself ("name", with "nameSource" saying
// whether `/rename` set it), so no transcript is read. The fixture names are invented.
func TestParseNamedFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "sessions-named.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 7 {
		t.Fatalf("want 7 sessions, got %d", len(got))
	}
	byPID := map[int]proto.Session{}
	for _, s := range got {
		byPID[s.PID] = s
	}
	for _, tc := range []struct {
		pid        int
		name       string
		remoteName string
		status     string
		remote     bool
	}{
		{1001, "alpha-lane", "", "busy", true},
		{1002, "café 日本 λane ✓", "", "idle", false}, // bridgeSessionId null: not remote-controlled
		{1003, "", "", "idle", false},               // name present but empty
		{1004, "", "", "", false},                   // whitespace-only name is no name
		{1006, "", "", "", false},                   // no name field at all
		{1007, "eta-lane", "eta-remote", "idle", true},
	} {
		s, ok := byPID[tc.pid]
		if !ok {
			t.Fatalf("pid %d missing", tc.pid)
		}
		if s.Name != tc.name {
			t.Errorf("pid %d name = %q, want %q", tc.pid, s.Name, tc.name)
		}
		if s.RemoteName != tc.remoteName {
			t.Errorf("pid %d remoteName = %q, want %q", tc.pid, s.RemoteName, tc.remoteName)
		}
		if s.Status != tc.status {
			t.Errorf("pid %d status = %q, want %q", tc.pid, s.Status, tc.status)
		}
		if s.RemoteControl != tc.remote {
			t.Errorf("pid %d remoteControl = %v, want %v", tc.pid, s.RemoteControl, tc.remote)
		}
	}
	// A very long name is carried whole: the UI truncates it for display, so the parser
	// must not decide where a name ends.
	if n := byPID[1005].Name; len(n) < 250 || !strings.HasSuffix(n, "-end") {
		t.Errorf("long name was altered: len %d", len(n))
	}
}

// The captured Windows fixture is a real sessions file, so it proves the live shape: the
// name is in the file, no transcript needed.
func TestWindowsFixtureCarriesNameFromTheSessionsFile(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "sessions-windows.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	named := 0
	for _, s := range got {
		if s.Name != "" {
			named++
		}
		if s.RemoteName != "" {
			t.Errorf("pid %d has a remoteName; 2.1.318 writes none", s.PID)
		}
	}
	if named == 0 {
		t.Fatal("no session in the fixture carries a name")
	}
}

// A record from an older agent carries none of the new fields and still decodes, with the
// new fields empty and no error: the protocol addition is backwards compatible.
func TestParseLegacyRecordLeavesNewFieldsEmpty(t *testing.T) {
	got, err := parse([]byte(`[{"pid":5,"sessionId":"a","cwd":"/w","startedAt":7,"procStart":"p"}]`))
	if err != nil || len(got) != 1 {
		t.Fatalf("got %+v, %v", got, err)
	}
	if s := got[0]; s.Name != "" || s.RemoteName != "" || s.Status != "" || s.RemoteControl {
		t.Fatalf("legacy record gained a field: %+v", s)
	}
}

// Both the Windows and Linux scans go through scanDir, so one parser produces the name on
// either platform. Only the record's own fields differ by file, never by OS.
func TestScanDirCarriesNameAndRemoteControl(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "100.json", `{"pid":100,"sessionId":"a","cwd":"/w","startedAt":1,"procStart":"p",`+
		`"name":"lane-one","status":"busy","bridgeSessionId":"b-1"}`)
	got, err := scanDir(dir, func(int, string) bool { return true })
	if err != nil || len(got) != 1 {
		t.Fatalf("got %+v, %v", got, err)
	}
	if got[0].Name != "lane-one" || got[0].Status != "busy" || !got[0].RemoteControl {
		t.Fatalf("got %+v", got[0])
	}
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestScanIgnoresNonClaudeProcesses(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "100.json", `{"pid":100,"sessionId":"live","cwd":"c","startedAt":1,"procStart":"p1"}`)
	write(t, dir, "200.json", `{"pid":200,"sessionId":"reused-pid","cwd":"c","startedAt":1,"procStart":"p2"}`)
	write(t, dir, "100.abc.key", "SECRET-DO-NOT-READ")
	write(t, dir, "notes.txt", "hello")
	alive := func(pid int, procStart string) bool { return pid == 100 && procStart == "p1" }
	got, err := scanDir(dir, alive)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "live" {
		t.Fatalf("got %+v", got)
	}
}

func TestScanSurvivesUnreadableProcEntry(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "1.json", `{"pid":1,"sessionId":"ok","startedAt":1,"procStart":"p"}`)
	write(t, dir, "2.json", `{corrupt`)
	if err := os.Mkdir(filepath.Join(dir, "3.json"), 0o700); err != nil { // unreadable as a file
		t.Fatal(err)
	}
	got, err := scanDir(dir, func(int, string) bool { return true })
	if err != nil || len(got) != 1 || got[0].ID != "ok" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestScanMissingDirIsEmpty(t *testing.T) {
	got, err := scanDir(filepath.Join(t.TempDir(), "nope"), func(int, string) bool { return true })
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestNeedsReloadOnlyOlderSessions(t *testing.T) {
	swap := time.UnixMilli(10_000)
	ss := []proto.Session{
		{PID: 1, ID: "old", StartedAt: time.UnixMilli(5_000)},
		{PID: 2, ID: "same", StartedAt: swap},
		{PID: 3, ID: "new", StartedAt: time.UnixMilli(20_000)},
		{PID: 4, StartedAt: time.UnixMilli(1)}, // no id: keyed on PID
	}
	got := NeedsReload(ss, swap)
	if len(got) != 2 || got[0] != "old" || got[1] != "pid:4" {
		t.Fatalf("got %v", got)
	}
	if got := NeedsReload(nil, swap); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}
