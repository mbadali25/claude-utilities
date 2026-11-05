package sessions

import (
	"os"
	"path/filepath"
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
	if s.PID != 13308 || s.ID != "81ff45c1-87f1-4f43-a5ff-852ce20f0990" || s.Cwd != `C:\repos\anew\TheSelectSource` {
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
