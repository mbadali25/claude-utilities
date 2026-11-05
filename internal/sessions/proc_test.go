package sessions

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// fakeProc writes <root>/<pid>/stat and, when cmdline is non-nil, cmdline.
// stat fields are padded out to a real line's width so the parser sees field 22.
func fakeProc(t *testing.T, root string, pid int, comm, state string, startTicks uint64, cmdline []string) {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	fields := make([]string, statStartTimeIndex+1)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0] = state
	fields[statStartTimeIndex] = strconv.FormatUint(startTicks, 10)
	line := strconv.Itoa(pid) + " (" + comm + ") " + strings.Join(fields, " ") + " 3362816 385\n"
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	if cmdline != nil {
		body := strings.Join(cmdline, "\x00") + "\x00"
		if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseProcStatRealSample(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "proc-stat-linux.txt"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := parseProcStat(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if st.comm != "cat" || st.state != "R" || st.startTicks != 14416790 {
		t.Fatalf("got %+v", st)
	}
}

func TestParseProcStatCommWithSpacesAndParens(t *testing.T) {
	fields := strings.Repeat(" 0", statStartTimeIndex-1) // after state, up to starttime
	st, err := parseProcStat("42 (cla ude) :-)) S" + fields + " 777 extra\n")
	if err != nil {
		t.Fatal(err)
	}
	if st.comm != "cla ude) :-)" || st.state != "S" || st.startTicks != 777 {
		t.Fatalf("got %+v", st)
	}
}

func TestParseProcStatRejectsMalformed(t *testing.T) {
	for _, in := range []string{
		"",                    // empty file
		"42 claude S 0 0",     // no parentheses
		"42 (claude) S 1 2 3", // truncated before starttime
		"42 (claude) S" + strings.Repeat(" 0", statStartTimeIndex-1) + " notanumber",
	} {
		if _, err := parseProcStat(in); err == nil {
			t.Fatalf("input %q: expected an error", in)
		}
	}
}

func TestProcAliveHappyPathViaCmdline(t *testing.T) {
	root := t.TempDir()
	// comm is "node" (Claude Code is a Node CLI), so only cmdline carries the marker.
	fakeProc(t, root, 4242, "node", "S", 900, []string{"node", "/home/u/.local/share/claude/cli.js", "--resume"})
	if !procAlive(root, 4242, "900") {
		t.Fatal("live claude session reported dead")
	}
	// comm itself may carry it, with no cmdline at all.
	fakeProc(t, root, 4243, "claude", "R", 901, nil)
	if !procAlive(root, 4243, "901") {
		t.Fatal("live session with claude comm reported dead")
	}
}

func TestProcAliveDeadPid(t *testing.T) {
	root := t.TempDir()
	// No <root>/<pid> at all: the process is gone.
	if procAlive(root, 5000, "900") {
		t.Fatal("missing proc entry reported alive")
	}
	// Present but reaped.
	fakeProc(t, root, 5001, "claude", "Z", 900, nil)
	if procAlive(root, 5001, "900") {
		t.Fatal("zombie reported alive")
	}
	// A pid is never valid at or below zero.
	if procAlive(root, 0, "900") || procAlive(root, -1, "900") {
		t.Fatal("non-positive pid reported alive")
	}
}

func TestProcAlivePidReuse(t *testing.T) {
	root := t.TempDir()
	// Same pid, a claude process, but started later than the session recorded.
	fakeProc(t, root, 6000, "claude", "S", 999, nil)
	if procAlive(root, 6000, "900") {
		t.Fatal("reused pid reported alive")
	}
	// Right start time, but the pid now belongs to something else entirely.
	fakeProc(t, root, 6001, "sshd", "S", 900, []string{"/usr/sbin/sshd", "-D"})
	if procAlive(root, 6001, "900") {
		t.Fatal("non-claude process reported as a session")
	}
	// Unreadable cmdline and a comm without the marker: not provably claude.
	fakeProc(t, root, 6002, "node", "S", 900, nil)
	if procAlive(root, 6002, "900") {
		t.Fatal("unidentifiable process reported as a session")
	}
}

func TestProcAliveUnparseableProcStartIsNoEvidence(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 7000, "claude", "S", 900, nil)
	// The Linux producer's procStart format is unverified: a value that cannot
	// be a clock-tick count must not hide a session that is plainly alive.
	for _, ps := range []string{"", "   ", "2026-11-05T10:00:00Z", "-1"} {
		if !procAlive(root, 7000, ps) {
			t.Fatalf("procStart %q hid a live session", ps)
		}
	}
}

func TestProcAliveMalformedStatIsDead(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "8000")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte("{not a stat line"), 0o600); err != nil {
		t.Fatal(err)
	}
	if procAlive(root, 8000, "900") {
		t.Fatal("malformed stat reported alive")
	}
}

func TestScanDirWithFakeProcRoot(t *testing.T) {
	root := t.TempDir()
	sessDir := t.TempDir()
	fakeProc(t, root, 100, "node", "S", 500, []string{"node", "/opt/claude/cli.js"})
	fakeProc(t, root, 200, "claude", "S", 777, nil) // alive, but the file says it started at 500
	write(t, sessDir, "100.json", `{"pid":100,"sessionId":"live","cwd":"/home/u/p","startedAt":1,"procStart":"500"}`)
	write(t, sessDir, "200.json", `{"pid":200,"sessionId":"reused","cwd":"/home/u/p","startedAt":1,"procStart":"500"}`)
	write(t, sessDir, "300.json", `{"pid":300,"sessionId":"gone","cwd":"/home/u/p","startedAt":1,"procStart":"500"}`)
	write(t, sessDir, "100.abc.key", "SECRET-DO-NOT-READ")

	got, err := scanDir(sessDir, func(pid int, procStart string) bool { return procAlive(root, pid, procStart) })
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "live" || got[0].Cwd != "/home/u/p" {
		t.Fatalf("got %+v", got)
	}
}

func TestScanDirEmptyProcAndEmptySessionsDir(t *testing.T) {
	emptyProc := t.TempDir()
	sessDir := t.TempDir()
	got, err := scanDir(sessDir, func(pid int, procStart string) bool { return procAlive(emptyProc, pid, procStart) })
	if err != nil || len(got) != 0 {
		t.Fatalf("empty dir: got %v, %v", got, err)
	}
	// A populated sessions dir against an empty /proc yields nothing live.
	write(t, sessDir, "100.json", `{"pid":100,"sessionId":"live","procStart":"500"}`)
	got, err = scanDir(sessDir, func(pid int, procStart string) bool { return procAlive(emptyProc, pid, procStart) })
	if err != nil || len(got) != 0 {
		t.Fatalf("empty proc: got %v, %v", got, err)
	}
}
