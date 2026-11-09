package logx

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// logPath is the writer's target inside a fresh temp dir. Nothing in these tests writes outside it.
func logPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "server.log")
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// TestRotatingWriterRotatesAtTheSizeCap: the live file never grows past the cap, and the generation
// that was live becomes .1.
func TestRotatingWriterRotatesAtTheSizeCap(t *testing.T) {
	path := logPath(t)
	w, err := NewRotatingWriter(path, 100, 5)
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	defer func() { _ = w.Close() }()
	line := []byte(strings.Repeat("a", 30) + "\n") // 31 bytes
	for i := 0; i < 3; i++ {
		if _, err := w.Write(line); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	// 93 bytes in, still under the cap: one file, no rotation yet.
	if got := names(t, filepath.Dir(path)); len(got) != 1 {
		t.Fatalf("after 93 bytes: %v, want only server.log", got)
	}
	if _, err := w.Write(line); err != nil {
		t.Fatalf("the write that rotates: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat the live file: %v", err)
	}
	if fi.Size() != int64(len(line)) {
		t.Fatalf("live file is %d bytes, want the one line written after the rotation", fi.Size())
	}
	rolled, err := os.Stat(path + ".1")
	if err != nil {
		t.Fatalf("Stat server.log.1: %v", err)
	}
	if rolled.Size() != 93 {
		t.Fatalf("server.log.1 is %d bytes, want the 93 that were live", rolled.Size())
	}
}

// TestRotatingWriterKeepsFiveAndDeletesTheSixth: five files is the explicit retention (50 MiB at the
// server's 10 MiB cap). The sixth generation does not exist, it is deleted.
func TestRotatingWriterKeepsFiveAndDeletesTheSixth(t *testing.T) {
	path := logPath(t)
	w, err := NewRotatingWriter(path, 10, 5)
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	defer func() { _ = w.Close() }()
	// Each write is the whole cap, so every write after the first rotates.
	for i := 0; i < 12; i++ {
		if _, err := fmt.Fprintf(w, "%09d\n", i); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	got := names(t, filepath.Dir(path))
	if len(got) != 5 {
		t.Fatalf("%d files (%v), want five", len(got), got)
	}
	for _, want := range []string{"server.log", "server.log.1", "server.log.2", "server.log.3", "server.log.4"} {
		if _, err := os.Stat(filepath.Join(filepath.Dir(path), want)); err != nil {
			t.Fatalf("%s missing: %v", want, err)
		}
	}
	if _, err := os.Stat(path + ".5"); !os.IsNotExist(err) {
		t.Fatalf("server.log.5 exists (stat err %v): the retention is five files", err)
	}
	// The newest rotation holds the most recent line that was rolled out.
	b, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatalf("ReadFile .1: %v", err)
	}
	if strings.TrimSpace(string(b)) != "000000010" {
		t.Fatalf(".1 holds %q, want the line written just before the last rotation", strings.TrimSpace(string(b)))
	}
}

// TestRotatingWriterDeletesAGenerationBeyondTheChain: the rename chain alone does not enforce the
// retention. A stale server.log.4 with no server.log.3 to rename over it - a file an operator left,
// or what a run with a larger keep wrote - would otherwise sit there for ever, outside the 50 MiB
// the retention promises.
func TestRotatingWriterDeletesAGenerationBeyondTheChain(t *testing.T) {
	path := logPath(t)
	dir := filepath.Dir(path)
	for _, name := range []string{"server.log.1", "server.log.4"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("stale\n"), 0o600); err != nil {
			t.Fatalf("WriteFile %s: %v", name, err)
		}
	}
	w, err := NewRotatingWriter(path, 10, 5)
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	defer func() { _ = w.Close() }()
	for i := 0; i < 2; i++ {
		if _, err := fmt.Fprintf(w, "%09d\n", i); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if _, err := os.Stat(path + ".4"); !os.IsNotExist(err) {
		t.Fatalf("server.log.4 survived the rotation (stat err %v): keep-1 is deleted, not renamed over", err)
	}
	if got := names(t, dir); len(got) != 3 {
		t.Fatalf("%v, want server.log, .1 and .2", got)
	}
}

// TestRotatingWriterKeepsOneFileWhenAskedTo: keep=1 is "the live file only" and must truncate rather
// than leave a .1 nobody deletes.
func TestRotatingWriterKeepsOneFileWhenAskedTo(t *testing.T) {
	path := logPath(t)
	w, err := NewRotatingWriter(path, 10, 1)
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	defer func() { _ = w.Close() }()
	for i := 0; i < 4; i++ {
		if _, err := fmt.Fprintf(w, "%09d\n", i); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if got := names(t, filepath.Dir(path)); len(got) != 1 || got[0] != "server.log" {
		t.Fatalf("%v, want only server.log", got)
	}
}

// TestRotatingWriterRefusesNonsenseLimits: a zero cap would rotate on every write for ever and a
// keep of zero would delete the file it was asked to write.
func TestRotatingWriterRefusesNonsenseLimits(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct{ maxBytes, keep int64 }{{0, 5}, {-1, 5}, {10, 0}, {10, -1}} {
		w, err := NewRotatingWriter(filepath.Join(dir, "server.log"), c.maxBytes, int(c.keep))
		if err == nil {
			_ = w.Close()
			t.Fatalf("accepted maxBytes=%d keep=%d", c.maxBytes, c.keep)
		}
	}
	if got := names(t, dir); len(got) != 0 {
		t.Fatalf("a refused writer left %v behind", got)
	}
}

// TestRotatingWriterWritesALineLargerThanTheCap: a single line over the cap is written whole rather
// than dropped or split, and it rotates once, not in a loop. A JSON line with a long message is the
// real case.
func TestRotatingWriterWritesALineLargerThanTheCap(t *testing.T) {
	path := logPath(t)
	w, err := NewRotatingWriter(path, 16, 3)
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	defer func() { _ = w.Close() }()
	big := []byte(strings.Repeat("b", 64) + "\n")
	for i := 0; i < 2; i++ {
		n, err := w.Write(big)
		if err != nil || n != len(big) {
			t.Fatalf("write %d: n=%d err=%v", i, n, err)
		}
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Size() != int64(len(big)) {
		t.Fatalf("live file %d bytes, want one whole oversized line (%d)", fi.Size(), len(big))
	}
	if got := names(t, filepath.Dir(path)); len(got) != 2 {
		t.Fatalf("%v, want the live file and one rotation", got)
	}
}

// TestRotatingWriterReopensAnExistingFileAndCountsIt: a service restart must not reset the size
// accounting, or a log that is already at the cap grows without bound until the next restart.
func TestRotatingWriterReopensAnExistingFileAndCountsIt(t *testing.T) {
	path := logPath(t)
	if err := os.WriteFile(path, []byte(strings.Repeat("c", 95)), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	w, err := NewRotatingWriter(path, 100, 5)
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	defer func() { _ = w.Close() }()
	if _, err := w.Write([]byte("ten bytes!")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("the pre-existing 95 bytes were not counted: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(b) != "ten bytes!" {
		t.Fatalf("live file holds %q", b)
	}
}

// TestRotatingWriterFilesAreOwnerOnly: logs hold whatever a line carries, so they get the same
// treatment as every other file this repo writes into a data dir.
func TestRotatingWriterFilesAreOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not the ACL on windows; credfile.RestrictFile covers it and has its own tests")
	}
	path := filepath.Join(t.TempDir(), "logs", "server.log")
	w, err := NewRotatingWriter(path, 10, 3)
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	defer func() { _ = w.Close() }()
	for i := 0; i < 3; i++ {
		if _, err := fmt.Fprintf(w, "%09d\n", i); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	for _, name := range names(t, filepath.Dir(path)) {
		fi, err := os.Stat(filepath.Join(filepath.Dir(path), name))
		if err != nil {
			t.Fatalf("Stat %s: %v", name, err)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Fatalf("%s mode %04o, want 0600", name, perm)
		}
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("Stat the logs dir: %v", err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Fatalf("logs dir mode %04o, want 0700", perm)
	}
}

// TestRotatingWriterIsSafeUnderConcurrentWrites: slog writes from every goroutine that logs, so the
// writer is shared. Under -race this proves the lock covers the rotation as well as the write - a
// rotation that ran outside it would write to a closed file.
func TestRotatingWriterIsSafeUnderConcurrentWrites(t *testing.T) {
	path := logPath(t)
	w, err := NewRotatingWriter(path, 200, 4)
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	defer func() { _ = w.Close() }()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if _, err := fmt.Fprintf(w, "goroutine %d line %02d padded out a bit\n", g, i); err != nil {
					t.Errorf("write: %v", err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	if got := names(t, filepath.Dir(path)); len(got) > 4 {
		t.Fatalf("%d files (%v), want at most four", len(got), got)
	}
	// Every file still parses as whole lines: a torn write would leave a line without its newline
	// in the middle of a file.
	dir := filepath.Dir(path)
	for _, name := range names(t, dir) {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("ReadFile %s: %v", name, err)
		}
		for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
			if line != "" && !strings.HasPrefix(line, "goroutine ") {
				t.Fatalf("%s holds a torn line: %q", name, line)
			}
		}
	}
}

// TestRotatingWriterCloseIsIdempotentAndWritesAfterItFail: the service's shutdown path closes the
// writer, and a late log line must get an error rather than a panic or a silent drop.
func TestRotatingWriterCloseIsIdempotentAndWritesAfterItFail(t *testing.T) {
	path := logPath(t)
	w, err := NewRotatingWriter(path, 100, 3)
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := w.Write([]byte("late\n")); err == nil {
		t.Fatal("a write after Close succeeded")
	}
}

// TestDefaultRotationIsTheSpecsFiveByTenMiB keeps the numbers in one place: the Windows service's
// logs are 10 MiB a file, five files, a 50 MiB cap, and that is the explicit retention.
func TestDefaultRotationIsTheSpecsFiveByTenMiB(t *testing.T) {
	if DefaultLogMaxBytes != 10<<20 {
		t.Fatalf("DefaultLogMaxBytes = %d, want 10 MiB", DefaultLogMaxBytes)
	}
	if DefaultLogKeep != 5 {
		t.Fatalf("DefaultLogKeep = %d, want 5", DefaultLogKeep)
	}
}
