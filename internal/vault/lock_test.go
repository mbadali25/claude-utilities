package vault

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func lockDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// acquire takes the lock and releases it when the test ends, so a failure cannot leave a handle
// open and make the next test look like contention.
func acquire(t *testing.T, dir, cmd string) *Lock {
	t.Helper()
	l, err := AcquireLock(dir, cmd)
	if err != nil {
		t.Fatalf("AcquireLock(%q, %q): %v", dir, cmd, err)
	}
	t.Cleanup(func() { _ = l.Release() })
	return l
}

func TestAcquireThenSecondAcquireFailsWithThePidMessage(t *testing.T) {
	dir := lockDir(t)
	acquire(t, dir, "run")

	_, err := AcquireLock(dir, "migrate")
	if !errors.Is(err, ErrLockHeld) {
		t.Fatalf("second AcquireLock = %v, want ErrLockHeld", err)
	}
	msg := err.Error()
	for _, want := range []string{"server is running (pid ", fmt.Sprintf("pid %d", os.Getpid()), "cmd run", "started ", "stop it first"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q does not contain %q", msg, want)
		}
	}
}

func TestHolderMetadataIsReadableWhileLocked(t *testing.T) {
	dir := lockDir(t)
	before := time.Now().UTC().Add(-2 * time.Second)
	acquire(t, dir, "rotate")

	pid, cmd, started, ok := ReadLockHolder(dir)
	if !ok {
		t.Fatal("ReadLockHolder: not ok while the lock is held")
	}
	if pid != os.Getpid() || cmd != "rotate" {
		t.Fatalf("holder = pid %d cmd %q, want pid %d cmd %q", pid, cmd, os.Getpid(), "rotate")
	}
	if started.Before(before) || started.After(time.Now().UTC().Add(2*time.Second)) {
		t.Fatalf("started = %v, outside the window around now", started)
	}
	if started.Location() != time.UTC {
		t.Fatalf("started is not UTC: %v", started)
	}
}

// The lock covers one byte at 1 TiB so that a contender can read the holder line it has to print.
// Windows byte-range locks are mandatory: a lock over the whole file would fail the very read the
// error message needs. The offset must also not extend the file - a sparse 1 TiB lock file in
// every data dir would be its own bug.
func TestLockedByteIsAtOffsetOneTeraByte(t *testing.T) {
	if lockOffset != 1<<40 {
		t.Fatalf("lockOffset = %d, want 1<<40", lockOffset)
	}
	dir := lockDir(t)
	acquire(t, dir, "run")

	data, err := os.ReadFile(LockPath(dir))
	if err != nil {
		t.Fatalf("read the lock file while locked: %v", err)
	}
	if !strings.Contains(string(data), fmt.Sprintf(`"pid":%d`, os.Getpid())) {
		t.Fatalf("holder line does not carry this pid: %s", data)
	}
	st, err := os.Stat(LockPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() > lockMetaMax {
		t.Fatalf("lock file is %d bytes, want at most %d: the locked byte extended the file", st.Size(), lockMetaMax)
	}
}

func TestEmptyMetadataGivesTheNoPidMessage(t *testing.T) {
	dir := lockDir(t)
	l := acquire(t, dir, "run")

	// The holder has locked but not yet written its line, or someone truncated it.
	if err := os.WriteFile(LockPath(dir), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := ReadLockHolder(dir); ok {
		t.Fatal("ReadLockHolder: ok on an empty file")
	}
	_, err := AcquireLock(dir, "rotate")
	if !errors.Is(err, ErrLockHeld) {
		t.Fatalf("AcquireLock = %v, want ErrLockHeld", err)
	}
	want := "another process holds " + LockPath(dir) + ": stop it first"
	if err.Error() != want {
		t.Fatalf("message = %q, want %q", err.Error(), want)
	}
	_ = l
}

// A holder line is attacker-writable: anyone who can write the data dir can put anything in the
// first 4 KiB. Nothing from it reaches a message unless it is a plausible pid, a short printable
// command and a stamp this binary can parse.
func TestAHostileHolderLineIsNotPrinted(t *testing.T) {
	dir := lockDir(t)
	l := acquire(t, dir, "run")
	defer func() { _ = l.Release() }()

	for _, line := range []string{
		`{"pid":0,"cmd":"run","started":"2026-11-08T00:00:00Z"}`,
		`{"pid":-1,"cmd":"run","started":"2026-11-08T00:00:00Z"}`,
		`{"pid":1,"cmd":"run\nsudo rm -rf /","started":"2026-11-08T00:00:00Z"}`,
		`{"pid":1,"cmd":"` + strings.Repeat("x", 200) + `","started":"2026-11-08T00:00:00Z"}`,
		`{"pid":1,"cmd":"run","started":"not a time"}`,
		`{"pid":1,"cmd":"","started":"2026-11-08T00:00:00Z"}`,
		`{"pid":1,"cmd":"run"`,
		"\x00\x01\x02 not json at all",
	} {
		if err := os.WriteFile(LockPath(dir), []byte(line), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, _, ok := ReadLockHolder(dir); ok {
			t.Errorf("ReadLockHolder accepted %q", line)
		}
		_, err := AcquireLock(dir, "rotate")
		if !errors.Is(err, ErrLockHeld) {
			t.Fatalf("AcquireLock = %v, want ErrLockHeld", err)
		}
		if got := err.Error(); got != "another process holds "+LockPath(dir)+": stop it first" {
			t.Errorf("message for %q = %q", line, got)
		}
	}
}

func TestReleaseAllowsReacquire(t *testing.T) {
	dir := lockDir(t)
	l, err := AcquireLock(dir, "run")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	// Idempotent: a deferred Release after an explicit one is not an error.
	if err := l.Release(); err != nil {
		t.Fatalf("second Release: %v", err)
	}
	second := acquire(t, dir, "migrate")
	pid, cmd, _, ok := ReadLockHolder(dir)
	if !ok || pid != os.Getpid() || cmd != "migrate" {
		t.Fatalf("holder after reacquire = pid %d cmd %q ok %v", pid, cmd, ok)
	}
	_ = second
}

// An OS lock dies with the process, so there is no stale-lock reclaim to get wrong. The child
// exits through os.Exit without calling Release, which is also what a fatal does.
func TestLockDiesWithTheProcess(t *testing.T) {
	dir := lockDir(t)
	cmd := exec.Command(os.Args[0], "-test.run=TestLockHolderHelper", "-test.timeout=60s")
	cmd.Env = append(os.Environ(), lockHelperEnv+"="+dir)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})

	br := bufio.NewReader(stdout)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("helper never reported the lock: %v", err)
		}
		if strings.HasPrefix(line, lockHelperMarker) {
			break
		}
	}
	if _, err := AcquireLock(dir, "rotate"); !errors.Is(err, ErrLockHeld) {
		t.Fatalf("AcquireLock while the child holds it = %v, want ErrLockHeld", err)
	}
	if pid, _, _, ok := ReadLockHolder(dir); !ok || pid != cmd.Process.Pid {
		t.Fatalf("holder = pid %d ok %v, want the child's pid %d", pid, ok, cmd.Process.Pid)
	}

	_, _ = stdin.Write([]byte("go\n"))
	_ = stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper: %v", err)
	}
	l, err := AcquireLock(dir, "rotate")
	if err != nil {
		t.Fatalf("AcquireLock after the holder died: %v", err)
	}
	_ = l.Release()
}

const (
	lockHelperEnv    = "VAULT_LOCK_HELPER_DIR"
	lockHelperMarker = "LOCK-HELD"
)

// TestLockHolderHelper is the child half of TestLockDiesWithTheProcess. It is a no-op unless the
// parent set the environment variable, so a normal run skips it.
func TestLockHolderHelper(t *testing.T) {
	dir := os.Getenv(lockHelperEnv)
	if dir == "" {
		t.Skip("child of TestLockDiesWithTheProcess")
	}
	if _, err := AcquireLock(dir, "run"); err != nil {
		fmt.Printf("HELPER-FAILED %v\n", err)
		os.Exit(3)
	}
	fmt.Println(lockHelperMarker)
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	// No Release, deliberately: the OS releases the lock when this process ends.
	os.Exit(0)
}

// A lock file left behind by a process that is gone holds nothing: there is no OS lock on it, and
// the pid in its metadata is never the arbiter.
func TestAStaleHolderLineFromADeadProcessDoesNotBlock(t *testing.T) {
	dir := lockDir(t)
	stale := `{"pid":999999,"cmd":"run","started":"2020-01-01T00:00:00Z"}`
	if err := os.WriteFile(LockPath(dir), []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}
	l := acquire(t, dir, "migrate")
	pid, cmd, _, ok := ReadLockHolder(dir)
	if !ok || pid != os.Getpid() || cmd != "migrate" {
		t.Fatalf("stale line was not replaced: pid %d cmd %q ok %v", pid, cmd, ok)
	}
	_ = l
}

func TestLockFileIsOwnerOnly(t *testing.T) {
	var got []string
	restore := restrictFile
	restrictFile = func(p string) error {
		got = append(got, p)
		return restore(p)
	}
	t.Cleanup(func() { restrictFile = restore })

	dir := lockDir(t)
	acquire(t, dir, "run")

	if len(got) != 1 || got[0] != LockPath(dir) {
		t.Fatalf("RestrictFile calls = %v, want one for %q", got, LockPath(dir))
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(LockPath(dir))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %v, want 0600", st.Mode().Perm())
		}
	}
}

// Every mutator named in the spec takes the lock for the length of its command, so each of them
// refuses while a server holds it. The exit-2 mapping is the CLI's and lands with the `vault`
// dispatch (Task 3b.1); what this package owes the CLI is one error it can recognise.
func TestMutatorRefusesWhileAServerHoldsIt(t *testing.T) {
	dir := lockDir(t)
	acquire(t, dir, "run")

	for _, mutator := range []string{
		"init", "migrate", "add-slot", "remove-slot", "rotate", "change-passphrase",
		"downgrade", "finalize-migration", "purge-backups",
	} {
		l, err := AcquireLock(dir, mutator)
		if err == nil {
			_ = l.Release()
			t.Errorf("%s took the lock while a server holds it", mutator)
			continue
		}
		if !errors.Is(err, ErrLockHeld) {
			t.Errorf("%s: err = %v, want ErrLockHeld", mutator, err)
		}
		if !strings.Contains(err.Error(), "cmd run") {
			t.Errorf("%s: message does not name the holder's command: %q", mutator, err.Error())
		}
	}
}

// Review Focus 1: on a filesystem that gives an advisory-only lock - flock over NFS, LockFileEx on
// a mapped drive - two writers would both proceed with no contention error, which is the one
// failure the lock exists to prevent. A lock that cannot be proven exclusive is refused.
func TestAcquireRefusesWhenExclusivityCannotBeProven(t *testing.T) {
	restore := proveExclusive
	proveExclusive = func(string) error { return errors.New("the filesystem gave an advisory-only lock") }
	t.Cleanup(func() { proveExclusive = restore })

	dir := lockDir(t)
	_, err := AcquireLock(dir, "migrate")
	if err == nil {
		t.Fatal("AcquireLock succeeded on a filesystem whose lock cannot be relied on")
	}
	if errors.Is(err, ErrLockHeld) {
		t.Fatalf("err = %v, want a refusal that is not ErrLockHeld", err)
	}
	for _, want := range []string{dir, "advisory-only"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q does not contain %q", err.Error(), want)
		}
	}

	// The refusal must not leave the handle locked: the real probe passes, so this must succeed.
	proveExclusive = restore
	l, err := AcquireLock(dir, "migrate")
	if err != nil {
		t.Fatalf("AcquireLock after a refused probe: %v", err)
	}
	_ = l.Release()
}

func TestAcquireReportsAnUnusableLockPath(t *testing.T) {
	dir := lockDir(t)
	// A directory where the lock file belongs: the open fails on every OS, with no chmod games.
	if err := os.Mkdir(LockPath(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := AcquireLock(dir, "migrate")
	if err == nil {
		t.Fatal("AcquireLock succeeded with a directory in the lock file's place")
	}
	if errors.Is(err, ErrLockHeld) {
		t.Fatalf("err = %v, want a plain failure, not ErrLockHeld", err)
	}
	if !strings.Contains(err.Error(), LockPath(dir)) {
		t.Errorf("message %q does not name the lock file", err.Error())
	}
}

// A data dir can be anywhere, including a path with non-ASCII characters (Review Focus 2's
// neighbour). The lock, the holder line and the message all have to survive it.
func TestUnicodeDataDirLocksAndReports(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "données-日本語-🔐")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	acquire(t, dir, "rotate")
	if pid, cmd, _, ok := ReadLockHolder(dir); !ok || pid != os.Getpid() || cmd != "rotate" {
		t.Fatalf("holder = pid %d cmd %q ok %v", pid, cmd, ok)
	}
	_, err := AcquireLock(dir, "migrate")
	if !errors.Is(err, ErrLockHeld) {
		t.Fatalf("AcquireLock = %v, want ErrLockHeld", err)
	}
	if !strings.Contains(err.Error(), "cmd rotate") {
		t.Errorf("message = %q", err.Error())
	}
}

// AcquireLock creates the data dir, because `vault init` takes the lock before anything exists.
func TestAcquireCreatesTheDataDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "data")
	acquire(t, dir, "init")
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		t.Fatalf("data dir not created: %v", err)
	}
}

func TestLockHeldMessageShapes(t *testing.T) {
	dir := filepath.FromSlash("/srv/data")
	at := time.Date(2026, 11, 8, 9, 30, 0, 0, time.UTC)
	withMeta := lockHeldMessage(dir, 4242, "run", at, true)
	want := "server is running (pid 4242, cmd run, started 2026-11-08T09:30:00Z): stop it first"
	if withMeta != want {
		t.Fatalf("message = %q, want %q", withMeta, want)
	}
	noMeta := lockHeldMessage(dir, 0, "", time.Time{}, false)
	want = "another process holds " + filepath.Join(dir, LockFileName) + ": stop it first"
	if noMeta != want {
		t.Fatalf("message = %q, want %q", noMeta, want)
	}
}
