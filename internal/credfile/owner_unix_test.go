//go:build !windows

package credfile

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type chownCall struct {
	path     string
	uid, gid int
}

// recordChown makes the swap believe it runs as root and records every chown
// instead of performing it. Tests cannot be root, so both the euid check and
// the chown itself are seams.
func recordChown(t *testing.T, euid int, fail func(path string) error) *[]chownCall {
	t.Helper()
	calls := &[]chownCall{}
	oldChown, oldEuid := chownFn, geteuidFn
	geteuidFn = func() int { return euid }
	chownFn = func(path string, uid, gid int) error {
		*calls = append(*calls, chownCall{path, uid, gid})
		if fail != nil {
			return fail(path)
		}
		return nil
	}
	t.Cleanup(func() { chownFn, geteuidFn = oldChown, oldEuid })
	return calls
}

func ownerOf(t *testing.T, path string) (int, int) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no syscall.Stat_t on this platform")
	}
	return int(st.Uid), int(st.Gid)
}

// A root agent swapping for another user must hand the new file, the backup
// directory and the backup itself back to the credentials file's owner.
func TestSwapPreservesOwnerWhenRoot(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, fileWith(`{"old":true}`))
	uid, gid := ownerOf(t, p)
	calls := recordChown(t, 0, nil)

	backup, err := Replace(p, json.RawMessage(oauth("n", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 3 {
		t.Fatalf("chown calls = %v, want 3", *calls)
	}
	seen := map[string]bool{}
	for _, c := range *calls {
		if c.uid != uid || c.gid != gid {
			t.Fatalf("chown %q = %d:%d, want %d:%d", c.path, c.uid, c.gid, uid, gid)
		}
		seen[c.path] = true
	}
	for _, want := range []string{filepath.Join(dir, backupDir), backup} {
		if !seen[want] {
			t.Fatalf("no chown for %q; got %v", want, *calls)
		}
	}
	for path := range seen {
		if strings.HasPrefix(filepath.Base(path), ".credentials-") && strings.HasSuffix(path, ".tmp") {
			return
		}
	}
	t.Fatalf("no chown for the temp file; got %v", *calls)
}

// Not root: nothing is chowned, because the files are already this user's.
func TestSwapSkipsChownWhenNotRoot(t *testing.T) {
	p := write(t, t.TempDir(), fileWith(`{"old":true}`))
	calls := recordChown(t, 1000, nil)
	if _, err := Replace(p, json.RawMessage(oauth("n", 1))); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 0 {
		t.Fatalf("chown calls = %v, want none", *calls)
	}
}

// With no file yet there is no owner to preserve, so the default applies.
func TestSwapSkipsChownWhenTargetAbsent(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".credentials.json")
	calls := recordChown(t, 0, nil)
	if _, err := Replace(p, json.RawMessage(oauth("n", 1))); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 0 {
		t.Fatalf("chown calls = %v, want none", *calls)
	}
}

// A chown that fails must abort the swap: renaming a root-owned file over the
// user's credentials is exactly the breakage this change exists to prevent.
func TestSwapAbortsWhenTempChownFails(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, fileWith(`{"old":true}`))
	recordChown(t, 0, func(path string) error {
		if strings.HasSuffix(path, ".tmp") {
			return errors.New("denied")
		}
		return nil
	})
	backup, err := Replace(p, json.RawMessage(oauth("n", 1)))
	if err == nil {
		t.Fatal("want an error")
	}
	if backup != "" {
		t.Fatalf("backup = %q, want none", backup)
	}
	data, rerr := os.ReadFile(p)
	if rerr != nil || string(data) != fileWith(`{"old":true}`) {
		t.Fatalf("original changed: %s (%v)", data, rerr)
	}
	ents, _ := os.ReadDir(filepath.Join(dir, backupDir))
	if len(ents) != 0 {
		t.Fatalf("orphan backups: %d", len(ents))
	}
}

func TestSwapAbortsWhenBackupChownFails(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, fileWith(`{"old":true}`))
	recordChown(t, 0, func(string) error { return errors.New("denied") })
	if _, err := Replace(p, json.RawMessage(oauth("n", 1))); err == nil {
		t.Fatal("want an error")
	}
	data, _ := os.ReadFile(p)
	if string(data) != fileWith(`{"old":true}`) {
		t.Fatalf("original changed: %s", data)
	}
}

// The real thing, when the test process happens to be root: the swapped file
// keeps 0600 and the original owner, and the backup directory keeps 0700.
func TestSwapPreservesModeAndOwnerAsRoot(t *testing.T) {
	dir := t.TempDir()
	p := write(t, dir, fileWith(`{"old":true}`))
	if os.Geteuid() != 0 {
		// Not root: ownership cannot be handed over, but the modes still hold.
		backup, err := Replace(p, json.RawMessage(oauth("n", 1)))
		if err != nil {
			t.Fatal(err)
		}
		assertModes(t, p, backup)
		return
	}
	const other = 65534 // nobody on every distribution this agent targets
	if err := os.Chown(p, other, other); err != nil {
		t.Skipf("chown to nobody: %v", err)
	}
	backup, err := Replace(p, json.RawMessage(oauth("n", 1)))
	if err != nil {
		t.Fatal(err)
	}
	assertModes(t, p, backup)
	for _, path := range []string{p, backup, filepath.Join(dir, backupDir)} {
		if uid, gid := ownerOf(t, path); uid != other || gid != other {
			t.Fatalf("%q owner = %d:%d, want %d:%d", path, uid, gid, other, other)
		}
	}
}

func assertModes(t *testing.T, path, backup string) {
	t.Helper()
	for _, c := range []struct {
		path string
		want os.FileMode
	}{
		{path, 0o600},
		{backup, 0o600},
		{filepath.Join(filepath.Dir(path), backupDir), 0o700},
	} {
		fi, err := os.Stat(c.path)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != c.want {
			t.Fatalf("%q mode = %04o, want %04o", c.path, got, c.want)
		}
	}
}
