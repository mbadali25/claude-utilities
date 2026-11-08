//go:build !windows

package vault

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// mountinfoFixture is the shape /proc/self/mountinfo has, with the four lines that matter: a root
// ext4 mount, an NFS mount deeper in, a 9p mount (what a Windows drive looks like under WSL) and a
// mount point with an escaped space in its name.
const mountinfoFixture = `22 28 0:21 / /proc rw,nosuid - proc proc rw
28 1 8:2 / / rw,relatime - ext4 /dev/sda2 rw
33 28 0:33 / /mnt/share rw,relatime - nfs4 server:/export rw
34 28 0:34 / /mnt/c rw,relatime - 9p C:\ rw,aname=drvfs
35 28 0:35 / /mnt/with\040space rw,relatime - ext4 /dev/sdb1 rw
36 28 0:36 / /mnt/sharedata rw,relatime - ext4 /dev/sdc1 rw
`

func withMountTable(t *testing.T, body string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "mountinfo")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := mountTable
	mountTable = p
	t.Cleanup(func() { mountTable = restore })
}

func TestFilesystemTypeTakesTheLongestMatchingMountPoint(t *testing.T) {
	withMountTable(t, mountinfoFixture)
	cases := map[string]string{
		"/var/lib/claude-swap": "ext4",
		"/mnt/share/data":      "nfs4",
		"/mnt/share":           "nfs4",
		"/mnt/c/repos/x":       "9p",
		"/mnt/with space/data": "ext4",
		"/mnt/sharedata/vault": "ext4", // not under /mnt/share: the boundary is a component
		"/proc/self":           "proc",
	}
	for path, want := range cases {
		got, err := filesystemType(path)
		if err != nil {
			t.Errorf("filesystemType(%q): %v", path, err)
			continue
		}
		if got != want {
			t.Errorf("filesystemType(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestProveExclusiveRefusesANetworkFilesystem(t *testing.T) {
	withMountTable(t, mountinfoFixture)
	for path, want := range map[string]string{
		"/mnt/share/data": "nfs4",
		"/mnt/c/repos/x":  "9p",
	} {
		err := osProveExclusive(path)
		if err == nil {
			t.Errorf("osProveExclusive(%q) = nil, want a refusal", path)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("osProveExclusive(%q) = %v, want it to name %q", path, err, want)
		}
	}
	if err := osProveExclusive("/var/lib/claude-swap"); err != nil {
		t.Errorf("osProveExclusive on ext4 = %v, want nil", err)
	}
}

// An unreadable mount table is a refusal on Linux, where procfs is always there: "cannot prove
// exclusive" is the condition the lock refuses on, not "proven shared".
func TestProveExclusiveRefusesWhenTheMountTableCannotBeRead(t *testing.T) {
	withMountTable(t, mountinfoFixture)
	mountTable = filepath.Join(t.TempDir(), "absent")
	err := osProveExclusive("/var/lib/claude-swap")
	if runtime.GOOS != "linux" {
		if err != nil {
			t.Fatalf("osProveExclusive = %v, want nil where there is no mount table to read", err)
		}
		return
	}
	if err == nil {
		t.Fatal("osProveExclusive = nil with no mount table: the lock cannot be proven exclusive")
	}
	if !strings.Contains(err.Error(), "cannot be read") {
		t.Fatalf("osProveExclusive = %v", err)
	}
}

// Two handles on one data dir contend under flock exactly as two processes do, because the lock
// belongs to the open file description. That is what makes the second AcquireLock in the same test
// process a real test of the OS lock and not of a Go-level mutex.
func TestFlockContendsBetweenTwoHandlesInOneProcess(t *testing.T) {
	dir := t.TempDir()
	l := acquire(t, dir, "run")
	f, err := os.OpenFile(LockPath(dir), os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := lockHandle(f); err == nil {
		t.Fatal("a second handle took the lock")
	}
	_ = l
}

func TestUnescapeMountHandlesTheFourEscapes(t *testing.T) {
	cases := map[string]string{
		`/mnt/with\040space`: "/mnt/with space",
		`/mnt/tab\011here`:   "/mnt/tab\there",
		`/mnt/back\134slash`: `/mnt/back\slash`,
		`/plain/path`:        "/plain/path",
		`/trailing\04`:       `/trailing\04`, // too short to be an escape: left alone
	}
	for in, want := range cases {
		if got := unescapeMount(in); got != want {
			t.Errorf("unescapeMount(%q) = %q, want %q", in, got, want)
		}
	}
}
