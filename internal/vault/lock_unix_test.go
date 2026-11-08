//go:build !windows

package vault

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
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

// A lexical path says nothing about the filesystem it lands on. A data dir that is a symlink into
// an NFS mount reads back as the root filesystem's type unless the link is resolved first, and then
// the one filesystem the probe exists to refuse is reported as able to hold an exclusive lock.
func TestFilesystemTypeResolvesSymlinksBeforeTheMountLookup(t *testing.T) {
	root := realTempDir(t)
	share := filepath.Join(root, "share")
	if err := os.MkdirAll(filepath.Join(share, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(filepath.Join(share, "data"), link); err != nil {
		t.Skipf("os.Symlink is not available here: %v", err)
	}
	// Only the real path is on the NFS mount; a lexical lookup on the link sees the root mount.
	withMountTable(t, "28 1 8:2 / / rw,relatime - ext4 /dev/sda2 rw\n"+
		"33 28 0:33 / "+share+" rw,relatime - nfs4 server:/export rw\n")

	got, err := filesystemType(link)
	if err != nil {
		t.Fatalf("filesystemType(%q): %v", link, err)
	}
	if got != "nfs4" {
		t.Fatalf("filesystemType(symlink into an NFS mount) = %q, want nfs4", got)
	}
	if err := osProveExclusive(link); err == nil {
		t.Fatal("osProveExclusive reported a symlink into an NFS mount as able to hold an exclusive lock")
	}
}

// A path that is there and still cannot be resolved is a refusal, not a fallback to the lexical
// form: a dangling link at the data dir says nothing about what the lock would land on. A path that
// does not exist at all is different - `vault init` probes before it creates - and keeps the
// lexical answer.
func TestFilesystemTypeRefusesAPathItCannotResolve(t *testing.T) {
	withMountTable(t, mountinfoFixture)
	root := realTempDir(t)
	link := filepath.Join(root, "dangling")
	if err := os.Symlink(filepath.Join(root, "absent"), link); err != nil {
		t.Skipf("os.Symlink is not available here: %v", err)
	}
	if got, err := filesystemType(link); err == nil {
		t.Fatalf("filesystemType(dangling symlink) = %q, want a refusal", got)
	}
	if _, err := filesystemType(filepath.Join(root, "not-created-yet")); err != nil {
		t.Fatalf("filesystemType on a path that does not exist yet = %v, want the lexical answer", err)
	}
}

// The denylist is the list of filesystem types where flock is not this process's to rely on, and
// the FUSE and shared-folder families were missing from it: a data dir on an s3fs or rclone mount,
// a virtiofs or VMware shared folder, a clustered filesystem, or a Windows drive seen from WSL.
func TestAdvisoryFilesystemsCoverTheFuseAndSharedFolderTypes(t *testing.T) {
	for _, fs := range []string{
		"fuse", "fuseblk", "fuse.s3fs", "fuse.rclone", "fuse.gvfsd",
		"virtiofs", "vmhgfs", "glusterfs", "cephfs", "lustre", "smb", "drvfs",
	} {
		if !advisoryFilesystems[fs] {
			t.Errorf("%s is not in advisoryFilesystems", fs)
		}
	}
}

// realTempDir is t.TempDir() with every symlink resolved, so a test that writes a mount table of
// its own compares against the path the kernel would report rather than the one the OS handed out
// (/tmp is a symlink on some systems).
func realTempDir(t *testing.T) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return real
}

// EACCES from flock is a permission failure, not contention. Mapping it to errLockBusy would make
// AcquireLock print "server is running (pid N, cmd ...)" out of a holder line anyone who can write
// the data dir can forge, naming a process that is not running, instead of the permission problem
// the operator actually has.
func TestFlockBusyIsOnlyContention(t *testing.T) {
	if !flockBusy(unix.EWOULDBLOCK) {
		t.Error("flockBusy(EWOULDBLOCK) = false: that is the contention error flock returns")
	}
	for _, err := range []error{nil, unix.EACCES, unix.EPERM, unix.EBADF, unix.ENOLCK, unix.EINTR} {
		if flockBusy(err) {
			t.Errorf("flockBusy(%v) = true, want false", err)
		}
	}
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
