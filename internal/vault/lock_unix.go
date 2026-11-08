//go:build !windows

package vault

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

// lockHandle takes flock(LOCK_EX|LOCK_NB) on the open handle. flock is whole-file, so lockOffset
// is irrelevant here and a reader is never blocked; the offset exists for Windows, where the lock
// is mandatory and a whole-file lock would hide the holder line from a contender.
//
// flock associates the lock with the open file description, not the process, so two os.Open calls
// in one process contend exactly as two processes do - which is what makes the lock testable.
func lockHandle(f *os.File) error {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if flockBusy(err) {
		return errLockBusy
	}
	return err
}

// flockBusy reports whether a flock error means another open file description already holds the
// lock. Only EWOULDBLOCK does - EAGAIN is its other name for the same value on Linux. EACCES is
// not contention: it says this process may not lock the file, and calling that "busy" would print
// `server is running (pid N, cmd ...)` from a holder line anyone can write, naming a process that
// is not there, instead of the permission problem the operator has to fix.
func flockBusy(err error) bool { return errors.Is(err, unix.EWOULDBLOCK) }

// lockOpenNoFollow is the open flag that stops the lock file's open from following a symlink at the
// final component. The kernel refuses with ELOOP instead, which closes the window between
// AcquireLock's Lstat and its open.
const lockOpenNoFollow = unix.O_NOFOLLOW

func unlockHandle(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_UN) }

// advisoryFilesystems are the filesystem types where flock is not a lock this process may rely on:
// over NFS it is emulated or local-only depending on the mount options, over SMB/CIFS and 9p it is
// the server's to honour, and the rest are network or shared-folder filesystems with the same
// problem. Two writers on one of these would both proceed with no contention error, which is the
// one failure the lock exists to prevent (Review Focus 1).
//
// A denylist, not an allowlist, and that is a deliberate trade: ext4, xfs, btrfs, zfs, tmpfs and
// overlayfs all honour flock, but so do filesystems nobody has named yet, and an allowlist would
// refuse to start a server on the next one rather than on a broken one. What cannot be read at all
// is covered separately below.
// The FUSE entries include the bare "fuse" and "fuseblk": a FUSE filesystem's flock is whatever the
// userspace server chose to implement, and a mount table that names only "fuse" (an s3fs, rclone or
// gvfs mount, a sandbox's own bind) says nothing about which. "drvfs" is how WSL names a Windows
// drive it has mounted, which is the same shared-folder problem as vboxsf and vmhgfs. The clustered
// filesystems (glusterfs, cephfs, lustre) are network filesystems by construction.
var advisoryFilesystems = map[string]bool{
	"nfs": true, "nfs2": true, "nfs3": true, "nfs4": true, "cifs": true, "smbfs": true,
	"smb": true, "smb2": true, "smb3": true, "9p": true, "afs": true, "ncpfs": true,
	"coda": true, "davfs": true, "fuse": true, "fuseblk": true, "fuse.sshfs": true,
	"fuse.davfs": true, "fuse.s3fs": true, "fuse.rclone": true, "fuse.gvfsd": true,
	"vboxsf": true, "virtiofs": true, "vmhgfs": true, "drvfs": true,
	"glusterfs": true, "cephfs": true, "lustre": true,
}

// mountTable is the file the filesystem type is read from. A seam so a test can hand the probe a
// mount table with an NFS line in it; no CI machine has one mounted.
var mountTable = "/proc/self/mountinfo"

// osProveExclusive refuses a data dir on a filesystem whose flock cannot be relied on. On Linux
// the mount table is always there, so a mount table that cannot be read is itself a refusal: the
// condition is "cannot prove exclusive", not "proven shared". On another unix - where there is no
// /proc/self/mountinfo to read - there is nothing to prove it with and nothing claims there is, so
// the probe passes and the OS lock stands on its own.
func osProveExclusive(dataDir string) error {
	fsType, err := filesystemType(dataDir)
	if err != nil {
		if runtime.GOOS != "linux" {
			return nil
		}
		return fmt.Errorf("its filesystem type cannot be read, so the lock cannot be proven exclusive: %w", err)
	}
	if advisoryFilesystems[fsType] {
		return fmt.Errorf("it is on %s, where flock is advisory-only or the server's to honour and cannot be proven exclusive", fsType)
	}
	// The same question, asked of the kernel instead of the mount table, and refused on either
	// answer. The mount table is text a container, a bind mount or a chroot can make describe a
	// mount this process is not on; statfs describes the directory. It can only add a refusal: a
	// statfs that fails says nothing (see statfsNetworkFS), and one that says "local" does not
	// rescue a mount table that said otherwise, because the refusals above have already returned.
	if name, network := statfsNetworkFS(dataDir); network {
		return fmt.Errorf("statfs reports it on %s, where an exclusive lock is the server's to honour and cannot be proven", name)
	}
	return nil
}

// filesystemType returns the type of the filesystem the path is on, by finding the longest mount
// point in the mount table that the path sits under. mountinfo's own format: fields up to a lone
// "-" describe the mount, the mount point is the fifth of them, and the first field after the "-"
// is the filesystem type.
func filesystemType(path string) (string, error) {
	abs, err := resolveForMountLookup(path)
	if err != nil {
		return "", err
	}
	f, err := os.Open(filepath.Clean(mountTable))
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	best, bestType := "", ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		left, right, ok := strings.Cut(sc.Text(), " - ")
		if !ok {
			continue
		}
		fields := strings.Fields(left)
		after := strings.Fields(right)
		if len(fields) < 5 || len(after) < 1 {
			continue
		}
		point := unescapeMount(fields[4])
		if !underMount(abs, point) || len(point) < len(best) {
			continue
		}
		best, bestType = point, after[0]
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	if bestType == "" {
		return "", errors.New("no mount point covers the path")
	}
	return bestType, nil
}

// resolveForMountLookup is the path the mount table is asked about: absolute, and with every
// symlink resolved. A lexical path is not an answer to "which filesystem is this on" - a data dir
// under /var/lib that is a link into an NFS mount reads back as the root filesystem's type, and the
// one filesystem the probe exists to refuse is the one it would then allow.
//
// Two failure shapes, deliberately different. A path that is not there yet cannot be resolved and
// is not lying about anything either - `vault init` takes the lock before the data dir exists, and
// AcquireLock's own MkdirAll runs before the probe - so it keeps the lexical form. A path that is
// there and still cannot be resolved (a dangling link, a component that cannot be traversed) is a
// refusal: nothing here knows what it would land on, and "cannot prove exclusive" is the condition.
func resolveForMountLookup(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err == nil {
		return resolved, nil
	}
	// #nosec G703 -- abs is the operator's own --data-dir made absolute; this only asks whether it exists
	if _, lerr := os.Lstat(filepath.Clean(abs)); errors.Is(lerr, os.ErrNotExist) {
		return abs, nil
	}
	return "", fmt.Errorf("resolve %s: %w", abs, err)
}

// underMount reports whether path is at or below the mount point, on a component boundary: /datax
// is not under /data.
func underMount(path, point string) bool {
	if point == "/" {
		return true
	}
	return path == point || strings.HasPrefix(path, point+"/")
}

// unescapeMount undoes the octal escapes mountinfo uses for the four bytes a space-separated field
// cannot hold: space, tab, newline and backslash. A data dir with a space in its path reads back
// as itself, so the mount point comparison is not silently wrong about it.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+3 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		var v byte
		ok := true
		for _, c := range []byte(s[i+1 : i+4]) {
			if c < '0' || c > '7' {
				ok = false
				break
			}
			v = v*8 + (c - '0')
		}
		if !ok {
			b.WriteByte(s[i])
			continue
		}
		b.WriteByte(v)
		i += 3
	}
	return b.String()
}
