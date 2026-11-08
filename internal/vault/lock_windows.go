//go:build windows

package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// lockHandle takes the mandatory exclusive byte-range lock Windows offers:
// LOCKFILE_EXCLUSIVE_LOCK with LOCKFILE_FAIL_IMMEDIATELY, over one byte at lockOffset. It never
// blocks, and a range another handle already holds comes back as errLockBusy - including a handle
// in this same process, because byte-range locks are per-handle.
func lockHandle(f *os.File) error {
	err := windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		uint32(lockLen),
		0,
		overlappedAtLockOffset(),
	)
	if err == nil {
		return nil
	}
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
		return errLockBusy
	}
	return err
}

func unlockHandle(f *os.File) error {
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, uint32(lockLen), 0, overlappedAtLockOffset())
}

// lockOpenNoFollow is zero here: Windows has no O_NOFOLLOW, so a reparse point at the lock path is
// refused by AcquireLock's os.Lstat before the open rather than by the open itself. The narrow
// window that leaves - the path swapped between the Lstat and the open - needs write access to the
// data dir to reach, and closing it would mean CreateFile with FILE_FLAG_OPEN_REPARSE_POINT plus
// GetFileInformationByHandle and os.NewFile in place of one os.OpenFile. Recorded rather than done.
const lockOpenNoFollow = 0

// overlappedAtLockOffset points the lock at the single byte at lockOffset. Locking a region beyond
// the end of the file is allowed and does not extend it, which is why the lock file stays a few
// hundred bytes rather than becoming a sparse 1 TiB file in every data dir.
func overlappedAtLockOffset() *windows.Overlapped {
	return &windows.Overlapped{
		Offset:     uint32(lockOffset & 0xFFFFFFFF),
		OffsetHigh: uint32(lockOffset >> 32),
	}
}

// osProveExclusive refuses a data dir whose lock this process may not rely on. LockFileEx is
// mandatory on a local volume, but over SMB it is the redirector's to honour: a mapped drive or a
// UNC path can report a lock taken that another client never sees, and two servers would then both
// write the vault believing they were alone (Review Focus 1). A volume whose type cannot be
// established is refused too, because "cannot prove exclusive" is the condition, not "proven
// shared".
func osProveExclusive(dataDir string) error {
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return fmt.Errorf("resolve the path: %w", err)
	}
	// \\?\ only turns off path parsing; what follows still says local volume or UNC share.
	trimmed := strings.TrimPrefix(abs, `\\?\`)
	if strings.HasPrefix(trimmed, `UNC\`) || strings.HasPrefix(trimmed, `\\`) {
		return errors.New("it is a UNC network path, where an exclusive lock is the server's to honour and cannot be proven")
	}
	vol := filepath.VolumeName(trimmed)
	if vol == "" {
		return errors.New("its volume cannot be determined, so the lock cannot be proven exclusive")
	}
	root, err := windows.UTF16PtrFromString(vol + `\`)
	if err != nil {
		return fmt.Errorf("read the volume name: %w", err)
	}
	switch windows.GetDriveType(root) {
	case windows.DRIVE_REMOTE:
		return errors.New("it is on a network drive, where an exclusive lock is the server's to honour and cannot be proven")
	case windows.DRIVE_UNKNOWN, windows.DRIVE_NO_ROOT_DIR:
		return errors.New("its volume type cannot be read, so the lock cannot be proven exclusive")
	}
	return nil
}
