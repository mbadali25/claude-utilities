//go:build linux

package vault

import "golang.org/x/sys/unix"

// networkMagics are the statfs f_type values of filesystems where a flock is not this process's to
// rely on, by the name an operator would recognise them under.
//
// This is deliberately a second source for the question /proc/self/mountinfo already answers, not
// a replacement for it. The mount table is text, and a container, a bind mount or a chroot can make
// it describe a mount this process is not actually on; statfs asks the kernel about the directory
// itself. Either saying "network" is enough to refuse (see osProveExclusive), because the failure
// being prevented - two writers who both believe they are alone - is not one worth a second chance.
//
// CIFS_MAGIC_NUMBER and SMB2_MAGIC_NUMBER are not exported by golang.org/x/sys/unix v0.47.0, so
// those two carry their value and the kernel header it comes from; the rest use the package's
// constants rather than hand-typed hex, because a magic typed wrong silently never matches.
var networkMagics = map[uint32]string{
	unix.NFS_SUPER_MAGIC:  "nfs",
	unix.SMB_SUPER_MAGIC:  "smb",
	0xff534d42:            "cifs", // CIFS_MAGIC_NUMBER, fs/smb/client/cifsfs.h
	0xfe534d42:            "smb2", // SMB2_MAGIC_NUMBER, fs/smb/client/cifsglob.h
	unix.CODA_SUPER_MAGIC: "coda",
	unix.AFS_SUPER_MAGIC:  "afs",
	unix.V9FS_MAGIC:       "9p",
	unix.FUSE_SUPER_MAGIC: "fuse",
	unix.NCP_SUPER_MAGIC:  "ncpfs",
}

// statfsNetworkFS names the filesystem under path when it is one no exclusive lock can be proven
// on, and reports false otherwise. statfs resolves the path itself, so it needs no EvalSymlinks of
// its own.
//
// A failed call reports false, never a refusal: the path may not exist yet (`vault init` probes
// before it creates), and the mount table is the probe that owns the "cannot prove exclusive"
// answer. This one only ever adds a refusal.
func statfsNetworkFS(path string) (string, bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return "", false
	}
	// f_type is a 32-bit magic the kernel hands back in a word whose width and signedness differ by
	// architecture (int64 on amd64 and arm64, int32 on 386). Taking the low 32 bits back as uint32
	// is the one conversion that reads the same magic on all of them.
	name, ok := networkMagics[uint32(st.Type)] //nolint:gosec // narrowing a 32-bit magic back to 32 bits
	return name, ok
}
