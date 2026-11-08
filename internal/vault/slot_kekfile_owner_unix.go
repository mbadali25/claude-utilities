//go:build unix

package vault

import (
	"io/fs"
	"syscall"
)

// fileOwnerUID reports the uid that owns the file this FileInfo describes, and whether this
// platform could say at all. The unix half: os.Stat fills Sys() with a *syscall.Stat_t everywhere
// the `unix` build tag applies, so `known` is false only if some future platform stops doing so.
//
// It exists for one check, on the credstore routes only: the KEK file must be root-owned. The 0600
// mode check alone proves less than it looks - a root-owned 0700 directory holding a file some
// other account owns is still a 0600 file, and the owner is then the account the slot is supposed
// to be keeping the key away from. The directory's mode is not the file's.
//
// The build tag is `unix` and not `!windows`, because syscall.Stat_t does not exist on plan9 or
// js/wasm either.
func fileOwnerUID(fi fs.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}
