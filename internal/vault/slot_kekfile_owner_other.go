//go:build !unix

package vault

import "io/fs"

// fileOwnerUID, everywhere that is not unix. There is nothing to report: a Windows file is owned by
// a SID, not a uid, and fs.FileInfo carries no equivalent. So `known` is false and the caller skips
// the root-ownership check rather than inventing an answer.
//
// That costs nothing here. The credstore routes this check guards are reachable only as uid 0, and
// os.Geteuid returns -1 on Windows, so they are structurally unreachable on the platform where this
// file compiles.
func fileOwnerUID(fs.FileInfo) (int, bool) { return 0, false }
