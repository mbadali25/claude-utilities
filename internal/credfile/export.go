package credfile

// RestrictFile restricts path's Windows ACL to the owner plus whatever SIDs SetACLPolicy named
// (owner-only by default); a no-op elsewhere, where callers set 0600 directly. Exported for
// other secret stores.
func RestrictFile(path string) error { return restrictACL(path, false) }

// RestrictDir does the same for the directory at path, with inheritable grants so files created
// inside start with the same access; a no-op outside Windows.
func RestrictDir(path string) error { return restrictACL(path, true) }

// SyncDir fsyncs dir so a rename inside it is durable. Best effort; no-op on Windows.
func SyncDir(dir string) { syncDir(dir) }
