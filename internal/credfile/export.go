package credfile

// RestrictFile makes path owner-only on Windows (ACL); a no-op elsewhere,
// where callers set 0600 directly. Exported for other secret stores.
func RestrictFile(path string) error { return restrictACL(path, false) }

// RestrictDir makes the directory at path owner-only on Windows (ACL); a no-op elsewhere.
func RestrictDir(path string) error { return restrictACL(path, true) }

// SyncDir fsyncs dir so a rename inside it is durable. Best effort; no-op on Windows.
func SyncDir(dir string) { syncDir(dir) }
