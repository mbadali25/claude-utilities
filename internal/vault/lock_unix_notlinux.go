//go:build !windows && !linux

package vault

// statfsNetworkFS is the statfs half of the exclusivity probe, and it exists only on Linux: the
// f_type magics it matches are Linux's, and Statfs_t does not carry the field on every unix. On
// another unix there is no /proc/self/mountinfo either, so the probe as a whole already stands
// down and the OS lock stands on its own - see osProveExclusive, which says so and why.
func statfsNetworkFS(string) (string, bool) { return "", false }
