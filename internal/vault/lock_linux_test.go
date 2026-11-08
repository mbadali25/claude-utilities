//go:build linux

package vault

import "testing"

// The statfs probe is the second, independent answer to the same question /proc/self/mountinfo
// answers, and a magic typed wrong silently never matches - so the table is asserted rather than
// trusted. No CI machine has an NFS or SMB mount, which is why the values and not a real mount are
// what this checks; the live call is exercised against the test's own temp dir, which must read as
// local or every lock test would refuse.
func TestNetworkMagicsNameTheFilesystemsTheyAreFor(t *testing.T) {
	for magic, want := range map[uint32]string{
		0x6969:     "nfs",
		0x517b:     "smb",
		0xff534d42: "cifs",
		0xfe534d42: "smb2",
		0x73757245: "coda",
		0x5346414f: "afs",
		0x01021997: "9p",
		0x65735546: "fuse",
		0x564c:     "ncpfs",
	} {
		if got := networkMagics[magic]; got != want {
			t.Errorf("networkMagics[%#x] = %q, want %q", magic, got, want)
		}
	}
	if len(networkMagics) != 9 {
		t.Errorf("networkMagics has %d entries, want 9", len(networkMagics))
	}
}

func TestStatfsReadsTheLocalTempDirAsLocal(t *testing.T) {
	if name, network := statfsNetworkFS(t.TempDir()); network {
		t.Fatalf("the test temp dir reads as %s: every lock test would refuse", name)
	}
	// A path the kernel cannot stat says nothing, and must not become a refusal: the mount table is
	// the probe that reports "cannot prove exclusive", and this one only ever adds a refusal.
	if name, network := statfsNetworkFS("/this/path/does/not/exist"); network {
		t.Fatalf("a path that cannot be statfs'd reported as %s", name)
	}
}
