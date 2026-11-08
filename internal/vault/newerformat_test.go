package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The shelf life this file was written with has expired, as planned: Task 3a.2 made CSV2 the
// current format, so a CSV2 file is no longer "written by a newer server" and ErrNewerFormat moved
// from the magic to the header's `v`. The two assertions that said otherwise are inverted below
// rather than deleted, and the `v != 2` half of ErrNewerFormat is pinned by TestClosedTopLevelHeader
// in slots_test.go. TestErrNewerFormatMessageNamesDowngrade rides on that path now and is unchanged.

// v2Fixture is the committed 40-byte CSV2 file: the magic, a header length of 24 and filler. It is
// now what it always literally was - a **malformed** v2 header - and that is why it is kept rather
// than retired: it says its header is 24 bytes long, which puts the whole file 20 bytes under the
// 8 + hdrLen + 12 + 16 minimum, so it is the on-disk case for the length bound. It holds no key
// material and no payload, and nothing in this package may write a file in this format.
func v2Fixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "newer-v2-header.bin"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	// Guards the one way this fixture rots silently: a checkout filter or an editor that prepends
	// a BOM or rewrites line endings moves the magic off byte 0, and every test below then passes
	// for the wrong reason.
	if len(data) != 40 || !strings.HasPrefix(string(data), v2VaultMagic) {
		t.Fatalf("fixture is %d bytes and does not start with %s", len(data), v2VaultMagic)
	}
	return data
}

// withMagic copies the fixture with its first four bytes replaced, so one committed fixture
// covers the keyring and the unknown-magic cases too.
func withMagic(t *testing.T, m string) []byte {
	t.Helper()
	b := append([]byte(nil), v2Fixture(t)...)
	copy(b, m)
	return b
}

// writeFixture drops data in a temp dir under the name the server would read it by.
func writeFixture(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return p
}

// The inversion. A CSV2 file is parsed now, so this fixture's 24-byte header claim against a
// 40-byte file is a malformed v2 header: errCorrupt, and never ErrNewerFormat, because the magic no
// longer names a writer this binary cannot follow.
func TestOpenACSV2FileWithAMalformedHeaderIsErrCorrupt(t *testing.T) {
	p := writeFixture(t, t.TempDir(), "vault.bin", v2Fixture(t))
	_, err := open(t, p, "pw")
	if !errors.Is(err, errCorrupt) {
		t.Fatalf("want errCorrupt, got %v", err)
	}
	if errors.Is(err, ErrNewerFormat) {
		t.Fatalf("still reports as a newer format: %v", err)
	}
	// Never a bad key either: a crafted header must not push an operator towards rotating a
	// correct passphrase.
	if errors.Is(err, ErrBadKey) {
		t.Fatalf("reports a bad key for an unparseable header: %v", err)
	}
}

func TestOpenACSK2FileWithAMalformedHeaderIsErrCorrupt(t *testing.T) {
	t.Setenv(keyEnv, "pw")
	p := writeFixture(t, t.TempDir(), KeyringFileName, withMagic(t, v2KeyringMagic))
	_, err := OpenKeyring(p, EnvKey(keyEnv))
	if !errors.Is(err, errCorrupt) {
		t.Fatalf("want errCorrupt, got %v", err)
	}
	if errors.Is(err, ErrNewerFormat) {
		t.Fatalf("still reports as a newer format: %v", err)
	}
}

// A v2 magic is recognised only against the magic the caller asked for. Recognising either v2
// magic in either reader would be the first step towards a keyring opening as a vault.
func TestCrossMagicStillErrCorrupt(t *testing.T) {
	t.Setenv(keyEnv, "pw")
	dir := t.TempDir()
	kp := writeFixture(t, dir, "keyring-bytes-in-a-vault-path.bin", withMagic(t, v2KeyringMagic))
	if _, err := Open(kp, EnvKey(keyEnv)); !errors.Is(err, errCorrupt) {
		t.Fatalf("CSK2 opened as a vault: want errCorrupt, got %v", err)
	}
	vp := writeFixture(t, dir, "vault-bytes-in-a-keyring-path.bin", v2Fixture(t))
	if _, err := OpenKeyring(vp, EnvKey(keyEnv)); !errors.Is(err, errCorrupt) {
		t.Fatalf("CSV2 opened as a keyring: want errCorrupt, got %v", err)
	}
}

func TestUnknownMagicStillErrCorrupt(t *testing.T) {
	p := writeFixture(t, t.TempDir(), "vault.bin", withMagic(t, "CSV9"))
	_, err := open(t, p, "pw")
	if !errors.Is(err, errCorrupt) {
		t.Fatalf("want errCorrupt, got %v", err)
	}
}

func TestShortFileStillErrCorrupt(t *testing.T) {
	// Three bytes cannot hold a four-byte magic: the prefix test must not index past the end.
	p := writeFixture(t, t.TempDir(), "vault.bin", []byte("CSV"))
	_, err := open(t, p, "pw")
	if !errors.Is(err, errCorrupt) {
		t.Fatalf("want errCorrupt, got %v", err)
	}
}

// --- the order of the passphrase check against the v2 branch ---
//
// Reading the magic and parsing a header need no passphrase, so the one answer a v2 file must never
// produce is "set environment variable": the operator would go and set a key for a file whose
// header cannot be read, and the temptation after that is to rotate the passphrase. The four tests
// below pin the whole ordering, not just the cases that changed: the two that assert ErrNoKey are
// the regression pins for it.

func TestOpenAMalformedCSV2WithNoKeyStillReportsMalformed(t *testing.T) {
	p := writeFixture(t, t.TempDir(), "vault.bin", v2Fixture(t))
	_, err := open(t, p, "")
	if !errors.Is(err, errCorrupt) {
		t.Fatalf("want errCorrupt, got %v - any other answer sends the operator to set a key for "+
			"a file whose header cannot be read", err)
	}
	if errors.Is(err, ErrNoKey) {
		t.Fatalf("the header answer moved behind the key check: %v", err)
	}
}

func TestOpenAMalformedCSK2WithNoKeyStillReportsMalformed(t *testing.T) {
	t.Setenv(keyEnv, "")
	p := writeFixture(t, t.TempDir(), KeyringFileName, withMagic(t, v2KeyringMagic))
	_, err := OpenKeyring(p, EnvKey(keyEnv))
	if !errors.Is(err, errCorrupt) {
		t.Fatalf("want errCorrupt, got %v", err)
	}
	if errors.Is(err, ErrNoKey) {
		t.Fatalf("the header answer moved behind the key check: %v", err)
	}
}

// A v1 file still asks for the passphrase first: that one IS openable once the key is set.
func TestOpenV1VaultWithNoKeyStillReportsNoKey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vault.bin")
	v, err := open(t, p, "pw")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := v.Put(acct("a")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := open(t, p, ""); !errors.Is(err, ErrNoKey) {
		t.Fatalf("want ErrNoKey, got %v", err)
	}
}

// An unknown magic with no key answers ErrNoKey, as it did before the reorder: this binary cannot
// say whether the file is damaged or merely sealed with a key it has not been given.
func TestOpenCorruptVaultWithNoKeyStillReportsNoKey(t *testing.T) {
	p := writeFixture(t, t.TempDir(), "vault.bin", withMagic(t, "CSV9"))
	if _, err := open(t, p, ""); !errors.Is(err, ErrNoKey) {
		t.Fatalf("want ErrNoKey, got %v - the corrupt row moved ahead of the key check", err)
	}
}

func TestErrNewerFormatMessageNamesDowngrade(t *testing.T) {
	msg := ErrNewerFormat.Error()
	for _, want := range []string{"newer server", "server vault downgrade"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message %q does not name %q", msg, want)
		}
	}
	if strings.Contains(msg, "malformed") {
		t.Fatalf("message %q still says malformed", msg)
	}
}

// The v1 path is untouched: the magic test adds a case, it does not replace one.
func TestV1OpenIsUnaffected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "vault.bin")
	v, err := open(t, p, "pw")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := v.Put(acct("a")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	again, err := open(t, p, "pw")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got, ok := again.Get("a"); !ok || got.Label != "La" {
		t.Fatalf("v1 round trip lost the account: %+v ok=%v", got, ok)
	}
}
