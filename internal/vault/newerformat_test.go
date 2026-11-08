package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Shelf life: two assertions here are deliberately temporary. Task 3a.2 of the cert-vault plan
// makes CSV2 the current format, at which point a CSV2 file is no longer "newer" and
// ErrNewerFormat moves to a header v other than 2. That task owns the inversion of
// TestOpenV2VaultReturnsErrNewerFormat and TestOpenV2KeyringReturnsErrNewerFormat. Until then
// these are correct for the window in which v1 is the current format.

// v2Fixture is the synthetic 40-byte "written by a newer server" header: the magic, a plausible
// header length and filler. It holds no key material and no payload, nothing in it can be
// decrypted, and nothing in this package may write a file in this format.
func v2Fixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "newer-v2-header.bin"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	// Guards the one way this fixture rots silently: a checkout filter or an editor that prepends
	// a BOM or rewrites line endings moves the magic off byte 0, and every test below then passes
	// for the wrong reason.
	if len(data) != 40 || !strings.HasPrefix(string(data), newerVaultMagic) {
		t.Fatalf("fixture is %d bytes and does not start with %s", len(data), newerVaultMagic)
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

func TestOpenV2VaultReturnsErrNewerFormat(t *testing.T) {
	p := writeFixture(t, t.TempDir(), "vault.bin", v2Fixture(t))
	_, err := open(t, p, "pw")
	if !errors.Is(err, ErrNewerFormat) {
		t.Fatalf("want ErrNewerFormat, got %v", err)
	}
	// "malformed vault file" is what sends an operator looking for a corrupt disk or a wrong
	// passphrase. A newer format must never also report as malformed.
	if errors.Is(err, errCorrupt) {
		t.Fatalf("also reports as malformed: %v", err)
	}
}

func TestOpenV2KeyringReturnsErrNewerFormat(t *testing.T) {
	t.Setenv(keyEnv, "pw")
	p := writeFixture(t, t.TempDir(), KeyringFileName, withMagic(t, newerKeyringMagic))
	_, err := OpenKeyring(p, keyEnv)
	if !errors.Is(err, ErrNewerFormat) {
		t.Fatalf("want ErrNewerFormat, got %v", err)
	}
	if errors.Is(err, errCorrupt) {
		t.Fatalf("also reports as malformed: %v", err)
	}
}

// A newer magic is recognised only against the magic the caller asked for. Recognising either v2
// magic in either reader would be the first step towards a keyring opening as a vault.
func TestCrossMagicStillErrCorrupt(t *testing.T) {
	t.Setenv(keyEnv, "pw")
	dir := t.TempDir()
	kp := writeFixture(t, dir, "keyring-bytes-in-a-vault-path.bin", withMagic(t, newerKeyringMagic))
	if _, err := Open(kp, keyEnv); !errors.Is(err, errCorrupt) || errors.Is(err, ErrNewerFormat) {
		t.Fatalf("CSK2 opened as a vault: want errCorrupt, got %v", err)
	}
	vp := writeFixture(t, dir, "vault-bytes-in-a-keyring-path.bin", v2Fixture(t))
	if _, err := OpenKeyring(vp, keyEnv); !errors.Is(err, errCorrupt) || errors.Is(err, ErrNewerFormat) {
		t.Fatalf("CSV2 opened as a keyring: want errCorrupt, got %v", err)
	}
}

func TestUnknownMagicStillErrCorrupt(t *testing.T) {
	p := writeFixture(t, t.TempDir(), "vault.bin", withMagic(t, "CSV9"))
	_, err := open(t, p, "pw")
	if !errors.Is(err, errCorrupt) || errors.Is(err, ErrNewerFormat) {
		t.Fatalf("want errCorrupt, got %v", err)
	}
}

func TestShortFileStillErrCorrupt(t *testing.T) {
	// Three bytes cannot hold a four-byte magic: the prefix test must not index past the end.
	p := writeFixture(t, t.TempDir(), "vault.bin", []byte("CSV"))
	_, err := open(t, p, "pw")
	if !errors.Is(err, errCorrupt) || errors.Is(err, ErrNewerFormat) {
		t.Fatalf("want errCorrupt, got %v", err)
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
