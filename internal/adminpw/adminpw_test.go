package adminpw

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	boot = "bootstrap-from-env"
	good = "a-long-enough-password"
	next = "another-long-password"
)

func path(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), FileName)
}

func open(t *testing.T, p, bootstrap string) *Store {
	t.Helper()
	s, err := Open(p, bootstrap)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func TestBootstrapAuthenticatesUntilAHashIsStored(t *testing.T) {
	p := path(t)
	s := open(t, p, boot)
	if s.Stored() {
		t.Fatal("Stored() true with no file")
	}
	if !s.Verify(boot) {
		t.Fatal("bootstrap rejected while no hash is stored")
	}
	if s.Verify(good) || s.Verify("") {
		t.Fatal("a wrong or empty password verified")
	}
}

func TestNoBootstrapAndNoFileVerifiesNothing(t *testing.T) {
	s := open(t, path(t), "")
	for _, pw := range []string{"", boot, good} {
		if s.Verify(pw) {
			t.Fatalf("verified %q with neither hash nor bootstrap", pw)
		}
	}
}

func TestSetThenVerifyNewPasswordAndRejectOld(t *testing.T) {
	s := open(t, path(t), boot)
	if err := s.Set(good); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if !s.Stored() {
		t.Fatal("Stored() false after Set")
	}
	if !s.Verify(good) {
		t.Fatal("new password rejected")
	}
	if s.Verify(next) {
		t.Fatal("a wrong password verified")
	}
}

func TestStoredHashBeatsBootstrap(t *testing.T) {
	p := path(t)
	s := open(t, p, boot)
	if err := s.Set(good); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if s.Verify(boot) {
		t.Fatal("bootstrap still verifies after a hash was stored")
	}
	// A fresh store over the same file ignores the bootstrap too.
	s2 := open(t, p, boot)
	if !s2.Stored() || s2.Verify(boot) || !s2.Verify(good) {
		t.Fatalf("reopened: stored=%v boot=%v good=%v", s2.Stored(), s2.Verify(boot), s2.Verify(good))
	}
}

func TestPersistsAcrossRestart(t *testing.T) {
	p := path(t)
	if err := open(t, p, boot).Set(good); err != nil {
		t.Fatalf("Set: %v", err)
	}
	// A later process with no bootstrap at all still authenticates the stored password.
	s := open(t, p, "")
	if !s.Stored() || !s.Verify(good) {
		t.Fatalf("restart: stored=%v verify=%v", s.Stored(), s.Verify(good))
	}
	if err := s.Set(next); err != nil {
		t.Fatalf("Set again: %v", err)
	}
	s = open(t, p, "")
	if !s.Verify(next) || s.Verify(good) {
		t.Fatalf("replacement not persisted: next=%v good=%v", s.Verify(next), s.Verify(good))
	}
}

func TestSetRejectsTooShort(t *testing.T) {
	p := path(t)
	s := open(t, p, boot)
	short := strings.Repeat("x", MinLength-1)
	if err := s.Set(short); !errors.Is(err, ErrTooShort) {
		t.Fatalf("Set(%d chars) = %v, want ErrTooShort", len(short), err)
	}
	if s.Stored() || s.Verify(short) {
		t.Fatal("a rejected password was stored")
	}
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file written for a rejected password: %v", err)
	}
	if !s.Verify(boot) {
		t.Fatal("bootstrap stopped working after a rejected Set")
	}
	// Exactly MinLength characters is accepted, and length counts characters, not bytes.
	if err := s.Set(strings.Repeat("é", MinLength)); err != nil {
		t.Fatalf("Set(%d multi-byte chars): %v", MinLength, err)
	}
}

func TestFileHoldsNoPlaintextAndIsOwnerOnly(t *testing.T) {
	p := path(t)
	if err := open(t, p, boot).Set(good); err != nil {
		t.Fatalf("Set: %v", err)
	}
	data, err := os.ReadFile(p) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{good, boot} {
		if strings.Contains(string(data), bad) {
			t.Fatalf("file holds the plaintext %q", bad)
		}
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != fs.FileMode(0o600) {
		t.Fatalf("mode %v, want 0600", st.Mode().Perm())
	}
}

func TestOpenRejectsCorruptFile(t *testing.T) {
	cases := map[string]string{
		"not json":      `{`,
		"wrong algo":    `{"v":1,"algo":"bcrypt","time":3,"memKiB":65536,"par":4,"salt":"AAAAAAAAAAAAAAAAAAAAAA==","hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`,
		"wrong version": `{"v":2,"algo":"argon2id","time":3,"memKiB":65536,"par":4,"salt":"AAAAAAAAAAAAAAAAAAAAAA==","hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`,
		"short salt":    `{"v":1,"algo":"argon2id","time":3,"memKiB":65536,"par":4,"salt":"AAAA","hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`,
		"zero time":     `{"v":1,"algo":"argon2id","time":0,"memKiB":65536,"par":4,"salt":"AAAAAAAAAAAAAAAAAAAAAA==","hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`,
		"huge memory":   `{"v":1,"algo":"argon2id","time":3,"memKiB":4294967295,"par":4,"salt":"AAAAAAAAAAAAAAAAAAAAAA==","hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			p := path(t)
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(p, boot); err == nil {
				t.Fatal("Open accepted a malformed file")
			}
		})
	}
}

func TestSetFailureKeepsThePreviousPassword(t *testing.T) {
	p := path(t)
	s := open(t, p, boot)
	if err := s.Set(good); err != nil {
		t.Fatalf("Set: %v", err)
	}
	old := renameFn
	renameFn = func(string, string) error { return errors.New("injected rename failure") }
	defer func() { renameFn = old }()
	if err := s.Set(next); err == nil {
		t.Fatal("Set succeeded with a failing rename")
	}
	if !s.Verify(good) || s.Verify(next) {
		t.Fatalf("failed write changed the password: good=%v next=%v", s.Verify(good), s.Verify(next))
	}
	// No temp file is left behind holding the abandoned hash.
	ents, err := os.ReadDir(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}
