package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"claude-utilities/internal/adminpw"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// noStdin stands in for a closed stdin: run must not read it unless set-password was asked for.
func noStdin() *strings.Reader { return strings.NewReader("") }

func TestListenRequiredRefusesStartWithoutFlag(t *testing.T) {
	var out bytes.Buffer
	full := map[string]string{keyEnv: "k", passwordEnv: "p"}
	if code := run(context.Background(), nil, env(full), noStdin(), &out); code == 0 || !strings.Contains(out.String(), "--listen") {
		t.Fatalf("code %d out %q", code, out.String())
	}
}

func TestMissingSecretsRefuseStart(t *testing.T) {
	for _, m := range []map[string]string{{passwordEnv: "p"}, {keyEnv: "k"}} {
		var out bytes.Buffer
		code := run(context.Background(), []string{"--listen", "127.0.0.1:0", "--data-dir", t.TempDir()}, env(m), noStdin(), &out)
		if code == 0 || !strings.Contains(out.String(), "CLAUDESWAP_") {
			t.Fatalf("env %v: code %d out %q", m, code, out.String())
		}
	}
}

func TestBadListenAddressRefused(t *testing.T) {
	var out bytes.Buffer
	args := []string{"--listen", "nonsense", "--data-dir", t.TempDir()}
	if code := run(context.Background(), args, env(map[string]string{keyEnv: "k", passwordEnv: "p"}), noStdin(), &out); code == 0 {
		t.Fatalf("accepted %q", out.String())
	}
}

// --- set-password ---

// setPassword runs the subcommand against dir with stdin holding in.
func setPassword(t *testing.T, dir, in string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := run(context.Background(), []string{"set-password", "--data-dir", dir}, env(nil), strings.NewReader(in), &out)
	return code, out.String()
}

func TestSetPasswordReadsStdinAndStoresAHash(t *testing.T) {
	dir := t.TempDir()
	if code, out := setPassword(t, dir, "a-long-enough-password\n"); code != 0 {
		t.Fatalf("code %d out %q", code, out)
	}
	p := filepath.Join(dir, adminpw.FileName)
	data, err := os.ReadFile(p) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("hash file: %v", err)
	}
	if strings.Contains(string(data), "a-long-enough-password") {
		t.Fatal("the hash file holds the plaintext")
	}
	// A new store over the same dir authenticates it, and ignores a different bootstrap.
	s, err := adminpw.Open(p, "env-bootstrap-value")
	if err != nil {
		t.Fatal(err)
	}
	if !s.Stored() || !s.Verify("a-long-enough-password") || s.Verify("env-bootstrap-value") {
		t.Fatalf("stored=%v stdin=%v env=%v", s.Stored(), s.Verify("a-long-enough-password"), s.Verify("env-bootstrap-value"))
	}
}

func TestSetPasswordAcceptsStdinWithoutATrailingNewline(t *testing.T) {
	dir := t.TempDir()
	if code, out := setPassword(t, dir, "no-trailing-newline-pw"); code != 0 {
		t.Fatalf("code %d out %q", code, out)
	}
	s, err := adminpw.Open(filepath.Join(dir, adminpw.FileName), "")
	if err != nil {
		t.Fatal(err)
	}
	if !s.Verify("no-trailing-newline-pw") {
		t.Fatal("password not stored as typed")
	}
}

func TestSetPasswordRefusesTooShortAndWritesNothing(t *testing.T) {
	dir := t.TempDir()
	code, out := setPassword(t, dir, strings.Repeat("x", adminpw.MinLength-1)+"\n")
	if code != 2 || !strings.Contains(out, "at least 12 characters") {
		t.Fatalf("code %d out %q", code, out)
	}
	if _, err := os.Stat(filepath.Join(dir, adminpw.FileName)); !os.IsNotExist(err) {
		t.Fatalf("hash file written for a short password: %v", err)
	}
}

func TestSetPasswordRefusesEmptyStdin(t *testing.T) {
	dir := t.TempDir()
	if code, out := setPassword(t, dir, ""); code != 2 || !strings.Contains(out, "stdin") {
		t.Fatalf("code %d out %q", code, out)
	}
}

func TestSetPasswordHasNoPasswordFlagOrArgument(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	args := []string{"set-password", "--data-dir", dir, "--password", "a-long-enough-password"}
	if code := run(context.Background(), args, env(nil), noStdin(), &out); code == 0 {
		t.Fatalf("--password accepted: %q", out.String())
	}
	out.Reset()
	args = []string{"set-password", "--data-dir", dir, "a-long-enough-password"}
	if code := run(context.Background(), args, env(nil), noStdin(), &out); code == 0 {
		t.Fatalf("a positional password accepted: %q", out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, adminpw.FileName)); !os.IsNotExist(err) {
		t.Fatalf("a hash was written from argv: %v", err)
	}
}

func TestServerStartsWithAStoredHashAndNoEnvPassword(t *testing.T) {
	dir := t.TempDir()
	if code, out := setPassword(t, dir, "a-long-enough-password\n"); code != 0 {
		t.Fatalf("set-password code %d out %q", code, out)
	}
	// With a hash on disk the admin password environment variable is no longer required, so the
	// only complaint left is the missing listen address.
	var out bytes.Buffer
	code := run(context.Background(), []string{"--data-dir", dir}, env(map[string]string{keyEnv: "k"}), noStdin(), &out)
	if code != 2 || !strings.Contains(out.String(), "--listen") {
		t.Fatalf("code %d out %q", code, out.String())
	}
	if strings.Contains(out.String(), passwordEnv) {
		t.Fatalf("still demands %s with a hash stored: %q", passwordEnv, out.String())
	}
}

func TestServerRefusesACorruptPasswordFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, adminpw.FileName), []byte(`{"v":1,"algo":"nope"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	args := []string{"--listen", "127.0.0.1:0", "--data-dir", dir}
	code := run(context.Background(), args, env(map[string]string{keyEnv: "k", passwordEnv: "p"}), noStdin(), &out)
	if code == 0 || !strings.Contains(out.String(), "admin password file") {
		t.Fatalf("code %d out %q", code, out.String())
	}
}
