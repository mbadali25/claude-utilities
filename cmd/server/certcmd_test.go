package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"claude-utilities/internal/hub"
)

// certRun drives `server cert ...` the way main does, with in on stdin and one buffer for both
// streams (the binary writes everything to stderr today).
func certRun(args []string, in string) (int, string) {
	var out bytes.Buffer
	code := certCmd(args, strings.NewReader(in), &out, &out)
	return code, out.String()
}

// seedPair puts a real, loadable pair in <dir>/tls and returns the data dir and its fingerprint.
func seedPair(t *testing.T) (dataDir, fp string) {
	t.Helper()
	dataDir = t.TempDir()
	_, _, fp, err := hub.EnsureCert(filepath.Join(dataDir, "tls"))
	if err != nil {
		t.Fatal(err)
	}
	return dataDir, fp
}

func pairBytes(t *testing.T, dataDir string) [2][]byte {
	t.Helper()
	var out [2][]byte
	for i, name := range []string{"server-cert.pem", "server-key.pem"} {
		b, err := os.ReadFile(filepath.Join(dataDir, "tls", name))
		if err != nil {
			b = nil
		}
		out[i] = b
	}
	return out
}

func TestCertRenewWritesANewPairAndPrintsBothFingerprints(t *testing.T) {
	dataDir, oldFP := seedPair(t)
	code, out := certRun([]string{"renew", "--data-dir", dataDir}, "renew\n")
	if code != 0 {
		t.Fatalf("code %d out %q", code, out)
	}
	_, _, newFP, err := hub.EnsureCert(filepath.Join(dataDir, "tls"))
	if err != nil {
		t.Fatal(err)
	}
	if newFP == oldFP {
		t.Fatal("renew left the old pair in place")
	}
	for _, want := range []string{oldFP, newFP, "re-enrol"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output must name %q: %q", want, out)
		}
	}
}

func TestCertRenewRefusesWithoutTheTypedConfirmation(t *testing.T) {
	for _, in := range []string{"", "\n", "y\n", "yes\n", "RENEW\n"} {
		dataDir, oldFP := seedPair(t)
		before := pairBytes(t, dataDir)
		code, out := certRun([]string{"renew", "--data-dir", dataDir}, in)
		if code != 2 {
			t.Fatalf("stdin %q: code %d out %q", in, code, out)
		}
		if after := pairBytes(t, dataDir); !bytes.Equal(before[0], after[0]) || !bytes.Equal(before[1], after[1]) {
			t.Fatalf("stdin %q: the pair was written without a confirmation", in)
		}
		if _, _, fp, err := hub.EnsureCert(filepath.Join(dataDir, "tls")); err != nil || fp != oldFP {
			t.Fatalf("stdin %q: the pin moved: %q want %q err %v", in, fp, oldFP, err)
		}
	}
}

func TestCertRenewOnAnUnreadablePairStillRefuses(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits; hub's TestEnsureCertRefusesUnreadableKeyWindows covers the deny-ACE path")
	}
	dataDir, _ := seedPair(t)
	key := filepath.Join(dataDir, "tls", "server-key.pem")
	if err := os.Chmod(key, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(key, 0o600) })
	if _, err := os.ReadFile(key); err == nil {
		t.Skip("a 0000 mode does not deny this process (running as root?): the key stayed readable")
	}
	before := pairBytes(t, dataDir)
	code, out := certRun([]string{"renew", "--data-dir", dataDir}, "renew\n")
	if code != 5 {
		t.Fatalf("code %d, want 5: %q", code, out)
	}
	if err := os.Chmod(key, 0o600); err != nil {
		t.Fatal(err)
	}
	after := pairBytes(t, dataDir)
	if !bytes.Equal(before[0], after[0]) || !bytes.Equal(before[1], after[1]) {
		t.Fatal("renew replaced a pair it could not read")
	}
}

func TestCertRenewGeneratesWhenNeitherFileExists(t *testing.T) {
	dataDir := t.TempDir()
	code, out := certRun([]string{"renew", "--data-dir", dataDir}, "renew\n")
	if code != 0 {
		t.Fatalf("code %d out %q", code, out)
	}
	if _, _, fp, err := hub.EnsureCert(filepath.Join(dataDir, "tls")); err != nil || len(fp) != 64 {
		t.Fatalf("no pair written: fp %q err %v", fp, err)
	}
}

// TestCertRenewTakesNoDataDirLockYet is a tripwire, not an endorsement: `cert renew` is a mutator
// and Global Constraints / Locking of the cert-vault plan says it must hold
// <data-dir>/.claude-swap.lock for the command. The lock does not exist until Task 3a.7, so this
// asserts what is true today and FAILS the moment the lock lands, which is when Task 3a.7 must
// invert it. It must never be relaxed into a skip.
func TestCertRenewTakesNoDataDirLockYet(t *testing.T) {
	dataDir, _ := seedPair(t)
	if code, out := certRun([]string{"renew", "--data-dir", dataDir}, "renew\n"); code != 0 {
		t.Fatalf("code %d out %q", code, out)
	}
	if _, err := os.Stat(filepath.Join(dataDir, ".claude-swap.lock")); !os.IsNotExist(err) {
		t.Fatalf("the data-dir lock exists: invert this test and assert contention instead (Task 3a.7): %v", err)
	}
}

func TestCertUnknownSubcommandExitsTwo(t *testing.T) {
	for _, args := range [][]string{{"wibble"}, {}} {
		code, out := certRun(args, "")
		if code != 2 || !strings.Contains(out, "renew") {
			t.Fatalf("args %v: code %d out %q", args, code, out)
		}
	}
}

func TestCertIsInTheFixedDispatchNameSet(t *testing.T) {
	// `server cert ...` never reaches the flag parser, so it does not demand --listen or the
	// environment variables a console run needs.
	var out bytes.Buffer
	code := run(context.Background(), []string{"cert", "wibble"}, env(nil), noStdin(), &out)
	if code != 2 {
		t.Fatalf("code %d out %q", code, out.String())
	}
	for _, unwanted := range []string{"--listen", keyEnv, passwordEnv} {
		if strings.Contains(out.String(), unwanted) {
			t.Fatalf("`server cert` reached the run path: %q names %q", out.String(), unwanted)
		}
	}
	// A bare --listen still does reach the flag parser, so scripts/start-server.ps1 is unaffected.
	out.Reset()
	code = run(context.Background(), []string{"--listen", "nonsense", "--data-dir", t.TempDir()},
		env(map[string]string{keyEnv: "k", passwordEnv: "p"}), noStdin(), &out)
	if code != 2 || !strings.Contains(out.String(), "--listen") {
		t.Fatalf("code %d out %q", code, out.String())
	}
}
