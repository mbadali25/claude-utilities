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

// pairBytes snapshots both PEM files. It fails rather than tolerating a read error: a nil for an
// unreadable file would compare unequal to the same file read later and pass for a refusal the
// command never made.
func pairBytes(t *testing.T, dataDir string) [2][]byte {
	t.Helper()
	var out [2][]byte
	for i, name := range []string{"server-cert.pem", "server-key.pem"} {
		b, err := os.ReadFile(filepath.Join(dataDir, "tls", name))
		if err != nil {
			t.Fatalf("snapshot %s: %v", name, err)
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

func TestCertRenewTellsTheOperatorToRestartBeforeReEnrolling(t *testing.T) {
	dataDir, oldFP := seedPair(t)
	code, out := certRun([]string{"renew", "--data-dir", dataDir}, "renew\n")
	if code != 0 {
		t.Fatalf("code %d out %q", code, out)
	}
	// A running server loaded the old pair once, at startup, and keeps serving it: there is no
	// reload. Re-enrolling an agent on the new pin before the restart therefore breaks that agent,
	// so the guidance has to name the restart, not just the re-enrolment.
	for _, want := range []string{oldFP, "stop the server", "until it is restarted", "re-enrol"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output must name %q: %q", want, out)
		}
	}
}

func TestCertRenewOnAFreshDirSaysNothingAboutAChangedPin(t *testing.T) {
	dataDir := t.TempDir()
	code, out := certRun([]string{"renew", "--data-dir", dataDir}, "renew\n")
	if code != 0 {
		t.Fatalf("code %d out %q", code, out)
	}
	_, _, fp, err := hub.EnsureCert(filepath.Join(dataDir, "tls"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, fp) {
		t.Fatalf("output must print the new pin %q: %q", fp, out)
	}
	// No pair existed, so nobody holds a pin and there is nothing to re-enrol onto. The
	// confirmation PROMPT does say "re-enrol" - it is printed before the command can know - so
	// the assertion names two strings that appear only in the post-renew guidance.
	for _, unwanted := range []string{"WARNING", "--pin"} {
		if strings.Contains(out, unwanted) {
			t.Fatalf("output claims a pin changed on a fresh dir: %q names %q", out, unwanted)
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
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 file, so the refusal cannot be provoked; run the suite as an ordinary user")
	}
	dataDir, _ := seedPair(t)
	key := filepath.Join(dataDir, "tls", "server-key.pem")
	// Captured while the pair is still readable: pairBytes cannot read a 0000 key, so a snapshot
	// taken after the chmod would record nil for it and compare unequal for the wrong reason.
	before := pairBytes(t, dataDir)
	if err := os.Chmod(key, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(key, 0o600) })
	// Asserted, not skipped on a successful read: CI runs without -v, so a skip here would make an
	// uncovered case look like a pass. Root is the one environment that ignores the mode bits.
	if _, err := os.ReadFile(key); err == nil {
		t.Fatalf("a 0000 mode left the key readable, so this test proves nothing: %v", err)
	}
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
