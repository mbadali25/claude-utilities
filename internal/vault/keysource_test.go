package vault

import (
	"errors"
	"strings"
	"testing"
)

// These tests pin the KeySource contract that replaced `Open(path, keyEnv string)`. The reason the
// signature had to change is in the design: a service has no passphrase in its environment by
// design, so "the name of an environment variable" cannot be the only way to say what key a process
// may use. EnvKey is the adapter that keeps every console run and every test behaving exactly as it
// did, down to the error text, and the tests below are what proves that claim.

// recordingKeySource counts and orders the calls Open makes, so the v1 path's contract - the
// passphrase, once, and no machine slot - is asserted rather than assumed.
type recordingKeySource struct {
	pass        string
	passErr     error
	openers     []SlotOpener
	passCalls   int
	machineCall int
	order       []string
}

func (r *recordingKeySource) Passphrase() (string, error) {
	r.passCalls++
	r.order = append(r.order, "passphrase")
	return r.pass, r.passErr
}

func (r *recordingKeySource) Machine() []SlotOpener {
	r.machineCall++
	r.order = append(r.order, "machine")
	return r.openers
}

// stubOpener is a SlotOpener that fails if it is ever asked to unwrap: a v1 file has no slots, so
// any Unwrap call on the v1 path is a bug, not a fallback.
type stubOpener struct {
	t    *testing.T
	kind string
}

func (s stubOpener) Type() string { return s.kind }

func (s stubOpener) Unwrap(_ Slot, _ []byte) ([]byte, error) {
	s.t.Helper()
	s.t.Fatalf("Unwrap called on a v1 file by opener %q", s.kind)
	return nil, nil
}

// --- EnvKey: today's behaviour, unchanged ---

func TestEnvKeyReturnsTheVariableValue(t *testing.T) {
	t.Setenv("KEYSOURCE_TEST_KEY", "a-passphrase")
	got, err := EnvKey("KEYSOURCE_TEST_KEY").Passphrase()
	if err != nil {
		t.Fatalf("Passphrase: %v", err)
	}
	if got != "a-passphrase" {
		t.Fatalf("got %q, want the variable's value", got)
	}
}

// Unset and set-to-empty are one case on purpose: os.Getenv cannot tell them apart, and the error
// an operator sees must not depend on which one it was.
func TestEnvKeyReturnsErrNoKeyWhenEmpty(t *testing.T) {
	for _, name := range []string{"KEYSOURCE_TEST_UNSET_KEY", "KEYSOURCE_TEST_EMPTY_KEY"} {
		if name == "KEYSOURCE_TEST_EMPTY_KEY" {
			t.Setenv(name, "")
		}
		got, err := EnvKey(name).Passphrase()
		if !errors.Is(err, ErrNoKey) {
			t.Fatalf("%s: want ErrNoKey, got %v", name, err)
		}
		if got != "" {
			t.Fatalf("%s: returned a passphrase %q alongside ErrNoKey", name, got)
		}
		// The hint is the whole value of the message: "encryption key not set" without the
		// variable's name leaves an operator guessing which variable.
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("%s: message %q does not name the variable", name, err)
		}
		if !strings.Contains(err.Error(), "set environment variable") {
			t.Fatalf("%s: message %q lost the instruction", name, err)
		}
	}
}

func TestEnvKeyMachineIsNil(t *testing.T) {
	if got := EnvKey("KEYSOURCE_TEST_KEY").Machine(); got != nil {
		t.Fatalf("EnvKey offered %d machine openers; it must offer none", len(got))
	}
}

// --- PromptKey ---

func TestPromptKeyReadsOneLineFromStdin(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"s3cret\n", "s3cret"},
		{"s3cret\r\n", "s3cret"},
		{"s3cret", "s3cret"}, // no trailing newline: EOF ends the line
	} {
		got, err := PromptKey(strings.NewReader(tc.in)).Passphrase()
		if err != nil {
			t.Fatalf("%q: Passphrase: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("%q: got %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPromptKeyReturnsErrNoKeyOnEOF(t *testing.T) {
	got, err := PromptKey(strings.NewReader("")).Passphrase()
	if !errors.Is(err, ErrNoKey) {
		t.Fatalf("want ErrNoKey, got %v", err)
	}
	if got != "" {
		t.Fatalf("returned a passphrase %q alongside ErrNoKey", got)
	}
}

func TestPromptKeyMachineIsNil(t *testing.T) {
	if got := PromptKey(strings.NewReader("")).Machine(); got != nil {
		t.Fatalf("PromptKey offered %d machine openers; it must offer none", len(got))
	}
}

// --- Open against a KeySource ---

// writeV1Vault leaves a real v1 file on disk, sealed with pass, and returns its path.
func writeV1Vault(t *testing.T, pass string) string {
	t.Helper()
	p := t.TempDir() + "/vault.bin"
	v, err := open(t, p, pass)
	if err != nil {
		t.Fatalf("seed Open: %v", err)
	}
	if err := v.Put(acct("a")); err != nil {
		t.Fatalf("seed Put: %v", err)
	}
	return p
}

func TestOpenV1CallsPassphraseExactlyOnce(t *testing.T) {
	p := writeV1Vault(t, "pw")
	ks := &recordingKeySource{pass: "pw"}
	v, err := Open(p, ks)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got, ok := v.Get("a"); !ok || got.Label != "La" {
		t.Fatalf("the KeySource opened the file but lost the account: %+v ok=%v", got, ok)
	}
	// Once, not twice: argon2id is deliberately expensive, and a PromptKey asked twice would
	// prompt an operator twice for one open.
	if ks.passCalls != 1 {
		t.Fatalf("Passphrase called %d times, want 1", ks.passCalls)
	}
}

func TestOpenV1WithNoPassphraseReturnsErrNoKey(t *testing.T) {
	p := writeV1Vault(t, "pw")
	ks := &recordingKeySource{passErr: ErrNoKey}
	if _, err := Open(p, ks); !errors.Is(err, ErrNoKey) {
		t.Fatalf("want ErrNoKey, got %v", err)
	}
}

// A KeySource that breaks its own contract - an empty passphrase with no error - must not derive a
// key from "". Deriving one would open and later re-seal a vault under a passphrase nobody chose.
func TestOpenRejectsAnEmptyPassphraseWithNoError(t *testing.T) {
	p := writeV1Vault(t, "pw")
	ks := &recordingKeySource{pass: ""}
	if _, err := Open(p, ks); !errors.Is(err, ErrNoKey) {
		t.Fatalf("want ErrNoKey, got %v", err)
	}
}

// The v1 path is passphrase-only. Task 3a.2 adds the v2 header and 3a.4 the slot unwrap, and the
// plan's TestOpenTriesMachineSlotsBeforePassphrase belongs to that work: there is no v2 file to
// order anything against until the header exists, and nothing here may write one. What this task
// can pin, and what 3a.2 must not break, is that a v1 file never reaches a machine opener.
func TestOpenV1DoesNotConsultMachineSlots(t *testing.T) {
	p := writeV1Vault(t, "pw")
	ks := &recordingKeySource{pass: "pw", openers: []SlotOpener{stubOpener{t: t, kind: "test-opener"}}}
	if _, err := Open(p, ks); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if ks.passCalls != 1 {
		t.Fatalf("Passphrase called %d times, want 1", ks.passCalls)
	}
	// stubOpener.Unwrap fails the test if it is reached; this asserts the opener list was not even
	// asked for, so a v1 open stays one argon2id and no DPAPI or KEK-file read.
	if ks.machineCall != 0 {
		t.Fatalf("Machine called %d times on a v1 file, want 0", ks.machineCall)
	}
}

func TestOpenKeyringUsesTheKeySource(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/" + KeyringFileName
	t.Setenv(keyEnv, "pw")
	seed, err := OpenKeyring(p, EnvKey(keyEnv))
	if err != nil {
		t.Fatalf("seed OpenKeyring: %v", err)
	}
	if _, err := seed.Generate("h1"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	ks := &recordingKeySource{pass: "pw"}
	k, err := OpenKeyring(p, ks)
	if err != nil {
		t.Fatalf("OpenKeyring: %v", err)
	}
	if _, ok := k.Get("h1"); !ok {
		t.Fatal("the KeySource opened the keyring but lost the key")
	}
	if ks.passCalls != 1 {
		t.Fatalf("Passphrase called %d times, want 1", ks.passCalls)
	}
}

// --- HostKeys ---

// On this binary HostKeys has no opener to return on any platform: the dpapi opener is Task 3a.5
// and the kek-file opener is Task 3a.6. nil is what makes the passphrase fall-through work, so the
// nil case is the one worth pinning now - it is the behaviour a console run depends on.
func TestHostKeysIsNilWhenNeitherCredentialNorFlagResolves(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if got := HostKeys(HostKeyOptions{}); got != nil {
		t.Fatalf("HostKeys returned %d openers with no credential directory and no --kek-file", len(got))
	}
}
