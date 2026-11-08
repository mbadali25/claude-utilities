package vault

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
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
		got, err := PromptKey(strings.NewReader(tc.in), io.Discard).Passphrase()
		if err != nil {
			t.Fatalf("%q: Passphrase: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("%q: got %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPromptKeyReturnsErrNoKeyOnEOF(t *testing.T) {
	got, err := PromptKey(strings.NewReader(""), io.Discard).Passphrase()
	if !errors.Is(err, ErrNoKey) {
		t.Fatalf("want ErrNoKey, got %v", err)
	}
	if got != "" {
		t.Fatalf("returned a passphrase %q alongside ErrNoKey", got)
	}
}

// countingReader counts the Read calls a KeySource makes, so "the passphrase is read once for the
// whole process" is asserted against stdin itself rather than inferred from two opens succeeding.
type countingReader struct {
	r     io.Reader
	reads int
}

func (c *countingReader) Read(p []byte) (int, error) {
	c.reads++
	return c.r.Read(p)
}

// cmd/server/main.go builds one KeySource in serve() and hands it to Open and then OpenKeyring,
// because the keyring is sealed with the vault's passphrase. A single-use source makes that second
// call fail on a drained stdin - the operator would be asked for the passphrase again, or, worse,
// told there is none. One source, two sealed files, one read.
func TestOnePromptKeyOpensTheVaultThenTheKeyringOnOneStdinRead(t *testing.T) {
	dir := t.TempDir()
	vp := filepath.Join(dir, "vault.bin")
	kp := filepath.Join(dir, KeyringFileName)
	t.Setenv(keyEnv, "pw")
	v, err := Open(vp, EnvKey(keyEnv))
	if err != nil {
		t.Fatalf("seed Open: %v", err)
	}
	if err := v.Put(acct("a")); err != nil {
		t.Fatalf("seed Put: %v", err)
	}
	seed, err := OpenKeyring(kp, EnvKey(keyEnv))
	if err != nil {
		t.Fatalf("seed OpenKeyring: %v", err)
	}
	if _, err := seed.Generate("h1"); err != nil {
		t.Fatalf("seed Generate: %v", err)
	}

	in := &countingReader{r: strings.NewReader("pw\n")}
	ks := PromptKey(in, io.Discard)
	if _, err := Open(vp, ks); err != nil {
		t.Fatalf("Open: %v", err)
	}
	afterVault := in.reads
	if afterVault == 0 {
		t.Fatal("the vault open never read stdin")
	}
	k, err := OpenKeyring(kp, ks)
	if err != nil {
		t.Fatalf("OpenKeyring with the same KeySource: %v", err)
	}
	if _, ok := k.Get("h1"); !ok {
		t.Fatal("the second open succeeded but lost the key")
	}
	if in.reads != afterVault {
		t.Fatalf("the keyring open read stdin %d more times; the passphrase must be read once per process", in.reads-afterVault)
	}
}

// The prompt line is written only on the terminal branch, and no test can own a real TTY on
// Windows and Linux both, so the branch is forced and the text is read back off the injected
// writer. What this pins is the text and where it goes. term.ReadPassword's no-echo read stays
// unproven - it needs a TTY - and on this plain file it fails, which is why ErrNoKey is the
// expected answer here.
func TestPromptKeyWritesThePromptToTheInjectedWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-terminal")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	var buf bytes.Buffer
	ks := &promptKey{in: f, out: &buf, isTerminal: func(int) bool { return true }}
	if _, err := ks.Passphrase(); !errors.Is(err, ErrNoKey) {
		t.Fatalf("want ErrNoKey when the no-echo read fails, got %v", err)
	}
	got := buf.String()
	if !strings.HasPrefix(got, "Vault passphrase (not echoed): ") {
		t.Fatalf("the injected writer got %q; an operator must be told what is being asked for and "+
			"that it will not echo", got)
	}
}

// Nothing passes a writer yet, so the default is the one an operator actually meets. It must be
// stderr: stdout may be a pipe a caller is parsing, and a prompt in it corrupts that stream.
func TestPromptKeyWithNoWriterPromptsOnStderr(t *testing.T) {
	p, ok := PromptKey(strings.NewReader(""), nil).(*promptKey)
	if !ok {
		t.Fatalf("PromptKey returned %T, not *promptKey", PromptKey(strings.NewReader(""), nil))
	}
	if p.writer() != os.Stderr {
		t.Fatal("a PromptKey built with no writer must prompt on stderr")
	}
}

// A piped run gets no prompt: there is nobody to read it, and the bytes would land in whatever the
// caller pointed stderr at.
func TestPromptKeyPipedInputWritesNoPrompt(t *testing.T) {
	var buf bytes.Buffer
	got, err := PromptKey(strings.NewReader("s3cret\n"), &buf).Passphrase()
	if err != nil {
		t.Fatalf("Passphrase: %v", err)
	}
	if got != "s3cret" {
		t.Fatalf("got %q, want the piped line", got)
	}
	if buf.Len() != 0 {
		t.Fatalf("a piped run wrote %q; the prompt belongs to the terminal branch only", buf.String())
	}
}

func TestPromptKeyMachineIsNil(t *testing.T) {
	if got := PromptKey(strings.NewReader(""), io.Discard).Machine(); got != nil {
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

// A v2 file is answered from its own bytes - the magic, the header length and the header - and none
// of that needs a key, so no key may be asked for. The fixture's header is malformed, so the answer
// is errCorrupt since Task 3a.2 made CSV2 readable; newerformat_test.go pins that error, and this
// pins that nothing was asked to produce it. It matters more than it did with an env var name: a
// PromptKey would stop the run dead on a prompt that cannot open the file whatever is typed, and
// telling an operator to set CLAUDESWAP_KEY for an unopenable file is how a correct passphrase
// gets rotated out of confusion. Both magics, because each reader recognises only its own.
func TestOpenV2DoesNotAskForThePassphrase(t *testing.T) {
	dir := t.TempDir()
	vp := writeFixture(t, dir, "vault.bin", v2Fixture(t))
	kp := writeFixture(t, dir, KeyringFileName, withMagic(t, v2KeyringMagic))

	vks := &recordingKeySource{pass: "pw"}
	if _, err := Open(vp, vks); !errors.Is(err, errCorrupt) {
		t.Fatalf("Open: want errCorrupt, got %v", err)
	}
	kks := &recordingKeySource{pass: "pw"}
	if _, err := OpenKeyring(kp, kks); !errors.Is(err, errCorrupt) {
		t.Fatalf("OpenKeyring: want errCorrupt, got %v", err)
	}
	for _, tc := range []struct {
		what string
		ks   *recordingKeySource
	}{{"CSV2 vault", vks}, {"CSK2 keyring", kks}} {
		if tc.ks.passCalls != 0 {
			t.Fatalf("%s: Passphrase called %d times, want 0", tc.what, tc.ks.passCalls)
		}
		if tc.ks.machineCall != 0 {
			t.Fatalf("%s: Machine called %d times, want 0", tc.what, tc.ks.machineCall)
		}
	}
}

// --- HostKeys ---

// HostKeys is a declared signature with no body yet: it discards its options and returns nil on
// every platform and for every input, because the dpapi opener is Task 3a.5 and the kek-file
// opener is Task 3a.6. So this test cannot fail on any option or environment, and it does not
// pretend to - it pins the placeholder itself. nil is what makes the passphrase fall-through work,
// which is the behaviour a console run depends on today, and the test that distinguishes a
// resolved credential from an unresolved one belongs to the task that can resolve one.
func TestHostKeysIsAPlaceholderUntilSlot5(t *testing.T) {
	for _, opts := range []HostKeyOptions{
		{},
		{CredentialName: "vault-kek", KEKFile: "/etc/claude-swap/kek", AllowRootCredsDecrypt: true},
	} {
		if got := HostKeys(opts); got != nil {
			t.Fatalf("HostKeys(%+v) returned %d openers; it has no opener to return yet", opts, len(got))
		}
	}
}
