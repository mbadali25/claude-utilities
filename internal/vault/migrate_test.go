package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Tests for the two format conversions, MigrateToV2 and DowngradeToV1.
//
// Every path here is under t.TempDir() and every key is a literal in this file: nothing reaches a
// real data dir, a real credstore or a host's live vault. The machine key is always a kek-file over
// a temp file, never dpapi, so both halves of the gate run the same assertions.
//
// argon2id is NOT stubbed in this file, unlike slots_test.go's parser tests. A conversion's whole
// claim is that the payload survives the envelope change, and a stubbed derivation would make the
// v1 key a constant - so a migrate that sealed under the wrong passphrase would still open. The
// cost is a handful of real derivations per test, which is the price of the assertion meaning
// something.

const (
	// migratePass is the passphrase every v1 fixture here is sealed under, and the one migrate
	// re-wraps. Deliberately not initPass: a test that passed because two fixtures shared a
	// passphrase would be asserting nothing.
	migratePass = "the-migrate-passphrase"
	// migrateWrongPass is a passphrase that opens nothing here.
	migrateWrongPass = "not-the-migrate-passphrase"
)

func migrateKEK() []byte { return bytes.Repeat([]byte{0x3b}, keyLen) }

// migrateSource is the key source an operator's migrate run has: a passphrase and one kek-file
// machine opener.
func migrateSource(t *testing.T, kek []byte) KeySource {
	t.Helper()
	return &recordingKeySource{pass: migratePass, openers: []SlotOpener{kekFileOpenerFor(t, kek)}}
}

// v1VaultWith leaves a real v1 vault.bin on disk holding one account, and returns its path. It goes
// through Open/Put rather than through a hand-built envelope because the fixture's job here is to be
// a file the live v1 path wrote; the hand-built v1 envelope is golden_test.go's independentV1, and
// it is used where independence from this package is the point.
func v1VaultWith(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, vaultFileName)
	v, err := open(t, p, migratePass)
	if err != nil {
		t.Fatalf("seed a v1 vault: %v", err)
	}
	if err := v.Put(acct("a")); err != nil {
		t.Fatalf("seed Put: %v", err)
	}
	return p
}

// payloadUnder reads the file's plaintext payload with the passphrase alone. It is the only way to
// compare "the same accounts" across a format change, because the envelope changes entirely.
func payloadUnder(t *testing.T, path, magicStr, pass string) []byte {
	t.Helper()
	_, plain, err := openSealed(path, magicStr, passOnly{pass: pass})
	if err != nil {
		t.Fatalf("open %s under the passphrase: %v", filepath.Base(path), err)
	}
	return plain
}

// copyBeside is the verified byte copy migrate's caller writes before calling it: `<name>.v1.<ts>`.
func copyBeside(t *testing.T, path, suffix string) string {
	t.Helper()
	dst := path + suffix
	if err := os.WriteFile(dst, bytesOf(t, path), 0o600); err != nil {
		t.Fatalf("write the copy: %v", err)
	}
	return dst
}

// --- MigrateToV2: the happy path ---

// The baseline, and the one assertion the whole command exists for: the payload that came out of
// the v1 file goes back into the v2 file unchanged, and both keys open it.
func TestMigrateToV2KeepsThePayloadAndOpensUnderBothKeys(t *testing.T) {
	dir := t.TempDir()
	path := v1VaultWith(t, dir)
	before := payloadUnder(t, path, magic, migratePass)
	bak := copyBeside(t, path, ".v1.123")

	info, err := MigrateToV2(path, bak, migratePass, Slot{Type: slotTypeKEKFile}, migrateSource(t, migrateKEK()))
	if err != nil {
		t.Fatalf("MigrateToV2: %v", err)
	}
	if info.Format != FormatV2 || info.Name != vaultFileName {
		t.Fatalf("info = %+v, want %s as %s", info, vaultFileName, FormatV2)
	}
	if !bytes.HasPrefix(bytesOf(t, path), []byte(v2VaultMagic)) {
		t.Fatalf("%s does not start with %s", vaultFileName, v2VaultMagic)
	}
	if got := payloadUnder(t, path, magic, migratePass); !bytes.Equal(got, before) {
		t.Fatalf("the payload changed across the migration:\n before %q\n after  %q", before, got)
	}
	// Two slots, one of each kind: the recovery rung and the unattended-start rung.
	_, slots := headerOf(t, path)
	if len(slots) != 2 || countPassphraseSlots(slots) != 1 || len(slotIDsByType(slots, slotTypeKEKFile)) != 1 {
		t.Fatalf("the migrated header has %d slots (%d passphrase), want one of each kind",
			len(slots), countPassphraseSlots(slots))
	}
	// And the machine slot opens it on its own, which is what a service will do.
	_, viaMachine, err := openSealed(path, magic, machineOnly{inner: migrateSource(t, migrateKEK())})
	if err != nil {
		t.Fatalf("the migrated file did not open under the machine slot alone: %v", err)
	}
	if !bytes.Equal(viaMachine, before) {
		t.Fatal("the machine slot opened the migrated file and gave back a different payload")
	}
}

// The keyring is migrated by the same entry, under its own magic. A keyring that came back as CSV2
// would be a vault as far as every reader is concerned.
func TestMigrateToV2MigratesTheKeyringUnderItsOwnMagic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, KeyringFileName)
	t.Setenv(keyEnv, migratePass)
	k, err := OpenKeyring(path, EnvKey(keyEnv))
	if err != nil {
		t.Fatalf("seed a v1 keyring: %v", err)
	}
	if _, err := k.Generate("host-1"); err != nil {
		t.Fatalf("seed Generate: %v", err)
	}
	before := payloadUnder(t, path, keyringMagic, migratePass)

	if _, err := MigrateToV2(path, copyBeside(t, path, ".v1.123"), migratePass,
		Slot{Type: slotTypeKEKFile}, migrateSource(t, migrateKEK())); err != nil {
		t.Fatalf("MigrateToV2: %v", err)
	}
	if !bytes.HasPrefix(bytesOf(t, path), []byte(v2KeyringMagic)) {
		t.Fatalf("the migrated keyring does not start with %s", v2KeyringMagic)
	}
	if got := payloadUnder(t, path, keyringMagic, migratePass); !bytes.Equal(got, before) {
		t.Fatal("the keyring's payload changed across the migration")
	}
}

// A v1 payload this binary cannot parse is still migrated byte for byte. The conversion is an
// envelope change and nothing else: a migrate that re-serialised the accounts would silently drop
// a field a newer server wrote, which is the same class of loss unknown-slot retention exists to
// prevent on the header side.
func TestMigrateToV2CarriesAPayloadItCannotParse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, vaultFileName)
	odd := []byte(`{"not":"an account list","unicode":"héllo é中"}`)
	writeIndependentV1(t, path, magic, migratePass, odd)

	if _, err := MigrateToV2(path, copyBeside(t, path, ".v1.123"), migratePass,
		Slot{Type: slotTypeKEKFile}, migrateSource(t, migrateKEK())); err != nil {
		t.Fatalf("MigrateToV2 refused a payload it does not parse: %v", err)
	}
	if got := payloadUnder(t, path, magic, migratePass); !bytes.Equal(got, odd) {
		t.Fatalf("the odd payload was not carried: %q", got)
	}
}

// The passphrase is re-wrapped, not changed. It is the sentence the spec insists migrate's output
// says, and this is the half that has to be true for it: the same secret opens the file afterwards,
// and the one that does not still does not.
func TestMigrateToV2ReWrapsThePassphraseItDoesNotChangeIt(t *testing.T) {
	dir := t.TempDir()
	path := v1VaultWith(t, dir)
	if _, err := MigrateToV2(path, copyBeside(t, path, ".v1.123"), migratePass,
		Slot{Type: slotTypeKEKFile}, migrateSource(t, migrateKEK())); err != nil {
		t.Fatalf("MigrateToV2: %v", err)
	}
	if _, _, err := openSealed(path, magic, passOnly{pass: migratePass}); err != nil {
		t.Fatalf("the passphrase that opened the v1 file does not open the v2 file: %v", err)
	}
	if _, _, err := openSealed(path, magic, passOnly{pass: migrateWrongPass}); !errors.Is(err, ErrBadKey) {
		t.Fatalf("a passphrase that never opened this vault opens the migrated file: %v", err)
	}
}

// A unicode path is a path. The conversion joins nothing and parses no name, but replaceFile's temp
// file lands in the same directory, so a directory name that is not ASCII is worth one test rather
// than an assumption.
func TestMigrateToV2OnAUnicodePath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "données-中文")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := v1VaultWith(t, dir)
	before := payloadUnder(t, path, magic, migratePass)
	if _, err := MigrateToV2(path, copyBeside(t, path, ".v1.123"), migratePass,
		Slot{Type: slotTypeKEKFile}, migrateSource(t, migrateKEK())); err != nil {
		t.Fatalf("MigrateToV2: %v", err)
	}
	if got := payloadUnder(t, path, magic, migratePass); !bytes.Equal(got, before) {
		t.Fatal("the payload changed across a migration under a unicode path")
	}
}

// The migrated file is owner-only, like every other write in this package. A v2 file readable by
// anyone on the host would make the machine slot's whole claim ("a secret that is not in the copy")
// false for the copy that matters most.
func TestMigrateToV2LeavesTheFileOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are synthesized from the read-only attribute on Windows; the ACL is asserted in acl_windows_test.go")
	}
	dir := t.TempDir()
	path := v1VaultWith(t, dir)
	if _, err := MigrateToV2(path, copyBeside(t, path, ".v1.123"), migratePass,
		Slot{Type: slotTypeKEKFile}, migrateSource(t, migrateKEK())); err != nil {
		t.Fatalf("MigrateToV2: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("the migrated file is mode %#o, want no group or other bits", perm)
	}
}

// --- MigrateToV2: the refusals, every one of which must leave the file alone ---

func TestMigrateToV2Refusals(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T, dir string) string // returns the path to migrate
		machine Slot
		pass    string
		kek     []byte
		want    error
	}{
		{
			name:    "no passphrase is never invented",
			setup:   func(t *testing.T, dir string) string { return v1VaultWith(t, dir) },
			machine: Slot{Type: slotTypeKEKFile}, pass: "", kek: migrateKEK(), want: ErrNoKey,
		},
		{
			name:    "the wrong passphrase",
			setup:   func(t *testing.T, dir string) string { return v1VaultWith(t, dir) },
			machine: Slot{Type: slotTypeKEKFile}, pass: migrateWrongPass, kek: migrateKEK(), want: ErrBadKey,
		},
		{
			name:    "a slot type this binary cannot create",
			setup:   func(t *testing.T, dir string) string { return v1VaultWith(t, dir) },
			machine: Slot{Type: slotTypePassphrase}, pass: migratePass, kek: migrateKEK(), want: nil,
		},
		{
			name:    "a file that is already v2",
			setup:   func(t *testing.T, dir string) string { return initVaultAt(t, dir) },
			machine: Slot{Type: slotTypeKEKFile}, pass: migratePass, kek: migrateKEK(), want: ErrNewerFormat,
		},
		{
			name:    "a file that is not there",
			setup:   func(_ *testing.T, dir string) string { return filepath.Join(dir, vaultFileName) },
			machine: Slot{Type: slotTypeKEKFile}, pass: migratePass, kek: migrateKEK(), want: ErrNotV2,
		},
		{
			name: "a file of no format this binary knows",
			setup: func(t *testing.T, dir string) string {
				p := filepath.Join(dir, vaultFileName)
				if err := os.WriteFile(p, []byte("NOPE and then some filler bytes"), 0o600); err != nil {
					t.Fatal(err)
				}
				return p
			},
			machine: Slot{Type: slotTypeKEKFile}, pass: migratePass, kek: migrateKEK(), want: errCorrupt,
		},
		{
			name:    "a machine slot with no key on this host",
			setup:   func(t *testing.T, dir string) string { return v1VaultWith(t, dir) },
			machine: Slot{Type: slotTypeKEKFile}, pass: migratePass, kek: nil, want: ErrKEKUnreachable,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			path := c.setup(t, dir)
			before, had := os.ReadFile(filepath.Clean(path))
			ks := KeySource(&recordingKeySource{pass: c.pass})
			if c.kek != nil {
				ks = migrateSource(t, c.kek)
			}
			if _, err := MigrateToV2(path, path+".v1.123", c.pass, c.machine, ks); err == nil {
				t.Fatal("MigrateToV2 succeeded on a case that must be refused")
			} else if c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("error = %v, want %v", err, c.want)
			}
			// Nothing written, in every one of them. A refusal that replaced the file would be the
			// worst outcome of the lot: the operator fixes what the message names and runs it again.
			after, nowHave := os.ReadFile(filepath.Clean(path))
			if (had == nil) != (nowHave == nil) || !bytes.Equal(before, after) {
				t.Fatalf("%s changed on a refused migration", filepath.Base(path))
			}
			if _, err := os.Stat(path + ".v1.123"); err == nil {
				t.Fatal("a refused migration wrote the restore copy")
			}
		})
	}
}

// No temp file is left behind by a refused or a completed conversion. A `.vault-*.tmp` beside the
// vault is how an operator ends up copying a half-written envelope over a working one.
func TestMigrateToV2LeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	path := v1VaultWith(t, dir)
	if _, err := MigrateToV2(path, copyBeside(t, path, ".v1.123"), migratePass,
		Slot{Type: slotTypeKEKFile}, migrateSource(t, migrateKEK())); err != nil {
		t.Fatalf("MigrateToV2: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("a temp file survived the migration: %s", e.Name())
		}
	}
}

// --- MigrateToV2: the verify, and the restore behind it ---

// shiftingKEK is a key source whose machine opener holds one KEK for the first caller and a
// different one for every caller after it. MigrateToV2 resolves the sealer once, up front, and asks
// again for the machine-slot-alone verify - so this makes the verify, and only the verify, fail.
//
// It is the one injection that reaches the step between the replace and the restore. A seam on the
// comparison itself would prove the restore runs when the code says to run it; this proves it runs
// when the FILE is wrong, which is the property.
type shiftingKEK struct {
	t     *testing.T
	pass  string
	calls int
}

func (s *shiftingKEK) Passphrase() (string, error) { return s.pass, nil }

func (s *shiftingKEK) Machine() []SlotOpener {
	s.calls++
	kek := migrateKEK()
	if s.calls > 1 {
		kek = bytes.Repeat([]byte{0x11}, keyLen)
	}
	return []SlotOpener{kekFileOpenerFor(s.t, kek)}
}

// The spec's step 6: a mismatch restores the v1 copy over the v2 file and exits non-zero with the
// reason. Here the machine slot stops opening between the write and the verify, so the new file is
// real and unopenable - exactly the state a migration must not leave behind.
func TestMigrateToV2RestoresTheV1CopyWhenTheVerifyFails(t *testing.T) {
	dir := t.TempDir()
	path := v1VaultWith(t, dir)
	original := bytesOf(t, path)
	bak := copyBeside(t, path, ".v1.123")

	_, err := MigrateToV2(path, bak, migratePass, Slot{Type: slotTypeKEKFile},
		&shiftingKEK{t: t, pass: migratePass})
	if err == nil {
		t.Fatal("MigrateToV2 succeeded with a machine key that stopped opening after the write")
	}
	if !strings.Contains(err.Error(), "restored") {
		t.Fatalf("the error does not say the file was restored: %v", err)
	}
	if got := bytesOf(t, path); !bytes.Equal(got, original) {
		t.Fatal("the v1 file was not restored byte for byte after a failed verify")
	}
	// And it is a working v1 file again, not just the right bytes.
	if got := payloadUnder(t, path, magic, migratePass); len(got) == 0 {
		t.Fatal("the restored file does not open as v1")
	}
}

// Review Focus 3's second half: when the RESTORE itself cannot run, the message names the copy to
// put back by hand. There is nothing else left to tell an operator, and a message that only said
// "verify failed" would leave them with a v2 file no key opens and no instruction.
func TestMigrateToV2NamesTheCopyWhenTheRestoreAlsoFails(t *testing.T) {
	dir := t.TempDir()
	path := v1VaultWith(t, dir)
	missing := filepath.Join(dir, vaultFileName+".v1.gone")

	_, err := MigrateToV2(path, missing, migratePass, Slot{Type: slotTypeKEKFile},
		&shiftingKEK{t: t, pass: migratePass})
	if err == nil {
		t.Fatal("MigrateToV2 succeeded with a failing verify and no copy to restore from")
	}
	for _, want := range []string{filepath.Base(missing), "by hand"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the error does not contain %q: %v", want, err)
		}
	}
}

// --- DowngradeToV1 ---

// initVaultAt creates a v2 vault.bin in dir through the one creator and returns its path. The
// passphrase is migratePass so one constant covers both directions.
func initVaultAt(t *testing.T, dir string) string {
	t.Helper()
	if _, err := InitV2(dir, migratePass, Slot{Type: slotTypeKEKFile}, migrateSource(t, migrateKEK())); err != nil {
		t.Fatalf("InitV2: %v", err)
	}
	return filepath.Join(dir, vaultFileName)
}

// The round trip, and the assertion that matters most: the bytes the OLD path reads. The v1 reader
// used here is independentV1Open, a copy of the v1 envelope kept in the test - not this package's
// openSealed, which would be this code agreeing with itself.
func TestDowngradeToV1WritesAFileTheOldPathOpens(t *testing.T) {
	dir := t.TempDir()
	path := initVaultAt(t, dir)
	// Something in the payload, so "it opened" is not true of an empty file by accident.
	v, err := Open(path, passOnly{pass: migratePass})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := v.Put(acct("a")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	before := payloadUnder(t, path, magic, migratePass)
	v2Bytes := bytesOf(t, path)
	keep := path + ".v2.123"

	info, err := DowngradeToV1(path, keep, migratePass)
	if err != nil {
		t.Fatalf("DowngradeToV1: %v", err)
	}
	if info.Format != FormatV1 {
		t.Fatalf("info = %+v, want %s", info, FormatV1)
	}
	if !bytes.HasPrefix(bytesOf(t, path), []byte(magic)) {
		t.Fatalf("the downgraded file does not start with %s", magic)
	}
	got, oerr := independentV1Open(bytesOf(t, path), magic, migratePass)
	if oerr != nil {
		t.Fatalf("a copy of the v1 reader could not open the downgraded file: %v", oerr)
	}
	if !bytes.Equal(got, before) {
		t.Fatalf("the payload changed across the downgrade:\n before %q\n after  %q", before, got)
	}
	// The v2 bytes are kept, byte for byte, so the downgrade is itself reversible.
	if !bytes.Equal(bytesOf(t, keep), v2Bytes) {
		t.Fatalf("%s is not the v2 file it was copied from", filepath.Base(keep))
	}
}

// A fresh salt and a fresh nonce, per the spec's downgrade line. Two downgrades of the same vault
// under the same passphrase must not produce the same envelope: a repeated nonce under a repeated
// derived key leaks the key stream, and the plaintext here is the whole vault.
func TestDowngradeToV1DrawsAFreshSaltAndNonce(t *testing.T) {
	dir := t.TempDir()
	path := initVaultAt(t, dir)
	first, err := DowngradeToV1(path, path+".v2.1", migratePass)
	if err != nil {
		t.Fatalf("first downgrade: %v", err)
	}
	_ = first
	one := bytesOf(t, path)

	// Back to v2 and down again, so the two v1 envelopes carry the same payload.
	if _, err := MigrateToV2(path, copyBeside(t, path, ".v1.1"), migratePass,
		Slot{Type: slotTypeKEKFile}, migrateSource(t, migrateKEK())); err != nil {
		t.Fatalf("migrate back up: %v", err)
	}
	if _, err := DowngradeToV1(path, path+".v2.2", migratePass); err != nil {
		t.Fatalf("second downgrade: %v", err)
	}
	two := bytesOf(t, path)

	saltAndNonce := len(magic) + saltLen + nonceLen
	if bytes.Equal(one[:saltAndNonce], two[:saltAndNonce]) {
		t.Fatal("two downgrades produced the same salt and nonce")
	}
}

// The full round trip at the payload level: v1 -> v2 -> v1 gives the same plaintext back, which is
// the one promise the rollback story rests on.
func TestMigrateAndDowngradeRoundTripThePayloadByteForByte(t *testing.T) {
	dir := t.TempDir()
	path := v1VaultWith(t, dir)
	before := payloadUnder(t, path, magic, migratePass)

	if _, err := MigrateToV2(path, copyBeside(t, path, ".v1.123"), migratePass,
		Slot{Type: slotTypeKEKFile}, migrateSource(t, migrateKEK())); err != nil {
		t.Fatalf("MigrateToV2: %v", err)
	}
	if _, err := DowngradeToV1(path, path+".v2.123", migratePass); err != nil {
		t.Fatalf("DowngradeToV1: %v", err)
	}
	got, err := independentV1Open(bytesOf(t, path), magic, migratePass)
	if err != nil {
		t.Fatalf("the v1 reader could not open the round-tripped file: %v", err)
	}
	if !bytes.Equal(got, before) {
		t.Fatalf("the payload did not survive v1 -> v2 -> v1:\n before %q\n after  %q", before, got)
	}
}

// Every downgrade refusal, and the same rule as migrate's: the file on disk is untouched and the
// kept copy is not created.
func TestDowngradeToV1Refusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, dir string) string
		pass  string
		want  error
	}{
		{
			name:  "no passphrase",
			setup: initVaultAt,
			pass:  "", want: ErrNoKey,
		},
		{
			name:  "the wrong passphrase",
			setup: initVaultAt,
			pass:  migrateWrongPass, want: ErrBadKey,
		},
		{
			name:  "a file that is already v1",
			setup: func(t *testing.T, dir string) string { return v1VaultWith(t, dir) },
			pass:  migratePass, want: ErrNotV2,
		},
		{
			name:  "a file that is not there",
			setup: func(_ *testing.T, dir string) string { return filepath.Join(dir, vaultFileName) },
			pass:  migratePass, want: nil,
		},
		{
			// A header with no passphrase slot cannot be written by this binary (ErrNoRecoverySlot on
			// every v2 write), but one repaired by hand could carry it - and a downgrade of it would
			// seal the vault under a passphrase that never opened the v2 file.
			name: "a v2 file with no passphrase slot",
			setup: func(t *testing.T, dir string) string {
				p := filepath.Join(dir, vaultFileName)
				writeIndependentV2(t, p, v2VaultMagic, []independentSlot{
					{id: "kekslot1", kek: migrateKEK()},
				}, []byte(`[]`))
				return p
			},
			pass: migratePass, want: ErrNoRecoverySlot,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			path := c.setup(t, dir)
			before, had := os.ReadFile(filepath.Clean(path))
			keep := path + ".v2.123"
			if _, err := DowngradeToV1(path, keep, c.pass); err == nil {
				t.Fatal("DowngradeToV1 succeeded on a case that must be refused")
			} else if c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("error = %v, want %v", err, c.want)
			}
			after, nowHave := os.ReadFile(filepath.Clean(path))
			if (had == nil) != (nowHave == nil) || !bytes.Equal(before, after) {
				t.Fatalf("%s changed on a refused downgrade", filepath.Base(path))
			}
			if _, err := os.Stat(keep); err == nil {
				t.Fatal("a refused downgrade wrote the kept v2 copy")
			}
		})
	}
}

// --- what neither entry may ever do ---

// Nothing either conversion writes carries key material in the clear. The v2 header and the v1
// salt are the parts of each file that are not encrypted, and a passphrase or a KEK appearing in
// either would be the whole design undone.
func TestNeitherConversionWritesKeyMaterialInTheClear(t *testing.T) {
	dir := t.TempDir()
	path := v1VaultWith(t, dir)
	bak := copyBeside(t, path, ".v1.123")
	if _, err := MigrateToV2(path, bak, migratePass, Slot{Type: slotTypeKEKFile},
		migrateSource(t, migrateKEK())); err != nil {
		t.Fatalf("MigrateToV2: %v", err)
	}
	secrets := [][]byte{[]byte(migratePass), migrateKEK()}
	for _, secret := range secrets {
		if bytes.Contains(bytesOf(t, path), secret) {
			t.Fatal("the migrated file carries key material in the clear")
		}
	}
	if _, err := DowngradeToV1(path, path+".v2.123", migratePass); err != nil {
		t.Fatalf("DowngradeToV1: %v", err)
	}
	for _, secret := range secrets {
		if bytes.Contains(bytesOf(t, path), secret) {
			t.Fatal("the downgraded file carries key material in the clear")
		}
	}
}
