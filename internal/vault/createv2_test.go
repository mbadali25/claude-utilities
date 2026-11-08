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

// Tests for the one creator of a v2 file. Every path here is under t.TempDir(): nothing in this file
// goes near a real data dir, a real credstore or a host's live vault, and no test here has a route
// to one - InitV2 takes the directory it is given and refuses a file that is already there.

// initPass is the passphrase every fixture below creates the files under. Literal, so a failure is
// reproducible, and deliberately not addSlotPass: a test that passed because two fixtures shared a
// passphrase would be asserting nothing.
const initPass = "the-init-passphrase"

// initKEK is the 32-byte key-encryption key the machine slot of these fixtures wraps under.
func initKEK() []byte { return bytes.Repeat([]byte{0x5c}, keyLen) }

// kekMachineSlot is the machine slot spec a Linux-shaped host hands InitV2, and kekSource the key
// source that can reach its KEK. Together they are the portable half of the matrix: a kek-file slot
// needs no platform API, so both halves of the gate run these.
func kekMachineSlot() Slot { return Slot{Type: slotTypeKEKFile} }

func initKeySource(t *testing.T, pass string) KeySource {
	t.Helper()
	return &recordingKeySource{pass: pass, openers: []SlotOpener{kekFileOpenerFor(t, initKEK())}}
}

// initBoth creates both files in a fresh temp dir and returns the dir and the FileInfos.
func initBoth(t *testing.T) (string, []FileInfo) {
	t.Helper()
	dir := t.TempDir()
	infos, err := InitV2(dir, initPass, kekMachineSlot(), initKeySource(t, initPass))
	if err != nil {
		t.Fatalf("InitV2: %v", err)
	}
	return dir, infos
}

// assertNeitherFileExists is the "nothing was written" half of every refusal below. A creator that
// refused after writing one of the two files would leave a data dir that looks initialised and is
// not, which is the one state `init` exists to avoid producing.
func assertNeitherFileExists(t *testing.T, dir string) {
	t.Helper()
	for _, name := range []string{vaultFileName, KeyringFileName} {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s exists after a refused InitV2 (stat err %v)", name, err)
		}
	}
}

// The baseline: both files land, both carry the v2 magic of their own kind, and each has exactly the
// two slots the design requires - one passphrase slot (the recovery rung) and one machine slot.
func TestInitV2WritesBothFilesAsV2(t *testing.T) {
	dir, infos := initBoth(t)
	if len(infos) != 2 {
		t.Fatalf("InitV2 reported %d files, want 2", len(infos))
	}
	for i, want := range []string{v2VaultMagic, v2KeyringMagic} {
		name := []string{vaultFileName, KeyringFileName}[i]
		data := bytesOf(t, filepath.Join(dir, name))
		if !bytes.HasPrefix(data, []byte(want)) {
			t.Fatalf("%s does not start with %s", name, want)
		}
		if infos[i].Name != name || infos[i].Format != FormatV2 {
			t.Fatalf("info %d = %+v, want %s as %s", i, infos[i], name, FormatV2)
		}
		_, slots := headerOf(t, filepath.Join(dir, name))
		if len(slots) != 2 {
			t.Fatalf("%s has %d slots, want 2", name, len(slots))
		}
		if countPassphraseSlots(slots) != 1 {
			t.Fatalf("%s has %d passphrase slots, want 1", name, countPassphraseSlots(slots))
		}
		if got := slotIDsByType(slots, slotTypeKEKFile); len(got) != 1 {
			t.Fatalf("%s has %d kek-file slots, want 1", name, len(got))
		}
	}
}

// The two files are two independent envelopes. A shared data key would mean one compromised key
// opens both, and a shared slot id would make "which slot opened this file" ambiguous in the audit
// line, because the id is length-prefixed into every wrap's AAD.
func TestInitV2GivesEachFileItsOwnDataKeyAndSlotIDs(t *testing.T) {
	dir, _ := initBoth(t)
	vh, vslots := headerOf(t, filepath.Join(dir, vaultFileName))
	kh, kslots := headerOf(t, filepath.Join(dir, KeyringFileName))
	if vh.DEK.ID == kh.DEK.ID {
		t.Fatalf("both files share a dek.id")
	}
	for _, a := range vslots {
		for _, b := range kslots {
			if a.ID == b.ID {
				t.Fatalf("both files carry slot id %s", a.ID)
			}
		}
	}
	if vslots[0].ID == vslots[1].ID {
		t.Fatalf("the two slots of one file share an id")
	}
}

// The data key itself, not the id beside it. dek and dek.id are drawn from two independent randRead
// calls, so two files with different ids can still be sealed under one key - which is exactly the
// property the test above cannot see. One compromised key must not open both envelopes.
func TestInitV2DoesNotShareADataKeyBetweenTheTwoFiles(t *testing.T) {
	dir, _ := initBoth(t)
	ringPath := filepath.Join(dir, KeyringFileName)
	vs, _, err := openSealed(filepath.Join(dir, vaultFileName), magic, initKeySource(t, initPass))
	if err != nil {
		t.Fatalf("openSealed vault.bin: %v", err)
	}
	ks, _, err := openSealed(ringPath, keyringMagic, initKeySource(t, initPass))
	if err != nil {
		t.Fatalf("openSealed %s: %v", KeyringFileName, err)
	}
	if len(vs.dek) != keyLen || len(ks.dek) != keyLen {
		t.Fatalf("data key lengths %d and %d, want %d each", len(vs.dek), len(ks.dek), keyLen)
	}
	if bytes.Equal(vs.dek, ks.dek) {
		t.Fatal("both files are sealed under the same data key")
	}
	// And the key is bound to its own file: the keyring's payload must not open under the vault's
	// data key even if a future change made the two keys equal by accident.
	aead, err := payloadAEAD(vs.dek)
	if err != nil {
		t.Fatalf("payloadAEAD: %v", err)
	}
	raw, err := os.ReadFile(ringPath)
	if err != nil {
		t.Fatal(err)
	}
	aad, _, err := rawHeaderOf(raw)
	if err != nil {
		t.Fatalf("rawHeaderOf: %v", err)
	}
	body := raw[len(aad):]
	if _, err := aead.Open(nil, body[:nonceLen], body[nonceLen:], aad); err == nil {
		t.Fatalf("the %s payload opened under vault.bin's data key", KeyringFileName)
	}
}

// createFileExcl's refusal, on its own. InitV2's pre-flight stat answers first on every path a test
// can reach through InitV2, so the atomic no-clobber - the half the comment says makes the property
// true rather than the one that words it well - needs a direct caller.
func TestCreateFileExclRefusesAPathThatIsAlreadyThere(t *testing.T) {
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"a whole file", []byte("the bytes that were there")},
		// Inspect reads a zero-byte file as absent, so this is the one a format test cannot refuse.
		{"a zero-byte file a torn create left", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), vaultFileName)
			if err := os.WriteFile(path, tc.body, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := createFileExcl(path, []byte("the bytes a creator would write")); !errors.Is(err, ErrVaultExists) {
				t.Fatalf("createFileExcl over %s = %v, want ErrVaultExists", tc.name, err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("the file that was there is gone: %v", err)
			}
			if !bytes.Equal(got, tc.body) {
				t.Fatalf("the file that was there was written over: %d bytes, want %d", len(got), len(tc.body))
			}
		})
	}
}

// A symlink at the target is the case no stat can see: os.Stat follows the link, so a DANGLING one
// reads as "nothing there" and the pre-flight check waves it through. O_EXCL is the only thing left
// that refuses it, and without it a creation would write the vault wherever the link points - which
// is anywhere on the disk, outside the data dir the operator named.
func TestCreateFileExclRefusesADanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	elsewhere := filepath.Join(dir, "elsewhere")
	if err := os.MkdirAll(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	// An existing directory and a name in it that does not exist: without O_EXCL the open would
	// create the target, so the refusal is the only thing keeping the bytes out of it.
	target := filepath.Join(elsewhere, "landed")
	link := filepath.Join(dir, vaultFileName)
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("this host cannot create a symlink: %v", err)
	}
	if _, err := os.Stat(link); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a dangling symlink does not stat as absent on this host (%v); the premise does not hold", err)
	}
	if err := createFileExcl(link, []byte("the bytes a creator would write")); err == nil {
		t.Fatal("createFileExcl followed a dangling symlink instead of refusing it")
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the bytes landed at the symlink's target, outside the path that was asked for")
	}
}

// Each file opens under the passphrase ALONE and under the machine key ALONE. That is the whole
// point of a slot list, and it is the property `vault init` prints a line about: the service starts
// with no passphrase, and an operator who loses the host key still has a way in.
func TestInitV2OpensWithEitherKeyAlone(t *testing.T) {
	dir, _ := initBoth(t)
	vaultPath := filepath.Join(dir, vaultFileName)
	ringPath := filepath.Join(dir, KeyringFileName)

	passOnly := &recordingKeySource{pass: initPass}
	v, err := Open(vaultPath, passOnly)
	if err != nil {
		t.Fatalf("Open with the passphrase alone: %v", err)
	}
	if got := v.List(); len(got) != 0 {
		t.Fatalf("a fresh vault holds %d accounts, want 0", len(got))
	}
	k, err := OpenKeyring(ringPath, passOnly)
	if err != nil {
		t.Fatalf("OpenKeyring with the passphrase alone: %v", err)
	}
	if got := k.List(); len(got) != 0 {
		t.Fatalf("a fresh keyring holds %d keys, want 0", len(got))
	}

	// No passphrase at all, not an empty one: exactly what a service has.
	machineOnly := &recordingKeySource{passErr: ErrNoKey, openers: []SlotOpener{kekFileOpenerFor(t, initKEK())}}
	if _, err := Open(vaultPath, machineOnly); err != nil {
		t.Fatalf("Open with the machine key alone: %v", err)
	}
	if _, err := OpenKeyring(ringPath, machineOnly); err != nil {
		t.Fatalf("OpenKeyring with the machine key alone: %v", err)
	}
}

// A created file must be writable by the ordinary save path, or `init` would produce a vault the
// server cannot store an account in.
func TestInitV2CreatesFilesTheOrdinarySavePathCanWrite(t *testing.T) {
	dir, _ := initBoth(t)
	path := filepath.Join(dir, vaultFileName)
	v := openV2(t, path, initPass)
	if err := v.Put(Account{ID: "a1", Label: "one", Identity: "one@example.test"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	again := openV2(t, path, initPass)
	if _, ok := again.Get("a1"); !ok {
		t.Fatalf("the account did not survive a save of a file init created")
	}
	if !bytes.HasPrefix(bytesOf(t, path), []byte(v2VaultMagic)) {
		t.Fatalf("a save of an init-created file did not stay v2")
	}
}

// init never writes over a file that is already there, and it refuses on EITHER of the two. The
// half-initialised data dir - a v2 vault beside a v1 keyring - is the mixed pair the journal exists
// to make readable, and creating one deliberately is not something a creator should be able to do.
func TestInitV2RefusesWhenEitherFileExists(t *testing.T) {
	for _, name := range []string{vaultFileName, KeyringFileName} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte("not a vault"), 0o600); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
			_, err := InitV2(dir, initPass, kekMachineSlot(), initKeySource(t, initPass))
			if !errors.Is(err, ErrVaultExists) {
				t.Fatalf("InitV2 over an existing %s = %v, want ErrVaultExists", name, err)
			}
			if !strings.Contains(err.Error(), name) {
				t.Fatalf("the refusal does not name %s: %v", name, err)
			}
			if got := bytesOf(t, path); !bytes.Equal(got, []byte("not a vault")) {
				t.Fatalf("%s was overwritten", name)
			}
			other := vaultFileName
			if name == vaultFileName {
				other = KeyringFileName
			}
			if _, serr := os.Stat(filepath.Join(dir, other)); !errors.Is(serr, os.ErrNotExist) {
				t.Fatalf("%s was created by a refused InitV2", other)
			}
		})
	}
}

// An EMPTY vault.bin reads as "absent" to Inspect - a fresh install has no file and a zero-byte one
// is indistinguishable from a torn create - so the refusal cannot be left to a format check. It is
// the create itself that refuses, on the file's existence.
func TestInitV2RefusesAnEmptyExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, vaultFileName)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := InitV2(dir, initPass, kekMachineSlot(), initKeySource(t, initPass)); !errors.Is(err, ErrVaultExists) {
		t.Fatalf("InitV2 over a zero-byte vault.bin = %v, want ErrVaultExists", err)
	}
}

// No passphrase, no vault. There is no invented passphrase anywhere in this package, and a file with
// no passphrase slot is refused on write anyway (ErrNoRecoverySlot) - this is the earlier, clearer
// refusal, and it proves nothing was written on the way to it.
func TestInitV2RefusesAnEmptyPassphrase(t *testing.T) {
	dir := t.TempDir()
	_, err := InitV2(dir, "", kekMachineSlot(), initKeySource(t, ""))
	if !errors.Is(err, ErrNoKey) {
		t.Fatalf("InitV2 with no passphrase = %v, want ErrNoKey", err)
	}
	assertNeitherFileExists(t, dir)
}

// A passphrase slot is not a machine slot, and a type this binary cannot wrap is not either. Both
// are a caller's mistake, refused before anything is created.
func TestInitV2RefusesAMachineSlotThatIsNotOne(t *testing.T) {
	for _, typ := range []string{slotTypePassphrase, "cng", ""} {
		t.Run(typ, func(t *testing.T) {
			dir := t.TempDir()
			_, err := InitV2(dir, initPass, Slot{Type: typ}, initKeySource(t, initPass))
			if err == nil {
				t.Fatalf("InitV2 with machine slot type %q succeeded", typ)
			}
			assertNeitherFileExists(t, dir)
		})
	}
}

// A machine slot whose key this process cannot reach is ErrKEKUnreachable and NOT ErrBadKey: the key
// is where it should be and this process may not have it, and an operator pushed towards rotating a
// correct passphrase is a stated Anti-goal. The probe lands before the first byte is written.
func TestInitV2RefusesWhenTheMachineKeyIsUnreachable(t *testing.T) {
	dir := t.TempDir()
	_, err := InitV2(dir, initPass, kekMachineSlot(), &recordingKeySource{pass: initPass})
	if !errors.Is(err, ErrKEKUnreachable) {
		t.Fatalf("InitV2 with no reachable KEK = %v, want ErrKEKUnreachable", err)
	}
	assertNeitherFileExists(t, dir)
}

// A dpapi slot is wrappable on Windows and nowhere else. Off Windows the probe refuses and writes
// nothing, rather than a half-created data dir discovering it on the second file.
func TestInitV2DPAPISlotFollowsThePlatform(t *testing.T) {
	dir := t.TempDir()
	_, err := InitV2(dir, initPass, Slot{Type: slotTypeDPAPI}, &recordingKeySource{pass: initPass})
	if runtime.GOOS == "windows" {
		if err != nil {
			t.Fatalf("InitV2 with a dpapi slot on Windows: %v", err)
		}
		_, slots := headerOf(t, filepath.Join(dir, vaultFileName))
		if got := slotIDsByType(slots, slotTypeDPAPI); len(got) != 1 {
			t.Fatalf("%d dpapi slots, want 1", len(got))
		}
		// By type, not by index: marshalHeader appends a new slot in slot-id order, so which of the
		// two comes first in the header is randomness and not a property to pin.
		for _, s := range slots {
			if s.Type != slotTypeDPAPI {
				continue
			}
			if s.Scope != dpapiScopeMachine {
				t.Fatalf("dpapi slot scope %q, want %q", s.Scope, dpapiScopeMachine)
			}
		}
		return
	}
	if err == nil {
		t.Fatalf("InitV2 with a dpapi slot off Windows succeeded")
	}
	assertNeitherFileExists(t, dir)
}

// A unicode passphrase and a unicode directory are both ordinary inputs: the passphrase is bytes to
// argon2id and the directory is a path the operator chose. Neither may change the outcome.
func TestInitV2AcceptsAUnicodePassphraseAndPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "données-privées-日本")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	const pass = "pässwörd-ключ-🔐"
	if _, err := InitV2(dir, pass, kekMachineSlot(), initKeySource(t, pass)); err != nil {
		t.Fatalf("InitV2: %v", err)
	}
	if _, err := Open(filepath.Join(dir, vaultFileName), &recordingKeySource{pass: pass}); err != nil {
		t.Fatalf("Open with the unicode passphrase: %v", err)
	}
}

// The files a creator makes carry the same owner-only permissions every other write in this package
// sets. A fresh vault.bin readable by the world would be a silent regression of the one property the
// whole design rests on: the key is not in the copy, but the copy should not be free either.
func TestInitV2CreatesOwnerOnlyFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not the permission model on Windows; credfile.RestrictFile sets the ACL")
	}
	dir, _ := initBoth(t)
	for _, name := range []string{vaultFileName, KeyringFileName} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if perm := st.Mode().Perm(); perm != 0o600 {
			t.Fatalf("%s mode %04o, want 0600", name, perm)
		}
	}
}

// A failure on the SECOND file undoes the first. Nothing existed before the call - that is checked -
// so removing what this call itself created loses nothing, and it leaves a data dir `init` can be
// run against again rather than one that refuses for ever.
// The failure is injected through randRead rather than by making the second path unwritable, and
// that is not a style choice: InitV2 stats BOTH paths before it creates either, and os.Stat on a
// directory returns no error - so a directory at tunnelkeys.bin refuses at the pre-flight with
// ErrVaultExists, having created nothing, and the rollback loop never runs. The stub below starves
// the keyring of randomness the moment vault.bin exists, which lands the failure exactly where this
// test says it does. The assertion that the error is NOT ErrVaultExists is what keeps it honest.
func TestInitV2RemovesTheFirstFileWhenTheSecondFails(t *testing.T) {
	dir := t.TempDir()
	ks := initKeySource(t, initPass)
	vaultPath := filepath.Join(dir, vaultFileName)

	prev := randRead
	randRead = func(b []byte) (int, error) {
		if _, err := os.Stat(vaultPath); err == nil {
			return 0, errors.New("injected: no randomness left for the keyring")
		}
		return prev(b)
	}
	t.Cleanup(func() { randRead = prev })

	_, err := InitV2(dir, initPass, kekMachineSlot(), ks)
	if err == nil {
		t.Fatal("InitV2 succeeded with the keyring's randomness starved")
	}
	if errors.Is(err, ErrVaultExists) {
		t.Fatalf("the failure landed at the pre-flight, not on the second file, so the rollback was "+
			"never exercised: %v", err)
	}
	if _, serr := os.Stat(vaultPath); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("vault.bin survived a failed InitV2 (stat err %v)", serr)
	}
	if _, serr := os.Stat(filepath.Join(dir, KeyringFileName)); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("tunnelkeys.bin exists after the failure that created it (stat err %v)", serr)
	}
}

// Nothing a created file carries is a key. The header is the one part of the file that is not
// encrypted, so a wrap, a KEK or the passphrase appearing in it would be the whole design undone.
func TestInitV2WritesNoKeyMaterialInTheClear(t *testing.T) {
	dir, _ := initBoth(t)
	for _, name := range []string{vaultFileName, KeyringFileName} {
		data := bytesOf(t, filepath.Join(dir, name))
		for _, secret := range [][]byte{[]byte(initPass), initKEK()} {
			if bytes.Contains(data, secret) {
				t.Fatalf("%s carries key material in the clear", name)
			}
		}
	}
}
