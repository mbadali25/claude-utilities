package vault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// This file holds the two format conversions, and nothing else: v1 -> v2 (`server vault migrate`)
// and v2 -> v1 (`server vault downgrade`). They are the second and third doors into the v2 format
// after InitV2, and they are here rather than in createv2.go because they are not creators: each
// one REPLACES a file that must already be there, where InitV2 refuses a file that is.
//
// Why the payload never leaves the package. Both entries read a plaintext payload, write a new
// envelope and then prove the new envelope gives the SAME payload back, byte for byte. The
// comparison is the point of the step - a migration that re-sealed a truncated payload and said
// nothing is the Anti-goal - and it is done in here so that the plaintext (every account's refresh
// token) never crosses an API boundary, never reaches cmd/server and can never be printed. The
// caller gets a FileInfo and an error.
//
// Why each entry verifies and restores itself. The spec's step 6 is "re-open with the machine slot
// only, then with the passphrase only, compare the payload byte for byte ... any mismatch: restore
// the v1 copy over the v2 file". That sequence has to be inside one call: between the replace and
// the verify the file on disk is the new one, and a caller that got a FileInfo back and then failed
// its own verify would have to re-derive the old payload to compare against. So the caller writes
// and PROVES the copy first (it is the one step an operator can be told to redo by hand) and hands
// the path in; everything after the replace belongs to the call.
//
// Neither entry takes a lock, writes a journal or prompts. The caller holds the data-dir lock for
// the length of the command and writes the journal around these calls, exactly as it does for
// InitV2, so an interrupted conversion is readable afterwards.

// MigrateToV2 replaces the v1 file at path with a v2 file carrying the same payload: one passphrase
// slot under pass (re-wrapped, never changed - the operator's passphrase is the same secret
// afterwards) and one machine slot of machine's type.
//
// restoreFrom is the verified byte copy of the v1 file the caller has already written beside it
// (`<name>.v1.<ts>`). It is read only on the failure path: if the new file does not open under both
// keys with the same payload, those bytes go back over path before the error is returned. A caller
// that has not written and proved that copy must not call this.
//
// ks is consulted for one thing: the machine key behind the machine slot, and again for the
// machine-slot-alone half of the verify. Its Passphrase is never called - pass is the passphrase the
// operator typed for this command - so a KeySource with no passphrase is a valid argument.
//
// Every refusal that can land before the first byte does: the file's format, the machine slot's
// type, a machine sealer this host cannot resolve or cannot wrap under, and a wrong passphrase are
// all answered with path untouched.
func MigrateToV2(path, restoreFrom, pass string, machine Slot, ks KeySource) (FileInfo, error) {
	if pass == "" {
		// Not an invented one and not an empty one: migrate re-wraps the passphrase the operator
		// typed, and a key derived from "" would seal the vault under a passphrase nobody chose.
		return FileInfo{}, fmt.Errorf("%w: migrate was given no passphrase, and it never invents one", ErrNoKey)
	}
	switch machine.Type {
	case slotTypeDPAPI, slotTypeKEKFile:
	default:
		return FileInfo{}, fmt.Errorf("vault: migrate: %q is not a machine slot type this binary can create; "+
			"the two are %s and %s", machine.Type, slotTypeDPAPI, slotTypeKEKFile)
	}
	magicStr, err := v1KindOf(path)
	if err != nil {
		return FileInfo{}, err
	}
	// Resolved AND proved on a throwaway wrap while the file on disk is still the v1 one, for the
	// reason InitV2 does it before the first create: a dpapi slot off Windows, or a KEK this process
	// cannot read, must be found before anything is replaced rather than after.
	machineSealer, err := machineSealerFor(machine, ks)
	if err != nil {
		return FileInfo{}, err
	}
	if err := probeSealer(machineSealer, machine.Type); err != nil {
		return FileInfo{}, err
	}
	// The payload as the spec's step 2 reads it: under the operator's passphrase alone, which is the
	// only key a v1 file has. A wrong passphrase stops here with nothing written.
	_, plain, err := openSealed(path, magicStr, passOnly{pass: pass})
	if err != nil {
		return FileInfo{}, err
	}
	defer zero(plain)

	data, info, err := buildSealedV2(filepath.Base(path), magicStr, plain, pass, machine, machineSealer)
	if err != nil {
		return FileInfo{}, err
	}
	// The first byte written to path. Atomic: replaceFile writes a temp file beside it and renames,
	// so a crash here leaves either the whole v1 file or the whole v2 one, never a torn mixture.
	if err := replaceFile(path, data); err != nil {
		return FileInfo{}, err
	}
	if verr := proveSamePayload(path, magicStr, plain, pass, ks); verr != nil {
		if rerr := restoreOver(restoreFrom, path); rerr != nil {
			// Both failed. The message names the copy to put back by hand, because that is the only
			// instruction left - and the caller leaves its journal in place for the settle on the next
			// start, which is the spec's own answer for a restore that cannot complete.
			return FileInfo{}, fmt.Errorf("%w; and %s could not be restored over %s: %v - copy it back by hand",
				verr, filepath.Base(restoreFrom), filepath.Base(path), rerr)
		}
		return FileInfo{}, fmt.Errorf("%w; %s was restored from %s", verr,
			filepath.Base(path), filepath.Base(restoreFrom))
	}
	logger.Info("vault: migrated to v2", "op", "migrate", "result", "migrated",
		"format", FormatV2, "slottype", machine.Type, "slots", len(info.Slots))
	return info, nil
}

// DowngradeToV1 replaces the v2 file at path with a v1 file carrying the same payload, sealed under
// pass with a fresh argon2id salt and a fresh nonce, and keeps the v2 bytes at keepAt
// (`<name>.v2.<ts>`). It is the rollback the whole v2 design rests on: the passphrase slot exists so
// that this command can always be run.
//
// It refuses a file with no passphrase slot before it writes anything. Such a file cannot be written
// by this binary at all (ErrNoRecoverySlot on every v2 write), but a header repaired by hand could
// carry one, and a downgrade of it would produce a v1 file sealed under a passphrase that never
// opened the v2 one.
//
// The payload is read under the typed passphrase ALONE, not under a machine slot. That is the check
// that matters here and it is not an accident of the signature: the v1 file this command writes is
// openable by nothing but that passphrase, so a downgrade that read the payload through a dpapi or
// kek-file slot would happily seal the vault under a passphrase the operator has mistyped, and the
// first thing to discover it would be the old binary failing to start.
func DowngradeToV1(path, keepAt, pass string) (FileInfo, error) {
	if pass == "" {
		return FileInfo{}, fmt.Errorf("%w: downgrade was given no passphrase, and the v1 file it writes "+
			"can be opened by nothing else", ErrNoKey)
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return FileInfo{}, fmt.Errorf("vault: downgrade: read %s: %w", filepath.Base(path), err)
	}
	magicStr, err := v1KindOfV2Bytes(data)
	if err != nil {
		return FileInfo{}, err
	}
	// From the header alone, before the passphrase is spent on argon2id and before anything is
	// written: a file this command must refuse is refused on bytes, not on a key.
	_, headerJSON, err := rawHeaderOf(data)
	if err != nil {
		return FileInfo{}, err
	}
	h, _, err := parseHeader(headerJSON)
	if err != nil {
		return FileInfo{}, err
	}
	if h.passphraseSlotCount() == 0 {
		return FileInfo{}, fmt.Errorf("%w: %s has no passphrase slot, so there is no passphrase for a v1 "+
			"file to be sealed under", ErrNoRecoverySlot, filepath.Base(path))
	}
	_, plain, err := openSealed(path, magicStr, passOnly{pass: pass})
	if err != nil {
		return FileInfo{}, err
	}
	defer zero(plain)

	// The v2 bytes are kept BEFORE path is replaced, and they are read back and compared: a copy
	// nobody proved is not a rollback. `downgrade` is the command an operator reaches for when they
	// already distrust the new format, so the generation it is leaving must survive it.
	if err := replaceFile(keepAt, data); err != nil {
		return FileInfo{}, fmt.Errorf("vault: downgrade: keep the v2 bytes: %w", err)
	}
	kept, err := os.ReadFile(filepath.Clean(keepAt))
	if err != nil || !bytes.Equal(kept, data) {
		return FileInfo{}, fmt.Errorf("vault: downgrade: %s does not read back as the v2 file it copied, "+
			"so there would be no way back: nothing was changed", filepath.Base(keepAt))
	}
	v1, err := buildSealedV1(magicStr, plain, pass)
	if err != nil {
		return FileInfo{}, err
	}
	if err := replaceFile(path, v1); err != nil {
		return FileInfo{}, err
	}
	if verr := proveSamePayload(path, magicStr, plain, pass, nil); verr != nil {
		if rerr := restoreOver(keepAt, path); rerr != nil {
			return FileInfo{}, fmt.Errorf("%w; and %s could not be restored over %s: %v - copy it back by hand",
				verr, filepath.Base(keepAt), filepath.Base(path), rerr)
		}
		return FileInfo{}, fmt.Errorf("%w; %s was restored from %s", verr,
			filepath.Base(path), filepath.Base(keepAt))
	}
	logger.Info("vault: downgraded to v1", "op", "downgrade", "result", "downgraded", "format", FormatV1)
	return FileInfo{Name: filepath.Base(path), Format: FormatV1}, nil
}

// buildSealedV1 is the v1 envelope: magic | salt(16) | nonce(12) | GCM(argon2id(pass, salt), payload)
// with the magic and the salt as the additional data. It is sealed.write's v1 branch written out
// once more rather than called, because that branch needs a *sealed whose salt and AEAD came from
// opening a v1 file, and here there is no v1 file to open - the whole point is that one is being
// made from a v2 one.
//
// The salt and the nonce are fresh, per the spec's downgrade line. Reusing the v2 file's passphrase
// salt would be a smaller change and the wrong one: the v1 key is AES-GCM'd directly over the whole
// payload, so a salt shared with a slot wrap would put two different ciphertexts under one derived
// key for no benefit.
func buildSealedV1(magicStr string, plain []byte, pass string) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := randRead(salt); err != nil {
		return nil, fmt.Errorf("vault: downgrade: salt: %w", err)
	}
	aead, err := deriveAEAD(pass, salt)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := randRead(nonce); err != nil {
		return nil, fmt.Errorf("vault: downgrade: nonce: %w", err)
	}
	header := append([]byte(magicStr), salt...)
	var buf bytes.Buffer
	buf.Write(header)
	buf.Write(nonce)
	buf.Write(aead.Seal(nil, nonce, plain, header))
	return buf.Bytes(), nil
}

// proveSamePayload re-opens the file just written and compares its payload to want, once under the
// machine slot alone and once under the passphrase alone. It is the spec's step 6, and the two
// checks answer different questions: the machine slot alone is "can the service start with nobody at
// the keyboard", the passphrase alone is "is the recovery rung real".
//
// ks is nil for a downgrade, which has no machine slot to check - a v1 file has none - so there the
// passphrase check is the whole verification, and it is also the only one that means anything.
//
// The comparison is bytes.Equal and not a constant-time compare on purpose: both sides are this
// process's own plaintext, one of them read seconds ago from the file the other was sealed into, so
// there is no attacker-chosen input and no oracle for a timing difference to leak to.
func proveSamePayload(path, magicStr string, want []byte, pass string, ks KeySource) error {
	checks := []struct {
		label string
		ks    KeySource
	}{
		{"the machine slot alone", machineOnly{inner: ks}},
		{"the passphrase alone", passOnly{pass: pass}},
	}
	for _, c := range checks {
		if ks == nil && c.label == "the machine slot alone" {
			continue
		}
		_, got, err := openSealed(path, magicStr, c.ks)
		if err != nil {
			return fmt.Errorf("vault: %s did not open under %s after it was written: %w",
				filepath.Base(path), c.label, err)
		}
		same := bytes.Equal(got, want)
		zero(got)
		if !same {
			return fmt.Errorf("vault: %s opened under %s and gave back a different payload than the one "+
				"that was read from it", filepath.Base(path), c.label)
		}
	}
	return nil
}

// restoreOver copies src's bytes over dst through replaceFile, so the restore lands atomically and
// with the same mode and ACL every other write in this package produces. An src that is absent or
// empty is refused rather than copied: writing zero bytes over a vault is worse than leaving the
// file that is there.
func restoreOver(src, dst string) error {
	if src == "" {
		return errors.New("no copy was named to restore from")
	}
	data, err := os.ReadFile(filepath.Clean(src))
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("%s is empty", filepath.Base(src))
	}
	return replaceFile(dst, data)
}

// v1KindOf names the file kind of the v1 file at path - the magic to pass through the rest of this
// package, which is the KIND and not the version - and refuses anything that is not a v1 file of a
// kind this binary knows.
//
// The three refusals are separate messages because they send an operator three different ways: a v2
// file needs nothing done to it, an absent file needs `init`, and anything else is a damaged or
// foreign file.
func v1KindOf(path string) (string, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("%w: there is no %s to migrate", ErrNotV2, filepath.Base(path))
	}
	if err != nil {
		return "", fmt.Errorf("vault: migrate: read %s: %w", filepath.Base(path), err)
	}
	switch {
	case bytes.HasPrefix(data, []byte(magic)):
		return magic, nil
	case bytes.HasPrefix(data, []byte(keyringMagic)):
		return keyringMagic, nil
	case bytes.HasPrefix(data, []byte(v2VaultMagic)), bytes.HasPrefix(data, []byte(v2KeyringMagic)):
		return "", fmt.Errorf("%w: %s is already v2", ErrNewerFormat, filepath.Base(path))
	}
	return "", fmt.Errorf("%w: %s is not a vault file this binary knows", errCorrupt, filepath.Base(path))
}

// v1KindOfV2Bytes is v1KindOf's inverse direction: the v1 magic - again the KIND - for bytes that
// must carry a v2 magic. v2Magic is the forward mapping and the only one; this is deliberately the
// only place that reads it backwards, so there is no second table to drift.
func v1KindOfV2Bytes(data []byte) (string, error) {
	switch {
	case bytes.HasPrefix(data, []byte(v2VaultMagic)):
		return magic, nil
	case bytes.HasPrefix(data, []byte(v2KeyringMagic)):
		return keyringMagic, nil
	case bytes.HasPrefix(data, []byte(magic)), bytes.HasPrefix(data, []byte(keyringMagic)):
		return "", fmt.Errorf("%w: it is already v1, so there is nothing to downgrade", ErrNotV2)
	}
	return "", fmt.Errorf("%w: it is not a vault file this binary knows", errCorrupt)
}

// passOnly is a KeySource holding one typed passphrase and no machine opener at all. It is how both
// entries here spend exactly the key the operator supplied: a v1 file has no machine slot, and the
// passphrase-alone half of a verify must not be answered by a dpapi slot that happened to open.
type passOnly struct{ pass string }

func (p passOnly) Passphrase() (string, error) {
	if p.pass == "" {
		return "", fmt.Errorf("%w: no passphrase was given", ErrNoKey)
	}
	return p.pass, nil
}

func (passOnly) Machine() []SlotOpener { return nil }

// machineOnly is a KeySource with another source's machine openers and NO passphrase - not an empty
// one, none. It is exactly what a service has, which is what makes the machine-slot-alone check
// answer the service's own question rather than a weaker one.
type machineOnly struct{ inner KeySource }

func (machineOnly) Passphrase() (string, error) {
	return "", fmt.Errorf("%w: this check offers no passphrase on purpose", ErrNoKey)
}

func (m machineOnly) Machine() []SlotOpener {
	if m.inner == nil {
		return nil
	}
	return m.inner.Machine()
}
