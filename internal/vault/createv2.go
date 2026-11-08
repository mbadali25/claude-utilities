package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"claude-utilities/internal/credfile"
)

// This file holds the only creator of a v2 file. It is openSealedV2's inverse, read in that order:
// where the opener parses a header, walks the slots until one gives up the data key and opens the
// payload under the header's own bytes, this draws a data key, wraps it into every slot, marshals
// the header and seals the payload under those same bytes.
//
// Why it is a separate door rather than a flag on the write path. `write` branches on whether the
// file arrived with a data key, so there is no argument anywhere that turns a CSV1 file into a CSV2
// one or the other way round, and create-on-open stays v1 for good (see Open). A v2 file needs a
// typed passphrase, a machine slot this host can actually wrap under, and a printed recovery rung -
// none of which a path inside Open has or could ask for. So the creation lives here, behind one
// exported entry that only `server vault init` calls, and nothing a default `server run` reaches
// can get to it.
//
// Two slots, never one. The passphrase slot is the recovery rung for every machine-key loss case in
// the design (Premise 3) and a v2 write with no passphrase slot is refused outright
// (ErrNoRecoverySlot); the machine slot is what lets a service start with no operator at the
// keyboard. A file with only one of the two is a file this creator will not write.
//
// Every refusal lands before the first byte. The machine slot's sealer is resolved AND proved on a
// throwaway key before either file is created, on the same reasoning proveSealers is built on: a
// dpapi slot off Windows, or a kek-file slot whose KEK this process cannot read, must be found while
// the directory is still untouched - not on the second of the two files, which is how a data dir
// ends up holding a v2 vault beside no keyring at all.

// ErrVaultExists means a file this creator was asked to create is already there. It is never
// overwritten: `init` is for a data dir that has none, a v1 file is `migrate`'s job, and a v2 file
// needs nothing done to it. The error names the file, because the operator's next step is to look at
// it (`server vault status`) rather than to delete it.
var ErrVaultExists = errors.New("vault: refusing to create over a file that is already there")

// InitV2 creates vault.bin and tunnelkeys.bin in dataDir as fresh v2 files, each sealed under its
// own data key and each carrying one passphrase slot (under pass) and one machine slot (machine's
// Type, and for a kek-file slot its credential Name, which defaults to vault-kek).
//
// machine supplies the type and at most a name. The slot ids, the `created` stamps, the argon2id
// salts and both data keys come from this package's own randomness, because they must: a caller that
// supplied any of them would be choosing key material from outside the one place that owns it. Only
// `dpapi` and `kek-file` are accepted - a second passphrase slot is `add-slot`'s business, and a
// type this binary cannot wrap is refused by name.
//
// ks is consulted for one thing only: the machine key behind the machine slot. Its Passphrase is
// never called - pass is the passphrase, typed by the operator for this command - so a KeySource
// with no passphrase at all is a valid argument here.
//
// It takes no lock. The caller holds the data-dir lock for the length of the command (every `vault`
// mutator does) and writes the vaultop journal before calling, so an interrupted creation is
// readable afterwards; the no-clobber refusal is atomic at the create regardless, so the lock is not
// what makes that property true.
//
// The returned FileInfos are the two files as `status` reports them, in the order vault.bin then
// tunnelkeys.bin, so the caller can print the slot ids it did not choose. On a failure partway it
// returns the error and leaves the directory as it found it: a file this call created is removed
// again, which loses nothing, because the call has already proved there was none.
func InitV2(dataDir, pass string, machine Slot, ks KeySource) ([]FileInfo, error) {
	if pass == "" {
		// Not an invented one, and not an empty one either: a key derived from "" would seal the vault
		// under a passphrase nobody chose, and the operator would never learn which.
		return nil, fmt.Errorf("%w: init was given no passphrase, and it never invents one", ErrNoKey)
	}
	switch machine.Type {
	case slotTypeDPAPI, slotTypeKEKFile:
	default:
		return nil, fmt.Errorf("vault: init: %q is not a machine slot type this binary can create; "+
			"the two are %s and %s", machine.Type, slotTypeDPAPI, slotTypeKEKFile)
	}
	// Resolved and proved while the directory is still untouched. See the file comment.
	machineSealer, err := machineSealerFor(machine, ks)
	if err != nil {
		return nil, err
	}
	if err := probeSealer(machineSealer, machine.Type); err != nil {
		return nil, err
	}

	accounts, err := json.Marshal(make([]Account, 0))
	if err != nil {
		return nil, fmt.Errorf("vault: init: encode: %w", err)
	}
	keys, err := json.Marshal(keyringPayload{Keys: make([]TunnelKey, 0)})
	if err != nil {
		return nil, fmt.Errorf("vault: init: encode: %w", err)
	}

	plan := []struct {
		path     string
		magicStr string
		plain    []byte
	}{
		{filepath.Join(dataDir, vaultFileName), magic, accounts},
		{filepath.Join(dataDir, KeyringFileName), keyringMagic, keys},
	}
	// Both existence checks before either create, so the refusal for a half-initialised data dir
	// names the file that is there and creates nothing beside it. The create itself refuses again,
	// atomically - this check is the one that produces the better message, not the one that makes the
	// property true.
	for _, f := range plan {
		if err := refuseExisting(f.path); err != nil {
			return nil, err
		}
	}
	out := make([]FileInfo, 0, len(plan))
	for _, f := range plan {
		info, cerr := createSealedV2(f.path, f.magicStr, f.plain, pass, machine, machineSealer)
		if cerr != nil {
			// Undo this call's own work. Every path in `out` was created by this call, a moment ago, in
			// a directory this call proved held neither file - so there is no copy of anyone's data in
			// them and removing them cannot lose anything. What it buys is a data dir `init` can be run
			// against again, rather than one that refuses for ever because the first file landed.
			for _, done := range out {
				removeQuiet(filepath.Join(dataDir, done.Name))
			}
			return nil, cerr
		}
		out = append(out, info)
	}
	logger.Info("vault: v2 files created", "op", "init", "result", "created",
		"format", FormatV2, "slottype", machine.Type, "slots", 2)
	return out, nil
}

// refuseExisting reports ErrVaultExists for a path that is already there. A zero-byte file counts:
// Inspect reads an empty file as "absent" - a fresh install has no file and a torn create is
// indistinguishable from one - so a format test could not have refused it, and creating over it
// would destroy whatever a previous run was in the middle of writing.
func refuseExisting(path string) error {
	_, err := os.Stat(filepath.Clean(path))
	switch {
	case err == nil:
		return fmt.Errorf("%w: %s", ErrVaultExists, filepath.Base(path))
	case errors.Is(err, os.ErrNotExist):
		return nil
	}
	return fmt.Errorf("vault: init: %s: %w", filepath.Base(path), err)
}

// createSealedV2 is the constructor: it writes one new v2 file at path and reports what it wrote.
// Unexported on purpose - the two files are created together or not at all, so there is no caller
// outside InitV2 that should be able to make one of them.
//
// The order is openSealedV2's, run backwards, and the last two steps are the ones that cannot drift:
// marshalHeader produces the bytes, and the payload is sealed under those same bytes in the same
// call. A creator that sealed the payload under a header it then re-marshalled would produce a file
// whose slots open and whose payload never does.
//
// marshalHeader is also where the writer's two refusals live, and both land before the create: it
// parses its own output, so every bound the reader enforces the writer enforces too, and a header
// with no passphrase slot is ErrNoRecoverySlot.
func createSealedV2(path, magicStr string, plain []byte, pass string, machine Slot,
	machineSealer slotSealer) (FileInfo, error) {
	info := FileInfo{Name: filepath.Base(path), Format: FormatV2}
	v2 := v2Magic(magicStr)
	if v2 == "" {
		return FileInfo{}, fmt.Errorf("%w: this file kind has no v2 format", errCorrupt)
	}
	dek := make([]byte, keyLen)
	if _, err := randRead(dek); err != nil {
		return FileInfo{}, fmt.Errorf("vault: init: data key: %w", err)
	}
	defer zero(dek)
	dekID := make([]byte, dekIDLen)
	if _, err := randRead(dekID); err != nil {
		return FileInfo{}, fmt.Errorf("vault: init: dek id: %w", err)
	}
	created := nowString()

	passSlot, err := newPassphraseSlot(created)
	if err != nil {
		return FileInfo{}, err
	}
	machineSlot, err := newMachineSlot(machine, created)
	if err != nil {
		return FileInfo{}, err
	}
	pairs := []struct {
		slot   Slot
		sealer slotSealer
	}{
		{machineSlot, machineSealer},
		{passSlot, &passphraseSealer{pass: pass, params: *passSlot.Argon2id}},
	}
	// An empty Slots and both slots in `changed`: marshalHeader appends a slot it has not seen, so
	// this is the "add two slots to a header that has none" shape, and the order in the file is
	// marshalHeader's (by slot id). The order does not matter to a reader - tryOrder re-sorts machine
	// slots ahead of passphrase slots on every open - so there is nothing to pin here.
	h := Header{V: headerVersion, DEK: DEKInfo{ID: encB64(dekID), Created: created}}
	changed := make(map[string]Slot, len(pairs))
	for _, p := range pairs {
		slotID, derr := decodeSlotID(p.slot.ID)
		if derr != nil {
			return FileInfo{}, derr
		}
		wrap, serr := p.sealer.seal(dek, slotAAD(v2, dekID, slotID, p.slot.Type))
		if serr != nil {
			return FileInfo{}, serr
		}
		s := p.slot
		s.Wrap = wrap
		changed[s.ID] = s
	}
	headerJSON, err := marshalHeader(h, changed)
	if err != nil {
		return FileInfo{}, err
	}
	// The slots are reported from a parse of the bytes that are about to be written, not from the
	// structs above: what an operator is shown has to be what the file carries, which is the same
	// reason writeV2 parses its own header before it advances anything.
	parsedHeader, parsedSlots, err := parseHeader(headerJSON)
	if err != nil {
		return FileInfo{}, err
	}
	for _, s := range parsedSlots {
		info.Slots = append(info.Slots, SlotInfo{ID: s.ID, Type: s.Type, Scope: s.Scope,
			Name: s.Name, Created: s.Created, Known: true,
			// True by proof rather than by assumption: the machine slot's sealer was resolved from the
			// key source this run holds and proved on a throwaway wrap before anything was created, so
			// this host does hold a key for it. A passphrase slot's key is in an operator's head.
			HostHoldsKey: s.Type != slotTypePassphrase})
	}
	raw := make([]byte, 0, v2PrefixLen+len(headerJSON))
	raw = append(raw, v2...)
	var n [4]byte
	//nolint:gosec // G115: marshalHeader caps the header at maxHdrLen (64 KiB), re-checked above.
	binary.BigEndian.PutUint32(n[:], uint32(len(headerJSON)))
	raw = append(raw, n[:]...)
	raw = append(raw, headerJSON...)

	aead, err := payloadAEAD(dek)
	if err != nil {
		return FileInfo{}, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := randRead(nonce); err != nil {
		return FileInfo{}, fmt.Errorf("vault: init: nonce: %w", err)
	}
	var buf bytes.Buffer
	buf.Write(raw)
	buf.Write(nonce)
	buf.Write(aead.Seal(nil, nonce, plain, raw))
	if err := createFileExcl(path, buf.Bytes()); err != nil {
		return FileInfo{}, err
	}
	info.DEKID = dekIDPrefix(parsedHeader.DEK.ID)
	return info, nil
}

// newPassphraseSlot is one fresh passphrase slot: a random id, a random argon2id salt and this
// binary's real cost parameters. The salt is 16 bytes of this package's randomness and the cost is
// not a caller's choice, for the same reason the data key is not.
func newPassphraseSlot(created string) (Slot, error) {
	id, err := newSlotID()
	if err != nil {
		return Slot{}, err
	}
	salt := make([]byte, saltLen)
	if _, err := randRead(salt); err != nil {
		return Slot{}, fmt.Errorf("vault: init: salt: %w", err)
	}
	return Slot{ID: id, Type: slotTypePassphrase, Created: created,
		Argon2id: &Argon2Params{T: argonTime, M: argonMem, P: argonPar, Salt: encB64(salt)}}, nil
}

// newMachineSlot is the machine slot as it will be written: the caller's type and name, this
// package's id and stamp, and nothing else the caller handed in. Wrap, Argon2id and Scope are
// cleared and re-derived rather than trusted, so a caller cannot smuggle a wrap, a cost parameter or
// a scope this binary does not write into a file it is creating.
func newMachineSlot(machine Slot, created string) (Slot, error) {
	id, err := newSlotID()
	if err != nil {
		return Slot{}, err
	}
	s := Slot{ID: id, Type: machine.Type, Name: machine.Name, Created: created}
	switch s.Type {
	case slotTypeDPAPI:
		s.Scope = dpapiScopeMachine
		// A dpapi protector holds its own key, so there is nothing for a name to point at.
		s.Name = ""
	case slotTypeKEKFile:
		if s.Name == "" {
			s.Name = kekCredentialName
		}
	}
	return s, nil
}

// newSlotID is 8 bytes of this package's randomness, base64-encoded. Two calls in one creation give
// two different ids with overwhelming probability, and the header parser refuses a duplicate anyway.
func newSlotID() (string, error) {
	id := make([]byte, slotIDLen)
	if _, err := randRead(id); err != nil {
		return "", fmt.Errorf("vault: init: slot id: %w", err)
	}
	return encB64(id), nil
}

// decodeSlotID is the slot id as slotAAD needs it: raw bytes, exactly slotIDLen of them.
func decodeSlotID(id string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(id)
	if err != nil || len(raw) != slotIDLen {
		return nil, errCorrupt
	}
	return raw, nil
}

// machineSealerFor resolves the wrapping half of the machine slot from the key source. It is the
// third site in this package that resolves a kek-file KEK, beside sealerSet.sealerFor (a rotation's)
// and Vault.hostKEKSealer (add-slot's), and it is separate for the reason those two are: the error an
// operator needs names the command they ran. Here it names init, which is the command that creates
// host key material, so a KEK that does not resolve is a setup step rather than a lost key.
func machineSealerFor(machine Slot, ks KeySource) (slotSealer, error) {
	if machine.Type == slotTypeDPAPI {
		return dpapiSealer{}, nil
	}
	if ks == nil {
		return nil, fmt.Errorf("%w: init was given no key source, so there is no KEK to wrap under", ErrKEKUnreachable)
	}
	op := openerFor(ks.Machine(), slotTypeKEKFile)
	if op == nil {
		return nil, fmt.Errorf("%w: no KEK resolves on this host, so a %s slot has nothing to wrap under",
			ErrKEKUnreachable, slotTypeKEKFile)
	}
	kf, ok := op.(*kekFileSlotOpener)
	if !ok {
		return nil, fmt.Errorf("%w: this host's %s opener cannot wrap", ErrKEKUnreachable, slotTypeKEKFile)
	}
	if kf.err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKEKUnreachable, kf.err)
	}
	return kekSealer{kek: kf.kek}, nil
}

// probeSealer proves a sealer can actually wrap, by sealing a throwaway key under a throwaway AAD.
// It is proveSealers' probe for the one slot a creation cannot resolve from a header: dpapi can be
// unavailable and a KEK can be present and refuse, and discovering either on the second of two files
// is how a data dir ends up half created.
func probeSealer(s slotSealer, slotType string) error {
	probeDEK := make([]byte, keyLen)
	probeDEKID := make([]byte, dekIDLen)
	probeSlotID := make([]byte, slotIDLen)
	if _, err := s.seal(probeDEK, slotAAD(v2VaultMagic, probeDEKID, probeSlotID, slotType)); err != nil {
		return err
	}
	return nil
}

// createFileExcl writes data to a NEW file at dst and refuses if dst is already there. It is
// replaceFile's creation counterpart and keeps the same three promises - the 0600 mode, the Windows
// owner-only ACL and the directory sync - so a file this creator makes is no more readable than one
// every other write in this package produces. It does not share replaceFile's body because it is a
// deliberately different sequence: there is no temp file and no rename, because the rename is
// precisely what would clobber.
//
// The no-clobber is atomic at the open (O_EXCL), not a stat followed by a write, so two commands
// racing on one data dir cannot both believe they created the file.
//
// What it does not survive, stated rather than implied: a hard crash between the create and the
// sync leaves a short dst, and the next `init` then refuses because something is there. That is the
// safe direction - the alternative is a creator that overwrites - and the refusal names the file, so
// `server vault status` (which reads it as absent, being empty or short) plus the vaultop journal the
// caller wrote are what explain it. Every failure this function can see for itself removes dst again.
func createFileExcl(dst string, data []byte) error {
	dir := filepath.Dir(dst)
	f, err := os.OpenFile(filepath.Clean(dst), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: %s", ErrVaultExists, filepath.Base(dst))
		}
		return fmt.Errorf("vault: create: %w", err)
	}
	fail := func(err error) error {
		_ = f.Close()
		removeQuiet(dst)
		return fmt.Errorf("vault: write: %w", err)
	}
	if err := f.Chmod(0o600); err != nil && !isWindowsChmodQuirk(err) {
		return fail(err)
	}
	// Windows: Chmod only toggles read-only, so set an owner-only ACL (no-op elsewhere).
	if err := credfile.RestrictFile(dst); err != nil {
		return fail(err)
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		removeQuiet(dst)
		return fmt.Errorf("vault: close: %w", err)
	}
	credfile.SyncDir(dir)
	return nil
}
