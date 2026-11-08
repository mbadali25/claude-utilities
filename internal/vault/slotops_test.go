package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests for the slot mutators: add, remove (which also rotates), rotate and change-passphrase, plus
// the two read-only inspectors the CLI's `status` and `verify` stand on.
//
// Every fixture is built by buildV2 out of this package's own primitives, and every path is under
// t.TempDir(): nothing here goes near a real data dir, a real credstore or a host's live vault.

// addSlotPass is the passphrase every fixture in this file is sealed under, and addSlotKEK a
// 32-byte key-encryption key for a kek-file slot. Literal, so a failure is reproducible.
const addSlotPass = "the-first-passphrase"

func addSlotKEK() []byte { return bytes.Repeat([]byte{0x7e}, keyLen) }

// v2VaultAt writes a v2 vault at <dir>/vault.bin from specs and returns its path.
func v2VaultAt(t *testing.T, dir string, specs []v2Spec, ids ...string) string {
	t.Helper()
	path := filepath.Join(dir, vaultFileName)
	data := buildV2(t, magic, []byte(fileDEK), specs, accountsPayload(t, ids...))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// openV2 opens a v2 vault with a passphrase-only key source, which is what an operator CLI run has.
func openV2(t *testing.T, path, pass string) *Vault {
	t.Helper()
	v, err := Open(path, &recordingKeySource{pass: pass})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return v
}

// headerOf re-parses a file's header off disk, which is how these tests ask what was written rather
// than what the in-memory struct believes.
func headerOf(t *testing.T, path string) (Header, []Slot) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	_, headerJSON, err := rawHeaderOf(data)
	if err != nil {
		t.Fatalf("rawHeaderOf: %v", err)
	}
	h, slots, err := parseHeader(headerJSON)
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	return h, slots
}

// slotIDsByType lists the ids of the slots of one type, in header order.
func slotIDsByType(slots []Slot, typ string) []string {
	var out []string
	for _, s := range slots {
		if s.Type == typ {
			out = append(out, s.ID)
		}
	}
	return out
}

// bytesOf is the whole file, for the "nothing was written" assertions every refusal carries.
func bytesOf(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// --- add-slot ---

// The baseline: a second slot wraps the SAME data key, so either key opens the file and both see
// the same accounts. That is the whole point of a slot - one payload, several ways in.
func TestAddSlotWrapsTheSameDEK(t *testing.T) {
	dir := t.TempDir()
	path := v2VaultAt(t, dir, []v2Spec{passSpec("slot0001", addSlotPass)}, "a1")
	v := openV2(t, path, addSlotPass)
	if err := v.AddSlot(Slot{Type: slotTypeKEKFile, Name: "vault-kek"}, addSlotKEK()); err != nil {
		t.Fatalf("AddSlot: %v", err)
	}
	h, slots := headerOf(t, path)
	if len(slots) != 2 {
		t.Fatalf("header has %d slots, want 2", len(slots))
	}
	if h.DEK.ID != b64([]byte(fileDEKID)) {
		t.Fatalf("add-slot changed the dek generation: %q", h.DEK.ID)
	}
	// Each key alone, on its own open, must produce the same account list.
	byPass := openV2(t, path, addSlotPass).List()
	byKEK, err := Open(path, kekSource(t, addSlotKEK(), "", ErrNoKey))
	if err != nil {
		t.Fatalf("open with the new kek-file slot alone: %v", err)
	}
	if len(byPass) != 1 || len(byKEK.List()) != 1 || byPass[0].ID != byKEK.List()[0].ID {
		t.Fatalf("the two slots do not yield the same payload: %v vs %v", byPass, byKEK.List())
	}
}

// Two passphrase slots, two independent passphrases: the staged rotation the spec calls for (add
// new, verify, remove old) needs exactly this.
func TestAddSlotPassphraseGivesTwoIndependentPassphraseSlots(t *testing.T) {
	dir := t.TempDir()
	path := v2VaultAt(t, dir, []v2Spec{passSpec("slot0001", addSlotPass)}, "a1")
	v := openV2(t, path, addSlotPass)
	if err := v.AddSlot(Slot{Type: slotTypePassphrase}, []byte("the-second-passphrase")); err != nil {
		t.Fatalf("AddSlot: %v", err)
	}
	_, slots := headerOf(t, path)
	if got := slotIDsByType(slots, slotTypePassphrase); len(got) != 2 {
		t.Fatalf("header has %d passphrase slots, want 2", len(got))
	}
	for _, pass := range []string{addSlotPass, "the-second-passphrase"} {
		if _, err := Open(path, &recordingKeySource{pass: pass}); err != nil {
			t.Fatalf("open with %q: %v", pass, err)
		}
	}
	// And the two salts differ, so the two slots are not the same derivation twice.
	a, b := slots[0].Argon2id, slots[1].Argon2id
	if a == nil || b == nil || a.Salt == b.Salt {
		t.Fatalf("the two passphrase slots share a salt")
	}
}

// A slot id is assigned by this package, from its own randomness seam. A caller that supplies one
// that is already in the header is refused, and nothing is written: the id is length-prefixed into
// every wrap's AAD, so two slots under one id is a file with an unanswerable "which slot opened it".
func TestAddSlotRefusesADuplicateSlotID(t *testing.T) {
	dir := t.TempDir()
	path := v2VaultAt(t, dir, []v2Spec{passSpec("slot0001", addSlotPass)}, "a1")
	v := openV2(t, path, addSlotPass)
	before := bytesOf(t, path)
	err := v.AddSlot(Slot{ID: b64([]byte("slot0001")), Type: slotTypeKEKFile}, addSlotKEK())
	if !errors.Is(err, ErrSlotExists) {
		t.Fatalf("AddSlot with a duplicate id = %v, want ErrSlotExists", err)
	}
	if !bytes.Equal(before, bytesOf(t, path)) {
		t.Fatalf("a refused add-slot wrote to the file")
	}
}

// A v1 file has no slots to add to. The answer names the command that gives it some, and is not
// ErrBadKey: nothing here is a wrong passphrase.
func TestEveryMutatorRefusesAV1File(t *testing.T) {
	path := writeV1Vault(t, addSlotPass)
	for _, tc := range []struct {
		name string
		call func(v *Vault) error
	}{
		{"add-slot", func(v *Vault) error { return v.AddSlot(Slot{Type: slotTypePassphrase}, []byte("x")) }},
		{"remove-slot", func(v *Vault) error {
			_, err := v.RemoveSlot(b64([]byte("slot0001")), &recordingKeySource{pass: addSlotPass})
			return err
		}},
		{"rotate", func(v *Vault) error { return v.Rotate(&recordingKeySource{pass: addSlotPass}) }},
		{"change-passphrase", func(v *Vault) error { return v.ChangePassphrase(addSlotPass, "next") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := openV2(t, path, addSlotPass)
			before := bytesOf(t, path)
			if err := tc.call(v); !errors.Is(err, ErrNotV2) {
				t.Fatalf("%s on a v1 file = %v, want ErrNotV2", tc.name, err)
			}
			if !bytes.Equal(before, bytesOf(t, path)) {
				t.Fatalf("%s wrote to a v1 file", tc.name)
			}
		})
	}
}

// --- remove-slot ---

// Removing a slot rotates the data key in the same write, which is the property that makes a
// removal mean something: the removed holder's wrapped copy is of a key the file no longer uses.
func TestRemoveSlotAlsoRotatesTheDEK(t *testing.T) {
	dir := t.TempDir()
	path := v2VaultAt(t, dir,
		[]v2Spec{passSpec("slot0001", addSlotPass), kekSpec("slot0002", addSlotKEK())}, "a1")
	kekSlotID := b64([]byte("slot0002"))
	before, _ := headerOf(t, path)
	v := openV2(t, path, addSlotPass)
	if _, err := v.RemoveSlot(kekSlotID, &recordingKeySource{pass: addSlotPass}); err != nil {
		t.Fatalf("RemoveSlot: %v", err)
	}
	after, slots := headerOf(t, path)
	if after.DEK.ID == before.DEK.ID {
		t.Fatalf("remove-slot kept the dek generation %q", after.DEK.ID)
	}
	if len(slots) != 1 || slots[0].Type != slotTypePassphrase {
		t.Fatalf("slots after removal: %v", slots)
	}
	// The removed key opens nothing current.
	if _, err := Open(path, kekSource(t, addSlotKEK(), "", ErrNoKey)); err == nil {
		t.Fatalf("the removed kek-file key still opens the vault")
	}
	// And the surviving passphrase still does.
	if _, err := Open(path, &recordingKeySource{pass: addSlotPass}); err != nil {
		t.Fatalf("the surviving passphrase slot no longer opens the vault: %v", err)
	}
}

// The last passphrase slot is the recovery rung for every machine-key loss case. Removing it is
// refused and writes nothing - not the vault, not the .bak.
func TestRemoveSlotRefusesTheLastPassphraseSlot(t *testing.T) {
	dir := t.TempDir()
	path := v2VaultAt(t, dir,
		[]v2Spec{passSpec("slot0001", addSlotPass), kekSpec("slot0002", addSlotKEK())}, "a1")
	v := openV2(t, path, addSlotPass)
	before := bytesOf(t, path)
	_, err := v.RemoveSlot(b64([]byte("slot0001")), &recordingKeySource{pass: addSlotPass})
	if !errors.Is(err, ErrLastPassphraseSlot) {
		t.Fatalf("RemoveSlot of the last passphrase slot = %v, want ErrLastPassphraseSlot", err)
	}
	if !bytes.Equal(before, bytesOf(t, path)) {
		t.Fatalf("a refused remove-slot wrote to the file")
	}
}

func TestRemoveSlotRefusesAnUnknownID(t *testing.T) {
	dir := t.TempDir()
	path := v2VaultAt(t, dir, []v2Spec{passSpec("slot0001", addSlotPass), kekSpec("slot0002", addSlotKEK())}, "a1")
	v := openV2(t, path, addSlotPass)
	before := bytesOf(t, path)
	if _, err := v.RemoveSlot(b64([]byte("nosuchid")), &recordingKeySource{pass: addSlotPass}); !errors.Is(err, ErrSlotNotFound) {
		t.Fatalf("RemoveSlot of an absent id = %v, want ErrSlotNotFound", err)
	}
	if !bytes.Equal(before, bytesOf(t, path)) {
		t.Fatalf("a refused remove-slot wrote to the file")
	}
}

// writeBak puts a .bak beside path, built from its own specs and its own data key, so a test can
// say exactly which generation the copy belongs to.
func writeBak(t *testing.T, path string, dek []byte, specs []v2Spec, ids ...string) {
	t.Helper()
	data := buildV2(t, magic, dek, specs, accountsPayload(t, ids...))
	if err := os.WriteFile(path+bakSuffix, data, 0o600); err != nil {
		t.Fatalf("write bak: %v", err)
	}
}

// A .bak of the generation being replaced is re-sealed under the new one, not deleted: the "regret
// recovery" the copy exists for is kept, and the removed key loses its way into it.
func TestRemoveSlotResealsTheBakItCanOpen(t *testing.T) {
	buf := captureLog(t)
	dir := t.TempDir()
	specs := []v2Spec{passSpec("slot0001", addSlotPass), kekSpec("slot0002", addSlotKEK())}
	path := v2VaultAt(t, dir, specs, "a1")
	writeBak(t, path, []byte(fileDEK), specs, "a1", "a2")
	v := openV2(t, path, addSlotPass)
	result, err := v.RemoveSlot(b64([]byte("slot0002")), &recordingKeySource{pass: addSlotPass})
	if err != nil {
		t.Fatalf("RemoveSlot: %v", err)
	}
	if !strings.Contains(result, "bak re-sealed") {
		t.Fatalf("bak result = %q, want it to name a re-seal", result)
	}
	// The copy is still a copy: it opens with the surviving passphrase and still holds two accounts.
	bak, err := Open(path+bakSuffix, &recordingKeySource{pass: addSlotPass})
	if err != nil {
		t.Fatalf("open the re-sealed bak: %v", err)
	}
	if len(bak.List()) != 2 {
		t.Fatalf("the re-sealed bak holds %d accounts, want 2", len(bak.List()))
	}
	// And the removed key no longer opens it, which is the hole this closes.
	if _, err := Open(path+bakSuffix, kekSource(t, addSlotKEK(), "", ErrNoKey)); err == nil {
		t.Fatalf("the removed key still opens the .bak")
	}
	assertLogLine(t, buf, map[string]string{"op": "bak", "result": "resealed"})
}

// assertLogLine fails unless one captured line carries every key and value given.
func assertLogLine(t *testing.T, buf *bytes.Buffer, want map[string]string) {
	t.Helper()
	for _, line := range logLines(t, buf) {
		ok := true
		for k, v := range want {
			if got, _ := line[k].(string); got != v {
				ok = false
				break
			}
		}
		if ok {
			return
		}
	}
	t.Fatalf("no log line carries %v; lines: %s", want, buf.String())
}

// A .bak no surviving key can open is deleted. The command says so, because its name does not.
func TestRemoveSlotDeletesABakItCannotOpen(t *testing.T) {
	buf := captureLog(t)
	dir := t.TempDir()
	path := v2VaultAt(t, dir,
		[]v2Spec{passSpec("slot0001", addSlotPass), kekSpec("slot0002", addSlotKEK())}, "a1")
	// A .bak of its own generation, sealed under a passphrase nothing in this run holds.
	writeBak(t, path, bytes.Repeat([]byte{0x5a}, keyLen), []v2Spec{passSpec("slot0009", "a-lost-passphrase")}, "a1")
	v := openV2(t, path, addSlotPass)
	result, err := v.RemoveSlot(b64([]byte("slot0002")), &recordingKeySource{pass: addSlotPass})
	if err != nil {
		t.Fatalf("RemoveSlot: %v", err)
	}
	if !strings.Contains(result, "bak removed") {
		t.Fatalf("bak result = %q, want it to name a removal", result)
	}
	if _, err := os.Stat(path + bakSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the unopenable .bak is still there: %v", err)
	}
	assertLogLine(t, buf, map[string]string{"op": "bak", "result": "removed"})
}

// Review Focus 4. A .bak of an EARLIER generation that a surviving slot still opens must be
// re-sealed, not deleted; only bytes nothing can open or nothing can parse are deleted, and the
// printed line says which of the two happened.
func TestRemoveSlotDistinguishesAnOlderGenerationBakFromADamagedOne(t *testing.T) {
	older := func(t *testing.T) (string, string) {
		t.Helper()
		dir := t.TempDir()
		path := v2VaultAt(t, dir,
			[]v2Spec{passSpec("slot0001", addSlotPass), kekSpec("slot0002", addSlotKEK())}, "a1")
		// A different data key - an earlier generation - but the same passphrase, which survives.
		writeBak(t, path, bytes.Repeat([]byte{0x33}, keyLen), []v2Spec{passSpec("slot0001", addSlotPass)}, "a1", "a2")
		v := openV2(t, path, addSlotPass)
		result, err := v.RemoveSlot(b64([]byte("slot0002")), &recordingKeySource{pass: addSlotPass})
		if err != nil {
			t.Fatalf("RemoveSlot: %v", err)
		}
		return path, result
	}
	path, result := older(t)
	if !strings.Contains(result, "bak re-sealed") {
		t.Fatalf("an older-generation .bak a surviving slot opens: result = %q, want a re-seal", result)
	}
	if _, err := os.Stat(path + bakSuffix); err != nil {
		t.Fatalf("the older-generation .bak was deleted: %v", err)
	}

	// Damaged bytes: the header will not parse at all.
	dir := t.TempDir()
	path = v2VaultAt(t, dir,
		[]v2Spec{passSpec("slot0001", addSlotPass), kekSpec("slot0002", addSlotKEK())}, "a1")
	if err := os.WriteFile(path+bakSuffix, []byte("CSV2\x00\x00\x00\x09not json!!!!!!!!!!!!!!!!!!!!"), 0o600); err != nil {
		t.Fatalf("write damaged bak: %v", err)
	}
	v := openV2(t, path, addSlotPass)
	result, err := v.RemoveSlot(b64([]byte("slot0002")), &recordingKeySource{pass: addSlotPass})
	if err != nil {
		t.Fatalf("RemoveSlot: %v", err)
	}
	if !strings.Contains(result, "bak removed") || !strings.Contains(result, "will not parse") {
		t.Fatalf("a damaged .bak: result = %q, want a removal naming the corruption", result)
	}
	if _, err := os.Stat(path + bakSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the damaged .bak is still there: %v", err)
	}
}

// A v1 .bak is a pre-migration artefact, not a copy of this generation. It is left exactly where it
// is - deleting it would take the v1 rollback with it - and the result names the command that owns
// v1 artefacts.
func TestRemoveSlotLeavesAV1BakAlone(t *testing.T) {
	dir := t.TempDir()
	path := v2VaultAt(t, dir,
		[]v2Spec{passSpec("slot0001", addSlotPass), kekSpec("slot0002", addSlotKEK())}, "a1")
	v1 := bytesOf(t, writeV1Vault(t, addSlotPass))
	if err := os.WriteFile(path+bakSuffix, v1, 0o600); err != nil {
		t.Fatalf("write v1 bak: %v", err)
	}
	v := openV2(t, path, addSlotPass)
	result, err := v.RemoveSlot(b64([]byte("slot0002")), &recordingKeySource{pass: addSlotPass})
	if err != nil {
		t.Fatalf("RemoveSlot: %v", err)
	}
	if !strings.Contains(result, "finalize-migration") {
		t.Fatalf("a v1 .bak: result = %q, want it to name finalize-migration", result)
	}
	if !bytes.Equal(v1, bytesOf(t, path+bakSuffix)) {
		t.Fatalf("the v1 .bak was rewritten")
	}
}

// --- rotate ---

func TestRotateChangesEverySlotsWrap(t *testing.T) {
	dir := t.TempDir()
	specs := []v2Spec{passSpec("slot0001", addSlotPass), kekSpec("slot0002", addSlotKEK())}
	path := v2VaultAt(t, dir, specs, "a1")
	_, before := headerOf(t, path)
	v := openV2(t, path, addSlotPass)
	ks := &recordingKeySource{pass: addSlotPass, openers: []SlotOpener{kekFileOpenerFor(t, addSlotKEK())}}
	if err := v.Rotate(ks); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	_, after := headerOf(t, path)
	if len(after) != len(before) {
		t.Fatalf("rotate changed the slot count: %d to %d", len(before), len(after))
	}
	for i := range before {
		if before[i].ID != after[i].ID {
			t.Fatalf("rotate renamed slot %d: %q to %q", i, before[i].ID, after[i].ID)
		}
		if before[i].Wrap.Nonce == after[i].Wrap.Nonce || before[i].Wrap.CT == after[i].Wrap.CT {
			t.Fatalf("slot %s kept its wrap through a rotation", after[i].ID)
		}
	}
	// Every slot still opens the file afterwards.
	if _, err := Open(path, &recordingKeySource{pass: addSlotPass}); err != nil {
		t.Fatalf("the passphrase slot no longer opens the vault: %v", err)
	}
	if _, err := Open(path, kekSource(t, addSlotKEK(), "", ErrNoKey)); err != nil {
		t.Fatalf("the kek-file slot no longer opens the vault: %v", err)
	}
}

// kekFileOpenerFor is a kek-file opener over a temp key file holding kek: the machine half of an
// operator's key source, with no credstore and no root route in sight.
func kekFileOpenerFor(t *testing.T, kek []byte) SlotOpener {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kek")
	if err := os.WriteFile(p, kek, 0o600); err != nil {
		t.Fatalf("write kek file: %v", err)
	}
	t.Setenv(credentialsDirEnv, "")
	t.Setenv(kekFileEnv, "")
	op := kekFileOpener(HostKeyOptions{KEKFile: p})
	if op == nil {
		t.Fatalf("kekFileOpener returned nil")
	}
	return op
}

// A rotation must re-wrap EVERY slot, and a slot of a type this binary does not know cannot be
// re-wrapped by anything here. It refuses, names the slot, and writes nothing.
func TestRotateRefusesWhileAnUnknownSlotIsPresent(t *testing.T) {
	dir := t.TempDir()
	path := v2VaultAt(t, dir, []v2Spec{
		passSpec("slot0001", addSlotPass),
		{raw: `{"id":"` + b64([]byte("slot0003")) + `","type":"cng","created":"` + fileCreated + `","wrap":{"blob":"AAEC"}}`},
	}, "a1")
	v := openV2(t, path, addSlotPass)
	before := bytesOf(t, path)
	err := v.Rotate(&recordingKeySource{pass: addSlotPass})
	if !errors.Is(err, ErrUnknownSlotPresent) {
		t.Fatalf("Rotate with an unknown slot = %v, want ErrUnknownSlotPresent", err)
	}
	if !strings.Contains(err.Error(), b64([]byte("slot0003"))) || !strings.Contains(err.Error(), "cng") {
		t.Fatalf("the refusal names neither the slot nor its type: %v", err)
	}
	if !bytes.Equal(before, bytesOf(t, path)) {
		t.Fatalf("a refused rotate wrote to the file")
	}
}

func TestRemoveSlotOfAnotherSlotRefusesWhileAnUnknownSlotIsPresent(t *testing.T) {
	dir := t.TempDir()
	path := v2VaultAt(t, dir, []v2Spec{
		passSpec("slot0001", addSlotPass),
		kekSpec("slot0002", addSlotKEK()),
		{raw: `{"id":"` + b64([]byte("slot0003")) + `","type":"cng","created":"` + fileCreated + `","wrap":{"blob":"AAEC"}}`},
	}, "a1")
	v := openV2(t, path, addSlotPass)
	before := bytesOf(t, path)
	if _, err := v.RemoveSlot(b64([]byte("slot0002")), &recordingKeySource{pass: addSlotPass}); !errors.Is(err, ErrUnknownSlotPresent) {
		t.Fatalf("RemoveSlot beside an unknown slot = %v, want ErrUnknownSlotPresent", err)
	}
	if !bytes.Equal(before, bytesOf(t, path)) {
		t.Fatalf("a refused remove-slot wrote to the file")
	}
}

// Removing the unknown slot ITSELF is the way out of the refusal above: after it is gone every
// remaining slot is one this binary can re-wrap.
func TestRemoveSlotOfTheUnknownSlotItselfSucceeds(t *testing.T) {
	dir := t.TempDir()
	path := v2VaultAt(t, dir, []v2Spec{
		passSpec("slot0001", addSlotPass),
		{raw: `{"id":"` + b64([]byte("slot0003")) + `","type":"cng","created":"` + fileCreated + `","wrap":{"blob":"AAEC"}}`},
	}, "a1")
	v := openV2(t, path, addSlotPass)
	if _, err := v.RemoveSlot(b64([]byte("slot0003")), &recordingKeySource{pass: addSlotPass}); err != nil {
		t.Fatalf("RemoveSlot of the unknown slot: %v", err)
	}
	_, slots := headerOf(t, path)
	if len(slots) != 1 || slots[0].Type != slotTypePassphrase {
		t.Fatalf("slots after removing the unknown one: %v", slots)
	}
	if _, err := Open(path, &recordingKeySource{pass: addSlotPass}); err != nil {
		t.Fatalf("the passphrase slot no longer opens the vault: %v", err)
	}
}

// A kek-file slot whose key this process cannot reach cannot be re-wrapped, so the rotation is
// refused by slot id - and there is deliberately no flag that drops it instead. Dropping a slot is
// remove-slot, by that name.
func TestRotateRefusesWhenASlotKEKIsUnreachable(t *testing.T) {
	dir := t.TempDir()
	path := v2VaultAt(t, dir,
		[]v2Spec{passSpec("slot0001", addSlotPass), kekSpec("slot0002", addSlotKEK())}, "a1")
	v := openV2(t, path, addSlotPass)
	before := bytesOf(t, path)
	// A key source with the passphrase and no machine opener at all: the kek-file slot is present in
	// the header and out of reach.
	err := v.Rotate(&recordingKeySource{pass: addSlotPass})
	if !errors.Is(err, ErrKEKUnreachable) {
		t.Fatalf("Rotate with an unreachable slot = %v, want ErrKEKUnreachable", err)
	}
	if !strings.Contains(err.Error(), b64([]byte("slot0002"))) {
		t.Fatalf("the refusal does not name the slot id: %v", err)
	}
	if !bytes.Equal(before, bytesOf(t, path)) {
		t.Fatalf("a refused rotate wrote to the file")
	}
}

// --- change-passphrase ---

// The passphrase changes; the data key does not. Everything sealed under the DEK - including a
// payload nobody is re-encrypting - stays put, and the old passphrase stops working.
func TestChangePassphraseKeepsTheSameDEK(t *testing.T) {
	dir := t.TempDir()
	path := v2VaultAt(t, dir, []v2Spec{passSpec("slot0001", addSlotPass)}, "a1")
	before, beforeSlots := headerOf(t, path)
	v := openV2(t, path, addSlotPass)
	if err := v.ChangePassphrase(addSlotPass, "the-next-passphrase"); err != nil {
		t.Fatalf("ChangePassphrase: %v", err)
	}
	after, afterSlots := headerOf(t, path)
	if after.DEK.ID != before.DEK.ID {
		t.Fatalf("change-passphrase rotated the dek: %q to %q", before.DEK.ID, after.DEK.ID)
	}
	if afterSlots[0].Argon2id.Salt == beforeSlots[0].Argon2id.Salt {
		t.Fatalf("change-passphrase reused the argon2id salt")
	}
	if _, err := Open(path, &recordingKeySource{pass: "the-next-passphrase"}); err != nil {
		t.Fatalf("the new passphrase does not open the vault: %v", err)
	}
	if _, err := Open(path, &recordingKeySource{pass: addSlotPass}); err == nil {
		t.Fatalf("the old passphrase still opens the vault")
	}
}

// A passphrase is text an operator types, and text is unicode. The round trip must not depend on
// the alphabet.
func TestChangePassphraseAcceptsAUnicodePassphrase(t *testing.T) {
	const next = "pässwörd-日本語-🔑"
	dir := t.TempDir()
	path := v2VaultAt(t, dir, []v2Spec{passSpec("slot0001", addSlotPass)}, "a1")
	v := openV2(t, path, addSlotPass)
	if err := v.ChangePassphrase(addSlotPass, next); err != nil {
		t.Fatalf("ChangePassphrase: %v", err)
	}
	if _, err := Open(path, &recordingKeySource{pass: next}); err != nil {
		t.Fatalf("the unicode passphrase does not open the vault: %v", err)
	}
}

func TestChangePassphraseRefusesTheWrongOldPassphrase(t *testing.T) {
	dir := t.TempDir()
	path := v2VaultAt(t, dir, []v2Spec{passSpec("slot0001", addSlotPass)}, "a1")
	v := openV2(t, path, addSlotPass)
	before := bytesOf(t, path)
	if err := v.ChangePassphrase("not-the-passphrase", "next"); !errors.Is(err, ErrBadKey) {
		t.Fatalf("ChangePassphrase with the wrong old passphrase = %v, want ErrBadKey", err)
	}
	if !bytes.Equal(before, bytesOf(t, path)) {
		t.Fatalf("a refused change-passphrase wrote to the file")
	}
}

// A file with no passphrase slot has nothing to change, and the answer is the same one the writer
// gives for a file that would have none: a vault whose only key is one host's is not recoverable.
func TestChangePassphraseRefusesIfItWouldLeaveZeroPassphraseSlots(t *testing.T) {
	dir := t.TempDir()
	path := v2VaultAt(t, dir, []v2Spec{kekSpec("slot0002", addSlotKEK())}, "a1")
	v, err := Open(path, kekSource(t, addSlotKEK(), "", ErrNoKey))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	before := bytesOf(t, path)
	if err := v.ChangePassphrase(addSlotPass, "next"); !errors.Is(err, ErrNoRecoverySlot) {
		t.Fatalf("ChangePassphrase on a file with no passphrase slot = %v, want ErrNoRecoverySlot", err)
	}
	if !bytes.Equal(before, bytesOf(t, path)) {
		t.Fatalf("a refused change-passphrase wrote to the file")
	}
}

// Documented behaviour, not a bug: a v1 copy left in the data dir is a passphrase-only envelope of
// its own, so the OLD passphrase still opens it after change-passphrase. `status` warns while both
// exist and `finalize-migration` is what ends it.
func TestAV1CopyStillOpensWithTheOldPassphrase(t *testing.T) {
	dir := t.TempDir()
	path := v2VaultAt(t, dir, []v2Spec{passSpec("slot0001", addSlotPass)}, "a1")
	v1 := bytesOf(t, writeV1Vault(t, addSlotPass))
	copyPath := path + ".v1.20261108T120000Z"
	if err := os.WriteFile(copyPath, v1, 0o600); err != nil {
		t.Fatalf("write v1 copy: %v", err)
	}
	v := openV2(t, path, addSlotPass)
	if err := v.ChangePassphrase(addSlotPass, "the-next-passphrase"); err != nil {
		t.Fatalf("ChangePassphrase: %v", err)
	}
	if _, err := Open(copyPath, &recordingKeySource{pass: addSlotPass}); err != nil {
		t.Fatalf("the v1 copy no longer opens with the old passphrase: %v", err)
	}
}

// A known slot that was tried and failed says so, by id. The only other record is the single "no
// slot could unwrap" at the end of the walk, which names kinds and not slots - so without this a
// vault opening on its last good slot is indistinguishable from one opening on its first.
func TestATriedSlotThatFailedIsLogged(t *testing.T) {
	buf := captureLog(t)
	dir := t.TempDir()
	// Two passphrase slots under different passphrases: opening with the second one's passphrase
	// tries the first, fails, and goes on.
	path := filepath.Join(dir, vaultFileName)
	data := buildV2(t, magic, []byte(fileDEK), []v2Spec{
		passSpec("slot0001", "the-other-operators-passphrase"),
		passSpec("slot0002", addSlotPass),
	}, accountsPayload(t, "a1"))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Open(path, &recordingKeySource{pass: addSlotPass}); err != nil {
		t.Fatalf("Open: %v", err)
	}
	assertLogLine(t, buf, map[string]string{
		"slot": b64([]byte("slot0001")), "slottype": slotTypePassphrase, "result": "failed"})
	if strings.Contains(buf.String(), addSlotPass) {
		t.Fatalf("the log carries a passphrase: %s", buf.String())
	}
}

// --- Inspect and VerifyFile: the read-only halves `status` and `verify` are built on ---

// Inspect answers from the header alone: no key, no passphrase, no payload. That is what makes it
// safe for `status`, which runs while the service holds the lock.
func TestInspectNamesSlotsWithoutAnyKey(t *testing.T) {
	dir := t.TempDir()
	path := v2VaultAt(t, dir,
		[]v2Spec{passSpec("slot0001", addSlotPass), kekSpec("slot0002", addSlotKEK())}, "a1")
	info, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if info.Format != "v2" || len(info.Slots) != 2 {
		t.Fatalf("Inspect = %+v", info)
	}
	if info.Slots[0].Type != slotTypePassphrase || info.Slots[1].Type != slotTypeKEKFile {
		t.Fatalf("slot types: %+v", info.Slots)
	}
	// Nothing in the answer is a wrap, a blob or a passphrase.
	b, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	_, slots := headerOf(t, path)
	for _, s := range slots {
		for _, secret := range []string{s.Wrap.CT, s.Wrap.Nonce, s.Wrap.Blob} {
			if secret != "" && bytes.Contains(b, []byte(secret)) {
				t.Fatalf("Inspect carries a wrap: %s", b)
			}
		}
	}
	if bytes.Contains(b, []byte(addSlotPass)) {
		t.Fatalf("Inspect carries the passphrase: %s", b)
	}
}

func TestInspectNamesTheFormatOfAnAbsentAndAV1File(t *testing.T) {
	dir := t.TempDir()
	absent, err := Inspect(filepath.Join(dir, vaultFileName))
	if err != nil {
		t.Fatalf("Inspect of an absent file: %v", err)
	}
	if absent.Format != FormatAbsent {
		t.Fatalf("absent file format = %q", absent.Format)
	}
	v1, err := Inspect(writeV1Vault(t, addSlotPass))
	if err != nil {
		t.Fatalf("Inspect of a v1 file: %v", err)
	}
	if v1.Format != "v1" || len(v1.Slots) != 0 {
		t.Fatalf("v1 file = %+v", v1)
	}
}

// Verify reports WHICH slot opened the file, which is the fact recoverDEK throws away and the one
// an operator checking a restore needs.
func TestVerifyFileReportsWhichSlotOpenedIt(t *testing.T) {
	dir := t.TempDir()
	path := v2VaultAt(t, dir,
		[]v2Spec{passSpec("slot0001", addSlotPass), kekSpec("slot0002", addSlotKEK())}, "a1")
	res, err := VerifyFile(path, kekSource(t, addSlotKEK(), "", ErrNoKey), false)
	if err != nil {
		t.Fatalf("VerifyFile: %v", err)
	}
	if !res.PayloadOK {
		t.Fatalf("payload did not open: %+v", res)
	}
	opened := 0
	for _, r := range res.Tried {
		if r.Opened {
			opened++
			if r.ID != b64([]byte("slot0002")) {
				t.Fatalf("the wrong slot is reported as opening the file: %+v", r)
			}
		}
	}
	if opened != 1 {
		t.Fatalf("%d slots reported as opening the file, want 1: %+v", opened, res.Tried)
	}
}

// --all-slots opens with every slot in turn, so one that has quietly stopped working is found
// before the day the others are gone.
func TestVerifyFileAllSlotsOpensEachInTurn(t *testing.T) {
	dir := t.TempDir()
	path := v2VaultAt(t, dir,
		[]v2Spec{passSpec("slot0001", addSlotPass), kekSpec("slot0002", addSlotKEK())}, "a1")
	ks := &recordingKeySource{pass: addSlotPass, openers: []SlotOpener{kekFileOpenerFor(t, addSlotKEK())}}
	res, err := VerifyFile(path, ks, true)
	if err != nil {
		t.Fatalf("VerifyFile: %v", err)
	}
	if len(res.Tried) != 2 {
		t.Fatalf("tried %d slots, want 2: %+v", len(res.Tried), res.Tried)
	}
	for _, r := range res.Tried {
		if !r.Opened {
			t.Fatalf("slot %s did not open: %+v", r.ID, r)
		}
	}
}

// Nothing opens: not an error value this package invents, but the one the open flow already gives,
// so the CLI's exit code and the service's are the same number for the same state.
func TestVerifyFileReportsAFileNoSlotOpens(t *testing.T) {
	dir := t.TempDir()
	path := v2VaultAt(t, dir, []v2Spec{passSpec("slot0001", addSlotPass)}, "a1")
	res, err := VerifyFile(path, &recordingKeySource{pass: "the-wrong-one"}, true)
	if err == nil || !errors.Is(err, ErrBadKey) {
		t.Fatalf("VerifyFile with no working key = %v, want ErrBadKey", err)
	}
	if res.PayloadOK {
		t.Fatalf("payload reported as open: %+v", res)
	}
}

// The payload is decrypted and never printed: the result carries counts, not content.
func TestVerifyFileNeverCarriesThePayload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, vaultFileName)
	payload := []byte(`[{"id":"a1","label":"a-very-secret-label","identity":"nobody@example.com","block":{"accessToken":"tok-do-not-print"},"updated":"2026-11-07T12:00:00Z"}]`)
	data := buildV2(t, magic, []byte(fileDEK), []v2Spec{passSpec("slot0001", addSlotPass)}, payload)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	res, err := VerifyFile(path, &recordingKeySource{pass: addSlotPass}, true)
	if err != nil {
		t.Fatalf("VerifyFile: %v", err)
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, secret := range []string{"a-very-secret-label", "nobody@example.com", "tok-do-not-print"} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatalf("the verify result carries %q: %s", secret, b)
		}
	}
	if res.Entries != 1 {
		t.Fatalf("entries = %d, want 1", res.Entries)
	}
}
