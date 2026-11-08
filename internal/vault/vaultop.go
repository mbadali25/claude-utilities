package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// This file holds the vault operation journal: the one record that says a slot operation was in
// flight, which files it spans, and how far it got. It is shaped like the agent's swap journal
// (internal/agent/journal.go) deliberately - write it before the first change, settle it on the
// next start, clear it when the operation is done - because that shape is already understood here
// and already has a runbook.
//
// What it closes. `rotate` and `remove-slot` touch two files, vault.bin and tunnelkeys.bin, and
// each of them has a .bak that opens under the slots of its time. Without a journal a crash
// between the two files leaves a pair nothing can explain: a v2 vault beside a v1 keyring, or a new
// vault beside a .bak the key just removed can still open. The four stages make that state
// readable, and the settle makes it finishable.
//
// Ordering, and the window it trades for. The operation (i) writes this journal, fsynced before
// anything else; (ii) re-seals or deletes each .bak, before the new generation is visible; (iii)
// renames the new file into place; (iv) removes the journal. A crash after (ii) and before (iii)
// leaves the old file - the state before the command ran - and no .bak, which is harmless. The
// window it replaces was not: a new vault visible beside a .bak openable by the removed key.
//
// Settle-or-refuse, before any mutation. Every 3b mutator calls SettleVaultOp on the journal it
// finds before it changes anything, and refuses the command if the settle cannot complete or
// revert. This is the spec's rule ("every vault mutator ... re-runs the re-seal-or-delete step and
// completes or reverts, then clears it"), stated here because the mutators themselves are Task
// 3b.2 and this is the file they will read. `server run` does not settle: it refuses to start,
// exit 3, non-restarting, naming `server vault verify --all-slots`, because a service must not
// perform a repair nobody asked for. `vault status` reports the journal and changes nothing.
//
// It carries no key material. NewDEKID is the base64 dek.id, which is the HKDF salt and part of
// every slot's AAD: public by construction. No DEK, no wrap, no blob, no passphrase is ever
// written here.

const (
	// VaultOpFileName is the journal's name inside the data dir.
	VaultOpFileName = "vaultop.journal"

	// vaultFileName is the account vault's file name. cmd/server still joins the literal; the
	// `vault` dispatch (Task 3b.1) adopts this constant.
	vaultFileName = "vault.bin"

	// StageStarted is (i): the journal is on disk and nothing else has changed.
	StageStarted = "started"
	// StageBak is (ii): every .bak has been re-sealed or deleted, and the new generation is not
	// yet visible.
	StageBak = "bak"
	// StageRenamed is (iii): the new generation is in place and only the journal is left.
	StageRenamed = "renamed"

	// The actions settle can take on one .bak, as the command prints them.
	bakResealed = "bak re-sealed"
	bakRemoved  = "bak removed"
	bakAbsent   = "no bak"

	// maxVaultOpField bounds the two free-text fields, so a crafted journal cannot put a screenful
	// into an operator's terminal.
	maxVaultOpField = 32
	// maxVaultOpFiles bounds the file list. An operation spans the vault and the keyring; four
	// leaves room without letting a journal name a directory's worth of deletions.
	maxVaultOpFiles = 4

	// maxVaultOpBytes bounds the journal read. The file lives in the data dir, so anyone who can
	// write there can make it as large as the disk allows, and ReadVaultOp runs before every
	// mutator and on every `server run` - an unbounded read is an unbounded allocation driven by
	// whoever got there first. A real journal is a couple of hundred bytes; 64 KiB is room for a
	// file list this package will never write and still a bound.
	maxVaultOpBytes = 64 << 10
)

// ErrVaultOpUnreadable marks a journal that is present but is not one this binary wrote: torn by a
// crash mid-write, or written by someone else. It is never repaired silently and never acted on -
// a journal says which files to delete a .bak from, so believing a crafted one is how a data dir
// loses files it should not.
var ErrVaultOpUnreadable = errors.New("vault: the vaultop journal is unreadable; run `server vault verify --all-slots`")

// ErrVaultOpMixedPair marks a settle that found the files the operation spans disagreeing about
// their format version. The journal carries one Stage for up to maxVaultOpFiles files, so it cannot
// say that the rename of the first landed and the rename of the second did not; the pair on disk
// can. When it does, neither branch of the settle is safe - "completed" would delete a .bak that is
// the only copy of the half that never landed, and "reverted" would clear the journal and call the
// data dir settled - so the settle refuses and leaves everything where it is, which is the state
// the spec hands to `server vault verify --all-slots` for a human to look at.
var ErrVaultOpMixedPair = errors.New("vault: the files this operation spans disagree about their format version")

// resealBak re-seals one file's .bak under the current generation, or deletes it when it cannot be
// opened. It is a seam: the re-seal needs the slot openers and the v2 write path, which are Task
// 3b.2, and until then the only honest action is the one the spec names for a .bak the command
// cannot open - delete it, and say so. Nothing in this binary writes a journal yet, so no real
// data dir reaches this.
var resealBak = removeBakOnly

// removeBakOnly is the default resealBak: delete the .bak beside path, or report that there was
// none. A .bak left behind after a slot removal is openable by the key that was removed, which is
// the hole the ordering closes; a lost recovery copy is the lesser harm, and the caller prints it.
func removeBakOnly(path string, _ VaultOp, _ KeySource) (string, error) {
	bak := path + bakSuffix
	err := os.Remove(bak)
	if errors.Is(err, os.ErrNotExist) {
		return bakAbsent, nil
	}
	if err != nil {
		return "", fmt.Errorf("vault: remove %s: %w", bak, err)
	}
	return bakRemoved, nil
}

// A VaultOp is one in-flight slot operation. Op is the command's name, Files the data-dir file
// names it spans (base names only, never a path), NewDEKID the base64 dek.id of the generation it
// is writing, and Stage how far it got.
type VaultOp struct {
	Op       string   `json:"op"`
	Files    []string `json:"files"`
	NewDEKID string   `json:"newDekId"`
	Stage    string   `json:"stage"`
}

// VaultOpPath is the journal's path for a data dir.
func VaultOpPath(dataDir string) string { return filepath.Join(dataDir, VaultOpFileName) }

// WriteVaultOp writes the journal, replacing any previous one, owner-only and fsynced before the
// rename makes it visible. It is step (i) of every operation that spans more than one write: the
// caller must have taken the data-dir lock first, and must not have changed anything yet.
func WriteVaultOp(dataDir string, op VaultOp) error {
	if err := op.validate(); err != nil {
		return err
	}
	data, err := json.Marshal(op)
	if err != nil {
		return fmt.Errorf("vault: marshal journal: %w", err)
	}
	return replaceFile(VaultOpPath(dataDir), data)
}

// ReadVaultOp reads the journal. ok is false with a nil error when there is none, which is the
// normal case; a journal that is present but not readable as one of ours is ErrVaultOpUnreadable,
// never a zero VaultOp a caller might act on.
func ReadVaultOp(dataDir string) (VaultOp, bool, error) {
	f, err := os.Open(filepath.Clean(VaultOpPath(dataDir)))
	if errors.Is(err, os.ErrNotExist) {
		return VaultOp{}, false, nil
	}
	if err != nil {
		return VaultOp{}, false, fmt.Errorf("vault: read journal: %w", err)
	}
	defer func() { _ = f.Close() }()
	// One byte past the bound, so a file at the bound is still told apart from one over it. A
	// LimitReader set to the bound itself would hand Unmarshal a truncated object and report a
	// parse error for a file whose only problem is its size, which sends an operator looking for
	// the wrong thing.
	data, err := io.ReadAll(io.LimitReader(f, maxVaultOpBytes+1))
	if err != nil {
		return VaultOp{}, false, fmt.Errorf("vault: read journal: %w", err)
	}
	if len(data) > maxVaultOpBytes {
		return VaultOp{}, false, fmt.Errorf("%w: it is over %d bytes", ErrVaultOpUnreadable, maxVaultOpBytes)
	}
	var op VaultOp
	if err := json.Unmarshal(data, &op); err != nil {
		return VaultOp{}, false, ErrVaultOpUnreadable
	}
	if err := op.validate(); err != nil {
		return VaultOp{}, false, ErrVaultOpUnreadable
	}
	return op, true, nil
}

// ClearVaultOp removes the journal. A journal that is already gone is not an error: that is how
// settle-on-start ends on a data dir nobody interrupted.
func ClearVaultOp(dataDir string) error {
	err := os.Remove(VaultOpPath(dataDir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("vault: clear journal: %w", err)
	}
	return nil
}

// SettleVaultOp finishes or undoes an interrupted operation and clears the journal. The result is
// what the command prints: "completed: <bak action per file>" when the new generation was already
// visible and only the .bak step and the journal were left, "reverted" when it was not, because
// then the file on disk is the one the command started with.
//
// ks is for the re-seal, which needs a key to open the .bak with; it is handed to resealBak.
//
// An error leaves the journal exactly where it was. A settle that half-finished and then reported
// success would be worse than one that reported nothing: the next mutator would mutate on top of
// it. The caller refuses the command and names `server vault verify --all-slots`.
func SettleVaultOp(dataDir string, op VaultOp, ks KeySource) (string, error) {
	if err := op.validate(); err != nil {
		return "", err
	}
	// Before either branch, because neither is safe on a mixed pair and the journal cannot tell
	// them apart: one Stage describes up to maxVaultOpFiles files, so a crash between the rename of
	// file 1 and the rename of file 2 reads as whichever stage was written last. At StageRenamed
	// the "completed" branch would delete the .bak of the half that never landed, which is the only
	// copy of it; at StageStarted or StageBak the "reverted" branch would clear the journal and
	// report the data dir settled. Refuse, leave everything alone, and name the verify the spec
	// hands a mixed pair to.
	if line, mixed := MixedPair(dataDir); mixed {
		return "", fmt.Errorf("%w: %s", ErrVaultOpMixedPair, line)
	}
	if op.Stage != StageRenamed {
		// (i) or (ii): the new generation never became visible, so the old file is intact and
		// there is nothing to finish. Any .bak was already dealt with at (ii), which is the
		// harmless half of the window the ordering trades for.
		if err := ClearVaultOp(dataDir); err != nil {
			return "", err
		}
		return "reverted", nil
	}
	actions := make([]string, 0, len(op.Files))
	for _, name := range op.Files {
		action, err := resealBak(filepath.Join(dataDir, name), op, ks)
		if err != nil {
			return "", err
		}
		actions = append(actions, name+": "+action)
	}
	if err := ClearVaultOp(dataDir); err != nil {
		return "", err
	}
	return "completed: " + strings.Join(actions, ", "), nil
}

// validate holds a journal to the shape this package wrote, on the way out and on the way back in.
// The file is in the data dir, so anyone who can write there can write it, and settle deletes a
// .bak from what it says: a name with a separator or a ".." in it would make that a deletion
// outside the data dir, and an unprintable Op or Stage would make it a forged line of output.
func (op VaultOp) validate() error {
	if !printableField(op.Op) {
		return fmt.Errorf("%w: op", ErrVaultOpUnreadable)
	}
	switch op.Stage {
	case StageStarted, StageBak, StageRenamed:
	default:
		return fmt.Errorf("%w: stage", ErrVaultOpUnreadable)
	}
	if len(op.Files) == 0 || len(op.Files) > maxVaultOpFiles {
		return fmt.Errorf("%w: files", ErrVaultOpUnreadable)
	}
	for _, name := range op.Files {
		if !plainFileName(name) {
			return fmt.Errorf("%w: file name", ErrVaultOpUnreadable)
		}
	}
	if op.NewDEKID != "" {
		if err := decodeExactly(op.NewDEKID, dekIDLen); err != nil {
			return fmt.Errorf("%w: newDekId", ErrVaultOpUnreadable)
		}
	}
	return nil
}

// printableField reports whether a free-text journal field may be read and printed: 1 to
// maxVaultOpField bytes of printable ASCII.
func printableField(s string) bool {
	if len(s) == 0 || len(s) > maxVaultOpField {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// plainFileName reports whether name is a file in the data dir and nothing else: a printable base
// name, with no separator, no volume and not "." or "..".
func plainFileName(name string) bool {
	if !printableField(name) || name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, `/\:`) {
		return false
	}
	return filepath.Base(name) == name
}

// MixedPair reports whether vault.bin and tunnelkeys.bin disagree about their format version, with
// the line `vault status` prints when they do. It is the state a crash across the two files can
// leave, and with no journal to explain it nothing here repairs it: a human runs the verify the
// line names, because the two files hold different things and guessing which one is authoritative
// is how an account list or a host's tunnel key is lost.
//
// False when either file is absent (a fresh install has neither, and only the keyring exists on
// some older hosts) and when a magic is not one this binary knows - a damaged file is the opener's
// error to report, with the message it already has.
func MixedPair(dataDir string) (string, bool) {
	vaultVer, ok := formatVersion(filepath.Join(dataDir, vaultFileName), magic, v2VaultMagic)
	if !ok {
		return "", false
	}
	ringVer, ok := formatVersion(filepath.Join(dataDir, KeyringFileName), keyringMagic, v2KeyringMagic)
	if !ok || vaultVer == ringVer {
		return "", false
	}
	return fmt.Sprintf("%s is %s but %s is %s: run `server vault verify --all-slots`",
		vaultFileName, vaultVer, KeyringFileName, ringVer), true
}

// formatVersion reads a file's magic and names its format version. ok is false for a file that is
// absent, empty, too short or carrying a magic this binary does not know.
func formatVersion(path, v1Magic, v2Magic string) (string, bool) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()
	// io.ReadFull, not f.Read: a single Read may return fewer bytes than the buffer holds without
	// an error, and a magic compared against a partly filled buffer is a format decision made on
	// bytes that were never read. Here the buffer is exactly the magic's length, so
	// io.ErrUnexpectedEOF means "shorter than a magic" and is one of the cases this reports as not
	// a format it knows.
	buf := make([]byte, len(v1Magic))
	if _, err := io.ReadFull(f, buf); err != nil {
		return "", false
	}
	switch string(buf) {
	case v1Magic:
		return "v1", true
	case v2Magic:
		return "v2", true
	}
	return "", false
}
