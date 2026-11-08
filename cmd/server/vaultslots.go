package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"claude-utilities/internal/logx"
	"claude-utilities/internal/vault"
)

// This file holds the four slot mutators as an operator reaches them: add-slot, remove-slot,
// rotate and change-passphrase. Everything they have in common is runMutation, and the order it
// imposes is the whole safety argument:
//
//	lock -> settle or refuse -> journal -> mutate -> clear the journal
//
// The lock first, because a slot operation while the server is running is last-writer-wins on the
// next save: the running server holds the header it read at startup and writes it back. The settle
// before anything is changed, because a journal on disk means a previous operation did not finish,
// and mutating on top of it is how a data dir ends up in a state nothing can explain. The journal
// before the mutation, because the mutation spans a recovery copy and a file.
//
// No passphrase is ever a flag, in any of them. It comes from CLAUDESWAP_KEY for a scripted run or
// from a prompt with no echo, exactly as `set-password` reads a password - argv is visible to every
// process on the host.

// maxStdinPassphraseStream bounds everything these commands will read from a pipe: at most three
// passphrases, each already bounded by maxStdinPassword. A stuck or hostile producer is not read
// forever.
const maxStdinPassphraseStream = 16 << 10

// The slot types `add-slot` accepts, which are the three this binary can wrap.
const (
	slotTypePassphrase = "passphrase"
	slotTypeDPAPI      = "dpapi"
	slotTypeKEKFile    = "kek-file"
)

// passphraseReader reads passphrases from one stdin, in order: with no echo when stdin is a
// terminal, else one line at a time from a single buffered reader.
//
// One reader for the whole command, deliberately. A command can need two passphrases - the existing
// one and a new one - and two independent readers over the same pipe would lose whatever the first
// one buffered past its line.
type passphraseReader struct {
	in  io.Reader
	out io.Writer
	br  *bufio.Reader
	// existing is the passphrase that opens the file today, read at most once. runMutation needs it
	// to open the vault and a command like change-passphrase needs the same value afterwards; a
	// second read would take the next line of a pipe, or ask an operator twice for one command.
	existing     string
	haveExisting bool
}

func newPassphraseReader(in io.Reader, out io.Writer) *passphraseReader {
	if in == nil {
		in = strings.NewReader("")
	}
	return &passphraseReader{in: in, out: out}
}

// read asks for one passphrase. At a terminal it is not echoed, and confirm asks for it twice; a
// pipe cannot be asked twice, so there it is one line, which is the same rule readNewPassword
// already follows for the admin password.
func (r *passphraseReader) read(prompt string, confirm bool) (string, error) {
	if f, ok := r.in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		_, _ = fmt.Fprint(r.out, prompt)
		first, err := term.ReadPassword(int(f.Fd()))
		_, _ = fmt.Fprintln(r.out)
		if err != nil {
			return "", fmt.Errorf("read passphrase: %w", err)
		}
		if confirm {
			_, _ = fmt.Fprint(r.out, "Repeat it: ")
			second, rerr := term.ReadPassword(int(f.Fd()))
			_, _ = fmt.Fprintln(r.out)
			if rerr != nil {
				return "", fmt.Errorf("read passphrase: %w", rerr)
			}
			if string(first) != string(second) {
				return "", errors.New("the two passphrases do not match; nothing was written")
			}
		}
		if len(first) == 0 {
			return "", errors.New("no passphrase entered; nothing was written")
		}
		return string(first), nil
	}
	if r.br == nil {
		r.br = bufio.NewReader(io.LimitReader(r.in, maxStdinPassphraseStream))
	}
	line, err := r.br.ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		return "", errors.New("no passphrase on stdin")
	}
	pass := strings.TrimRight(line, "\r\n")
	if pass == "" {
		return "", errors.New("no passphrase on stdin")
	}
	return pass, nil
}

// readExistingPassphrase is the passphrase that opens the file today: CLAUDESWAP_KEY for a scripted
// run, else a prompt. The environment wins because that is the scripted path the installers and the
// e2e scripts use, and a command that prompted anyway would hang in a script.
func readExistingPassphrase(r *passphraseReader) (string, error) {
	if r.haveExisting {
		return r.existing, nil
	}
	pass := os.Getenv(keyEnv)
	if pass == "" {
		var err error
		if pass, err = r.read("Vault passphrase (not echoed): ", false); err != nil {
			return "", err
		}
	}
	r.existing, r.haveExisting = pass, true
	return pass, nil
}

// readNewPassphrase is a passphrase being created. It is never invented here and never printed:
// the operator types it, or a scripted run pipes it.
func readNewPassphrase(r *passphraseReader) (string, error) {
	return r.read("New vault passphrase (not echoed): ", true)
}

// mutation is one slot operation: its name for the lock holder line, the journal and the audit
// line; the data-dir files it spans; and the change itself.
type mutation struct {
	op    string
	files []string
	// reader is the command's one stdin reader, shared so the existing passphrase is read once and
	// a second passphrase comes from the next line rather than from a drained pipe. A nil reader is
	// a command with nothing to read: the passphrase then has to be in CLAUDESWAP_KEY.
	reader *passphraseReader
	apply  func(v *vault.Vault, ks vault.KeySource) (string, error)
}

// runMutation is the one path every mutator takes. See the file comment for why the order is what
// it is; what follows is what each step costs when it fails.
//
// A held lock is exit 2 with the holder's pid, because the fix is to stop that process. An
// unreadable or unsettleable journal is a refusal that changes nothing and names
// `server vault verify --all-slots`, because a journal says which files to delete a recovery copy
// from and acting on one this binary cannot read is how a data dir loses files.
//
// A refusal that wrote nothing clears its own journal. That is not tidiness: a journal left behind
// by a command that never started would make the NEXT mutator settle an operation that did not
// happen, and the settle for a stage below `renamed` reports "reverted", which would read as though
// something had been undone.
func runMutation(dataDir string, m mutation, out io.Writer) int {
	lock, err := vault.AcquireLock(dataDir, m.op)
	if err != nil {
		_, _ = fmt.Fprintf(out, "vault %s: %s\n", m.op, logx.Redact(err.Error()))
		if errors.Is(err, vault.ErrLockHeld) {
			return exitUsage
		}
		return exitRuntime
	}
	defer func() { _ = lock.Release() }()

	// The format before the passphrase, from the header alone. A v1 or absent vault has no slots to
	// operate on whatever key is offered, so asking for a passphrase - or spending argon2id deriving
	// one - to arrive at the same refusal would be a prompt nobody needed, and a wrong-key message
	// for a file whose only problem is its format is exactly the confusion that gets a correct
	// passphrase rotated.
	info, ierr := vault.Inspect(filepath.Join(dataDir, vaultFileName))
	if ierr != nil {
		_, _ = fmt.Fprintf(out, "vault %s: %s\n", m.op, logx.Redact(ierr.Error()))
		return mutatorExitCode(ierr)
	}
	if info.Format != vault.FormatV2 {
		_, _ = fmt.Fprintf(out, "vault %s: %s is %s, so it has no key slots; run `server vault migrate` "+
			"(or `server vault init` when there is no vault yet)\n", m.op, vaultFileName, info.Format)
		return exitNewerFormat
	}

	reader := m.reader
	if reader == nil {
		reader = newPassphraseReader(nil, out)
	}
	pass, err := readExistingPassphrase(reader)
	if err != nil {
		_, _ = fmt.Fprintf(out, "vault %s: %s\n", m.op, logx.Redact(err.Error()))
		return exitUsage
	}
	ks := vault.WithMachineKeys(typedKey{pass: pass}, hostKeyOptions())

	if code := settleJournal(dataDir, m.op, ks, out); code != 0 {
		return code
	}
	// The vault is opened before the journal is written: Open takes no lock of its own and writes
	// nothing, so a file this command cannot read costs a refusal and not a journal entry.
	v, err := vault.Open(filepath.Join(dataDir, vaultFileName), ks)
	if err != nil {
		_, _ = fmt.Fprintf(out, "vault %s: %s\n", m.op, logx.Redact(err.Error()))
		return mutatorExitCode(err)
	}
	if err := vault.WriteVaultOp(dataDir, vault.VaultOp{
		Op: m.op, Files: m.files, Stage: vault.StageStarted}); err != nil {
		_, _ = fmt.Fprintf(out, "vault %s: %s\n", m.op, logx.Redact(err.Error()))
		return exitRuntime
	}
	result, err := m.apply(v, ks)
	if err != nil {
		if wroteNothing(err) {
			clearJournal(dataDir, m.op, out)
		}
		_, _ = fmt.Fprintf(out, "vault %s: %s\n", m.op, logx.Redact(err.Error()))
		code := mutatorExitCode(err)
		auditLine(out, m.op, "", "", "refused", code)
		return code
	}
	clearJournal(dataDir, m.op, out)
	if result != "" {
		_, _ = fmt.Fprintf(out, "vault %s: %s\n", m.op, result)
	}
	return 0
}

// settleJournal finishes or undoes an interrupted operation before this one changes anything, and
// refuses the command if it cannot. Nothing is repaired silently: the settle's own answer
// ("completed: ..." or "reverted") is printed, because a command that quietly undid someone else's
// half-finished rotation is a surprise an operator should not have to find in a log.
func settleJournal(dataDir, op string, ks vault.KeySource, out io.Writer) int {
	prev, ok, err := vault.ReadVaultOp(dataDir)
	if err != nil {
		_, _ = fmt.Fprintf(out, "vault %s: %s\n", op, logx.Redact(err.Error()))
		return exitUsage
	}
	if !ok {
		return 0
	}
	line, serr := vault.SettleVaultOp(dataDir, prev, ks)
	if serr != nil {
		_, _ = fmt.Fprintf(out, "vault %s: an interrupted %s could not be settled: %s\n",
			op, prev.Op, logx.Redact(serr.Error()))
		_, _ = fmt.Fprintln(out, "vault "+op+": nothing was changed; run `server vault verify --all-slots`")
		return exitUsage
	}
	_, _ = fmt.Fprintf(out, "vault %s: an interrupted %s was settled: %s\n", op, prev.Op, line)
	return 0
}

// clearJournal removes the journal and says so if it could not. A journal that outlives its
// operation makes the next command settle one that already finished, so a failure here is worth a
// line even though the operation itself succeeded.
func clearJournal(dataDir, op string, out io.Writer) {
	if err := vault.ClearVaultOp(dataDir); err != nil {
		_, _ = fmt.Fprintf(out, "vault %s: the journal could not be cleared: %s\n", op, logx.Redact(err.Error()))
	}
}

// wroteNothing reports whether an error is one of the refusals that land before the first byte is
// written. Every one of them is a sentinel this package can name; anything else - a failed rename, a
// full disk - may have written something, and its journal stays for the next command to settle.
func wroteNothing(err error) bool {
	for _, e := range []error{
		vault.ErrLastPassphraseSlot, vault.ErrUnknownSlotPresent, vault.ErrKEKUnreachable,
		vault.ErrSlotNotFound, vault.ErrSlotExists, vault.ErrNoRecoverySlot, vault.ErrNotV2,
		vault.ErrBadKey, vault.ErrNoKey, vault.ErrNewerFormat, vault.ErrMalformed,
	} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// mutatorExitCode is the mutators' exit table: 2 for a refusal an operator fixes by changing what
// they asked for or what this host can reach, 3 when no slot opens the file, 4 for a format this
// command cannot work on, 1 for anything else.
//
// It is deliberately separate from vaultExitCode, which maps the same sentinels for `server run`:
// there the number is an instruction to a service supervisor, and ErrKEKUnreachable means "the
// vault is locked, do not restart me" (3). Here the operator is standing at a console and the same
// state means "this host cannot reach that slot's key" (2), which is a thing they can act on.
func mutatorExitCode(err error) int {
	switch {
	case errors.Is(err, vault.ErrLockHeld):
		return exitUsage
	case errors.Is(err, vault.ErrNotV2), errors.Is(err, vault.ErrNewerFormat), errors.Is(err, vault.ErrMalformed):
		return exitNewerFormat
	case errors.Is(err, vault.ErrLastPassphraseSlot), errors.Is(err, vault.ErrUnknownSlotPresent),
		errors.Is(err, vault.ErrKEKUnreachable), errors.Is(err, vault.ErrSlotNotFound),
		errors.Is(err, vault.ErrSlotExists), errors.Is(err, vault.ErrNoRecoverySlot),
		errors.Is(err, vault.ErrNoKey):
		return exitUsage
	case errors.Is(err, vault.ErrBadKey):
		return exitVaultLocked
	}
	return exitRuntime
}

// auditLine is the one structured line per mutator run the spec asks for, in the keys logx already
// allows: the operation, the slot and its type when there is one, the result and the exit status.
// Never the KEK, the DEK, a wrap, a passphrase or a path to key material.
func auditLine(out io.Writer, op, slot, slotType, result string, exit int) {
	log := logx.New(out)
	args := []any{slog.String("op", op), slog.String("result", result), slog.Int("exit", exit)}
	if slot != "" {
		args = append(args, slog.String("slot", slot), slog.String("slottype", slotType))
	}
	log.Info("vault slot operation", args...)
}

// --- add-slot ---

// vaultAddSlot adds a key slot wrapping the vault's CURRENT data key, so every key that opened the
// file before still opens it. It is the recovery step for a lost machine key: open with the
// passphrase, add a slot for the new host key, start the service.
//
// What it does NOT do, and why: it never CREATES host key material. A `kek-file` slot is wrapped
// under the KEK this host already resolves (a unit's credential, `--kek-file`'s path, or the
// credstore entry when run as root); generating a KEK, writing the credstore entry and the unit
// drop-in, and running `systemctl daemon-reload` belong to `vault init`/`vault migrate`, which plan
// those steps before they take them. With no KEK to wrap under, this refuses and names them.
// plainKEK is accepted here for that reason: it selects the rung for the command that creates one.
func vaultAddSlot(dataDir, slotType string, plainKEK bool, stdin io.Reader, out io.Writer) int {
	switch slotType {
	case slotTypePassphrase, slotTypeDPAPI, slotTypeKEKFile:
	case "":
		_, _ = fmt.Fprintf(out, "vault add-slot: --type is required: %s, %s or %s\n",
			slotTypePassphrase, slotTypeDPAPI, slotTypeKEKFile)
		return exitUsage
	default:
		_, _ = fmt.Fprintf(out, "vault add-slot: %q is not a slot type this binary can create; the three are %s, %s and %s\n",
			slotType, slotTypePassphrase, slotTypeDPAPI, slotTypeKEKFile)
		return exitUsage
	}
	if plainKEK && slotType != slotTypeKEKFile {
		_, _ = fmt.Fprintf(out, "vault add-slot: --plain-kek only applies to a %s slot\n", slotTypeKEKFile)
		return exitUsage
	}
	if plainKEK {
		_, _ = fmt.Fprintln(out, "vault add-slot: --plain-kek selects the rung for the command that CREATES a KEK "+
			"(`vault init`/`vault migrate`); this command wraps under the KEK this host already resolves")
	}
	reader := newPassphraseReader(stdin, out)
	var added vault.SlotInfo
	code := runMutation(dataDir, mutation{op: "add-slot", files: []string{vaultFileName}, reader: reader,
		apply: func(v *vault.Vault, _ vault.KeySource) (string, error) {
			// The new passphrase is read here rather than before the lock, so it comes after the
			// existing one on a piped stdin: the natural order to type, and the only order in which
			// one reader can take both.
			var material []byte
			if slotType == slotTypePassphrase {
				next, err := readNewPassphrase(reader)
				if err != nil {
					return "", fmt.Errorf("%w: %s", vault.ErrNoKey, err.Error())
				}
				material = []byte(next)
			}
			if err := v.AddSlot(vault.Slot{Type: slotType}, material); err != nil {
				return "", err
			}
			// The id is assigned inside AddSlot from the package's own randomness, so it is read back
			// from the header rather than guessed here.
			info, err := vault.Inspect(filepath.Join(dataDir, vaultFileName))
			if err == nil {
				added = newestSlotOfType(info, slotType)
			}
			return fmt.Sprintf("added a %s slot", slotType), nil
		}}, out)
	if code == 0 && added.ID != "" {
		_, _ = fmt.Fprintf(out, "vault add-slot: slot %s type %s created %s\n", added.ID, added.Type, added.Created)
		_, _ = fmt.Fprintln(out, "vault add-slot: run `server vault verify --all-slots` to prove every slot still opens the file")
		auditLine(out, "add-slot", added.ID, added.Type, "added", 0)
	}
	return code
}

// newestSlotOfType returns the last slot of a type in header order, which is the one a
// just-finished add-slot created: marshalHeader appends a new slot, so header order ends with it.
func newestSlotOfType(info vault.FileInfo, slotType string) vault.SlotInfo {
	var newest vault.SlotInfo
	for _, s := range info.Slots {
		if s.Type == slotType {
			newest = s
		}
	}
	return newest
}

// --- remove-slot ---

// vaultRemoveSlot removes one slot AND rotates the data key in the same write, so a leaked copy of
// the removed slot's wrap opens nothing current. It refuses the last passphrase slot, and it says
// what it did with the recovery copy beside the file - re-sealed under the new generation, or
// removed, by a command whose name does not say "delete".
func vaultRemoveSlot(dataDir, slotID string, stdin io.Reader, out io.Writer) int {
	if slotID == "" {
		_, _ = fmt.Fprintln(out, "vault remove-slot: --id is required; `server vault status` prints the slot ids")
		return exitUsage
	}
	var slotType string
	code := runMutation(dataDir, mutation{op: "remove-slot", files: []string{vaultFileName},
		reader: newPassphraseReader(stdin, out),
		apply: func(v *vault.Vault, ks vault.KeySource) (string, error) {
			if info, err := vault.Inspect(filepath.Join(dataDir, vaultFileName)); err == nil {
				for _, s := range info.Slots {
					if s.ID == slotID {
						slotType = s.Type
					}
				}
			}
			bak, err := v.RemoveSlot(slotID, ks)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("slot %s removed, data key rotated; %s", slotID, bak), nil
		}}, out)
	if code == 0 {
		_, _ = fmt.Fprintln(out, "vault remove-slot: copies the command cannot reach - *.v1.<ts>, *.v2.<ts>, "+
			"backups you made elsewhere - still open with the removed key. `server vault purge-backups` is the last step.")
		auditLine(out, "remove-slot", slotID, slotType, "removed", 0)
	}
	return code
}

// --- rotate ---

// vaultRotate draws a new data key and re-wraps it into every slot. Every slot's key must be
// reachable: a slot this host cannot reach, or one of a type this binary does not know, is exit 2
// naming it, and there is deliberately no flag that drops it instead - dropping a slot is
// `remove-slot`, by that name, with its own recovery-copy handling.
func vaultRotate(dataDir string, stdin io.Reader, out io.Writer) int {
	code := runMutation(dataDir, mutation{op: "rotate", files: []string{vaultFileName},
		reader: newPassphraseReader(stdin, out),
		apply: func(v *vault.Vault, ks vault.KeySource) (string, error) {
			if err := v.Rotate(ks); err != nil {
				return "", err
			}
			return "data key rotated and re-wrapped into every slot", nil
		}}, out)
	if code == 0 {
		auditLine(out, "rotate", "", "", "rotated", 0)
	}
	return code
}

// --- change-passphrase ---

// vaultChangePassphrase re-wraps the same data key under a new passphrase, with a fresh argon2id
// salt. Nothing else changes - not the data key, not a machine slot, not the payload - so it is
// cheap and it is not a rotation in disguise.
//
// The keyring is NOT changed here, and the command says so. `vault init`/`vault migrate` are what
// create a v2 `tunnelkeys.bin`, so until they land no data dir can hold one; a v1 keyring beside
// the vault keeps its own passphrase (it is a passphrase-only envelope) and is left byte-identical
// rather than half-changed.
func vaultChangePassphrase(dataDir string, stdin io.Reader, out io.Writer) int {
	reader := newPassphraseReader(stdin, out)
	code := runMutation(dataDir, mutation{op: "change-passphrase", files: []string{vaultFileName}, reader: reader,
		apply: func(v *vault.Vault, _ vault.KeySource) (string, error) {
			// The existing passphrase was already read to open the file, and this returns that same
			// value rather than reading again. The new one is the next thing on stdin.
			old, oerr := readExistingPassphrase(reader)
			if oerr != nil {
				return "", fmt.Errorf("%w: %s", vault.ErrNoKey, oerr.Error())
			}
			next, nerr := readNewPassphrase(reader)
			if nerr != nil {
				return "", fmt.Errorf("%w: %s", vault.ErrNoKey, nerr.Error())
			}
			if err := v.ChangePassphrase(old, next); err != nil {
				return "", err
			}
			return "the passphrase slot was re-wrapped under the new passphrase; the data key is unchanged", nil
		}}, out)
	if code != 0 {
		return code
	}
	reportKeyringUntouched(dataDir, out)
	_, _ = fmt.Fprintln(out, "vault change-passphrase: a v1 copy in the data dir still opens with the OLD passphrase; "+
		"`server vault status` lists them and `server vault finalize-migration` removes them")
	auditLine(out, "change-passphrase", "", "", "changed", 0)
	return 0
}

// reportKeyringUntouched says what happened to the keyring, because "nothing" is the answer and an
// operator who was not told would reasonably assume the opposite.
func reportKeyringUntouched(dataDir string, out io.Writer) {
	info, err := vault.Inspect(filepath.Join(dataDir, vault.KeyringFileName))
	if err != nil {
		return
	}
	switch info.Format {
	case vault.FormatAbsent:
		return
	case vault.FormatV1:
		_, _ = fmt.Fprintf(out, "vault change-passphrase: %s is v1 and was NOT changed; it keeps its own passphrase "+
			"until `server vault migrate` gives it key slots\n", vault.KeyringFileName)
	default:
		_, _ = fmt.Fprintf(out, "vault change-passphrase: %s was NOT changed; its passphrase slot is changed by the same "+
			"command once `server vault migrate` manages both files\n", vault.KeyringFileName)
	}
}
