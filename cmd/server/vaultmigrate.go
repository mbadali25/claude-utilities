package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"claude-utilities/internal/credfile"
	"claude-utilities/internal/logx"
	"claude-utilities/internal/service"
	"claude-utilities/internal/vault"
)

// This file holds `server vault migrate` and `server vault downgrade`: the two commands that change
// a data dir's format, in either direction.
//
// migrate's order is the spec's steps 1-7 and the reordering revision 8 made to them, which is the
// whole safety argument:
//
//	lock -> service stopped -> what is there -> the pin -> the machine slot PLANNED -> passphrase ->
//	settle -> [--dry-run stops here, having written nothing] -> journal -> the v1 copies, PROVED ->
//	journal(bak) -> replace each file -> journal(renamed) -> the pin again -> clear the journal
//
// Everything before the journal writes nothing at all - not a KEK, not a drop-in, not a copy - so
// `--dry-run` is a claim this file can keep rather than one it has to remember to honour. The
// earlier spec text created the machine slot in step 3 and then said step 4 wrote nothing; revision
// 8 split planning from creating, and the split is what this ordering is.
//
// The v1 copy is written AND OPENED before the first replacement. A copy nobody proved is not a
// rollback, and this is the one step in the whole plan that can lose an operator's accounts: a
// migrate that fails between the copy and the rename, with a copy that does not open, has nothing
// to go back to. So the copy is made here, read back, and opened with the passphrase, and only then
// is its path handed to vault.MigrateToV2 as the bytes to restore from.
//
// The journal is LEFT IN PLACE when a replacement fails, deliberately. MigrateToV2 restores the v1
// bytes itself when it can, and says so when it cannot; either way the next command's settle is
// what finishes the data dir, and a journal cleared on the way out would take that away.

// serviceState reports the registered service's name and whether it is stopped. ok is false when
// there is no registered service, which is the only answer today: reading the SCM's state (and the
// unit's on Linux) belongs with `server service install`, which registers it in the first place.
//
// It is a seam so the refusal is testable now rather than when slice 4 lands. A slot operation
// against a data dir a running service holds is last-writer-wins on the next save, and on Windows
// the lock alone does not cover a service that is mid-start.
var serviceState = func() (name string, stopped, ok bool, err error) { return "", true, false, nil }

// fdeStatus is fullDiskEncryptionStatus unless a test replaces it. It shells out, so every test
// replaces it: a unit test that ran manage-bde or lsblk would be asserting the machine it runs on.
var fdeStatus = fullDiskEncryptionStatus

// nowStamp is the `<ts>` in `vault.bin.v1.<ts>`. Seconds, UTC, no punctuation a file name has to
// escape, and sortable - `status` lists these by name and an operator reads the order.
var nowStamp = func() string { return time.Now().UTC().Format("20060102T150405Z") }

// finalizeAfter is how long the spec asks an operator to run clean before `finalize-migration` is
// advisable. migrate prints the date, which is this added to today.
const finalizeAfter = 14 * 24 * time.Hour

// migrateFile is one file migrate has to deal with: where it is, what it is, and - once step 5 has
// run - the verified v1 copy its restore would come from.
type migrateFile struct {
	name    string
	path    string
	keyring bool
	copyAt  string
}

// vaultMigrate rewrites a v1 data dir as v2. dryRun prints the plan and writes nothing, except that it first settles a
// leftover journal (a real write); add overrides which machine slot type is used, and plainKEK selects the rung for the command that
// CREATES a KEK, which is not this one (see the note it prints).
//
// It returns the process exit code: 0 migrated, or planned, or already v2 and nothing to do; 2 a
// refusal the operator fixes by stopping something or typing something else; 3 a file no slot opens;
// 4 a format this command cannot work on; 1 anything else.
//
// Already-v2 is exit **0** and not 2, per revision 8 item 8: the installer calls `migrate`
// idempotently, and a non-zero exit there would fail an install that is in fact correct.
func vaultMigrate(dataDir string, dryRun bool, add string, plainKEK bool, stdin io.Reader, out io.Writer) int {
	const op = "migrate"
	lock, err := vault.AcquireLock(dataDir, op)
	if err != nil {
		_, _ = fmt.Fprintf(out, "vault %s: %s\n", op, logx.Redact(err.Error()))
		if errors.Is(err, vault.ErrLockHeld) {
			return exitUsage
		}
		return exitRuntime
	}
	defer func() { _ = lock.Release() }()

	if code := refuseARunningService(op, out); code != 0 {
		return code
	}
	todo, code := migrateWorkList(dataDir, op, out)
	if code != 0 {
		return code
	}
	if len(todo) == 0 {
		// Already v2, and the one return in this command that must still look at the journal. A
		// migrate interrupted between its last rename and the journal's removal leaves exactly this
		// state - a correct v2 pair with a journal in it - and `migrate` is the command an operator
		// re-runs. A return here that did not look would hand that journal to every other mutator
		// to refuse, and would pass over a journal this binary cannot read at all - which this same
		// command refuses when the files happen to be v1.
		if code := settleOnAnAlreadyV2Dir(dataDir, op, out); code != 0 {
			return code
		}
		// The installer calls this on every run, so it is also where a drop-in a failed first run
		// never wrote gets written. SyncKEKDropIn leaves an up-to-date one alone. A host with no
		// machine key has no kek-file slot to sync for, and that is not an error here.
		//
		// Never on a dry run: it writes /etc/systemd/system and runs systemctl.
		// That is the only write a dry run skips on this path: the settle above finishes a leftover
		// journal with real writes (vault.SettleVaultOp) on a dry run too, because a plan printed over an
		// unsettled pair would describe a state that is about to change.
		if dryRun {
			return 0
		}
		if machine, _, merr := machineSlotFor(add); merr == nil {
			return syncKEKDropIn(op, machine, out)
		}
		return 0
	}
	// The pin before the passphrase, because a data dir with no tls/ cannot pass the continuity
	// check whatever is typed, and because the fingerprint is the one public value an operator
	// compares by eye against what their agents hold.
	before, ferr := certFingerprint(dataDir)
	if ferr != nil {
		_, _ = fmt.Fprintf(out, "vault %s: %s\n", op, logx.Redact(ferr.Error()))
		_, _ = fmt.Fprintf(out, "vault %s: the pin continuity check needs the pair every enrolled agent "+
			"pins; nothing was written. Start the server once to create it, or point --data-dir at the "+
			"dir that has it\n", op)
		return exitUsage
	}
	_, _ = fmt.Fprintf(out, "vault %s: tls/server-cert.pem sha256 %s (this is the value agents pin)\n", op, before)

	machine, note, merr := machineSlotFor(add)
	if merr != nil {
		_, _ = fmt.Fprintf(out, "vault %s: %s\n", op, logx.Redact(merr.Error()))
		return mutatorExitCode(merr)
	}
	if plainKEK {
		_, _ = fmt.Fprintf(out, "vault %s: --plain-kek selects the rung for the command that CREATES a KEK; "+
			"this command wraps under the key this host already resolves\n", op)
	}

	pass, err := readExistingPassphrase(newPassphraseReader(stdin, out))
	if err != nil {
		_, _ = fmt.Fprintf(out, "vault %s: %s\n", op, logx.Redact(err.Error()))
		return exitUsage
	}
	// Step 2's "a wrong passphrase stops here with nothing written", and it has to be its own step
	// rather than a side effect of the first replacement: on a dry run there is no replacement, and
	// an operator who typed the wrong passphrase would otherwise be shown a plan that cannot run.
	if code := refuseAWrongPassphrase(todo, pass, op, out); code != 0 {
		return code
	}
	ks := vault.WithMachineKeys(typedKey{pass: pass}, hostKeyOptions())

	if code := settleJournalForMigrate(dataDir, op, ks, out); code != 0 {
		return code
	}
	if dryRun {
		printMigratePlan(dataDir, todo, machine, note, before, out)
		return 0
	}
	return runMigration(dataDir, op, todo, machine, note, before, pass, ks, out)
}

// runMigration is everything from the journal onwards - which is everything that writes. It is
// split out so the function above reads as the ordering the spec states and this one as the five
// steps that touch the disk.
func runMigration(dataDir, op string, todo []migrateFile, machine vault.Slot, note, before, pass string,
	ks vault.KeySource, out io.Writer) int {
	// (i) The journal, before the first write, naming exactly the files this run will replace. On a
	// mixed pair that is the v1 half alone, which is the per-file truth a single Stage cannot carry:
	// the settle for an operation that named one file cannot be confused about the other.
	//
	// ResealsBak is false: migrate never re-seals or deletes a recovery copy. It RENAMES a v1 `.bak`
	// into the `*.v1.<ts>` inventory, which is a different act - nothing is lost and nothing becomes
	// unopenable - and a settle that treated this journal as a `remove-slot` would delete it.
	journal := vault.VaultOp{Op: op, Files: fileNames(todo), Stage: vault.StageStarted}
	if err := vault.WriteVaultOp(dataDir, journal); err != nil {
		_, _ = fmt.Fprintf(out, "vault %s: %s\n", op, logx.Redact(err.Error()))
		return exitRuntime
	}
	stamp := nowStamp()
	for i := range todo {
		copyAt, err := keepAndProveV1Copy(&todo[i], stamp, pass)
		if err != nil {
			_, _ = fmt.Fprintf(out, "vault %s: %s\n", op, logx.Redact(err.Error()))
			_, _ = fmt.Fprintf(out, "vault %s: no file was replaced. The journal is left for the next "+
				"command to settle; run `server vault status`\n", op)
			return exitRuntime
		}
		_, _ = fmt.Fprintf(out, "vault %s: kept %s and proved it opens with the passphrase\n",
			op, filepath.Base(copyAt))
		if line := inventoryAV1Bak(todo[i].path, stamp); line != "" {
			_, _ = fmt.Fprintf(out, "vault %s: %s\n", op, line)
		}
	}
	// (ii) Every copy is on disk and proved, and no file has been replaced yet. This is the stage a
	// crash from here to (iii) leaves, and it is the harmless one: every file is still v1 and every
	// copy of it opens.
	journal.Stage = vault.StageBak
	if err := vault.WriteVaultOp(dataDir, journal); err != nil {
		_, _ = fmt.Fprintf(out, "vault %s: the journal could not be advanced: %s\n", op, logx.Redact(err.Error()))
	}
	for _, f := range todo {
		info, err := vault.MigrateToV2(f.path, f.copyAt, pass, machine, ks)
		if err != nil {
			// The journal stays. MigrateToV2 has either restored the v1 bytes or named the copy to put
			// back by hand, and in both cases the next command's settle is what finishes the data dir.
			_, _ = fmt.Fprintf(out, "vault %s: %s\n", op, logx.Redact(err.Error()))
			_, _ = fmt.Fprintf(out, "vault %s: the journal is left in place; run `server vault verify "+
				"--all-slots` before anything else\n", op)
			code := mutatorExitCode(err)
			auditLine(out, op, "", machine.Type, "refused", code)
			return code
		}
		_, _ = fmt.Fprintf(out, "vault %s: %s is %s, dek %s\n", op, info.Name, info.Format, info.DEKID)
		for _, s := range info.Slots {
			_, _ = fmt.Fprintf(out, "  slot %s type %s%s created %s\n", s.ID, s.Type, slotScopeOrName(s), s.Created)
		}
	}
	// (iii) Every file this run named is replaced and verified; only the journal is left.
	journal.Stage = vault.StageRenamed
	if err := vault.WriteVaultOp(dataDir, journal); err != nil {
		_, _ = fmt.Fprintf(out, "vault %s: the journal could not be advanced: %s\n", op, logx.Redact(err.Error()))
	}
	after, aerr := certFingerprint(dataDir)
	if aerr != nil || after != before {
		_, _ = fmt.Fprintf(out, "vault %s: the certificate fingerprint CHANGED across the migration "+
			"(was %s, now %s, err %v). Every enrolled agent pins the old value: do not restart the "+
			"server until you know why\n", op, before, after, logx.Redact(errText(aerr)))
		return exitRuntime
	}
	_, _ = fmt.Fprintf(out, "vault %s: tls/server-cert.pem sha256 %s - unchanged, so every agent's pin "+
		"still matches\n", op, after)

	clearJournalFn(dataDir, op, out)
	// Last, and after the journal is cleared: the vault is migrated and consistent whatever happens
	// to the unit's drop-in, and a failure here must not leave an operator thinking it is not.
	code := syncKEKDropIn(op, machine, out)
	printRecoveryLines(op, todo, note, stamp, out)
	if code != 0 {
		auditLine(out, op, "", machine.Type, "migrated-dropin-failed", code)
		return code
	}
	auditLine(out, op, "", machine.Type, "migrated", 0)
	return 0
}

// kekDropInSync is service.SyncKEKDropIn unless a test replaces it. The real one writes under
// /etc/systemd/system and runs systemctl, which no unit test may do.
var kekDropInSync = service.SyncKEKDropIn

// syncKEKDropIn makes the server unit's drop-in name the KEK this host holds, after a command has
// wrapped the vault under it. Only a kek-file slot has one: a dpapi slot has no unit and no
// credential. It returns the exit code to use: 0, or exitRuntime when the drop-in could not be
// written - the vault itself is already done, and the line says so.
//
// Nothing is printed when there was nothing to write (a console run keyed by CLAUDESWAP_KEK_FILE, a
// host with no credstore), and no path or credential name is ever printed: the service package
// returns fixed sentences.
func syncKEKDropIn(op string, machine vault.Slot, out io.Writer) int {
	if machine.Type != slotTypeKEKFile {
		return 0
	}
	rung, wrote, err := kekDropInSync()
	if err != nil {
		_, _ = fmt.Fprintf(out, "vault %s: the migration is complete, but the server unit's KEK drop-in "+
			"was not written: %s. The unit cannot find its key until it is; fix the cause and run "+
			"`server vault migrate` again\n", op, logx.Redact(err.Error()))
		return exitRuntime
	}
	if wrote {
		_, _ = fmt.Fprintf(out, "vault %s: wrote the server unit's KEK drop-in for the %s key and reloaded "+
			"systemd\n", op, rung)
	}
	return 0
}

// --- what is there, and what this command may do about it ---

// migrateWorkList says which files this run would replace. An empty list with code 0 is the
// already-v2 case; a non-zero code is a refusal.
//
// The keyring being absent is NOT a refusal: a server that has never run with --tunnels has no
// keyring, and that is the normal shape of most data dirs. The vault being absent IS one.
func migrateWorkList(dataDir, op string, out io.Writer) ([]migrateFile, int) {
	all := []migrateFile{
		{name: vaultFileName, path: filepath.Join(dataDir, vaultFileName)},
		{name: vault.KeyringFileName, path: filepath.Join(dataDir, vault.KeyringFileName), keyring: true},
	}
	formats := make([]string, len(all))
	var todo []migrateFile
	for i, f := range all {
		info, err := vault.Inspect(f.path)
		if err != nil {
			_, _ = fmt.Fprintf(out, "vault %s: %s is unreadable: %s\n", op, f.name, logx.Redact(err.Error()))
			_, _ = fmt.Fprintf(out, "vault %s: nothing was written; run `server vault status`\n", op)
			return nil, exitNewerFormat
		}
		formats[i] = info.Format
		if info.Format == vault.FormatV1 {
			todo = append(todo, f)
		}
	}
	if formats[0] == vault.FormatAbsent {
		_, _ = fmt.Fprintf(out, "vault %s: no vault at %s: run `server vault init`\n", op, dataDir)
		return nil, exitUsage
	}
	if len(todo) == 0 {
		// Exit 0, and the count, so an installer that calls this on every run reads a correct data dir
		// as correct and an operator can see WHY there was nothing to do.
		slots := 0
		if info, err := vault.Inspect(all[0].path); err == nil {
			slots = len(info.Slots)
		}
		_, _ = fmt.Fprintf(out, "vault %s: vault is already v2 (%d slots, formats match): nothing to migrate\n",
			op, slots)
		return nil, 0
	}
	if len(todo) == 1 && formats[0] != formats[1] && formats[1] != vault.FormatAbsent {
		// The mixed pair revision 8 item 9 defines: one file v2, one v1, which a crash across the two
		// writes leaves. migrate is the one command that proceeds, on the v1 half, and says which.
		_, _ = fmt.Fprintf(out, "vault %s: %s is %s and %s is %s - a mixed pair. Only %s will be "+
			"migrated; the other file is left exactly as it is\n",
			op, all[0].name, formats[0], all[1].name, formats[1], todo[0].name)
	}
	return todo, 0
}

// refuseARunningService refuses while a registered service is in any state but stopped. The lock
// would catch a running server, but on Windows a service that is mid-start has not taken it yet.
func refuseARunningService(op string, out io.Writer) int {
	name, stopped, ok, err := serviceState()
	if err != nil {
		_, _ = fmt.Fprintf(out, "vault %s: the registered service's state could not be read: %s\n",
			op, logx.Redact(err.Error()))
		return exitRuntime
	}
	if ok && !stopped {
		_, _ = fmt.Fprintf(out, "vault %s: the registered service %s is not stopped: stop it first\n", op, name)
		return exitUsage
	}
	return 0
}

// refuseAWrongPassphrase opens every file this run would touch, with the passphrase alone, and
// refuses before anything is planned further if one of them does not open. It writes nothing: both
// openers here read.
func refuseAWrongPassphrase(todo []migrateFile, pass, op string, out io.Writer) int {
	for _, f := range todo {
		if err := openV1(f.path, f.keyring, pass); err != nil {
			_, _ = fmt.Fprintf(out, "vault %s: %s does not open with that passphrase: %s\n",
				op, f.name, logx.Redact(err.Error()))
			_, _ = fmt.Fprintf(out, "vault %s: nothing was written\n", op)
			return mutatorExitCode(err)
		}
	}
	return 0
}

// openV1 opens one v1 file with the passphrase and nothing else, through the exported opener for its
// kind. A keyring opened as a vault would fail on its magic, which is why the kind is carried on
// migrateFile rather than guessed from the name here.
func openV1(path string, keyring bool, pass string) error {
	ks := vault.KeySource(typedKey{pass: pass})
	if keyring {
		_, err := vault.OpenKeyring(path, ks)
		return err
	}
	_, err := vault.Open(path, ks)
	return err
}

// machineSlotFor is the machine slot this run will write: the host's own by default, or the type
// --add names. A named type this host has no opener for is refused here, by name, rather than
// discovered by MigrateToV2's probe after the operator has typed a passphrase.
func machineSlotFor(add string) (vault.Slot, string, error) {
	switch add {
	case "":
		return machineSlotForHost()
	case slotTypeDPAPI, slotTypeKEKFile:
	default:
		return vault.Slot{}, "", fmt.Errorf("vault: migrate: --add %q is not a machine slot type this binary "+
			"can create; the two are %s and %s", add, slotTypeDPAPI, slotTypeKEKFile)
	}
	for _, opener := range vault.HostKeys(hostKeyOptions()) {
		if opener.Type() != add {
			continue
		}
		return vault.Slot{Type: add}, add + ": the type --add named, wrapped under the key this host resolves " +
			"for it", nil
	}
	return vault.Slot{}, "", fmt.Errorf("%w: this host has no %s key, so --add %s has nothing to wrap under",
		vault.ErrKEKUnreachable, add, add)
}

// --- the journal, and the one repair migrate is allowed to make ---

// settleJournalForMigrate is settleJournal plus the single obstruction this command may carry on
// past: a mixed pair. It is a separate function rather than a flag on settleJournal for the reason
// vault.VaultOp.ResealsBak gives for its polarity - the permission to repair comes from the COMMAND
// THE OPERATOR RAN, never from the journal's contents. A journal lives in the data dir, so anyone
// who can write there can write `{"op":"migrate",...}`, and a settle that unlocked its own dangerous
// branch on that string would be trusting a forgeable file.
//
// Every other mutator keeps refusing, and keeps refusing by construction: they call settleJournal,
// which has no way to reach this branch.
//
// Nothing is cleared here. migrate's own journal entry replaces whatever was there, and it names
// only the files this run will replace - which on a mixed pair is the v1 half. That entry IS the
// repair record: a single Stage cannot say "the first rename landed and the second did not", and a
// file list that names one file cannot be read as claiming anything about the other.
func settleJournalForMigrate(dataDir, op string, ks vault.KeySource, out io.Writer) int {
	prev, ok, err := vault.ReadVaultOp(dataDir)
	if err != nil {
		_, _ = fmt.Fprintf(out, "vault %s: %s\n", op, logx.Redact(err.Error()))
		return exitUsage
	}
	if !ok {
		return 0
	}
	line, serr := vault.SettleVaultOp(dataDir, prev, ks)
	if serr == nil {
		_, _ = fmt.Fprintf(out, "vault %s: an interrupted %s was settled: %s\n", op, prev.Op, line)
		return 0
	}
	if errors.Is(serr, vault.ErrVaultOpMixedPair) {
		_, _ = fmt.Fprintf(out, "vault %s: an interrupted %s left the two files at different format "+
			"versions: %s\n", op, prev.Op, logx.Redact(serr.Error()))
		_, _ = fmt.Fprintf(out, "vault %s: this is the one command that repairs that - it migrates the v1 "+
			"half and leaves the v2 half alone - so it carries on rather than refusing\n", op)
		return 0
	}
	_, _ = fmt.Fprintf(out, "vault %s: an interrupted %s could not be settled: %s\n",
		op, prev.Op, logx.Redact(serr.Error()))
	_, _ = fmt.Fprintln(out, "vault "+op+": nothing was changed; run `server vault verify --all-slots`")
	return exitUsage
}

// settleOnAnAlreadyV2Dir is the already-v2 return's journal step. It asks for no passphrase, and
// that constraint is what decides its three answers: already-v2 is exit 0 so an installer can call
// `migrate` on every run (revision 8 item 8), and a command that prompted when it had nothing to
// migrate would hang that script.
//
//   - No journal: nothing to do, exit 0, which is all this path ever did.
//   - A journal whose operation touches no recovery copy (ResealsBak false - migrate, init,
//     add-slot, change-passphrase): SettleVaultOp's own no-key branch clears it. Cleared, exit 0.
//     This is the crash-at-the-last-step case, and it needs no key because there is nothing to
//     re-seal: each file the operation named went through one atomic replaceFile.
//   - Anything else: REFUSED with exit 2 and nothing changed. A `rotate` or `remove-slot` journal
//     has a `.bak` that is still openable by the key being removed, and re-sealing it needs a key
//     this command has not asked for - an installer reading exit 0 here would start the service
//     over that hole. A journal this binary cannot read is refused for the reason it is refused on
//     a v1 dir: a journal says which files to touch, and the format of the files beside it is no
//     reason to believe one.
func settleOnAnAlreadyV2Dir(dataDir, op string, out io.Writer) int {
	prev, ok, err := vault.ReadVaultOp(dataDir)
	if err != nil {
		_, _ = fmt.Fprintf(out, "vault %s: %s\n", op, logx.Redact(err.Error()))
		_, _ = fmt.Fprintf(out, "vault %s: nothing was changed; run `server vault verify --all-slots`\n", op)
		return exitUsage
	}
	if !ok {
		return 0
	}
	if prev.ResealsBak {
		_, _ = fmt.Fprintf(out, "vault %s: an interrupted %s (stage %s) left a recovery copy to re-seal, "+
			"which needs a key this command does not ask for when it has nothing to migrate: the copy may "+
			"still open with a key that operation was taking away\n", op, prev.Op, prev.Stage)
		_, _ = fmt.Fprintf(out, "vault %s: nothing was changed; run `server vault verify --all-slots`, then "+
			"`server vault rotate`, which settles it\n", op)
		return exitUsage
	}
	line, serr := vault.SettleVaultOp(dataDir, prev, nil)
	if serr != nil {
		_, _ = fmt.Fprintf(out, "vault %s: an interrupted %s could not be settled: %s\n",
			op, prev.Op, logx.Redact(serr.Error()))
		_, _ = fmt.Fprintf(out, "vault %s: nothing was changed; run `server vault verify --all-slots`\n", op)
		return exitUsage
	}
	_, _ = fmt.Fprintf(out, "vault %s: an interrupted %s was settled: %s\n", op, prev.Op, line)
	return 0
}

func fileNames(todo []migrateFile) []string {
	out := make([]string, 0, len(todo))
	for _, f := range todo {
		out = append(out, f.name)
	}
	return out
}

// --- the v1 copies ---

// proveCopyOpens is keepAndProveV1Copy's open, and it is a seam because that refusal is otherwise
// unassertable. refuseAWrongPassphrase has already opened the original with this passphrase, and
// the copy is compared byte for byte against those same bytes, so every copy a test can construct
// opens trivially. What is left for the real open to catch is an environment's answer rather than a
// value's - a handle another process changed under the lock, bytes the file system acknowledged and
// did not keep - and without a seam the one line that turns a byte copy into a rollback could be
// deleted with the whole suite still green.
var proveCopyOpens = openV1

// keepAndProveV1Copy writes `<name>.v1.<stamp>` beside the file, reads it back, and OPENS it with
// the passphrase. All three, in that order, before any file is replaced.
//
// The open is the step that makes the copy a rollback rather than a file. A byte copy that reads
// back identically still proves nothing if the original was already damaged - and "the original was
// already damaged" is exactly the state an operator reaches for `migrate` in.
func keepAndProveV1Copy(f *migrateFile, stamp, pass string) (string, error) {
	data, err := os.ReadFile(filepath.Clean(f.path))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", f.name, err)
	}
	if len(data) == 0 {
		return "", fmt.Errorf("%s is empty, so there is nothing to copy or to migrate", f.name)
	}
	copyAt := f.path + ".v1." + stamp
	if err := writeOwnerOnly(copyAt, data); err != nil {
		return "", fmt.Errorf("keep %s: %w", filepath.Base(copyAt), err)
	}
	back, err := os.ReadFile(filepath.Clean(copyAt))
	if err != nil || !bytes.Equal(back, data) {
		return "", fmt.Errorf("%s does not read back as the file it copied, so it is not a rollback: "+
			"nothing was replaced", filepath.Base(copyAt))
	}
	if err := proveCopyOpens(copyAt, f.keyring, pass); err != nil {
		return "", fmt.Errorf("%s does not open with the passphrase, so it is not a rollback: %w",
			filepath.Base(copyAt), err)
	}
	f.copyAt = copyAt
	return copyAt, nil
}

// inventoryAV1Bak renames a `.bak` that is still a v1 envelope to `<name>.bak.v1.<stamp>`, and
// returns the line to print. Nothing in normal use would ever replace that file - only Delete and
// ReplaceBlock write `.bak`, and a v2 save never does - so without the rename it would outlive
// every other v1 artefact and keep every account openable by the passphrase alone indefinitely.
// Under the `*.v1.<ts>` name both `status` and `finalize-migration` can see it.
//
// A v2 `.bak`, or none, is left exactly as it is: a non-empty return value is the only signal.
func inventoryAV1Bak(path, stamp string) string {
	bak := path + ".bak"
	info, err := vault.Inspect(bak)
	if err != nil || info.Format != vault.FormatV1 {
		return ""
	}
	dst := bak + ".v1." + stamp
	if err := os.Rename(bak, dst); err != nil {
		return fmt.Sprintf("%s is a v1 recovery copy and could not be renamed to %s (%s); it will keep "+
			"opening with the passphrase alone until it is dealt with by hand",
			filepath.Base(bak), filepath.Base(dst), logx.Redact(err.Error()))
	}
	return fmt.Sprintf("renamed the v1 recovery copy %s to %s so retention can see it",
		filepath.Base(bak), filepath.Base(dst))
}

// writeOwnerOnly writes data to a NEW file, owner-only, with the same two mechanisms every write in
// internal/vault uses: the 0600 mode and, on Windows where the mode bits say nothing, an owner-only
// ACL. A v1 copy is a passphrase-only envelope holding every account, so it is exactly as sensitive
// as the file it was copied from.
//
// O_EXCL, not a truncate. The name carries a one-second stamp, so a file already at this path is a
// kept generation of this very file, and writing over a kept generation - even with bytes that
// ought to be identical - is the one thing the function that keeps the rollback must not do. The
// caller turns the refusal into "no file was replaced", which is the right answer: a second's wait
// costs nothing and a clobbered copy cannot be got back.
//
// And fsync before the mode is applied, because the copy's whole job is to survive the crash that
// happens while the file beside it is being replaced. os.WriteFile leaves the bytes acknowledged
// and not necessarily on the disk, which would make "proved it opens" a statement about the page
// cache. The directory entry is not synced here - cmd/server has no portable helper for that and
// internal/vault's is unexported - so a crash in the same instant can still lose the name; that is
// narrower than losing the content and it is written down rather than implied.
func writeOwnerOnly(path string, data []byte) error {
	//nolint:gosec // G703: path is <data-dir>/<one of two literal file names>.v1.<stamp>, where the
	// stamp is nowStamp's own digits-and-Z format and the only caller-supplied component is the data
	// dir the operator named with --data-dir. Writing beside the file is the command's job.
	f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, werr := f.Write(data); werr != nil {
		_ = f.Close()
		return werr
	}
	if serr := f.Sync(); serr != nil {
		_ = f.Close()
		return serr
	}
	if cerr := f.Close(); cerr != nil {
		return cerr
	}
	return credfile.RestrictFile(path)
}

// --- the pin ---

// certFingerprint is the sha256 of the DER in `<data-dir>/tls/server-cert.pem`, lowercase hex: the
// value every enrolled agent pins and the one migrate compares before and after.
//
// It reads and hashes here rather than calling internal/hub, and that is a deliberate trade recorded
// rather than hidden. hub exports EnsureCert and RenewCert and no read-only accessor; EnsureCert
// CREATES a pair when there is none, runs MkdirAll, re-applies the directory ACL and re-chmods the
// key - all writes, and a `--dry-run` that called it could not claim to have written nothing. The
// cost is that the hash is computed in two places (hub.loadPair and here) and could drift; what
// keeps it honest is that it is three lines of definition, not logic, and that the e2e runbook
// compares this command's output against the value `--pin` prints. A read-only
// `hub.CertFingerprint(dir)` is the better home and is left as a follow-up.
func certFingerprint(dataDir string) (string, error) {
	rel := filepath.Join("tls", "server-cert.pem")
	//nolint:gosec // G703: the data dir is the operator's own --data-dir and the rest is two literals.
	data, err := os.ReadFile(filepath.Join(dataDir, rel))
	if err != nil {
		return "", fmt.Errorf("%s: %w", rel, err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("%s is not a PEM certificate", rel)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("%s: %w", rel, err)
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), nil
}

// --- full-disk encryption (Decision 14) ---

// fullDiskEncryptionStatus says whether the volume the data dir sits on is encrypted at rest. It is
// reported and never enforced: Decision 14 is that a machine slot protects a stolen file and a
// stolen data dir and NOTHING against a disk image, so the one line this produces is the only place
// an operator is told which of those they are relying on.
//
// A command that is not there, or output this cannot read, is "unknown" and not "off". Claiming a
// volume is unencrypted because manage-bde is missing would be the same class of lie as claiming it
// is encrypted because it is present.
func fullDiskEncryptionStatus() (bool, string, error) {
	switch runtime.GOOS {
	case "windows":
		//nolint:gosec // G204: no caller-supplied argument; both are literals.
		raw, err := exec.Command("manage-bde.exe", "-status").CombinedOutput()
		if err != nil {
			return false, "", fmt.Errorf("manage-bde -status: %w", err)
		}
		text := string(raw)
		if strings.Contains(text, "Protection On") {
			return true, "BitLocker reports Protection On for at least one volume", nil
		}
		return false, "BitLocker reports no volume with Protection On", nil
	case "linux":
		//nolint:gosec // G204: no caller-supplied argument; both are literals.
		raw, err := exec.Command("lsblk", "-o", "TYPE,FSTYPE").CombinedOutput()
		if err != nil {
			return false, "", fmt.Errorf("lsblk -o TYPE,FSTYPE: %w", err)
		}
		text := string(raw)
		if strings.Contains(text, "crypt") {
			return true, "lsblk reports a crypt device or a crypto_LUKS filesystem", nil
		}
		return false, "lsblk reports no crypt device and no crypto_LUKS filesystem", nil
	}
	return false, "", fmt.Errorf("no full-disk-encryption probe for %s", runtime.GOOS)
}

// --- what the operator reads ---

// printMigratePlan is the dry run's whole output, and every line of it is read from the headers, the
// file names, this host's openers and the certificate - no key, no wrap, no path to key material -
// so a dry run on a host an operator cannot afford to guess about costs them nothing.
func printMigratePlan(dataDir string, todo []migrateFile, machine vault.Slot, note, fingerprint string,
	out io.Writer) {
	// The enumeration is the claim, and the lock file is named in it rather than left out. Every
	// vault command takes the data-dir lock before it knows whether it will refuse, and the lock file
	// is deliberately never deleted (an O_EXCL lock file's reclaim race is what the OS lock avoids),
	// so a dry run on a dir that had none leaves one behind. Saying "nothing was written" and then
	// leaving a file is the sort of small untruth that makes an operator distrust the rest of the
	// line.
	_, _ = fmt.Fprintf(out, "vault migrate: dry run, nothing was written to %s - no file, no copy, no "+
		"key material, no journal, no daemon-reload. The one exception is %s, which every vault "+
		"command takes before it knows whether it will refuse and none of them ever deletes\n",
		dataDir, vault.LockFileName)
	for _, f := range todo {
		_, _ = fmt.Fprintf(out, "  %s is %s and would become %s\n", f.name, vault.FormatV1, vault.FormatV2)
		_, _ = fmt.Fprintf(out, "    a byte copy would be kept as %s.v1.<ts>, read back and opened with the "+
			"passphrase before anything is replaced\n", f.name)
	}
	_, _ = fmt.Fprintf(out, "  each file would get one %s slot (the recovery key, re-wrapped from the "+
		"passphrase you just typed - it is NOT changed) and one %s slot\n", slotTypePassphrase, machine.Type)
	_, _ = fmt.Fprintf(out, "  machine slot %s\n", note)
	_, _ = fmt.Fprintf(out, "  tls/server-cert.pem sha256 %s would be compared again afterwards and must "+
		"not change\n", fingerprint)
	on, detail, err := fdeStatus()
	switch {
	case err != nil:
		_, _ = fmt.Fprintf(out, "  volume encryption: UNKNOWN (%s). A machine slot protects a stolen file "+
			"and a stolen data dir; only full-disk encryption protects a disk image\n", logx.Redact(err.Error()))
	case on:
		_, _ = fmt.Fprintf(out, "  volume encryption: on - %s\n", detail)
	default:
		_, _ = fmt.Fprintf(out, "  volume encryption: OFF - %s. A machine slot protects a stolen file and a "+
			"stolen data dir, and nothing here protects a disk image\n", detail)
	}
	_, _ = fmt.Fprintln(out, "  run it again without --dry-run to migrate")
}

// printRecoveryLines is the spec's step 7: the three ways back, and the date the copies become safe
// to remove. It is printed after the migration succeeded, because it is what an operator needs to
// write down at that moment and not before.
func printRecoveryLines(op string, todo []migrateFile, note, stamp string, out io.Writer) {
	_, _ = fmt.Fprintf(out, "vault %s: machine slot %s\n", op, note)
	_, _ = fmt.Fprintf(out, "vault %s: the passphrase you typed was RE-WRAPPED, not changed: it is the same "+
		"secret, and it is still the recovery key for every file here\n", op)
	_, _ = fmt.Fprintln(out, "recovery, three ways:")
	_, _ = fmt.Fprintln(out, "  1. `server vault downgrade` writes v1 files again, with the passphrase")
	for _, f := range todo {
		_, _ = fmt.Fprintf(out, "  2. or copy %s.v1.%s back over %s and start the old binary\n",
			f.name, stamp, f.name)
	}
	_, _ = fmt.Fprintf(out, "  3. `server vault finalize-migration` deletes those copies; it becomes "+
		"advisable on %s, after 14 days of clean uptime. Until then every copy above still opens with "+
		"the passphrase alone, which is what this migration exists to stop relying on\n",
		time.Now().UTC().Add(finalizeAfter).Format("2006-01-02"))
}

// --- downgrade ---

// vaultDowngrade writes v1 files again, keeping each v2 file's bytes as `<name>.v2.<ts>`. It is the
// rollback the passphrase slot exists for, and it is why `remove-slot` refuses the last one.
//
// It takes the lock and needs the service stopped, like every mutator. It does NOT need tls/ - the
// pin is not involved in a format change in this direction and refusing on its absence would make
// the rollback unavailable in exactly the state an operator reaches for it.
func vaultDowngrade(dataDir string, stdin io.Reader, out io.Writer) int {
	const op = "downgrade"
	lock, err := vault.AcquireLock(dataDir, op)
	if err != nil {
		_, _ = fmt.Fprintf(out, "vault %s: %s\n", op, logx.Redact(err.Error()))
		if errors.Is(err, vault.ErrLockHeld) {
			return exitUsage
		}
		return exitRuntime
	}
	defer func() { _ = lock.Release() }()

	if code := refuseARunningService(op, out); code != 0 {
		return code
	}
	todo, code := downgradeWorkList(dataDir, op, out)
	if code != 0 || len(todo) == 0 {
		return code
	}
	pass, err := readExistingPassphrase(newPassphraseReader(stdin, out))
	if err != nil {
		_, _ = fmt.Fprintf(out, "vault %s: %s\n", op, logx.Redact(err.Error()))
		return exitUsage
	}
	ks := vault.WithMachineKeys(typedKey{pass: pass}, hostKeyOptions())
	if code := settleJournal(dataDir, op, ks, out); code != 0 {
		// `downgrade` keeps the standard settle, and that means an interrupted migrate that left a
		// mixed pair refuses here. It is not a dead end and the operator should not have to work that
		// out: the copy-back is the documented route out of that state, and `migrate` is the other.
		// Saying so matters because this is the command someone reaches for when they want OUT, and a
		// refusal naming only `verify` reads as "you are stuck".
		_, _ = fmt.Fprintf(out, "vault %s: if the two files disagree about their format, this command "+
			"cannot settle it - copy the %s.v1.<ts> copy back over %s and start the old binary, or run "+
			"`server vault migrate`, which is the one command that repairs a mixed pair\n",
			op, vaultFileName, vaultFileName)
		return code
	}
	journal := vault.VaultOp{Op: op, Files: fileNames(todo), Stage: vault.StageStarted}
	if err := vault.WriteVaultOp(dataDir, journal); err != nil {
		_, _ = fmt.Fprintf(out, "vault %s: %s\n", op, logx.Redact(err.Error()))
		return exitRuntime
	}
	stamp := nowStamp()
	for _, f := range todo {
		keepAt := f.path + ".v2." + stamp
		if _, derr := vault.DowngradeToV1(f.path, keepAt, pass); derr != nil {
			_, _ = fmt.Fprintf(out, "vault %s: %s\n", op, logx.Redact(derr.Error()))
			_, _ = fmt.Fprintf(out, "vault %s: the journal is left in place; run `server vault verify "+
				"--all-slots`\n", op)
			code := mutatorExitCode(derr)
			auditLine(out, op, "", "", "refused", code)
			return code
		}
		_, _ = fmt.Fprintf(out, "vault %s: %s is v1 again; its v2 bytes are kept as %s\n",
			op, f.name, filepath.Base(keepAt))
	}
	journal.Stage = vault.StageRenamed
	if err := vault.WriteVaultOp(dataDir, journal); err != nil {
		_, _ = fmt.Fprintf(out, "vault %s: the journal could not be advanced: %s\n", op, logx.Redact(err.Error()))
	}
	clearJournalFn(dataDir, op, out)
	_, _ = fmt.Fprintf(out, "vault %s: these files now open with the passphrase ALONE - the machine slot is "+
		"gone, so a binary that predates v2 can start against this data dir, and so can anyone who has "+
		"the passphrase and a copy of the file\n", op)
	_, _ = fmt.Fprintf(out, "vault %s: `server vault purge-backups` removes the %s.v2.%s generations once "+
		"you are done with them; each one still opens with the keys it had\n", op, vaultFileName, stamp)
	auditLine(out, op, "", "", "downgraded", 0)
	return 0
}

// downgradeWorkList is the v2 files in the data dir. A pair that is already v1 is exit 0 and
// nothing to do, for migrate's reason: a rollback script that runs this twice must not fail the
// second time.
func downgradeWorkList(dataDir, op string, out io.Writer) ([]migrateFile, int) {
	all := []migrateFile{
		{name: vaultFileName, path: filepath.Join(dataDir, vaultFileName)},
		{name: vault.KeyringFileName, path: filepath.Join(dataDir, vault.KeyringFileName), keyring: true},
	}
	var todo []migrateFile
	for _, f := range all {
		info, err := vault.Inspect(f.path)
		if err != nil {
			_, _ = fmt.Fprintf(out, "vault %s: %s is unreadable: %s\n", op, f.name, logx.Redact(err.Error()))
			return nil, exitNewerFormat
		}
		if info.Format == vault.FormatV2 {
			todo = append(todo, f)
		}
	}
	if len(todo) == 0 {
		_, _ = fmt.Fprintf(out, "vault %s: nothing in %s is v2: nothing to downgrade\n", op, dataDir)
		return nil, 0
	}
	return todo, 0
}
