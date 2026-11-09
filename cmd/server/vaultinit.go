package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"claude-utilities/internal/logx"
	"claude-utilities/internal/vault"
)

// This file holds `server vault init`, the one command that creates a v2 vault and keyring. Nothing
// else in this binary can: create-on-open stays v1 for good (see vault.Open), the write path
// branches on whether the file arrived with a data key rather than on a flag, and the creator in
// internal/vault is reachable only from here.
//
// The order is every mutator's, and `init` has the same reasons for it:
//
//	lock -> refuse an existing file -> choose the machine slot -> passphrase -> settle -> journal ->
//	create -> verify -> clear the journal
//
// The refusals are grouped at the front deliberately. The two that cost nothing - a file already
// there, and a host with no machine key - land before the passphrase prompt, so an operator is not
// asked to invent a passphrase for a command that was going to refuse anyway. The passphrase is
// never a flag and never invented: CLAUDESWAP_KEY for a scripted run, else a prompt with no echo,
// confirmed twice at a terminal.
//
// What `init` does NOT do in this slice, stated rather than implied: it does not CREATE host key
// material. A kek-file slot is wrapped under the KEK this host already resolves - a unit's
// credential, CLAUDESWAP_KEK_FILE, or the credstore entry when run as root. Generating 32 new bytes,
// writing the credstore entry and the unit drop-in, choosing the rung and running a daemon-reload
// belong to the installer's KEK writer (`SelectRung`/`RenderKEKDropIn`), which is not in this binary
// yet. So is the pin-continuity line: reading the TLS fingerprint without being able to CREATE a
// pair needs a read-only accessor internal/hub does not export, and `migrate` is the command whose
// spec requires it. Until both land, this command says what it wrapped under and names what owns
// the rest, rather than printing a rung it did not choose.

// vaultInit creates vault.bin and tunnelkeys.bin as fresh v2 files. dryRun prints the plan and
// writes nothing - not a file, not a journal, not a byte in the data dir - and plainKEK selects the
// rung for the command that creates a KEK, which is not this one (see the file comment).
//
// It returns the process exit code: 0 created or planned; 2 a refusal the operator fixes by changing
// what is there or what they typed; 3 a file that no slot opened once it existed, or one of whose
// slots did not; 1 anything else, including a file that opened and whose payload would not parse.
func vaultInit(dataDir string, dryRun, plainKEK bool, stdin io.Reader, out io.Writer) int {
	const op = "init"
	lock, err := vault.AcquireLock(dataDir, op)
	if err != nil {
		_, _ = fmt.Fprintf(out, "vault %s: %s\n", op, logx.Redact(err.Error()))
		if errors.Is(err, vault.ErrLockHeld) {
			return exitUsage
		}
		return exitRuntime
	}
	defer func() { _ = lock.Release() }()

	// Before the settle, deliberately, and it is the one place in this binary where a refusal comes
	// before an interrupted operation is dealt with. `init` is for a data dir with NEITHER file, so a
	// file being there means this command is the wrong one whatever a journal says - and settling
	// first would mean a command that is about to refuse had already changed the directory. The
	// journal is not lost by it: the message sends the operator to `vault status`, which reports it,
	// and the mutator that actually owns the state (`migrate`, or a slot operation) settles it.
	if code := refuseAnExistingFile(dataDir, op, out); code != 0 {
		return code
	}
	machine, note, merr := machineSlotForHost()
	if merr != nil {
		_, _ = fmt.Fprintf(out, "vault %s: %s\n", op, logx.Redact(merr.Error()))
		// ErrKEKUnreachable is exit 2 here and exit 3 in `vault verify`, on purpose: see
		// mutatorExitCode's comment (vaultslots.go). An operator running `init` has a setup step to
		// take (2); a `verify` reporting the same state is reporting a vault nothing can open (3).
		return mutatorExitCode(merr)
	}
	if plainKEK {
		_, _ = fmt.Fprintf(out, "vault %s: --plain-kek selects the rung for the command that CREATES a KEK; "+
			"this command wraps under the key this host already resolves\n", op)
	}

	reader := newPassphraseReader(stdin, out)
	pass, err := readInitPassphrase(reader)
	if err != nil {
		_, _ = fmt.Fprintf(out, "vault %s: %s\n", op, logx.Redact(err.Error()))
		return exitUsage
	}
	ks := vault.WithMachineKeys(typedKey{pass: pass}, hostKeyOptions())

	// A journal in a data dir with no vault means a previous `init` did not finish. Settled or
	// refused before anything is written, exactly as every other mutator does it.
	if code := settleJournal(dataDir, op, ks, out); code != 0 {
		return code
	}

	if dryRun {
		printInitPlan(dataDir, machine, note, out)
		return 0
	}

	// (i) The journal, before the first write, naming both files. `init` never deals with a recovery
	// copy - there is none beside a file that does not exist yet - so ResealsBak is false and the
	// settle for an interrupted `init` removes nothing. See vault.VaultOp.ResealsBak.
	started := vault.VaultOp{Op: op, Files: []string{vaultFileName, vault.KeyringFileName},
		Stage: vault.StageStarted}
	if err := vault.WriteVaultOp(dataDir, started); err != nil {
		_, _ = fmt.Fprintf(out, "vault %s: %s\n", op, logx.Redact(err.Error()))
		return exitRuntime
	}
	infos, err := vault.InitV2(dataDir, pass, machine, ks)
	if err != nil {
		// InitV2 either created both files or left the directory as it found it - a file it created
		// before a later failure is removed again - so there is nothing for a settle to finish, and a
		// journal left behind would make the next command settle an operation that did not happen.
		clearJournalFn(dataDir, op, out)
		_, _ = fmt.Fprintf(out, "vault %s: %s\n", op, logx.Redact(err.Error()))
		return mutatorExitCode(err)
	}
	// (iii) Both files are in place; only the journal is left. Advanced before the verify and before
	// the clear, because this is the window in which a crash would otherwise leave a journal at
	// `started` beside two files that exist - which a settle would report as "reverted".
	advanced := started
	advanced.Stage = vault.StageRenamed
	if err := vault.WriteVaultOp(dataDir, advanced); err != nil {
		_, _ = fmt.Fprintf(out, "vault %s: the journal could not be advanced: %s\n", op, logx.Redact(err.Error()))
	}

	for _, info := range infos {
		_, _ = fmt.Fprintf(out, "vault %s: %s created as %s, dek %s\n", op, info.Name, info.Format, info.DEKID)
		for _, s := range info.Slots {
			_, _ = fmt.Fprintf(out, "  slot %s type %s%s created %s\n", s.ID, s.Type, slotScopeOrName(s), s.Created)
		}
	}
	if code := verifyAfterInit(dataDir, pass, out); code != 0 {
		return code
	}
	// Through the seam runMutation's last step uses, so the stage the journal carries when it goes is
	// observable from a test. See clearJournalFn and TestInitAdvancesTheJournalBeforeClearingIt.
	clearJournalFn(dataDir, op, out)

	_, _ = fmt.Fprintf(out, "vault %s: machine slot %s\n", op, note)
	_, _ = fmt.Fprintf(out, "vault %s: the passphrase is the recovery key for both files; it is the only way "+
		"back in if this host's machine key is lost. It is not stored anywhere.\n", op)
	reportTLSState(dataDir, op, out)
	auditLine(out, op, "", machine.Type, "created", 0)
	return 0
}

// refuseAnExistingFile refuses while either file is there, in any format, and names which command
// owns the state it found. `init` is for a data dir with none: a v1 file is `migrate`'s, a v2 file
// needs nothing, and a half-initialised dir (one file, not the other) is the state a crash leaves
// and not one to create a fresh file beside.
//
// The format is read from the header, so this costs no key and no prompt. The create itself refuses
// again, atomically, on the file's existence - including a zero-byte file this check reads as absent.
func refuseAnExistingFile(dataDir, op string, out io.Writer) int {
	names := []string{vaultFileName, vault.KeyringFileName}
	formats := make([]string, len(names))
	found := 0
	for i, name := range names {
		info, err := vault.Inspect(filepath.Join(dataDir, name))
		if err != nil {
			_, _ = fmt.Fprintf(out, "vault %s: %s is there and unreadable: %s\n", op, name, logx.Redact(err.Error()))
			_, _ = fmt.Fprintf(out, "vault %s: nothing was written; run `server vault status`\n", op)
			return exitUsage
		}
		if info.Format == vault.FormatAbsent {
			continue
		}
		formats[i] = string(info.Format)
		found++
	}
	if found == 0 {
		return 0
	}
	// A keyring with no vault beside it gets its own sentence, because neither command the other
	// message names is the operator's next step there: `migrate` needs a vault to migrate, and
	// "nothing at all" is wrong about a dir missing the file every account lives in. It is also the
	// one shape that cannot be an ordinary data dir - a host that never ran with --tunnels has
	// vault.bin and no keyring, which is normal and belongs to `migrate` like any other vault.
	if formats[0] == "" {
		_, _ = fmt.Fprintf(out, "vault %s: %s is there (%s) and %s is not, and there is no sequence "+
			"of commands that writes a keyring without a vault: nothing was written. Read `server "+
			"vault status`, then move %s out of the data dir by hand before running `init` again\n",
			op, names[1], formats[1], names[0], names[1])
		return exitUsage
	}
	_, _ = fmt.Fprintf(out, "vault %s: %s is already there (%s), so there is nothing to create: "+
		"use `server vault migrate` for a v1 file, and nothing at all for a v2 one\n",
		op, names[0], formats[0])
	return exitUsage
}

// machineSlotForHost names the machine slot this host can have, and the line the command prints
// about it. It is taken from the openers this host actually resolves rather than from a GOOS test,
// which is how the rest of this code decides the same question: dpapiOpener answers nil off Windows
// and kekFileOpener answers nil when no KEK resolves, and HostKeys returns them in try order - so
// the first machine opener on the list IS this host's machine key.
//
// A host with none is ErrKEKUnreachable and not ErrBadKey: nothing here is a wrong key, there is no
// key, and the fix is the installer's KEK step rather than a passphrase.
func machineSlotForHost() (vault.Slot, string, error) {
	for _, opener := range vault.HostKeys(hostKeyOptions()) {
		switch opener.Type() {
		case slotTypeDPAPI:
			return vault.Slot{Type: slotTypeDPAPI},
				slotTypeDPAPI + " (machine scope): the protector holds its own key, so there is no key file " +
					"to lose, to back up by accident, or to leave readable", nil
		case slotTypeKEKFile:
			return vault.Slot{Type: slotTypeKEKFile},
				slotTypeKEKFile + ": wrapped under the KEK this host already resolves. It does NOT protect " +
					"a backup that sweeps the key's location as well as the data dir, and nothing but " +
					"full-disk encryption protects a disk image", nil
		}
	}
	return vault.Slot{}, "", fmt.Errorf("%w: this host resolves no machine key, so there is nothing for a "+
		"machine slot to wrap under; create the host key first, then run `server vault init`", vault.ErrKEKUnreachable)
}

// readInitPassphrase is the passphrase `init` CREATES. CLAUDESWAP_KEY wins, because that is the
// scripted path the installers and the e2e scripts take and a command that prompted anyway would
// hang in a script; otherwise it is typed with no echo and confirmed. It is never a flag, and it is
// never invented: an empty answer is a refusal, not a generated value.
//
// The confirmation is a terminal's. A pipe cannot be asked twice - asking would consume the next
// line, or block - so there it is one line, which is the rule `set-password` and every other
// passphrase in this binary already follow.
func readInitPassphrase(r *passphraseReader) (string, error) {
	if pass := os.Getenv(keyEnv); pass != "" {
		return pass, nil
	}
	return r.read("New vault passphrase (not echoed): ", true)
}

// verifyAfterInit proves both files before the command claims success, with the two checks that mean
// different things. The machine slot ALONE answers "can the service start with nobody at the
// keyboard"; every slot in turn answers "is each key good". A created vault nobody proved is a vault
// whose first failure is a restart, which is the thing this command exists to prevent.
func verifyAfterInit(dataDir, pass string, out io.Writer) int {
	checks := []struct {
		label    string
		ks       vault.KeySource
		allSlots bool
	}{
		// No passphrase at all, not an empty one: exactly what a service has.
		{"the machine slot alone", vault.WithMachineKeys(nil, hostKeyOptions()), false},
		{"every slot in turn", vault.WithMachineKeys(typedKey{pass: pass}, hostKeyOptions()), true},
	}
	for _, c := range checks {
		for _, name := range []string{vaultFileName, vault.KeyringFileName} {
			res, err := vault.VerifyFile(filepath.Join(dataDir, name), c.ks, c.allSlots)
			// Which slots opened, before the payload, and only for the all-slots check. VerifyFile
			// takes the data key from the FIRST slot that gives it up and the machine slot is tried
			// first, so PayloadOK says the file opened and nothing about the slots after the one that
			// opened it. Without this the printed line "opens under every slot in turn" would be true
			// of a file whose passphrase slot does not open - which is the recovery rung this command
			// prints a paragraph about, and the one failure an operator cannot discover later.
			if err == nil && c.allSlots {
				if shut := slotsThatDidNotOpen(res); len(shut) > 0 {
					_, _ = fmt.Fprintf(out, "vault init: %s opened, but %d of its slots did not: %s\n",
						name, len(shut), strings.Join(shut, ", "))
					_, _ = fmt.Fprintln(out, "vault init: both files were created and a key this command "+
						"just wrote does not open one of them. The journal is left in place; run "+
						"`server vault verify --all-slots`.")
					return exitVaultLocked
				}
			}
			if err != nil || !res.PayloadOK {
				_, _ = fmt.Fprintf(out, "vault init: %s did NOT open under %s: %s\n", name, c.label,
					logx.Redact(errText(err)))
				_, _ = fmt.Fprintln(out, "vault init: both files were created and one of them does not open as "+
					"expected. The journal is left in place; run `server vault verify --all-slots`.")
				if err != nil {
					return mutatorExitCode(err)
				}
				// A false PayloadOK with no error of its own means the payload decrypted and did not
				// parse. That is not "no slot opened it" (3) - a slot did - so it is the runtime code,
				// and the exit table below says so.
				return exitRuntime
			}
			_, _ = fmt.Fprintf(out, "vault init: %s opens under %s (%d entries)\n", name, c.label, res.Entries)
		}
	}
	return 0
}

// slotsThatDidNotOpen names the slots a verify handed a key to and could not open. It is the half of
// a VerifyResult that PayloadOK cannot carry: the payload opens under one key, and this is every
// other key the same header promised.
//
// A slot of a type this binary does not know is left out: it was never handed a key - VerifyFile
// records a reason for it instead of an attempt - so counting it would refuse a file for carrying a
// slot a newer server wrote. Every other slot counts, a machine slot this host cannot reach
// included, because the caller is `init`: it created both slots itself a moment ago, under a
// passphrase this run read and a machine key it proved on a throwaway wrap before the first byte.
// On that path there is no honest reason for a known slot not to open.
func slotsThatDidNotOpen(res vault.VerifyResult) []string {
	known := make(map[string]bool, len(res.File.Slots))
	for _, s := range res.File.Slots {
		known[s.ID] = s.Known
	}
	shut := make([]string, 0, len(res.Tried))
	for _, r := range res.Tried {
		if known[r.ID] && !r.Opened {
			shut = append(shut, r.ID)
		}
	}
	return shut
}

// errText is an error's message, or a stand-in when a check failed with no error of its own (a
// payload that did not parse). A printed empty string would read as a blank reason.
func errText(err error) string {
	if err == nil {
		return "the payload did not parse"
	}
	return err.Error()
}

// printInitPlan says what a real run would do and that this one did nothing. Everything in it is
// read from the header, the file names and this host's openers - no key, no wrap, no path to key
// material - so a dry run on a host an operator cannot afford to guess about costs them nothing.
func printInitPlan(dataDir string, machine vault.Slot, note string, out io.Writer) {
	_, _ = fmt.Fprintf(out, "vault init: dry run, nothing was written to %s\n", dataDir)
	_, _ = fmt.Fprintf(out, "  would create %s as %s and %s as %s\n",
		vaultFileName, vault.FormatV2, vault.KeyringFileName, vault.FormatV2)
	_, _ = fmt.Fprintf(out, "  each with one %s slot (the recovery key) and one %s slot\n",
		slotTypePassphrase, machine.Type)
	_, _ = fmt.Fprintf(out, "  machine slot %s\n", note)
	_, _ = fmt.Fprintln(out, "  the passphrase would be the one in "+keyEnv+" or the one typed at the prompt; "+
		"it is never invented and never stored")
	_, _ = fmt.Fprintln(out, "  both files would then be opened with the machine slot alone and with every slot "+
		"in turn, before the command reports success")
	reportTLSState(dataDir, "init", out)
}

// reportTLSState says whether the TLS pair every enrolled agent pins is already there. `init` never
// writes under tls/ and never changes a pin, and an operator who was not told would reasonably
// wonder: a command that creates the vault looks like a command that creates the identity.
//
// It reports presence and not the fingerprint. Reading the pin needs an accessor internal/hub does
// not export, and the only exported route (EnsureCert) CREATES a pair when there is none - which is
// precisely what this command must not do to a data dir.
func reportTLSState(dataDir, op string, out io.Writer) {
	path := filepath.Join(dataDir, "tls", "server-cert.pem")
	//nolint:gosec // G703: the data dir is the operator's own --data-dir and the rest of the path is
	// two literals. Saying whether the pair in the directory they named is there is the whole point;
	// there is no untrusted component to traverse with, and filepath.Join already cleans.
	if _, err := os.Stat(path); err == nil {
		_, _ = fmt.Fprintf(out, "vault %s: tls/ is already there and was NOT touched, so the pin every enrolled "+
			"agent holds is unchanged\n", op)
		return
	}
	_, _ = fmt.Fprintf(out, "vault %s: there is no tls/ yet; the first `server run` creates the pair and prints "+
		"the sha256 agents pin with --pin\n", op)
}

// slotScopeOrName is the one extra word a slot line carries: a dpapi slot's scope or a kek-file
// slot's credential name. Never a path - the slot stores a name so there is one place the truth
// lives - and never a wrap.
func slotScopeOrName(s vault.SlotInfo) string {
	switch {
	case s.Scope != "":
		return " scope " + s.Scope
	case s.Name != "":
		return " name " + s.Name
	}
	return ""
}
