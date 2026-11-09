package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"claude-utilities/internal/logx"
	"claude-utilities/internal/vault"
)

// This file holds the two commands that delete the copies a migration leaves behind:
// `finalize-migration` and `purge-backups`. They differ in exactly one thing - which copies they
// consider theirs - and they share the gate that matters.
//
// The gate: BOTH keys must open every live file, before anything is deleted. Not one of them. A
// data dir whose machine slot works and whose passphrase does not is a data dir one lost host away
// from being unopenable, and deleting the v1 copies there is the Anti-goal ("a migration that
// leaves the vault openable by neither key") reached a fortnight later by a different command. So
// the check is the machine slot ALONE (the service's question) and then every slot in turn (is each
// key good), and either failing aborts with nothing deleted.
//
// Why they exist at all. Every `*.v1.<ts>`, every renamed `*.bak.v1.<ts>` and every pre-migration
// `.bak` is a passphrase-only envelope holding every account. They keep the whole vault openable by
// the passphrase alone for as long as they sit there, which is precisely what the v2 design exists
// to stop relying on. They are never deleted automatically and `status` names them with their age.
//
// What is NOT claimed: "securely". The files are unlinked, and their content was already encrypted.
// No overwrite pass is attempted and none is implied - on an SSD or on NTFS an overwrite proves
// nothing, and the spec says so in those words.
//
// Not here, and deliberately: `purgeDataDir` (the data dir wipe behind `service uninstall --purge`,
// with `tls/` kept unless `--purge-tls`). It has no caller until `server service uninstall` exists
// in slice 4 and it is that command's gate, its second typed confirmation and its hosts.json count
// that give it meaning. Building it here would ship an untestable flag surface ahead of the command
// that owns it.

// retentionMode says which copies a command may delete.
type retentionMode int

const (
	// finalizeV1Only is `finalize-migration`: the v1 artefacts and nothing else. A v2 `.bak` and a
	// `*.v2.<ts>` generation are left alone, which is the difference the spec draws between the two
	// commands - finalize is "the migration is over", not "tidy the directory".
	finalizeV1Only retentionMode = iota
	// purgeEveryGeneration is `purge-backups`: every `*.v1.<ts>`, every `*.v2.<ts>` left by a
	// downgrade, and `.bak` of either format. It exists because a v2 `.bak` or a `*.v2.<ts>` still
	// opens with a key `remove-slot` has since taken away, which finalize deliberately does not touch.
	purgeEveryGeneration
)

// vaultFinalizeMigration deletes the v1 copies a migration left, once both keys are proved. It is
// the command `migrate` names with a date 14 days out.
func vaultFinalizeMigration(dataDir string, stdin io.Reader, out io.Writer) int {
	return runRetention(dataDir, "finalize-migration", finalizeV1Only, false, stdin, out)
}

// vaultPurgeBackups deletes every generation of both files, in either format, once both keys are
// proved. keepBak spares the `.bak` beside each live file - the one-generation undo for a `Delete`
// or a `ReplaceBlock` an operator regrets on the spot.
func vaultPurgeBackups(dataDir string, keepBak bool, stdin io.Reader, out io.Writer) int {
	return runRetention(dataDir, "purge-backups", purgeEveryGeneration, keepBak, stdin, out)
}

// runRetention is the one path both commands take:
//
//	lock -> passphrase -> settle or refuse -> prove BOTH keys open every live file -> delete -> print
//
// No journal is written. A deletion is not a multi-file state change that can be half done: each
// unlink either happened or did not, nothing else in the data dir depends on it, and a journal would
// only give the next mutator an operation to settle that needs no settling. The settle of someone
// ELSE's interrupted operation still runs first, because deleting the copies that an interrupted
// rotation might be the only way back from is the worst possible moment to be wrong.
func runRetention(dataDir, op string, mode retentionMode, keepBak bool, stdin io.Reader, out io.Writer) int {
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
	pass, err := readExistingPassphrase(newPassphraseReader(stdin, out))
	if err != nil {
		_, _ = fmt.Fprintf(out, "vault %s: %s\n", op, logx.Redact(err.Error()))
		return exitUsage
	}
	ks := vault.WithMachineKeys(typedKey{pass: pass}, hostKeyOptions())
	if code := settleJournal(dataDir, op, ks, out); code != 0 {
		return code
	}
	if code := requireBothKeys(dataDir, pass, op, out); code != 0 {
		return code
	}
	victims := retentionVictims(dataDir, mode, keepBak)
	if len(victims) == 0 {
		_, _ = fmt.Fprintf(out, "vault %s: there is nothing to remove\n", op)
		auditLine(out, op, "", "", "nothing-to-remove", 0)
		return 0
	}
	removed, failed := 0, 0
	for _, v := range victims {
		//nolint:gosec // G703: v.name came from os.ReadDir(dataDir) and then through
		// isVaultGenerationName, which refuses any name that is not a plain base name beginning with
		// one of the two literal file names. Deleting a stored generation of those two files in the
		// directory the operator named is exactly what the command does.
		if err := os.Remove(filepath.Join(dataDir, v.name)); err != nil {
			_, _ = fmt.Fprintf(out, "vault %s: %s could NOT be removed: %s\n", op, v.name, logx.Redact(err.Error()))
			failed++
			continue
		}
		_, _ = fmt.Fprintf(out, "vault %s: removed %s (%s)\n", op, v.name, v.format)
		removed++
	}
	_, _ = fmt.Fprintf(out, "vault %s: %d removed, %d left behind\n", op, removed, failed)
	if failed > 0 {
		// Non-zero, because a copy that is still there still opens with the keys it had, and a script
		// that read 0 here would report the key removal complete when it is not.
		auditLine(out, op, "", "", "partial", exitRuntime)
		return exitRuntime
	}
	_, _ = fmt.Fprintf(out, "vault %s: the files were unlinked and their content was already encrypted. No "+
		"overwrite pass was attempted and none is claimed: on an SSD or on NTFS an overwrite proves "+
		"nothing. Copies you made elsewhere - a backup, another folder - are untouched and still open\n", op)
	auditLine(out, op, "", "", "removed", 0)
	return 0
}

// requireBothKeys is the gate. It proves, for every live file that is there, that the machine slot
// opens it with no passphrase at all AND that every slot in the header opens it.
//
// The second check is not the first one repeated. VerifyFile takes the data key from the FIRST slot
// that gives it up and the machine slot is tried first, so without --all-slots a file whose
// passphrase slot is broken verifies clean - and the passphrase slot is the rung these commands are
// about to delete the alternative to.
func requireBothKeys(dataDir, pass, op string, out io.Writer) int {
	checks := []struct {
		label    string
		ks       vault.KeySource
		allSlots bool
	}{
		// No passphrase at all, not an empty one: exactly what a service has.
		{"the machine slot alone", vault.WithMachineKeys(nil, hostKeyOptions()), false},
		{"every slot in turn", vault.WithMachineKeys(typedKey{pass: pass}, hostKeyOptions()), true},
	}
	for _, name := range []string{vaultFileName, vault.KeyringFileName} {
		path := filepath.Join(dataDir, name)
		info, ierr := vault.Inspect(path)
		if ierr != nil {
			_, _ = fmt.Fprintf(out, "vault %s: %s is unreadable: %s\n", op, name, logx.Redact(ierr.Error()))
			_, _ = fmt.Fprintf(out, "vault %s: nothing was removed\n", op)
			return mutatorExitCode(ierr)
		}
		switch info.Format {
		case vault.FormatAbsent:
			// The keyring is optional; the vault is not. A missing vault with copies beside it is
			// exactly the state those copies are for, so this refuses rather than tidying them away.
			if name == vaultFileName {
				_, _ = fmt.Fprintf(out, "vault %s: there is no %s to prove, and the copies beside it may be "+
					"the only ones left: nothing was removed. Restore one and run `server vault verify "+
					"--all-slots`\n", op, name)
				return exitUsage
			}
			continue
		case vault.FormatV1:
			_, _ = fmt.Fprintf(out, "vault %s: %s is still v1, so there is no machine slot to prove and "+
				"these copies are not leftovers: nothing was removed. Run `server vault migrate` first\n",
				op, name)
			return exitNewerFormat
		}
		for _, c := range checks {
			res, verr := vault.VerifyFile(path, c.ks, c.allSlots)
			if verr != nil || !res.PayloadOK {
				_, _ = fmt.Fprintf(out, "vault %s: %s does NOT open under %s: %s\n", op, name, c.label,
					logx.Redact(errText(verr)))
				_, _ = fmt.Fprintf(out, "vault %s: nothing was removed. Both keys have to work before the "+
					"copies that are the way back go away\n", op)
				if verr != nil {
					return mutatorExitCode(verr)
				}
				return exitRuntime
			}
			if c.allSlots {
				if shut := slotsThatDidNotOpen(res); len(shut) > 0 {
					_, _ = fmt.Fprintf(out, "vault %s: %s opened, but %d of its slots did not: %s\n",
						op, name, len(shut), strings.Join(shut, ", "))
					_, _ = fmt.Fprintf(out, "vault %s: nothing was removed; run `server vault verify "+
						"--all-slots`\n", op)
					return exitVaultLocked
				}
			}
			_, _ = fmt.Fprintf(out, "vault %s: %s opens under %s (%d entries)\n", op, name, c.label, res.Entries)
		}
	}
	return 0
}

// retentionArtefact is one file a retention command would delete, with the format to print beside it.
type retentionArtefact struct {
	name   string
	format string
}

// retentionVictims is the set of files the mode may delete, sorted by name so the printed order is
// the order `status` lists them in.
//
// Every candidate has to be a generation of one of the two live files - the name starts with
// `vault.bin` or `tunnelkeys.bin` - which is isV1ArtefactName's rule and the guard that keeps a
// command whose name says "backups" away from `admin-password.json`, `hosts.json`, `tls/`, the lock
// and the journal. The live files themselves are excluded by the same predicate.
func retentionVictims(dataDir string, mode retentionMode, keepBak bool) []retentionArtefact {
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return nil
	}
	var out []retentionArtefact
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		name := e.Name()
		if !isVaultGenerationName(name) {
			continue
		}
		isBak := strings.HasSuffix(name, ".bak")
		if isBak && keepBak {
			continue
		}
		info, ierr := vault.Inspect(filepath.Join(dataDir, name))
		format := info.Format
		if ierr != nil {
			// A generation this binary cannot parse is still a generation: purge removes it (that is
			// what the command is for), and finalize leaves it, because finalize only ever claims to
			// remove v1 artefacts and it cannot tell that this is one.
			format = "unreadable"
		}
		if mode == finalizeV1Only && format != vault.FormatV1 {
			continue
		}
		out = append(out, retentionArtefact{name: name, format: format})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// isVaultGenerationName reports whether a file name is a stored generation of one of the two live
// files: a `*.v1.<ts>` or `*.v2.<ts>` copy, or a `.bak`. It is isV1ArtefactName's superset - that
// one is what `status` lists and is restricted to the v1 shapes - and both are in one place so the
// set `status` shows and the set these commands delete cannot drift apart.
func isVaultGenerationName(name string) bool {
	if name == vaultFileName || name == vault.KeyringFileName {
		return false
	}
	// A plain base name and nothing else. os.ReadDir cannot produce anything else, so this is belt
	// and braces - but it is the guard the delete's nolint comment rests on, and a later caller that
	// hands this predicate a path should get false rather than a deletion outside the data dir.
	if name != filepath.Base(name) || strings.ContainsAny(name, `/\:`) {
		return false
	}
	if !strings.HasPrefix(name, vaultFileName) && !strings.HasPrefix(name, vault.KeyringFileName) {
		return false
	}
	return strings.Contains(name, ".v1.") || strings.Contains(name, ".v2.") ||
		strings.HasSuffix(name, ".bak")
}
