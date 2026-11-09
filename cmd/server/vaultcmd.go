package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"claude-utilities/internal/logx"
	"claude-utilities/internal/vault"
)

// This file holds the `vault` subcommand's dispatch and its two read-only commands, `status` and
// `verify`. The four mutators are vaultslots.go; everything they share - the data-dir lock, the
// vaultop journal, the passphrase seams and the exit-code mapping - lives here.
//
// `status` and `verify` take NO lock, deliberately: they are the two commands an operator runs on a
// server that will not start, and a command that refuses because the thing it is diagnosing holds a
// lock is a command nobody can use. Every mutator takes the lock for the length of the command.

// vaultUsage is the `vault` command summary. The passphrase appears in no line of it, because
// there is no flag for it anywhere: argv is visible to every process on the host.
const vaultUsage = `usage: server vault <subcommand> [--data-dir DIR]
  status                        what is in the data dir: formats, slots by type and id, which slots
                                this host holds a key for, v1 copies with their age, and any
                                interrupted operation. Read-only, takes no lock.
  verify [--all-slots]          open the live files and report which slot opened each. Read-only and
                                safe while the service is up. By default only the machine slots are
                                tried; --all-slots also asks for the passphrase and opens with every
                                slot in turn. Never prints payload.
  init [--dry-run]              create vault.bin and tunnelkeys.bin as v2, each with a passphrase
       [--plain-kek]            slot and this host's machine slot. Only for a data dir with neither
                                file: a v1 file belongs to migrate, a v2 file needs nothing.
                                --dry-run prints the plan and writes nothing at all.
  migrate [--dry-run]           rewrite a v1 vault.bin and tunnelkeys.bin as v2, keeping a verified
          [--add TYPE]          byte copy of each as <name>.v1.<ts> first. The passphrase is
          [--plain-kek]          re-wrapped, never changed. Already v2 exits 0 with nothing done.
                                --dry-run prints the plan and writes nothing at all; --add picks the
                                machine slot type (dpapi or kek-file) instead of this host's default.
  downgrade                     write v1 files again with the passphrase, keeping each v2 file's
                                bytes as <name>.v2.<ts>. The rollback the passphrase slot exists for.
  finalize-migration            delete the v1 copies a migration left, after proving BOTH the machine
                                slot and the passphrase open every live file. Advisable after 14 days.
  purge-backups [--keep-bak]    delete every stored generation of both files, v1 and v2, and the
                                .bak unless --keep-bak. Same both-keys gate as finalize-migration.
  add-slot --type TYPE          add a key slot wrapping the CURRENT data key: passphrase, dpapi or
          [--plain-kek]         kek-file. Every existing key keeps working.
  remove-slot --id SLOTID       remove one slot AND rotate the data key, so the removed key opens
                                nothing current. Refuses the last passphrase slot.
  rotate                        new data key, re-wrapped into every slot. Every slot's key must be
                                reachable; there is no flag that drops one (that is remove-slot).
  change-passphrase             re-wrap the same data key under a new passphrase.

The passphrase is read from CLAUDESWAP_KEY, or prompted with no echo; it is never a flag.
Slot operations need the service stopped: they take <data-dir>/.claude-swap.lock.`

// vaultFileName is the account vault's name inside the data dir, which every command here joins.
const vaultFileName = "vault.bin"

// serviceDataDir reports the data dir the registered service was installed with, and whether there
// is one. Decision 10 makes the service's own configuration the source of truth when --data-dir is
// absent, so console, CLI and service agree on one vault.
//
// It is a seam, and today it always answers "no service": reading the SCM's BinaryPathName (and the
// unit's ExecStart= on Linux) belongs with `server service install`, which registers the service in
// the first place. Until then every command falls back to today's default and nothing changes.
var serviceDataDir = func() (string, bool, error) { return "", false, nil }

// dataDirFromFlagOrService resolves which data dir a vault command works on: the flag if it was
// given, else the registered service's, else today's default. fromService says which, so a command
// can print where the value came from rather than leaving an operator to guess which vault they
// just changed.
func dataDirFromFlagOrService(flagValue string) (string, bool, error) {
	if flagValue != "" {
		return flagValue, false, nil
	}
	dir, ok, err := serviceDataDir()
	if err != nil {
		return "", false, err
	}
	if ok && dir != "" {
		return dir, true, nil
	}
	return defaultDataDir(), false, nil
}

// vaultCmd dispatches `server vault <subcommand>`. It is reached from run's fixed subcommand name
// set, so it never sees the console run's flags.
//
// out and errOut are the same writer in production, and that writer is os.Stderr: main() passes it
// as both, exactly as `cert renew` is called. So `server vault status > file` captures nothing
// today - the output is on stderr. It is deliberate rather than overlooked: giving these commands a
// real stdout means changing run's signature, which every existing test of it passes five arguments
// to, and the plan's Interfaces fix these signatures. Whoever adds `server service` (Task 4.5) is
// threading a stdout through anyway and should take this with it.
func vaultCmd(args []string, stdin io.Reader, out, errOut io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(errOut, vaultUsage)
		return exitUsage
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "status":
		return withDataDir(sub, rest, nil, out, errOut, func(dataDir string, _ *flag.FlagSet) int {
			return vaultStatus(dataDir, out)
		})
	case "verify":
		var allSlots bool
		return withDataDir(sub, rest, func(fs *flag.FlagSet) {
			fs.BoolVar(&allSlots, "all-slots", false, "also ask for the passphrase and open with every slot in turn")
		}, out, errOut, func(dataDir string, _ *flag.FlagSet) int {
			return vaultVerify(dataDir, allSlots, stdin, out)
		})
	case "init":
		var dryRun, plainKEK bool
		return withDataDir(sub, rest, func(fs *flag.FlagSet) {
			fs.BoolVar(&dryRun, "dry-run", false, "print what would be created and write nothing at all")
			fs.BoolVar(&plainKEK, "plain-kek", false, "on Linux, select the plain root-owned credstore file rather than an encrypted credential")
		}, out, errOut, func(dataDir string, _ *flag.FlagSet) int {
			return vaultInit(dataDir, dryRun, plainKEK, stdin, out)
		})
	case "migrate":
		var dryRun, plainKEK bool
		var add string
		return withDataDir(sub, rest, func(fs *flag.FlagSet) {
			fs.BoolVar(&dryRun, "dry-run", false, "print what would be migrated and write nothing at all")
			fs.StringVar(&add, "add", "", "the machine slot type to add: dpapi or kek-file (default: this host's)")
			fs.BoolVar(&plainKEK, "plain-kek", false, "on Linux, select the plain root-owned credstore file rather than an encrypted credential")
		}, out, errOut, func(dataDir string, _ *flag.FlagSet) int {
			return vaultMigrate(dataDir, dryRun, add, plainKEK, stdin, out)
		})
	case "downgrade":
		return withDataDir(sub, rest, nil, out, errOut, func(dataDir string, _ *flag.FlagSet) int {
			return vaultDowngrade(dataDir, stdin, out)
		})
	case "finalize-migration":
		return withDataDir(sub, rest, nil, out, errOut, func(dataDir string, _ *flag.FlagSet) int {
			return vaultFinalizeMigration(dataDir, stdin, out)
		})
	case "purge-backups":
		var keepBak bool
		return withDataDir(sub, rest, func(fs *flag.FlagSet) {
			fs.BoolVar(&keepBak, "keep-bak", false, "keep the .bak beside each live file")
		}, out, errOut, func(dataDir string, _ *flag.FlagSet) int {
			return vaultPurgeBackups(dataDir, keepBak, stdin, out)
		})
	case "add-slot":
		var slotType string
		var plainKEK bool
		return withDataDir(sub, rest, func(fs *flag.FlagSet) {
			fs.StringVar(&slotType, "type", "", "passphrase, dpapi or kek-file")
			fs.BoolVar(&plainKEK, "plain-kek", false, "on Linux, select the plain root-owned credstore file rather than an encrypted credential")
		}, out, errOut, func(dataDir string, _ *flag.FlagSet) int {
			return vaultAddSlot(dataDir, slotType, plainKEK, stdin, out)
		})
	case "remove-slot":
		var id string
		return withDataDir(sub, rest, func(fs *flag.FlagSet) {
			fs.StringVar(&id, "id", "", "the slot id to remove, as `vault status` prints it")
		}, out, errOut, func(dataDir string, _ *flag.FlagSet) int {
			return vaultRemoveSlot(dataDir, id, stdin, out)
		})
	case "rotate":
		return withDataDir(sub, rest, nil, out, errOut, func(dataDir string, _ *flag.FlagSet) int {
			return vaultRotate(dataDir, stdin, out)
		})
	case "change-passphrase":
		return withDataDir(sub, rest, nil, out, errOut, func(dataDir string, _ *flag.FlagSet) int {
			return vaultChangePassphrase(dataDir, stdin, out)
		})
	default:
		_, _ = fmt.Fprintf(errOut, "vault: unknown subcommand %q\n", sub)
		_, _ = fmt.Fprintln(errOut, vaultUsage)
		return exitUsage
	}
}

// withDataDir parses one subcommand's flags - every one of them takes --data-dir and nothing else
// unless it says so - resolves the data dir, and runs the body. A positional argument is refused
// everywhere: every input these commands take is a flag, a prompt or an environment variable, and a
// stray word on the line is far more likely to be a mistyped flag than an intention.
func withDataDir(name string, args []string, extra func(*flag.FlagSet), out, errOut io.Writer,
	body func(dataDir string, fs *flag.FlagSet) int) int {
	fs := flag.NewFlagSet("vault "+name, flag.ContinueOnError)
	fs.SetOutput(errOut)
	dir := fs.String("data-dir", "", "the data dir holding the vault (default: the registered service's, else "+defaultDataDir()+")")
	if extra != nil {
		extra(fs)
	}
	if err := fs.Parse(args); err != nil {
		_, _ = fmt.Fprintln(errOut, vaultUsage)
		return exitUsage
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintf(errOut, "vault %s: unexpected argument %q; every input is a flag, a prompt or an environment variable\n", name, fs.Arg(0))
		return exitUsage
	}
	dataDir, fromService, err := dataDirFromFlagOrService(*dir)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "vault "+name+":", logx.Redact(err.Error()))
		return exitRuntime
	}
	if fromService {
		_, _ = fmt.Fprintf(out, "vault %s: using the registered service's data dir %s\n", name, dataDir)
	}
	return body(dataDir, fs)
}

// --- status ---

// vaultStatus prints what is in the data dir and changes nothing. It opens no file and needs no
// key: every answer comes from the headers, the file names and the journal, which is what makes it
// the first command to run against a server that will not start.
//
// It exits 0 even when what it found is bad. The exit code of a diagnosis is not the diagnosis, and
// a script that wants a verdict runs `verify`.
func vaultStatus(dataDir string, out io.Writer) int {
	_, _ = fmt.Fprintf(out, "vault status: data dir %s\n", dataDir)
	for _, name := range []string{vaultFileName, vault.KeyringFileName} {
		info, err := vault.Inspect(filepath.Join(dataDir, name))
		if err != nil {
			_, _ = fmt.Fprintf(out, "%s: unreadable: %s\n", name, logx.Redact(err.Error()))
			continue
		}
		switch info.Format {
		case vault.FormatAbsent:
			_, _ = fmt.Fprintf(out, "%s: absent\n", name)
			continue
		case vault.FormatV1:
			_, _ = fmt.Fprintf(out, "%s: v1 - run `server vault migrate` to add key slots\n", name)
			continue
		}
		_, _ = fmt.Fprintf(out, "%s: v2, dek %s, %d slots\n", name, info.DEKID, len(info.Slots))
		for _, s := range info.Slots {
			_, _ = fmt.Fprintf(out, "  slot %s type %s created %s%s\n", s.ID, s.Type, s.Created, slotNote(s))
		}
	}
	if line, mixed := vault.MixedPair(dataDir); mixed {
		_, _ = fmt.Fprintln(out, "vault status: the two files disagree about their format version")
		_, _ = fmt.Fprintln(out, "  "+line)
	}
	reportV1Artefacts(dataDir, out)
	reportJournal(dataDir, out)
	return 0
}

// slotNote is the one thing status says about a slot beyond what the header holds: whether this
// host could use it. A passphrase slot is never "held by this host" - its key is in an operator's
// head - and saying so is the difference between "the service can start" and "you will be asked for
// the passphrase".
func slotNote(s vault.SlotInfo) string {
	switch {
	case !s.Known:
		return " - UNKNOWN type: skipped on open, and it blocks `rotate` and `remove-slot` of any other slot"
	case s.Type == "passphrase":
		return " - needs the passphrase"
	case s.HostHoldsKey:
		return " - this host holds a key for it"
	default:
		return " - no key on this host for it"
	}
}

// isV1ArtefactName reports the two shapes a v1 leftover takes in a data dir: a `migrate` copy
// (`<name>.v1.<ts>`, which also covers the renamed `<name>.bak.v1.<ts>`) and a recovery copy written
// by a binary that predates v2. The caller filters by the file's actual magic, so a `.bak` that is
// already v2 is not reported here.
//
// It requires the name to be a generation of one of the two live files, which is the same guard
// isVaultGenerationName (vaultretention.go) applies - and there it is load-bearing, because that
// predicate feeds a delete. The two are kept in step deliberately: the set `status` shows an
// operator and the set `finalize-migration` removes must be the same set.
func isV1ArtefactName(name string) bool {
	if name == vaultFileName || name == vault.KeyringFileName {
		return false
	}
	if !strings.HasPrefix(name, vaultFileName) && !strings.HasPrefix(name, vault.KeyringFileName) {
		return false
	}
	return strings.Contains(name, ".v1.") || strings.HasSuffix(name, ".bak")
}

// reportV1Artefacts lists every v1 copy with its age and prints the finalize line while any exists.
// They matter because each one is a passphrase-only envelope: they keep every account openable by
// the passphrase alone for as long as they sit there, which is the thing this design exists to stop
// relying on. They are never deleted automatically.
func reportV1Artefacts(dataDir string, out io.Writer) {
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.Type().IsRegular() || !isV1ArtefactName(e.Name()) {
			continue
		}
		info, ierr := vault.Inspect(filepath.Join(dataDir, e.Name()))
		if ierr != nil || info.Format != vault.FormatV1 {
			continue
		}
		names = append(names, e.Name())
	}
	if len(names) == 0 {
		return
	}
	sort.Strings(names)
	_, _ = fmt.Fprintf(out, "v1 copies present: %d. Each is openable by the passphrase alone.\n", len(names))
	for _, name := range names {
		age := "age unknown"
		// #nosec G703 -- the data dir is the operator's own --data-dir and name came from reading it,
		// so there is no untrusted traversal here: naming the files in the directory the operator
		// asked about is the command's whole job.
		if st, serr := os.Stat(filepath.Join(dataDir, name)); serr == nil {
			age = "age " + time.Since(st.ModTime()).Round(time.Hour).String()
		}
		_, _ = fmt.Fprintf(out, "  %s (%s)\n", name, age)
	}
	_, _ = fmt.Fprintln(out, "  run `server vault finalize-migration` once the v2 files have run clean for 14 days")
}

// reportJournal names an interrupted slot operation. It never settles one: status changes nothing,
// and the settle belongs to the next mutator (or to a human, through the verify this line names).
func reportJournal(dataDir string, out io.Writer) {
	op, ok, err := vault.ReadVaultOp(dataDir)
	if err != nil {
		_, _ = fmt.Fprintf(out, "%s: present and unreadable: %s\n", vault.VaultOpFileName, logx.Redact(err.Error()))
		return
	}
	if !ok {
		return
	}
	_, _ = fmt.Fprintf(out, "%s: an interrupted %s (stage %s) spanning %s\n",
		vault.VaultOpFileName, op.Op, op.Stage, strings.Join(op.Files, ", "))
	_, _ = fmt.Fprintln(out, "  the next slot operation settles it; to look first, run `server vault verify --all-slots`")
}

// --- verify ---

// vaultVerify opens the live files and reports which slot opened each. It takes no lock and writes
// nothing, which makes it the one vault command that is safe to run while the service is up.
//
// Its exit codes are its own, and one of them differs from the service's on purpose: a malformed
// header is 2 here and 4 there. The service's 4 is an instruction to its supervisor - "a restart
// cannot fix this, stop trying" - while this is an operator running a read-only check by hand, and
// 2 is "the thing you named is not something I can read".
func vaultVerify(dataDir string, allSlots bool, stdin io.Reader, out io.Writer) int {
	ks, err := verifyKeys(allSlots, stdin, out)
	if err != nil {
		_, _ = fmt.Fprintln(out, "vault verify:", logx.Redact(err.Error()))
		return exitUsage
	}
	// worst is the highest code any file produced, and the codes are ordered by how far from a
	// working vault the state is - 2 unreadable header, 3 no slot opens, 4 wrong format - so a pair
	// with two problems reports the further one. It is deliberately not the FIRST problem: a script
	// branching on this wants one number, and the per-file lines above carry both causes for a human.
	worst := 0
	if line, mixed := vault.MixedPair(dataDir); mixed {
		_, _ = fmt.Fprintln(out, "vault verify: the two files disagree about their format version")
		_, _ = fmt.Fprintln(out, "  "+line)
		worst = exitNewerFormat
	}
	for i, name := range []string{vaultFileName, vault.KeyringFileName} {
		path := filepath.Join(dataDir, name)
		// The keyring is optional: a server that has never run with --tunnels has none, and "absent"
		// is not a failure for it. The vault is not optional.
		if i > 0 {
			if info, ierr := vault.Inspect(path); ierr == nil && info.Format == vault.FormatAbsent {
				_, _ = fmt.Fprintf(out, "%s: absent (only a --tunnels server has one)\n", name)
				continue
			}
		}
		res, verr := vault.VerifyFile(path, ks, allSlots)
		reportVerify(name, res, verr, out)
		if code := verifyExitCode(res, verr); code > worst {
			worst = code
		}
	}
	return worst
}

// reportVerify prints one file's result: its format, its dek.id prefix, every slot with what it did,
// and the payload as a count. Never a key, never a wrap, never a line of payload.
func reportVerify(name string, res vault.VerifyResult, err error, out io.Writer) {
	switch res.File.Format {
	case vault.FormatAbsent:
		_, _ = fmt.Fprintf(out, "%s: absent - run `server vault init`\n", name)
		return
	case vault.FormatV1:
		_, _ = fmt.Fprintf(out, "%s: v1 - run `server vault migrate`\n", name)
		return
	}
	_, _ = fmt.Fprintf(out, "%s: %s, dek %s, %d slots\n", name, res.File.Format, res.File.DEKID, len(res.File.Slots))
	for _, r := range res.Tried {
		_, _ = fmt.Fprintf(out, "  slot %s type %s: %s\n", r.ID, r.Type, r.Reason)
	}
	if res.PayloadOK {
		_, _ = fmt.Fprintf(out, "  payload: opened and parsed, %d entries\n", res.Entries)
		return
	}
	if err != nil {
		_, _ = fmt.Fprintf(out, "  payload: NOT verified: %s\n", logx.Redact(err.Error()))
	}
}

// verifyExitCode is this command's own table: 0 verified, 2 a header it cannot read, 3 a file no
// slot opens, 4 a file that is v1, absent or written by a newer server.
func verifyExitCode(res vault.VerifyResult, err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, vault.ErrNotV2):
		return exitNewerFormat
	case errors.Is(err, vault.ErrNewerFormat):
		return exitNewerFormat
	case errors.Is(err, vault.ErrMalformed):
		return exitUsage
	case errors.Is(err, vault.ErrKEKUnreachable), errors.Is(err, vault.ErrBadKey), errors.Is(err, vault.ErrNoKey):
		return exitVaultLocked
	}
	if res.PayloadOK {
		return 0
	}
	return exitRuntime
}

// verifyKeys builds the key source for a verify run. Without --all-slots it has no passphrase at
// all - not an empty one, none - so the default check answers exactly the service's question: does
// a machine slot open this file. With --all-slots the passphrase comes from CLAUDESWAP_KEY for a
// scripted run, else from a prompt with no echo.
func verifyKeys(allSlots bool, stdin io.Reader, out io.Writer) (vault.KeySource, error) {
	if !allSlots {
		return vault.WithMachineKeys(nil, hostKeyOptions()), nil
	}
	pass, err := readExistingPassphrase(newPassphraseReader(stdin, out))
	if err != nil {
		return nil, err
	}
	return vault.WithMachineKeys(typedKey{pass: pass}, hostKeyOptions()), nil
}

// hostKeyOptions says where this process may look for machine-held key material. The root-only
// systemd-creds route is opted into only when this process is actually root, so a non-root run
// never shells out to systemd-creds and never reads /etc/credstore*; on Windows os.Geteuid is -1,
// so the route is unreachable there by construction rather than by a GOOS branch.
func hostKeyOptions() vault.HostKeyOptions {
	return vault.HostKeyOptions{AllowRootCredsDecrypt: os.Geteuid() == 0}
}

// typedKey is a passphrase this command already has in hand: read from the environment for a
// scripted run, or typed at a prompt. It offers no machine opener of its own - WithMachineKeys adds
// those - and it is never logged and never printed.
type typedKey struct{ pass string }

func (k typedKey) Passphrase() (string, error) {
	if k.pass == "" {
		return "", fmt.Errorf("%w: no passphrase was given", vault.ErrNoKey)
	}
	return k.pass, nil
}

func (typedKey) Machine() []vault.SlotOpener { return nil }
