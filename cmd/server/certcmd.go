package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"claude-utilities/internal/hub"
)

// certUsage is the `cert` command summary. There is one subcommand on purpose: nothing else in
// the binary may write the TLS pair.
const certUsage = `usage: server cert renew [--data-dir DIR]
  renew    write a NEW TLS pair. This CHANGES the sha256 fingerprint every enrolled agent pins,
           so every agent must re-enrol afterwards. It asks for the word "renew" to be typed;
           there is no flag for the confirmation, by design. It refuses on a pair it cannot read
           (exit 5): there the fault is a permission or ACL problem, not the certificate.`

// confirmWord is typed to confirm a renew. A flag would end up in a script.
const confirmWord = "renew"

// maxConfirmLine bounds the typed confirmation so a stuck or hostile producer is not read forever.
const maxConfirmLine = 1 << 10

// certCmd dispatches `server cert <subcommand>`. It is reached from run's fixed subcommand name
// set, so it never sees the console run's flags.
func certCmd(args []string, in io.Reader, out, errOut io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(errOut, certUsage)
		return 2
	}
	switch args[0] {
	case "renew":
		return certRenewCmd(args[1:], in, out, errOut)
	default:
		_, _ = fmt.Fprintf(errOut, "cert: unknown subcommand %q; the only one is `renew`\n", args[0])
		_, _ = fmt.Fprintln(errOut, certUsage)
		return 2
	}
}

// certRenewCmd writes a fresh pair after a typed confirmation, and prints the old and new
// fingerprints with the re-enrol warning. Both fingerprints are public values.
func certRenewCmd(args []string, in io.Reader, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("cert renew", flag.ContinueOnError)
	fs.SetOutput(errOut)
	dataDir := fs.String("data-dir", defaultDataDir(), "directory holding the TLS certificate pair")
	if err := fs.Parse(args); err != nil {
		_, _ = fmt.Fprintln(errOut, certUsage)
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(errOut, "cert renew: the confirmation is typed at the prompt, never as an argument")
		return 2
	}
	// TODO(cert-vault plan Task 3a.7): hold <data-dir>/.claude-swap.lock for this command, as
	// every vault mutator does. The lock does not exist yet; TestCertRenewTakesNoDataDirLockYet
	// is the tripwire that fails when it lands.
	if !confirmRenew(in, out) {
		_, _ = fmt.Fprintln(errOut, "cert renew: not confirmed; nothing was written and the fingerprint is unchanged")
		return 2
	}
	oldFP, newFP, err := hub.RenewCert(filepath.Join(*dataDir, "tls"))
	if err != nil {
		reportRefusal(errOut, "cert renew", err)
		return exitCodeFor(err)
	}
	if oldFP == "" {
		// There was no certificate to read, so no fingerprint was ever published and there is
		// nobody to re-enrol: the new pin is the whole story.
		_, _ = fmt.Fprintf(out, "cert renew: there was no loadable pair; new certificate sha256=%s\n", newFP)
		return 0
	}
	_, _ = fmt.Fprintf(out, "cert renew: old certificate sha256=%s\n", oldFP)
	_, _ = fmt.Fprintf(out, "cert renew: new certificate sha256=%s\n", newFP)
	// Order matters, and it is not the obvious one. A running server reads the pair once, when it
	// opens its listener, and this version has no reload: it serves the OLD certificate until it
	// is restarted. An agent re-enrolled on the new pin before that restart is an agent that
	// cannot connect, so the restart is step 1 and the re-enrolment is step 2.
	_, _ = fmt.Fprintln(out, "cert renew: WARNING the pinned fingerprint has changed.")
	_, _ = fmt.Fprintln(out, "cert renew: 1. stop the server if it is running: it keeps serving the OLD pair "+
		"until it is restarted, because the pair is loaded once at startup and never reloaded.")
	_, _ = fmt.Fprintln(out, "cert renew: 2. start it again; it then serves the new pair.")
	_, _ = fmt.Fprintf(out, "cert renew: 3. re-enrol every agent with --pin %s; until it does, it refuses "+
		"to connect.\n", newFP)
	return 0
}

// confirmRenew requires confirmWord to be typed, because a new pair is a new pin for the whole
// fleet. One line is read, so a deliberate `echo renew |` works and a stray `-y` does not exist.
func confirmRenew(in io.Reader, out io.Writer) bool {
	_, _ = fmt.Fprintf(out, "This writes a NEW TLS pair. The sha256 every enrolled agent pins changes and every "+
		"agent must re-enrol. Type %s to continue: ", confirmWord)
	br := bufio.NewReader(io.LimitReader(in, maxConfirmLine))
	line, err := br.ReadString('\n')
	_, _ = fmt.Fprintln(out)
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		return false
	}
	return strings.TrimRight(line, "\r\n") == confirmWord
}
