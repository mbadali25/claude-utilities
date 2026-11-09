// Package service holds the parts a packaged install needs and a console run does not: each
// binary's exit-code table, the fatal marker that stops a supervisor from retrying a code a restart
// cannot fix, and the readiness handshake a `Type=notify` unit waits for.
//
// Both binaries import it, and the numbers are NOT shared: the server's table and the agent's table
// are two definitions that happen to render the same `RestartPreventExitStatus=` value today. The
// code is shared, the meanings are not. See the spec's "Service lifecycle / Exit codes" for the
// server's rows and 8.10 for the agent's.
package service

import (
	"sort"
	"strconv"
	"strings"
)

// Row is one line of one binary's exit-code table: the code, and what that code means for THAT
// binary.
//
// The meaning is data rather than a comment on purpose. Both tables hold a 5, both render "2 3 4 5",
// and the only thing that distinguishes them is what each number means - so a test can only hold
// the two apart if it can read the meanings. (The plan sketched Table as a bare `NonRestarting
// []int`; the rows carry the meanings instead, with NonRestarting derived from them, so there is one
// definition per table and not a list and a parallel comment that can drift.)
type Row struct {
	// Code is the process exit status.
	Code int
	// Meaning is the one-line reason, for an operator and for the rows' own tests. It names
	// sentinels where a sentinel is the cause, because "vault locked" alone sent a reviewer looking
	// for the row vault.ErrKEKUnreachable belongs to and finding none.
	Meaning string
}

// Table is one binary's set of exit codes that a restart cannot fix. 0 (clean stop) and 1 (a
// retryable runtime failure) are deliberately absent: they are the codes a supervisor SHOULD retry,
// so a number missing from this table is the answer "restart me", and `IsNonRestarting` never has to
// invent a meaning for a code no row names.
type Table struct {
	// Name is the binary the table belongs to, and the field that tells two identical-looking
	// tables apart.
	Name string
	// rows is unexported so there is no field to assign over and no backing array to share: every
	// accessor hands back a copy, and each constructor builds a fresh literal.
	rows []Row
}

// ServerTable is the server's exit-code table: rows 2-5 of the spec's "Service lifecycle / Exit
// codes". Exit 2 is in the set by Matthew's decision of 2026-11-07 - a missed `set-password`, a bad
// flag baked into the service command line and a held data-dir lock all survive a restart.
//
// Row 3 and the unreachable KEK (the carry-over from the PR 22 review). The vault's
// ErrKEKUnreachable had no row written down anywhere, and this is where its row lives: for
// `server run` it is 3, the spec's "vault locked: no slot could unwrap", because a process with no
// passphrase that cannot reach its machine key has no second way in and a restart changes nothing.
// The console mutators map the SAME sentinel to 2 (cmd/server's mutatorExitCode, documented at
// vaultinit.go), and that difference is deliberate and now recorded in both places: an operator
// standing at a console has a setup step to take, where a supervisor only needs to be told to stop
// trying. Nothing in this slice renumbers either.
func ServerTable() Table {
	return Table{
		Name: "server",
		rows: []Row{
			{Code: 2, Meaning: "usage, missing input (no admin password hash and no bootstrap), or the data-dir lock is held by another process"},
			{Code: 3, Meaning: "vault locked: no slot could unwrap (vault.ErrKEKUnreachable), or an interrupted vaultop journal was found on start"},
			{Code: 4, Meaning: "format: a vault written by a newer server or a malformed one, a v1 vault with no passphrase, no vault and no passphrase, or a v2 vault with a v1 keyring"},
			{Code: 5, Meaning: "certificate refused: EnsureCert would have had to regenerate or re-ACL the TLS pair and did not"},
		},
	}
}

// AgentTable is the agent's exit-code table (spec 8.10). The numbers are its own: 2 already means
// "enrolment denied" in its live code and in two consumers, so nothing here is renumbered to match
// the server. 5 is `wrong_home` under O16 and is defined here, in slice 4, so there is one
// definition of the agent's table and slice 8 consumes it rather than amending it.
func AgentTable() Table {
	return Table{
		Name: "agent",
		rows: []Row{
			{Code: 2, Meaning: "enrolment denied by the server: the hub suppresses a denied fingerprint for an hour, so a retry cannot succeed"},
			{Code: 3, Meaning: "config-fatal: no agent.json at the resolved state dir, a service principal as the run-as account, an unknown flag on run, or a state dir the install refused"},
			{Code: 4, Meaning: "enrolment rejected at run time: the host token is refused or the server pin does not match"},
			{Code: 5, Meaning: "wrong home: the live home is not the one this host enrolled with (O16)"},
		},
	}
}

// Rows returns a copy of the table's rows, in the order they are written.
func (t Table) Rows() []Row {
	out := make([]Row, len(t.rows))
	copy(out, t.rows)
	return out
}

// NonRestarting returns the table's codes, ascending, as a fresh slice. Ordering is the accessor's
// job rather than the literal's, so a row added out of order still renders a directive systemd and
// the SCM read the same way.
func (t Table) NonRestarting() []int {
	codes := make([]int, 0, len(t.rows))
	for _, r := range t.rows {
		codes = append(codes, r.Code)
	}
	sort.Ints(codes)
	return codes
}

// IsNonRestarting reports whether a restart could not fix this exit code. Any code no row names -
// 0, 1, or a number from somewhere else entirely, such as systemd's own 243 - is restartable, which
// is the fail-open answer: at worst a supervisor retries something it could not fix, never the other
// way round.
func (t Table) IsNonRestarting(code int) bool {
	for _, r := range t.rows {
		if r.Code == code {
			return true
		}
	}
	return false
}

// Meaning returns this binary's meaning for an exit code, and false for a code the table does not
// hold. It never guesses: an unknown code gets the empty string.
func (t Table) Meaning(code int) (string, bool) {
	for _, r := range t.rows {
		if r.Code == code {
			return r.Meaning, true
		}
	}
	return "", false
}

// RestartPreventExitStatus renders the systemd directive's value: the codes, ascending,
// space-separated, e.g. "2 3 4 5". The unit writers of slices 4b, 4c and 8 take the string from the
// table of the binary they are writing a unit for, never from a list of their own.
func (t Table) RestartPreventExitStatus() string {
	codes := t.NonRestarting()
	parts := make([]string, 0, len(codes))
	for _, c := range codes {
		parts = append(parts, strconv.Itoa(c))
	}
	return strings.Join(parts, " ")
}
