package service

import (
	"strings"
	"testing"
)

// TestServerAndAgentTablesAreIndependent is the whole reason there are two constructors. The two
// tables render the same directive value today, so the only thing that can prove they are separate
// definitions is that neither shares state with the other and that each names itself.
func TestServerAndAgentTablesAreIndependent(t *testing.T) {
	srv, agt := ServerTable(), AgentTable()
	if srv.Name != "server" || agt.Name != "agent" {
		t.Fatalf("names %q and %q, want server and agent", srv.Name, agt.Name)
	}
	if srv.Name == agt.Name {
		t.Fatal("the two tables carry the same name: nothing tells them apart")
	}

	// Mutating what one call handed back must not reach either table. A package-level slice shared
	// by both constructors is exactly the collapse this test exists to catch.
	codes := srv.NonRestarting()
	codes[0] = 99
	codes = append(codes, 42)
	_ = codes
	rows := srv.Rows()
	rows[0].Code, rows[0].Meaning = 99, "mutated"

	for _, c := range []struct {
		name  string
		table Table
	}{{"server", ServerTable()}, {"agent", AgentTable()}} {
		got := c.table.NonRestarting()
		if len(got) != 4 || got[0] != 2 || got[1] != 3 || got[2] != 4 || got[3] != 5 {
			t.Fatalf("%s after mutating the server's copies: %v", c.name, got)
		}
		if m, ok := c.table.Meaning(2); !ok || m == "mutated" {
			t.Fatalf("%s row 2 meaning %q ok=%v after a mutation", c.name, m, ok)
		}
	}
}

// TestRestartPreventExitStatusRendersAscending asserts each table's value against its own
// definition. It never compares the two strings: a test that leaned on them differing would pass a
// refactor that collapsed the tables into one list.
func TestRestartPreventExitStatusRendersAscending(t *testing.T) {
	if got := ServerTable().RestartPreventExitStatus(); got != "2 3 4 5" {
		t.Fatalf("server: %q, want %q", got, "2 3 4 5")
	}
	if got := AgentTable().RestartPreventExitStatus(); got != "2 3 4 5" {
		t.Fatalf("agent: %q, want %q", got, "2 3 4 5")
	}
	// Ascending is the renderer's job, not the literal's: a row list written out of order still
	// produces a directive systemd reads the same way.
	jumbled := Table{Name: "jumbled", rows: []Row{{5, "five"}, {2, "two"}, {4, "four"}, {3, "three"}}}
	if got := jumbled.RestartPreventExitStatus(); got != "2 3 4 5" {
		t.Fatalf("jumbled: %q, want %q", got, "2 3 4 5")
	}
	if got := (Table{Name: "empty"}).RestartPreventExitStatus(); got != "" {
		t.Fatalf("empty table: %q, want the empty string", got)
	}
}

// TestBothTablesCarryFiveForDifferentReasons is the doc-anchored half: both tables hold a 5 and the
// meanings are not interchangeable. A merge of the two tables has to delete this test.
func TestBothTablesCarryFiveForDifferentReasons(t *testing.T) {
	srv, ok := ServerTable().Meaning(5)
	if !ok || !strings.Contains(srv, "certificate refused") {
		t.Fatalf("server 5 = %q ok=%v, want the refused certificate", srv, ok)
	}
	agt, ok := AgentTable().Meaning(5)
	if !ok || !strings.Contains(agt, "wrong home") {
		t.Fatalf("agent 5 = %q ok=%v, want the wrong home (O16)", agt, ok)
	}
	if strings.Contains(srv, "wrong home") || strings.Contains(agt, "certificate") {
		t.Fatalf("the two meanings of 5 have bled into each other: server %q, agent %q", srv, agt)
	}
	// The agent's 2 is the server's odd one out too: enrolment denied against usage/missing input.
	if m, _ := AgentTable().Meaning(2); !strings.Contains(m, "enrolment denied") {
		t.Fatalf("agent 2 = %q, want enrolment denied", m)
	}
	if m, _ := ServerTable().Meaning(2); strings.Contains(m, "enrolment") {
		t.Fatalf("server 2 = %q: that is the agent's meaning", m)
	}
}

// TestServerRowThreeNamesTheUnreachableKEK is the carry-over from the PR 22 review: the vault's
// ErrKEKUnreachable had no row anywhere in the exit-code table, and this table owns the rows. 3 is
// its number for `server run` - "no slot could unwrap, a restart cannot fix it" - and the console
// mutators keep their own 2 for the same sentinel (cmd/server: mutatorExitCode), which the server
// binary's test pins from the other side.
func TestServerRowThreeNamesTheUnreachableKEK(t *testing.T) {
	m, ok := ServerTable().Meaning(3)
	if !ok {
		t.Fatal("the server table has no row 3")
	}
	for _, want := range []string{"ErrKEKUnreachable", "vaultop"} {
		if !strings.Contains(m, want) {
			t.Fatalf("server 3 = %q, want it to name %q", m, want)
		}
	}
}

// TestUnknownExitCodeIsNeitherNonRestartingNorMeaningful: 0 and 1 are the restarting codes and must
// never read as fatal, and a number no table knows gets no invented meaning.
func TestUnknownExitCodeIsNeitherNonRestartingNorMeaningful(t *testing.T) {
	for _, table := range []Table{ServerTable(), AgentTable()} {
		for _, code := range []int{-1, 0, 1, 6, 243, 1 << 20} {
			if table.IsNonRestarting(code) {
				t.Fatalf("%s: exit %d reads as non-restarting", table.Name, code)
			}
			if m, ok := table.Meaning(code); ok || m != "" {
				t.Fatalf("%s: exit %d invented the meaning %q", table.Name, code, m)
			}
		}
		for _, code := range table.NonRestarting() {
			if !table.IsNonRestarting(code) {
				t.Fatalf("%s: exit %d is in the set but reads as restarting", table.Name, code)
			}
		}
	}
}

// TestEveryRowHasOneCodeAndAMeaning guards the data itself: a duplicate code would render a
// directive with a repeat in it, and an empty meaning would leave a row an operator cannot read.
func TestEveryRowHasOneCodeAndAMeaning(t *testing.T) {
	for _, table := range []Table{ServerTable(), AgentTable()} {
		seen := map[int]bool{}
		for _, r := range table.Rows() {
			if seen[r.Code] {
				t.Fatalf("%s: exit %d appears twice", table.Name, r.Code)
			}
			seen[r.Code] = true
			if r.Code < 2 || r.Code > 5 {
				t.Fatalf("%s: exit %d is outside the 2-5 fatal range", table.Name, r.Code)
			}
			if strings.TrimSpace(r.Meaning) == "" {
				t.Fatalf("%s: exit %d has no meaning", table.Name, r.Code)
			}
		}
		if len(seen) != len(table.NonRestarting()) {
			t.Fatalf("%s: %d rows but %d codes", table.Name, len(seen), len(table.NonRestarting()))
		}
	}
}
