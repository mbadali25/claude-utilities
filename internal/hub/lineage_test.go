package hub

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"claude-utilities/internal/proto"
	"claude-utilities/internal/vault"
)

// seedLineage stores A and B with distinct refresh-token lineages, as real logins have.
func (f *fixture) seedLineage() {
	f.t.Helper()
	for _, a := range []vault.Account{
		{ID: "A", Label: "a", Identity: "id-a", Block: json.RawMessage(`{"refreshToken":"rt-a","accessToken":"a0"}`)},
		{ID: "B", Label: "b", Identity: "id-b", Block: json.RawMessage(`{"refreshToken":"rt-b","accessToken":"b0"}`)},
	} {
		if err := f.v.Put(a); err != nil {
			f.t.Fatal(err)
		}
	}
}

// A swap never rewrites ~/.claude.json, so identity stays "id-a" after A->B. Swapping back must
// really swap, and neither slot may take the other's login.
func TestSwapBackAfterSwapWithStaleIdentity(t *testing.T) {
	f := newFixture(t)
	f.seedLineage()
	a, _, id := f.enrol("box")
	f.reg.SwapIn("A", id)
	s := f.newScript("id-a", `{"refreshToken":"rt-a","accessToken":"a1"}`)
	s.staleIdentity = true
	s.serve(a)

	if _, err := f.h.Swap(context.Background(), id, "B"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.Swap(context.Background(), id, "A"); err != nil {
		t.Fatal(err)
	}
	_, blocks := s.snapshot()
	if len(blocks) != 2 {
		t.Fatalf("second swap was treated as a no-op: %d swap_req sent", len(blocks))
	}
	if blocks[1] != `{"refreshToken":"rt-a","accessToken":"a1"}` {
		t.Fatalf("swap back sent %s, want A's written-back login", blocks[1])
	}
	if got := f.vaultBlock("A"); !strings.Contains(got, `"rt-a"`) || strings.Contains(got, `"rt-b"`) {
		t.Fatalf("vault A lost its lineage: %s", got)
	}
	if got := f.vaultBlock("B"); got != `{"refreshToken":"rt-b","accessToken":"b0"}` {
		t.Fatalf("vault B = %s", got)
	}
	if o := f.reg.OwnerOf("A"); o.HostID != id {
		t.Fatalf("owner of A: %+v", o)
	}
}

// B's refresh token rotated after the swap, so no stored login matches by lineage. The hub knows
// it put B on this host, so the stale identity must not send B's login into A's slot.
func TestRotatedLoginAfterSwapStillBelongsToTheSwappedAccount(t *testing.T) {
	f := newFixture(t)
	f.seedLineage()
	a, _, id := f.enrol("box")
	f.reg.SwapIn("A", id)
	s := f.newScript("id-a", `{"refreshToken":"rt-a","accessToken":"a1"}`)
	s.staleIdentity = true
	s.serve(a)
	if _, err := f.h.Swap(context.Background(), id, "B"); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.liveBlock = `{"refreshToken":"rt-b2","accessToken":"b2"}`
	s.mu.Unlock()
	if _, err := f.h.Swap(context.Background(), id, "A"); err != nil {
		t.Fatal(err)
	}
	if got := f.vaultBlock("A"); strings.Contains(got, "rt-b2") || !strings.Contains(got, `"rt-a"`) {
		t.Fatalf("vault A = %s", got)
	}
	if got := f.vaultBlock("B"); got != `{"refreshToken":"rt-b2","accessToken":"b2"}` {
		t.Fatalf("vault B did not take its own rotated login: %s", got)
	}
}

// Identity says A but the live login is B's (the hub has no memory of a swap, e.g. after a
// restart). The login wins: this is not a no-op, and A's slot is untouched.
func TestStaleOauthAccountDoesNotMakeSwapANoOp(t *testing.T) {
	f := newFixture(t)
	f.seedLineage()
	a, _, id := f.enrol("box")
	f.reg.SwapIn("A", id)
	s := f.newScript("id-a", `{"refreshToken":"rt-b","accessToken":"b-live"}`)
	s.staleIdentity = true
	s.serve(a)
	if _, err := f.h.Swap(context.Background(), id, "A"); err != nil {
		t.Fatal(err)
	}
	if _, blocks := s.snapshot(); len(blocks) != 1 || blocks[0] != `{"refreshToken":"rt-a","accessToken":"a0"}` {
		t.Fatalf("swap_req blocks: %v", blocks)
	}
	if got := f.vaultBlock("A"); got != `{"refreshToken":"rt-a","accessToken":"a0"}` {
		t.Fatalf("vault A overwritten: %s", got)
	}
}

// A live login whose lineage differs from the slot it is attributed to by identity alone must
// never overwrite that slot.
func TestWritebackSkippedOnLineageMismatch(t *testing.T) {
	f := newFixture(t)
	f.seedLineage()
	a, _, id := f.enrol("box")
	f.reg.SwapIn("A", id)
	s := f.newScript("id-a", `{"refreshToken":"rt-stranger","accessToken":"x"}`)
	s.serve(a)
	if _, err := f.h.Swap(context.Background(), id, "B"); err != nil {
		t.Fatal(err)
	}
	if got := f.vaultBlock("A"); got != `{"refreshToken":"rt-a","accessToken":"a0"}` {
		t.Fatalf("vault A overwritten by a different lineage: %s", got)
	}
}

// A no-op and a real swap both succeed, so the only thing that can tell them apart is the
// outcome Swap reports. Without it the admin UI cannot say "already on this account" and a
// press on the preselected account looks like nothing happened at all.
func TestSwapOutcomeDistinguishesNoOpFromRealSwap(t *testing.T) {
	f := newFixture(t)
	f.seedLineage()
	a, _, id := f.enrol("box")
	f.reg.SwapIn("A", id)
	s := f.newScript("id-a", `{"refreshToken":"rt-a","accessToken":"a0"}`)
	s.serve(a)

	got, err := f.h.Swap(context.Background(), id, "A")
	if err != nil {
		t.Fatal(err)
	}
	if got != SwapAlreadyActive {
		t.Fatalf("swap to the active account reported %q, want %q", got, SwapAlreadyActive)
	}
	if got, err = f.h.Swap(context.Background(), id, "B"); err != nil {
		t.Fatal(err)
	}
	if got != SwapDone {
		t.Fatalf("swap to a different account reported %q, want %q", got, SwapDone)
	}
}

// A refused swap reports no outcome: the caller must not read one off a failure.
func TestSwapOutcomeEmptyOnError(t *testing.T) {
	f := newFixture(t)
	f.seedLineage()
	got, err := f.h.Swap(context.Background(), "ghost", "B")
	if !errors.Is(err, ErrUnknownHost) {
		t.Fatalf("err = %v, want ErrUnknownHost", err)
	}
	if got != "" {
		t.Fatalf("outcome %q on a refused swap, want empty", got)
	}
}

// The already-active path must not touch the vault, even for the Active holder with a fresher block.
func TestNoOpSwapLeavesVaultUntouched(t *testing.T) {
	f := newFixture(t)
	f.seedLineage()
	before, _ := f.v.Get("A")
	a, _, id := f.enrol("box")
	f.reg.SwapIn("A", id)
	s := f.newScript("id-a", `{"refreshToken":"rt-a","accessToken":"a-fresh"}`)
	s.serve(a)
	if _, err := f.h.Swap(context.Background(), id, "A"); err != nil {
		t.Fatal(err)
	}
	after, _ := f.v.Get("A")
	if string(after.Block) != string(before.Block) || !after.Updated.Equal(before.Updated) {
		t.Fatalf("no-op mutated the vault: %s -> %s", before.Block, after.Block)
	}
	if order, _ := s.snapshot(); len(order) != 1 {
		t.Fatalf("no-op sent a swap: %v", order)
	}
}

// The heartbeat reports the stale identity; the dashboard must still show the account that was swapped in.
func TestHostViewShowsSwappedAccountDespiteStaleHeartbeat(t *testing.T) {
	f := newFixture(t)
	f.seedLineage()
	a, _, id := f.enrol("box")
	f.reg.SwapIn("A", id)
	s := f.newScript("id-a", `{"refreshToken":"rt-a","accessToken":"a1"}`)
	s.staleIdentity = true
	s.serve(a)
	if _, err := f.h.Swap(context.Background(), id, "B"); err != nil {
		t.Fatal(err)
	}
	a.send(proto.TypeReport, "", proto.Report{ActiveIdentity: "id-a", CredsPresent: true,
		Sessions: []proto.Session{{PID: 9, ID: "marker", Cwd: "/x", StartedAt: f.clk.Now()}}})
	eventually(t, func() bool { return len(f.h.Hosts()[0].Sessions) == 1 })
	if v := f.h.Hosts()[0]; v.ActiveAccount != "B" {
		t.Fatalf("view after stale heartbeat: %+v", v)
	}
}

// A completed swap tells the usage poller which account just landed, once; a no-op swap does not.
func TestSwapTellsTheOnSwapHookOnlyForARealSwap(t *testing.T) {
	f := newFixture(t)
	f.seedLineage()
	a, _, id := f.enrol("box")
	f.reg.SwapIn("A", id)
	s := f.newScript("id-a", `{"refreshToken":"rt-a","accessToken":"a0"}`)
	s.serve(a)
	var got []string
	f.h.SetOnSwap(func(acct string) { got = append(got, acct) })

	if _, err := f.h.Swap(context.Background(), id, "A"); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("no-op swap reported %v", got)
	}
	if _, err := f.h.Swap(context.Background(), id, "B"); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "B" {
		t.Fatalf("real swap reported %v, want [B]", got)
	}
}
