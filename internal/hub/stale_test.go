package hub

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"claude-utilities/internal/ownership"
	"claude-utilities/internal/proto"
	"claude-utilities/internal/vault"
)

// seedStale stores A, B and C with distinct refresh-token lineages. C is the account a second host
// is signed in as, so that host's live login is known to the vault.
func (f *fixture) seedStale() {
	f.t.Helper()
	f.seedLineage()
	if err := f.v.Put(vault.Account{ID: "C", Label: "c", Identity: "id-c",
		Block: json.RawMessage(`{"refreshToken":"rt-c","accessToken":"c0"}`)}); err != nil {
		f.t.Fatal(err)
	}
}

// twoHosts enrols "one" (live on B) and "two" (live on C), each with a scripted agent.
func (f *fixture) twoHosts() (one, two *script, oneID, twoID string, oneAgent *agent) {
	f.t.Helper()
	f.seedStale()
	a1, _, id1 := f.enrol("one")
	f.reg.SwapIn("B", id1)
	one = f.newScript("id-b", `{"refreshToken":"rt-b","accessToken":"b1"}`)
	one.serve(a1)
	a2, _, id2 := f.enrol("two")
	f.reg.SwapIn("C", id2)
	two = f.newScript("id-c", `{"refreshToken":"rt-c","accessToken":"c1"}`)
	two.serve(a2)
	return one, two, id1, id2, a1
}

func swapEx(f *fixture, host, acct string) (SwapResult, error) {
	return f.h.SwapEx(context.Background(), host, acct)
}

func noLeak(t *testing.T, out string, secrets ...string) {
	t.Helper()
	for _, leak := range secrets {
		if strings.Contains(out, leak) {
			t.Fatalf("log leaked %q:\n%s", leak, out)
		}
	}
}

// One account may be swapped onto any number of hosts: the second swap is not refused, it reaches
// the agent with the vault's login, and ownership records the later host as Active.
func TestSwapSucceedsOnASecondHostHoldingTheSameAccount(t *testing.T) {
	f := newFixture(t)
	_, two, id1, id2, _ := f.twoHosts()
	if _, err := swapEx(f, id1, "A"); err != nil { // host one now holds A's lineage
		t.Fatal(err)
	}
	got, err := swapEx(f, id2, "A")
	if err != nil || got.Outcome != SwapDone {
		t.Fatalf("second host: %+v, %v", got, err)
	}
	if _, blocks := two.snapshot(); len(blocks) != 1 || blocks[0] != f.vaultBlock("A") {
		t.Fatalf("swap_req to the second host: %v", blocks)
	}
	use := f.reg.HostsUsing("A")
	if use[id2] != ownership.Active || use[id1] != ownership.Shared {
		t.Fatalf("ownership of A: %v", use)
	}
	noLeak(t, f.logs.String(), "rt-a", "id-a", `"a0"`)
	if strings.Contains(f.logs.String(), "held_elsewhere") {
		t.Fatalf("a held-elsewhere refusal was logged:\n%s", f.logs.String())
	}
}

func TestSwapAllowedForTheHolderItself(t *testing.T) {
	f := newFixture(t)
	_, _, id1, _, _ := f.twoHosts()
	if _, err := swapEx(f, id1, "A"); err != nil {
		t.Fatal(err)
	}
	got, err := swapEx(f, id1, "A") // same host, same account: the no-op
	if err != nil || got.Outcome != SwapAlreadyActive {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestSwapAllowedWhenTheHolderIsOffline(t *testing.T) {
	f := newFixture(t)
	_, _, id1, id2, a1 := f.twoHosts()
	if _, err := swapEx(f, id1, "A"); err != nil {
		t.Fatal(err)
	}
	_ = a1.ws.CloseNow()
	eventually(t, func() bool {
		for _, v := range f.h.Hosts() {
			if v.HostID == id1 {
				return !v.Online
			}
		}
		return false
	})
	if _, err := swapEx(f, id2, "A"); err != nil {
		t.Fatalf("an offline holder must not block the swap: %v", err)
	}
}

// A stored login of any age is swapped without a caution: the result carries only the outcome and home.
func TestSwapOfAnOldStoredLoginSucceeds(t *testing.T) {
	f := newFixture(t)
	_, _, id1, _, _ := f.twoHosts()
	acct, _ := f.v.Get("A")
	acct.Updated = f.clk.Now().Add(-30 * time.Hour)
	if err := f.v.Put(acct); err != nil {
		t.Fatal(err)
	}
	if got, err := swapEx(f, id1, "A"); err != nil || got.Outcome != SwapDone {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestStaleAfterDefaultsToSixHours(t *testing.T) {
	if got := newFixture(t).h.StaleAfter(); got != 6*time.Hour {
		t.Fatalf("default %v", got)
	}
}

func TestSwapRefusedForUnauthorizedAccountWithSignInAgain(t *testing.T) {
	f := newFixture(t)
	_, two, _, id2, _ := f.twoHosts()
	f.h.SetUnauthorized(func(id string) bool { return id == "A" })
	_, err := swapEx(f, id2, "A")
	if !errors.Is(err, ErrSignInAgain) {
		t.Fatalf("got %v, want ErrSignInAgain", err)
	}
	if !strings.Contains(err.Error(), "sign in again first") {
		t.Fatalf("message %q", err.Error())
	}
	if _, blocks := two.snapshot(); len(blocks) != 0 {
		t.Fatalf("a swap_req was sent: %v", blocks)
	}
}

func TestUnauthorizedDoesNotBlockAnAlreadyActiveNoOp(t *testing.T) {
	f := newFixture(t)
	_, _, id1, _, _ := f.twoHosts()
	if _, err := swapEx(f, id1, "A"); err != nil {
		t.Fatal(err)
	}
	f.h.SetUnauthorized(func(string) bool { return true })
	got, err := swapEx(f, id1, "A")
	if err != nil || got.Outcome != SwapAlreadyActive {
		t.Fatalf("got %+v, %v", got, err)
	}
}

// Swap keeps its two-value shape for every existing caller.
func TestSwapWrapperAllowsAHeldAccount(t *testing.T) {
	f := newFixture(t)
	_, _, id1, id2, _ := f.twoHosts()
	if _, err := f.h.Swap(context.Background(), id1, "A"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.Swap(context.Background(), id2, "A"); err != nil {
		t.Fatalf("got %v", err)
	}
}

// An imported login is live on the importing host; another host may take it too.
func TestImportedAccountCanBeSwappedOntoAnotherHost(t *testing.T) {
	f := newFixture(t)
	f.seedStale()
	a1, _, id1 := f.enrol("one")
	f.newScript("id-n", `{"claudeAiOauth":{"refreshToken":"rt-n","accessToken":"n0"}}`).serve(a1)
	acct, err := f.h.Import(context.Background(), id1, "n")
	if err != nil {
		t.Fatal(err)
	}
	a2, _, id2 := f.enrol("two")
	f.reg.SwapIn("C", id2)
	f.newScript("id-c", `{"refreshToken":"rt-c","accessToken":"c1"}`).serve(a2)
	if _, err := swapEx(f, id2, acct.ID); err != nil {
		t.Fatalf("got %v", err)
	}
}

// Two hosts hold A. The vault copy follows the Active holder only: a Shared host's rotated login is
// never adopted, and its swap-away never writes back over the vault.
func TestSharedHostNeitherAdoptsNorWritesBackOverTheVault(t *testing.T) {
	f := newFixture(t)
	one, _, id1, id2, _ := f.twoHosts()
	for _, id := range []string{id1, id2} {
		if _, err := swapEx(f, id, "A"); err != nil {
			t.Fatal(err)
		}
	}
	want := f.vaultBlock("A")
	// Host one (Shared) now holds a rotated A login.
	one.mu.Lock()
	one.liveBlock = `{"refreshToken":"rt-a-one","accessToken":"a-one"}`
	one.staleIdentity = true
	one.mu.Unlock()
	if err := f.h.AdoptHeld(context.Background(), id1); err != nil {
		t.Fatal(err)
	}
	if got := f.vaultBlock("A"); got != want {
		t.Fatalf("adopt from a Shared host changed vault A: %s", got)
	}
	// Swapping the Shared host away writes nothing back either (identity names A, lineage differs).
	if _, err := swapEx(f, id1, "B"); err != nil {
		t.Fatal(err)
	}
	if got := f.vaultBlock("A"); got != want {
		t.Fatalf("write-back from a Shared host changed vault A: %s", got)
	}
}

// The Active host's rotation is adopted; a later rotation by a different, non-matching lineage on the
// other host cannot displace it.
func TestOnlyTheActiveHostsRotationIsAdoptedAndNeverAcrossLineages(t *testing.T) {
	f := newFixture(t)
	one, two, id1, id2, _ := f.twoHosts()
	for _, id := range []string{id1, id2} {
		if _, err := swapEx(f, id, "A"); err != nil {
			t.Fatal(err)
		}
	}
	rotated := `{"refreshToken":"rt-a-2","accessToken":"a2"}`
	two.mu.Lock()
	two.liveBlock = rotated
	two.mu.Unlock()
	if err := f.h.AdoptHeld(context.Background(), id2); err != nil {
		t.Fatal(err)
	}
	if got := f.vaultBlock("A"); got != rotated {
		t.Fatalf("Active host's rotation not adopted: %s", got)
	}
	// Host two is then moved to another login out of band, and exports C's lineage while still
	// recorded Active on A: nothing of C may land in A's slot.
	two.mu.Lock()
	two.liveBlock = `{"refreshToken":"rt-c","accessToken":"c9"}`
	two.mu.Unlock()
	if err := f.h.AdoptHeld(context.Background(), id2); err != nil {
		t.Fatal(err)
	}
	if got := f.vaultBlock("A"); got != rotated {
		t.Fatalf("a different lineage reached vault A: %s", got)
	}
	// And the Shared host one still cannot overwrite it.
	one.mu.Lock()
	one.liveBlock = `{"refreshToken":"rt-a-one","accessToken":"x"}`
	one.mu.Unlock()
	if err := f.h.AdoptHeld(context.Background(), id1); err != nil {
		t.Fatal(err)
	}
	if got := f.vaultBlock("A"); got != rotated {
		t.Fatalf("vault A = %s", got)
	}
}

// An Active host whose live login has another lineage than the stored one (identity names A, token
// does not match) must not write back into A's slot at swap time.
func TestWriteBackFromAMismatchedLineageIsRefusedOnASharedAccount(t *testing.T) {
	f := newFixture(t)
	_, two, id1, id2, _ := f.twoHosts()
	for _, id := range []string{id1, id2} {
		if _, err := swapEx(f, id, "A"); err != nil {
			t.Fatal(err)
		}
	}
	want := f.vaultBlock("A")
	two.mu.Lock()
	two.liveBlock = `{"refreshToken":"rt-unknown","accessToken":"u1"}`
	two.staleIdentity = true
	two.mu.Unlock()
	if _, err := swapEx(f, id2, "B"); err != nil {
		t.Fatal(err)
	}
	if got := f.vaultBlock("A"); got != want {
		t.Fatalf("mismatched lineage written to vault A: %s", got)
	}
	noLeak(t, f.logs.String(), "rt-unknown", "rt-a", "id-a")
}

// Hosts swapping onto the same account at the same time all succeed, and the vault copy stays on
// the account's lineage. Run under -race.
func TestConcurrentSwapsOntoOneAccountAllSucceed(t *testing.T) {
	f := newFixture(t)
	_, _, id1, id2, _ := f.twoHosts()
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, id := range []string{id1, id2} {
		wg.Add(1)
		go func() { defer wg.Done(); _, errs[i] = swapEx(f, id, "A") }()
	}
	wg.Add(2)
	go func() { defer wg.Done(); _ = f.h.AdoptHeld(context.Background(), id1) }()
	go func() { defer wg.Done(); _ = f.h.AdoptHeld(context.Background(), id2) }()
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("host %d: %v", i, err)
		}
	}
	if got := f.vaultBlock("A"); !strings.Contains(got, `"rt-a"`) {
		t.Fatalf("vault A lost its lineage: %s", got)
	}
	use := f.reg.HostsUsing("A")
	if len(use) != 2 {
		t.Fatalf("ownership of A: %v", use)
	}
	active := 0
	for _, st := range use {
		if st == ownership.Active {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("want exactly one Active holder, got %v", use)
	}
}

func TestSwapResultCarriesTheAgentsHomeCode(t *testing.T) {
	f := newFixture(t)
	one, _, id1, id2, _ := f.twoHosts()
	one.mu.Lock()
	one.home = proto.HomeMoved
	one.mu.Unlock()
	got, err := swapEx(f, id1, "A")
	if err != nil || got.Home != proto.HomeMoved {
		t.Fatalf("got %+v, %v; want the agent's home code passed through", got, err)
	}
	// An older agent reports no home: the result says nothing rather than guessing.
	got, err = swapEx(f, id2, "C")
	if err != nil || got.Home != "" {
		t.Fatalf("got %+v, %v", got, err)
	}
}
