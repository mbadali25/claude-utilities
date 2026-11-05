package hub

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

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

func TestSwapRefusedWhenAnotherOnlineHostHoldsTheLineage(t *testing.T) {
	f := newFixture(t)
	_, two, id1, id2, _ := f.twoHosts()
	if _, err := swapEx(f, id1, "A"); err != nil { // host one now holds A's lineage
		t.Fatal(err)
	}
	two.mu.Lock()
	two.order = nil
	two.mu.Unlock()

	_, err := swapEx(f, id2, "A")
	if !errors.Is(err, ErrHeldElsewhere) {
		t.Fatalf("got %v, want ErrHeldElsewhere", err)
	}
	var he *HeldError
	if !errors.As(err, &he) || he.Host != "one" {
		t.Fatalf("holder not named: %+v", he)
	}
	if want := "Held by one: swap that host to another account first, or sign in again"; err.Error() != want {
		t.Fatalf("message %q, want %q", err.Error(), want)
	}
	if order, blocks := two.snapshot(); len(blocks) != 0 {
		t.Fatalf("a swap_req reached the refused host: %v %v", order, blocks)
	}
	out := f.logs.String()
	for _, leak := range []string{"rt-a", "id-a", "a0"} {
		if strings.Contains(out, leak) {
			t.Fatalf("log leaked %q:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "held_elsewhere") {
		t.Fatalf("refusal reason not logged:\n%s", out)
	}
}

func TestSwapAllowedForTheHolderItself(t *testing.T) {
	f := newFixture(t)
	_, _, id1, _, _ := f.twoHosts()
	if _, err := swapEx(f, id1, "A"); err != nil {
		t.Fatal(err)
	}
	got, err := swapEx(f, id1, "A") // same host, same account: the no-op, never a refusal
	if err != nil || got.Outcome != SwapAlreadyActive {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestSwapAllowedOnceTheHolderMovedToAnotherAccount(t *testing.T) {
	f := newFixture(t)
	_, _, id1, id2, _ := f.twoHosts()
	for _, target := range []string{"A", "B"} { // one holds A, then leaves it for B
		if _, err := swapEx(f, id1, target); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := swapEx(f, id2, "A"); err != nil {
		t.Fatalf("A is free now: %v", err)
	}
}

func TestSwapWarnsWhenTheHolderIsOffline(t *testing.T) {
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
	got, err := swapEx(f, id2, "A")
	if err != nil {
		t.Fatalf("an offline holder must not block the swap: %v", err)
	}
	if len(got.Warnings) != 1 || got.Warnings[0].Code != WarnHolderOffline || got.Warnings[0].Host != "one" {
		t.Fatalf("warnings: %+v", got.Warnings)
	}
}

func TestSwapStaleCopyWarningThresholds(t *testing.T) {
	cases := []struct {
		name    string
		age     time.Duration
		after   time.Duration // 0 keeps the default
		zeroAt  bool
		warn    bool
		wantHrs int
	}{
		{name: "fresh", age: 5 * time.Hour},
		{name: "exactly at the threshold", age: 6 * time.Hour},
		{name: "just over", age: 6*time.Hour + time.Minute, warn: true, wantHrs: 6},
		{name: "old", age: 30 * time.Hour, warn: true, wantHrs: 30},
		{name: "custom threshold", age: 2 * time.Hour, after: time.Hour, warn: true, wantHrs: 2},
		{name: "unknown age is not flagged", zeroAt: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			_, _, id1, _, _ := f.twoHosts()
			if tc.after > 0 {
				f.h.SetStaleAfter(tc.after)
			}
			acct, _ := f.v.Get("A")
			acct.Updated = f.clk.Now().Add(-tc.age)
			if tc.zeroAt {
				acct.Updated = time.Time{}
			}
			if err := f.v.Put(acct); err != nil {
				t.Fatal(err)
			}
			got, err := swapEx(f, id1, "A")
			if err != nil {
				t.Fatal(err)
			}
			if !tc.warn {
				if len(got.Warnings) != 0 {
					t.Fatalf("unexpected warnings %+v", got.Warnings)
				}
				return
			}
			if len(got.Warnings) != 1 || got.Warnings[0].Code != WarnStaleCopy || got.Warnings[0].AgeHours != tc.wantHrs {
				t.Fatalf("warnings %+v, want stale_copy at %d h", got.Warnings, tc.wantHrs)
			}
		})
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
	acct, _ := f.v.Get("A") // an old copy too: unauthorized wins over the stale warning
	acct.Updated = f.clk.Now().Add(-48 * time.Hour)
	if err := f.v.Put(acct); err != nil {
		t.Fatal(err)
	}
	_, err := swapEx(f, id2, "A")
	if !errors.Is(err, ErrSignInAgain) {
		t.Fatalf("got %v, want ErrSignInAgain", err)
	}
	if !strings.Contains(err.Error(), "Sign in again first") {
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

// Swap keeps its two-value shape for every existing caller and still applies the guards.
func TestSwapWrapperAppliesTheGuards(t *testing.T) {
	f := newFixture(t)
	_, _, id1, id2, _ := f.twoHosts()
	if _, err := f.h.Swap(context.Background(), id1, "A"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.Swap(context.Background(), id2, "A"); !errors.Is(err, ErrHeldElsewhere) {
		t.Fatalf("got %v", err)
	}
}

// An imported login is live on the importing host, so another host may not take it.
func TestImportedAccountCountsAsHeldByTheImportingHost(t *testing.T) {
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
	if _, err := swapEx(f, id2, acct.ID); !errors.Is(err, ErrHeldElsewhere) {
		t.Fatalf("got %v, want ErrHeldElsewhere", err)
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
