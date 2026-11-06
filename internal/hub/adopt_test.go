package hub

import (
	"context"
	"sync"
	"testing"
	"time"

	"claude-utilities/internal/vault"
)

const (
	adoptR1 = `{"accessToken":"a1","refreshToken":"R1"}`
	adoptR2 = `{"accessToken":"a2","refreshToken":"R2"}`
)

// adoptFixture holds account A (token R1) as the Active holdings of one host whose export the
// script answers; one adopt pass has already recorded the host's lineage.
func adoptFixture(t *testing.T) (*fixture, *script, string, *[]string) {
	t.Helper()
	f := newFixture(t)
	if err := f.v.Put(vault.Account{ID: "A", Label: "a", Identity: "id-a", Block: []byte(adoptR1)}); err != nil {
		t.Fatal(err)
	}
	a, _, id := f.enrol("box")
	f.reg.SwapIn("A", id)
	s := f.newScript("id-a", adoptR1)
	s.serve(a)
	var mu sync.Mutex
	reset := []string{}
	f.h.SetOnReplaced(func(acct string) { mu.Lock(); reset = append(reset, acct); mu.Unlock() })
	if err := f.h.AdoptHeld(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	return f, s, id, &reset
}

func TestAdoptHeldTakesTheRotatedBlockAndResetsThePoller(t *testing.T) {
	f, s, id, reset := adoptFixture(t)
	s.mu.Lock()
	s.liveBlock = adoptR2
	s.mu.Unlock()
	if err := f.h.AdoptHeld(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if got := f.vaultBlock("A"); got != adoptR2 {
		t.Fatalf("vault A = %s", got)
	}
	if len(*reset) != 1 || (*reset)[0] != "A" {
		t.Fatalf("poller resets %v", *reset)
	}
	// A second rotation is adopted too: the host's lineage moved with the vault copy.
	s.mu.Lock()
	s.liveBlock = `{"accessToken":"a3","refreshToken":"R3"}`
	s.mu.Unlock()
	if err := f.h.AdoptHeld(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if got := f.vaultBlock("A"); got != `{"accessToken":"a3","refreshToken":"R3"}` {
		t.Fatalf("vault A = %s", got)
	}
}

func TestAdoptHeldIsANoOpWhenTheBlockIsIdentical(t *testing.T) {
	f, _, id, reset := adoptFixture(t)
	before, _ := f.v.Get("A")
	time.Sleep(2 * time.Millisecond)
	if err := f.h.AdoptHeld(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	after, _ := f.v.Get("A")
	if !after.Updated.Equal(before.Updated) || string(after.Block) != adoptR1 {
		t.Fatalf("vault changed: %+v -> %+v", before, after)
	}
	if len(*reset) != 0 {
		t.Fatalf("poller reset on a no-op: %v", *reset)
	}
}

func TestAdoptHeldRefusesADifferentLineage(t *testing.T) {
	f, s, id, reset := adoptFixture(t)
	// A host that was moved to another login out of band: its lineage proof no longer matches.
	f.h.mu.Lock()
	f.h.hosts[id].lineage = lineageHash([]byte(`{"refreshToken":"OTHER"}`))
	f.h.mu.Unlock()
	s.mu.Lock()
	s.liveBlock = adoptR2
	s.mu.Unlock()
	if err := f.h.AdoptHeld(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if got := f.vaultBlock("A"); got != adoptR1 {
		t.Fatalf("vault A = %s, want unchanged", got)
	}
	if len(*reset) != 0 {
		t.Fatalf("poller reset on a refusal: %v", *reset)
	}
}

func TestAdoptHeldSkipsAHostThatIsNotTheActiveHolder(t *testing.T) {
	f, s, id, _ := adoptFixture(t)
	_, _, other := f.enrol("box2")
	f.reg.SwapIn("A", other) // id becomes Shared
	s.mu.Lock()
	s.liveBlock = adoptR2
	s.mu.Unlock()
	if err := f.h.AdoptHeld(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if got := f.vaultBlock("A"); got != adoptR1 {
		t.Fatalf("vault A = %s, want unchanged", got)
	}
}

func TestAdoptHeldStoresOnlyTheClaudeAiOauthBlock(t *testing.T) {
	f, s, id, _ := adoptFixture(t)
	s.mu.Lock()
	s.liveBlock = `{"claudeAiOauth":` + adoptR2 + `,"mcpOAuth":{"srv":"mcp-secret"}}`
	s.mu.Unlock()
	if err := f.h.AdoptHeld(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if got := f.vaultBlock("A"); got != adoptR2 {
		t.Fatalf("vault A = %s", got)
	}
}

func TestAdoptDueHostsThrottlesPerHostAndSkipsOfflineOnes(t *testing.T) {
	f := newFixture(t)
	_, _, id := f.enrol("box")
	f.h.mu.Lock()
	due := f.h.adoptDueLocked(f.clk.Now())
	again := f.h.adoptDueLocked(f.clk.Now())
	f.h.mu.Unlock()
	if len(due) != 1 || due[0] != id || len(again) != 0 {
		t.Fatalf("due %v then %v", due, again)
	}
	f.clk.Advance(adoptEvery + time.Second)
	f.h.mu.Lock()
	later := f.h.adoptDueLocked(f.clk.Now())
	f.h.mu.Unlock()
	if len(later) != 1 {
		t.Fatalf("after the interval: %v", later)
	}
	f.clk.Advance(OfflineAfter + time.Second)
	f.h.mu.Lock()
	f.h.hosts[id].c = nil
	off := f.h.adoptDueLocked(f.clk.Now().Add(adoptEvery * 2))
	f.h.mu.Unlock()
	if len(off) != 0 {
		t.Fatalf("offline host due: %v", off)
	}
}

func TestAdoptHeldConcurrentWithSwapAndItself(t *testing.T) {
	f, s, id, _ := adoptFixture(t)
	if err := f.v.Put(vault.Account{ID: "B", Label: "b", Identity: "id-b", Block: []byte(`{"refreshToken":"RB"}`)}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.liveBlock = adoptR2
	s.mu.Unlock()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = f.h.AdoptHeld(context.Background(), id) }()
	}
	wg.Add(1)
	go func() { defer wg.Done(); _, _ = f.h.Swap(context.Background(), id, "B") }()
	wg.Wait() // the assertion is -race plus no deadlock: adopt and swap share the host's swapMu
}
