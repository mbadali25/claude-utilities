package ownership

import (
	"fmt"
	"sync"
	"testing"
)

func TestIdleAccountOwnedByServer(t *testing.T) {
	r := New()
	if o := r.OwnerOf("a"); !o.Server || o.HostID != "" {
		t.Fatalf("got %+v", o)
	}
	if len(r.HostsUsing("a")) != 0 {
		t.Fatal("expected no hosts")
	}
}

func TestSwapInMakesHostOwner(t *testing.T) {
	r := New()
	r.SwapIn("a", "h1")
	if o := r.OwnerOf("a"); o.Server || o.HostID != "h1" {
		t.Fatalf("got %+v", o)
	}
	if s := r.HostsUsing("a")["h1"]; s != Active {
		t.Fatalf("got %v", s)
	}
}

func TestSecondHostSwapInMovesOwnerAndMarksFirstShared(t *testing.T) {
	r := New()
	r.SwapIn("a", "h1")
	r.SwapIn("a", "h2")
	if o := r.OwnerOf("a"); o.HostID != "h2" {
		t.Fatalf("got %+v", o)
	}
	m := r.HostsUsing("a")
	if m["h1"] != Shared || m["h2"] != Active {
		t.Fatalf("got %v", m)
	}
}

func TestSwapAwayLastHostReturnsToServer(t *testing.T) {
	r := New()
	r.SwapIn("a", "h1")
	r.SwapAway("a", "h1")
	if o := r.OwnerOf("a"); !o.Server {
		t.Fatalf("got %+v", o)
	}
	if len(r.HostsUsing("a")) != 0 {
		t.Fatal("expected no hosts")
	}
	r.SwapAway("a", "h1") // unknown: no-op
	r.SwapAway("zz", "h1")
}

func TestSwapAwayOwnerPassesToRemainingHolder(t *testing.T) {
	r := New()
	r.SwapIn("a", "h1")
	r.SwapIn("a", "h2")
	r.SwapIn("a", "h3")
	r.SwapAway("a", "h3")
	if o := r.OwnerOf("a"); o.HostID != "h2" {
		t.Fatalf("got %+v", o)
	}
	if s := r.HostsUsing("a")["h2"]; s != Active {
		t.Fatalf("got %v", s)
	}
	// non-owner leaving keeps owner
	r.SwapAway("a", "h1")
	if o := r.OwnerOf("a"); o.HostID != "h2" {
		t.Fatalf("got %+v", o)
	}
}

func TestHostLostOwnerWithSharersMarksStale(t *testing.T) {
	r := New()
	r.SwapIn("a", "h1")
	r.SwapIn("a", "h2")
	r.HostLost("h2")
	m := r.HostsUsing("a")
	if _, ok := m["h2"]; ok {
		t.Fatal("lost host still listed")
	}
	if m["h1"] != Stale {
		t.Fatalf("got %v", m)
	}
}

func TestHostLostSoleOwnerReturnsToServerNeedsWriteback(t *testing.T) {
	r := New()
	r.SwapIn("a", "h1")
	r.HostLost("h1")
	if o := r.OwnerOf("a"); !o.Server {
		t.Fatalf("got %+v", o)
	}
	if !r.NeedsWritebackCheck("a") {
		t.Fatal("expected writeback check")
	}
	r.SwapIn("a", "h2")
	if r.NeedsWritebackCheck("a") {
		t.Fatal("flag should clear on swap in")
	}
}

func TestHostLostNonOwnerJustRemoved(t *testing.T) {
	r := New()
	r.SwapIn("a", "h1")
	r.SwapIn("a", "h2")
	r.HostLost("h1")
	if o := r.OwnerOf("a"); o.HostID != "h2" {
		t.Fatalf("got %+v", o)
	}
	if s := r.HostsUsing("a")["h2"]; s != Active {
		t.Fatalf("got %v", s)
	}
}

func TestSwapInSameHostTwiceIsIdempotent(t *testing.T) {
	r := New()
	r.SwapIn("a", "h1")
	r.SwapIn("a", "h1")
	if len(r.HostsUsing("a")) != 1 || r.OwnerOf("a").HostID != "h1" {
		t.Fatal("not idempotent")
	}
}

func TestHostsUsingReturnsCopy(t *testing.T) {
	r := New()
	r.SwapIn("a", "h1")
	r.HostsUsing("a")["h9"] = Active
	if len(r.HostsUsing("a")) != 1 {
		t.Fatal("map aliased")
	}
}

func TestConcurrentOpsRaceFree(t *testing.T) {
	r := New()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			h := fmt.Sprintf("h%d", i%4)
			for j := 0; j < 100; j++ {
				r.SwapIn("a", h)
				r.OwnerOf("a")
				r.HostsUsing("a")
				r.SwapAway("a", h)
				r.HostLost(h)
			}
		}(i)
	}
	wg.Wait()
}
