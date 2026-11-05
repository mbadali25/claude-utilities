package usage

import (
	"testing"
	"time"
)

// Poller must satisfy the interface the remove path takes, or a caller holding a Forgetter breaks.
var _ Forgetter = (*Poller)(nil)

func TestForgetDropsEveryTraceOfOneAccount(t *testing.T) {
	p := NewPoller(nil, time.Minute)
	now := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return now }

	// A failed poll leaves a last answer, a failure count and a backoff; a manual poll leaves a floor.
	p.record("gone", Usage{}, ErrUnauthorized)
	p.record("stays", Usage{}, ErrUnauthorized)
	p.mu.Lock()
	p.manualAt["gone"] = now
	p.manualAt["stays"] = now
	p.mu.Unlock()

	p.Forget("gone")

	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.last["gone"]; ok {
		t.Error("Forget left the last answer behind")
	}
	if _, ok := p.fails["gone"]; ok {
		t.Error("Forget left the failure count behind")
	}
	if _, ok := p.nextAt["gone"]; ok {
		t.Error("Forget left the backoff behind")
	}
	if _, ok := p.manualAt["gone"]; ok {
		t.Error("Forget left the manual-poll floor behind")
	}
	if _, ok := p.last["stays"]; !ok {
		t.Error("Forget touched another account's last answer")
	}
	if p.fails["stays"] == 0 {
		t.Error("Forget touched another account's failure count")
	}
	if _, ok := p.nextAt["stays"]; !ok {
		t.Error("Forget touched another account's backoff")
	}
	if _, ok := p.manualAt["stays"]; !ok {
		t.Error("Forget touched another account's manual floor")
	}
}

func TestForgetAnUnknownAccountIsANoOp(t *testing.T) {
	p := NewPoller(nil, time.Minute)
	p.Forget("never-seen")
	if _, ok := p.Last("never-seen"); ok {
		t.Fatal("Forget invented an entry")
	}
}

// A forgotten account must not inherit the backoff it had before: an id reused later starts clean.
func TestForgetClearsTheBackoffSoAFreshPollIsDue(t *testing.T) {
	p := NewPoller(nil, time.Minute)
	now := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		p.record("a", Usage{}, ErrUnauthorized)
	}
	if g := p.enter("a", true); g.wait == 0 {
		t.Fatal("expected the backoff to refuse a manual poll")
	}
	p.Forget("a")
	if g := p.enter("a", true); g.wait != 0 {
		t.Fatalf("a forgotten account is still waiting out %v", g.wait)
	}
}
