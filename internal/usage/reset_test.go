package usage

import (
	"context"
	"testing"
	"time"
)

// After "sign in again" the stored login is new, so a standing 401 and its hour of waiting no longer
// describe it: Reset clears the failure state, keeps the account, and makes it due now.
func TestResetEndsUnauthorizedBackoffAndPollsImmediately(t *testing.T) {
	h := &hits{}
	p, c := newSched(nil, "a")
	h.c = c
	p.d = h.doer(401, nil)
	p.step(context.Background(), nil)
	if u, _ := p.Last("a"); u.Err != "unauthorized" {
		t.Fatalf("setup: %+v", u)
	}
	if got := p.Info("a"); got.Tier != TierBackoff || got.NextAt.Sub(c.t) != time.Hour {
		t.Fatalf("setup: %+v", got)
	}

	p.d = h.doer(200, nil)
	p.Reset("a")
	if u, _ := p.Last("a"); u.Err != "" || !u.RetryAt.IsZero() {
		t.Fatalf("error state survived Reset: %+v", u)
	}
	if got := p.Info("a"); got.Tier == TierBackoff || !got.NextAt.IsZero() && got.NextAt.After(c.t) {
		t.Fatalf("still in backoff or not due: %+v", got)
	}
	before := len(h.ids)
	c.t = c.t.Add(30 * time.Second) // the global spacing after the 401 still applies; the hour does not
	polled, _ := p.step(context.Background(), nil)
	if !polled || len(h.ids) != before+1 {
		t.Fatalf("Reset did not buy one immediate poll: polled=%v calls %d->%d", polled, before, len(h.ids))
	}
	if u, _ := p.Last("a"); u.Err != "" || u.FetchedAt.IsZero() {
		t.Fatalf("after the poll: %+v", u)
	}
}

func TestResetOfAnUnknownAccountIsHarmless(t *testing.T) {
	p, _ := newSched(nil, "a")
	p.Reset("nope")
	if _, ok := p.Last("nope"); ok {
		t.Fatal("Reset invented state")
	}
}

// A poll that began with the old login must not write its answer over the fresh start.
func TestResetDiscardsAnInFlightPoll(t *testing.T) {
	p, c := newSched(nil, "a")
	h := &hits{c: c}
	p.d = h.doer(401, nil)
	g := p.enter("a", false)
	p.Reset("a")
	u := p.record("a", Usage{}, ErrUnauthorized, g.epoch)
	p.finish("a", g, u, ErrUnauthorized)
	if u, ok := p.Last("a"); ok && u.Err != "" {
		t.Fatalf("a stale poll stored %+v after Reset", u)
	}
}
