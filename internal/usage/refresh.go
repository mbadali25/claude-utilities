package usage

// On-demand polling, for the admin page's Refresh buttons. Two guards stand between a button and
// Anthropic's endpoint: a single flight per account, so callers that overlap share one request, and
// a floor between manual polls that also waits out whatever backoff a failure left behind.

import (
	"context"
	"time"

	"claude-utilities/internal/vault"
)

// MinRefreshInterval is the shortest gap between two on-demand polls of one account. A refresh
// inside it is refused with the time left, so a held-down button costs the endpoint nothing.
const MinRefreshInterval = 15 * time.Second

// RefreshStatus is what became of one account's on-demand poll.
type RefreshStatus string

const (
	// Refreshed means the endpoint answered, for this caller or for the flight it joined.
	Refreshed RefreshStatus = "refreshed"
	// RateLimited means the poll was refused by the floor or by a failure's backoff; the account's
	// last known usage is still reported, with how long is left to wait.
	RateLimited RefreshStatus = "rate_limited"
	// UnknownID means no stored account has that id.
	UnknownID RefreshStatus = "unknown_id"
	// Failed means the endpoint was asked and did not give usable usage. Usage.Err names the
	// category and the windows are whatever was last known.
	Failed RefreshStatus = "error"
)

// RefreshResult is one account's outcome. It never carries a credential block: Usage holds windows,
// a timestamp and an error category only.
type RefreshResult struct {
	ID         string
	Status     RefreshStatus
	Usage      Usage
	RetryAfter time.Duration // set only when Status is RateLimited
}

// flight is one in-progress poll of one account. Callers that arrive while it runs wait on done and
// read the same answer; only its owner fetches and records.
type flight struct {
	done chan struct{}
	u    Usage
	err  error
}

func (f *flight) wait(ctx context.Context) (Usage, error) {
	select {
	case <-f.done:
		return f.u, f.err
	case <-ctx.Done():
		return Usage{}, errUnavailable
	}
}

// gate is one locked decision about polling an account now: join the flight already running, own a
// new one, or (manual callers only) wait.
type gate struct {
	f     *flight
	owner bool          // the caller must fetch, record and finish f
	wait  time.Duration // non-zero: refused, this much time is left
}

// enter decides, under one lock, what a caller may do with this account. A poll already in flight is
// joined whoever asked, so a manual refresh never duplicates a scheduled one. A manual caller that
// is not refused marks the floor for the next one.
func (p *Poller) enter(id string, manual bool) gate {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if f := p.inflight[id]; f != nil {
		if manual {
			p.manualAt[id] = now
		}
		return gate{f: f}
	}
	if manual {
		until := p.manualAt[id].Add(MinRefreshInterval)
		if n := p.nextAt[id]; n.After(until) {
			until = n // the scheduler is serving a backoff; a button does not get past it
		}
		if now.Before(until) {
			return gate{wait: until.Sub(now)}
		}
		p.manualAt[id] = now
	}
	f := &flight{done: make(chan struct{})}
	p.inflight[id] = f
	return gate{f: f, owner: true}
}

// poll runs the account's poll, or waits for the one already running, and returns what was stored.
func (p *Poller) poll(ctx context.Context, a vault.Account, g gate) (Usage, error) {
	if !g.owner {
		return g.f.wait(ctx)
	}
	u, err := p.fetchAccount(ctx, a)
	u = p.record(a.ID, u, err)
	p.mu.Lock()
	delete(p.inflight, a.ID)
	p.mu.Unlock()
	g.f.u, g.f.err = u, err
	close(g.f.done)
	return u, err
}

// RefreshNow polls the named accounts outside the schedule and reports one result each, in the order
// asked (every account, in the accounts source's order, when ids is empty). It makes at most one
// request per account and shares a poll already in flight, so a page full of accounts cannot turn
// one click into a flood.
func (p *Poller) RefreshNow(ctx context.Context, ids []string) []RefreshResult {
	known := map[string]vault.Account{}
	var order []string
	for _, a := range p.accountsFn()() {
		if _, dup := known[a.ID]; dup {
			continue
		}
		known[a.ID] = a
		order = append(order, a.ID)
	}
	want := order
	if len(ids) > 0 {
		want = ids
	}
	out := make([]RefreshResult, 0, len(want))
	for _, id := range want {
		a, ok := known[id]
		if !ok {
			out = append(out, RefreshResult{ID: id, Status: UnknownID})
			continue
		}
		if g := p.enter(id, true); g.wait > 0 {
			last, _ := p.Last(id)
			out = append(out, RefreshResult{ID: id, Status: RateLimited, Usage: last, RetryAfter: g.wait})
		} else if u, err := p.poll(ctx, a, g); err != nil {
			out = append(out, RefreshResult{ID: id, Status: Failed, Usage: u})
		} else {
			out = append(out, RefreshResult{ID: id, Status: Refreshed, Usage: u})
		}
	}
	return out
}
