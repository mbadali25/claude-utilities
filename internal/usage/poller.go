package usage

// The scheduler. One goroutine (Run) polls at most one account per step, never closer than MinSpacing
// (jittered) to the previous request, and picks the next account by tier: accounts a host is using
// live come first, idle accounts are visited rarely, and an account in backoff is never visited
// until its wait is over. The upstream endpoint rate limits hard, so the aim is the fewest requests
// that keep the numbers someone is looking at fresh.

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"os"
	"sync"
	"time"

	"claude-utilities/internal/logx"
	"claude-utilities/internal/vault"
)

// logger is the poller's structured, allowlist-filtered logger.
var logger = logx.New(os.Stderr).With("component", "usage")

func init() {
	// "field" carries a response field path (five_hour.resets_at) and never a value.
	// "tier" is one of active, idle, backoff.
	logx.Allow("field", "tier")
}

// Tier says how often an account is polled.
type Tier string

const (
	// TierActive: a host holds the login live, it was swapped in recently, or someone is looking at it.
	TierActive Tier = "active"
	// TierIdle: nobody is using it; checked rarely.
	TierIdle Tier = "idle"
	// TierBackoff: the last poll failed; nothing is sent until the wait is over.
	TierBackoff Tier = "backoff"
)

func (t Tier) rank() int {
	switch t {
	case TierActive:
		return 0
	case TierIdle:
		return 1
	}
	return 2
}

// Config holds every scheduling constant. A zero field takes its default.
type Config struct {
	MinSpacing        time.Duration // global gap between any two scheduled requests
	ManualSpacing     time.Duration // gap a button-pressed poll waits for after the previous request
	ActiveEvery       time.Duration
	IdleEvery         time.Duration
	BackoffBase       time.Duration // first wait after a failure; doubles per consecutive failure
	BackoffMax        time.Duration // cap on that doubling
	UnauthorizedEvery time.Duration // wait after a 401/403; a manual Refresh may go sooner
	MaxRetryAfter     time.Duration // sanity cap on a server-sent Retry-After
	ActiveHold        time.Duration // how long a swap keeps an account in the active tier
	WatchHold         time.Duration // how long being looked at (card open, Refresh) keeps it active
	Jitter            float64       // fraction, e.g. 0.2 = plus or minus 20%
}

// DefaultConfig is the production schedule. For 10 accounts with 1 held live it is about 57
// requests an hour, where polling every account every 5 minutes was 120.
func DefaultConfig() Config {
	return Config{
		MinSpacing: 25 * time.Second, ManualSpacing: 2 * time.Second,
		ActiveEvery: 2 * time.Minute, IdleEvery: 20 * time.Minute,
		BackoffBase: 5 * time.Minute, BackoffMax: time.Hour, UnauthorizedEvery: time.Hour,
		MaxRetryAfter: 6 * time.Hour,
		ActiveHold:    10 * time.Minute, WatchHold: 5 * time.Minute, Jitter: 0.2,
	}
}

func (c Config) withDefaults() Config {
	d := DefaultConfig()
	if c.MinSpacing == 0 {
		c.MinSpacing = d.MinSpacing
	}
	if c.ManualSpacing == 0 {
		c.ManualSpacing = d.ManualSpacing
	}
	if c.ActiveEvery == 0 {
		c.ActiveEvery = d.ActiveEvery
	}
	if c.IdleEvery == 0 {
		c.IdleEvery = d.IdleEvery
	}
	if c.BackoffBase == 0 {
		c.BackoffBase = d.BackoffBase
	}
	if c.BackoffMax == 0 {
		c.BackoffMax = d.BackoffMax
	}
	if c.UnauthorizedEvery == 0 {
		c.UnauthorizedEvery = d.UnauthorizedEvery
	}
	if c.MaxRetryAfter == 0 {
		c.MaxRetryAfter = d.MaxRetryAfter
	}
	if c.ActiveHold == 0 {
		c.ActiveHold = d.ActiveHold
	}
	if c.WatchHold == 0 {
		c.WatchHold = d.WatchHold
	}
	if c.Jitter < 0 || c.Jitter >= 1 {
		c.Jitter = d.Jitter
	}
	return c
}

// Poller polls a set of accounts on the schedule above.
type Poller struct {
	d     Doer
	cfg   Config
	now   func() time.Time
	rnd   func() float64 // uniform in [0,1); replaced in tests
	sleep func(ctx context.Context, d time.Duration) error
	wakeC chan struct{}

	mu          sync.Mutex
	accounts    func() []vault.Account
	held        func(accountID string) bool
	last        map[string]Usage
	fails       map[string]int
	authFail    map[string]bool // the standing failure is a 401/403, not a rate limit
	nextAt      map[string]time.Time
	manualAt    map[string]time.Time
	activeUntil map[string]time.Time
	watchUntil  map[string]time.Time
	epoch       map[string]uint64 // bumped by Forget; a poll that began earlier is discarded
	epochSeq    uint64
	lastPollAt  time.Time
	slotGap     time.Duration // spacing owed after lastPollAt, jittered when that poll began
	inflight    map[string]*flight
	refresher   Refresher
	onRefreshed func(accountID string, block json.RawMessage)
}

// NewPoller returns a poller with the given schedule.
func NewPoller(d Doer, cfg Config) *Poller {
	return &Poller{
		d: d, cfg: cfg.withDefaults(), now: time.Now, rnd: rand.Float64, sleep: sleepCtx,
		wakeC: make(chan struct{}, 1),
		last:  map[string]Usage{}, fails: map[string]int{}, authFail: map[string]bool{},
		nextAt: map[string]time.Time{}, manualAt: map[string]time.Time{},
		activeUntil: map[string]time.Time{}, watchUntil: map[string]time.Time{},
		epoch: map[string]uint64{}, inflight: map[string]*flight{},
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// SetAccounts names where the poller reads the accounts to poll. The func must return only
// server-owned accounts. Call it before Run; RefreshNow reports an unknown account until it is set.
func (p *Poller) SetAccounts(accounts func() []vault.Account) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.accounts = accounts
}

// SetHeld names how the poller learns that a host is using an account live. Call before Run.
func (p *Poller) SetHeld(held func(accountID string) bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.held = held
}

// accountsFn returns the configured source, or one that yields nothing.
func (p *Poller) accountsFn() func() []vault.Account {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.accounts == nil {
		return func() []vault.Account { return nil }
	}
	return p.accounts
}

// SetRefresher enables one refresh-and-retry on 401. onRefreshed receives the
// new block so the caller can persist it (a rotated refresh token is lost
// otherwise). Call before Run.
func (p *Poller) SetRefresher(r Refresher, onRefreshed func(accountID string, block json.RawMessage)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refresher, p.onRefreshed = r, onRefreshed
}

// Last returns the last known usage for an account.
func (p *Poller) Last(accountID string) (Usage, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	u, ok := p.last[accountID]
	return u, ok
}

// Info is what the page says about an account's schedule.
type Info struct {
	Tier   Tier
	Every  time.Duration // the interval of the tier; zero in backoff
	NextAt time.Time     // zero when the account is due now
}

// Info reports the account's tier and when it is next due.
func (p *Poller) Info(accountID string) Info {
	p.mu.Lock()
	defer p.mu.Unlock()
	t := p.tierLocked(accountID, p.now())
	return Info{Tier: t, Every: p.everyLocked(t), NextAt: p.nextAt[accountID]}
}

// NoteSwap records that a swap just put this account on a host: it joins the active tier for
// ActiveHold and gets one immediate poll (still subject to the global spacing). An account in
// backoff keeps its wait; the swap does not buy it a request.
func (p *Poller) NoteSwap(accountID string) {
	p.mu.Lock()
	now := p.now()
	p.activeUntil[accountID] = now.Add(p.cfg.ActiveHold)
	if p.fails[accountID] == 0 {
		p.nextAt[accountID] = now
	}
	p.mu.Unlock()
	p.wake()
}

// Touch records that someone is looking at the account (its card was opened, Refresh was pressed):
// it is active for WatchHold. The first touch of an idle account also brings its next poll forward
// to ActiveEvery after its last answer; repeated touches change nothing.
func (p *Poller) Touch(accountID string) {
	p.mu.Lock()
	now := p.now()
	fresh := !now.Before(p.watchUntil[accountID])
	p.watchUntil[accountID] = now.Add(p.cfg.WatchHold)
	if fresh && p.fails[accountID] == 0 {
		due := p.last[accountID].FetchedAt.Add(p.cfg.ActiveEvery)
		if n, ok := p.nextAt[accountID]; ok && n.After(due) {
			p.nextAt[accountID] = due
		}
	}
	p.mu.Unlock()
	p.wake()
}

// Forget drops every trace of one account and silences any poll of it still in flight: that poll
// finishes, but its answer is neither stored nor reported. A later account reusing the id starts
// from nothing. It is a no-op for an id the poller never saw.
func (p *Poller) Forget(accountID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.last, accountID)
	delete(p.fails, accountID)
	delete(p.authFail, accountID)
	delete(p.nextAt, accountID)
	delete(p.manualAt, accountID)
	delete(p.activeUntil, accountID)
	delete(p.watchUntil, accountID)
	p.epochSeq++
	p.epoch[accountID] = p.epochSeq
}

// Reset is for an account whose stored login was just replaced ("sign in again"): the failure state
// belonged to the old login. It clears the failure count, the standing 401 and the wait, drops the
// error from the last answer (the last-known windows stay), makes the account due now so the next
// step polls it, and silences any poll of the old login still in flight. It is a no-op for an id the
// poller never saw.
func (p *Poller) Reset(accountID string) {
	p.mu.Lock()
	if u, ok := p.last[accountID]; ok {
		u.Err, u.RetryAt = "", time.Time{}
		p.last[accountID] = u
	}
	delete(p.fails, accountID)
	delete(p.authFail, accountID)
	delete(p.nextAt, accountID)
	delete(p.manualAt, accountID)
	p.epochSeq++
	p.epoch[accountID] = p.epochSeq
	p.mu.Unlock()
	p.wake()
}

func (p *Poller) wake() {
	select {
	case p.wakeC <- struct{}{}:
	default:
	}
}

// tierLocked classifies an account. Callers hold p.mu.
func (p *Poller) tierLocked(id string, now time.Time) Tier {
	switch {
	case p.fails[id] > 0:
		return TierBackoff
	case now.Before(p.activeUntil[id]), now.Before(p.watchUntil[id]):
		return TierActive
	case p.held != nil && p.held(id):
		return TierActive
	}
	return TierIdle
}

func (p *Poller) everyLocked(t Tier) time.Duration {
	switch t {
	case TierActive:
		return p.cfg.ActiveEvery
	case TierIdle:
		return p.cfg.IdleEvery
	}
	return 0
}

// jitter spreads d by plus or minus Jitter.
func (p *Poller) jitter(d time.Duration) time.Duration {
	return time.Duration(float64(d) * (1 + p.cfg.Jitter*(2*p.rnd()-1)))
}

// backoff is the wait after the given number of consecutive failures: BackoffBase doubling up to
// BackoffMax, or the server's Retry-After when that is longer (itself capped by MaxRetryAfter).
// It carries no jitter; record adds it.
func (p *Poller) backoff(fails int, retryAfter time.Duration) time.Duration {
	if fails < 1 {
		fails = 1
	}
	if fails > 20 {
		fails = 20
	}
	w := p.cfg.BackoffBase << (fails - 1)
	if w > p.cfg.BackoffMax || w <= 0 {
		w = p.cfg.BackoffMax
	}
	if retryAfter > p.cfg.MaxRetryAfter {
		retryAfter = p.cfg.MaxRetryAfter
	}
	if retryAfter > w {
		w = retryAfter
	}
	return w
}

// Run polls on the schedule until ctx ends. Call SetAccounts first.
func (p *Poller) Run(ctx context.Context, onUpdate func(accountID string, u Usage)) {
	for {
		polled, wait := p.step(ctx, onUpdate)
		if ctx.Err() != nil {
			return
		}
		if polled {
			continue // the next step reports the spacing owed
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-p.wakeC:
			t.Stop()
		case <-t.C:
		}
	}
}

const maxIdleWait = 30 * time.Second

// step polls at most one due account. It returns whether it did, and otherwise how long to wait
// before looking again: the rest of the global spacing when something is due, else the time to the
// earliest due account (capped, because the account list can change).
func (p *Poller) step(ctx context.Context, onUpdate func(string, Usage)) (bool, time.Duration) {
	accts := p.accountsFn()()
	p.mu.Lock()
	now := p.now()
	var best *vault.Account
	var bestTier Tier
	var bestAt time.Time
	soonest := maxIdleWait
	for i := range accts {
		a := &accts[i]
		if p.inflight[a.ID] != nil {
			continue
		}
		if n := p.nextAt[a.ID]; n.After(now) {
			if d := n.Sub(now); d < soonest {
				soonest = d
			}
			continue
		}
		t := p.tierLocked(a.ID, now)
		if t == TierBackoff {
			t = TierIdle // backoff is over; due accounts rank by when they became due
		}
		n := p.nextAt[a.ID]
		if best == nil || t.rank() < bestTier.rank() || (t == bestTier && n.Before(bestAt)) {
			best, bestTier, bestAt = a, t, n
		}
	}
	if best == nil {
		p.mu.Unlock()
		return false, clampWait(soonest)
	}
	if owed := p.lastPollAt.Add(p.slotGap).Sub(now); owed > 0 {
		p.mu.Unlock()
		return false, owed
	}
	p.mu.Unlock()
	a := *best
	g := p.enter(a.ID, false)
	if !g.owner {
		return false, time.Second
	}
	u, _ := p.poll(ctx, a, g)
	p.mu.Lock()
	gone := p.epoch[a.ID] != g.epoch
	p.mu.Unlock()
	if onUpdate != nil && !gone {
		onUpdate(a.ID, u)
	}
	return true, 0
}

func clampWait(d time.Duration) time.Duration {
	if d < time.Second {
		return time.Second
	}
	return d
}

func accessToken(block json.RawMessage) (string, bool) {
	var b struct {
		AccessToken string `json:"accessToken"`
	}
	if json.Unmarshal(block, &b) != nil || b.AccessToken == "" {
		return "", false
	}
	return b.AccessToken, true
}

func category(err error) string {
	switch {
	case errors.Is(err, ErrRateLimited):
		return "rate limited"
	case errors.Is(err, ErrUnauthorized):
		return "unauthorized"
	case errors.Is(err, ErrSchema):
		return "unexpected schema"
	case errors.Is(err, errBadBlock):
		return "no access token"
	default:
		return "unavailable"
	}
}

func (p *Poller) fetchAccount(ctx context.Context, a vault.Account) (Usage, error) {
	tok, ok := accessToken(a.Block)
	if !ok {
		return Usage{}, errBadBlock
	}
	u, err := Fetch(ctx, p.d, tok)
	if !errors.Is(err, ErrUnauthorized) {
		return u, err
	}
	p.mu.Lock()
	r, cb := p.refresher, p.onRefreshed
	p.mu.Unlock()
	if r == nil {
		return u, err
	}
	nb, rerr := r.Refresh(ctx, a.Block)
	if rerr != nil {
		return Usage{}, ErrUnauthorized // do not surface refresher text
	}
	if cb != nil {
		cb(a.ID, nb)
	}
	tok, ok = accessToken(nb)
	if !ok {
		return Usage{}, errBadBlock
	}
	return Fetch(ctx, p.d, tok)
}

// record stores one poll's answer and schedules the account's next poll. A success clears the
// account's failures and waits its tier's interval; a failure keeps the last-known windows with
// their own FetchedAt, names the failure category, and waits out a backoff. It returns what was
// stored, which is what every caller reports. A poll that began before Forget stores nothing.
func (p *Poller) record(id string, u Usage, err error, epoch uint64) Usage {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if p.epoch[id] != epoch {
		return u
	}
	if err == nil {
		u.FetchedAt = now.UTC()
		u.RetryAt = time.Time{}
		p.fails[id] = 0
		delete(p.authFail, id)
		p.last[id] = u
		t := p.tierLocked(id, now)
		p.nextAt[id] = now.Add(p.jitter(p.everyLocked(t)))
		return u
	}
	p.fails[id]++
	var wait time.Duration
	var rl *RateLimitError
	switch {
	case errors.Is(err, ErrUnauthorized):
		p.authFail[id] = true
		wait = p.jitter(p.cfg.UnauthorizedEvery)
	default:
		delete(p.authFail, id)
		var ra time.Duration
		if errors.As(err, &rl) {
			ra = rl.RetryAfter
		}
		wait = p.backoff(p.fails[id], ra)
		if ra >= wait {
			// The server named the time: never come back before it, and only spread later.
			wait += time.Duration(float64(wait) * p.cfg.Jitter * p.rnd())
		} else {
			wait = p.jitter(wait)
		}
	}
	p.nextAt[id] = now.Add(wait)
	u = p.last[id] // keep last-known windows and their FetchedAt
	u.Err = category(err)
	u.RetryAt = p.nextAt[id]
	logger.Warn("poll failed", "action", "poll", "result", "failed", "account", id, "tier", string(TierBackoff),
		"reason", u.Err, "field", SchemaField(err), "durationms", wait.Milliseconds())
	p.last[id] = u
	return u
}
