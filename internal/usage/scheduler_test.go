package usage

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"claude-utilities/internal/logx"
	"claude-utilities/internal/vault"
)

// schedCfg is a schedule with round numbers and no jitter, so a test can read the clock.
func schedCfg() Config {
	return Config{
		MinSpacing: 25 * time.Second, ManualSpacing: 2 * time.Second,
		ActiveEvery: 2 * time.Minute, IdleEvery: 20 * time.Minute,
		BackoffBase: 5 * time.Minute, BackoffMax: time.Hour, UnauthorizedEvery: time.Hour,
		MaxRetryAfter: 6 * time.Hour, ActiveHold: 10 * time.Minute, WatchHold: 5 * time.Minute,
	}
}

func newSched(d Doer, ids ...string) (*Poller, *clock) {
	p := NewPoller(d, schedCfg())
	c := &clock{t: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
	p.now = c.now
	p.rnd = func() float64 { return 0.5 } // jitter is (2*0.5-1) = 0
	p.sleep = func(_ context.Context, d time.Duration) error { c.t = c.t.Add(d); return nil }
	p.SetAccounts(func() []vault.Account {
		out := make([]vault.Account, 0, len(ids))
		for _, id := range ids {
			out = append(out, acct(id, "tok-"+id))
		}
		return out
	})
	return p, c
}

// hits records which account each request was for and when, by the fake clock.
type hits struct {
	mu  sync.Mutex
	c   *clock
	ids []string
	at  []time.Time
}

func (h *hits) doer(code int, hdr map[string]string) *fakeDoer {
	return &fakeDoer{fn: func(r *http.Request) (*http.Response, error) {
		h.mu.Lock()
		h.ids = append(h.ids, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer tok-"))
		h.at = append(h.at, h.c.t)
		h.mu.Unlock()
		if code == 200 {
			return resp(200, okBody, nil), nil
		}
		return resp(code, "", hdr), nil
	}}
}

// run advances the fake clock through the poller's own waits for the given span.
func run(p *Poller, c *clock, span time.Duration) {
	end := c.t.Add(span)
	for c.t.Before(end) {
		polled, wait := p.step(context.Background(), nil)
		if !polled {
			c.t = c.t.Add(wait)
		}
	}
}

func TestStartupFanOutIsSerialisedAtTheGlobalSpacing(t *testing.T) {
	h := &hits{}
	p, c := newSched(nil, "a", "b", "c", "d", "e", "f", "g", "h", "i", "j")
	h.c = c
	p.d = h.doer(200, nil)
	run(p, c, 10*time.Minute)
	if len(h.at) < 10 {
		t.Fatalf("only %d requests", len(h.at))
	}
	for i := 1; i < len(h.at); i++ {
		if gap := h.at[i].Sub(h.at[i-1]); gap < 25*time.Second {
			t.Fatalf("requests %d and %d only %v apart", i-1, i, gap)
		}
	}
	seen := map[string]bool{}
	for _, id := range h.ids[:10] {
		seen[id] = true
	}
	if len(seen) != 10 {
		t.Fatalf("first ten requests did not cover every account once: %v", h.ids[:10])
	}
}

func TestJitterStaysInsideItsBounds(t *testing.T) {
	cfg := schedCfg()
	cfg.Jitter = 0.2
	for _, r := range []float64{0, 0.25, 0.5, 0.999999} {
		p := NewPoller(nil, cfg)
		p.rnd = func() float64 { return r }
		got := p.jitter(100 * time.Second)
		if got < 80*time.Second || got > 120*time.Second {
			t.Errorf("rnd %v: %v outside 80s..120s", r, got)
		}
	}
	p := NewPoller(nil, cfg)
	p.rnd = func() float64 { return 0 }
	lo := p.jitter(100 * time.Second)
	p.rnd = func() float64 { return 0.999999 }
	hi := p.jitter(100 * time.Second)
	if lo >= 100*time.Second || hi <= 100*time.Second {
		t.Fatalf("jitter does not spread: %v .. %v", lo, hi)
	}
}

func TestTheGlobalSpacingIsJittered(t *testing.T) {
	cfg := schedCfg()
	cfg.Jitter = 0.2
	d := staticDoer(200, okBody, nil)
	p := NewPoller(d, cfg)
	c := &clock{t: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
	p.now = c.now
	p.rnd = func() float64 { return 0 } // the shortest spacing: 20s
	p.SetAccounts(func() []vault.Account { return []vault.Account{acct("a", "t"), acct("b", "t")} })
	p.step(context.Background(), nil)
	_, wait := p.step(context.Background(), nil)
	if wait != 20*time.Second {
		t.Fatalf("owed %v, want 20s", wait)
	}
}

func TestHeldAccountIsPolledBeforeIdleOnes(t *testing.T) {
	h := &hits{}
	p, c := newSched(nil, "a", "b", "held", "d")
	h.c = c
	p.d = h.doer(200, nil)
	p.SetHeld(func(id string) bool { return id == "held" })
	run(p, c, 3*time.Minute)
	if h.ids[0] != "held" {
		t.Fatalf("order %v: the held account must come first", h.ids)
	}
}

func TestTiersSetTheIntervalAfterASuccess(t *testing.T) {
	p, c := newSched(staticDoer(200, okBody, nil), "held", "idle")
	p.SetHeld(func(id string) bool { return id == "held" })
	p.step(context.Background(), nil)
	c.t = c.t.Add(30 * time.Second)
	p.step(context.Background(), nil)
	if got := p.Info("held"); got.Tier != TierActive || got.Every != 2*time.Minute || got.NextAt.Sub(time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)) != 2*time.Minute {
		t.Fatalf("held: %+v", got)
	}
	if got := p.Info("idle"); got.Tier != TierIdle || got.Every != 20*time.Minute {
		t.Fatalf("idle: %+v", got)
	}
}

func TestRequestsPerHourForTenAccounts(t *testing.T) {
	for _, tc := range []struct {
		held     int
		min, max int
	}{{0, 30, 50}, {1, 50, 75}, {2, 75, 105}} {
		h := &hits{}
		ids := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}
		p, c := newSched(nil, ids...)
		h.c = c
		p.d = h.doer(200, nil)
		p.SetHeld(func(id string) bool {
			for _, x := range ids[:tc.held] {
				if x == id {
					return true
				}
			}
			return false
		})
		run(p, c, 30*time.Minute) // settle past the startup fan-out
		before := len(h.at)
		run(p, c, time.Hour)
		n := len(h.at) - before
		t.Logf("10 accounts, %d held: %d requests/hour", tc.held, n)
		if n < tc.min || n > tc.max {
			t.Errorf("held=%d: %d requests in an hour, want %d..%d", tc.held, n, tc.min, tc.max)
		}
	}
}

func TestRateLimitWithoutRetryAfterBacksOffExponentiallyToTheCap(t *testing.T) {
	h := &hits{}
	p, c := newSched(nil, "a")
	h.c = c
	p.d = h.doer(429, nil)
	var waits []time.Duration
	for i := 0; i < 7; i++ {
		start := c.t
		if polled, _ := p.step(context.Background(), nil); !polled {
			t.Fatalf("round %d: not polled", i)
		}
		waits = append(waits, p.Info("a").NextAt.Sub(start))
		c.t = p.Info("a").NextAt
	}
	want := []time.Duration{5, 10, 20, 40, 60, 60, 60}
	for i, w := range want {
		if waits[i] != w*time.Minute {
			t.Fatalf("waits %v, want %v minutes", waits, want)
		}
	}
}

func TestRetryAfterIsHonouredAndNeverPolledEarly(t *testing.T) {
	h := &hits{}
	p, c := newSched(nil, "a")
	h.c = c
	p.d = h.doer(429, map[string]string{"Retry-After": "5400"}) // 90 minutes, over the 5 minute backoff
	p.step(context.Background(), nil)
	run(p, c, 89*time.Minute)
	if len(h.at) != 1 {
		t.Fatalf("polled %d times inside Retry-After", len(h.at))
	}
	run(p, c, 2*time.Minute)
	if len(h.at) != 2 {
		t.Fatalf("not polled after Retry-After: %d", len(h.at))
	}
}

func TestRetryAfterIsCappedBySanityLimit(t *testing.T) {
	p, _ := newSched(nil, "a")
	if got := p.backoff(1, 48*time.Hour); got != 6*time.Hour {
		t.Fatalf("got %v", got)
	}
}

func TestRetryAfterHTTPDate(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	if got := parseRetryAfter(now.Add(90*time.Second).Format(http.TimeFormat), now); got != 90*time.Second {
		t.Fatalf("date: %v", got)
	}
	for _, bad := range []string{"", "soon", "-5", "0", now.Add(-time.Hour).Format(http.TimeFormat)} {
		if got := parseRetryAfter(bad, now); got != 0 {
			t.Errorf("%q: %v", bad, got)
		}
	}
}

func TestRecoveryClearsTheErrorAndReturnsToTheTierInterval(t *testing.T) {
	code := 429
	d := &fakeDoer{fn: func(*http.Request) (*http.Response, error) {
		if code == 200 {
			return resp(200, okBody, nil), nil
		}
		return resp(code, "", nil), nil
	}}
	p, c := newSched(d, "a")
	p.step(context.Background(), nil)
	if u, _ := p.Last("a"); u.Err != "rate limited" || u.RetryAt.IsZero() {
		t.Fatalf("after 429: %+v", u)
	}
	code = 200
	c.t = p.Info("a").NextAt
	p.step(context.Background(), nil)
	u, _ := p.Last("a")
	if u.Err != "" || !u.RetryAt.IsZero() || u.SevenDay.UsedPct != 95 {
		t.Fatalf("after recovery: %+v", u)
	}
	if got := p.Info("a"); got.Tier != TierIdle || got.NextAt.Sub(c.t) != 20*time.Minute {
		t.Fatalf("after recovery: %+v", got)
	}
}

func TestScheduleNeverPollsAnAccountInBackoff(t *testing.T) {
	h := &hits{}
	p, c := newSched(nil, "limited", "fine")
	h.c = c
	p.d = &fakeDoer{fn: func(r *http.Request) (*http.Response, error) {
		h.mu.Lock()
		h.ids = append(h.ids, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer tok-"))
		h.at = append(h.at, c.t)
		h.mu.Unlock()
		if strings.HasSuffix(r.Header.Get("Authorization"), "limited") {
			return resp(429, "", nil), nil
		}
		return resp(200, okBody, nil), nil
	}}
	run(p, c, 4*time.Minute) // 429, then it must wait 5 minutes; "fine" is idle for 20
	limited := 0
	for _, id := range h.ids {
		if id == "limited" {
			limited++
		}
	}
	if limited != 1 {
		t.Fatalf("limited account polled %d times in its backoff: %v", limited, h.ids)
	}
}

func TestSwapPromotesAndPollsOnceImmediately(t *testing.T) {
	h := &hits{}
	p, c := newSched(nil, "a", "b")
	h.c = c
	p.d = h.doer(200, nil)
	run(p, c, time.Minute) // both settle idle
	n := len(h.ids)
	p.NoteSwap("b")
	if got := p.Info("b"); got.Tier != TierActive || !got.NextAt.Equal(c.t) {
		t.Fatalf("after swap: %+v", got)
	}
	run(p, c, 30*time.Second)
	if len(h.ids) != n+1 || h.ids[n] != "b" {
		t.Fatalf("want exactly one immediate poll of b: %v", h.ids[n:])
	}
}

func TestSwapDoesNotBuyAnAccountInBackoffARequest(t *testing.T) {
	h := &hits{}
	p, c := newSched(nil, "a")
	h.c = c
	p.d = h.doer(429, nil)
	p.step(context.Background(), nil)
	next := p.Info("a").NextAt
	p.NoteSwap("a")
	if got := p.Info("a"); !got.NextAt.Equal(next) || got.Tier != TierBackoff {
		t.Fatalf("swap moved a backoff: %+v", got)
	}
}

func TestSwapTierLapsesBackToIdle(t *testing.T) {
	p, c := newSched(staticDoer(200, okBody, nil), "a")
	p.NoteSwap("a")
	p.step(context.Background(), nil)
	if p.Info("a").Tier != TierActive {
		t.Fatal("not active after swap")
	}
	c.t = c.t.Add(11 * time.Minute) // ActiveHold is 10
	if got := p.Info("a"); got.Tier != TierIdle {
		t.Fatalf("not demoted: %+v", got)
	}
	p.step(context.Background(), nil)
	if got := p.Info("a"); got.NextAt.Sub(c.t) != 20*time.Minute {
		t.Fatalf("demoted account is still rescheduled as active: %+v", got)
	}
}

func TestReleasedHostDemotesAccount(t *testing.T) {
	held := true
	p, c := newSched(staticDoer(200, okBody, nil), "a")
	p.SetHeld(func(string) bool { return held })
	p.step(context.Background(), nil)
	held = false
	c.t = p.Info("a").NextAt
	p.step(context.Background(), nil)
	if got := p.Info("a"); got.Tier != TierIdle || got.NextAt.Sub(c.t) != 20*time.Minute {
		t.Fatalf("%+v", got)
	}
}

func TestTouchPromotesForWatchHoldAndPullsNextPollForward(t *testing.T) {
	p, c := newSched(staticDoer(200, okBody, nil), "a")
	p.step(context.Background(), nil) // idle, next in 20 min
	c.t = c.t.Add(time.Minute)
	p.Touch("a")
	if got := p.Info("a"); got.Tier != TierActive || got.NextAt.Sub(c.t) != time.Minute {
		t.Fatalf("after touch: %+v (next should be last answer + 2m)", got)
	}
	next := p.Info("a").NextAt
	p.Touch("a") // a second touch inside the hold changes nothing
	if !p.Info("a").NextAt.Equal(next) {
		t.Fatal("repeat touch moved the schedule")
	}
	c.t = c.t.Add(6 * time.Minute)
	if got := p.Info("a"); got.Tier != TierIdle {
		t.Fatalf("not demoted after WatchHold: %+v", got)
	}
}

func TestUnauthorizedWaitsAnHourButAButtonMayRetry(t *testing.T) {
	h := &hits{}
	p, c := newSched(nil, "a")
	h.c = c
	p.d = h.doer(401, nil)
	p.step(context.Background(), nil)
	if got := p.Info("a"); got.Tier != TierBackoff || got.NextAt.Sub(c.t) != time.Hour {
		t.Fatalf("%+v", got)
	}
	c.t = c.t.Add(20 * time.Second) // past the manual floor, far inside the hour
	r := p.RefreshNow(context.Background(), []string{"a"})[0]
	if r.Status != Failed || len(h.ids) != 2 {
		t.Fatalf("a button must retry a 401: %+v calls=%d", r, len(h.ids))
	}
}

func TestRefreshRespectsARateLimitBackoffAndReportsHowLongIsLeft(t *testing.T) {
	h := &hits{}
	p, c := newSched(nil, "a")
	h.c = c
	p.d = h.doer(429, nil)
	p.step(context.Background(), nil) // 5 minute backoff
	c.t = c.t.Add(time.Minute)
	r := p.RefreshNow(context.Background(), []string{"a"})[0]
	if r.Status != RateLimited || r.RetryAfter != 4*time.Minute || len(h.ids) != 1 {
		t.Fatalf("%+v calls=%d", r, len(h.ids))
	}
}

func TestRefreshAllSpacesRequestsByManualSpacing(t *testing.T) {
	h := &hits{}
	p, c := newSched(nil, "a", "b", "c")
	h.c = c
	p.d = h.doer(200, nil)
	p.RefreshNow(context.Background(), nil)
	if len(h.at) != 3 {
		t.Fatalf("calls %d", len(h.at))
	}
	for i := 1; i < 3; i++ {
		if gap := h.at[i].Sub(h.at[i-1]); gap < 2*time.Second {
			t.Fatalf("manual requests %v apart", gap)
		}
	}
}

func TestRefreshAllDoesNotPromoteEveryAccount(t *testing.T) {
	p, _ := newSched(staticDoer(200, okBody, nil), "a", "b")
	p.RefreshNow(context.Background(), nil)
	if p.Info("a").Tier != TierIdle {
		t.Fatal("a Refresh-all must not put every account on the 2 minute schedule")
	}
	p.RefreshNow(context.Background(), []string{"a"})
}

func TestForgetSilencesAnInFlightPoll(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	d := &fakeDoer{fn: func(*http.Request) (*http.Response, error) {
		close(started)
		<-release
		return resp(200, okBody, nil), nil
	}}
	p, _ := newSched(d, "a")
	updates := 0
	done := make(chan struct{})
	go func() {
		p.step(context.Background(), func(string, Usage) { updates++ })
		close(done)
	}()
	<-started
	p.Forget("a")
	close(release)
	<-done
	if _, ok := p.Last("a"); ok {
		t.Fatal("a forgotten account's in-flight answer was stored")
	}
	if updates != 0 {
		t.Fatal("a forgotten account's in-flight answer was reported")
	}
	if _, ok := p.nextAt["a"]; ok {
		t.Fatal("a forgotten account was rescheduled")
	}
}

func TestForgetClearsEverythingForAReusedID(t *testing.T) {
	p, _ := newSched(staticDoer(429, "", nil), "a")
	p.NoteSwap("a")
	p.Touch("a")
	p.step(context.Background(), nil)
	p.Forget("a")
	p.Forget("never-seen")
	if _, ok := p.Last("a"); ok || p.fails["a"] != 0 || len(p.nextAt) != 0 || len(p.activeUntil) != 0 || len(p.watchUntil) != 0 {
		t.Fatalf("state survives Forget: fails=%d next=%v", p.fails["a"], p.nextAt)
	}
	if p.Info("a").Tier != TierIdle {
		t.Fatal("a reused id inherits a tier")
	}
}

func TestSchedulerLogsOnlyAllowlistedKeysAndNoSecrets(t *testing.T) {
	var buf bytes.Buffer
	old := logger
	logger = logx.New(&buf)
	defer func() { logger = old }()
	d := fakeDoer{fn: func(*http.Request) (*http.Response, error) {
		return resp(429, "", map[string]string{"Retry-After": "120"}), nil
	}}
	p, _ := newSched(&d, "a")
	p.step(context.Background(), nil)
	out := buf.String()
	if strings.Contains(out, "tok-a") || strings.Contains(out, "[dropped]") || !strings.Contains(out, `"tier":"backoff"`) {
		t.Fatalf("log: %s", out)
	}
}

func TestSlowSpacingNeverStarvesAFreshAccount(t *testing.T) {
	// An account added later is polled within one spacing of being added, not at the next idle slot.
	p, c := newSched(staticDoer(200, okBody, nil), "a")
	ids := []string{"a"}
	p.SetAccounts(func() []vault.Account {
		var out []vault.Account
		for _, id := range ids {
			out = append(out, acct(id, "t"))
		}
		return out
	})
	run(p, c, time.Minute)
	ids = append(ids, "new")
	run(p, c, 30*time.Second)
	if _, ok := p.Last("new"); !ok {
		t.Fatal(fmt.Sprint("new account not polled within the spacing: ", ids))
	}
}

func TestJitterNeverShortensARetryAfter(t *testing.T) {
	cfg := schedCfg()
	cfg.Jitter = 0.3
	for _, r := range []float64{0, 0.5, 0.999} {
		p := NewPoller(&fakeDoer{fn: func(*http.Request) (*http.Response, error) {
			return resp(429, "", map[string]string{"Retry-After": "3600"}), nil
		}}, cfg)
		c := &clock{t: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
		p.now, p.rnd = c.now, func() float64 { return r }
		p.SetAccounts(func() []vault.Account { return []vault.Account{acct("a", "t")} })
		p.step(context.Background(), nil)
		if w := p.Info("a").NextAt.Sub(c.t); w < time.Hour {
			t.Errorf("rnd %v: next poll in %v, before the server's Retry-After", r, w)
		}
	}
}
