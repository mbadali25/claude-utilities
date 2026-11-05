package usage

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"claude-utilities/internal/logx"
	"claude-utilities/internal/vault"
)

func results(rs []RefreshResult) map[string]RefreshResult {
	m := map[string]RefreshResult{}
	for _, r := range rs {
		m[r.ID] = r
	}
	return m
}

func TestRefreshNowPollsEveryAccountWhenNoIDsAreNamed(t *testing.T) {
	d := staticDoer(200, okBody, nil)
	p, c := newTestPoller(d)
	p.SetAccounts(func() []vault.Account { return []vault.Account{acct("a", "tok-a"), acct("b", "tok-b")} })

	out := p.RefreshNow(context.Background(), nil)
	if len(out) != 2 || len(d.calls) != 2 {
		t.Fatalf("results=%d calls=%d", len(out), len(d.calls))
	}
	for _, r := range out {
		if r.Status != Refreshed || r.Usage.SevenDay.UsedPct != 95 || !r.Usage.FetchedAt.Equal(c.t.UTC()) {
			t.Fatalf("%s: %+v", r.ID, r)
		}
	}
	if last, ok := p.Last("a"); !ok || last.SevenDay.UsedPct != 95 {
		t.Fatalf("last not stored: %+v", last)
	}
}

func TestRefreshNowPollsOnlyTheNamedAccount(t *testing.T) {
	d := staticDoer(200, okBody, nil)
	p, _ := newTestPoller(d)
	p.SetAccounts(func() []vault.Account { return []vault.Account{acct("a", "tok-a"), acct("b", "tok-b")} })

	out := p.RefreshNow(context.Background(), []string{"b"})
	if len(out) != 1 || out[0].ID != "b" || out[0].Status != Refreshed {
		t.Fatalf("out = %+v", out)
	}
	if len(d.calls) != 1 || d.calls[0].Header.Get("Authorization") != "Bearer tok-b" {
		t.Fatalf("calls = %d", len(d.calls))
	}
}

func TestRefreshNowRefusesASecondPollInsideTheMinimumInterval(t *testing.T) {
	d := staticDoer(200, okBody, nil)
	p, c := newTestPoller(d)
	p.SetAccounts(func() []vault.Account { return []vault.Account{acct("a", "tok-a")} })

	if r := p.RefreshNow(context.Background(), []string{"a"})[0]; r.Status != Refreshed {
		t.Fatalf("first: %+v", r)
	}
	c.t = c.t.Add(MinRefreshInterval - time.Second)
	r := p.RefreshNow(context.Background(), []string{"a"})[0]
	if r.Status != RateLimited || r.RetryAfter != time.Second {
		t.Fatalf("second: %+v", r)
	}
	if len(d.calls) != 1 {
		t.Fatalf("refused poll still hit the endpoint: %d calls", len(d.calls))
	}
	// The refused result still carries the last-known usage, so the UI has something to show.
	if r.Usage.SevenDay.UsedPct != 95 {
		t.Fatalf("refused result lost the last answer: %+v", r.Usage)
	}
	c.t = c.t.Add(time.Second)
	if r := p.RefreshNow(context.Background(), []string{"a"})[0]; r.Status != Refreshed {
		t.Fatalf("after the interval: %+v", r)
	}
	if len(d.calls) != 2 {
		t.Fatalf("calls = %d", len(d.calls))
	}
}

func TestRefreshNowWaitsOutTheSchedulersBackoff(t *testing.T) {
	d := staticDoer(429, "", map[string]string{"Retry-After": "120"})
	p, c := newTestPoller(d)
	accts := func() []vault.Account { return []vault.Account{acct("a", "tok-a")} }
	p.SetAccounts(accts)

	p.pollOnce(context.Background(), accts, nil) // one 429 leaves a 2 minute backoff
	calls := len(d.calls)
	c.t = c.t.Add(MinRefreshInterval) // past the manual floor, still inside the backoff

	r := p.RefreshNow(context.Background(), []string{"a"})[0]
	if r.Status != RateLimited || r.RetryAfter != 2*time.Minute-MinRefreshInterval {
		t.Fatalf("r = %+v", r)
	}
	if len(d.calls) != calls {
		t.Fatal("a manual refresh pushed past the backoff and hit the endpoint")
	}
}

func TestRefreshNowReportsUnknownAccountWithoutPolling(t *testing.T) {
	d := staticDoer(200, okBody, nil)
	p, _ := newTestPoller(d)
	p.SetAccounts(func() []vault.Account { return []vault.Account{acct("a", "tok-a")} })

	out := results(p.RefreshNow(context.Background(), []string{"nope", "a"}))
	if out["nope"].Status != UnknownID {
		t.Fatalf("unknown: %+v", out["nope"])
	}
	if out["a"].Status != Refreshed {
		t.Fatalf("known account refused after an unknown one: %+v", out["a"])
	}
	if len(d.calls) != 1 {
		t.Fatalf("calls = %d", len(d.calls))
	}
}

func TestRefreshNowReportsFailureAndKeepsTheLastKnownAnswer(t *testing.T) {
	code := 200
	d := &fakeDoer{fn: func(*http.Request) (*http.Response, error) {
		if code == 200 {
			return resp(200, okBody, nil), nil
		}
		return resp(code, "", nil), nil
	}}
	p, c := newTestPoller(d)
	p.SetAccounts(func() []vault.Account { return []vault.Account{acct("a", "tok-a")} })

	p.RefreshNow(context.Background(), []string{"a"})
	okAt := c.t.UTC()
	code = 500
	c.t = c.t.Add(time.Hour)

	r := p.RefreshNow(context.Background(), []string{"a"})[0]
	if r.Status != Failed || r.Usage.Err != "unavailable" {
		t.Fatalf("r = %+v", r)
	}
	if r.Usage.SevenDay.UsedPct != 95 || !r.Usage.FetchedAt.Equal(okAt) {
		t.Fatalf("failure threw away the last answer: %+v", r.Usage)
	}
}

// Two callers asking for the same account at once must cost the endpoint one request: the second
// joins the poll already running and shares its answer. The doer blocks until the test has started
// the second caller, so the overlap is certain rather than likely.
func TestConcurrentRefreshOfOneAccountMakesOneRequest(t *testing.T) {
	entered, release := make(chan struct{}, 1), make(chan struct{})
	d := &fakeDoer{fn: func(*http.Request) (*http.Response, error) {
		entered <- struct{}{}
		<-release
		return resp(200, okBody, nil), nil
	}}
	p, _ := newTestPoller(d)
	p.SetAccounts(func() []vault.Account { return []vault.Account{acct("a", "tok-a")} })

	var wg sync.WaitGroup
	got := make([]RefreshResult, 2)
	wg.Add(1)
	go func() { defer wg.Done(); got[0] = p.RefreshNow(context.Background(), []string{"a"})[0] }()
	<-entered // the first caller owns the flight and is inside Do
	wg.Add(1)
	go func() { defer wg.Done(); got[1] = p.RefreshNow(context.Background(), []string{"a"})[0] }()
	// Give the joiner time to reach the gate; it must wait, not start a second request.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if len(d.calls) != 1 {
		t.Fatalf("single-flight broken: %d requests", len(d.calls))
	}
	for i, r := range got {
		if r.Status != Refreshed || r.Usage.SevenDay.UsedPct != 95 {
			t.Fatalf("caller %d: %+v", i, r)
		}
	}
	if got[0].Usage.FetchedAt != got[1].Usage.FetchedAt {
		t.Fatalf("callers got different answers: %v vs %v", got[0].Usage.FetchedAt, got[1].Usage.FetchedAt)
	}
}

// A manual refresh that lands while the scheduled poll is already fetching the same account joins
// that poll too, so the two never double up on the endpoint.
func TestRefreshJoinsAScheduledPollInFlight(t *testing.T) {
	entered, release := make(chan struct{}, 1), make(chan struct{})
	d := &fakeDoer{fn: func(*http.Request) (*http.Response, error) {
		entered <- struct{}{}
		<-release
		return resp(200, okBody, nil), nil
	}}
	p, _ := newTestPoller(d)
	accts := func() []vault.Account { return []vault.Account{acct("a", "tok-a")} }
	p.SetAccounts(accts)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); p.pollOnce(context.Background(), accts, nil) }()
	<-entered
	var r RefreshResult
	wg.Add(1)
	go func() { defer wg.Done(); r = p.RefreshNow(context.Background(), []string{"a"})[0] }()
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if len(d.calls) != 1 {
		t.Fatalf("manual refresh duplicated the scheduled poll: %d requests", len(d.calls))
	}
	if r.Status != Refreshed || r.Usage.SevenDay.UsedPct != 95 {
		t.Fatalf("r = %+v", r)
	}
}

func TestRefreshNowWithoutAccountsSourceReportsUnknown(t *testing.T) {
	p, _ := newTestPoller(staticDoer(200, okBody, nil))
	if out := p.RefreshNow(context.Background(), nil); len(out) != 0 {
		t.Fatalf("out = %+v", out)
	}
	out := p.RefreshNow(context.Background(), []string{"a"})
	if len(out) != 1 || out[0].Status != UnknownID {
		t.Fatalf("out = %+v", out)
	}
}

func TestRefreshNowNeverLogsATokenOrADroppedField(t *testing.T) {
	var buf bytes.Buffer
	old := logger
	logger = logx.New(&buf)
	defer func() { logger = old }()

	for _, code := range []int{200, 401, 429, 500} {
		p, _ := newTestPoller(staticDoer(code, okBody, nil))
		p.SetAccounts(func() []vault.Account { return []vault.Account{acct("a", "tok-secret")} })
		p.RefreshNow(context.Background(), []string{"a"})
	}
	if strings.Contains(buf.String(), "tok-secret") || strings.Contains(buf.String(), "[dropped]") {
		t.Fatalf("log = %q", buf.String())
	}
}
