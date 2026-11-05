// Package usage polls the Anthropic OAuth usage endpoint for server-owned
// accounts. Tokens are never logged and never appear in error text.
package usage

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"claude-utilities/internal/logx"
	"claude-utilities/internal/vault"
)

// logger is the poller's structured, allowlist-filtered logger.
var logger = logx.New(os.Stderr).With("component", "usage")

func init() {
	// "field" carries a response field path (five_hour.resets_at) and never a value.
	logx.Allow("field")
}

const (
	endpoint   = "https://api.anthropic.com/api/oauth/usage"
	betaHeader = "oauth-2025-04-20"
	maxBody    = 1 << 20
	maxBackoff = time.Hour
)

var (
	ErrRateLimited  = errors.New("usage: rate limited")
	ErrSchema       = errors.New("usage: unexpected response schema")
	ErrUnauthorized = errors.New("usage: unauthorized")

	errBadBlock    = errors.New("usage: credential block has no access token")
	errUnavailable = errors.New("usage: request failed")
)

// SchemaError names the response field path that failed validation, so the next occurrence is
// diagnosable from the log alone. Field holds a fixed path built from the keys this package
// looks for ("five_hour.resets_at"), never a key or a value read out of the response.
type SchemaError struct{ Field string }

func (e *SchemaError) Error() string        { return ErrSchema.Error() + " at " + e.Field }
func (e *SchemaError) Is(target error) bool { return target == ErrSchema }

// SchemaField returns the failing field path, or "" when err is not a schema failure.
func SchemaField(err error) string {
	var se *SchemaError
	if errors.As(err, &se) {
		return se.Field
	}
	return ""
}

// RateLimitError carries the server's Retry-After (zero when absent).
type RateLimitError struct{ RetryAfter time.Duration }

func (e *RateLimitError) Error() string        { return ErrRateLimited.Error() }
func (e *RateLimitError) Is(target error) bool { return target == ErrRateLimited }

// Window is one usage window.
type Window struct {
	UsedPct  float64
	ResetsAt time.Time
}

// Usage is the last answer for an account. On a failed poll the previous
// windows and FetchedAt are kept and Err names the failure category.
type Usage struct {
	FiveHour, SevenDay Window
	FetchedAt          time.Time
	Err                string
}

// Doer is the subset of *http.Client the poller needs.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Refresher renews an expired credential block. The concrete endpoint is not
// yet proven (spike S2 deferred), so production wiring supplies none.
type Refresher interface {
	Refresh(ctx context.Context, block json.RawMessage) (json.RawMessage, error)
}

type rawWindow struct {
	Utilization *float64 `json:"utilization"`
	ResetsAt    *string  `json:"resets_at"`
}

// parseWindow is deliberately tolerant: unknown fields are ignored, a null or absent window is
// a zero Window, and a null or absent utilization or resets_at keeps whatever the other field
// says. It still rejects what it cannot read - a window that is not an object, a utilization
// that is not a finite number at or above zero, a resets_at that is not an RFC3339 string -
// and names the field path so the failure is diagnosable without a redeploy.
func parseWindow(name string, raw json.RawMessage) (Window, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return Window{}, nil
	}
	var rw rawWindow
	if err := json.Unmarshal(raw, &rw); err != nil {
		return Window{}, &SchemaError{Field: fieldPath(name, err)}
	}
	var w Window
	if rw.Utilization != nil {
		u := *rw.Utilization
		if u < 0 || math.IsNaN(u) || math.IsInf(u, 0) {
			return Window{}, &SchemaError{Field: name + ".utilization"}
		}
		w.UsedPct = u
	}
	if rw.ResetsAt != nil {
		t, err := time.Parse(time.RFC3339Nano, *rw.ResetsAt) // accepts a fraction or none
		if err != nil {
			return Window{}, &SchemaError{Field: name + ".resets_at"}
		}
		w.ResetsAt = t.UTC()
	}
	return w, nil
}

// fieldPath turns a decode failure into a fixed path: the member the decoder named when it
// named one (a wrong-typed utilization), else the window itself (a window that is not an
// object). Only keys this package already knows can appear, never text from the response.
func fieldPath(name string, err error) string {
	var ute *json.UnmarshalTypeError
	if errors.As(err, &ute) {
		switch ute.Field {
		case "utilization", "resets_at":
			return name + "." + ute.Field
		}
	}
	return name
}

// Fetch asks the usage endpoint once. A null window parses to a zero Window.
func Fetch(ctx context.Context, d Doer, accessToken string) (Usage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Usage{}, errUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("anthropic-beta", betaHeader)
	resp, err := d.Do(req)
	if err != nil {
		return Usage{}, errUnavailable // never wrap: transport text may echo headers
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		e := &RateLimitError{}
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
			e.RetryAfter = time.Duration(s) * time.Second
		}
		return Usage{}, e
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return Usage{}, ErrUnauthorized
	case resp.StatusCode != http.StatusOK:
		return Usage{}, errUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return Usage{}, errUnavailable
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(body, &top) != nil || top == nil {
		return Usage{}, &SchemaError{Field: "body"}
	}
	fh, okF := top["five_hour"]
	sd, okS := top["seven_day"]
	if !okF && !okS {
		// Neither known window key: this is some other payload, not a thinner one.
		return Usage{}, &SchemaError{Field: "windows"}
	}
	var u Usage
	if u.FiveHour, err = parseWindow("five_hour", fh); err != nil {
		return Usage{}, err
	}
	if u.SevenDay, err = parseWindow("seven_day", sd); err != nil {
		return Usage{}, err
	}
	u.FetchedAt = time.Now().UTC()
	return u, nil
}

// Poller polls a set of accounts, backing off per account on failure.
type Poller struct {
	d        Doer
	interval time.Duration
	now      func() time.Time

	mu          sync.Mutex
	accounts    func() []vault.Account
	last        map[string]Usage
	fails       map[string]int
	nextAt      map[string]time.Time
	manualAt    map[string]time.Time
	inflight    map[string]*flight
	refresher   Refresher
	onRefreshed func(accountID string, block json.RawMessage)
}

// NewPoller returns a poller that polls every interval.
func NewPoller(d Doer, interval time.Duration) *Poller {
	return &Poller{
		d: d, interval: interval, now: time.Now,
		last: map[string]Usage{}, fails: map[string]int{}, nextAt: map[string]time.Time{},
		manualAt: map[string]time.Time{}, inflight: map[string]*flight{},
	}
}

// SetAccounts names where the poller reads the accounts to poll. The func must return only
// server-owned accounts. Call it before Run; RefreshNow reports an unknown account until it is set.
func (p *Poller) SetAccounts(accounts func() []vault.Account) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.accounts = accounts
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

// Run polls immediately, then every interval, until ctx ends. Call SetAccounts first: Run reads the
// accounts from there, so an on-demand RefreshNow and the schedule always see the same set.
func (p *Poller) Run(ctx context.Context, onUpdate func(accountID string, u Usage)) {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		p.pollOnce(ctx, p.accountsFn(), onUpdate)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (p *Poller) backoff(fails int, retryAfter time.Duration) time.Duration {
	if fails > 20 {
		fails = 20
	}
	w := p.interval << (fails - 1)
	if w > maxBackoff || w <= 0 {
		w = maxBackoff
	}
	if retryAfter > w {
		w = retryAfter
	}
	return w
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

// pollOnce polls every due account. One account's failure never stops others.
func (p *Poller) pollOnce(ctx context.Context, accounts func() []vault.Account, onUpdate func(string, Usage)) {
	for _, a := range accounts() {
		if ctx.Err() != nil {
			return
		}
		p.mu.Lock()
		due := !p.now().Before(p.nextAt[a.ID])
		p.mu.Unlock()
		if !due {
			continue
		}
		u, _ := p.poll(ctx, a, p.enter(a.ID, false))
		if onUpdate != nil {
			onUpdate(a.ID, u)
		}
	}
}

// record stores one poll's answer. A success clears the account's backoff; a failure counts against
// it, keeps the last-known windows with their own FetchedAt, and names the failure category. It
// returns what was stored, which is what every caller reports.
func (p *Poller) record(id string, u Usage, err error) Usage {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err == nil {
		u.FetchedAt = p.now().UTC()
		p.fails[id] = 0
		delete(p.nextAt, id)
		p.last[id] = u
		return u
	}
	p.fails[id]++
	var ra time.Duration
	var rl *RateLimitError
	if errors.As(err, &rl) {
		ra = rl.RetryAfter
	}
	wait := p.backoff(p.fails[id], ra)
	p.nextAt[id] = p.now().Add(wait)
	u = p.last[id] // keep last-known windows and their FetchedAt
	u.Err = category(err)
	logger.Warn("poll failed", "action", "poll", "result", "failed", "account", id,
		"reason", u.Err, "field", SchemaField(err), "durationms", wait.Milliseconds())
	p.last[id] = u
	return u
}
