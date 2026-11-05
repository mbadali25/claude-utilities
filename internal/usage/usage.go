// Package usage polls the Anthropic OAuth usage endpoint for server-owned
// accounts. Tokens are never logged and never appear in error text.
package usage

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"claude-utilities/internal/vault"
)

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

func parseWindow(raw json.RawMessage) (Window, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return Window{}, nil
	}
	var rw rawWindow
	if err := json.Unmarshal(raw, &rw); err != nil || rw.Utilization == nil || rw.ResetsAt == nil {
		return Window{}, ErrSchema
	}
	t, err := time.Parse(time.RFC3339Nano, *rw.ResetsAt)
	if err != nil {
		return Window{}, ErrSchema
	}
	return Window{UsedPct: *rw.Utilization, ResetsAt: t.UTC()}, nil
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
	defer resp.Body.Close()
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
		return Usage{}, ErrSchema
	}
	fh, okF := top["five_hour"]
	sd, okS := top["seven_day"]
	if !okF && !okS {
		return Usage{}, ErrSchema
	}
	var u Usage
	if u.FiveHour, err = parseWindow(fh); err != nil {
		return Usage{}, err
	}
	if u.SevenDay, err = parseWindow(sd); err != nil {
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
	last        map[string]Usage
	fails       map[string]int
	nextAt      map[string]time.Time
	refresher   Refresher
	onRefreshed func(accountID string, block json.RawMessage)
}

// NewPoller returns a poller that polls every interval.
func NewPoller(d Doer, interval time.Duration) *Poller {
	return &Poller{
		d: d, interval: interval, now: time.Now,
		last: map[string]Usage{}, fails: map[string]int{}, nextAt: map[string]time.Time{},
	}
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

// Run polls immediately, then every interval, until ctx ends. The accounts
// func must return only server-owned accounts.
func (p *Poller) Run(ctx context.Context, accounts func() []vault.Account, onUpdate func(accountID string, u Usage)) {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		p.pollOnce(ctx, accounts, onUpdate)
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
		u, err := p.fetchAccount(ctx, a)
		p.mu.Lock()
		if err == nil {
			u.FetchedAt = p.now().UTC()
			p.fails[a.ID] = 0
			delete(p.nextAt, a.ID)
		} else {
			p.fails[a.ID]++
			var ra time.Duration
			var rl *RateLimitError
			if errors.As(err, &rl) {
				ra = rl.RetryAfter
			}
			wait := p.backoff(p.fails[a.ID], ra)
			p.nextAt[a.ID] = p.now().Add(wait)
			u = p.last[a.ID] // keep last-known windows and their FetchedAt
			u.Err = category(err)
			log.Printf("usage: poll failed account=%s reason=%q retry_in=%s", a.ID, u.Err, wait)
		}
		p.last[a.ID] = u
		p.mu.Unlock()
		if onUpdate != nil {
			onUpdate(a.ID, u)
		}
	}
}
