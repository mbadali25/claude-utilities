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
	"strconv"
	"strings"
	"time"
)

const (
	endpoint   = "https://api.anthropic.com/api/oauth/usage"
	betaHeader = "oauth-2025-04-20"
	maxBody    = 1 << 20
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

// StatusError is a non-success HTTP answer: Kind is the sentinel it matches under errors.Is
// (ErrUnauthorized, errUnavailable) and Status the code, which the poller logs.
type StatusError struct {
	Status int
	Kind   error
	// BodyClass is a fixed class of a 401/403 body (see classifyBody); empty for other statuses.
	BodyClass string
}

func (e *StatusError) Error() string { return e.Kind.Error() }
func (e *StatusError) Unwrap() error { return e.Kind }

// HTTPStatus is the HTTP status behind a failed fetch, or 0 when there was none (a transport
// failure, a schema error). The bare ErrUnauthorized counts as 401.
func HTTPStatus(err error) int {
	var se *StatusError
	switch {
	case errors.As(err, &se):
		return se.Status
	case errors.Is(err, ErrRateLimited):
		return http.StatusTooManyRequests
	case errors.Is(err, ErrUnauthorized):
		return http.StatusUnauthorized
	}
	return 0
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
	// RetryAt is when the next scheduled poll may run after a failure; zero after a success.
	RetryAt time.Time
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

// parseRetryAfter reads a Retry-After header: delay-seconds or an HTTP date. Zero when absent,
// unreadable or already past.
func parseRetryAfter(h string, now time.Time) time.Duration {
	h = strings.TrimSpace(h)
	if s, err := strconv.Atoi(h); err == nil {
		if s > 0 {
			return time.Duration(s) * time.Second
		}
		return 0
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
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
		return Usage{}, &RateLimitError{RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())}
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return Usage{}, &StatusError{Status: resp.StatusCode, Kind: ErrUnauthorized, BodyClass: readErrClass(resp.Body)}
	case resp.StatusCode != http.StatusOK:
		return Usage{}, &StatusError{Status: resp.StatusCode, Kind: errUnavailable}
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
