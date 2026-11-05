package usage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"claude-utilities/internal/logx"
	"claude-utilities/internal/vault"
)

const okBody = `{"five_hour":{"utilization":12.5,"resets_at":"2026-11-05T01:59:00-06:00"},
"seven_day":{"utilization":95.0,"resets_at":"2026-11-06T18:00:00.317113-06:00"},"limits":[]}`

type fakeDoer struct {
	mu    sync.Mutex
	fn    func(req *http.Request) (*http.Response, error)
	calls []*http.Request
}

func (f *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.calls = append(f.calls, req)
	f.mu.Unlock()
	return f.fn(req)
}

func resp(code int, body string, hdr map[string]string) *http.Response {
	h := http.Header{}
	for k, v := range hdr {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: h}
}

func staticDoer(code int, body string, hdr map[string]string) *fakeDoer {
	return &fakeDoer{fn: func(*http.Request) (*http.Response, error) { return resp(code, body, hdr), nil }}
}

func TestFetchParsesFiveHourAndSevenDay(t *testing.T) {
	d := staticDoer(200, okBody, nil)
	u, err := Fetch(context.Background(), d, "tok-abc")
	if err != nil {
		t.Fatal(err)
	}
	if u.FiveHour.UsedPct != 12.5 || u.SevenDay.UsedPct != 95 {
		t.Fatalf("pct: %+v", u)
	}
	want := time.Date(2026, 11, 5, 7, 59, 0, 0, time.UTC)
	if !u.FiveHour.ResetsAt.Equal(want) {
		t.Fatalf("resets: %v", u.FiveHour.ResetsAt)
	}
	r := d.calls[0]
	if r.Method != "GET" || r.URL.String() != "https://api.anthropic.com/api/oauth/usage" ||
		r.Header.Get("Authorization") != "Bearer tok-abc" ||
		r.Header.Get("anthropic-beta") != "oauth-2025-04-20" {
		t.Fatalf("bad request: %v %v", r.URL, r.Header)
	}
}

func TestFetchNullFiveHourIsZeroWindow(t *testing.T) {
	body := `{"five_hour":null,"seven_day":{"utilization":3,"resets_at":"2026-11-06T18:00:00Z"}}`
	u, err := Fetch(context.Background(), staticDoer(200, body, nil), "t")
	if err != nil {
		t.Fatal(err)
	}
	if u.FiveHour != (Window{}) || u.SevenDay.UsedPct != 3 {
		t.Fatalf("%+v", u)
	}
}

func TestFetch429ReturnsErrRateLimitedWithRetryAfter(t *testing.T) {
	_, err := Fetch(context.Background(), staticDoer(429, "", map[string]string{"Retry-After": "120"}), "t")
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v", err)
	}
	var rl *RateLimitError
	if !errors.As(err, &rl) || rl.RetryAfter != 120*time.Second {
		t.Fatalf("retry-after: %v", err)
	}
}

func TestFetchUnexpectedSchemaReturnsErrSchemaNotPanic(t *testing.T) {
	for _, body := range []string{
		`not json`, `[]`, `{}`, `null`,
		`{"seven_day":{"utilization":"high","resets_at":"2026-11-06T18:00:00Z"}}`,
		`{"seven_day":{"utilization":1,"resets_at":"yesterday"}}`,
		`{"seven_day":7}`,
	} {
		_, err := Fetch(context.Background(), staticDoer(200, body, nil), "t")
		if !errors.Is(err, ErrSchema) {
			t.Errorf("body %q: err = %v", body, err)
		}
	}
}

// ultraBody is a redacted, fake-numbers body shaped like a higher plan tier: extra windows,
// extra scalar fields, a null window, and a present window with no reset time.
const ultraBody = `{
  "five_hour": {"utilization": 7, "resets_at": "2026-11-05T12:00:00Z", "remaining": 93},
  "seven_day": {"utilization": 41.5, "resets_at": null},
  "seven_day_opus": {"utilization": 0, "resets_at": null},
  "seven_day_oauth_apps": null,
  "plan": "ultra",
  "plan_tier": 3,
  "limits": [],
  "organization": {"role": "admin"}
}`

// TestFetchToleratesNullMissingAndExtraFields pins the shapes a poll must survive: a window
// field that is null or absent, an integer utilization, a reset time with or without a
// fraction, and unknown fields at either level.
func TestFetchToleratesNullMissingAndExtraFields(t *testing.T) {
	reset := time.Date(2026, 11, 6, 18, 0, 0, 0, time.UTC)
	cases := []struct {
		name       string
		body       string
		wantFive   Window
		wantSevenD Window
	}{
		{"null resets_at keeps utilization", `{"seven_day":{"utilization":42,"resets_at":null}}`,
			Window{}, Window{UsedPct: 42}},
		{"missing resets_at keeps utilization", `{"seven_day":{"utilization":42}}`,
			Window{}, Window{UsedPct: 42}},
		{"null utilization keeps reset time", `{"seven_day":{"utilization":null,"resets_at":"2026-11-06T18:00:00Z"}}`,
			Window{}, Window{ResetsAt: reset}},
		{"missing utilization keeps reset time", `{"seven_day":{"resets_at":"2026-11-06T18:00:00Z"}}`,
			Window{}, Window{ResetsAt: reset}},
		{"empty window object", `{"seven_day":{}}`, Window{}, Window{}},
		{"integer utilization", `{"seven_day":{"utilization":3,"resets_at":"2026-11-06T18:00:00Z"}}`,
			Window{}, Window{UsedPct: 3, ResetsAt: reset}},
		{"fractional seconds", `{"seven_day":{"utilization":3,"resets_at":"2026-11-06T18:00:00.317113Z"}}`,
			Window{}, Window{UsedPct: 3, ResetsAt: reset.Add(317113 * time.Microsecond)}},
		{"unknown fields everywhere", `{"five_hour":null,"seven_day":{"utilization":3,"resets_at":"2026-11-06T18:00:00Z","remaining":97,"label":"x"},"next":{"a":1},"count":2}`,
			Window{}, Window{UsedPct: 3, ResetsAt: reset}},
		{"only five_hour present", `{"five_hour":{"utilization":8,"resets_at":"2026-11-06T18:00:00Z"}}`,
			Window{UsedPct: 8, ResetsAt: reset}, Window{}},
		{"both windows null", `{"five_hour":null,"seven_day":null}`, Window{}, Window{}},
		{"ultra shape", ultraBody,
			Window{UsedPct: 7, ResetsAt: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)},
			Window{UsedPct: 41.5}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, err := Fetch(context.Background(), staticDoer(200, c.body, nil), "t")
			if err != nil {
				t.Fatalf("err = %v (field %q)", err, SchemaField(err))
			}
			if u.FiveHour != c.wantFive || u.SevenDay != c.wantSevenD {
				t.Fatalf("five = %+v want %+v; seven = %+v want %+v",
					u.FiveHour, c.wantFive, u.SevenDay, c.wantSevenD)
			}
		})
	}
}

// TestFetchSchemaErrorNamesFailingField keeps a schema failure diagnosable: the error says
// which field path failed, and carries no value from the body.
func TestFetchSchemaErrorNamesFailingField(t *testing.T) {
	cases := map[string]string{
		`not json`:                             "body",
		`[]`:                                   "body",
		`null`:                                 "body",
		`{}`:                                   "windows",
		`{"other":1}`:                          "windows",
		`{"seven_day":7}`:                      "seven_day",
		`{"seven_day":[]}`:                     "seven_day",
		`{"seven_day":{"utilization":"high"}}`: "seven_day.utilization",
		`{"seven_day":{"utilization":[1]}}`:    "seven_day.utilization",
		`{"seven_day":{"utilization":-1}}`:     "seven_day.utilization",
		`{"five_hour":{"utilization":1,"resets_at":"yesterday"}}`: "five_hour.resets_at",
		`{"five_hour":{"utilization":1,"resets_at":99}}`:          "five_hour.resets_at",
	}
	for body, wantField := range cases {
		_, err := Fetch(context.Background(), staticDoer(200, body, nil), "t")
		if !errors.Is(err, ErrSchema) {
			t.Errorf("body %q: err = %v, want ErrSchema", body, err)
			continue
		}
		if got := SchemaField(err); got != wantField {
			t.Errorf("body %q: field = %q, want %q", body, got, wantField)
		}
		if strings.Contains(err.Error(), "high") || strings.Contains(err.Error(), "yesterday") {
			t.Errorf("body %q: error text echoes a value: %v", body, err)
		}
	}
	if got := SchemaField(ErrUnauthorized); got != "" {
		t.Errorf("SchemaField(non-schema error) = %q, want empty", got)
	}
}

// TestPollFailureLogsFailingField proves the next occurrence is diagnosable from the log alone.
func TestPollFailureLogsFailingField(t *testing.T) {
	var buf bytes.Buffer
	old := logger
	logger = logx.New(&buf)
	defer func() { logger = old }()
	p, _ := newTestPoller(staticDoer(200, `{"seven_day":{"utilization":"high"}}`, nil))
	p.pollOnce(context.Background(),
		func() []vault.Account { return []vault.Account{acct("a", "tok-a")} },
		func(string, Usage) {})
	if !strings.Contains(buf.String(), "seven_day.utilization") {
		t.Fatalf("log does not name the failing field: %s", buf.String())
	}
	if strings.Contains(buf.String(), "[dropped]") {
		t.Fatalf("field key is not allowlisted: %s", buf.String())
	}
	if strings.Contains(buf.String(), "high") {
		t.Fatalf("log echoes a response value: %s", buf.String())
	}
}

func TestFetch401ReturnsErrUnauthorized(t *testing.T) {
	for _, c := range []int{401, 403} {
		_, err := Fetch(context.Background(), staticDoer(c, "", nil), "t")
		if !errors.Is(err, ErrUnauthorized) {
			t.Errorf("%d: %v", c, err)
		}
	}
}

func TestFetchOtherStatusAndTransportErrors(t *testing.T) {
	if _, err := Fetch(context.Background(), staticDoer(500, "", nil), "t"); err == nil ||
		errors.Is(err, ErrSchema) || errors.Is(err, ErrRateLimited) {
		t.Fatalf("500: %v", err)
	}
	d := &fakeDoer{fn: func(*http.Request) (*http.Response, error) { return nil, errors.New("boom tok-secret") }}
	_, err := Fetch(context.Background(), d, "tok-secret")
	if err == nil || strings.Contains(err.Error(), "tok-secret") {
		t.Fatalf("transport err must exist and not echo token: %v", err)
	}
}

func block(tok string) json.RawMessage {
	return json.RawMessage(`{"accessToken":"` + tok + `","refreshToken":"r-` + tok + `"}`)
}

func acct(id, tok string) vault.Account { return vault.Account{ID: id, Block: block(tok)} }

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTestPoller(d Doer) (*Poller, *clock) {
	p := NewPoller(d, Config{BackoffBase: time.Minute, Jitter: 0})
	p.rnd = func() float64 { return 0.5 }
	c := &clock{t: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
	p.now = c.now
	p.sleep = func(_ context.Context, d time.Duration) error { c.t = c.t.Add(d); return nil }
	return p, c
}

func TestPollerBacksOffExponentiallyOn429(t *testing.T) {
	d := staticDoer(429, "", nil)
	p, c := newTestPoller(d)
	accts := func() []vault.Account { return []vault.Account{acct("a", "tok-a")} }
	var waits []time.Duration
	for i := 0; i < 4; i++ {
		before := len(d.calls)
		p.pollOnce(context.Background(), accts, func(string, Usage) {})
		if len(d.calls) != before+1 {
			t.Fatalf("round %d: expected a call", i)
		}
		w := p.nextAt["a"].Sub(c.t)
		waits = append(waits, w)
		// Not due yet: no call.
		p.pollOnce(context.Background(), accts, func(string, Usage) {})
		if len(d.calls) != before+1 {
			t.Fatalf("round %d: polled during backoff", i)
		}
		c.t = c.t.Add(w)
	}
	for i := 1; i < len(waits); i++ {
		if waits[i] != 2*waits[i-1] {
			t.Fatalf("not exponential: %v", waits)
		}
	}
}

func TestBackoffCappedAndHonoursRetryAfter(t *testing.T) {
	p, _ := newTestPoller(staticDoer(200, okBody, nil))
	if got := p.backoff(50, 0); got != p.cfg.BackoffMax {
		t.Fatalf("cap: %v", got)
	}
	if got := p.backoff(1, 10*time.Minute); got != 10*time.Minute {
		t.Fatalf("retry-after: %v", got)
	}
}

func TestPollerKeepsLastKnownWithTimestampOnError(t *testing.T) {
	code := 200
	d := &fakeDoer{fn: func(*http.Request) (*http.Response, error) {
		if code == 200 {
			return resp(200, okBody, nil), nil
		}
		return resp(code, "", nil), nil
	}}
	p, c := newTestPoller(d)
	accts := func() []vault.Account { return []vault.Account{acct("a", "tok-a")} }
	p.pollOnce(context.Background(), accts, func(string, Usage) {})
	okAt := c.t
	code = 429
	c.t = c.t.Add(time.Hour)
	var got Usage
	p.pollOnce(context.Background(), accts, func(_ string, u Usage) { got = u })
	last, ok := p.Last("a")
	if !ok || last.SevenDay.UsedPct != 95 || !last.FetchedAt.Equal(okAt) || last.Err == "" {
		t.Fatalf("last = %+v", last)
	}
	if got != last {
		t.Fatalf("onUpdate got %+v want %+v", got, last)
	}
	if _, ok := p.Last("missing"); ok {
		t.Fatal("unknown account must report !ok")
	}
}

func TestOneRevokedAccountDoesNotStopOthers(t *testing.T) {
	d := &fakeDoer{fn: func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") == "Bearer tok-bad" {
			return resp(401, "", nil), nil
		}
		return resp(200, okBody, nil), nil
	}}
	p, _ := newTestPoller(d)
	accts := func() []vault.Account {
		return []vault.Account{acct("bad", "tok-bad"), acct("good", "tok-good")}
	}
	updates := map[string]Usage{}
	p.pollOnce(context.Background(), accts, func(id string, u Usage) { updates[id] = u })
	if updates["good"].Err != "" || updates["good"].SevenDay.UsedPct != 95 {
		t.Fatalf("good: %+v", updates["good"])
	}
	if updates["bad"].Err == "" {
		t.Fatalf("bad should carry an error: %+v", updates["bad"])
	}
}

func TestMalformedBlockIsErrorNotPanic(t *testing.T) {
	p, _ := newTestPoller(staticDoer(200, okBody, nil))
	var got Usage
	p.pollOnce(context.Background(),
		func() []vault.Account { return []vault.Account{{ID: "x", Block: json.RawMessage(`{}`)}} },
		func(_ string, u Usage) { got = u })
	if got.Err == "" {
		t.Fatal("expected error for block without accessToken")
	}
}

type fakeRefresher struct {
	calls int
	err   error
}

func (f *fakeRefresher) Refresh(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return block("tok-new"), nil
}

func TestUnauthorizedTriggersRefreshThenRetryAndReportsNewBlock(t *testing.T) {
	d := &fakeDoer{fn: func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") == "Bearer tok-new" {
			return resp(200, okBody, nil), nil
		}
		return resp(401, "", nil), nil
	}}
	p, _ := newTestPoller(d)
	fr := &fakeRefresher{}
	var persisted json.RawMessage
	p.SetRefresher(fr, func(id string, b json.RawMessage) { persisted = b })
	var got Usage
	p.pollOnce(context.Background(),
		func() []vault.Account { return []vault.Account{acct("a", "tok-old")} },
		func(_ string, u Usage) { got = u })
	if fr.calls != 1 || got.Err != "" || got.SevenDay.UsedPct != 95 {
		t.Fatalf("calls=%d got=%+v", fr.calls, got)
	}
	if string(persisted) != string(block("tok-new")) {
		t.Fatal("refreshed block not handed to onRefreshed")
	}
}

func TestRefreshFailureSurfacesError(t *testing.T) {
	p, _ := newTestPoller(staticDoer(401, "", nil))
	p.SetRefresher(&fakeRefresher{err: errors.New("nope")}, nil)
	var got Usage
	p.pollOnce(context.Background(),
		func() []vault.Account { return []vault.Account{acct("a", "tok-old")} },
		func(_ string, u Usage) { got = u })
	if got.Err == "" {
		t.Fatal("expected error")
	}
}

func TestPollerNeverLogsToken(t *testing.T) {
	var buf bytes.Buffer
	old := logger
	logger = logx.New(&buf)
	defer func() { logger = old }()
	for _, c := range []int{200, 401, 429, 500} {
		p, _ := newTestPoller(staticDoer(c, okBody, nil))
		p.SetRefresher(&fakeRefresher{err: errors.New("refresh failed r-tok-secret")}, nil)
		p.pollOnce(context.Background(),
			func() []vault.Account { return []vault.Account{acct("a", "tok-secret")} },
			func(string, Usage) {})
	}
	// Transport error that echoes the token must not reach logs or Err.
	d := &fakeDoer{fn: func(*http.Request) (*http.Response, error) { return nil, errors.New("Bearer tok-secret") }}
	p, _ := newTestPoller(d)
	var got Usage
	p.pollOnce(context.Background(),
		func() []vault.Account { return []vault.Account{acct("a", "tok-secret")} },
		func(_ string, u Usage) { got = u })
	if strings.Contains(buf.String(), "tok-secret") || strings.Contains(got.Err, "tok-secret") {
		t.Fatalf("token leaked: log=%q err=%q", buf.String(), got.Err)
	}
	if strings.Contains(buf.String(), "[dropped]") {
		t.Fatalf("poll log used a non-allowlisted field: %s", buf.String())
	}
	if buf.Len() == 0 {
		t.Fatal("expected some log output for failures")
	}
}

func TestRunStopsOnContextCancelAndPollsImmediately(t *testing.T) {
	d := staticDoer(200, okBody, nil)
	p := NewPoller(d, Config{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	updated := make(chan struct{}, 1)
	p.SetAccounts(func() []vault.Account { return []vault.Account{acct("a", "t")} })
	go func() {
		p.Run(ctx, func(string, Usage) {
			select {
			case updated <- struct{}{}:
			default:
			}
		})
		close(done)
	}()
	select {
	case <-updated:
	case <-time.After(2 * time.Second):
		t.Fatal("no immediate poll")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop")
	}
}
