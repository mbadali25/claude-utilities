package usage

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"claude-utilities/internal/logx"
)

// A failed poll must say WHICH HTTP status the endpoint answered with, so a 401 (login rejected)
// can be told from a 429 (rate limited) and a 403 from the log alone, each with logx's timestamp.
func TestPollFailureLogsHTTPStatusAndTimestamp(t *testing.T) {
	for _, tc := range []struct {
		code    int
		headers map[string]string
		reason  string
	}{
		{http.StatusUnauthorized, nil, "unauthorized"},
		{http.StatusForbidden, nil, "unauthorized"},
		{http.StatusTooManyRequests, map[string]string{"Retry-After": "120"}, "rate limited"},
		{http.StatusInternalServerError, nil, "unavailable"},
	} {
		t.Run(tc.reason+"-"+http.StatusText(tc.code), func(t *testing.T) {
			var buf bytes.Buffer
			old := logger
			logger = logx.New(&buf)
			defer func() { logger = old }()
			d := fakeDoer{fn: func(*http.Request) (*http.Response, error) { return resp(tc.code, "", tc.headers), nil }}
			p, _ := newSched(&d, "a")
			p.step(context.Background(), nil)
			out := buf.String()
			want := `"status":` + strconv.Itoa(tc.code)
			if !strings.Contains(out, want) || !strings.Contains(out, `"reason":"`+tc.reason+`"`) ||
				!strings.Contains(out, `"time"`) || strings.Contains(out, "[dropped]") || strings.Contains(out, "tok-a") {
				t.Fatalf("want %s with reason %q and a time, log: %s", want, tc.reason, out)
			}
		})
	}
}

func TestFetchStatusErrorsStillMatchTheirSentinels(t *testing.T) {
	d := fakeDoer{fn: func(*http.Request) (*http.Response, error) { return resp(403, "", nil), nil }}
	_, err := Fetch(context.Background(), &d, "tok")
	if !errors.Is(err, ErrUnauthorized) || HTTPStatus(err) != 403 {
		t.Fatalf("err %v status %d", err, HTTPStatus(err))
	}
	d = fakeDoer{fn: func(*http.Request) (*http.Response, error) { return resp(429, "", nil), nil }}
	if _, err = Fetch(context.Background(), &d, "tok"); !errors.Is(err, ErrRateLimited) || HTTPStatus(err) != 429 {
		t.Fatalf("err %v status %d", err, HTTPStatus(err))
	}
	if HTTPStatus(errors.New("x")) != 0 || HTTPStatus(ErrUnauthorized) != 401 {
		t.Fatal("unexpected status for a non-HTTP error or the bare sentinel")
	}
}
