package usage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"claude-utilities/internal/logx"
	"claude-utilities/internal/vault"
)

// syncBuf is a goroutine-safe log sink.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func captureLogger(t *testing.T) *syncBuf {
	t.Helper()
	buf := &syncBuf{}
	old := logger
	logger = logx.New(buf)
	t.Cleanup(func() { logger = old })
	return buf
}

func TestStatusClassMapsTokenStatusToFixedEnum(t *testing.T) {
	for code, want := range map[int]string{
		400: "bad_request", 401: "unauthorized", 403: "forbidden", 429: "rate_limited",
		500: "server_error", 502: "server_error", 599: "server_error",
		404: "other", 418: "other", 302: "other", 200: "other", 0: "other",
	} {
		if got := StatusClass(code); got != want {
			t.Errorf("StatusClass(%d) = %q, want %q", code, got, want)
		}
	}
}

func tokenServer(t *testing.T, code int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestOAuthRefreshCarriesStatusClassInATypedError(t *testing.T) {
	for code, want := range map[int]string{
		400: "bad_request", 401: "unauthorized", 403: "forbidden", 429: "rate_limited", 500: "server_error",
	} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			_, err := newRefresher(tokenServer(t, code, `{"error":"x"}`).URL).Refresh(context.Background(), json.RawMessage(storedBlock))
			var re *RefreshError
			if !errors.As(err, &re) || re.StatusClass != want {
				t.Fatalf("err %v, want RefreshError class %q", err, want)
			}
		})
	}
}

func TestOAuthRefreshTimeoutAndTransportFailureAreNetwork(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)
	r := newRefresher(srv.URL)
	r.HTTP = &http.Client{Timeout: 30 * time.Millisecond}
	for name, rf := range map[string]*OAuthRefresher{"timeout": r, "refused": newRefresher("http://127.0.0.1:1/")} {
		_, err := rf.Refresh(context.Background(), json.RawMessage(storedBlock))
		var re *RefreshError
		if !errors.As(err, &re) || re.StatusClass != "network" {
			t.Fatalf("%s: err %v, want class network", name, err)
		}
	}
}

func pollOnceWith(p *Poller, id string) Usage {
	var got Usage
	p.pollOnce(context.Background(),
		func() []vault.Account { return []vault.Account{{ID: id, Block: json.RawMessage(storedBlock)}} },
		func(_ string, u Usage) { got = u })
	return got
}

func TestPollerLogsRefreshFailureWithStatusClassAndStaysUnauthorized(t *testing.T) {
	for code, want := range map[int]string{
		400: "bad_request", 401: "unauthorized", 403: "forbidden", 429: "rate_limited", 500: "server_error",
	} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			buf := captureLogger(t)
			tok := tokenServer(t, code, `{"error":"leak","access_token":"sk-ant-FAKE-tok","email":"victim@example.com"}`)
			var hits int
			d := &fakeDoer{fn: func(*http.Request) (*http.Response, error) { hits++; return resp(401, "", nil), nil }}
			p, _ := pollerWithRefresher(newRefresher(tok.URL), d)
			got := pollOnceWith(p, "acct-1")
			out := buf.String()
			for _, w := range []string{`"action":"refresh"`, `"result":"failed"`, `"account":"acct-1"`, `"status_class":"` + want + `"`} {
				if !strings.Contains(out, w) {
					t.Fatalf("log lacks %s: %s", w, out)
				}
			}
			for _, bad := range []string{"leak", "sk-ant-FAKE-tok", "victim@example.com", "old-r", "old-a", "[dropped]"} {
				if strings.Contains(out, bad) {
					t.Fatalf("log contains %q: %s", bad, out)
				}
			}
			if got.Err != "unauthorized" || hits != 1 {
				t.Fatalf("behaviour changed: err=%q usage fetches=%d", got.Err, hits)
			}
		})
	}
}

func TestPollerLogsNetworkAndOtherRefreshFailures(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"network": {&RefreshError{StatusClass: "network"}, "network"},
		"plain":   {errors.New("refresh failed r-tok-secret"), "other"},
	} {
		t.Run(name, func(t *testing.T) {
			buf := captureLogger(t)
			fr := &fakeRefresher{err: tc.err}
			p, _ := pollerWithRefresher(fr, staticDoer(401, "", nil))
			if got := pollOnceWith(p, "a"); got.Err != "unauthorized" || fr.calls != 1 {
				t.Fatalf("err=%q calls=%d", got.Err, fr.calls)
			}
			out := buf.String()
			if !strings.Contains(out, `"status_class":"`+tc.want+`"`) || strings.Contains(out, "r-tok-secret") {
				t.Fatalf("log: %s", out)
			}
		})
	}
}

func TestPollerDoesNotLogRefreshFailureWhenRefreshSucceedsOrIsNotAttempted(t *testing.T) {
	buf := captureLogger(t)
	d := &fakeDoer{fn: func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") == "Bearer tok-new" {
			return resp(200, okBody, nil), nil
		}
		return resp(401, "", nil), nil
	}}
	p, _ := pollerWithRefresher(&fakeRefresher{}, d)
	pollOnceWith(p, "a")
	p2, _ := newTestPoller(staticDoer(401, "", nil)) // no refresher wired
	pollOnceWith(p2, "b")
	if strings.Contains(buf.String(), `"action":"refresh"`) {
		t.Fatalf("poller logged a refresh line it has no outcome for: %s", buf.String())
	}
}

func TestRefreshFailureLoggingIsRaceFree(t *testing.T) {
	buf := captureLogger(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p, _ := pollerWithRefresher(&fakeRefresher{err: &RefreshError{StatusClass: "server_error"}}, staticDoer(401, "", nil))
			pollOnceWith(p, fmt.Sprintf("a%d", i))
		}(i)
	}
	wg.Wait()
	if n := strings.Count(buf.String(), `"status_class":"server_error"`); n != 8 {
		t.Fatalf("want 8 refresh failure lines, got %d: %s", n, buf.String())
	}
}
