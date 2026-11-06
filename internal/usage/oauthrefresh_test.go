package usage

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"claude-utilities/internal/vault"
)

const storedBlock = `{"accessToken":"old-a","refreshToken":"old-r","expiresAt":1,"scopes":["user:profile","user:inference"],` +
	`"subscriptionType":"max","rateLimitTier":"tier-x","futureField":{"k":[1,2]}}`

var fixedNow = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

func newRefresher(url string) *OAuthRefresher {
	r := NewOAuthRefresher()
	r.URL = url
	r.Now = func() time.Time { return fixedNow }
	return r
}

func decodeMap(t *testing.T, b []byte) map[string]json.RawMessage {
	t.Helper()
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("not an object: %v", err)
	}
	return m
}

func TestOAuthRefreshSendsExpectedRequestAndMerges(t *testing.T) {
	var gotBody map[string]any
	var gotCT, gotAuth, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT, gotAuth, gotMethod = r.Header.Get("Content-Type"), r.Header.Get("Authorization"), r.Method
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		_, _ = io.WriteString(w, `{"access_token":"new-a","refresh_token":"new-r","expires_in":3600,"refresh_token_expires_in":7200,"scope":"user:profile user:inference"}`)
	}))
	defer srv.Close()

	r := newRefresher(srv.URL)
	out, err := r.Refresh(context.Background(), json.RawMessage(storedBlock))
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotCT != "application/json" || gotAuth != "" {
		t.Fatalf("method=%q ct=%q auth=%q", gotMethod, gotCT, gotAuth)
	}
	if gotBody["grant_type"] != "refresh_token" || gotBody["refresh_token"] != "old-r" ||
		gotBody["client_id"] != r.ClientID || gotBody["scope"] != "user:profile user:inference" {
		t.Fatalf("body = %v", gotBody)
	}
	m := decodeMap(t, out)
	var s string
	_ = json.Unmarshal(m["accessToken"], &s)
	if s != "new-a" {
		t.Fatalf("accessToken = %s", m["accessToken"])
	}
	_ = json.Unmarshal(m["refreshToken"], &s)
	if s != "new-r" {
		t.Fatalf("refreshToken = %s", m["refreshToken"])
	}
	var exp, rexp int64
	_ = json.Unmarshal(m["expiresAt"], &exp)
	_ = json.Unmarshal(m["refreshTokenExpiresAt"], &rexp)
	if exp != fixedNow.Add(time.Hour).UnixMilli() || rexp != fixedNow.Add(2*time.Hour).UnixMilli() {
		t.Fatalf("expiresAt=%d refreshTokenExpiresAt=%d", exp, rexp)
	}
	for k, want := range map[string]string{"subscriptionType": `"max"`, "rateLimitTier": `"tier-x"`, "futureField": `{"k":[1,2]}`} {
		if string(m[k]) != want {
			t.Fatalf("%s = %s, want %s", k, m[k], want)
		}
	}
}

func TestOAuthRefreshKeepsOldRefreshTokenWhenAbsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"access_token":"new-a","expires_in":60}`)
	}))
	defer srv.Close()
	out, err := newRefresher(srv.URL).Refresh(context.Background(), json.RawMessage(storedBlock))
	if err != nil {
		t.Fatal(err)
	}
	m := decodeMap(t, out)
	if string(m["refreshToken"]) != `"old-r"` {
		t.Fatalf("refreshToken = %s", m["refreshToken"])
	}
	if _, ok := m["refreshTokenExpiresAt"]; ok {
		t.Fatal("refreshTokenExpiresAt invented")
	}
	if string(m["scopes"]) != `["user:profile","user:inference"]` {
		t.Fatalf("scopes = %s", m["scopes"])
	}
}

func TestOAuthRefreshErrorsNeverEchoBodyOrTokens(t *testing.T) {
	cases := map[string]func(http.ResponseWriter){
		"400":       func(w http.ResponseWriter) { w.WriteHeader(400); _, _ = io.WriteString(w, `{"error":"leak old-r"}`) },
		"500":       func(w http.ResponseWriter) { w.WriteHeader(500) },
		"bad json":  func(w http.ResponseWriter) { _, _ = io.WriteString(w, `not json old-r`) },
		"no access": func(w http.ResponseWriter) { _, _ = io.WriteString(w, `{"expires_in":5}`) },
		"no expiry": func(w http.ResponseWriter) { _, _ = io.WriteString(w, `{"access_token":"x"}`) },
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { h(w) }))
			defer srv.Close()
			_, err := newRefresher(srv.URL).Refresh(context.Background(), json.RawMessage(storedBlock))
			if err == nil {
				t.Fatal("want error")
			}
			if strings.Contains(err.Error(), "old-r") || strings.Contains(err.Error(), "leak") {
				t.Fatalf("error echoes body: %v", err)
			}
		})
	}
}

func TestOAuthRefreshRejectsBlockWithoutRefreshToken(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { atomic.AddInt32(&hits, 1) }))
	defer srv.Close()
	for _, b := range []string{`{"accessToken":"a"}`, `not json`, ``} {
		if _, err := newRefresher(srv.URL).Refresh(context.Background(), json.RawMessage(b)); err == nil {
			t.Fatalf("block %q: want error", b)
		}
	}
	if hits != 0 {
		t.Fatalf("made %d requests with nothing to refresh", hits)
	}
}

func TestOAuthRefreshTransportErrorHidesToken(t *testing.T) {
	r := newRefresher("http://127.0.0.1:1/old-r")
	_, err := r.Refresh(context.Background(), json.RawMessage(storedBlock))
	if err == nil || strings.Contains(err.Error(), "old-r") {
		t.Fatalf("err = %v", err)
	}
}

// pollerWithFakeEndpoints returns a poller whose usage endpoint 401s on the old token and accepts the new.
func pollerWithRefresher(r Refresher, srvUsage Doer) (*Poller, *clock) {
	p, c := newTestPoller(srvUsage)
	p.SetRefresher(r, func(string, json.RawMessage) {})
	return p, c
}

func TestPollerRefreshFailureKeepsLastNumbersAndBacksOffOnce(t *testing.T) {
	var tokenHits int32
	tok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&tokenHits, 1)
		w.WriteHeader(400)
	}))
	defer tok.Close()
	ok := true
	d := &fakeDoer{fn: func(*http.Request) (*http.Response, error) {
		if ok {
			return resp(200, okBody, nil), nil
		}
		return resp(401, "", nil), nil
	}}
	p, c := pollerWithRefresher(newRefresher(tok.URL), d)
	accts := func() []vault.Account { return []vault.Account{{ID: "a", Block: json.RawMessage(storedBlock)}} }
	var got Usage
	rec := func(_ string, u Usage) { got = u }
	p.pollOnce(context.Background(), accts, rec)
	good := got
	ok = false
	c.t = c.t.Add(time.Hour)
	p.pollOnce(context.Background(), accts, rec)
	if got.Err != "unauthorized" || got.SevenDay != good.SevenDay || !got.FetchedAt.Equal(good.FetchedAt) {
		t.Fatalf("got %+v, last good %+v", got, good)
	}
	if tokenHits != 1 {
		t.Fatalf("token endpoint hits = %d", tokenHits)
	}
	// Within the backoff nothing is retried.
	c.t = c.t.Add(10 * time.Minute)
	p.pollOnce(context.Background(), accts, rec)
	if tokenHits != 1 {
		t.Fatalf("retried inside backoff: hits = %d", tokenHits)
	}
}

func TestPollerNeverRefreshesDisallowedAccount(t *testing.T) {
	var tokenHits int32
	tok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&tokenHits, 1)
		_, _ = io.WriteString(w, `{"access_token":"n","expires_in":60}`)
	}))
	defer tok.Close()
	p, _ := pollerWithRefresher(newRefresher(tok.URL), staticDoer(401, "", nil))
	p.SetRefreshAllowed(func(id string) bool { return id == "free" })
	var got Usage
	p.pollOnce(context.Background(),
		func() []vault.Account { return []vault.Account{{ID: "held", Block: json.RawMessage(storedBlock)}} },
		func(_ string, u Usage) { got = u })
	if tokenHits != 0 || got.Err != "unauthorized" {
		t.Fatalf("hits=%d err=%q", tokenHits, got.Err)
	}
	p.pollOnce(context.Background(),
		func() []vault.Account { return []vault.Account{{ID: "free", Block: json.RawMessage(storedBlock)}} },
		func(string, Usage) {})
	if tokenHits != 1 {
		t.Fatalf("allowed account not refreshed: hits=%d", tokenHits)
	}
}

func TestOAuthRefreshConcurrentUseIsRaceFree(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"access_token":"n","refresh_token":"r","expires_in":60}`)
	}))
	defer srv.Close()
	r := newRefresher(srv.URL)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.Refresh(context.Background(), json.RawMessage(storedBlock)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}
