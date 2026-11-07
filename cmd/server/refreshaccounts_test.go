package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"

	"claude-utilities/internal/logx"
	"claude-utilities/internal/ownership"
	"claude-utilities/internal/usage"
	"claude-utilities/internal/vault"
)

func TestParseRefreshAccounts(t *testing.T) {
	cases := []struct {
		name, in string
		want     []string
	}{
		{"empty", "", nil},
		{"only commas and spaces", " , ,, ", nil},
		{"single", "abc", []string{"abc"}},
		{"spaces trimmed", " a1 , b2 ", []string{"a1", "b2"}},
		{"trailing comma", "a1,b2,", []string{"a1", "b2"}},
		{"leading comma", ",a1", []string{"a1"}},
		{"duplicates keep first position", "a1,b2,a1,b2", []string{"a1", "b2"}},
		{"case sensitive", "ABCDEF0123456789,abcdef0123456789", []string{"ABCDEF0123456789", "abcdef0123456789"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseRefreshAccounts(c.in); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("parse(%q) = %#v, want %#v", c.in, got, c.want)
			}
		})
	}
}

func TestRefreshGate(t *testing.T) {
	owned := map[string]bool{"a": true, "b": false, "c": true}
	gate := refreshGate([]string{"a", "b", "zzz"}, func(id string) bool { return owned[id] })
	for id, want := range map[string]bool{
		"a":   true,  // listed and server-owned
		"b":   false, // listed but a host holds it
		"c":   false, // server-owned but not listed
		"zzz": false, // listed, unknown: ownership gate says not owned here
		"A":   false, // ids are case-sensitive
	} {
		if got := gate(id); got != want {
			t.Errorf("gate(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestRefreshGateEmptyListRefusesEverything(t *testing.T) {
	gate := refreshGate(nil, func(string) bool { return true })
	if gate("a") || gate("") {
		t.Fatal("empty allowlist must refresh nothing")
	}
}

func TestEmptyListRefusesAllNoTokenCall(t *testing.T) {
	hits, saved, wired, p := refreshPoller(t, "a", true, true)
	res := p.RefreshNow(context.Background(), []string{"a"})
	if !wired || *hits != 0 || *saved != nil || res[0].Usage.Err != "unauthorized" {
		t.Fatalf("wired=%v hits=%d saved=%q res=%+v", wired, *hits, *saved, res[0])
	}
}

func TestEmptyListLogsFailClosed(t *testing.T) {
	var buf bytes.Buffer
	p := usage.NewPoller(doerFunc(nil), usage.Config{})
	wireRefresher(p, true, usage.NewOAuthRefresher(), logx.New(&buf), nil, func(string) bool { return true },
		func(string, json.RawMessage) error { return nil })
	out := buf.String()
	for _, w := range []string{`"action":"refresh"`, `"result":"fail-closed"`, `"count":0`} {
		if !strings.Contains(out, w) {
			t.Fatalf("log lacks %s: %s", w, out)
		}
	}
}

func TestListedLogsCount(t *testing.T) {
	var buf bytes.Buffer
	p := usage.NewPoller(doerFunc(nil), usage.Config{})
	wireRefresher(p, true, usage.NewOAuthRefresher(), logx.New(&buf), []string{"a", "b"}, func(string) bool { return true },
		func(string, json.RawMessage) error { return nil })
	if out := buf.String(); !strings.Contains(out, `"count":2`) || strings.Contains(out, "[dropped]") {
		t.Fatalf("log: %s", out)
	}
}

func TestUnlistedAccountOn401NotRefreshed(t *testing.T) {
	hits, saved, _, p := refreshPoller(t, "a", true, true, "other")
	res := p.RefreshNow(context.Background(), []string{"a"})
	if *hits != 0 || *saved != nil || res[0].Usage.Err != "unauthorized" {
		t.Fatalf("hits=%d saved=%q res=%+v", *hits, *saved, res[0])
	}
}

func TestListedHostOwnedNotRefreshedViaRegistry(t *testing.T) {
	reg := ownership.New()
	reg.SwapIn("a", "host1") // Active
	reg.SwapIn("a", "host2") // host1 becomes Shared
	hits, saved, _, p := refreshPollerOwned(t, "a", []string{"a"}, func(id string) bool { return reg.OwnerOf(id).Server })
	res := p.RefreshNow(context.Background(), []string{"a"})
	if *hits != 0 || *saved != nil || res[0].Usage.Err != "unauthorized" {
		t.Fatalf("hits=%d saved=%q res=%+v", *hits, *saved, res[0])
	}
}

func TestListedServerOwnedRefreshedOnce(t *testing.T) {
	reg := ownership.New() // empty after restart: server owns everything
	hits, saved, _, p := refreshPollerOwned(t, "a", []string{"a"}, func(id string) bool { return reg.OwnerOf(id).Server })
	p.RefreshNow(context.Background(), []string{"a"})
	if *hits != 1 || !strings.Contains(string(*saved), `"new-a"`) {
		t.Fatalf("hits=%d saved=%q", *hits, *saved)
	}
}

func TestUnknownListedIdIsHarmless(t *testing.T) {
	hits, saved, _, p := refreshPoller(t, "a", true, true, "a", "no-such-account")
	p.RefreshNow(context.Background(), []string{"a"})
	if *hits != 1 || *saved == nil {
		t.Fatalf("hits=%d saved=%q", *hits, *saved)
	}
}

func TestCountUnmatched(t *testing.T) {
	stored := []vault.Account{{ID: "a"}, {ID: "b"}}
	if got := countUnmatched([]string{"a", "x", "y"}, stored); got != 2 {
		t.Fatalf("got %d, want 2", got)
	}
	if got := countUnmatched(nil, stored); got != 0 {
		t.Fatalf("got %d, want 0", got)
	}
}

func TestAllowlistWithoutRefreshTokensWarnsAndWiresNothing(t *testing.T) {
	var buf bytes.Buffer
	log := logx.New(&buf)
	warnRefreshAccountsIgnored(log, false, []string{"a"})
	if out := buf.String(); !strings.Contains(out, `"level":"WARN"`) || !strings.Contains(out, `"result":"ignored"`) {
		t.Fatalf("log: %s", out)
	}
	buf.Reset()
	warnRefreshAccountsIgnored(log, true, []string{"a"})
	warnRefreshAccountsIgnored(log, false, nil)
	if buf.Len() != 0 {
		t.Fatalf("unexpected log: %s", buf.String())
	}
	hits, saved, wired, p := refreshPoller(t, "a", false, true, "a")
	p.RefreshNow(context.Background(), []string{"a"})
	if wired || *hits != 0 || *saved != nil {
		t.Fatalf("wired=%v hits=%d saved=%q", wired, *hits, *saved)
	}
}

func TestRefreshGateRaceFree(t *testing.T) {
	reg := ownership.New()
	gate := refreshGate([]string{"a", "b"}, func(id string) bool { return reg.OwnerOf(id).Server })
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				reg.SwapIn("a", "h")
				_ = gate("a")
				reg.SwapAway("a", "h")
				_ = gate("b")
			}
		}()
	}
	wg.Wait()
	_ = io.Discard
}
