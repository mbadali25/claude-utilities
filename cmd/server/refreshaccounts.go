package main

import (
	"log/slog"
	"strings"

	"claude-utilities/internal/vault"
)

// parseRefreshAccounts splits the --refresh-accounts value into account ids: comma-separated,
// spaces trimmed, empties dropped, duplicates removed (first position kept). Ids are
// case-sensitive, exactly as stored.
func parseRefreshAccounts(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		id := strings.TrimSpace(part)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// refreshGate returns the poller's refresh gate: an account refreshes only when it is in listed
// AND serverOwned says the server may. An empty list refreshes nothing (fail closed).
func refreshGate(listed []string, serverOwned func(string) bool) func(string) bool {
	set := make(map[string]bool, len(listed))
	for _, id := range listed {
		set[id] = true
	}
	return func(id string) bool { return set[id] && serverOwned(id) }
}

// countUnmatched counts listed ids that match no stored account.
func countUnmatched(listed []string, stored []vault.Account) int {
	have := make(map[string]bool, len(stored))
	for _, a := range stored {
		have[a.ID] = true
	}
	n := 0
	for _, id := range listed {
		if !have[id] {
			n++
		}
	}
	return n
}

// warnRefreshAccountsIgnored logs that --refresh-accounts does nothing without --refresh-tokens.
func warnRefreshAccountsIgnored(log *slog.Logger, refreshTokens bool, listed []string) {
	if refreshTokens || len(listed) == 0 {
		return
	}
	log.Warn("--refresh-accounts ignored: --refresh-tokens is off", "action", "refresh", "result", "ignored", "count", len(listed))
}
