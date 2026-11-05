package web

// POST /api/usage/refresh: poll the usage endpoint now, for one account or for all of them. It needs
// a signed-in admin session and a CSRF token (authPost), and two limits stand between the page's
// buttons and Anthropic's endpoint: this route's own window, counted across every session, and the
// poller's per-account floor and backoff, which come back as a per-account "rate_limited" result
// rather than as an HTTP error, because the rest of the accounts in the same request did refresh.

import (
	"math"
	"net/http"
	"time"

	"claude-utilities/internal/usage"
)

const (
	// maxRefreshRequests is how many refresh requests this server accepts per window, from every
	// session together. The poller's own floor bounds the requests one account can cause; this
	// bounds how often a page may ask at all.
	maxRefreshRequests = 6
	refreshWindow      = time.Minute
)

// refreshRowJSON is one account's outcome. updatedAt is null until an account has ever been polled;
// retryAfterSec and error appear only on the statuses that have one. No field can carry a token: the
// poller hands back windows, a timestamp and an error category.
type refreshRowJSON struct {
	ID            string     `json:"id"`
	Status        string     `json:"status"`
	UpdatedAt     *time.Time `json:"updatedAt"`
	RetryAfterSec int64      `json:"retryAfterSec,omitempty"`
	Error         string     `json:"error,omitempty"`
}

// overRefreshLimit records one refresh request and reports whether this server is over its budget
// for the window. The counter is global, not per source address: it protects one upstream endpoint,
// which does not care which browser asked.
func (s *server) overRefreshLimit() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := s.now().Add(-refreshWindow)
	keep := s.refreshHits[:0]
	for _, t := range s.refreshHits {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	s.refreshHits = keep
	if len(keep) >= maxRefreshRequests {
		return true
	}
	s.refreshHits = append(keep, s.now())
	return false
}

// refreshRow turns one poller result into its JSON row.
func refreshRow(r usage.RefreshResult) refreshRowJSON {
	out := refreshRowJSON{ID: r.ID, Status: string(r.Status)}
	if !r.Usage.FetchedAt.IsZero() {
		f := r.Usage.FetchedAt
		out.UpdatedAt = &f
	}
	if r.Status == usage.RateLimited && r.RetryAfter > 0 {
		out.RetryAfterSec = int64(math.Ceil(r.RetryAfter.Seconds()))
	}
	if r.Status == usage.Failed {
		out.Error = r.Usage.Err // a category ("unauthorized", "unavailable"), never response text
	}
	return out
}

func (s *server) usageRefresh(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Account string `json:"account"`
	}
	// A bare POST with no body means every account, so readJSON (which rejects an empty body) only
	// runs when there is something to read.
	if r.ContentLength != 0 && !readJSON(w, r, &in) {
		return
	}
	if len(in.Account) > maxLabel {
		writeErr(w, http.StatusBadRequest, "account id too long")
		return
	}
	ip := clientIP(r)
	if s.overRefreshLimit() {
		logger.Warn("usage refresh refused", "action", "usage_refresh", "result", "refused",
			"reason", "too many requests", "source_ip", ip)
		writeErr(w, http.StatusTooManyRequests, "too many refresh requests; wait a minute")
		return
	}
	var ids []string
	if in.Account != "" {
		ids = []string{in.Account}
	}
	res := s.usage.RefreshNow(r.Context(), ids)
	rows := make([]refreshRowJSON, 0, len(res))
	refreshed := 0
	for _, x := range res {
		if x.Status == usage.Refreshed {
			refreshed++
		}
		rows = append(rows, refreshRow(x))
	}
	// The poller logs each failed poll itself with the same audit fields; this route logs only what
	// it alone knows - which address asked and how much was asked for - at debug level, so an
	// operator clicking Refresh does not drown the log.
	logger.Debug("usage refresh", "action", "usage_refresh", "result", "ok",
		"count", refreshed, "targetCount", len(rows), "source_ip", ip)
	writeJSON(w, http.StatusOK, map[string]any{"results": rows})
}

// usageWatch says an admin has a card open: the account joins the short polling schedule for a few
// minutes. It sends no request upstream itself, so it needs no rate limit of its own beyond the
// session and CSRF checks every POST has; an unknown id is a 404 so a stale page learns it.
func (s *server) usageWatch(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Account string `json:"account"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Account == "" || len(in.Account) > maxLabel {
		writeErr(w, http.StatusBadRequest, "account id required")
		return
	}
	if _, ok := s.vault.Get(in.Account); !ok {
		writeErr(w, http.StatusNotFound, "no such account")
		return
	}
	s.usage.Touch(in.Account)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
