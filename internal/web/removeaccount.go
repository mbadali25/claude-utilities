package web

// POST /api/accounts/remove deletes one stored account. It is the only destructive account route,
// so it carries every gate the others do - a signed-in admin session and the session's CSRF token
// (authPost), a bounded body with unknown fields refused - plus a per-source budget of its own: a
// stolen CSRF token should not be able to empty the vault in one burst.
//
// What it does NOT do: reach a host. The hub's RemoveAccount sends no agent frame, and this
// handler adds none. A host holding the login keeps it, which is why the held-live refusal below
// is the default.

import (
	"net/http"
	"time"

	"claude-utilities/internal/hub"
)

const (
	// maxRemovals is how many removals one source may ask for in removeWindow. Ten accounts is
	// more than this estate has, and an operator removing them one by one is minutes of clicking,
	// so the budget never gets in a real way's path.
	maxRemovals  = 10
	removeWindow = time.Minute
)

// overRemoveLimit records one removal request and reports whether this source is over its budget.
// Same shape as overCommandLimit: the tracked-address table is bounded, so a spray cannot grow it.
func (s *server) overRemoveLimit(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := s.now().Add(-removeWindow)
	keep := s.removeHits[ip][:0]
	for _, t := range s.removeHits[ip] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	if len(keep) >= maxRemovals {
		s.removeHits[ip] = keep
		return true
	}
	if len(s.removeHits) < maxTrackedIPs || s.removeHits[ip] != nil {
		s.removeHits[ip] = append(keep, s.now())
	} else {
		s.removeHits[ip] = keep
	}
	if len(s.removeHits[ip]) == 0 {
		delete(s.removeHits, ip)
	}
	return false
}

// maxAccountID bounds the id field so a megabyte of junk never reaches the vault lookup. Hub ids
// are 16 hex characters; the cap is loose because the e2e fixture and older imports use their own.
const maxAccountID = 128

func (s *server) removeAccount(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Account string `json:"account"`
		Force   bool   `json:"force"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Account == "" || len(in.Account) > maxAccountID {
		writeErr(w, http.StatusBadRequest, "an account id is required")
		return
	}
	ip := clientIP(r)
	if s.overRemoveLimit(ip) {
		logger.Warn("account removal refused", "action", "remove_account", "result", "refused",
			"reason", "too many removals from this source", "source_ip", ip)
		writeErr(w, http.StatusTooManyRequests, "too many removals; wait a minute")
		return
	}
	err := s.hub.RemoveAccount(in.Account, in.Force)
	if held, ok := hub.HeldBy(err); ok {
		// The host name is agent-supplied text. It goes to the browser, which writes it with
		// textContent, and nowhere else: not into this log line, not into the error string.
		logger.Warn("account removal refused", "action", "remove_account", "account", in.Account,
			"host_id", held.HostID, "result", "refused", "reason", "an online host holds it live",
			"source_ip", ip)
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":  "an online host is signed in as this account",
			"heldBy": held.HostName,
		})
		return
	}
	if err != nil {
		hubError(w, err)
		return
	}
	// Only now, and only on success: the poller's state for an account that no longer exists.
	s.usage.Forget(in.Account)
	logger.Warn("account removed", "action", "remove_account", "account", in.Account,
		"result", "ok", "source_ip", ip)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
