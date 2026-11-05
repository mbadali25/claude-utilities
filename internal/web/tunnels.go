package web

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"claude-utilities/internal/logx"
	"claude-utilities/internal/tunnel"
)

// The /api/tunnels routes. They follow the existing pattern exactly: s.auth for reads (401
// unauthenticated) and s.authPost for writes (401, then 403 on a wrong or missing
// X-CSRF-Token). Every one of them is absent when the server runs without --tunnels, so a probe
// of a server that does not have the feature gets the same 404 as a route that never existed.
//
// Nothing here returns a private key, and nothing here logs an address or a username: the audit
// lines carry the label under "host", the action, the result and a reason code.

const (
	// maxAddTunnel bounds how many tunnels may be added per hour across every session: each one
	// generates a key and writes the keyring.
	maxAddTunnel   = 10
	addTunnelWin   = time.Hour
	maxHostKeyText = 4096
	maxTunnelID    = 64
)

func (s *server) routeTunnels(mux *http.ServeMux) {
	if s.tunnel == nil {
		return
	}
	mux.HandleFunc("GET /api/tunnels", s.auth(s.tunnelList))
	mux.HandleFunc("POST /api/tunnels", s.authPost(s.tunnelAdd))
	mux.HandleFunc("POST /api/tunnels/import", s.authPost(s.tunnelImport))
	mux.HandleFunc("POST /api/tunnels/{id}", s.authPost(s.tunnelUpdate))
	mux.HandleFunc("DELETE /api/tunnels/{id}", s.authPost(s.tunnelRemove))
	mux.HandleFunc("POST /api/tunnels/{id}/enable", s.authPost(s.tunnelEnable(true)))
	mux.HandleFunc("POST /api/tunnels/{id}/disable", s.authPost(s.tunnelEnable(false)))
	mux.HandleFunc("POST /api/tunnels/{id}/restart", s.authPost(s.tunnelRestart))
	mux.HandleFunc("POST /api/tunnels/{id}/hostkey", s.authPost(s.tunnelHostKey))
	mux.HandleFunc("POST /api/tunnels/{id}/key/generate", s.authPost(s.tunnelKey("generate")))
	mux.HandleFunc("POST /api/tunnels/{id}/key/rotate", s.authPost(s.tunnelKey("rotate")))
	mux.HandleFunc("POST /api/tunnels/{id}/key/rotate/commit", s.authPost(s.tunnelKey("rotate_commit")))
	mux.HandleFunc("POST /api/tunnels/{id}/key/rotate/cancel", s.authPost(s.tunnelKey("rotate_cancel")))
	mux.HandleFunc("POST /api/tunnels/{id}/key/revoke", s.authPost(s.tunnelKey("revoke")))
	mux.HandleFunc("POST /api/tunnels/{id}/key/revoked", s.authPost(s.tunnelKey("revoke_confirmed")))
}

// tunnelAudit writes one audit line. Allowlisted keys only: the label under "host", never the
// address, the username, a key or raw ssh stderr.
func tunnelAudit(level string, action, label, result, reason string) {
	args := []any{"action", action, "host", label, "result", result}
	if reason != "" {
		args = append(args, "reason", reason)
	}
	if level == "warn" {
		logger.Warn("tunnel admin", args...)
		return
	}
	logger.Info("tunnel admin", args...)
}

// tunnelID reads and bounds the {id} path value.
func tunnelID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if id == "" || len(id) > maxTunnelID || strings.ContainsAny(id, "/\\ \t\r\n") {
		writeErr(w, http.StatusNotFound, tunnel.ErrUnknown.Error())
		return "", false
	}
	return id, true
}

// tunnelError maps a tunnel error to a status an operator can act on. The text of these errors is
// written for an operator and carries no address, so it is safe to show.
func tunnelError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, tunnel.ErrUnknown):
		writeErr(w, http.StatusNotFound, err.Error())
	case errors.Is(err, tunnel.ErrRateLimited):
		writeErr(w, http.StatusTooManyRequests, err.Error())
	case errors.Is(err, tunnel.ErrBadLabel), errors.Is(err, tunnel.ErrBadAddress),
		errors.Is(err, tunnel.ErrBadUser), errors.Is(err, tunnel.ErrBadPort),
		errors.Is(err, tunnel.ErrBadHostKey):
		writeErr(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, tunnel.ErrNoKeyYet):
		writeErr(w, http.StatusConflict, err.Error())
	default:
		if strings.HasPrefix(err.Error(), "tunnel: ") { // authored here, already address-free
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		logger.Warn("tunnel request failed", "action", "tunnel", "result", "failed", logx.Err(err))
		writeErr(w, http.StatusBadGateway, "the request failed; see the server log")
	}
}

func (s *server) tunnelList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.tunnel.List())
}

// overAddTunnelLimit records one add and reports whether the estate-wide budget is spent.
func (s *server) overAddTunnelLimit() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := s.now().Add(-addTunnelWin)
	keep := s.addTunnelHits[:0]
	for _, t := range s.addTunnelHits {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	if len(keep) >= maxAddTunnel {
		s.addTunnelHits = keep
		return true
	}
	s.addTunnelHits = append(keep, s.now())
	return false
}

func (s *server) tunnelAdd(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Label   string `json:"label"`
		Address string `json:"address"`
		User    string `json:"user"`
		Port    int    `json:"port"`
		HostID  string `json:"hostId"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if s.overAddTunnelLimit() {
		tunnelAudit("warn", "tunnel_added", in.Label, "refused", "too many tunnels added this hour")
		writeErr(w, http.StatusTooManyRequests, "too many tunnels added this hour; wait and try again")
		return
	}
	v, err := s.tunnel.Add(tunnel.Spec{ID: in.HostID, Label: in.Label, Address: in.Address,
		User: in.User, Port: in.Port})
	if err != nil {
		tunnelAudit("warn", "tunnel_added", in.Label, "failed", "refused by validation")
		tunnelError(w, err)
		return
	}
	tunnelAudit("info", "tunnel_added", v.Label, "ok", "")
	writeJSON(w, http.StatusCreated, v)
}

func (s *server) tunnelUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := tunnelID(w, r)
	if !ok {
		return
	}
	var in struct {
		Address string `json:"address"`
		User    string `json:"user"`
		Port    int    `json:"port"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	v, err := s.tunnel.Update(id, in.Address, in.User, in.Port)
	if err != nil {
		tunnelError(w, err)
		return
	}
	tunnelAudit("info", "tunnel_updated", v.Label, "ok", "")
	writeJSON(w, http.StatusOK, v)
}

func (s *server) tunnelEnable(on bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := tunnelID(w, r)
		if !ok {
			return
		}
		v, err := s.tunnel.SetEnabled(id, on)
		if err != nil {
			tunnelError(w, err)
			return
		}
		action := "tunnel_disabled"
		if on {
			action = "tunnel_enabled"
		}
		tunnelAudit("info", action, v.Label, "ok", "")
		writeJSON(w, http.StatusOK, v)
	}
}

func (s *server) tunnelRestart(w http.ResponseWriter, r *http.Request) {
	id, ok := tunnelID(w, r)
	if !ok {
		return
	}
	// The label is read first so a refused restart can still be audited by name.
	label := ""
	if v, found := s.tunnel.Get(id); found {
		label = v.Label
	}
	if err := s.tunnel.Restart(id); err != nil {
		if errors.Is(err, tunnel.ErrRateLimited) {
			tunnelAudit("warn", "tunnel_restart_requested", label, "refused", "rate limited")
		}
		tunnelError(w, err)
		return
	}
	tunnelAudit("info", "tunnel_restart_requested", label, "ok", "")
	v, _ := s.tunnel.Get(id)
	writeJSON(w, http.StatusOK, v)
}

func (s *server) tunnelHostKey(w http.ResponseWriter, r *http.Request) {
	id, ok := tunnelID(w, r)
	if !ok {
		return
	}
	var in struct {
		HostKey string `json:"hostKey"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if len(in.HostKey) > maxHostKeyText {
		writeErr(w, http.StatusBadRequest, tunnel.ErrBadHostKey.Error())
		return
	}
	v, err := s.tunnel.SeedHostKey(id, in.HostKey)
	if err != nil {
		tunnelError(w, err)
		return
	}
	tunnelAudit("info", "tunnel_hostkey_seeded", v.Label, "ok", "")
	writeJSON(w, http.StatusOK, v)
}

// tunnelKey handles every key action. They share a handler because they share the shape: act,
// audit by label, answer with the refreshed view and its generated commands.
func (s *server) tunnelKey(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := tunnelID(w, r)
		if !ok {
			return
		}
		var (
			v   tunnel.View
			err error
		)
		switch action {
		case "generate":
			v, err = s.tunnel.GenerateKey(id)
		case "rotate":
			v, err = s.tunnel.RotateKey(id)
		case "rotate_commit":
			v, err = s.tunnel.CommitRotation(id)
		case "rotate_cancel":
			v, err = s.tunnel.CancelRotation(id)
		case "revoke":
			v, err = s.tunnel.RevokeKey(id)
		case "revoke_confirmed":
			v, err = s.tunnel.ConfirmRevoked(id)
		default:
			writeErr(w, http.StatusNotFound, "unknown key action")
			return
		}
		if err != nil {
			label := ""
			if cur, found := s.tunnel.Get(id); found {
				label = cur.Label
			}
			tunnelAudit("warn", "tunnel_key_"+action, label, "failed", "")
			tunnelError(w, err)
			return
		}
		level := "info"
		reason := ""
		if action == "revoke" {
			// Never a false green: the line is almost certainly still on the host.
			level, reason = "warn", "the authorized_keys line is probably still on the host"
		}
		tunnelAudit(level, "tunnel_key_"+action, v.Label, "ok", reason)
		writeJSON(w, http.StatusOK, v)
	}
}

func (s *server) tunnelRemove(w http.ResponseWriter, r *http.Request) {
	id, ok := tunnelID(w, r)
	if !ok {
		return
	}
	v, err := s.tunnel.Remove(id)
	if err != nil {
		tunnelError(w, err)
		return
	}
	tunnelAudit("warn", "tunnel_removed", v.Label, "ok",
		"run the remove command on the host; this server cannot")
	writeJSON(w, http.StatusOK, v)
}

// tunnelImport reads the interim scheduled task's host list. The path is fixed, not taken from
// the request: a caller-supplied path would be an arbitrary-file-read through an admin session.
// The file is left in place - it is the rollback path for the scheduled task.
func (s *server) tunnelImport(w http.ResponseWriter, _ *http.Request) {
	path := interimHostListPath()
	if path == "" {
		writeErr(w, http.StatusNotFound, "there is no interim host list to import on this machine")
		return
	}
	added, skipped, err := s.tunnel.ImportFile(path)
	if err != nil {
		tunnelAudit("warn", "tunnel_imported", "", "failed", "the host list could not be read")
		tunnelError(w, err)
		return
	}
	tunnelAudit("info", "tunnel_imported", "", "ok", "")
	writeJSON(w, http.StatusOK, map[string]any{"added": added, "skipped": skipped,
		"tunnels": s.tunnel.List()})
}

// interimHostListPath is where scripts/claude-swap-tunnels.ps1 keeps its host list. Overridable
// by environment for a test or a non-default profile, never by a request.
func interimHostListPath() string {
	if p := os.Getenv("CLAUDESWAP_TUNNELS_JSON"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".claude-swap", "tunnels.json")
}
