// Package web serves the claude-swap admin page and its JSON API.
//
// Every route except GET / and POST /login needs a session cookie; every POST except /login also
// needs the session's CSRF token in X-CSRF-Token. No response ever carries a credential block.
package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"claude-utilities/internal/hub"
	"claude-utilities/internal/logx"
	"claude-utilities/internal/usage"
	"claude-utilities/internal/vault"
)

const (
	cookieName       = "claudeswap_session"
	sessionTTL       = 12 * time.Hour
	maxSessions      = 64
	maxLoginFailures = 10
	loginWindow      = time.Minute
	maxTrackedIPs    = 1024
	maxBody          = 4 << 10
	maxLabel         = 64
	maxFingerprint   = 128
)

//go:embed static/index.html
var indexHTML string

var pageTmpl = template.Must(template.New("index").Parse(indexHTML))

// hubAPI is the part of *hub.Hub the web layer uses.
type hubAPI interface {
	Hosts() []hub.HostView
	Pending() []hub.PendingView
	Swap(ctx context.Context, hostID, accountID string) error
	NewEnrolCode() (string, time.Time)
	Revoke(hostID string) error
	Import(ctx context.Context, hostID, label string) (vault.Account, error)
	Relabel(accountID, label string) error
	AddAccount(ctx context.Context, hostID, label string) (string, error)
	AddStatus(id string) (hub.AddView, error)
	AddCode(id, code string) error
	AddCancel(id string) error
	Allow(fingerprint string) (string, error)
	Deny(fingerprint string) error
}

// usageAPI is the part of *usage.Poller the web layer uses.
type usageAPI interface {
	Last(accountID string) (usage.Usage, bool)
}

// Handler returns the admin UI and API. It panics if adminPassword is empty.
// logger is the web layer's structured, allowlist-filtered logger.
var logger = logx.New(os.Stderr).With("component", "web")

func Handler(h *hub.Hub, v *vault.Vault, p *usage.Poller, adminPassword string) http.Handler {
	if adminPassword == "" {
		panic("web: adminPassword must be non-empty")
	}
	return newHandler(h, v, p, adminPassword, time.Now)
}

type sess struct {
	csrf    string
	expires time.Time
}

type server struct {
	hub   hubAPI
	vault *vault.Vault
	usage usageAPI
	pwSum [sha256.Size]byte
	now   func() time.Time

	mu       sync.Mutex
	sessions map[string]sess
	failures map[string][]time.Time // per source IP
}

func newHandler(h hubAPI, v *vault.Vault, u usageAPI, password string, now func() time.Time) http.Handler {
	s := &server{hub: h, vault: v, usage: u, pwSum: sha256.Sum256([]byte(password)), now: now, sessions: map[string]sess{}, failures: map[string][]time.Time{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("GET /api/accounts", s.auth(s.accounts))
	mux.HandleFunc("GET /api/hosts", s.auth(s.hosts))
	mux.HandleFunc("GET /api/pending", s.auth(s.pending))
	mux.HandleFunc("POST /api/swap", s.authPost(s.swap))
	mux.HandleFunc("POST /api/enrol-code", s.authPost(s.enrolCode))
	mux.HandleFunc("POST /api/hosts/{id}/revoke", s.authPost(s.revoke))
	mux.HandleFunc("POST /api/import", s.authPost(s.importLogin))
	mux.HandleFunc("POST /api/accounts/{id}/label", s.authPost(s.relabel))
	mux.HandleFunc("POST /api/accounts/add", s.authPost(s.addAccount))
	mux.HandleFunc("GET /api/accounts/add/{id}", s.auth(s.addStatus))
	mux.HandleFunc("POST /api/accounts/add/{id}/code", s.authPost(s.addCode))
	mux.HandleFunc("POST /api/accounts/add/{id}/cancel", s.authPost(s.addCancel))
	mux.HandleFunc("POST /api/pending/{fp}/allow", s.authPost(s.allow))
	mux.HandleFunc("POST /api/pending/{fp}/deny", s.authPost(s.deny))
	return headers(s.apiGate(mux))
}

// apiGate answers 401 for any /api/ request without a session, whatever its method, so a
// wrong-method probe learns nothing about the routes.
func (s *server) apiGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if _, ok := s.session(r); !ok {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Cache-Control", "no-store")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("web: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func eq(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// session returns the caller's live session and its id, or false.
func (s *server) session(r *http.Request) (sess, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return sess{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for id, x := range s.sessions {
		if !now.Before(x.expires) {
			delete(s.sessions, id)
		}
	}
	x, ok := s.sessions[c.Value]
	return x, ok
}

func (s *server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.session(r); !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// authPost checks the session first (401), then the CSRF token (403).
func (s *server) authPost(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		x, ok := s.session(r)
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !eq(r.Header.Get("X-CSRF-Token"), x.csrf) {
			writeErr(w, http.StatusForbidden, "missing or invalid CSRF token")
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": logx.Redact(msg)})
}

func readJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request body")
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "malformed request body")
		return false
	}
	return true
}

// --- page and login ---

type pendRow struct{ Fingerprint, HostName, OS, SourceIP, Since, Expires string }

type pageData struct {
	LoggedIn bool
	CSRF     string
	Nonce    string
	Error    string
	Pending  []pendRow
}

func (s *server) render(w http.ResponseWriter, code int, d pageData) {
	d.Nonce = randToken(16)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+d.Nonce+
		"'; style-src 'nonce-"+d.Nonce+"'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.WriteHeader(code)
	if err := pageTmpl.Execute(w, d); err != nil {
		logger.Error("render failed", "action", "render", "result", "failed", logx.Err(err))
	}
}

func (s *server) index(w http.ResponseWriter, r *http.Request) {
	x, ok := s.session(r)
	if !ok {
		s.render(w, http.StatusOK, pageData{})
		return
	}
	d := pageData{LoggedIn: true, CSRF: x.csrf}
	for _, p := range s.hub.Pending() {
		d.Pending = append(d.Pending, pendRow{p.Fingerprint, p.HostName, p.OS, p.SourceIP,
			p.Since.Format(time.RFC3339), p.ExpiresAt.Format(time.RFC3339)})
	}
	s.render(w, http.StatusOK, d)
}

// recentFailuresLocked prunes and counts one source's failures in the window. Callers hold s.mu.
func (s *server) recentFailuresLocked(ip string) int {
	cut := s.now().Add(-loginWindow)
	keep := s.failures[ip][:0]
	for _, t := range s.failures[ip] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(s.failures, ip)
	} else {
		s.failures[ip] = keep
	}
	return len(keep)
}

func clientIP(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	if err := r.ParseForm(); err != nil {
		s.render(w, http.StatusBadRequest, pageData{Error: "Bad request."})
		return
	}
	got := sha256.Sum256([]byte(r.PostFormValue("password")))
	ip := clientIP(r)
	s.mu.Lock()
	if s.recentFailuresLocked(ip) >= maxLoginFailures {
		s.mu.Unlock()
		logger.Warn("login refused", "action", "login", "result", "refused", "reason", "too many failures", "source_ip", ip)
		s.render(w, http.StatusTooManyRequests, pageData{Error: "Too many failed attempts. Wait a minute."})
		return
	}
	if subtle.ConstantTimeCompare(got[:], s.pwSum[:]) != 1 {
		if len(s.failures) < maxTrackedIPs || s.failures[ip] != nil {
			s.failures[ip] = append(s.failures[ip], s.now())
		}
		s.mu.Unlock()
		logger.Warn("login failed", "action", "login", "result", "failed", "reason", "wrong password", "source_ip", ip)
		s.render(w, http.StatusUnauthorized, pageData{Error: "Wrong password."})
		return
	}
	if len(s.sessions) >= maxSessions { // bound memory: drop the soonest-to-expire
		var oldID string
		var oldAt time.Time
		for id, x := range s.sessions {
			if oldID == "" || x.expires.Before(oldAt) {
				oldID, oldAt = id, x.expires
			}
		}
		delete(s.sessions, oldID)
	}
	id := randToken(32)
	s.sessions[id] = sess{csrf: randToken(32), expires: s.now().Add(sessionTTL)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: id, Path: "/", HttpOnly: true, Secure: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --- API ---

type windowView struct {
	LeftPct  float64   `json:"leftPct"`
	ResetsAt time.Time `json:"resetsAt"`
}

type accountView struct {
	ID         string      `json:"id"`
	Label      string      `json:"label"`
	Identity   string      `json:"identity"`
	Owner      string      `json:"owner"`
	FiveHour   *windowView `json:"fiveHour"`
	SevenDay   *windowView `json:"sevenDay"`
	FetchedAt  *time.Time  `json:"fetchedAt"`
	AgeSeconds *int64      `json:"ageSeconds"`
	Error      string      `json:"error,omitempty"`
}

func window(w usage.Window) *windowView {
	if w.ResetsAt.IsZero() {
		return nil // the endpoint returned null for this window
	}
	left := 100 - w.UsedPct
	if left < 0 {
		left = 0
	} else if left > 100 {
		left = 100
	}
	return &windowView{LeftPct: left, ResetsAt: w.ResetsAt}
}

func (s *server) view(a vault.Account, owners map[string]string) accountView {
	v := accountView{ID: a.ID, Label: a.Label, Identity: a.Identity, Owner: "server"}
	if o, ok := owners[a.ID]; ok {
		v.Owner = o
	}
	if u, ok := s.usage.Last(a.ID); ok {
		v.FiveHour, v.SevenDay, v.Error = window(u.FiveHour), window(u.SevenDay), u.Err
		if !u.FetchedAt.IsZero() {
			f := u.FetchedAt
			age := int64(s.now().Sub(f).Seconds())
			if age < 0 {
				age = 0
			}
			v.FetchedAt, v.AgeSeconds = &f, &age
		}
	}
	return v
}

func (s *server) owners() map[string]string {
	m := map[string]string{}
	for _, h := range s.hub.Hosts() {
		if h.ActiveAccount != "" {
			m[h.ActiveAccount] = h.Name
		}
	}
	return m
}

func (s *server) accounts(w http.ResponseWriter, _ *http.Request) {
	owners := s.owners()
	list := s.vault.ListPublic() // Block is already removed; accountView has no field for it
	out := make([]accountView, 0, len(list))
	for _, a := range list {
		out = append(out, s.view(a, owners))
	}
	writeJSON(w, http.StatusOK, out)
}

type sessionJSON struct {
	PID         int       `json:"pid"`
	ID          string    `json:"id"`
	Cwd         string    `json:"cwd"`
	StartedAt   time.Time `json:"startedAt"`
	NeedsReload bool      `json:"needsReload"`
}

type hostJSON struct {
	HostID        string        `json:"hostId"`
	Name          string        `json:"name"`
	OS            string        `json:"os"`
	Online        bool          `json:"online"`
	ActiveAccount string        `json:"activeAccount"`
	NeedsReload   bool          `json:"needsReload"`
	SwapBlocked   bool          `json:"swapBlocked"`
	Sessions      []sessionJSON `json:"sessions"`
}

func (s *server) hosts(w http.ResponseWriter, _ *http.Request) {
	hs := s.hub.Hosts()
	out := make([]hostJSON, 0, len(hs))
	for _, h := range hs {
		j := hostJSON{HostID: h.HostID, Name: h.Name, OS: h.OS, Online: h.Online, ActiveAccount: h.ActiveAccount,
			SwapBlocked: h.SwapBlocked, Sessions: make([]sessionJSON, 0, len(h.Sessions))}
		for _, x := range h.Sessions {
			j.Sessions = append(j.Sessions, sessionJSON{PID: x.PID, ID: x.ID, Cwd: x.Cwd, StartedAt: x.StartedAt, NeedsReload: x.NeedsReload})
			j.NeedsReload = j.NeedsReload || x.NeedsReload
		}
		out = append(out, j)
	}
	writeJSON(w, http.StatusOK, out)
}

// hubError maps a hub error to a status and a reason that is safe to show. Unknown errors keep
// their (redacted) text: hub errors already carry operator-facing reasons, never a token.
func hubError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, hub.ErrUnknownHost), errors.Is(err, hub.ErrUnknownAccount), errors.Is(err, hub.ErrNotPending), errors.Is(err, hub.ErrNoAdd):
		writeErr(w, http.StatusNotFound, err.Error())
	case errors.Is(err, hub.ErrAddBusy), errors.Is(err, hub.ErrNotAwaitingCode):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.Is(err, vault.ErrLabelTaken):
		writeErr(w, http.StatusConflict, "an account with that label already exists")
	case errors.Is(err, hub.ErrPendingExpired):
		writeErr(w, http.StatusGone, "the pending connection expired; the agent must reconnect")
	case errors.Is(err, hub.ErrUnknownLiveAccount), errors.Is(err, hub.ErrAgentOffline), errors.Is(err, hub.ErrAlreadyStored):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.Is(err, hub.ErrSwapOutcomeUnknown):
		msg := err.Error()
		if errors.Is(err, hub.ErrUnexpectedReply) { // never echo agent-supplied text
			logger.Warn("hub error", "action", "hub", "result", "failed", logx.Err(err))
			msg = hub.ErrSwapOutcomeUnknown.Error() + ": " + hub.ErrUnexpectedReply.Error()
		}
		writeErr(w, http.StatusBadGateway, msg)
	case errors.Is(err, hub.ErrUnexpectedReply):
		logger.Warn("hub error", "action", "hub", "result", "failed", logx.Err(err))
		writeErr(w, http.StatusBadGateway, hub.ErrUnexpectedReply.Error())
	default:
		logger.Warn("hub error", "action", "hub", "result", "failed", logx.Err(err))
		if strings.HasPrefix(err.Error(), "hub: ") { // hub-authored, already redacted at the source
			writeErr(w, http.StatusBadGateway, err.Error())
			return
		}
		writeErr(w, http.StatusBadGateway, "the request failed; see the server log")
	}
}

func (s *server) swap(w http.ResponseWriter, r *http.Request) {
	var in struct{ Host, Account string }
	if !readJSON(w, r, &in) {
		return
	}
	if in.Host == "" || in.Account == "" {
		writeErr(w, http.StatusBadRequest, "host and account are required")
		return
	}
	if err := s.hub.Swap(r.Context(), in.Host, in.Account); err != nil {
		hubError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *server) enrolCode(w http.ResponseWriter, _ *http.Request) {
	code, exp := s.hub.NewEnrolCode()
	writeJSON(w, http.StatusOK, map[string]any{"code": code, "expires": exp})
}

func (s *server) revoke(w http.ResponseWriter, r *http.Request) {
	if err := s.hub.Revoke(r.PathValue("id")); err != nil {
		hubError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *server) importLogin(w http.ResponseWriter, r *http.Request) {
	var in struct{ Host, Label string }
	if !readJSON(w, r, &in) {
		return
	}
	in.Label = strings.TrimSpace(in.Label)
	if in.Host == "" || in.Label == "" || len(in.Label) > maxLabel {
		writeErr(w, http.StatusBadRequest, "host and a label of 1-64 characters are required")
		return
	}
	for _, a := range s.vault.ListPublic() {
		if strings.EqualFold(a.Label, in.Label) {
			writeErr(w, http.StatusConflict, "an account with that label already exists")
			return
		}
	}
	a, err := s.hub.Import(r.Context(), in.Host, in.Label)
	if err != nil {
		hubError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, s.view(a, s.owners()))
}

// --- add account (sign-in relay) ---

const maxCode = 2048

// jobID returns the {id} path value if it has the shape of a hub job id; otherwise it answers 404.
func jobID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if len(id) != 16 || strings.Trim(id, "0123456789abcdef") != "" {
		writeErr(w, http.StatusNotFound, hub.ErrNoAdd.Error())
		return "", false
	}
	return id, true
}

func (s *server) addAccount(w http.ResponseWriter, r *http.Request) {
	var in struct{ Host, Label string }
	if !readJSON(w, r, &in) {
		return
	}
	in.Label = strings.TrimSpace(in.Label)
	if in.Host == "" || in.Label == "" || len(in.Label) > maxLabel {
		writeErr(w, http.StatusBadRequest, "host and a label of 1-64 characters are required")
		return
	}
	for _, a := range s.vault.ListPublic() {
		if strings.EqualFold(a.Label, in.Label) {
			writeErr(w, http.StatusConflict, "an account with that label already exists")
			return
		}
	}
	id, err := s.hub.AddAccount(r.Context(), in.Host, in.Label)
	if err != nil {
		hubError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"id": id})
}

// addStatusJSON never carries a credential block: accountView has no field for one. url appears
// only while the job awaits the code.
type addStatusJSON struct {
	State   string       `json:"state"`
	URL     string       `json:"url,omitempty"`
	Account *accountView `json:"account,omitempty"`
	Error   string       `json:"error,omitempty"`
}

func (s *server) addStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := jobID(w, r)
	if !ok {
		return
	}
	v, err := s.hub.AddStatus(id)
	if err != nil {
		hubError(w, err)
		return
	}
	out := addStatusJSON{State: string(v.State), Error: v.Error}
	if v.State == hub.AddAwaitingCode {
		out.URL = v.URL
	}
	if v.Account != nil {
		a := *v.Account
		a.Block = nil
		av := s.view(a, s.owners())
		out.Account = &av
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) addCode(w http.ResponseWriter, r *http.Request) {
	id, ok := jobID(w, r)
	if !ok {
		return
	}
	var in struct{ Code string }
	if !readJSON(w, r, &in) {
		return
	}
	in.Code = strings.TrimSpace(in.Code)
	if in.Code == "" || len(in.Code) > maxCode {
		writeErr(w, http.StatusBadRequest, "paste the code from Anthropic's page (1-2048 characters)")
		return
	}
	if err := s.hub.AddCode(id, in.Code); err != nil {
		hubError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *server) addCancel(w http.ResponseWriter, r *http.Request) {
	id, ok := jobID(w, r)
	if !ok {
		return
	}
	if err := s.hub.AddCancel(id); err != nil {
		hubError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *server) relabel(w http.ResponseWriter, r *http.Request) {
	var in struct{ Label string }
	if !readJSON(w, r, &in) {
		return
	}
	id := r.PathValue("id")
	label := strings.TrimSpace(in.Label)
	if id == "" || label == "" || len(label) > maxLabel {
		writeErr(w, http.StatusBadRequest, "a label of 1-64 characters is required")
		return
	}
	switch err := s.hub.Relabel(id, label); {
	case err == nil:
		a, ok := s.vault.Get(id)
		if !ok {
			writeErr(w, http.StatusNotFound, hub.ErrUnknownAccount.Error())
			return
		}
		a.Block = nil
		writeJSON(w, http.StatusOK, s.view(a, s.owners()))
	case errors.Is(err, vault.ErrLabelInvalid):
		writeErr(w, http.StatusBadRequest, "a label of 1-64 characters is required")
	case errors.Is(err, vault.ErrLabelTaken):
		writeErr(w, http.StatusConflict, "an account with that label already exists")
	default:
		hubError(w, err)
	}
}

type pendingJSON struct {
	Fingerprint string    `json:"fingerprint"`
	HostName    string    `json:"hostName"`
	OS          string    `json:"os"`
	SourceIP    string    `json:"sourceIp"`
	Since       time.Time `json:"since"`
	Expires     time.Time `json:"expires"`
}

func (s *server) pending(w http.ResponseWriter, _ *http.Request) {
	ps := s.hub.Pending()
	out := make([]pendingJSON, 0, len(ps))
	for _, p := range ps {
		out = append(out, pendingJSON{p.Fingerprint, p.HostName, p.OS, p.SourceIP, p.Since, p.ExpiresAt})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) allow(w http.ResponseWriter, r *http.Request) {
	fp := r.PathValue("fp")
	if fp == "" || len(fp) > maxFingerprint {
		writeErr(w, http.StatusBadRequest, "bad fingerprint")
		return
	}
	id, err := s.hub.Allow(fp)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]string{"hostId": id})
	case errors.Is(err, hub.ErrNotPending), errors.Is(err, hub.ErrPendingExpired):
		hubError(w, err)
	default:
		logger.Warn("allow failed", "action", "allow", "result", "failed", "reason", "hub refused; details are in the hub log")
		writeErr(w, http.StatusInternalServerError, "could not approve the connection; see the server log")
	}
}

func (s *server) deny(w http.ResponseWriter, r *http.Request) {
	fp := r.PathValue("fp")
	if fp == "" || len(fp) > maxFingerprint {
		writeErr(w, http.StatusBadRequest, "bad fingerprint")
		return
	}
	if err := s.hub.Deny(fp); err != nil {
		hubError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
