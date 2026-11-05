package tunnel

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"

	"claude-utilities/internal/logx"
)

// State is a tunnel's state. up deliberately means "the child survived the grace window", not
// "the forward is established": proving the latter needs an `ssh -v` stderr parse, and that text
// carries the host address. The Hosts tab therefore shows the tunnel state and the agent state as
// two separate indicators and never merges them - "tunnel up, agent offline" is the diagnostic
// case, not a contradiction.
type State string

const (
	StateDisabled      State = "disabled"
	StateConnecting    State = "connecting"
	StateUp            State = "up"
	StateDown          State = "down"
	StateFailed        State = "failed"
	StateRevokePending State = "revoke_pending"
)

// HostTunnel is the UI-safe snapshot of one tunnel. It carries no address and no username: Label
// is the only identifying string, and Reason is one of the fixed codes.
type HostTunnel struct {
	ID          string    `json:"id"`
	Label       string    `json:"label"`
	State       State     `json:"state"`
	Since       time.Time `json:"since"`
	Enabled     bool      `json:"enabled"`
	Attempt     int       `json:"attempt"`
	Restarts1h  int       `json:"restarts1h"`
	LastRestart time.Time `json:"lastRestart,omitzero"`
	Reason      Reason    `json:"reason,omitempty"`
	Detail      string    `json:"detail,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Rotating    bool      `json:"rotating,omitempty"`
	HasHostKey  bool      `json:"hasHostKey"`
}

// Options configures a Supervisor. Only DataDir, Keys and Runner are required.
type Options struct {
	DataDir string
	Keys    Keys
	Runner  Runner
	Log     *slog.Logger
	// Now, Delay, Grace and Stable exist so the state machine can be tested without sleeping for
	// a minute. Zero values take the production defaults.
	Now    func() time.Time
	Delay  func(attempt int) time.Duration
	Grace  time.Duration
	Stable time.Duration
}

// Supervisor keeps one tunnel child per enabled host alive. One supervisor per server process,
// one goroutine per host: hosts are independent, one failing never delays another, and no lock is
// held while a child runs.
type Supervisor struct {
	opt     Options
	journal *journal
	// orphans are the previous process's children, reaped on Start.
	orphans []journalEntry

	mu         sync.Mutex
	hosts      map[string]*runner
	order      []string
	knownHosts string
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	started    bool
	stopped    bool
}

// runner is one host's tunnel. Everything but the channels is guarded by Supervisor.mu.
type runner struct {
	spec     Spec
	state    State
	since    time.Time
	attempt  int
	reason   Reason
	detail   string
	restarts []time.Time
	pid      int
	// kick asks the loop to act now: start a disabled tunnel, or skip the remaining backoff.
	kick chan struct{}
	// proc is the live child, so Stop and a restart request can kill it.
	proc Proc
}

// New opens the journal and returns a Supervisor. It starts nothing: Start does that, after the
// vault is unlocked, because the key material lives there.
func New(o Options) (*Supervisor, error) {
	if o.DataDir == "" {
		return nil, errors.New("tunnel: a data dir is required")
	}
	if o.Keys == nil || o.Runner == nil {
		return nil, errors.New("tunnel: keys and a runner are required")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Delay == nil {
		o.Delay = NextDelay
	}
	if o.Grace == 0 {
		o.Grace = graceWindow
	}
	if o.Stable == 0 {
		o.Stable = stableAfter
	}
	if o.Log == nil {
		o.Log = logx.New(io.Discard)
	}
	o.Log = o.Log.With("component", "tunnel")
	j, orphans, err := openJournal(o.DataDir)
	if err != nil {
		return nil, err
	}
	return &Supervisor{opt: o, journal: j, orphans: orphans, hosts: map[string]*runner{}}, nil
}

// Set replaces the configured tunnels. A spec whose fields changed restarts that host's tunnel;
// one that is unchanged is left running. Specs are validated by the caller (the web layer) before
// they get here; an invalid one is refused rather than spawned.
func (s *Supervisor) Set(specs []Spec) error {
	for _, sp := range specs {
		if err := Validate(sp); err != nil {
			return err
		}
	}
	kh, err := writeKnownHosts(s.opt.DataDir, specs)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.knownHosts = kh
	seen := map[string]bool{}
	var fresh []*runner
	for _, sp := range specs {
		seen[sp.ID] = true
		r, ok := s.hosts[sp.ID]
		if !ok {
			r = &runner{spec: sp, state: StateDisabled, since: s.opt.Now(), kick: make(chan struct{}, 1)}
			s.hosts[sp.ID] = r
			s.order = append(s.order, sp.ID)
			fresh = append(fresh, r)
			continue
		}
		changed := r.spec != sp
		r.spec = sp
		if changed {
			s.nudgeLocked(r)
		}
	}
	// A tunnel that is gone from the configuration stops.
	var dropped []*runner
	for id, r := range s.hosts {
		if !seen[id] {
			dropped = append(dropped, r)
			delete(s.hosts, id)
		}
	}
	s.order = keep(s.order, seen)
	running := s.started && !s.stopped
	ctx := s.ctx
	s.mu.Unlock()

	for _, r := range dropped {
		s.killChild(r, ReasonStopped)
	}
	if running {
		for _, r := range fresh {
			s.wg.Add(1)
			go s.loop(ctx, r)
		}
	}
	return nil
}

func keep(ids []string, seen map[string]bool) []string {
	out := ids[:0]
	for _, id := range ids {
		if seen[id] {
			out = append(out, id)
		}
	}
	return out
}

// Start reaps the previous process's orphans, then runs one goroutine per configured host. It
// never blocks: a host that cannot be reached sits in down or failed and the UI says so.
func (s *Supervisor) Start(ctx context.Context) {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.ctx, s.cancel = context.WithCancel(ctx)
	rctx := s.ctx
	rs := make([]*runner, 0, len(s.hosts))
	for _, r := range s.hosts {
		rs = append(rs, r)
	}
	s.mu.Unlock()

	if n := reap(s.orphans); n > 0 {
		s.opt.Log.Warn("reaped tunnels from a previous server process",
			"action", "tunnel_reap", "result", "ok", "count", n)
	}
	s.journal.clear()
	for _, r := range rs {
		s.wg.Add(1)
		go s.loop(rctx, r)
	}
}

// Stop cancels every runner, kills its child and empties the journal. A second Stop is a no-op.
func (s *Supervisor) Stop() {
	s.mu.Lock()
	if s.stopped || !s.started {
		s.stopped = true
		s.mu.Unlock()
		return
	}
	s.stopped = true
	cancel := s.cancel
	rs := make([]*runner, 0, len(s.hosts))
	for _, r := range s.hosts {
		rs = append(rs, r)
	}
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	for _, r := range rs {
		s.killChild(r, ReasonStopped)
	}
	s.wg.Wait()
	s.journal.clear()
	for _, r := range rs {
		s.opt.Log.Info("tunnel stopped", "action", "tunnel_stopped", "host", r.spec.Label, "result", "ok")
	}
}

// List returns a snapshot of every configured tunnel, ordered as configured.
func (s *Supervisor) List() []HostTunnel {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.opt.Now()
	out := make([]HostTunnel, 0, len(s.order))
	for _, id := range s.order {
		r, ok := s.hosts[id]
		if !ok {
			continue
		}
		out = append(out, s.viewLocked(r, now))
	}
	return out
}

// Get returns one tunnel's snapshot.
func (s *Supervisor) Get(id string) (HostTunnel, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.hosts[id]
	if !ok {
		return HostTunnel{}, false
	}
	return s.viewLocked(r, s.opt.Now()), true
}

// Spec returns a tunnel's configuration, for the web layer to echo back the non-secret fields it
// was given. Address and User are in it, so a caller must not put the result in a log.
func (s *Supervisor) Spec(id string) (Spec, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.hosts[id]
	if !ok {
		return Spec{}, false
	}
	return r.spec, true
}

// Specs returns every configuration, ordered as configured.
func (s *Supervisor) Specs() []Spec {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Spec, 0, len(s.order))
	for _, id := range s.order {
		if r, ok := s.hosts[id]; ok {
			out = append(out, r.spec)
		}
	}
	return out
}

func (s *Supervisor) viewLocked(r *runner, now time.Time) HostTunnel {
	v := HostTunnel{ID: r.spec.ID, Label: r.spec.Label, State: r.state, Since: r.since,
		Enabled: r.spec.Enabled, Attempt: r.attempt, Reason: r.reason, Detail: r.detail,
		HasHostKey: r.spec.HostKey != ""}
	cut := now.Add(-time.Hour)
	for _, t := range r.restarts {
		if t.After(cut) {
			v.Restarts1h++
		}
	}
	if n := len(r.restarts); n > 0 {
		v.LastRestart = r.restarts[n-1]
	}
	if cur, prev, ok := s.opt.Keys.PublicKey(r.spec.ID); ok {
		if fp, err := Fingerprint(cur); err == nil {
			v.Fingerprint = fp
		}
		v.Rotating = prev != nil
	}
	return v
}

// Restart asks a host's tunnel to start now, skipping any remaining backoff and clearing a
// terminal state. It is the one action that makes a failed tunnel try again.
func (s *Supervisor) Restart(id string) error {
	s.mu.Lock()
	r, ok := s.hosts[id]
	if !ok {
		s.mu.Unlock()
		return ErrUnknown
	}
	r.attempt = 0
	s.nudgeLocked(r)
	s.mu.Unlock()
	s.opt.Log.Info("tunnel restart requested", "action", "tunnel_restart_requested",
		"host", r.spec.Label, "result", "accepted")
	s.killChild(r, ReasonStopped)
	return nil
}

// nudgeLocked wakes a host's loop. Caller holds s.mu. The channel is buffered, so a nudge while
// one is already pending is dropped rather than blocking.
func (s *Supervisor) nudgeLocked(r *runner) {
	select {
	case r.kick <- struct{}{}:
	default:
	}
}

// killChild kills a host's live child, if any, outside the lock.
func (s *Supervisor) killChild(r *runner, _ Reason) {
	s.mu.Lock()
	p := r.proc
	s.mu.Unlock()
	if p != nil {
		_ = p.Kill()
	}
}

// setState moves a host to a new state. Reason is the LAST error, not a property of the state:
// an empty reason leaves the previous one in place, so a row that is retrying still shows why it
// is retrying, and only reaching up clears it. Without that, the UI's "last error" column blinks
// empty every time a child is respawned.
func (s *Supervisor) setState(r *runner, st State, reason Reason, detail string) {
	s.mu.Lock()
	changed := r.state != st || (reason != "" && r.reason != reason)
	r.state, r.since = st, s.opt.Now()
	if st == StateUp {
		r.reason, r.detail = "", ""
	}
	if reason != "" {
		r.reason, r.detail = reason, detail
	}
	reason = r.reason
	label, attempt := r.spec.Label, r.attempt
	s.mu.Unlock()
	if !changed {
		return
	}
	// "reason" carries the code, not "code": logx clamps an allowlisted "code" value to 8
	// characters and redacts anything longer, which every reason code here exceeds.
	args := []any{"action", "tunnel_state_change", "host", label, "tunnelstate", string(st),
		"attempt", attempt, "result", "ok"}
	if reason != "" {
		args = append(args, "reason", string(reason))
	}
	if st == StateFailed {
		s.opt.Log.Warn("tunnel state", args...)
		return
	}
	s.opt.Log.Info("tunnel state", args...)
}

// loop is one host's tunnel runner: the state machine in the addendum, one iteration per child.
func (s *Supervisor) loop(ctx context.Context, r *runner) {
	defer s.wg.Done()
	for {
		if ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		spec, kh := r.spec, s.knownHosts
		s.mu.Unlock()

		if !spec.Enabled {
			s.setState(r, StateDisabled, "", "")
			if !s.wait(ctx, r, 0) {
				return
			}
			continue
		}
		reason, detail, wait := s.runOnce(ctx, r, spec, kh)
		if ctx.Err() != nil {
			return
		}
		if !reason.Retryable() {
			s.setState(r, StateFailed, reason, detail)
			if !s.wait(ctx, r, 0) { // only a Restart or a config change gets out of failed
				return
			}
			continue
		}
		s.setState(r, StateDown, reason, detail)
		if !s.wait(ctx, r, wait) {
			return
		}
	}
}

// runOnce writes the key file, starts one child, follows it to its exit and returns why it ended
// plus how long to wait before the next attempt.
func (s *Supervisor) runOnce(ctx context.Context, r *runner, spec Spec, knownHosts string) (Reason, string, time.Duration) {
	s.mu.Lock()
	attempt := r.attempt
	s.mu.Unlock()
	next := s.opt.Delay(attempt)

	if spec.HostKey == "" {
		// StrictHostKeyChecking=yes would fail on the first dial anyway; say so plainly instead
		// of spending a child to find out.
		return ReasonHostkeyNotSeeded, ReasonHostkeyNotSeeded.Sentence(), next
	}
	seed, ok := s.opt.Keys.Seed(spec.ID)
	if !ok {
		return ReasonNoKey, ReasonNoKey.Sentence(), next
	}
	dir, err := keyDir(s.opt.DataDir)
	if err != nil {
		return ReasonExecFailed, Scrub(err.Error(), spec.Address, spec.User), next
	}
	keyPath, err := writeKeyFile(dir, spec.ID, seed)
	if err != nil {
		return ReasonExecFailed, Scrub(err.Error(), spec.Address, spec.User), next
	}
	defer removeQuiet(keyPath)

	s.setState(r, StateConnecting, "", "")
	proc, err := s.opt.Runner.Start(ctx, spec, keyPath, knownHosts)
	if err != nil {
		return ReasonExecFailed, Scrub(err.Error(), spec.Address, spec.User), next
	}
	started := s.opt.Now()
	pid := proc.Pid()
	// Record the child under the lock BEFORE anything else can block: Stop kills through r.proc,
	// so a child adopted after Stop has run would outlive the server. adopt refuses in that case
	// and kills it itself.
	if !s.adopt(r, proc, started) {
		return ReasonStopped, "", next
	}
	if jerr := s.journal.add(journalEntry{HostID: spec.ID, PID: pid, Started: started, KeyPath: keyPath}); jerr != nil {
		s.opt.Log.Warn("tunnel journal write failed", "action", "tunnel_journal", "host", spec.Label,
			"result", "failed", "reason", "a hard kill of the server may leave this child behind")
	}
	s.opt.Log.Info("tunnel start", "action", "tunnel_start", "host", spec.Label, "pid", pid, "result", "ok")

	exited := make(chan int, 1)
	go func() { exited <- proc.Wait() }()

	var code int
	select {
	case code = <-exited:
	case <-time.After(s.opt.Grace):
		s.setState(r, StateUp, "", "")
		code = <-exited
	}
	ended := s.opt.Now()
	// Classify reads the stderr here and nowhere else, so the text cannot be kept by accident.
	reason := Classify(proc.Stderr(), code)
	s.journal.remove(pid)
	s.mu.Lock()
	r.proc, r.pid = nil, 0
	if ended.Sub(started) >= s.opt.Stable {
		r.attempt = 0
	} else {
		r.attempt++
	}
	attempt = r.attempt
	s.mu.Unlock()
	s.opt.Log.Info("tunnel exit", "action", "tunnel_exit", "host", spec.Label, "pid", pid,
		"reason", string(reason), "attempt", attempt, "durationms", ended.Sub(started).Milliseconds(),
		"result", "exited")
	return reason, reason.Sentence(), s.opt.Delay(attempt)
}

// adopt records a freshly started child as this host's live one, or kills it at once and reports
// false when the supervisor is already stopping.
func (s *Supervisor) adopt(r *runner, p Proc, started time.Time) bool {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		_ = p.Kill()
		return false
	}
	r.proc, r.pid = p, p.Pid()
	r.restarts = append(r.restarts, started)
	if len(r.restarts) > maxRestartHistory {
		r.restarts = r.restarts[len(r.restarts)-maxRestartHistory:]
	}
	s.mu.Unlock()
	return true
}

// maxRestartHistory bounds the restart timestamps kept per host. The UI needs an hour's worth and
// the last restart time, so an unreachable host cannot grow this list for a week.
const maxRestartHistory = 64

// wait blocks for d, or until the host is kicked or the context ends. d == 0 waits indefinitely
// for a kick, which is how disabled and failed park. It returns false when the loop must stop.
func (s *Supervisor) wait(ctx context.Context, r *runner, d time.Duration) bool {
	if d <= 0 {
		select {
		case <-ctx.Done():
			return false
		case <-r.kick:
			return true
		}
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-r.kick:
		return true
	case <-t.C:
		return true
	}
}

func init() {
	// The allowlist is an allowlist: a key not registered here logs as "[dropped]". Note what is
	// deliberately absent - there is no key containing "key" (logx.Allow panics on one), and the
	// reason code travels under "reason" rather than "code", whose values are clamped to 8
	// characters. "host" already exists and means the label, never an address.
	logx.Allow("tunnelstate", "restarts", "fingerprint")
}
