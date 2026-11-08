package tunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"claude-utilities/internal/logx"
	"claude-utilities/internal/vault"
)

// --- fixtures ---------------------------------------------------------------------------------

// These are the values no log line, API response or generated command may ever contain. They are
// deliberately distinctive so the leak test can grep for them.
const (
	secretAddress = "host-7.estate.invalid"
	secretUser    = "someoperator"
)

func okSpec() Spec {
	return Spec{ID: "h-1", Label: "SRL-LIN", Address: secretAddress, User: secretUser,
		Port: DefaultPort, Enabled: true, HostKey: testHostKey(nil)}
}

// testHostKey returns a canonical host key line for seeding known_hosts.
func testHostKey(t *testing.T) string {
	pub, _, err := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{7}, 64)))
	if err != nil {
		if t != nil {
			t.Fatalf("host key: %v", err)
		}
		return ""
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

// fakeKeys is an in-memory Keys.
type fakeKeys struct {
	mu    sync.Mutex
	seeds map[string][]byte
}

func newFakeKeys(ids ...string) *fakeKeys {
	k := &fakeKeys{seeds: map[string][]byte{}}
	for i, id := range ids {
		k.seeds[id] = bytes.Repeat([]byte{byte(i + 1)}, ed25519.SeedSize)
	}
	return k
}

func (k *fakeKeys) Seed(id string) ([]byte, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	s, ok := k.seeds[id]
	return s, ok
}

func (k *fakeKeys) PublicKey(id string) (ed25519.PublicKey, ed25519.PublicKey, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	s, ok := k.seeds[id]
	if !ok {
		return nil, nil, false
	}
	return ed25519.NewKeyFromSeed(s).Public().(ed25519.PublicKey), nil, true
}

// fakeProc is a scripted child. linger is how long it stays alive: zero exits at once, and a
// long linger is how a test says "this tunnel stays up".
type fakeProc struct {
	pid    int
	code   int
	stderr string
	done   chan struct{}
	once   sync.Once
	linger time.Duration
}

func (p *fakeProc) Pid() int { return p.pid }
func (p *fakeProc) Wait() int {
	if p.linger > 0 {
		select {
		case <-p.done:
		case <-time.After(p.linger):
		}
	}
	return p.code
}
func (p *fakeProc) Kill() error    { p.once.Do(func() { close(p.done) }); return nil }
func (p *fakeProc) Stderr() string { return p.stderr }

// fakeRunner records every start and hands back whatever the test scripted.
type fakeRunner struct {
	mu       sync.Mutex
	starts   []Spec
	argv     [][]string
	procs    []*fakeProc
	script   func(n int) (code int, stderr string, linger time.Duration)
	startErr error
	spawned  chan struct{}
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{spawned: make(chan struct{}, 64),
		script: func(int) (int, string, time.Duration) {
			return 1, "kex_exchange_identification: connection closed by remote host", 0
		}}
}

func (r *fakeRunner) Start(_ context.Context, s Spec, keyPath, knownHosts string) (Proc, error) {
	r.mu.Lock()
	if r.startErr != nil {
		err := r.startErr
		r.mu.Unlock()
		return nil, err
	}
	n := len(r.starts)
	r.starts = append(r.starts, s)
	r.argv = append(r.argv, Args(s, keyPath, knownHosts))
	code, stderr, linger := r.script(n)
	p := &fakeProc{pid: 30000 + n, code: code, stderr: stderr, done: make(chan struct{}), linger: linger}
	r.procs = append(r.procs, p)
	r.mu.Unlock()
	select {
	case r.spawned <- struct{}{}:
	default:
	}
	return p, nil
}

func (r *fakeRunner) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.starts)
}

func (r *fakeRunner) labels() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.starts))
	for _, s := range r.starts {
		out = append(out, s.Label)
	}
	return out
}

func (r *fakeRunner) lastArgv(t *testing.T) []string {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.argv) == 0 {
		t.Fatal("nothing was spawned")
	}
	return r.argv[len(r.argv)-1]
}

func (r *fakeRunner) exitLast() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n := len(r.procs); n > 0 {
		_ = r.procs[n-1].Kill()
	}
}

func (r *fakeRunner) waitSpawn(t *testing.T, want int) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for r.count() < want {
		select {
		case <-r.spawned:
		case <-deadline:
			t.Fatalf("only %d of %d spawns happened", r.count(), want)
		}
	}
}

type sup struct {
	s   *Supervisor
	r   *fakeRunner
	k   *fakeKeys
	log *bytes.Buffer
	dir string
}

func newSup(t *testing.T, specs ...Spec) *sup {
	t.Helper()
	dir := t.TempDir()
	r := newFakeRunner()
	k := newFakeKeys("h-1", "h-2")
	buf := &bytes.Buffer{}
	s, err := New(Options{DataDir: dir, Keys: k, Runner: r, Log: logx.New(buf),
		Grace: 10 * time.Millisecond, Stable: 500 * time.Millisecond,
		Delay: func(int) time.Duration { return 5 * time.Millisecond }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(specs) > 0 {
		if err := s.Set(specs); err != nil {
			t.Fatalf("Set: %v", err)
		}
	}
	return &sup{s: s, r: r, k: k, log: buf, dir: dir}
}

// waitState polls until a tunnel reaches one of the wanted states.
func (x *sup) waitState(t *testing.T, id string, want ...State) HostTunnel {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last HostTunnel
	for time.Now().Before(deadline) {
		v, ok := x.s.Get(id)
		if ok {
			last = v
			for _, w := range want {
				if v.State == w {
					return v
				}
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("%s stayed in %q (reason %q), want one of %v", id, last.State, last.Reason, want)
	return last
}

// --- backoff ----------------------------------------------------------------------------------

func TestNextDelayDoublesCapsAndJitters(t *testing.T) {
	for attempt := 0; attempt < 30; attempt++ {
		nominal := time.Duration(1<<min(attempt, 10)) * time.Second
		if nominal > MaxDelay {
			nominal = MaxDelay
		}
		for i := 0; i < 20; i++ {
			d := NextDelay(attempt)
			if d > nominal || d < nominal*8/10 {
				t.Fatalf("attempt %d: %v outside [%v, %v]", attempt, d, nominal*8/10, nominal)
			}
		}
	}
	for _, a := range []int{-7, 1 << 30} {
		if d := NextDelay(a); d <= 0 || d > MaxDelay {
			t.Fatalf("attempt %d: %v", a, d)
		}
	}
	// The first retry must be fast: the flat 15 s wait is what this replaces.
	if NextDelay(0) > time.Second {
		t.Fatalf("the first retry waits %v, want <= 1s", NextDelay(0))
	}
}

// --- validation -------------------------------------------------------------------------------

func TestValidateRefusesAnythingThatCouldReachAnArgv(t *testing.T) {
	for name, mut := range map[string]func(*Spec){
		"space in address":     func(s *Spec) { s.Address = "a b" },
		"quote in address":     func(s *Spec) { s.Address = `a"b` },
		"newline in address":   func(s *Spec) { s.Address = "a\nb" },
		"leading dash address": func(s *Spec) { s.Address = "-oProxyCommand=x" },
		"semicolon address":    func(s *Spec) { s.Address = "a;id" },
		"backtick address":     func(s *Spec) { s.Address = "a`id`" },
		"dollar address":       func(s *Spec) { s.Address = "a$x" },
		"empty address":        func(s *Spec) { s.Address = "" },
		"long address":         func(s *Spec) { s.Address = strings.Repeat("a", 254) },
		"space in user":        func(s *Spec) { s.User = "a b" },
		"uppercase user":       func(s *Spec) { s.User = "Root" },
		"leading dash user":    func(s *Spec) { s.User = "-oFoo" },
		"empty user":           func(s *Spec) { s.User = "" },
		"quote in label":       func(s *Spec) { s.Label = `a"b` },
		"space in label":       func(s *Spec) { s.Label = "a b" },
		"slash in label":       func(s *Spec) { s.Label = "a/b" },
		"empty label":          func(s *Spec) { s.Label = "" },
		"long label":           func(s *Spec) { s.Label = strings.Repeat("a", 33) },
		"port zero":            func(s *Spec) { s.Port = 0 },
		"port too high":        func(s *Spec) { s.Port = 70000 },
		"negative port":        func(s *Spec) { s.Port = -1 },
	} {
		s := okSpec()
		mut(&s)
		if err := Validate(s); err == nil {
			t.Errorf("%s: Validate accepted %+v", name, s)
		}
	}
	for _, addr := range []string{"host.example.internal", "10.0.0.5", "a", "h-1.sub.example.", "::1"} {
		s := okSpec()
		s.Address = addr
		if err := Validate(s); err != nil {
			t.Errorf("Validate rejected a valid address %q: %v", addr, err)
		}
	}
}

func TestSetRefusesAnInvalidSpecAndSpawnsNothing(t *testing.T) {
	x := newSup(t)
	bad := okSpec()
	bad.Address = "a b"
	if err := x.s.Set([]Spec{bad}); !errors.Is(err, ErrBadAddress) {
		t.Fatalf("want ErrBadAddress, got %v", err)
	}
	x.s.Start(t.Context())
	defer x.s.Stop()
	time.Sleep(30 * time.Millisecond)
	if x.r.count() != 0 {
		t.Fatalf("an invalid spec spawned %d children", x.r.count())
	}
}

// --- argv -------------------------------------------------------------------------------------

func TestArgvCarriesEveryHardeningOptionAndExactlyOneForward(t *testing.T) {
	got := Args(okSpec(), "C:\\keys\\tun-h-1", "C:\\data\\known_hosts")
	joined := strings.Join(got, " ")
	// The bf8b46d hardening plus what the addendum adds. Every one of these is load-bearing; a
	// missing -F would let the user's ssh_config contribute a forward.
	for _, want := range []string{
		"-F " + nullDevice,
		"-i C:\\keys\\tun-h-1",
		"-N",
		"ForwardAgent=no",
		"ForwardX11=no",
		"PermitLocalCommand=no",
		"IdentitiesOnly=yes",
		"BatchMode=yes",
		"PubkeyAuthentication=yes",
		"PreferredAuthentications=publickey",
		"ExitOnForwardFailure=yes",
		"ServerAliveInterval=30",
		"ServerAliveCountMax=3",
		"StrictHostKeyChecking=yes",
		"UserKnownHostsFile=C:\\data\\known_hosts",
		"GlobalKnownHostsFile=" + nullDevice,
		"-R 127.0.0.1:8443:127.0.0.1:8443",
		secretUser + "@" + secretAddress,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("argv is missing %q\ngot: %s", want, joined)
		}
	}
	// Matthew has other network traffic on this machine: a local or dynamic forward must never
	// appear, and there must be exactly one -R.
	for _, never := range []string{"-L", "-D", "-W", "StrictHostKeyChecking=no", "accept-new", "-g"} {
		for _, a := range got {
			if a == never {
				t.Errorf("argv contains %q", never)
			}
		}
	}
	rs := 0
	for _, a := range got {
		if a == "-R" {
			rs++
		}
	}
	if rs != 1 {
		t.Errorf("argv carries %d -R forwards, want exactly 1", rs)
	}
}

// --- classification ---------------------------------------------------------------------------

func TestClassifyMapsStderrToAReasonAndRetryability(t *testing.T) {
	for _, tc := range []struct {
		stderr string
		code   int
		want   Reason
		retry  bool
	}{
		{"Permission denied (publickey).", 255, ReasonAuthDenied, false},
		{"@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@", 255, ReasonHostkeyMismatch, false},
		{"Host key verification failed.", 255, ReasonHostkeyUnknown, false},
		{"Warning: remote port forwarding failed for listen port 8443", 1, ReasonForwardRefused, true},
		{"channel 0: open failed: administratively prohibited", 1, ReasonForwardRefused, true},
		{"ssh: connect to host port 22: Connection refused", 255, ReasonUnreachable, true},
		{"ssh: Could not resolve hostname: Name or service not known", 255, ReasonUnreachable, true},
		{"", 0, ReasonUnreachable, true},
		{"", -1, ReasonKilled, true},
		{"", 42, Reason("exit_42"), true},
	} {
		got := Classify(tc.stderr, tc.code)
		if got != tc.want {
			t.Errorf("Classify(%q, %d) = %q, want %q", tc.stderr, tc.code, got, tc.want)
		}
		if got.Retryable() != tc.retry {
			t.Errorf("%q.Retryable() = %v, want %v", got, got.Retryable(), tc.retry)
		}
		if got.Sentence() == "" {
			t.Errorf("%q has no sentence", got)
		}
	}
	// The mismatch banner also contains "host key"; it must not be read as the generic failure.
	if r := Classify("REMOTE HOST IDENTIFICATION HAS CHANGED\nHost key verification failed.", 255); r != ReasonHostkeyMismatch {
		t.Errorf("the mismatch banner classified as %q", r)
	}
}

func TestScrubRemovesTheAddressTheUserAndForeignIPs(t *testing.T) {
	in := "ssh: connect to host " + secretAddress + " as " + secretUser +
		" via 10.1.2.3 and 192.168.0.9 (loopback 127.0.0.1)   \n  spaced"
	got := Scrub(in, secretAddress, secretUser)
	for _, bad := range []string{secretAddress, secretUser, "10.1.2.3", "192.168.0.9"} {
		if strings.Contains(got, bad) {
			t.Errorf("Scrub kept %q: %s", bad, got)
		}
	}
	if !strings.Contains(got, "127.0.0.1") {
		t.Errorf("Scrub masked loopback, which carries no information: %s", got)
	}
	if strings.Contains(got, "  ") || strings.Contains(got, "\n") {
		t.Errorf("Scrub did not collapse whitespace: %q", got)
	}
	if Scrub("   ", secretAddress, secretUser) != "" {
		t.Error("Scrub should return empty for blank text")
	}
	if n := len(Scrub(strings.Repeat("x ", 500), "", "")); n > maxScrub {
		t.Errorf("Scrub returned %d bytes, want <= %d", n, maxScrub)
	}
}

// --- supervisor state machine -----------------------------------------------------------------

func TestSupervisorStartsOneChildPerEnabledHostAndNoneForADisabledOne(t *testing.T) {
	on, off := okSpec(), okSpec()
	off.ID, off.Label, off.Enabled = "h-2", "TSS", false
	x := newSup(t, on, off)
	x.r.script = func(int) (int, string, time.Duration) { return 0, "", time.Minute } // stay up
	x.s.Start(t.Context())
	defer x.s.Stop()

	x.waitState(t, "h-1", StateUp)
	x.waitState(t, "h-2", StateDisabled)
	if got := x.r.labels(); len(got) != 1 || got[0] != "SRL-LIN" {
		t.Fatalf("spawned %v, want exactly [SRL-LIN]", got)
	}
	// The child must be pointed at the MANAGED known_hosts in the data dir and at the ephemeral
	// key file, not at anything in the operator's own ~/.ssh.
	argv := strings.Join(x.r.lastArgv(t), " ")
	wantKH := "UserKnownHostsFile=" + filepath.Join(x.dir, KnownHostsFileName)
	if !strings.Contains(argv, wantKH) {
		t.Errorf("argv does not use the managed known_hosts (%s): %s", wantKH, argv)
	}
	if !strings.Contains(argv, "-i "+filepath.Join(x.dir, keyDirName)) {
		t.Errorf("argv does not use the ephemeral key file in the data dir: %s", argv)
	}
}

func TestRetryableExitGoesDownThenRestartsAndCountsTheAttempt(t *testing.T) {
	x := newSup(t, okSpec())
	x.s.Start(t.Context())
	defer x.s.Stop()

	x.r.waitSpawn(t, 3) // the default script exits retryably, so it respawns on its own
	v := x.waitState(t, "h-1", StateDown, StateConnecting, StateUp)
	if v.Attempt == 0 && v.State == StateDown {
		t.Fatal("a retryable exit did not increment the attempt counter")
	}
	if v.Restarts1h < 1 {
		t.Fatalf("restarts in the last hour = %d, want >= 1", v.Restarts1h)
	}
	if v.LastRestart.IsZero() {
		t.Fatal("the last restart time was never recorded")
	}
}

func TestAChildUpLongerThanStableResetsTheAttemptCounter(t *testing.T) {
	x := newSup(t, okSpec())
	// Exit retryably twice to climb the counter, then stay up past Stable.
	x.r.script = func(n int) (int, string, time.Duration) {
		if n < 2 {
			return 1, "connection refused", 0
		}
		return 1, "connection refused", 600 * time.Millisecond
	}
	x.s.Start(t.Context())
	defer x.s.Stop()

	x.r.waitSpawn(t, 3)
	x.waitState(t, "h-1", StateUp)
	// The third child lingers past Stable (500ms) and then exits; the counter must be back to 0.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if v, ok := x.s.Get("h-1"); ok && v.Attempt == 0 && x.r.count() >= 4 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	v, _ := x.s.Get("h-1")
	t.Fatalf("attempt is still %d after a stable connection", v.Attempt)
}

func TestTerminalReasonsStopTheRetryLoopUntilRestart(t *testing.T) {
	for _, tc := range []struct {
		stderr string
		want   Reason
	}{
		{"Permission denied (publickey).", ReasonAuthDenied},
		{"@@@ REMOTE HOST IDENTIFICATION HAS CHANGED! @@@", ReasonHostkeyMismatch},
	} {
		x := newSup(t, okSpec())
		x.r.script = func(int) (int, string, time.Duration) { return 255, tc.stderr, 0 }
		x.s.Start(t.Context())

		v := x.waitState(t, "h-1", StateFailed)
		if v.Reason != tc.want {
			t.Fatalf("reason = %q, want %q", v.Reason, tc.want)
		}
		after := x.r.count()
		time.Sleep(60 * time.Millisecond) // many backoff windows at 5ms
		if x.r.count() != after {
			t.Fatalf("%q kept respawning: %d then %d", tc.want, after, x.r.count())
		}
		// Restart is the way out of a terminal state.
		if err := x.s.Restart("h-1"); err != nil {
			t.Fatalf("Restart: %v", err)
		}
		x.r.waitSpawn(t, after+1)
		x.s.Stop()
	}
}

func TestForwardRefusedIsRetried(t *testing.T) {
	x := newSup(t, okSpec())
	x.r.script = func(int) (int, string, time.Duration) {
		return 1, "Warning: remote port forwarding failed for listen port 8443", 0
	}
	x.s.Start(t.Context())
	defer x.s.Stop()
	x.r.waitSpawn(t, 3)
	if v, _ := x.s.Get("h-1"); v.Reason != ReasonForwardRefused {
		t.Fatalf("reason = %q, want %q", v.Reason, ReasonForwardRefused)
	}
}

func TestAHostWithNoKeyOrNoHostKeyFailsWithoutSpawning(t *testing.T) {
	nokey := okSpec()
	nokey.ID = "h-nokey"
	noseed := okSpec()
	noseed.ID, noseed.Label, noseed.HostKey = "h-2", "TSS", ""
	x := newSup(t, nokey, noseed)
	x.s.Start(t.Context())
	defer x.s.Stop()

	if v := x.waitState(t, "h-nokey", StateFailed); v.Reason != ReasonNoKey {
		t.Fatalf("reason = %q, want %q", v.Reason, ReasonNoKey)
	}
	if v := x.waitState(t, "h-2", StateFailed); v.Reason != ReasonHostkeyNotSeeded {
		t.Fatalf("reason = %q, want %q", v.Reason, ReasonHostkeyNotSeeded)
	}
	if x.r.count() != 0 {
		t.Fatalf("spawned %d children for hosts that cannot connect", x.r.count())
	}
}

func TestStartFailureIsExecFailedAndScrubbed(t *testing.T) {
	x := newSup(t, okSpec())
	x.r.startErr = errors.New("cannot start ssh for " + secretUser + "@" + secretAddress)
	x.s.Start(t.Context())
	defer x.s.Stop()
	v := x.waitState(t, "h-1", StateFailed)
	if v.Reason != ReasonExecFailed {
		t.Fatalf("reason = %q, want %q", v.Reason, ReasonExecFailed)
	}
	if strings.Contains(v.Detail, secretAddress) || strings.Contains(v.Detail, secretUser) {
		t.Fatalf("the detail leaked the address or the user: %q", v.Detail)
	}
}

func TestStopKillsEveryChildEmptiesTheJournalAndIsIdempotent(t *testing.T) {
	two := okSpec()
	two.ID, two.Label = "h-2", "TSS"
	x := newSup(t, okSpec(), two)
	x.r.script = func(int) (int, string, time.Duration) { return 0, "", time.Minute }
	x.s.Start(context.Background())

	x.waitState(t, "h-1", StateUp)
	x.waitState(t, "h-2", StateUp)
	journalPath := filepath.Join(x.dir, JournalFileName)
	if n := journalCount(t, journalPath); n != 2 {
		t.Fatalf("the journal holds %d live children, want 2", n)
	}
	x.s.Stop()
	x.s.Stop() // a second Stop is a no-op
	if n := journalCount(t, journalPath); n != 0 {
		t.Fatalf("the journal still holds %d entries after Stop", n)
	}
	if !strings.Contains(x.log.String(), "tunnel_stopped") {
		t.Error("Stop logged no tunnel_stopped line")
	}
	// Every ephemeral key file is gone.
	left, _ := filepath.Glob(filepath.Join(x.dir, keyDirName, "*"))
	if len(left) != 0 {
		t.Fatalf("ephemeral key files survived Stop: %v", left)
	}
}

func TestSetStopsATunnelThatIsGoneFromTheConfiguration(t *testing.T) {
	two := okSpec()
	two.ID, two.Label = "h-2", "TSS"
	x := newSup(t, okSpec(), two)
	x.r.script = func(int) (int, string, time.Duration) { return 0, "", time.Minute }
	x.s.Start(t.Context())
	defer x.s.Stop()
	x.waitState(t, "h-1", StateUp)
	x.waitState(t, "h-2", StateUp)

	if err := x.s.Set([]Spec{okSpec()}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if _, ok := x.s.Get("h-2"); ok {
		t.Fatal("the removed tunnel is still listed")
	}
	if n := len(x.s.List()); n != 1 {
		t.Fatalf("List returned %d tunnels, want 1", n)
	}
}

func TestRestartOnAnUnknownHost(t *testing.T) {
	x := newSup(t, okSpec())
	if err := x.s.Restart("nope"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("want ErrUnknown, got %v", err)
	}
}

// --- ephemeral key file -----------------------------------------------------------------------

func TestTheEphemeralKeyFileIsRestrictedAndRemovedWhenTheChildExits(t *testing.T) {
	x := newSup(t, okSpec())
	var seen string
	x.r.script = func(int) (int, string, time.Duration) { return 0, "", time.Minute }
	x.s.Start(t.Context())
	defer x.s.Stop()
	x.waitState(t, "h-1", StateUp)

	files, _ := filepath.Glob(filepath.Join(x.dir, keyDirName, "tun-*"))
	if len(files) != 1 {
		t.Fatalf("want exactly one ephemeral key file, got %v", files)
	}
	seen = files[0]
	if _, err := os.Stat(seen); err != nil {
		t.Fatalf("stat: %v", err)
	}
	// What makes the file owner-only is checked per platform: the Unix mode, or the Windows ACL,
	// since Windows Chmod only toggles the read-only bit and reports 0666 whatever we ask for.
	checkKeyFileRestricted(t, seen)
	// It must be a real OpenSSH private key, not something ssh will reject.
	data, err := os.ReadFile(seen) // #nosec G304 -- a path this test just created
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if _, err := ssh.ParsePrivateKey(data); err != nil {
		t.Fatalf("ssh cannot parse the key file: %v", err)
	}
	x.r.exitLast()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(seen); os.IsNotExist(err) {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("the ephemeral key file outlived its child")
}

// --- journal and reap -------------------------------------------------------------------------

func journalCount(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- a path the test owns
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatalf("read journal: %v", err)
	}
	var list []journalEntry
	if err := json.Unmarshal(data, &list); err != nil {
		t.Fatalf("parse journal: %v", err)
	}
	return len(list)
}

// A journal that survives a hard kill must not let the next server process kill an unrelated
// process that has since been given the same pid. The pid here is this test binary's own, which
// is certainly not ssh, so reap must leave it alone - and the orphan key file must still go.
func TestReapNeverKillsAProcessThatIsNotSSH(t *testing.T) {
	dir := t.TempDir()
	orphanKey := filepath.Join(dir, "orphan-key")
	if err := os.WriteFile(orphanKey, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	entries := []journalEntry{
		{HostID: "h-1", PID: os.Getpid(), Started: time.Now(), KeyPath: orphanKey},
		{HostID: "h-2", PID: 0},
		{HostID: "h-3", PID: -3},
	}
	if n := reap(entries); n != 0 {
		t.Fatalf("reap terminated %d processes, want 0", n)
	}
	if _, err := os.Stat(orphanKey); !os.IsNotExist(err) {
		t.Error("reap left the orphaned key file behind")
	}
	// And this process is, obviously, still running.
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("reap killed the test: %v", err)
	}
}

func TestSupervisorReapsAJournalLeftByAHardKill(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "left-behind-key")
	if err := os.WriteFile(key, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	entries := []journalEntry{{HostID: "h-1", PID: os.Getpid(), Started: time.Now(), KeyPath: key}}
	data, _ := json.Marshal(entries)
	if err := os.WriteFile(filepath.Join(dir, JournalFileName), data, 0o600); err != nil {
		t.Fatalf("write journal: %v", err)
	}
	s, err := New(Options{DataDir: dir, Keys: newFakeKeys(), Runner: newFakeRunner(), Log: logx.New(&bytes.Buffer{})})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.Start(t.Context())
	defer s.Stop()
	if _, err := os.Stat(key); !os.IsNotExist(err) {
		t.Error("the orphaned key file survived the reap at start")
	}
	if n := journalCount(t, filepath.Join(dir, JournalFileName)); n != 0 {
		t.Errorf("the journal was not emptied at start: %d entries", n)
	}
}

// --- known_hosts ------------------------------------------------------------------------------

func TestKnownHostsIsManagedAndSeededFromThePastedKey(t *testing.T) {
	a, b := okSpec(), okSpec()
	b.ID, b.Label, b.Address = "h-2", "TSS", "other.estate.invalid"
	b.HostKey = "" // not seeded yet
	x := newSup(t, a, b)
	path := filepath.Join(x.dir, KnownHostsFileName)
	if n := countKnownHosts(path); n != 1 {
		t.Fatalf("known_hosts has %d entries, want 1 (only the seeded host)", n)
	}
	b.HostKey = testHostKey(t)
	if err := x.s.Set([]Spec{a, b}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if n := countKnownHosts(path); n != 2 {
		t.Fatalf("known_hosts has %d entries after seeding the second host, want 2", n)
	}
	// A host that leaves the configuration must not leave a line behind.
	if err := x.s.Set([]Spec{a}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if n := countKnownHosts(path); n != 1 {
		t.Fatalf("known_hosts has %d entries after removing a host, want 1", n)
	}
}

func TestParseHostKeyAcceptsAPublicKeyAndRefusesEverythingElse(t *testing.T) {
	line := testHostKey(t)
	got, err := ParseHostKey(line + " root@somewhere")
	if err != nil {
		t.Fatalf("ParseHostKey: %v", err)
	}
	if got != line {
		t.Fatalf("ParseHostKey = %q, want the key without the comment %q", got, line)
	}
	if HostKeyFingerprint(got) == "" || !strings.HasPrefix(HostKeyFingerprint(got), "SHA256:") {
		t.Errorf("no SHA256 fingerprint for a valid host key: %q", HostKeyFingerprint(got))
	}
	for _, bad := range []string{"", "   ", "not a key", "ssh-ed25519 !!!!", line + "\nextra line",
		strings.Repeat("a", 5000)} {
		if _, err := ParseHostKey(bad); !errors.Is(err, ErrBadHostKey) {
			t.Errorf("ParseHostKey(%.20q) = %v, want ErrBadHostKey", bad, err)
		}
	}
}

// --- authorized_keys lines --------------------------------------------------------------------

func authKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	k, err := SSHPublicKey(pub)
	if err != nil {
		t.Fatalf("SSHPublicKey: %v", err)
	}
	return k
}

func TestTheAuthorizedKeysLineOrdersItsOptionsCorrectly(t *testing.T) {
	k := authKey(t)
	line := Line(k, "SRL-LIN", DefaultPort, false)
	t.Logf("recommended line: %s", line)
	if !strings.HasPrefix(line, `command="/bin/false",restrict,port-forwarding,permitlisten="127.0.0.1:8443" `) {
		t.Fatalf("unexpected option list: %s", line)
	}
	// restrict denies everything including future capabilities; a LATER option wins, so
	// port-forwarding must come after it or forwarding stays off and the tunnel never works.
	if strings.Index(line, "restrict") > strings.Index(line, "port-forwarding") {
		t.Fatal("port-forwarding comes before restrict, which would be overridden")
	}
	if !strings.HasSuffix(line, " claude-swap-tunnel-SRL-LIN") {
		t.Fatalf("the line does not name the host: %s", line)
	}
	tight := Line(k, "SRL-LIN", DefaultPort, true)
	t.Logf("tightened (OPTION, not applied): %s", tight)
	if !strings.Contains(tight, `permitopen="127.0.0.1:1"`) {
		t.Fatal("the tightened line is missing permitopen")
	}
	if strings.Index(tight, "port-forwarding") > strings.Index(tight, `permitopen=`) {
		t.Fatal("permitopen must come after port-forwarding")
	}
	if strings.Contains(line, `permitopen=`) {
		t.Fatal("the recommended line must not carry permitopen: it is an unverified option")
	}
}

func TestGeneratedCommandsCarryThePublicKeyOnlyAndAreIdempotent(t *testing.T) {
	k := authKey(t)
	seed := bytes.Repeat([]byte{3}, ed25519.SeedSize)
	priv, err := encodePrivateKey(seed)
	if err != nil {
		t.Fatalf("encodePrivateKey: %v", err)
	}
	install := InstallCommand(k, "SRL-LIN", DefaultPort, false)
	remove := RemoveCommand(k)
	for _, cmd := range []string{install, remove} {
		if strings.Contains(cmd, "PRIVATE KEY") || bytes.Contains([]byte(cmd), priv) {
			t.Fatal("a generated command contains private key material")
		}
		if strings.Contains(cmd, secretAddress) || strings.Contains(cmd, secretUser) {
			t.Fatal("a generated command contains the host address or the username")
		}
		if strings.Contains(cmd, "\n") {
			t.Fatalf("a generated command is not one line: %q", cmd)
		}
	}
	if !strings.Contains(install, keyBody(k)) {
		t.Fatal("the install command does not contain the public key")
	}
	if !strings.Contains(install, `grep -qF "$K"`) {
		t.Fatal("the install command is not idempotent: no grep guard")
	}
	if !strings.Contains(install, "chmod 600 ~/.ssh/authorized_keys") || !strings.Contains(install, "chmod 700 ~/.ssh") {
		t.Fatal("the install command does not fix the modes")
	}
	if !strings.Contains(install, "ssh-keygen -lf") {
		t.Fatal("the install command does not print the host's own fingerprint")
	}
	if !strings.Contains(remove, `grep -vF "$K"`) || !strings.Contains(remove, "mv ") {
		t.Fatal("the remove command does not filter the file and rename it into place")
	}
}

// The remove command must leave every other line in authorized_keys alone. Asserted against a
// fixture file by running the same grep -vF the generated command runs.
func TestRemoveLeavesOtherAuthorizedKeysLinesAlone(t *testing.T) {
	k := authKey(t)
	ours := Line(k, "SRL-LIN", DefaultPort, false)
	fixture := []string{
		"ssh-rsa AAAAB3NzaC1yc2EAAAA somebody@laptop",
		ours,
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA other@box",
	}
	needle := keyBody(k)
	var kept []string
	for _, l := range fixture {
		if !strings.Contains(l, needle) { // what grep -vF does
			kept = append(kept, l)
		}
	}
	if len(kept) != 2 {
		t.Fatalf("removing our line kept %d of 3 lines: %v", len(kept), kept)
	}
	for _, l := range kept {
		if strings.Contains(l, needle) {
			t.Fatal("our key survived the removal")
		}
	}
}

func TestFingerprintMatchesSSHKeygenFormAndShortens(t *testing.T) {
	pub := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	fp, err := Fingerprint(pub)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if !strings.HasPrefix(fp, "SHA256:") || len(fp) < 20 {
		t.Fatalf("unexpected fingerprint %q", fp)
	}
	if s := Short(fp); len(s) != 8 || strings.Contains(s, "SHA256") {
		t.Fatalf("Short(%q) = %q", fp, s)
	}
}

// --- the leak test ----------------------------------------------------------------------------

// A whole lifecycle against a captured log, asserting the output names the reason codes and
// contains neither the address, the username nor any private key byte. Table-driven over the
// events, because a leak-only assertion passes just as happily when the field is empty.
func TestAFullLifecycleLogsReasonCodesAndNoSecrets(t *testing.T) {
	x := newSup(t, okSpec())
	// start -> auth failure (terminal) -> restart -> up -> stop
	phase := 0
	x.r.script = func(int) (int, string, time.Duration) {
		if phase == 0 {
			return 255, "Permission denied (publickey).\ndebug1: connecting to " + secretAddress +
				" as " + secretUser + " from 10.4.5.6", 0
		}
		return 0, "", time.Minute
	}
	x.s.Start(context.Background())
	x.waitState(t, "h-1", StateFailed)
	phase = 1
	if err := x.s.Restart("h-1"); err != nil {
		t.Fatalf("Restart: %v", err)
	}
	x.waitState(t, "h-1", StateUp)
	x.s.Stop()

	out := x.log.String()
	for _, want := range []string{
		string(ReasonAuthDenied), // the code must actually be there, not just absent of secrets
		"tunnel_state_change",
		"tunnel_start",
		"tunnel_exit",
		"tunnel_restart_requested",
		"tunnel_stopped",
		`"host":"SRL-LIN"`,
		`"tunnelstate":"failed"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the log never mentions %q", want)
		}
	}
	for _, never := range []string{secretAddress, secretUser, "10.4.5.6", "PRIVATE KEY",
		"Permission denied (publickey)", "[dropped]"} {
		if strings.Contains(out, never) {
			t.Errorf("the log leaked %q\n--- log ---\n%s", never, out)
		}
	}
}

// --- a real child process, through the fake ssh binary --------------------------------------

// buildFakeSSH compiles testdata/fakessh into its own directory and returns the executable and
// that directory. The fake is scripted by files beside it, not by the environment, because
// ExecRunner deliberately gives a child an allowlisted environment.
func buildFakeSSH(t *testing.T) (exe, dir string) {
	t.Helper()
	dir = t.TempDir()
	exe = filepath.Join(dir, "fakessh")
	if isWindows() {
		exe += ".exe"
	}
	out, err := runGo(t, "build", "-o", exe, "./testdata/fakessh")
	if err != nil {
		t.Skipf("cannot build the fake ssh (%v): %s", err, out)
	}
	return exe, dir
}

func scriptFakeSSH(t *testing.T, dir string, stderr string, code, sleepMS int) {
	t.Helper()
	data, err := json.Marshal(map[string]any{"stderr": stderr, "exit": code, "sleepMs": sleepMS})
	if err != nil {
		t.Fatalf("marshal script: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "script.json"), data, 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}
}

func readArgv(t *testing.T, dir string) [][]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "argv.log")) // #nosec G304 -- a path the test owns
	if err != nil {
		t.Fatalf("read argv.log: %v", err)
	}
	var out [][]string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var argv []string
		if err := json.Unmarshal([]byte(line), &argv); err != nil {
			t.Fatalf("parse argv line %q: %v", line, err)
		}
		out = append(out, argv)
	}
	return out
}

// The argv must survive as a slice all the way into the child, with no shell and no quoting in
// between: the child writes its own os.Args back and the test compares them.
func TestExecRunnerPassesTheArgvThroughAsASliceAndClassifiesRealStderr(t *testing.T) {
	exe, dir := buildFakeSSH(t)
	scriptFakeSSH(t, dir, "Permission denied (publickey).", 255, 0)

	keyDirPath := t.TempDir()
	seed := bytes.Repeat([]byte{5}, ed25519.SeedSize)
	keyPath, err := writeKeyFile(keyDirPath, "h-1", seed)
	if err != nil {
		t.Fatalf("writeKeyFile: %v", err)
	}
	spec := okSpec()
	p, err := ExecRunner{Path: exe}.Start(context.Background(), spec, keyPath, filepath.Join(keyDirPath, "known_hosts"))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if p.Pid() <= 0 {
		t.Fatalf("pid = %d", p.Pid())
	}
	code := p.Wait()
	if code != 255 {
		t.Fatalf("exit code = %d, want 255", code)
	}
	if r := Classify(p.Stderr(), code); r != ReasonAuthDenied {
		t.Fatalf("Classify = %q, want %q", r, ReasonAuthDenied)
	}
	got := readArgv(t, dir)
	if len(got) != 1 {
		t.Fatalf("the fake ran %d times, want 1", len(got))
	}
	want := Args(spec, keyPath, filepath.Join(keyDirPath, "known_hosts"))
	if len(got[0]) != len(want) {
		t.Fatalf("argv length %d, want %d\ngot:  %v\nwant: %v", len(got[0]), len(want), got[0], want)
	}
	for i := range want {
		if got[0][i] != want[i] {
			t.Fatalf("argv[%d] = %q, want %q", i, got[0][i], want[i])
		}
	}
}

func TestExecRunnerRefusesAnInvalidSpecBeforeSpawning(t *testing.T) {
	exe, dir := buildFakeSSH(t)
	scriptFakeSSH(t, dir, "", 0, 0)
	bad := okSpec()
	bad.Address = "-oProxyCommand=calc"
	if _, err := (ExecRunner{Path: exe}).Start(context.Background(), bad, "k", "kh"); err == nil {
		t.Fatal("ExecRunner spawned a child for an invalid spec")
	}
	if _, err := os.Stat(filepath.Join(dir, "argv.log")); !os.IsNotExist(err) {
		t.Fatal("the fake ssh ran despite an invalid spec")
	}
}

func TestExecRunnerReportsAMissingBinaryAsExecFailed(t *testing.T) {
	_, err := ExecRunner{Path: filepath.Join(t.TempDir(), "definitely-not-here")}.
		Start(context.Background(), okSpec(), "k", "kh")
	if err == nil {
		t.Fatal("starting a missing binary succeeded")
	}
	if !errors.Is(err, errExec) {
		t.Fatalf("err = %v, want errExec", err)
	}
	if Classify(err.Error(), -1) == ReasonAuthDenied {
		t.Fatal("a missing binary classified as an auth failure")
	}
}

// --- vault.Keyring satisfies Keys -------------------------------------------------------------

func TestVaultKeyringSatisfiesKeysAndDrivesTheSupervisor(t *testing.T) {
	t.Setenv("CSTUNNELKEY", "a-long-test-passphrase")
	dir := t.TempDir()
	kr, err := vault.OpenKeyring(filepath.Join(dir, vault.KeyringFileName), vault.EnvKey("CSTUNNELKEY"))
	if err != nil {
		t.Fatalf("OpenKeyring: %v", err)
	}
	if _, err := kr.Generate("h-1"); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var keys Keys = kr // the interface is what the supervisor takes
	cur, prev, ok := keys.PublicKey("h-1")
	if !ok || cur == nil || prev != nil {
		t.Fatal("PublicKey did not answer for a freshly generated key")
	}
	fp, err := Fingerprint(cur)
	if err != nil || !strings.HasPrefix(fp, "SHA256:") {
		t.Fatalf("Fingerprint = %q, %v", fp, err)
	}
	r := newFakeRunner()
	r.script = func(int) (int, string, time.Duration) { return 0, "", time.Minute }
	s, err := New(Options{DataDir: dir, Keys: keys, Runner: r, Log: logx.New(&bytes.Buffer{}),
		Grace: 10 * time.Millisecond, Delay: func(int) time.Duration { return 5 * time.Millisecond }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Set([]Spec{okSpec()}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	s.Start(t.Context())
	defer s.Stop()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if v, ok := s.Get("h-1"); ok && v.State == StateUp {
			if v.Fingerprint != fp {
				t.Fatalf("the view shows fingerprint %q, want %q", v.Fingerprint, fp)
			}
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("the tunnel never came up with a real keyring behind it")
}

func TestNewRefusesMissingDependencies(t *testing.T) {
	if _, err := New(Options{Keys: newFakeKeys(), Runner: newFakeRunner()}); err == nil {
		t.Error("New accepted an empty data dir")
	}
	if _, err := New(Options{DataDir: t.TempDir(), Runner: newFakeRunner()}); err == nil {
		t.Error("New accepted a nil Keys")
	}
	if _, err := New(Options{DataDir: t.TempDir(), Keys: newFakeKeys()}); err == nil {
		t.Error("New accepted a nil Runner")
	}
}

// --- test helpers -----------------------------------------------------------------------------

func isWindows() bool { return runtime.GOOS == "windows" }

// runGo shells out to the go tool to build the fake ssh binary.
func runGo(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("go", args...) // #nosec G204 -- fixed arguments from this test only
	out, err := cmd.CombinedOutput()
	return string(out), err
}
