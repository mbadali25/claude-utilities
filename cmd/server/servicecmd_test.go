package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"claude-utilities/internal/install"
	"claude-utilities/internal/service"
)

// TestMain pins every service seam to a fake for the WHOLE package, before any test runs.
//
// This is a hard rule and not a convenience: no test in this repository registers, starts, stops or
// deletes a real Windows service, runs icacls against a real path, writes to the event log or
// touches the firewall. Without this the default seams are the real ones, and `registeredDataDir`
// alone would make every `server run` test in this package query the live SCM - read-only, but
// host-dependent: a developer who happened to have the service installed would see the
// data-dir-mismatch warning appear in tests that assert there is none.
//
// The defaults here are "nothing registered" and "no ACL policy", which is exactly the behaviour
// every test in this package was written against. A test that wants a service installs its own
// fake.
func TestMain(m *testing.M) {
	newSCM = func() (scm, error) { return newFakeSCM(), nil }
	aclPolicy = func() ([]string, error) { return nil, nil }
	installEventSrc = func(string) error { return nil }
	removeEventSrc = func(string) error { return nil }
	runICacls = func([]string) ([]byte, error) { return nil, nil }
	runFirewall = func([]string) ([]byte, error) {
		panic("a test tried to change the firewall: the seam exists so that can never happen")
	}
	// The Linux counterpart: the real sync stats /etc/credstore and writes /etc/systemd/system, so a
	// migrate test on a root-run Linux box would otherwise install a drop-in on the developer's host.
	// The default is "nothing to write"; a test that wants a write uses stubDropInSync.
	kekDropInSync = func() (service.Rung, bool, error) { return 0, false, nil }
	os.Exit(m.Run())
}

// --- the fake service control manager ---

type fakeSvc struct {
	mu          *sync.Mutex
	cfg         serviceConfig
	recovery    []recoveryAction
	resetPeriod uint32
	onNonCrash  bool
	status      serviceStatus
	starts      int
	stops       int
	deleted     bool
	updates     int
	startErr    error
}

func (f *fakeSvc) Config() (serviceConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cfg, nil
}

func (f *fakeSvc) UpdateConfig(c serviceConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cfg = c
	f.updates++
	return nil
}

func (f *fakeSvc) SetRecovery(actions []recoveryAction, reset uint32, onNonCrash bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recovery = append([]recoveryAction(nil), actions...)
	f.resetPeriod = reset
	f.onNonCrash = onNonCrash
	return nil
}

func (f *fakeSvc) Start() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.startErr != nil {
		return f.startErr
	}
	f.starts++
	f.status.State = "start_pending"
	return nil
}

func (f *fakeSvc) Stop() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stops++
	f.status.State = "stopped"
	return nil
}

func (f *fakeSvc) Query() (serviceStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status, nil
}

func (f *fakeSvc) Delete() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = true
	return nil
}

func (f *fakeSvc) Close() error { return nil }

type fakeSCM struct {
	mu      sync.Mutex
	svcs    map[string]*fakeSvc
	creates int
}

func newFakeSCM() *fakeSCM { return &fakeSCM{svcs: map[string]*fakeSvc{}} }

func (f *fakeSCM) Open(name string) (scmService, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.svcs[name]
	if !ok || s.deleted {
		return nil, errServiceNotRegistered
	}
	return s, nil
}

func (f *fakeSCM) Create(name string, cfg serviceConfig) (scmService, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.svcs[name]; ok && !s.deleted {
		return nil, errServiceExists
	}
	f.creates++
	s := &fakeSvc{mu: &f.mu, cfg: cfg, status: serviceStatus{State: "stopped"}}
	f.svcs[name] = s
	return s, nil
}

func (f *fakeSCM) Close() error { return nil }

// registered returns the fake's view of the one service this product installs.
func (f *fakeSCM) registered() *fakeSvc {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.svcs[service.WindowsServiceName]
	if s == nil || s.deleted {
		return nil
	}
	return s
}

// useSCM points the seam at one fake for the duration of a test.
func useSCM(t *testing.T, f *fakeSCM) *fakeSCM {
	t.Helper()
	orig := newSCM
	t.Cleanup(func() { newSCM = orig })
	newSCM = func() (scm, error) { return f, nil }
	return f
}

// fakeExe points serviceExe at a plausible absolute path inside the test's own directory.
func fakeExe(t *testing.T, name string) string {
	t.Helper()
	exe := filepath.Join(t.TempDir(), name)
	orig := serviceExe
	t.Cleanup(func() { serviceExe = orig })
	serviceExe = func() (string, error) { return exe, nil }
	return exe
}

// capture runs serviceCmd and returns its code plus everything it printed.
func capture(t *testing.T, args []string, stdin string) (int, string) {
	t.Helper()
	var buf strings.Builder
	code := serviceCmd(args, strings.NewReader(stdin), &buf, &buf)
	return code, buf.String()
}

// --- the registration ---

// TestInstallConfigSetsVirtualAccountDelayedAutoAndUnrestrictedSID is the golden registration.
// Decision 2: the virtual account, automatic with the delay, and its own unrestricted SID so there
// is something to grant on the data dir. Never LocalSystem.
func TestInstallConfigSetsVirtualAccountDelayedAutoAndUnrestrictedSID(t *testing.T) {
	cfg := installServiceConfig(installOptions{Exe: `C:\bin\server.exe`, DataDir: `C:\data`, Listen: "10.0.0.5:8443"})
	if cfg.ServiceStartName != `NT SERVICE\ClaudeSwapServer` {
		t.Fatalf("the account is %q, want NT SERVICE\\ClaudeSwapServer", cfg.ServiceStartName)
	}
	if !cfg.DelayedAutoStart || !cfg.AutoStart {
		t.Fatalf("start type: auto=%v delayed=%v, want both true", cfg.AutoStart, cfg.DelayedAutoStart)
	}
	if !cfg.UnrestrictedSidType {
		t.Fatal("the service has no unrestricted SID type, so there is no service SID to grant")
	}
	lower := strings.ToLower(cfg.ServiceStartName)
	for _, forbidden := range []string{"localsystem", `nt authority\system`} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("the account is %q: LocalSystem is never the answer", cfg.ServiceStartName)
		}
	}
	if cfg.DisplayName == "" || cfg.Description == "" {
		t.Fatal("the registration has no display name or description for an operator to read in services.msc")
	}
}

// TestInstallBakesDataDirAndListenIntoTheCommandLine: Decision 10. The SCM is the single source of
// truth for both, and the command line names `run` rather than the bare flag form kept for scripts.
func TestInstallBakesDataDirAndListenIntoTheCommandLine(t *testing.T) {
	o := installOptions{
		Exe: `C:\bin\server.exe`, DataDir: `C:\ProgramData\claude-swap-server`, Listen: "10.0.0.5:8443",
		Tunnels: true, RefreshTokens: true, RefreshAccounts: "a,b", StaleAfter: 6 * time.Hour,
	}
	got := o.commandLine()
	for _, want := range []string{"run", "--listen", "10.0.0.5:8443", "--data-dir",
		`C:\ProgramData\claude-swap-server`, "--tunnels", "--refresh-tokens", "--refresh-accounts", "a,b",
		"--stale-after", "6h0m0s"} {
		if !strings.Contains(got, want) {
			t.Fatalf("the command line %q does not carry %q", got, want)
		}
	}
	if dir, ok := dataDirFromCommandLine(got); !ok || dir != o.DataDir {
		t.Fatalf("the baked data dir reads back as %q/%v, want %q", dir, ok, o.DataDir)
	}
	// The flags that are OFF must not appear at all: a baked --tunnels nobody asked for would put a
	// second tunnel supervisor against every host.
	off := installOptions{Exe: `C:\bin\server.exe`, DataDir: `C:\d`, Listen: "127.0.0.1:1"}.commandLine()
	for _, absent := range []string{"--tunnels", "--refresh-tokens", "--refresh-accounts", "--stale-after"} {
		if strings.Contains(off, absent) {
			t.Fatalf("the default command line %q carries %q", off, absent)
		}
	}
}

// TestBakedCommandLineRoundTripsSpacesAndUnicode: a Windows path with a space in it is the normal
// case, and an unquoted one becomes two arguments - the service would then start with a truncated
// data dir and quietly create a second vault.
func TestBakedCommandLineRoundTripsSpacesAndUnicode(t *testing.T) {
	cases := []string{
		`C:\Program Files\Claude Swap\server.exe`,
		`C:\Données\clé\server.exe`,
		`C:\path with trailing slash\`,
		`C:\quote"inside\server.exe`,
		`C:\日本語\サーバー.exe`,
	}
	for _, dir := range cases {
		line := installOptions{Exe: `C:\bin\server.exe`, DataDir: dir, Listen: "127.0.0.1:8443"}.commandLine()
		got, ok := dataDirFromCommandLine(line)
		if !ok {
			t.Fatalf("%q: the baked command line %q has no readable --data-dir", dir, line)
		}
		if got != dir {
			t.Fatalf("%q round-tripped as %q through %q", dir, got, line)
		}
	}
	// And the exe survives the same trip, because CreateService needs it apart from its arguments.
	line := installOptions{Exe: cases[0], DataDir: `C:\d`, Listen: "127.0.0.1:1"}.commandLine()
	if got := splitCommandLine(line); len(got) == 0 || got[0] != cases[0] {
		t.Fatalf("the exe round-tripped as %q, want %q", got, cases[0])
	}
}

// TestInstallRecoveryChainIsFiveThirtyThenNone is revision 8 item 13. SERVICE_FAILURE_ACTIONS
// repeats the LAST action for every failure past the end of the array, so a third entry of "restart
// after 60 s" would be a one-minute restart loop for a fatal cause, for the whole reset period.
func TestInstallRecoveryChainIsFiveThirtyThenNone(t *testing.T) {
	got := serverRecoveryActions()
	want := []recoveryAction{
		{Kind: recoveryRestart, Delay: 5 * time.Second},
		{Kind: recoveryRestart, Delay: 30 * time.Second},
		{Kind: recoveryNone},
	}
	if len(got) != len(want) {
		t.Fatalf("the chain has %d actions, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("action %d is %+v, want %+v", i, got[i], want[i])
		}
	}
	if got[len(got)-1].Kind != recoveryNone {
		t.Fatal("the last action is not terminal: the SCM would repeat it for every later failure")
	}
	if recoveryResetPeriodSeconds != 86400 {
		t.Fatalf("the reset period is %d, want 86400", recoveryResetPeriodSeconds)
	}
}

// TestTheRecoveryChainIsConsistentWithTheNonRestartingCodes: the chain and the exit table are two
// halves of one rule. The SCM has no per-exit-code exemption, so the terminal third action bounds
// the chain and the marker is what refuses the retry - and the marker only refuses the codes the
// table holds. A code added to the table with no marker behind it, or a chain that never ends,
// breaks the rule from one side or the other.
func TestTheRecoveryChainIsConsistentWithTheNonRestartingCodes(t *testing.T) {
	codes := service.ServerTable().NonRestarting()
	want := []int{2, 3, 4, 5}
	if len(codes) != len(want) {
		t.Fatalf("the non-restarting codes are %v, want %v", codes, want)
	}
	for i := range want {
		if codes[i] != want[i] {
			t.Fatalf("the non-restarting codes are %v, want %v", codes, want)
		}
	}
	for _, c := range []int{0, 1} {
		if service.ServerTable().IsNonRestarting(c) {
			t.Fatalf("exit %d is in the non-restarting set; the recovery chain exists to retry it", c)
		}
	}
	restarts := 0
	for _, a := range serverRecoveryActions() {
		if a.Kind == recoveryRestart {
			restarts++
		}
	}
	if restarts == 0 {
		t.Fatal("the chain never restarts, so exit 1 would never be retried")
	}
}

// --- install ---

func TestInstallRegistersGrantsAndPrintsTheFirewallLineWithoutRunningIt(t *testing.T) {
	f := useSCM(t, newFakeSCM())
	fakeExe(t, "server.exe")
	dataDir := t.TempDir()

	var icacls [][]string
	origIcacls, origEvent := runICacls, installEventSrc
	t.Cleanup(func() { runICacls, installEventSrc = origIcacls, origEvent })
	runICacls = func(args []string) ([]byte, error) { icacls = append(icacls, args); return nil, nil }
	var sources []string
	installEventSrc = func(src string) error { sources = append(sources, src); return nil }

	code, out := capture(t, []string{"install", "--listen", "10.0.0.5:8443", "--data-dir", dataDir}, "")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if f.creates != 1 {
		t.Fatalf("%d services created, want one: %s", f.creates, out)
	}

	// The event source, which is the only place an operator can read why a service never started.
	if len(sources) != 1 || sources[0] != service.EventSourceName {
		t.Fatalf("event sources %v, want exactly %q", sources, service.EventSourceName)
	}

	// The grant: both principals, inheritable, /T so icacls visits the tree (files already there get the per-file pass), and the
	// inheritance removal that makes it the only access. icacls takes account NAMES; the credfile
	// policy takes SIDs, and crossing them is a silent failure.
	if len(icacls) != 1 {
		t.Fatalf("%d icacls runs, want one: %v", len(icacls), icacls)
	}
	args := strings.Join(icacls[0], " ")
	for _, want := range []string{dataDir, "/inheritance:r", service.WindowsServiceAccount + ":(OI)(CI)F",
		service.AdministratorsAccount + ":(OI)(CI)F", "/T"} {
		if !strings.Contains(args, want) {
			t.Fatalf("the icacls arguments %q do not carry %q", args, want)
		}
	}
	if strings.Contains(args, "*"+service.WindowsServiceAccount) {
		t.Fatalf("the icacls grant carries the SID form of an account name: %q", args)
	}
	// And it is exactly what the shared builder produces, so the two callers cannot drift.
	shared := install.IcaclsLockdownArgs(dataDir, service.WindowsServiceAccount, service.AdministratorsAccount)
	if strings.Join(shared, " ") != args {
		t.Fatalf("install built %q, the shared builder builds %q", args, strings.Join(shared, " "))
	}

	// The firewall line is printed and NOT run: runFirewall panics if it is reached.
	if !strings.Contains(out, "firewall rule NOT created") {
		t.Fatalf("the install does not say the firewall rule was not created: %s", out)
	}
	if !strings.Contains(out, "netsh advfirewall firewall add rule") || !strings.Contains(out, "localport=8443") {
		t.Fatalf("the install does not print a pasteable firewall line for the listen port: %s", out)
	}
}

// TestInstallSetsTheRecoveryChainOnTheService: the chain has to reach the SCM, not just exist as a
// function. The mutation this catches is an install that registers the service and never calls
// SetRecovery, which leaves the SCM's default (no recovery at all).
func TestInstallSetsTheRecoveryChainOnTheService(t *testing.T) {
	f := useSCM(t, newFakeSCM())
	fakeExe(t, "server.exe")
	code, out := capture(t, []string{"install", "--listen", "127.0.0.1:8443", "--data-dir", t.TempDir()}, "")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	s := f.registered()
	if s == nil {
		t.Fatal("nothing was registered")
	}
	if len(s.recovery) != 3 || s.recovery[2].Kind != recoveryNone {
		t.Fatalf("the recovery chain on the service is %+v", s.recovery)
	}
	if s.resetPeriod != recoveryResetPeriodSeconds {
		t.Fatalf("the reset period is %d, want %d", s.resetPeriod, recoveryResetPeriodSeconds)
	}
	if !s.onNonCrash {
		t.Fatal("non-crash failures are not included, so a non-zero exit would not trigger recovery at all")
	}
	if s.cfg.ServiceStartName != service.WindowsServiceAccount {
		t.Fatalf("the registered account is %q", s.cfg.ServiceStartName)
	}
}

// TestInstallIsIdempotent: an installer calls this on every upgrade, so a second run updates the
// registration rather than failing - and it must not create a second service.
func TestInstallIsIdempotent(t *testing.T) {
	f := useSCM(t, newFakeSCM())
	fakeExe(t, "server.exe")
	dir := t.TempDir()
	args := []string{"install", "--listen", "127.0.0.1:8443", "--data-dir", dir}
	if code, out := capture(t, args, ""); code != 0 {
		t.Fatalf("first install exit %d: %s", code, out)
	}
	code, out := capture(t, append(args, "--tunnels"), "")
	if code != 0 {
		t.Fatalf("second install exit %d: %s", code, out)
	}
	if f.creates != 1 {
		t.Fatalf("%d services created across two installs, want one", f.creates)
	}
	if !strings.Contains(out, "already registered") {
		t.Fatalf("the second install does not say it updated an existing registration: %s", out)
	}
	s := f.registered()
	if s == nil || !strings.Contains(s.cfg.BinaryPathName, "--tunnels") {
		t.Fatalf("the second install did not update the command line: %+v", s)
	}
	if s.updates == 0 {
		t.Fatal("UpdateConfig was never called, so the registration kept the first install's flags")
	}
}

// TestConcurrentInstallIsOneService: two installers at once - an upgrade script and an operator -
// must leave one registration. Whichever CreateService loses the race re-opens the winner's service
// and updates it, so neither exits non-zero and there is never a half-configured second attempt.
func TestConcurrentInstallIsOneService(t *testing.T) {
	f := useSCM(t, newFakeSCM())
	fakeExe(t, "server.exe")
	dir := t.TempDir()

	var wg sync.WaitGroup
	codes := make([]int, 4)
	outs := make([]string, 4)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var buf strings.Builder
			codes[i] = serviceCmd([]string{"install", "--listen", "127.0.0.1:8443", "--data-dir", dir},
				strings.NewReader(""), &buf, &buf)
			outs[i] = buf.String()
		}(i)
	}
	wg.Wait()
	for i, c := range codes {
		if c != 0 {
			t.Fatalf("install %d exit %d: %s", i, c, outs[i])
		}
	}
	if f.creates != 1 {
		t.Fatalf("%d services created by four concurrent installs, want one", f.creates)
	}
	if f.registered() == nil {
		t.Fatal("no service is registered after four concurrent installs")
	}
}

// TestInstallPrintsTheFingerprintBeforeAndAfterAndRefusesIfItDiffers: an install changes a
// registration and some ACLs, never the TLS pair. The sha256 every enrolled agent pins must be the
// same number afterwards, and exit 5 is "certificate refused" - the non-restarting code.
func TestInstallPrintsTheFingerprintBeforeAndAfterAndRefusesIfItDiffers(t *testing.T) {
	useSCM(t, newFakeSCM())
	fakeExe(t, "server.exe")
	orig := certFingerprintOf
	t.Cleanup(func() { certFingerprintOf = orig })

	reads := 0
	certFingerprintOf = func(string) (string, error) {
		reads++
		if reads == 1 {
			return "aaaa1111", nil
		}
		return "bbbb2222", nil
	}
	code, out := capture(t, []string{"install", "--listen", "127.0.0.1:8443", "--data-dir", t.TempDir()}, "")
	if code != exitCertRefused {
		t.Fatalf("exit %d, want %d (certificate refused): %s", code, exitCertRefused, out)
	}
	for _, want := range []string{"aaaa1111", "bbbb2222", "REFUSED", "pins"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the refusal does not mention %q: %s", want, out)
		}
	}
	if strings.Contains(out, "start it with") {
		t.Fatalf("the install told the operator to start it after refusing: %s", out)
	}

	// Stable across the install is the normal case, and it is reported both times.
	certFingerprintOf = func(string) (string, error) { return "cccc3333", nil }
	code, out = capture(t, []string{"install", "--listen", "127.0.0.1:8443", "--data-dir", t.TempDir()}, "")
	if code != 0 {
		t.Fatalf("exit %d with a stable fingerprint: %s", code, out)
	}
	if strings.Count(out, "cccc3333") != 2 {
		t.Fatalf("the fingerprint is not reported before AND after: %s", out)
	}

	// No pair yet is not a mismatch: nothing is pinned before the first run.
	certFingerprintOf = func(string) (string, error) { return "", errors.New("no certificate") }
	code, out = capture(t, []string{"install", "--listen", "127.0.0.1:8443", "--data-dir", t.TempDir()}, "")
	if code != 0 {
		t.Fatalf("exit %d with no certificate yet: %s", code, out)
	}
	if strings.Contains(out, "sha256=") {
		t.Fatalf("a fingerprint was printed with no pair: %s", out)
	}
}

// TestInstallReappliesTheACLPolicyAfterRegistering: before CreateService the service does not
// exist, so its SID cannot resolve and the policy this process started with is Administrators-only.
// Writing with that policy from here on would strip the service from every file it then touched, so
// the policy has to be re-resolved once the service is real.
func TestInstallReappliesTheACLPolicyAfterRegistering(t *testing.T) {
	scm := newFakeSCM()
	useSCM(t, scm)
	fakeExe(t, "server.exe")
	origPolicy, origSet := aclPolicy, setACLPolicy
	t.Cleanup(func() { aclPolicy, setACLPolicy = origPolicy, origSet })

	// Like the real resolver: the service SID exists only once the service is registered.
	aclPolicy = func() ([]string, error) {
		if scm.registered() == nil {
			return []string{service.AdministratorsSID}, nil
		}
		return []string{service.AdministratorsSID, "S-1-5-80-9"}, nil
	}
	var applied [][]string
	setACLPolicy = func(sids ...string) error {
		applied = append(applied, append([]string(nil), sids...))
		return nil
	}
	code, out := capture(t, []string{"install", "--listen", "127.0.0.1:8443", "--data-dir", t.TempDir()}, "")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if len(applied) != 1 {
		t.Fatalf("the policy was applied %d times inside install, want once (after the registration): %v",
			len(applied), applied)
	}
	if len(applied[0]) != 2 {
		t.Fatalf("the re-applied policy is %v; it must carry the service SID as well as Administrators",
			applied[0])
	}
	if !strings.Contains(out, "ACL policy now names") {
		t.Fatalf("the install does not say the policy gained the service: %s", out)
	}
}

// TestInstallNarrowsWhenTheServiceSIDWillNotResolveAfterRegistering is G17 on the install path
// (Matthew, 2026-11-10): the service is registered but its SID will not resolve, so the install
// finishes with the narrower policy (Administrators only), says so, and never widens.
func TestInstallNarrowsWhenTheServiceSIDWillNotResolveAfterRegistering(t *testing.T) {
	useSCM(t, newFakeSCM())
	fakeExe(t, "server.exe")
	origPolicy, origSet := aclPolicy, setACLPolicy
	t.Cleanup(func() { aclPolicy, setACLPolicy = origPolicy, origSet })

	aclPolicy = func() ([]string, error) {
		return []string{service.AdministratorsSID}, fmt.Errorf("%w: lookup failed", service.ErrACLPolicyNarrowed)
	}
	var applied [][]string
	setACLPolicy = func(sids ...string) error {
		applied = append(applied, append([]string(nil), sids...))
		return nil
	}

	code, out := capture(t, []string{"install", "--listen", "127.0.0.1:8443", "--data-dir", t.TempDir()}, "")
	if code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out)
	}
	if len(applied) != 1 || len(applied[0]) != 1 || applied[0][0] != service.AdministratorsSID {
		t.Fatalf("applied %v, want exactly the Administrators SID once", applied)
	}
	if !strings.Contains(out, "narrowed") || !strings.Contains(out, "acl-policy-narrowed") {
		t.Fatalf("the operator is not told the policy was narrowed, with its reason: %s", out)
	}
}

// TestResolveServicePolicyNarrowsAndOnlyFailsOnOtherErrors is the service-start half of G17: a
// narrowing applies the Administrators-only policy and reports narrowed=true with no error; a
// different resolver error stops the start with exit 2; a rejected grant stops it with exit 1.
func TestResolveServicePolicyNarrowsAndOnlyFailsOnOtherErrors(t *testing.T) {
	origPolicy, origSet := aclPolicy, setACLPolicy
	t.Cleanup(func() { aclPolicy, setACLPolicy = origPolicy, origSet })
	var applied [][]string
	setACLPolicy = func(sids ...string) error {
		applied = append(applied, append([]string(nil), sids...))
		return nil
	}

	aclPolicy = func() ([]string, error) {
		return []string{service.AdministratorsSID}, fmt.Errorf("%w: lookup failed", service.ErrACLPolicyNarrowed)
	}
	narrowed, code, reason, err := resolveServicePolicy()
	if err != nil || !narrowed || code != 0 || reason != "" {
		t.Fatalf("narrowing: narrowed=%v code=%d reason=%q err=%v", narrowed, code, reason, err)
	}
	if len(applied) != 1 || len(applied[0]) != 1 || applied[0][0] != service.AdministratorsSID {
		t.Fatalf("applied %v, want the Administrators SID once", applied)
	}

	aclPolicy = func() ([]string, error) { return nil, errors.New("boom") }
	applied = nil
	narrowed, code, reason, err = resolveServicePolicy()
	if err == nil || narrowed || code != exitUsage || reason != "acl-policy-failed" || len(applied) != 0 {
		t.Fatalf("other error: narrowed=%v code=%d reason=%q err=%v applied=%v", narrowed, code, reason, err, applied)
	}

	aclPolicy = func() ([]string, error) { return []string{service.AdministratorsSID}, nil }
	setACLPolicy = func(...string) error { return errors.New("icacls said no") }
	_, code, reason, err = resolveServicePolicy()
	if err == nil || code != exitRuntime || reason != "acl-policy-rejected" {
		t.Fatalf("rejected grant: code=%d reason=%q err=%v", code, reason, err)
	}
}

// TestApplyACLPolicyNarrowsInsteadOfRefusing: the entry point applies the narrowed policy, logs the
// reason and exits 0 for a writing command; a read-only command applies nothing.
func TestApplyACLPolicyNarrowsInsteadOfRefusing(t *testing.T) {
	origPolicy, origSet := aclPolicy, setACLPolicy
	t.Cleanup(func() { aclPolicy, setACLPolicy = origPolicy, origSet })
	aclPolicy = func() ([]string, error) {
		return []string{service.AdministratorsSID}, fmt.Errorf("%w: lookup failed", service.ErrACLPolicyNarrowed)
	}
	applied := 0
	setACLPolicy = func(...string) error { applied++; return nil }

	var errOut bytes.Buffer
	if code := applyACLPolicy([]string{"init"}, &errOut); code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, errOut.String())
	}
	if applied != 1 {
		t.Fatalf("applied %d times, want 1", applied)
	}
	if !strings.Contains(errOut.String(), "acl-policy-narrowed") || strings.Contains(errOut.String(), "service not registered") {
		t.Fatalf("output %q: want the narrowed reason and not the not-registered hint", errOut.String())
	}

	applied = 0
	errOut.Reset()
	if code := applyACLPolicy([]string{"service", "status"}, &errOut); code != 0 || applied != 0 {
		t.Fatalf("read-only: exit %d, applied %d, want 0 and 0", code, applied)
	}

	aclPolicy = func() ([]string, error) { return nil, errors.New("boom") }
	if code := applyACLPolicy([]string{"init"}, &errOut); code != exitUsage {
		t.Fatalf("a non-narrowing error exited %d, want %d", code, exitUsage)
	}
}

// TestInstallRequiresListen: it is baked into the command line, so there is no default to guess.
func TestInstallRequiresListen(t *testing.T) {
	useSCM(t, newFakeSCM())
	fakeExe(t, "server.exe")
	code, out := capture(t, []string{"install", "--data-dir", t.TempDir()}, "")
	if code != exitUsage {
		t.Fatalf("exit %d, want %d: %s", code, exitUsage, out)
	}
	if !strings.Contains(out, "--listen") {
		t.Fatalf("the refusal does not name the missing flag: %s", out)
	}
	code, out = capture(t, []string{"install", "--listen", "8443", "--data-dir", t.TempDir()}, "")
	if code != exitUsage {
		t.Fatalf("a bare port exits %d, want %d: %s", code, exitUsage, out)
	}
}

// --- start, stop, status ---

// TestStartDeletesTheMarkerFirst: an operator asking for a start after a fix always gets one. The
// deletion is unconditional and it happens BEFORE the start, so the handler cannot read a marker
// the operator has already answered for.
func TestStartDeletesTheMarkerFirst(t *testing.T) {
	f := useSCM(t, newFakeSCM())
	dir := t.TempDir()
	if _, err := f.Create(service.WindowsServiceName, serviceConfig{
		BinaryPathName: `"C:\bin\server.exe" run --listen 127.0.0.1:8443 --data-dir ` + quoteArg(dir),
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	logDir := serviceLogDir(dir)
	if err := service.WriteMarker(logDir, service.Marker{
		Exit: 3, Reason: "vault-locked", TS: time.Now(), Boot: service.BootInstant(),
	}); err != nil {
		t.Fatalf("WriteMarker: %v", err)
	}

	code, out := capture(t, []string{"start"}, "")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if _, ok := service.ReadMarker(logDir); ok {
		t.Fatal("the marker survived `service start`; the next start would refuse")
	}
	s := f.registered()
	if s == nil || s.starts != 1 {
		t.Fatalf("the service was started %v times", s)
	}
}

// TestStartOnAnUnregisteredServiceSaysSo rather than reporting a nil-pointer or a bare errno.
func TestStartOnAnUnregisteredServiceSaysSo(t *testing.T) {
	useSCM(t, newFakeSCM())
	code, out := capture(t, []string{"start", "--data-dir", t.TempDir()}, "")
	if code != exitUsage {
		t.Fatalf("exit %d, want %d: %s", code, exitUsage, out)
	}
	if !strings.Contains(out, "server service install") {
		t.Fatalf("the refusal does not name the command that fixes it: %s", out)
	}
}

// TestStatusReportsStateTheLastExitAndTheBakedCommandLine. There is deliberately no version line
// and no /healthz probe: this binary carries no version string and serves no /healthz route, so
// printing either would be a claim `status` cannot see.
func TestStatusReportsStateTheLastExitAndTheBakedCommandLine(t *testing.T) {
	f := useSCM(t, newFakeSCM())
	dir := t.TempDir()
	cmdline := `"C:\bin\server.exe" run --listen 10.0.0.5:8443 --data-dir ` + quoteArg(dir)
	h, err := f.Create(service.WindowsServiceName, serviceConfig{
		BinaryPathName: cmdline, ServiceStartName: service.WindowsServiceAccount,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	fs, ok := h.(*fakeSvc)
	if !ok {
		t.Fatalf("Create returned %T", h)
	}
	fs.status = serviceStatus{State: "stopped", Win32ExitCode: 1066, ServiceSpecificExitCode: 3}
	if err := service.WriteMarker(serviceLogDir(dir), service.Marker{
		Exit: 3, Reason: "vault-locked", TS: time.Now(), Boot: service.BootInstant(),
	}); err != nil {
		t.Fatalf("WriteMarker: %v", err)
	}

	code, out := capture(t, []string{"status"}, "")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	for _, want := range []string{"state stopped", cmdline, service.WindowsServiceAccount,
		"last exit 3", "vault locked", "last fatal exit=3 reason=vault-locked", "a restart cannot fix"} {
		if !strings.Contains(out, want) {
			t.Fatalf("status does not report %q: %s", want, out)
		}
	}
	if strings.Contains(out, "1066") {
		t.Fatalf("status printed the win32 code instead of the service-specific one: %s", out)
	}
}

// TestStatusOnAnUnregisteredServiceIsNotAnError: an operator asking "is it installed" gets an
// answer and exit 0, with the hint. It is also the one command that still works when the ACL policy
// cannot be resolved, which is why it must never need the SCM to succeed.
func TestStatusOnAnUnregisteredServiceIsNotAnError(t *testing.T) {
	useSCM(t, newFakeSCM())
	code, out := capture(t, []string{"status", "--data-dir", t.TempDir()}, "")
	if code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out)
	}
	for _, want := range []string{"is not registered", "server service install", "no last-fatal marker"} {
		if !strings.Contains(out, want) {
			t.Fatalf("status does not report %q: %s", want, out)
		}
	}
}

// --- uninstall and purge ---

// TestUninstallLeavesTheDataDirAndPrintsItsPath: the service and the event source go, the vault
// stays, and the path is printed because an operator who wanted it gone needs to know where it is.
func TestUninstallLeavesTheDataDirAndPrintsItsPath(t *testing.T) {
	f := useSCM(t, newFakeSCM())
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "vault.bin"), []byte("CSV2"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := f.Create(service.WindowsServiceName, serviceConfig{BinaryPathName: `"x" run --data-dir ` + quoteArg(dir)}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	var removed []string
	orig := removeEventSrc
	t.Cleanup(func() { removeEventSrc = orig })
	removeEventSrc = func(src string) error { removed = append(removed, src); return nil }

	code, out := capture(t, []string{"uninstall"}, "")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if f.registered() != nil {
		t.Fatal("the service is still registered")
	}
	if len(removed) != 1 || removed[0] != service.EventSourceName {
		t.Fatalf("event sources removed: %v", removed)
	}
	if _, err := os.Stat(filepath.Join(dir, "vault.bin")); err != nil {
		t.Fatalf("uninstall deleted the vault without --purge: %v", err)
	}
	if !strings.Contains(out, "KEPT") {
		t.Fatalf("uninstall does not say the data dir was kept: %s", out)
	}
}

// TestUninstallOnAnUnregisteredServiceStillTidiesUp: an uninstall after a failed install must not
// stop at "no such service" and leave the event source behind.
func TestUninstallOnAnUnregisteredServiceStillTidiesUp(t *testing.T) {
	useSCM(t, newFakeSCM())
	removed := 0
	orig := removeEventSrc
	t.Cleanup(func() { removeEventSrc = orig })
	removeEventSrc = func(string) error { removed++; return nil }
	code, out := capture(t, []string{"uninstall", "--data-dir", t.TempDir()}, "")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if removed != 1 {
		t.Fatalf("the event source was removed %d times", removed)
	}
	if !strings.Contains(out, "not registered") {
		t.Fatalf("uninstall does not say there was nothing to delete: %s", out)
	}
}

// TestUninstallPurgeKeepsTLSAndWarns is revision 8 item 9, decided by Matthew 2026-11-07.
// server-cert.pem is the identity every enrolled agent pins: `--purge` deleting it would de-enrol
// the fleet through a flag whose name promises only tidiness.
func TestUninstallPurgeKeepsTLSAndWarns(t *testing.T) {
	useSCM(t, newFakeSCM())
	dir := seedDataDir(t)
	code, out := capture(t, []string{"uninstall", "--data-dir", dir, "--purge"}, purgeWord+"\n")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "vault.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the vault survived --purge: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, tlsDirName, "server-cert.pem")); err != nil {
		t.Fatalf("--purge deleted tls/, which de-enrols every agent: %v", err)
	}
	for _, want := range []string{"kept", "de-enrol", "--purge-tls"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the purge does not warn about %q: %s", want, out)
		}
	}
}

// TestUninstallPurgeTLSNeedsTheSecondConfirmation: one typed word deletes the vault; deleting the
// pin needs a second one, and refusing it leaves EVERYTHING in place rather than half the dir.
func TestUninstallPurgeTLSNeedsTheSecondConfirmation(t *testing.T) {
	useSCM(t, newFakeSCM())
	dir := seedDataDir(t)
	code, out := capture(t, []string{"uninstall", "--data-dir", dir, "--purge", "--purge-tls"},
		purgeWord+"\nno thanks\n")
	if code != exitUsage {
		t.Fatalf("exit %d, want %d: %s", code, exitUsage, out)
	}
	for _, name := range []string{"vault.bin", filepath.Join(tlsDirName, "server-cert.pem")} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s was deleted after the second confirmation was refused: %v", name, err)
		}
	}
	if !strings.Contains(out, "nothing at all was deleted") {
		t.Fatalf("the refusal does not say nothing was deleted: %s", out)
	}

	// Both words typed: everything goes, and the output says the fleet must re-enrol.
	code, out = capture(t, []string{"uninstall", "--data-dir", dir, "--purge", "--purge-tls"},
		purgeWord+"\n"+purgeTLSWord+"\n")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the data dir survived --purge --purge-tls: %v", err)
	}
	if !strings.Contains(out, "re-enrol") {
		t.Fatalf("the full purge does not say every agent must re-enrol: %s", out)
	}
}

// TestUninstallPurgeNotConfirmedDeletesNothing: the typed word is the whole control, and a flag is
// never enough on its own.
func TestUninstallPurgeNotConfirmedDeletesNothing(t *testing.T) {
	useSCM(t, newFakeSCM())
	dir := seedDataDir(t)
	code, out := capture(t, []string{"uninstall", "--data-dir", dir, "--purge"}, "yes\n")
	if code != exitUsage {
		t.Fatalf("exit %d, want %d: %s", code, exitUsage, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "vault.bin")); err != nil {
		t.Fatalf("the vault was deleted without the typed word: %v", err)
	}
	// And the prompt names the host count, so the operator knows the size of what they are doing.
	code, out = capture(t, []string{"uninstall", "--data-dir", dir, "--purge", "--purge-tls"}, purgeWord+"\n\n")
	if code != exitUsage {
		t.Fatalf("exit %d, want %d: %s", code, exitUsage, out)
	}
	if !strings.Contains(out, "2 host entries") {
		t.Fatalf("the tls/ prompt does not name the host count: %s", out)
	}
}

// TestPurgeTLSWithoutPurgeIsRefused: on its own it would delete the pin and keep the vault, which
// is the worst of both.
func TestPurgeTLSWithoutPurgeIsRefused(t *testing.T) {
	useSCM(t, newFakeSCM())
	dir := seedDataDir(t)
	code, out := capture(t, []string{"uninstall", "--data-dir", dir, "--purge-tls"}, purgeTLSWord+"\n")
	if code != exitUsage {
		t.Fatalf("exit %d, want %d: %s", code, exitUsage, out)
	}
	if _, err := os.Stat(filepath.Join(dir, tlsDirName, "server-cert.pem")); err != nil {
		t.Fatalf("tls/ was deleted by --purge-tls alone: %v", err)
	}
	if !strings.Contains(out, "needs --purge") {
		t.Fatalf("the refusal does not say why: %s", out)
	}
}

// seedDataDir writes a data dir that looks like a real one: a vault, a backup, a host list with two
// hosts, a logs directory and a TLS pair. It is always a t.TempDir() - no test ever points a purge
// at a path outside its own temporary directory.
func seedDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"vault.bin", "vault.bin.bak", "admin-password.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "hosts.json"),
		[]byte(`[{"hostId":"a"},{"hostId":"b"}]`), 0o600); err != nil {
		t.Fatalf("seed hosts.json: %v", err)
	}
	for _, sub := range []string{"logs", tlsDirName} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatalf("seed %s: %v", sub, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, tlsDirName, "server-cert.pem"), []byte("pem"), 0o600); err != nil {
		t.Fatalf("seed the pair: %v", err)
	}
	return dir
}

// --- the data dir the SCM holds, and the policy funnel ---

// TestServiceRegisteredDataDirReadsTheBakedFlag is Decision 10's single source of truth, and the
// carry-over this slice closes: registeredDataDir answered "none" until something read the SCM.
func TestServiceRegisteredDataDirReadsTheBakedFlag(t *testing.T) {
	f := useSCM(t, newFakeSCM())
	if got, ok := serviceRegisteredDataDir(); ok {
		t.Fatalf("an unregistered service answered %q", got)
	}
	want := `C:\Program Files\claude swap\data`
	if _, err := f.Create(service.WindowsServiceName, serviceConfig{
		BinaryPathName: `"C:\bin\server.exe" run --listen 10.0.0.5:8443 --data-dir ` + quoteArg(want),
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, ok := serviceRegisteredDataDir()
	if !ok || got != want {
		t.Fatalf("the registered data dir reads as %q/%v, want %q", got, ok, want)
	}
	// main.go's seam is this function, so the console run's warning now has something to compare.
	if registeredDataDir == nil {
		t.Fatal("registeredDataDir is nil")
	}
}

// TestFlagValueReadsBothSpellings: the baked command line is written by this code, but a hand-edited
// registration can use either form, and reading the wrong one would silently fall back to the
// profile default - a second vault nobody meant to have.
func TestFlagValueReadsBothSpellings(t *testing.T) {
	cases := []struct {
		args []string
		want string
		ok   bool
	}{
		{[]string{"run", "--data-dir", `C:\a`}, `C:\a`, true},
		{[]string{"run", "--data-dir=C:\\a"}, `C:\a`, true},
		{[]string{"run", "-data-dir", `C:\a`}, `C:\a`, true},
		{[]string{"run", "-data-dir=C:\\a"}, `C:\a`, true},
		{[]string{"run", "--listen", "x"}, "", false},
		{[]string{"run", "--data-dir"}, "", false},
	}
	for _, c := range cases {
		got, ok := flagValue(c.args, "data-dir")
		if got != c.want || ok != c.ok {
			t.Fatalf("flagValue(%v) = %q/%v, want %q/%v", c.args, got, ok, c.want, c.ok)
		}
	}
}

// TestReadOnlyInvocationKeepsTheDiagnosticsReachable: the commands that explain a G17 narrowing
// write nothing and must apply no policy. The mutation this catches is a mutator sneaking into the exempt set.
func TestReadOnlyInvocationKeepsTheDiagnosticsReachable(t *testing.T) {
	readOnly := [][]string{
		nil, {"--help"}, {"-h"},
		{"service", "status"}, {"vault", "status"}, {"vault", "verify"}, {"vault"}, {"service"},
	}
	for _, args := range readOnly {
		if !readOnlyInvocation(args) {
			t.Fatalf("%v is treated as a writer; the refusal would take away a diagnostic", args)
		}
	}
	writers := [][]string{
		{"run", "--listen", "127.0.0.1:1"}, {"--listen", "127.0.0.1:1"},
		{"service", "install"}, {"service", "uninstall"}, {"service", "start"}, {"service", "stop"},
		{"vault", "init"}, {"vault", "migrate"}, {"vault", "rotate"}, {"vault", "add-slot"},
		{"vault", "remove-slot"}, {"vault", "change-passphrase"}, {"cert", "renew"}, {"set-password"},
	}
	for _, args := range writers {
		if readOnlyInvocation(args) {
			t.Fatalf("%v is exempt from the ACL refusal, but it writes", args)
		}
	}
}

// TestOpNameIsTheSubcommandOrRun: the `op` on the refusal's log line.
func TestOpNameIsTheSubcommandOrRun(t *testing.T) {
	cases := map[string][]string{
		"run":     {"--listen", "127.0.0.1:1"},
		"vault":   {"vault", "status"},
		"service": {"service", "install"},
	}
	for want, args := range cases {
		if got := opName(args); got != want {
			t.Fatalf("opName(%v) = %q, want %q", args, got, want)
		}
	}
	if got := opName(nil); got != "run" {
		t.Fatalf("opName(nil) = %q, want run", got)
	}
}

// TestServiceCmdOnNonWindowsSaysSo: a clear sentence rather than a nil-pointer dereference. The
// real seams are used here, not the fakes, because what is being tested is the default.
func TestServiceCmdOnNonWindowsSaysSo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this is the other build's behaviour")
	}
	orig := newSCM
	t.Cleanup(func() { newSCM = orig })
	newSCM = platformNewSCM

	for _, args := range [][]string{
		{"install", "--listen", "127.0.0.1:8443", "--data-dir", t.TempDir()},
		{"start"}, {"stop"}, {"status"},
	} {
		code, out := capture(t, args, "")
		if code == 0 {
			t.Fatalf("`service %v` succeeded off windows: %s", args[0], out)
		}
		if !strings.Contains(out, "not supported on this OS") {
			t.Fatalf("`service %v` does not say it is unsupported: %s", args[0], out)
		}
	}
	if _, ok := runAsWindowsService(); ok {
		t.Fatal("runAsWindowsService claims this process is a Windows service")
	}
}

// TestServiceUsageIsPrintedWithNoSubcommand, and an unknown one is named rather than guessed.
func TestServiceUsageIsPrintedWithNoSubcommand(t *testing.T) {
	code, out := capture(t, nil, "")
	if code != exitUsage {
		t.Fatalf("exit %d, want %d", code, exitUsage)
	}
	for _, want := range []string{"install", "uninstall", "start", "stop", "status"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the usage does not list %q: %s", want, out)
		}
	}
	code, out = capture(t, []string{"reinstall"}, "")
	if code != exitUsage {
		t.Fatalf("exit %d, want %d", code, exitUsage)
	}
	if !strings.Contains(out, `"reinstall"`) {
		t.Fatalf("the refusal does not name the unknown subcommand: %s", out)
	}
}

// TestServiceLogDirIsTheLogsSubdirectory: the marker and the log file share a directory, and it is
// `<data-dir>\logs`. Reading the data dir instead would look one level above the file the handler
// wrote, and the refusal would silently never fire.
func TestServiceLogDirIsTheLogsSubdirectory(t *testing.T) {
	if got, want := serviceLogDir(`C:\d`), filepath.Join(`C:\d`, "logs"); got != want {
		t.Fatalf("serviceLogDir = %q, want %q", got, want)
	}
}
