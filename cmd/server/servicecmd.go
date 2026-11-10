package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"claude-utilities/internal/credfile"
	"claude-utilities/internal/hub"
	"claude-utilities/internal/install"
	"claude-utilities/internal/logx"
	"claude-utilities/internal/service"
)

// This file is the portable half of `server service`. Everything that decides something lives here
// - the configuration the service is registered with, the recovery chain, the baked command line
// and its quoting, the install/uninstall/start/stop/status flow and the purge rules - behind a
// small service-control seam that servicecmd_windows.go implements against the SCM and
// servicecmd_other.go refuses.
//
// The split is not tidiness. The gate builds and vets for linux as well as windows and runs the
// unix tests in WSL, so logic whose only test is Windows-only is logic two legs of the gate never
// exercise. Keeping the decisions here means the recovery chain, the golden configuration, the
// quoting, the idempotent and concurrent installs and every purge rule are tested on both.

// serviceUsage is the `service` command summary.
const serviceUsage = `usage: server service install|uninstall|start|stop|status [flags]
  install    register the Windows service, set its recovery chain, register the event source and
             grant the data dir to the service account and Administrators. --listen is required and
             is baked into the service command line, with --data-dir, so the SCM is the one source
             of truth for both. It prints the firewall line and does NOT run it unless --firewall.
  uninstall  stop and delete the service, remove the event source, and LEAVE the data dir, printing
             where it is. --purge deletes the data dir after a typed confirmation but keeps tls/;
             --purge --purge-tls removes tls/ too, behind a second typed confirmation, because that
             re-pins the server and de-enrols every agent.
  start      delete the last-fatal marker, then start the service. An operator asking for a start
             after a fix always gets one.
  stop       stop the service and wait for the drain.
  status     the registered state, the last exit code, the baked command line and the marker.`

// purgeWord and purgeTLSWord are typed to confirm a purge. Flags alone are never enough: one of
// these deletes a vault and the other de-enrols the fleet.
const (
	purgeWord    = "purge"
	purgeTLSWord = "de-enrol"
)

// recoveryResetPeriodSeconds is the SCM's failure-count reset period: 24 h. It governs only how the
// SCM counts failures and is deliberately decoupled from the marker's ten-minute window.
const recoveryResetPeriodSeconds = 86400

// tlsDirName is the one directory `--purge` keeps.
const tlsDirName = "tls"

// errServiceNotRegistered is "there is no such service", which is an answer rather than a problem:
// it is the normal state before the first install and what `status` reports.
var errServiceNotRegistered = errors.New("no " + service.WindowsServiceName + " service is registered")

// errServiceExists is CreateService losing a race with another install.
var errServiceExists = errors.New("the " + service.WindowsServiceName + " service already exists")

// serviceConfig is the portable view of the registration. It carries only the fields this product
// sets; servicecmd_windows.go maps it onto mgr.Config.
type serviceConfig struct {
	// BinaryPathName is the full command line, exe included and quoted.
	BinaryPathName string
	DisplayName    string
	Description    string
	// ServiceStartName is the account. It is the virtual account, never LocalSystem (Decision 2).
	ServiceStartName string
	// AutoStart and DelayedAutoStart are "Automatic (Delayed Start)".
	AutoStart        bool
	DelayedAutoStart bool
	// UnrestrictedSidType asks for SERVICE_SID_TYPE_UNRESTRICTED, so the service has its own SID to
	// grant on the data dir. INFERENCE from the spec, to confirm on the first host run: the virtual
	// account is assumed to require a service SID. If it does not work there, the named fallback is
	// `NT AUTHORITY\LocalService` - never LocalSystem.
	UnrestrictedSidType bool
}

// recoveryKind is one entry of the SCM's failure-action chain.
type recoveryKind int

const (
	// recoveryRestart restarts the service after the delay.
	recoveryRestart recoveryKind = iota
	// recoveryNone is SC_ACTION_NONE: no action, deliberately terminal.
	recoveryNone
)

// recoveryAction is one failure action and its delay.
type recoveryAction struct {
	Kind  recoveryKind
	Delay time.Duration
}

// serviceStatus is the portable view of a query.
type serviceStatus struct {
	// State is the SCM's state, lower case: "running", "stopped", "start_pending", ...
	State string
	// Win32ExitCode is 1066 (ERROR_SERVICE_SPECIFIC_ERROR) when the service reported its own code.
	Win32ExitCode uint32
	// ServiceSpecificExitCode is the server's exit code, which is the number an operator needs.
	ServiceSpecificExitCode uint32
	ProcessID               uint32
}

// scmService is one registered service.
type scmService interface {
	Config() (serviceConfig, error)
	UpdateConfig(serviceConfig) error
	SetRecovery(actions []recoveryAction, resetPeriodSeconds uint32, onNonCrashFailures bool) error
	Start() error
	Stop() error
	Query() (serviceStatus, error)
	Delete() error
	Close() error
}

// scm is the service control manager.
type scm interface {
	// Open returns errServiceNotRegistered when there is no such service.
	Open(name string) (scmService, error)
	// Create returns errServiceExists when another process registered it first.
	Create(name string, cfg serviceConfig) (scmService, error)
	Close() error
}

// The seams. Every one of them is a variable so no test in this package ever registers, starts,
// stops or deletes a real service, runs icacls against a real path, writes to the event log or
// touches the firewall.
var (
	newSCM          = platformNewSCM
	installEventSrc = platformInstallEventSource
	removeEventSrc  = platformRemoveEventSource
	runICacls       = platformRunICacls
	runFirewall     = platformRunFirewall
	serviceExe      = os.Executable
	aclPolicy       = service.ACLPolicy
	setACLPolicy    = credfile.SetACLPolicy
	// certFingerprintOf is the read-only fingerprint reader `install` compares before and after.
	// It is the same reader `vault migrate` uses, behind a seam so a test can make the two readings
	// disagree without writing a certificate.
	certFingerprintOf = certFingerprint
)

// serverRecoveryActions is the SCM failure-action chain: restart after 5 s, restart after 30 s,
// then NOTHING.
//
// The third action is terminal on purpose (revision 8). SERVICE_FAILURE_ACTIONS repeats the LAST
// action in the array for every failure past the end of it, so a third entry of "restart after
// 60 s" would be a one-minute restart loop for a fatal cause, for the whole 86400 s reset period.
// SC_ACTION_NONE ends the chain and leaves the service stopped with its last exit code readable.
//
// This is the Windows half of the same rule the exit table states: codes 2-5 are the ones a restart
// cannot fix. The SCM has no per-exit-code exemption, so the terminal action bounds the chain and
// the last-fatal marker is what actually refuses the retry.
func serverRecoveryActions() []recoveryAction {
	return []recoveryAction{
		{Kind: recoveryRestart, Delay: 5 * time.Second},
		{Kind: recoveryRestart, Delay: 30 * time.Second},
		{Kind: recoveryNone},
	}
}

// installOptions is everything baked into the service command line. Config a service needs is baked
// at install, as install-agent.sh bakes the agent's state dir; there is no config file in v1.
type installOptions struct {
	Exe             string
	DataDir         string
	Listen          string
	Tunnels         bool
	RefreshTokens   bool
	RefreshAccounts string
	StaleAfter      time.Duration
	Firewall        bool
}

// commandLine renders the baked command line: the exe, `run`, and the flags the service needs.
// `run` is explicit rather than the bare flag form, so what the SCM holds is the documented entry
// point and not the spelling kept for old scripts.
func (o installOptions) commandLine() string {
	parts := []string{quoteArg(o.Exe), "run", "--listen", quoteArg(o.Listen), "--data-dir", quoteArg(o.DataDir)}
	if o.Tunnels {
		parts = append(parts, "--tunnels")
	}
	if o.RefreshTokens {
		parts = append(parts, "--refresh-tokens")
		if o.RefreshAccounts != "" {
			parts = append(parts, "--refresh-accounts", quoteArg(o.RefreshAccounts))
		}
	}
	if o.StaleAfter > 0 {
		parts = append(parts, "--stale-after", o.StaleAfter.String())
	}
	return strings.Join(parts, " ")
}

// installServiceConfig is the golden registration. The account is the virtual account, the start
// type is automatic with the delay, and the service gets its own unrestricted SID so there is
// something to grant on the data dir.
func installServiceConfig(o installOptions) serviceConfig {
	return serviceConfig{
		BinaryPathName:      o.commandLine(),
		DisplayName:         "Claude Swap server",
		Description:         "Serves the Claude Swap hub and admin UI over TLS on the LAN.",
		ServiceStartName:    service.WindowsServiceAccount,
		AutoStart:           true,
		DelayedAutoStart:    true,
		UnrestrictedSidType: true,
	}
}

// quoteArg renders s as one argument of a Windows command line, the way CommandLineToArgvW reads
// it back: wrapped in quotes when it holds a space, a tab or a quote, with the backslashes that
// precede a quote doubled and the quote escaped. Unicode needs nothing special - the command line
// is UTF-16 and a non-ASCII path is just characters - but a path with a space in it is the normal
// case on Windows (`C:\Program Files\...`) and an unquoted one becomes two arguments.
func quoteArg(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for _, r := range s {
		switch r {
		case '\\':
			slashes++
			b.WriteRune(r)
		case '"':
			// Every backslash run immediately before a quote is doubled, then the quote is escaped.
			b.WriteString(strings.Repeat(`\`, slashes))
			slashes = 0
			b.WriteString(`\"`)
		default:
			slashes = 0
			b.WriteRune(r)
		}
	}
	// A trailing backslash run would escape the closing quote, so it is doubled too.
	b.WriteString(strings.Repeat(`\`, slashes))
	b.WriteByte('"')
	return b.String()
}

// splitCommandLine tokenises a Windows command line the way CommandLineToArgvW does, which is how a
// baked `--data-dir "C:\Program Files\x"` is read back out of the registration. It is the inverse
// of quoteArg and the round trip is pinned by a test.
func splitCommandLine(s string) []string {
	var args []string
	var cur strings.Builder
	inQuotes, started := false, false
	slashes := 0

	flushSlashes := func(n int) { cur.WriteString(strings.Repeat(`\`, n)) }
	for _, r := range s {
		switch {
		case r == '\\':
			slashes++
			started = true
		case r == '"':
			flushSlashes(slashes / 2)
			if slashes%2 == 1 {
				cur.WriteByte('"') // escaped quote
			} else {
				inQuotes = !inQuotes
			}
			slashes = 0
			started = true
		case !inQuotes && (r == ' ' || r == '\t'):
			flushSlashes(slashes)
			slashes = 0
			if started {
				args = append(args, cur.String())
				cur.Reset()
				started = false
			}
		default:
			flushSlashes(slashes)
			slashes = 0
			cur.WriteRune(r)
			started = true
		}
	}
	flushSlashes(slashes)
	if started {
		args = append(args, cur.String())
	}
	return args
}

// dataDirFromCommandLine reads the baked `--data-dir` out of a registered service's command line.
// Decision 10: the SCM is the single source of truth for the data dir, so this is what a `service`
// or `vault` command resolves when the flag is absent, and what a console run compares itself
// against before warning.
func dataDirFromCommandLine(cmdline string) (string, bool) {
	return flagValue(splitCommandLine(cmdline), "data-dir")
}

// flagValue reads one flag out of an argument list, in both spellings Go's flag package accepts
// (`--name value`, `--name=value`) and with either one or two leading dashes.
func flagValue(args []string, name string) (string, bool) {
	for i, a := range args {
		for _, prefix := range []string{"--" + name, "-" + name} {
			if a == prefix {
				if i+1 < len(args) {
					return args[i+1], true
				}
				return "", false
			}
			if strings.HasPrefix(a, prefix+"=") {
				return strings.TrimPrefix(a, prefix+"="), true
			}
		}
	}
	return "", false
}

// serviceRegisteredDataDir is main.go's registeredDataDir: the data dir the registered service was
// installed with, read from the SCM. It opens the service read-only and closes it again; an
// unregistered service, or an OS with no SCM, answers "no".
func serviceRegisteredDataDir() (string, bool) {
	m, err := newSCM()
	if err != nil {
		return "", false
	}
	defer func() { _ = m.Close() }()
	s, err := m.Open(service.WindowsServiceName)
	if err != nil {
		return "", false
	}
	defer func() { _ = s.Close() }()
	cfg, err := s.Config()
	if err != nil {
		return "", false
	}
	return dataDirFromCommandLine(cfg.BinaryPathName)
}

// serviceCmd dispatches `server service <subcommand>`. It is reached from run's fixed subcommand
// name set, so it never sees the console run's flags.
func serviceCmd(args []string, in io.Reader, out, errOut io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(errOut, serviceUsage)
		return exitUsage
	}
	switch args[0] {
	case "install":
		return serviceInstallCmd(args[1:], out, errOut)
	case "uninstall":
		return serviceUninstallCmd(args[1:], in, out, errOut)
	case "start":
		return serviceStartCmd(args[1:], out, errOut)
	case "stop":
		return serviceStopCmd(args[1:], out, errOut)
	case "status":
		return serviceStatusCmd(args[1:], out, errOut)
	default:
		_, _ = fmt.Fprintf(errOut, "service: unknown subcommand %q\n", args[0])
		_, _ = fmt.Fprintln(errOut, serviceUsage)
		return exitUsage
	}
}

// serviceInstallCmd registers the service, sets its recovery chain, registers the event source and
// re-grants the data dir. It is idempotent: a second run updates the registration rather than
// failing, which is what makes it safe for an installer to call on every upgrade.
func serviceInstallCmd(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("service install", flag.ContinueOnError)
	fs.SetOutput(errOut)
	dataDir := fs.String("data-dir", defaultServiceDataDir(), "directory for the vault, host list, TLS pair and admin password hash")
	listen := fs.String("listen", "", "host:port the service listens on (required, no default)")
	tunnels := fs.Bool("tunnels", false, "supervise the reverse SSH tunnels")
	refreshTokens := fs.Bool("refresh-tokens", false, "refresh expired logins of the accounts named in --refresh-accounts")
	refreshAccounts := fs.String("refresh-accounts", "", "comma-separated account ids --refresh-tokens may refresh")
	staleAfter := fs.Duration("stale-after", hub.DefaultStaleAfter, "flag a stored login older than this")
	firewall := fs.Bool("firewall", false, "create the inbound firewall rule as well as printing it")
	if err := fs.Parse(args); err != nil {
		_, _ = fmt.Fprintln(errOut, serviceUsage)
		return exitUsage
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintf(errOut, "service install: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}
	if *listen == "" {
		_, _ = fmt.Fprintln(errOut, "service install: --listen host:port is required; it is baked into the "+
			"service command line, so there is no default to guess")
		return exitUsage
	}
	if _, _, err := net.SplitHostPort(*listen); err != nil {
		_, _ = fmt.Fprintln(errOut, "service install: --listen must be host:port")
		return exitUsage
	}
	exe, err := serviceExe()
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "service install:", logx.Redact(err.Error()))
		return exitRuntime
	}
	abs, err := filepath.Abs(*dataDir)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "service install:", logx.Redact(err.Error()))
		return exitRuntime
	}
	opts := installOptions{
		Exe: exe, DataDir: abs, Listen: *listen, Tunnels: *tunnels,
		RefreshTokens: *refreshTokens, RefreshAccounts: *refreshAccounts,
		StaleAfter: *staleAfter, Firewall: *firewall,
	}

	// The fingerprint before and after. An install changes ACLs and a registration, never the TLS
	// pair: the sha256 every enrolled agent pins must be the same number afterwards, and an install
	// that changed it would de-enrol the fleet without saying so. An absent pair is not a mismatch -
	// there is nothing pinned yet.
	before, beforeOK := readCertFingerprint(abs)
	if beforeOK {
		_, _ = fmt.Fprintf(out, "service install: certificate sha256=%s (before)\n", before)
	}

	m, err := newSCM()
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "service install:", logx.Redact(err.Error()))
		return exitUsage
	}
	defer func() { _ = m.Close() }()

	cfg := installServiceConfig(opts)
	svcHandle, created, err := createOrUpdate(m, cfg)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "service install:", logx.Redact(err.Error()))
		return exitRuntime
	}
	defer func() { _ = svcHandle.Close() }()
	if created {
		_, _ = fmt.Fprintf(out, "service install: registered %s as %s, automatic with a delayed start\n",
			service.WindowsServiceName, service.WindowsServiceAccount)
	} else {
		_, _ = fmt.Fprintf(out, "service install: %s was already registered; its configuration was updated\n",
			service.WindowsServiceName)
	}

	if err := svcHandle.SetRecovery(serverRecoveryActions(), recoveryResetPeriodSeconds, true); err != nil {
		_, _ = fmt.Fprintln(errOut, "service install:", logx.Redact(err.Error()))
		return exitRuntime
	}
	_, _ = fmt.Fprintf(out, "service install: recovery restart after 5s, restart after 30s, then no action "+
		"(failure count resets after %ds); non-crash failures included\n", recoveryResetPeriodSeconds)

	if err := installEventSrc(service.EventSourceName); err != nil {
		_, _ = fmt.Fprintln(errOut, "service install:", logx.Redact(err.Error()))
		return exitRuntime
	}
	_, _ = fmt.Fprintf(out, "service install: event source %s registered in the Application log\n", service.EventSourceName)

	// The policy is re-resolved AFTER the registration: before it the service did not exist, so its
	// SID could not resolve and the policy this process started with is Administrators-only. Writing
	// with that policy from here on would strip the service from every file it then touched.
	if code := reapplyACLPolicy(out, errOut); code != 0 {
		_, _ = fmt.Fprintln(errOut, "service install: the service is registered but the data dir was not "+
			"granted to it; run `server service uninstall` to remove it, fix the cause above, then install again")
		return code
	}

	// icacls takes account NAMES, where the credfile policy takes SIDs. The (OI)(CI) terms are
	// inheritable, so they land on the directories (the data dir and tls/) and on files created from
	// now on. They do NOT land on files that already exist: icacls visits those under /T but applies
	// container-only flags to directories alone. The per-file pass below covers them.
	icacls := install.IcaclsLockdownArgs(abs, service.WindowsServiceAccount, service.AdministratorsAccount)
	if out2, err := runICacls(icacls); err != nil {
		_, _ = fmt.Fprintln(errOut, "service install: icacls:", logx.Redact(err.Error()))
		if len(out2) > 0 {
			_, _ = fmt.Fprintln(errOut, "service install: icacls said:", logx.Redact(string(out2)))
		}
		return exitRuntime
	}
	_, _ = fmt.Fprintf(out, "service install: granted %s and %s full control of %s, inheritable, so files "+
		"created from now on carry it\n", service.WindowsServiceAccount, service.AdministratorsAccount,
		logx.TildePath(abs))

	// Files written before the service existed (admin-password.json, vault.bin, tunnelkeys.bin) hold
	// an explicit DACL with inheritance removed, so the grant above never reached them. Re-apply the
	// process policy to each one: owner plus the policy SIDs reapplyACLPolicy installed, nothing
	// wider (RestrictFile grants the current user, which on an elevated install is the installer),
	// so a narrowed policy (G17) never widens a file. It also never removes a service ACE an earlier
	// install granted; `server service uninstall` is the way to take that back.
	n, err := restrictExistingFiles(abs)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "service install:", logx.Redact(err.Error()))
		_, _ = fmt.Fprintln(errOut, "service install: the service is registered but a file in the data dir "+
			"was not granted to it; close whatever holds that file open, then run `server service install` again")
		return exitRuntime
	}
	_, _ = fmt.Fprintf(out, "service install: re-applied the ACL policy to %d files already in %s\n", n,
		logx.TildePath(abs))

	after, afterOK := readCertFingerprint(abs)
	if afterOK {
		_, _ = fmt.Fprintf(out, "service install: certificate sha256=%s (after)\n", after)
	}
	if beforeOK && afterOK && before != after {
		_, _ = fmt.Fprintf(errOut, "service install: REFUSED the certificate fingerprint changed during the "+
			"install (before %s, after %s): every enrolled agent pins the old one, so nothing was started. "+
			"Investigate before running `server service start`.\n", before, after)
		return exitCertRefused
	}

	_, _ = fmt.Fprintln(out, "service install: firewall rule NOT created. If the LAN needs one, run:")
	_, _ = fmt.Fprintln(out, "service install:   "+strings.Join(firewallCommand(*listen), " "))
	if *firewall {
		if out2, err := runFirewall(firewallArgs(*listen)); err != nil {
			_, _ = fmt.Fprintln(errOut, "service install: the firewall rule failed:", logx.Redact(err.Error()))
			if len(out2) > 0 {
				_, _ = fmt.Fprintln(errOut, "service install: netsh said:", logx.Redact(string(out2)))
			}
			return exitRuntime
		}
		_, _ = fmt.Fprintln(out, "service install: firewall rule created (--firewall was given)")
	}
	_, _ = fmt.Fprintln(out, "service install: start it with `server service start`")
	return 0
}

// createOrUpdate registers the service, or updates the registration when it is already there.
// Two installs at once are one service: whichever Create loses the race gets errServiceExists,
// re-opens the winner's service and updates it, so the loser still exits 0 with one registration
// standing rather than a half-configured second attempt.
func createOrUpdate(m scm, cfg serviceConfig) (scmService, bool, error) {
	if s, err := m.Open(service.WindowsServiceName); err == nil {
		if err := s.UpdateConfig(cfg); err != nil {
			_ = s.Close()
			return nil, false, err
		}
		return s, false, nil
	} else if !errors.Is(err, errServiceNotRegistered) {
		return nil, false, err
	}
	s, err := m.Create(service.WindowsServiceName, cfg)
	if err == nil {
		return s, true, nil
	}
	if !errors.Is(err, errServiceExists) {
		return nil, false, err
	}
	s, err = m.Open(service.WindowsServiceName)
	if err != nil {
		return nil, false, err
	}
	if err := s.UpdateConfig(cfg); err != nil {
		_ = s.Close()
		return nil, false, err
	}
	return s, false, nil
}

// serviceUninstallCmd stops and deletes the service, removes the event source and leaves the data
// dir unless --purge.
func serviceUninstallCmd(args []string, in io.Reader, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("service uninstall", flag.ContinueOnError)
	fs.SetOutput(errOut)
	dataDir := fs.String("data-dir", "", "the data dir to report, and to purge with --purge (default: the registered one)")
	purge := fs.Bool("purge", false, "delete the data dir after a typed confirmation, keeping tls/")
	purgeTLS := fs.Bool("purge-tls", false, "with --purge, also delete tls/: this re-pins the server and de-enrols every agent")
	if err := fs.Parse(args); err != nil {
		_, _ = fmt.Fprintln(errOut, serviceUsage)
		return exitUsage
	}
	if *purgeTLS && !*purge {
		_, _ = fmt.Fprintln(errOut, "service uninstall: --purge-tls needs --purge; on its own it would delete "+
			"the pin and keep the vault")
		return exitUsage
	}
	dir := *dataDir
	if dir == "" {
		if registered, ok := serviceRegisteredDataDir(); ok {
			dir = registered
		} else {
			dir = defaultServiceDataDir()
		}
	}

	m, err := newSCM()
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "service uninstall:", logx.Redact(err.Error()))
		return exitUsage
	}
	defer func() { _ = m.Close() }()

	switch s, err := m.Open(service.WindowsServiceName); {
	case errors.Is(err, errServiceNotRegistered):
		_, _ = fmt.Fprintf(out, "service uninstall: %s was not registered; nothing to delete\n",
			service.WindowsServiceName)
	case err != nil:
		_, _ = fmt.Fprintln(errOut, "service uninstall:", logx.Redact(err.Error()))
		return exitRuntime
	default:
		// A stop failure is not fatal here: a service that is already stopped, or stuck, must not
		// block the delete an operator asked for.
		if err := s.Stop(); err != nil {
			_, _ = fmt.Fprintln(out, "service uninstall: the stop did not succeed; deleting anyway:",
				logx.Redact(err.Error()))
		}
		if err := s.Delete(); err != nil {
			_ = s.Close()
			_, _ = fmt.Fprintln(errOut, "service uninstall:", logx.Redact(err.Error()))
			return exitRuntime
		}
		_ = s.Close()
		_, _ = fmt.Fprintf(out, "service uninstall: deleted %s\n", service.WindowsServiceName)
	}

	if err := removeEventSrc(service.EventSourceName); err != nil {
		_, _ = fmt.Fprintln(out, "service uninstall: the event source was not removed:", logx.Redact(err.Error()))
	} else {
		_, _ = fmt.Fprintf(out, "service uninstall: event source %s removed\n", service.EventSourceName)
	}

	if !*purge {
		_, _ = fmt.Fprintf(out, "service uninstall: the data dir is KEPT at %s (the vault, the host list, the "+
			"admin password hash and tls/). Delete it with `--purge` if that is what you want.\n",
			logx.TildePath(dir))
		return 0
	}
	return purgeCmd(dir, *purgeTLS, in, out, errOut)
}

// purgeCmd deletes the data dir behind a typed confirmation, and tls/ behind a second one.
//
// tls/ is kept by default (revision 8 item 9, decided by Matthew 2026-11-07): server-cert.pem is
// the identity every enrolled agent pins, so deleting it de-enrols the whole fleet - an anti-goal
// reached through a flag whose name promises only tidiness.
func purgeCmd(dir string, purgeTLS bool, in io.Reader, out, errOut io.Writer) int {
	if in == nil {
		in = strings.NewReader("")
	}
	// ONE buffered reader for both prompts. A second bufio.Reader over the same stream would find
	// nothing left to read: the first one buffers ahead, so it would already have swallowed the
	// second typed word and `--purge --purge-tls` would refuse a confirmation the operator gave.
	prompts := bufio.NewReader(io.LimitReader(in, 2*maxConfirmLine))
	if !confirmTyped(prompts, out, purgeWord, fmt.Sprintf("This DELETES the data dir at %s: the vault, its backups, "+
		"the host list and the admin password hash. There is no undo. Type %s to continue: ",
		logx.TildePath(dir), purgeWord)) {
		_, _ = fmt.Fprintln(errOut, "service uninstall: not confirmed; nothing in the data dir was deleted")
		return exitUsage
	}
	if purgeTLS {
		if !confirmTyped(prompts, out, purgeTLSWord, fmt.Sprintf("--purge-tls also deletes tls/. "+
			"server-cert.pem is the sha256 EVERY enrolled agent pins: deleting it re-pins this server and "+
			"de-enrols the whole fleet, which must then re-enrol by hand%s. Type %s to continue: ",
			enrolledHostNote(dir), purgeTLSWord)) {
			_, _ = fmt.Fprintln(errOut, "service uninstall: tls/ was not confirmed; nothing at all was deleted")
			return exitUsage
		}
	}
	kept, err := purgeDataDir(dir, purgeTLS)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "service uninstall:", logx.Redact(err.Error()))
		return exitRuntime
	}
	if len(kept) > 0 {
		_, _ = fmt.Fprintf(out, "service uninstall: purged %s, kept %s — deleting it re-pins the server and "+
			"de-enrols every agent; use `--purge --purge-tls` if that is what you want\n",
			logx.TildePath(dir), strings.Join(kept, ", "))
		return 0
	}
	_, _ = fmt.Fprintf(out, "service uninstall: purged %s, tls/ included: every agent must re-enrol against "+
		"the new fingerprint\n", logx.TildePath(dir))
	return 0
}

// purgeDataDir removes everything in dir, keeping tls/ unless purgeTLS. It returns what it kept.
// The directory itself is removed only when nothing was kept, so a kept tls/ still has a home.
func purgeDataDir(dir string, purgeTLS bool) (kept []string, err error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !purgeTLS && e.IsDir() && strings.EqualFold(e.Name(), tlsDirName) {
			kept = append(kept, tlsDirName+string(os.PathSeparator))
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return kept, err
		}
	}
	sort.Strings(kept)
	if len(kept) == 0 {
		if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
			return kept, err
		}
	}
	return kept, nil
}

// enrolledHostNote names how many hosts are about to be de-enrolled, when hosts.json can still be
// counted. It is a count, never a host name.
func enrolledHostNote(dir string) string {
	b, err := os.ReadFile(filepath.Clean(filepath.Join(dir, "hosts.json")))
	if err != nil {
		return ""
	}
	n := strings.Count(string(b), `"hostId"`)
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(" (%d host entries are in hosts.json)", n)
}

// serviceStartCmd deletes the marker and starts the service. The deletion is first and
// unconditional: an operator asking for a start after a fix always gets one, which is the whole
// difference between this and an automatic start.
func serviceStartCmd(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("service start", flag.ContinueOnError)
	fs.SetOutput(errOut)
	dataDir := fs.String("data-dir", "", "the data dir whose marker is cleared (default: the registered one)")
	if err := fs.Parse(args); err != nil {
		_, _ = fmt.Fprintln(errOut, serviceUsage)
		return exitUsage
	}
	dir := resolveDataDir(*dataDir)
	if err := service.DeleteMarker(serviceLogDir(dir)); err != nil {
		_, _ = fmt.Fprintln(errOut, "service start: the last-fatal marker could not be deleted:",
			logx.Redact(err.Error()))
		return exitRuntime
	}
	m, s, code := openRegistered("service start", errOut)
	if code != 0 {
		return code
	}
	defer func() { _ = s.Close(); _ = m.Close() }()
	if err := s.Start(); err != nil {
		_, _ = fmt.Fprintln(errOut, "service start:", logx.Redact(err.Error()))
		return exitRuntime
	}
	_, _ = fmt.Fprintf(out, "service start: %s starting; `server service status` reports when it is running\n",
		service.WindowsServiceName)
	return 0
}

// serviceStopCmd stops the service and waits for the drain.
func serviceStopCmd(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("service stop", flag.ContinueOnError)
	fs.SetOutput(errOut)
	if err := fs.Parse(args); err != nil {
		_, _ = fmt.Fprintln(errOut, serviceUsage)
		return exitUsage
	}
	m, s, code := openRegistered("service stop", errOut)
	if code != 0 {
		return code
	}
	defer func() { _ = s.Close(); _ = m.Close() }()
	if err := s.Stop(); err != nil {
		_, _ = fmt.Fprintln(errOut, "service stop:", logx.Redact(err.Error()))
		return exitRuntime
	}
	_, _ = fmt.Fprintf(out, "service stop: %s stopped\n", service.WindowsServiceName)
	return 0
}

// serviceStatusCmd reports the registered state, the last exit code with the table's meaning, the
// baked command line, the data dir and the marker.
//
// There is no version line and no /healthz probe here. The binary has a version string (stamped at
// release, shown by `server --version`), but this command does not print it: it reports what the
// SCM and the files show, not the running process. There is no /healthz route yet either, so
// printing either would be a claim this command cannot see.
func serviceStatusCmd(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("service status", flag.ContinueOnError)
	fs.SetOutput(errOut)
	dataDir := fs.String("data-dir", "", "the data dir whose marker is read (default: the registered one)")
	if err := fs.Parse(args); err != nil {
		_, _ = fmt.Fprintln(errOut, serviceUsage)
		return exitUsage
	}
	m, err := newSCM()
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "service status:", logx.Redact(err.Error()))
		return exitUsage
	}
	defer func() { _ = m.Close() }()

	dir := *dataDir
	s, openErr := m.Open(service.WindowsServiceName)
	if openErr == nil {
		defer func() { _ = s.Close() }()
		if cfg, err := s.Config(); err == nil {
			_, _ = fmt.Fprintf(out, "service status: command line %s\n", cfg.BinaryPathName)
			_, _ = fmt.Fprintf(out, "service status: account %s\n", cfg.ServiceStartName)
			if baked, ok := dataDirFromCommandLine(cfg.BinaryPathName); ok && dir == "" {
				dir = baked
			}
		}
		if st, err := s.Query(); err == nil {
			_, _ = fmt.Fprintf(out, "service status: state %s\n", st.State)
			reportExit(out, st)
		}
	} else if errors.Is(openErr, errServiceNotRegistered) {
		_, _ = fmt.Fprintf(out, "service status: %s is not registered\n", service.WindowsServiceName)
		_, _ = fmt.Fprintln(out, "service status: "+service.NotRegisteredHint)
	} else {
		_, _ = fmt.Fprintln(errOut, "service status:", logx.Redact(openErr.Error()))
		return exitRuntime
	}

	dir = resolveDataDir(dir)
	_, _ = fmt.Fprintf(out, "service status: data dir %s\n", logx.TildePath(dir))
	if mk, ok := service.ReadMarker(serviceLogDir(dir)); ok {
		_, _ = fmt.Fprintf(out, "service status: last fatal exit=%d reason=%s at %s\n",
			mk.Exit, mk.Reason, mk.TS.Format(time.RFC3339))
	} else {
		_, _ = fmt.Fprintln(out, "service status: no last-fatal marker")
	}
	return 0
}

// reportExit prints the exit code the SCM recorded, with this binary's meaning for it. 1066 is
// ERROR_SERVICE_SPECIFIC_ERROR: the number that matters is then the service-specific one.
func reportExit(out io.Writer, st serviceStatus) {
	code := int(st.Win32ExitCode)
	specific := st.Win32ExitCode == 1066
	if specific {
		code = int(st.ServiceSpecificExitCode)
	}
	if meaning, ok := service.ServerTable().Meaning(code); ok {
		_, _ = fmt.Fprintf(out, "service status: last exit %d — %s\n", code, meaning)
		_, _ = fmt.Fprintln(out, "service status: a restart cannot fix that code, so the recovery chain does "+
			"not retry it; fix the cause, then `server service start`")
		return
	}
	if specific {
		_, _ = fmt.Fprintf(out, "service status: last exit %d\n", code)
		return
	}
	_, _ = fmt.Fprintf(out, "service status: last win32 exit %d\n", st.Win32ExitCode)
}

// openRegistered opens the service for a command that needs one, turning "not registered" into the
// hint rather than a stack of errors.
func openRegistered(op string, errOut io.Writer) (scm, scmService, int) {
	m, err := newSCM()
	if err != nil {
		_, _ = fmt.Fprintln(errOut, op+":", logx.Redact(err.Error()))
		return nil, nil, exitUsage
	}
	s, err := m.Open(service.WindowsServiceName)
	if err != nil {
		_ = m.Close()
		if errors.Is(err, errServiceNotRegistered) {
			_, _ = fmt.Fprintln(errOut, op+": "+service.NotRegisteredHint)
			return nil, nil, exitUsage
		}
		_, _ = fmt.Fprintln(errOut, op+":", logx.Redact(err.Error()))
		return nil, nil, exitRuntime
	}
	return m, s, 0
}

// resolveDataDir falls back to the registered dir and then to the installer's default.
func resolveDataDir(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if registered, ok := serviceRegisteredDataDir(); ok {
		return registered
	}
	return defaultServiceDataDir()
}

// serviceLogDir is where the service's log file and its last-fatal marker live. The marker is in
// `<data-dir>\logs` and NOT in the data dir itself: a reader that looked one level up would never
// find the file the handler wrote, and the refusal would silently never fire.
func serviceLogDir(dataDir string) string { return filepath.Join(dataDir, "logs") }

// defaultServiceDataDir is the installer's default, `%ProgramData%\claude-swap-server` (Decision
// 10). It is deliberately NOT defaultDataDir(), which is the profile directory a console run uses:
// a service account's profile is not where a shared vault belongs.
func defaultServiceDataDir() string {
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "claude-swap-server")
	}
	return defaultDataDir()
}

// readCertFingerprint reads the pinned sha256 without writing anything. An absent or unreadable
// pair is "no fingerprint", not an error: an install before the first run has nothing pinned yet.
func readCertFingerprint(dataDir string) (string, bool) {
	fp, err := certFingerprintOf(dataDir)
	if err != nil || fp == "" {
		return "", false
	}
	return fp, true
}

// firewallCommand is the line an operator can paste. It is printed, never run, unless --firewall.
func firewallCommand(listen string) []string {
	return append([]string{"netsh"}, firewallArgs(listen)...)
}

// firewallArgs is the netsh argument list for the inbound rule on the listen port.
func firewallArgs(listen string) []string {
	port := listen
	if _, p, err := net.SplitHostPort(listen); err == nil {
		port = p
	}
	return []string{"advfirewall", "firewall", "add", "rule",
		"name=Claude Swap server", "dir=in", "action=allow", "protocol=TCP", "localport=" + port}
}

// resolveServicePolicy resolves and installs the ACL policy for the service's own start (G17). A
// narrowing is not an error: it returns narrowed=true so the caller logs it once the log file
// exists. Any other failure returns the exit code and the logged reason to stop the start with.
func resolveServicePolicy() (narrowed bool, code int, reason string, err error) {
	policy, err := aclPolicy()
	narrowed = errors.Is(err, service.ErrACLPolicyNarrowed)
	if err != nil && !narrowed {
		return false, exitUsage, "acl-policy-failed", err
	}
	if err := setACLPolicy(policy...); err != nil {
		return false, exitRuntime, "acl-policy-rejected", err
	}
	return narrowed, 0, "", nil
}

// reapplyACLPolicy re-resolves the policy and installs it. It is called after the registration, when
// the service's SID exists for the first time, and it takes the same G17 narrowing as the entry
// point: a registered service whose SID will not resolve gets the narrower policy, the install
// finishes, and the operator is told in the output and in one structured log line.
func reapplyACLPolicy(out, errOut io.Writer) int {
	policy, err := aclPolicy()
	if errors.Is(err, service.ErrACLPolicyNarrowed) {
		logx.New(errOut).Warn("acl policy", "reason", service.ACLPolicyNarrowedReason, "op", "service install")
		_, _ = fmt.Fprintln(errOut, "service install: WARNING:", logx.Redact(err.Error()))
		err = nil
	}
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "service install:", logx.Redact(err.Error()))
		return exitUsage
	}
	if err := setACLPolicy(policy...); err != nil {
		_, _ = fmt.Fprintln(errOut, "service install:", logx.Redact(err.Error()))
		return exitRuntime
	}
	if len(policy) > 0 && service.ACLPolicyNamesTheService(policy) {
		_, _ = fmt.Fprintf(out, "service install: the data-dir ACL policy now names %s as well as %s\n",
			service.WindowsServiceAccount, service.AdministratorsAccount)
	}
	return 0
}

// restrictExistingFiles runs credfile.RestrictFile over every regular file under dir, so a file
// written under an earlier (Administrators-only) policy picks up the SIDs the policy names now. It
// returns how many files it restricted. Symlinks and directories are skipped: the icacls grant
// covers directories, and a link must not carry a grant to its target. The first failure stops the
// walk and names the path, never the file's contents. On unix RestrictFile is a no-op.
func restrictExistingFiles(dir string) (int, error) {
	n := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if err := credfile.RestrictFile(path); err != nil {
			return fmt.Errorf("restrict %s: %w", logx.TildePath(path), err)
		}
		n++
		return nil
	})
	return n, err
}

// confirmTyped requires word to be typed. One line is read, so a deliberate `echo purge |` works
// and a stray `-y` does not exist.
func confirmTyped(in io.Reader, out io.Writer, word, prompt string) bool {
	if in == nil {
		return false
	}
	_, _ = fmt.Fprint(out, prompt)
	// A *bufio.Reader is used as is: wrapping it again would buffer ahead and swallow the next
	// prompt's answer. purgeCmd bounds the stream once, underneath the shared reader.
	br, ok := in.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(io.LimitReader(in, maxConfirmLine))
	}
	line, err := br.ReadString('\n')
	_, _ = fmt.Fprintln(out)
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		return false
	}
	return strings.TrimRight(line, "\r\n") == word
}

// readOnlyInvocations are the commands that write nothing. They apply no ACL policy when it is
// narrowed (G17), because they are exactly the commands an operator needs in order to find out WHY
// it is narrowed.
var readOnlyInvocations = map[string]map[string]bool{
	"service": {"status": true},
	"vault":   {"status": true, "verify": true},
}

// readOnlyInvocation reports whether these arguments name a command that writes nothing.
// A bare invocation, a help flag and an unknown subcommand are read-only too: they print usage and
// exit before touching the data dir.
func readOnlyInvocation(args []string) bool {
	if len(args) == 0 {
		return true
	}
	if isHelpArg(args[0]) {
		return true
	}
	subs, ok := readOnlyInvocations[args[0]]
	if !ok {
		return false
	}
	if len(args) == 1 {
		return true
	}
	return subs[args[1]]
}

// isHelpArg spots the spellings that only print usage.
func isHelpArg(a string) bool {
	switch strings.ToLower(strings.TrimLeft(a, "-")) {
	case "h", "help":
		return true
	}
	return false
}

// opName is the `op` a refusal is logged against: the subcommand, or "run" for the bare flag form.
func opName(args []string) string {
	if len(args) == 0 {
		return "run"
	}
	name := args[0]
	if strings.HasPrefix(name, "-") {
		return "run"
	}
	for _, r := range name {
		if !unicode.IsLetter(r) && r != '-' {
			return "run"
		}
	}
	return name
}
