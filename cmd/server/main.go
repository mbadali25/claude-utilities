// Command server runs the claude-swap hub and admin UI on one TLS listener: agents connect to
// /ws, the browser uses everything else. The set-password subcommand replaces the admin UI
// password stored in the data dir.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"claude-utilities/internal/adminpw"
	"claude-utilities/internal/hub"
	"claude-utilities/internal/logx"
	"claude-utilities/internal/ownership"
	"claude-utilities/internal/service"
	"claude-utilities/internal/tunnel"
	"claude-utilities/internal/usage"
	"claude-utilities/internal/vault"
	"claude-utilities/internal/web"
)

// The entry point's seams. The order these fire in is the contract this slice adds - the lock
// before the first writer, readiness after the last thing that can fail - and an ordering contract
// that nothing can observe is one that breaks silently. They are variables so a test records the
// order against the real implementations rather than against a mock of the whole entry point.
//
// registeredDataDir is the exception: it has no implementation yet. Reading the service's baked
// --data-dir means the SCM on Windows (mgr.Service.Config().BinaryPathName) and the unit's
// ExecStart= on Linux, which arrive with the service halves in slices 4b and 4c. Until then it
// answers "no service registered", which is the truth on a host where none is.
var (
	acquireLock       = vault.AcquireLock
	readVaultOp       = vault.ReadVaultOp
	ensureCert        = hub.EnsureCert
	listenTCP         = net.Listen
	notifyReady       = service.NotifyReady
	notifyStopping    = service.NotifyStopping
	registeredDataDir = func() (string, bool) { return "", false }
)

const (
	keyEnv       = "CLAUDESWAP_KEY"
	passwordEnv  = "CLAUDESWAP_ADMIN_PASSWORD"
	shutdownWait = 5 * time.Second
)

// usageText is the command summary; the name avoids the internal/usage import.
const usageText = `usage: server run <flags> | server <flags> | server set-password [--data-dir DIR]
       server cert renew [--data-dir DIR] | server vault <subcommand> [--data-dir DIR]
  run                    run the hub and admin UI. This is the preferred form; the bare flag form
                         below is kept unchanged for existing scripts (scripts/start-server.ps1 and
                         the e2e start script pass --listen with no subcommand).
  vault <subcommand>     status, verify, add-slot, remove-slot, rotate, change-passphrase.
                         Run "server vault" with no subcommand to list them.
  --listen host:port     run the hub and admin UI (required, no default)
  --data-dir DIR         vault, host list, TLS certificate and admin password hash
  --tunnels              supervise the reverse SSH tunnels to the Linux hosts, and
                         show the Tunnels tab. OFF by default: it must not run at the
                         same time as the interim claude-swap-tunnels scheduled task,
                         because two supervisors dialling one host fight over its port.
  --refresh-tokens       refresh an expired stored login through the OAuth token endpoint.
                         OFF by default. Refreshes ONLY the accounts named in --refresh-accounts
                         (none listed = nothing refreshed); a failure is not retried before the
                         1 h unauthorized backoff.
  --refresh-accounts a,b comma-separated account ids that --refresh-tokens may refresh. Needs
                         --refresh-tokens (ignored with a warning otherwise). Ownership is
                         in-memory and empty after a restart, so this list is the real scope
                         control; the ownership check only skips accounts swapped or imported
                         since start.
  --stale-after DUR     flag a stored login older than this (default 6h; access tokens
                         last about 8h). A flagged login still swaps, with a warning.
  set-password           replace the admin UI password; it is read from a no-echo
                         prompt when stdin is a terminal, else one line of stdin.
                         There is no flag for it, by design.
  cert renew             write a new TLS pair. This is the ONLY command that changes the
                         certificate: the fingerprint every agent pins changes with it, so
                         every agent must re-enrol. It asks for a typed confirmation.`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Getenv, os.Stdin, os.Stderr)
	stop()
	os.Exit(code)
}

func defaultDataDir() string {
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "claude-swap-server")
	}
	return "claude-swap-server"
}

// Exit codes. 0 clean stop, 1 runtime failure, 2 bad usage or missing input, 4 the vault is in a
// format this binary cannot read - written by a newer server, or malformed - and 5 certificate
// refused. 3 (vault locked) arrives
// with a later slice of the cert-vault plan, and 4 gains its other two causes there too (a v1
// vault with no passphrase, and no vault and no passphrase).
//
// "A code a restart cannot fix must not be retried; only 1 is" is the contract for the service
// units that slices 4 and 8 of the cert-vault plan write (the systemd unit's
// RestartPreventExitStatus and the Windows task's failure actions). Nothing in this repository
// enforces it today: this binary returns the codes and no supervisor here reads them, so the
// restart behaviour of a packaged install is whatever those units end up saying.
const (
	exitRuntime     = 1
	exitUsage       = 2
	exitVaultLocked = 3
	exitNewerFormat = 4
	exitCertRefused = 5
)

// A subcommand is one member of the fixed name set. One signature for all of them so the table
// below is data a test can walk: the guard it enforces is "no name without an owner, and no owner
// without a name", in either direction.
type subcommand func(ctx context.Context, args []string, getenv func(string) string, in io.Reader, errOut io.Writer) int

// dispatchTable is the fixed subcommand name set. Decision 13: these names and nothing else;
// anything else, a leading "-" included, goes to the flag parser, so a bare `server --listen ...`
// keeps working for scripts/start-server.ps1 and the e2e start script.
//
// Five names, three owners. `set-password` and `cert` were here already, `run` and `vault` are this
// slice's, and `service` joins in slice 4 with `server service install`. A name is registered only
// by the task that has a handler for it: a name in this table with nothing behind it would be a
// subcommand that exists in the usage text and fails at the prompt.
func dispatchTable() map[string]subcommand {
	return map[string]subcommand{
		"run": func(ctx context.Context, args []string, getenv func(string) string, _ io.Reader, errOut io.Writer) int {
			return serveCmd(ctx, args, getenv, errOut)
		},
		"set-password": func(_ context.Context, args []string, _ func(string) string, in io.Reader, errOut io.Writer) int {
			return setPasswordCmd(args, in, errOut)
		},
		"cert": func(_ context.Context, args []string, _ func(string) string, in io.Reader, errOut io.Writer) int {
			return certCmd(args, in, errOut, errOut)
		},
		"vault": func(_ context.Context, args []string, _ func(string) string, in io.Reader, errOut io.Writer) int {
			return vaultCmd(args, in, errOut, errOut)
		},
	}
}

// run returns the process exit code: 0 clean stop, 1 runtime failure, 2 bad usage or missing
// secrets, 3 a vault no slot could unwrap, 4 a vault this binary cannot read, 5 a refused
// certificate.
func run(ctx context.Context, args []string, getenv func(string) string, in io.Reader, errOut io.Writer) int {
	if len(args) > 0 {
		if handler, ok := dispatchTable()[args[0]]; ok {
			return handler(ctx, args[1:], getenv, in, errOut)
		}
	}
	return serveCmd(ctx, args, getenv, errOut)
}

// serveCmd parses the console run's flags and serves. It is reached two ways and must behave
// identically through both: `server run --listen ...` and the bare `server --listen ...` that every
// existing script uses.
func serveCmd(ctx context.Context, args []string, getenv func(string) string, errOut io.Writer) int {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(errOut)
	listen := fs.String("listen", "", "host:port to listen on (required, no default)")
	dataDir := fs.String("data-dir", defaultDataDir(), "directory for the vault, host list, TLS certificate and admin password hash")
	tunnels := fs.Bool("tunnels", false, "supervise the reverse SSH tunnels and show the Tunnels tab (must not overlap the interim scheduled task)")
	refreshTokens := fs.Bool("refresh-tokens", false, "refresh expired logins, only of the accounts named in --refresh-accounts, through the OAuth token endpoint")
	refreshAccounts := fs.String("refresh-accounts", "", "comma-separated account ids --refresh-tokens may refresh (none = refresh nothing)")
	staleAfter := fs.Duration("stale-after", hub.DefaultStaleAfter, "flag a stored login older than this")
	if err := fs.Parse(args); err != nil {
		_, _ = fmt.Fprintln(errOut, usageText)
		return 2
	}
	if *staleAfter <= 0 {
		_, _ = fmt.Fprintln(errOut, "server: --stale-after must be a positive duration such as 6h")
		return 2
	}
	if *listen == "" {
		_, _ = fmt.Fprintln(errOut, "server: --listen host:port is required (there is no default; choose the LAN address deliberately)")
		return 2
	}
	if _, _, err := net.SplitHostPort(*listen); err != nil {
		_, _ = fmt.Fprintln(errOut, "server: --listen must be host:port")
		return 2
	}
	// A stored hash wins over the environment variable, which is only the bootstrap for a data
	// dir that has never had `server set-password` run against it. It is checked before the lock
	// deliberately: an input this process will never have is no reason to create a data dir, take
	// its lock, or make another server wait.
	pw, err := adminpw.Open(passwordPath(*dataDir), getenv(passwordEnv))
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "server:", logx.Redact(err.Error()))
		return 1
	}
	if !pw.Stored() && getenv(passwordEnv) == "" {
		_, _ = fmt.Fprintf(errOut, "server: set %s (admin UI password) or run `server set-password` first\n", passwordEnv)
		return exitUsage
	}

	log := logx.New(errOut)
	// Decision 10: one data dir, named once, through TildePath so a developer's home never carries
	// a username into a log line - and a warning when the registered service disagrees with it.
	log.Info("data dir", "datadir", logx.TildePath(*dataDir))
	warnOtherServiceDataDir(log, *dataDir)

	// The lock before anything that writes. EnsureCert is the first writer, and two servers
	// generating a pair into one tls/ is how every agent's pin stops matching.
	lock, err := acquireLock(*dataDir, "run")
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "server:", logx.Redact(err.Error()))
		return lockExitCode(err)
	}
	// Held for the process lifetime: the vault mutators take the same lock, so a `vault rotate`
	// against a running server waits rather than racing it.
	defer func() { _ = lock.Release() }()

	if code := refuseInterruptedVaultOp(*dataDir, log, errOut); code != 0 {
		return code
	}

	ks, code := entryKeySource(getenv, *dataDir, *tunnels, log, errOut)
	if code != 0 {
		return code
	}

	// This is the one place a serve error becomes an exit code, so it is the one place the
	// `cert refused` line can carry both the reason and the code.
	if err := serve(ctx, *listen, *dataDir, pw, ks, *tunnels, *refreshTokens, parseRefreshAccounts(*refreshAccounts), *staleAfter, errOut); err != nil && !errors.Is(err, context.Canceled) {
		reportRefusal(errOut, "server", err)
		return exitCodeForRun(err, getenv(keyEnv) != "")
	}
	return 0
}

// lockExitCode is 2 when another process holds the data-dir lock and 1 when taking it failed for
// any other reason. 2 is the non-restarting code on purpose: a lock a live server holds is still
// held after a restart, so a supervisor that retried would only hide the message naming the holder.
func lockExitCode(err error) int {
	if errors.Is(err, vault.ErrLockHeld) {
		return exitUsage
	}
	return exitRuntime
}

// warnOtherServiceDataDir is Decision 10's only guard: the installer bakes --data-dir into the
// service command line, so the SCM is the single source of truth, and a console run against a
// different dir is a second vault nobody meant to have. It warns rather than refuses, because
// running a developer's vault beside a service is a thing an operator does deliberately.
func warnOtherServiceDataDir(log *slog.Logger, inUse string) {
	registered, ok := registeredDataDir()
	if !ok || sameDir(registered, inUse) {
		return
	}
	log.Warn("a service is registered with a different data dir",
		"reason", "datadir-mismatch", "datadir", logx.TildePath(registered))
}

// sameDir compares two data-dir paths the way the filesystem does: case-insensitively on Windows.
func sameDir(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// refuseInterruptedVaultOp refuses to start when a vaultop journal is present, with exit 3.
//
// The server never settles one. The settle re-runs or reverts a half-finished slot operation, and a
// service doing that unattended - with the operator who ran the mutator gone, and the result in a
// log nobody is reading - is how a recovery copy or a host's tunnel key is lost. 3 is non-restarting,
// so the supervisor stops instead of looping, and the message names the read-only command that looks
// at the state without changing it.
func refuseInterruptedVaultOp(dataDir string, log *slog.Logger, errOut io.Writer) int {
	op, ok, err := readVaultOp(dataDir)
	switch {
	case err != nil:
		log.Error("vaultop interrupted", "reason", "unreadable", "op", "run")
		_, _ = fmt.Fprintln(errOut, "server:", logx.Redact(err.Error()))
		return exitVaultLocked
	case ok:
		log.Error("vaultop interrupted", "reason", "present", "op", op.Op)
		_, _ = fmt.Fprintf(errOut, "server: %s names an interrupted %s (stage %s): the next vault "+
			"command settles it; to look first, run `server vault verify --all-slots`\n",
			vault.VaultOpFileName, op.Op, op.Stage)
		return exitVaultLocked
	}
	return 0
}

// entryKeySource picks the keys for this entry point and refuses, with the format code, the states a
// process with no passphrase cannot do anything about.
//
// Two entry points, one command. With CLAUDESWAP_KEY set this is a console run and the passphrase is
// the key, exactly as before. Without it this is the service: machine-held openers only, which is
// why Open stopped taking the name of an environment variable - a name cannot express "this process
// has no passphrase". The refusals below are the three states that reach exit 4 rather than a
// confusing ErrNoKey from inside the opener.
func entryKeySource(getenv func(string) string, dataDir string, tunnels bool, log *slog.Logger, errOut io.Writer) (vault.KeySource, int) {
	// A v2 vault with a v1 keyring, or the reverse: what a crash between the two writes leaves.
	// Only --tunnels opens the keyring, so only --tunnels refuses - and it refuses rather than
	// starting half-open, with the vault serving accounts and the tunnels silently dead.
	if tunnels {
		if line, mixed := vault.MixedPair(dataDir); mixed {
			log.Error("format", "reason", "mixed-pair", "op", "run")
			_, _ = fmt.Fprintln(errOut, "server:", line)
			return nil, exitNewerFormat
		}
	}
	if getenv(keyEnv) != "" {
		return vault.EnvKey(keyEnv), 0
	}

	info, err := vault.Inspect(filepath.Join(dataDir, vaultFileName))
	if err != nil {
		// A file this binary cannot even inspect is a format it cannot read, which is exit 4's own
		// row; reportRefusal carries the reason when the error is one of the vault's sentinels.
		reportRefusal(errOut, "server", err)
		return nil, exitNewerFormat
	}
	switch info.Format {
	case vault.FormatAbsent:
		// Never created here: a vault needs a passphrase slot (it is the recovery key for every
		// machine-key loss), so a process with no passphrase must not write one.
		log.Error("format", "reason", "no-vault", "op", "run")
		_, _ = fmt.Fprintf(errOut, "server: no vault at %s and no passphrase (%s is unset): "+
			"run `server vault init`\n", logx.TildePath(dataDir), keyEnv)
		return nil, exitNewerFormat
	case vault.FormatV1:
		log.Error("format", "reason", "v1-no-passphrase", "op", "run")
		_, _ = fmt.Fprintf(errOut, "server: the vault at %s is v1, which has no key slots, and this "+
			"process has no passphrase (%s is unset): run `server vault migrate`\n",
			logx.TildePath(dataDir), keyEnv)
		return nil, exitNewerFormat
	}
	return vault.WithMachineKeys(nil, hostKeyOptions()), 0
}

// exitCodeForRun maps a serve error for `server run`, which is the one entry point that reaches
// both the console's keys and the service's. It is exitCodeFor plus the single row whose code
// depends on which of the two this process is.
//
// With a passphrase, ErrBadKey is a wrong CLAUDESWAP_KEY: an operator's typo at a console, exit 1,
// and a retry is the right thing for a supervisor to do with it. With no passphrase there is no
// second way in, so "no slot could unwrap" (ErrBadKey, or the ErrNoKey recoverDEK returns when the
// only slots are kinds this host has no opener for) IS the spec's exit-3 row, "vault locked". That
// is the restored-data-dir and cleared-machine-key case, and leaving it at 1 would make it the one
// fatal a supervisor retries: ErrKEKUnreachable alone does not cover it, because a KEK file that
// reads but holds the wrong key never reaches that sentinel.
func exitCodeForRun(err error, hasPassphrase bool) int {
	if code := exitCodeFor(err); code != exitRuntime {
		return code
	}
	if !hasPassphrase && (errors.Is(err, vault.ErrBadKey) || errors.Is(err, vault.ErrNoKey)) {
		return exitVaultLocked
	}
	return exitRuntime
}

// exitCodeFor maps a serve error to a process exit code. It is the single mapping site: `serve`
// returns errors unchanged and `run` is the only place an error becomes an int.
//
// The order is fixed rather than left to the reader: certificate refusals first (5), then the
// vault rows (4, and 3 as a later slice extends them), then 1. The two domains are disjoint today
// - the cert sentinels live in internal/hub, the vault sentinels in internal/vault, and no error
// satisfies errors.Is against both - but fixing the order means an error that one day wraps both
// resolves to the more specific refusal deterministically.
func exitCodeFor(err error) int {
	if c := certExitCode(err); c != exitRuntime {
		return c
	}
	return vaultExitCode(err)
}

// vaultExitCode is 4 when this binary cannot read the vault's format, 3 when a key slot's key is
// configured and out of reach, and 1 for anything else.
// Two causes share the code: a header written by a newer server, and a header that is malformed -
// which since the v2 parser landed includes every out-of-bounds number in a v2 header. A restart
// cannot make either readable, so 4 is one of the codes the service units of slices 4 and 8 must
// keep out of their restart loop; see the exit-code block above for why that is a contract and not
// yet a behaviour. A later slice adds 3 (no slot could unwrap) and 4's other two causes.
//
// Malformed is deliberately not 3 and deliberately not ErrBadKey's code: a crafted header must
// never push an operator towards rotating a correct passphrase.
func vaultExitCode(err error) int {
	if errors.Is(err, vault.ErrNewerFormat) || errors.Is(err, vault.ErrMalformed) {
		return exitNewerFormat
	}
	// 3 is the spec's "vault locked" row: a kek-file slot is configured and this process cannot
	// reach its key, which is the machine-key loss case (a restored data dir, a cleared TPM, a lost
	// credential.secret). A restart cannot fix it, so it is one of the codes the service units keep
	// out of their restart loop, and it must never be reported as a bad key - the fix is a root
	// shell, a mode bit or `server vault add-slot`, never rotating a passphrase that is correct.
	//
	// ErrBadKey keeps exit 1 here deliberately: on the console path it is a wrong CLAUDESWAP_KEY,
	// which is an operator's typo and not a locked vault. The no-passphrase entry point, for which
	// "no slot could unwrap" IS the locked state, raises the same sentinel to 3 in exitCodeForRun -
	// this function is also `cert renew`'s and the mutators', which all have a passphrase.
	if errors.Is(err, vault.ErrKEKUnreachable) {
		return exitVaultLocked
	}
	return exitRuntime
}

// vaultReason is the half of the case table an exit code cannot carry, and it is a fixed string:
// the error text names a file this process could not read, so quoting it could quote file content.
// The two reasons are distinct because the operator's next step differs - downgrade on the newer
// binary, against restore from a copy.
func vaultReason(err error) string {
	switch {
	case errors.Is(err, vault.ErrNewerFormat):
		return "newer-format"
	case errors.Is(err, vault.ErrMalformed):
		return "malformed"
	}
	return ""
}

// certExitCode is 5 for any of internal/hub's certificate refusals and 1 for anything else. A
// restart cannot fix a refused certificate, so 5 is the other code those future service units
// must keep out of their restart loop, on the same terms as 4.
func certExitCode(err error) int {
	for _, e := range []error{
		hub.ErrCertPairIncomplete, hub.ErrCertUnreadable, hub.ErrCertCorrupt,
		hub.ErrCertMismatch, hub.ErrCertExpired,
	} {
		if errors.Is(err, e) {
			return exitCertRefused
		}
	}
	return exitRuntime
}

// certReason is the half of the case table an exit code cannot carry. The mapping lives in
// internal/hub, which owns the two unexported causes of ErrCertUnreadable (a denied read and a
// failed re-ACL) that a log reason has to tell apart.
func certReason(err error) string { return hub.CertReason(err) }

// reportRefusal prints the refusal and emits the one structured line the case table asks for,
// whichever domain the error came from. It sits beside exitCodeFor on purpose: every path that
// turns an error into an exit code goes through both, so a code can never be returned with the
// reason line missing. That pairing is the bug it fixes - `cert renew` shares exitCodeFor, so a
// vault error reaching it used to exit 4 silently while only `run` logged the format reason.
//
// A line carries the reason and nothing else: no path, no fingerprint, no file bytes, no key
// material. ("exit" joins them once logx allowlists the key, in Task 3a.9.)
func reportRefusal(errOut io.Writer, prefix string, err error) {
	log := logx.New(errOut)
	if r := certReason(err); r != "" {
		log.Error("cert refused", slog.String("reason", r))
	}
	if r := vaultReason(err); r != "" {
		log.Error("format", slog.String("reason", r))
	}
	_, _ = fmt.Fprintln(errOut, prefix+":", logx.Redact(err.Error()))
}

// passwordPath is where the argon2id admin password hash lives inside a data dir.
func passwordPath(dataDir string) string { return filepath.Join(dataDir, adminpw.FileName) }

// setPasswordCmd replaces the stored admin password. The password is never taken from a flag:
// argv is visible to every process on the host. With a terminal on stdin it is prompted for
// twice with echo off; otherwise one line is read from stdin, so a script can pipe it in.
func setPasswordCmd(args []string, in io.Reader, errOut io.Writer) int {
	fs := flag.NewFlagSet("set-password", flag.ContinueOnError)
	fs.SetOutput(errOut)
	dataDir := fs.String("data-dir", defaultDataDir(), "directory holding the admin password hash")
	if err := fs.Parse(args); err != nil {
		_, _ = fmt.Fprintln(errOut, usageText)
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(errOut, "set-password: the password is read from the prompt or stdin, never from an argument")
		return 2
	}
	pwd, err := readNewPassword(in, errOut)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "set-password:", logx.Redact(err.Error()))
		return 2
	}
	store, err := adminpw.Open(passwordPath(*dataDir), "")
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "set-password:", logx.Redact(err.Error()))
		return 1
	}
	if err := store.Set(pwd); err != nil {
		_, _ = fmt.Fprintln(errOut, "set-password:", logx.Redact(err.Error()))
		if errors.Is(err, adminpw.ErrTooShort) {
			return 2
		}
		return 1
	}
	// A running server read the hash once at startup, so it keeps accepting the old password and
	// keeps its sessions until it restarts. Only the UI's own change ends sessions immediately.
	_, _ = fmt.Fprintf(errOut, "set-password: stored in %s; %s is no longer used. Restart the server to pick this up: "+
		"a running one keeps the old password and its open sessions until then.\n", passwordPath(*dataDir), passwordEnv)
	return 0
}

// readNewPassword reads the new password without echoing it when in is a terminal, and without a
// confirmation prompt when it is not (a pipe cannot be asked twice).
func readNewPassword(in io.Reader, errOut io.Writer) (string, error) {
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		_, _ = fmt.Fprintf(errOut, "New admin password (%d characters or more, not echoed): ", adminpw.MinLength)
		first, err := term.ReadPassword(int(f.Fd()))
		_, _ = fmt.Fprintln(errOut)
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		_, _ = fmt.Fprint(errOut, "Repeat it: ")
		second, err := term.ReadPassword(int(f.Fd()))
		_, _ = fmt.Fprintln(errOut)
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		if string(first) != string(second) {
			return "", errors.New("the two passwords do not match")
		}
		return string(first), nil
	}
	// Not a terminal: take exactly one line, so a trailing newline from `echo` is not part of it.
	br := bufio.NewReader(io.LimitReader(in, maxStdinPassword))
	line, err := br.ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		return "", errors.New("no password on stdin")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// maxStdinPassword bounds a piped password so a stuck or hostile producer cannot be read forever.
const maxStdinPassword = 4 << 10

// wireRefresher turns on server-side token refresh when enabled, and reports whether it did. An
// account refreshes only if its id is in listed (the --refresh-accounts allowlist) AND serverOwned
// is true. An empty list refreshes nothing (fail closed). The ownership registry is in-memory and
// empty after a restart, so serverOwned is true for every account until a swap or import in this
// process; host connect or report does not populate it. The allowlist is therefore the real scope
// control, and the ownership check only skips accounts swapped or imported since start. Effect on
// other hosts of refreshing a login a host holds: not observed; unproven. A failed refresh is not
// retried here; the poller's unauthorized backoff applies. A persist failure is logged by account only.
func wireRefresher(p *usage.Poller, enabled bool, r usage.Refresher, log *slog.Logger, listed []string, serverOwned func(string) bool,
	persist func(id string, block json.RawMessage) error) bool {
	if !enabled {
		return false
	}
	p.SetRefreshAllowed(refreshGate(listed, serverOwned))
	if len(listed) == 0 {
		log.Warn("token refresh has no accounts: --refresh-accounts is empty, refreshing nothing", "action", "refresh", "result", "fail-closed", "count", 0)
	} else {
		log.Info("token refresh allowlist", "action", "refresh", "result", "allowlist", "count", len(listed))
	}
	p.SetRefresher(r, func(id string, b json.RawMessage) {
		if err := persist(id, b); err != nil {
			log.Error("persist refreshed login failed", "action", "refresh", "result", "failed", "account", id)
			return
		}
		// Logged only once the vault holds the new login; the failing token call is logged by the poller.
		log.Info("token refreshed", "action", "refresh", "result", "ok", "account", id)
	})
	return true
}

func serve(ctx context.Context, listen, dataDir string, pw web.PasswordAPI, ks vault.KeySource, tunnels, refreshTokens bool, refreshAccounts []string, staleAfter time.Duration, errOut io.Writer) error {
	certFile, keyFile, fp, err := ensureCert(filepath.Join(dataDir, "tls"))
	if err != nil {
		return err
	}
	log := logx.New(errOut)
	// Once per start, for both levels, and at the EnsureCert call site rather than after
	// vault.Open: a server that then exits 3 or 4 on the vault must still have said that its
	// certificate is about to expire. The once-a-day (case-table row 6) and hourly (row 7)
	// repeats need a ticker in the run loop, which arrives with Task 4.3 of the cert-vault plan;
	// row 7's admin-UI notice is Task 8.7. Until then an expiring pair is visible here, in the
	// journal and in the Windows event log, and nowhere else.
	if level, text, ok := hub.CertExpiryWarning(certFile, time.Now()); ok {
		if level == "warn" {
			log.Warn(text, "reason", "cert-expiry")
		} else {
			log.Info(text, "reason", "cert-expiry")
		}
	}
	// The keys were chosen by entryKeySource, once, and are handed to both sealed files because the
	// keyring is sealed with the same key material as the vault: the passphrase from CLAUDESWAP_KEY
	// for a console run, this host's machine-held openers for the service.
	v, err := vault.Open(filepath.Join(dataDir, vaultFileName), ks)
	if err != nil {
		return err
	}
	reg := ownership.New()
	h := hub.New(v, reg, filepath.Join(dataDir, "hosts.json"), log)
	// Without --refresh-tokens an expired token shows as "unauthorized" in the UI.
	poller := usage.NewPoller(&http.Client{Timeout: 20 * time.Second}, usage.DefaultConfig())
	warnRefreshAccountsIgnored(log, refreshTokens, refreshAccounts)
	if wireRefresher(poller, refreshTokens, usage.NewOAuthRefresher(), log, refreshAccounts,
		func(id string) bool { return reg.OwnerOf(id).Server },
		func(id string, b json.RawMessage) error { return v.ReplaceBlock(id, b, time.Now()) }) {
		log.Warn("token refresh enabled", "action", "refresh", "result", "enabled")
		if n := countUnmatched(refreshAccounts, v.List()); n > 0 {
			log.Warn("listed accounts match no stored account", "action", "refresh", "result", "unmatched", "count", n)
		}
	}

	// The tunnel supervisor, only with --tunnels. It is started after the vault passphrase has
	// been accepted, because the keyring is unlocked with the same one, and stopped before the
	// listener goes away so its ssh children do not outlive the process.
	var tm *tunnel.Manager
	if tunnels {
		kr, kerr := vault.OpenKeyring(filepath.Join(dataDir, vault.KeyringFileName), ks)
		if kerr != nil {
			return kerr
		}
		tm, err = tunnel.NewManager(tunnel.Options{DataDir: dataDir, Log: log}, kr)
		if err != nil {
			return err
		}
		defer tm.Stop()
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go h.Run(ctx)
	if tm != nil {
		tm.Start(ctx)
		_, _ = fmt.Fprintln(errOut, "server: tunnel supervisor started; make sure the "+
			"claude-swap-tunnels scheduled task is NOT also running")
	}
	// Poll every stored account, including ones a host currently holds: the agent sends no usage
	// report, so the vault copy (refreshed by swap write-back) is the only source. The accounts are
	// set before the listener starts, so an admin's Refresh cannot arrive before the source exists.
	poller.SetAccounts(v.List)
	// A host holding an account live, or a swap that just landed one, puts it on the short schedule.
	poller.SetHeld(func(id string) bool { return !reg.OwnerOf(id).Server })
	h.SetOnSwap(poller.NoteSwap)
	// "Sign in again" stored a fresh login: the old one's 401 and backoff no longer apply.
	h.SetOnReplaced(poller.Reset)
	// A swap onto an account the usage endpoint rejected would only sign the host out.
	h.SetUnauthorized(func(id string) bool {
		u, ok := poller.Last(id)
		return ok && u.Err == "unauthorized"
	})
	h.SetStaleAfter(staleAfter)
	go poller.Run(ctx, nil)

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", h.ServeWS)
	mux.Handle("/", web.Handler(h, v, poller, pw, tm))
	srv := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	// READY=1 goes out after the LAST thing that can fail, which is what `Type=notify` buys: with
	// Type=simple `systemctl start` returns as soon as the process exists, so a server about to
	// exit 3 on a locked vault would be reported as started. So the pair is loaded here rather than
	// inside ListenAndServeTLS, and the listener is bound here rather than in the goroutine: after
	// these two there is nothing left between readiness and serving.
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	ln, err := listenTCP("tcp", listen)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(errOut, "server: listening on https://%s  certificate sha256=%s\n", listen, fp)
	if err := notifyReady(); err != nil {
		// A readiness message that cannot be sent is not a reason to refuse service: the server is
		// up, and on a console run there is no socket to send it to at all. It is logged so a unit
		// that then times out has the cause in the journal rather than only "start timed out".
		log.Warn("readiness notification failed", "reason", "notify", logx.Err(err))
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ServeTLS(ln, "", "") }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		if err := notifyStopping(); err != nil {
			log.Warn("stopping notification failed", "reason", "notify", logx.Err(err))
		}
		sctx, c := context.WithTimeout(context.Background(), shutdownWait)
		defer c()
		return errors.Join(srv.Shutdown(sctx), ctx.Err())
	}
}
