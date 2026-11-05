// Command server runs the claude-swap hub and admin UI on one TLS listener: agents connect to
// /ws, the browser uses everything else. The set-password subcommand replaces the admin UI
// password stored in the data dir.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"claude-utilities/internal/adminpw"
	"claude-utilities/internal/hub"
	"claude-utilities/internal/logx"
	"claude-utilities/internal/ownership"
	"claude-utilities/internal/tunnel"
	"claude-utilities/internal/usage"
	"claude-utilities/internal/vault"
	"claude-utilities/internal/web"
)

const (
	keyEnv       = "CLAUDESWAP_KEY"
	passwordEnv  = "CLAUDESWAP_ADMIN_PASSWORD"
	shutdownWait = 5 * time.Second
)

// usageText is the command summary; the name avoids the internal/usage import.
const usageText = `usage: server <flags> | server set-password [--data-dir DIR]
  --listen host:port     run the hub and admin UI (required, no default)
  --data-dir DIR         vault, host list, TLS certificate and admin password hash
  --tunnels              supervise the reverse SSH tunnels to the Linux hosts, and
                         show the Tunnels tab. OFF by default: it must not run at the
                         same time as the interim claude-swap-tunnels scheduled task,
                         because two supervisors dialling one host fight over its port.
  set-password           replace the admin UI password; it is read from a no-echo
                         prompt when stdin is a terminal, else one line of stdin.
                         There is no flag for it, by design.`

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

// run returns the process exit code: 0 clean stop, 1 runtime failure, 2 bad usage or missing secrets.
func run(ctx context.Context, args []string, getenv func(string) string, in io.Reader, errOut io.Writer) int {
	if len(args) > 0 && args[0] == "set-password" {
		return setPasswordCmd(args[1:], in, errOut)
	}
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(errOut)
	listen := fs.String("listen", "", "host:port to listen on (required, no default)")
	dataDir := fs.String("data-dir", defaultDataDir(), "directory for the vault, host list, TLS certificate and admin password hash")
	tunnels := fs.Bool("tunnels", false, "supervise the reverse SSH tunnels and show the Tunnels tab (must not overlap the interim scheduled task)")
	if err := fs.Parse(args); err != nil {
		_, _ = fmt.Fprintln(errOut, usageText)
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
	if getenv(keyEnv) == "" {
		_, _ = fmt.Fprintf(errOut, "server: set %s (vault passphrase)\n", keyEnv)
		return 2
	}
	// A stored hash wins over the environment variable, which is only the bootstrap for a data
	// dir that has never had `server set-password` run against it.
	pw, err := adminpw.Open(passwordPath(*dataDir), getenv(passwordEnv))
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "server:", logx.Redact(err.Error()))
		return 1
	}
	if !pw.Stored() && getenv(passwordEnv) == "" {
		_, _ = fmt.Fprintf(errOut, "server: set %s (admin UI password) or run `server set-password` first\n", passwordEnv)
		return 2
	}
	if err := serve(ctx, *listen, *dataDir, pw, *tunnels, errOut); err != nil && !errors.Is(err, context.Canceled) {
		_, _ = fmt.Fprintln(errOut, "server:", logx.Redact(err.Error()))
		return 1
	}
	return 0
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

func serve(ctx context.Context, listen, dataDir string, pw web.PasswordAPI, tunnels bool, errOut io.Writer) error {
	certFile, keyFile, fp, err := hub.EnsureCert(filepath.Join(dataDir, "tls"))
	if err != nil {
		return err
	}
	v, err := vault.Open(filepath.Join(dataDir, "vault.bin"), keyEnv)
	if err != nil {
		return err
	}
	log := logx.New(errOut)
	reg := ownership.New()
	h := hub.New(v, reg, filepath.Join(dataDir, "hosts.json"), log)
	// Without a refresher (spike S2 deferred) an expired token shows as "unauthorized" in the UI.
	poller := usage.NewPoller(&http.Client{Timeout: 20 * time.Second}, usage.DefaultConfig())

	// The tunnel supervisor, only with --tunnels. It is started after the vault passphrase has
	// been accepted, because the keyring is unlocked with the same one, and stopped before the
	// listener goes away so its ssh children do not outlive the process.
	var tm *tunnel.Manager
	if tunnels {
		kr, kerr := vault.OpenKeyring(filepath.Join(dataDir, vault.KeyringFileName), keyEnv)
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
	go poller.Run(ctx, nil)

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", h.ServeWS)
	mux.Handle("/", web.Handler(h, v, poller, pw, tm))
	srv := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	_, _ = fmt.Fprintf(errOut, "server: listening on https://%s  certificate sha256=%s\n", listen, fp)
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServeTLS(certFile, keyFile) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		sctx, c := context.WithTimeout(context.Background(), shutdownWait)
		defer c()
		return errors.Join(srv.Shutdown(sctx), ctx.Err())
	}
}
