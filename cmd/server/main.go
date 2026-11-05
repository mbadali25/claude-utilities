// Command server runs the claude-swap hub and admin UI on one TLS listener: agents connect to
// /ws, the browser uses everything else.
package main

import (
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
	"syscall"
	"time"

	"claude-utilities/internal/hub"
	"claude-utilities/internal/logx"
	"claude-utilities/internal/ownership"
	"claude-utilities/internal/usage"
	"claude-utilities/internal/vault"
	"claude-utilities/internal/web"
)

const (
	keyEnv       = "CLAUDESWAP_KEY"
	passwordEnv  = "CLAUDESWAP_ADMIN_PASSWORD"
	usagePoll    = 5 * time.Minute
	shutdownWait = 5 * time.Second
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Getenv, os.Stderr)
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
func run(ctx context.Context, args []string, getenv func(string) string, errOut io.Writer) int {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(errOut)
	listen := fs.String("listen", "", "host:port to listen on (required, no default)")
	dataDir := fs.String("data-dir", defaultDataDir(), "directory for the vault, host list and TLS certificate")
	if err := fs.Parse(args); err != nil {
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
	if getenv(keyEnv) == "" || getenv(passwordEnv) == "" {
		_, _ = fmt.Fprintf(errOut, "server: set %s (vault passphrase) and %s (admin UI password)\n", keyEnv, passwordEnv)
		return 2
	}
	if err := serve(ctx, *listen, *dataDir, getenv(passwordEnv), errOut); err != nil && !errors.Is(err, context.Canceled) {
		_, _ = fmt.Fprintln(errOut, "server:", logx.Redact(err.Error()))
		return 1
	}
	return 0
}

func serve(ctx context.Context, listen, dataDir, password string, errOut io.Writer) error {
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
	poller := usage.NewPoller(&http.Client{Timeout: 20 * time.Second}, usagePoll)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go h.Run(ctx)
	go poller.Run(ctx, func() []vault.Account {
		var own []vault.Account
		for _, a := range v.List() {
			if reg.OwnerOf(a.ID).Server {
				own = append(own, a)
			}
		}
		return own
	}, nil)

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", h.ServeWS)
	mux.Handle("/", web.Handler(h, v, poller, password))
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
