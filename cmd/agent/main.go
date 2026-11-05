// Command agent runs on each host: enrol registers it with the server, run keeps it connected,
// install registers it to start at login.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"claude-utilities/internal/agent"
	"claude-utilities/internal/install"
	"claude-utilities/internal/logx"
)

const usage = `usage: agent <command>
  enrol   --server URL --pin SHA256HEX   register this host
          (pre-approved code: set CLAUDESWAP_ENROL_CODE, not a flag)
  run                                    connect and serve the server
  install                                start the agent at login`

// codeEnv names the environment variable holding the pre-approved enrolment code.
const codeEnv = "CLAUDESWAP_ENROL_CODE"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := dispatch(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// dispatch returns the process exit code: 0 ok, 1 error, 2 enrolment denied.
func dispatch(ctx context.Context, args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, usage)
		return 1
	}
	switch args[0] {
	case "enrol":
		return enrolCmd(ctx, args[1:], out, errOut)
	case "run":
		return runCmd(ctx, errOut)
	case "install":
		return installCmd(errOut)
	}
	fmt.Fprintln(errOut, usage)
	return 1
}

func enrolCmd(ctx context.Context, args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("enrol", flag.ContinueOnError)
	fs.SetOutput(errOut)
	server := fs.String("server", "", "server URL (https)")
	pin := fs.String("pin", "", "server certificate SHA-256 fingerprint (hex)")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *server == "" || *pin == "" {
		fmt.Fprintln(errOut, "enrol: --server and --pin are required")
		return 1
	}
	// The pre-approved code is a bearer secret: read it from the environment, never argv.
	code := os.Getenv(codeEnv)
	if _, err := agent.Enrol(ctx, *server, *pin, "", code, out); err != nil {
		fmt.Fprintln(errOut, "enrol:", logx.Redact(err.Error()))
		if errors.Is(err, agent.ErrDenied) {
			return 2
		}
		return 1
	}
	return 0
}

func runCmd(ctx context.Context, errOut io.Writer) int {
	dir, err := agent.DefaultStateDir()
	if err == nil {
		var cfg agent.Config
		if cfg, err = agent.LoadConfig(dir); err == nil {
			err = agent.Run(ctx, cfg)
		}
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(errOut, "run:", logx.Redact(err.Error()))
		return 1
	}
	return 0
}

func installCmd(errOut io.Writer) int {
	exe, err := os.Executable()
	if err == nil {
		var dir string
		if dir, err = agent.DefaultStateDir(); err == nil {
			err = install.Install(exe, dir)
		}
	}
	if err != nil {
		fmt.Fprintln(errOut, "install:", logx.Redact(err.Error()))
		return 1
	}
	return 0
}
