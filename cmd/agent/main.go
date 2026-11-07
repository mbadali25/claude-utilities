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
	"path/filepath"
	"syscall"
	"time"

	"claude-utilities/internal/agent"
	"claude-utilities/internal/install"
	"claude-utilities/internal/logx"
)

const usage = `usage: agent <command>
  enrol   --server URL --pin SHA256HEX   register this host
          (pre-approved code: set CLAUDESWAP_ENROL_CODE, not a flag)
  run                                    connect and serve the server
  install                                start the agent at login
  hooks   install | uninstall            opt in to (or out of) the session-control hook;
                                         edits only this program's block in settings.json
  hook    --tag TAG [--state-dir DIR]    the hook itself: reads the hook payload on stdin`

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
		_, _ = fmt.Fprintln(errOut, usage)
		return 1
	}
	switch args[0] {
	case "enrol":
		return enrolCmd(ctx, args[1:], out, errOut)
	case "run":
		return runCmd(ctx, errOut)
	case "install":
		return installCmd(errOut)
	case "hooks":
		return hooksCmd(args[1:], out, errOut)
	case "hook":
		return hookCmd(args[1:], os.Stdin, out)
	}
	_, _ = fmt.Fprintln(errOut, usage)
	return 1
}

// hooksCmd installs or removes the session-control hook. It is explicit opt-in: nothing else in
// this program edits the user's settings.json, and the previous file is kept as a backup.
func hooksCmd(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(errOut, "hooks: say install or uninstall")
		return 1
	}
	switch args[0] {
	case "install":
		exe, err := os.Executable()
		if err != nil {
			_, _ = fmt.Fprintln(errOut, "hooks install:", logx.Redact(err.Error()))
			return 1
		}
		// The hook runs without the unit's environment, so bake in the dir this install resolves.
		stateDir, err := agent.DefaultStateDir()
		if err != nil {
			_, _ = fmt.Fprintln(errOut, "hooks install:", logx.Redact(err.Error()))
			return 1
		}
		path, err := agent.InstallHooks(exe, stateDir)
		if err != nil {
			_, _ = fmt.Fprintln(errOut, "hooks install:", logx.Redact(err.Error()))
			return 1
		}
		_, _ = fmt.Fprintln(out, "hook installed in", path)
		return 0
	case "uninstall":
		path, n, err := agent.UninstallHooks()
		if err != nil {
			_, _ = fmt.Fprintln(errOut, "hooks uninstall:", logx.Redact(err.Error()))
			return 1
		}
		_, _ = fmt.Fprintf(out, "removed %d hook entries from %s\n", n, path)
		return 0
	}
	_, _ = fmt.Fprintln(errOut, "hooks: say install or uninstall")
	return 1
}

// hookCmd is the hook itself. It always writes valid JSON and always exits 0: a hook that fails
// interrupts the user's session, and nothing it carries is worth that. The --tag flag exists so
// the installed command string carries a marker the installer can recognise; its value is unused.
// --state-dir wins over the environment; without it (an entry installed by an older build) the
// default state dir applies.
func hookCmd(args []string, in io.Reader, out io.Writer) int {
	fs := flag.NewFlagSet("hook", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	_ = fs.String("tag", "", "marker for the installer; unused")
	stateDir := fs.String("state-dir", "", "agent state dir")
	if err := fs.Parse(args); err != nil {
		_, _ = fmt.Fprintln(out, "{}")
		return 0
	}
	dir := *stateDir
	if dir == "" {
		var err error
		if dir, err = agent.DefaultStateDir(); err != nil {
			_, _ = fmt.Fprintln(out, "{}")
			return 0
		}
	}
	if err := agent.RunHook(in, out, dir, time.Now); err != nil {
		_, _ = fmt.Fprintln(out, "{}")
	}
	return 0
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
		_, _ = fmt.Fprintln(errOut, "enrol: --server and --pin are required")
		return 1
	}
	// The pre-approved code is a bearer secret: read it from the environment, never argv.
	code := os.Getenv(codeEnv)
	if _, err := agent.Enrol(ctx, *server, *pin, "", code, out); err != nil {
		_, _ = fmt.Fprintln(errOut, "enrol:", logx.Redact(err.Error()))
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
		_, _ = fmt.Fprintln(errOut, "run:", logx.Redact(err.Error()))
		if errors.Is(err, os.ErrNotExist) {
			logMissingConfig(errOut, dir)
		}
		return 1
	}
	return 0
}

// runLogName is the file, under the default state dir, that records why `run` could not start.
const runLogName = "agent-run.log"

// logMissingConfig explains a missing agent.json on stderr and in a file under the default state
// dir. The logon task passes no environment, so this is where an operator finds out that
// CLAUDESWAP_STATE_DIR was set at enrol time but not for the task.
func logMissingConfig(errOut io.Writer, tried string) {
	w := errOut
	if def, err := install.TaskStateDir(); err == nil && os.MkdirAll(def, 0o700) == nil {
		// #nosec G304 -- def is the fixed per-user default state dir plus a constant name
		if f, ferr := os.OpenFile(filepath.Join(def, runLogName), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); ferr == nil {
			defer func() { _ = f.Close() }()
			w = io.MultiWriter(errOut, f)
		}
	}
	logx.New(w).Error("agent config missing: run `agent enrol` first, and make "+install.StateDirEnv+
		" the same for enrol and the logon task (tried "+tried+")",
		"component", "agent", "action", "run", "result", "no config")
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
		_, _ = fmt.Fprintln(errOut, "install:", logx.Redact(err.Error()))
		return 1
	}
	return 0
}
