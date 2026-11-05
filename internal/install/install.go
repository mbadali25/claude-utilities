// Package install registers the agent to start at login: a scheduled task on
// Windows, a systemd user unit on Linux. Nothing here handles credentials.
package install

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	taskName = "ClaudeSwapAgent"
	unitName = "claude-swap-agent.service"
	// StateDirEnv tells the agent where its state lives. The Linux unit sets it.
	StateDirEnv = "CLAUDESWAP_STATE_DIR"
)

// DefaultStateDirName is the directory under the user config dir that holds the agent's state.
const DefaultStateDirName = "claude-swap-agent"

// TaskStateDir is the state dir an agent resolves when StateDirEnv is unset, which is what the
// Windows logon task gets (schtasks passes no environment). It is the single source of the default.
func TaskStateDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("install: user config dir: %w", err)
	}
	return filepath.Join(base, DefaultStateDirName), nil
}

// taskStateDir is a seam for tests.
var taskStateDir = TaskStateDir

// oneLine drops line breaks so a path cannot inject extra unit directives.
func oneLine(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// execQuote escapes s for a double-quoted ExecStart= word: backslash and quote
// are escaped, and '%' and '$' are doubled so specifiers and variables are not
// expanded.
func execQuote(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%", "$", "$$").Replace(oneLine(s))
}

// envQuote escapes s for a double-quoted Environment= value. systemd expands
// specifiers (%) there but never '$', so '$' stays literal.
func envQuote(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%").Replace(oneLine(s))
}

// RenderSystemdUserUnit returns the unit file text for the agent. A user unit
// cannot order itself after network-online.target (that target belongs to the
// system manager), so the agent must retry its own connection; Restart=always
// covers a failed start, and the start limit stops a tight crash loop.
func RenderSystemdUserUnit(exe, stateDir string) string {
	return fmt.Sprintf(`[Unit]
Description=Claude Swap agent
StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
ExecStart="%s" run
Environment="%s=%s"
WorkingDirectory=%s
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
`, execQuote(exe), StateDirEnv, envQuote(stateDir), strings.ReplaceAll(oneLine(stateDir), "%", "%%"))
}

// SchtasksCreateArgs returns the schtasks arguments that register the agent to
// run at logon as user. The task command is `"<exe>" run`; the exe is quoted so
// a path with spaces stays one word, and an embedded quote is backslash-escaped.
// The result is one argument: exec quotes it again for the command line.
func SchtasksCreateArgs(exe, user string) []string {
	tr := `"` + strings.ReplaceAll(exe, `"`, `\"`) + `" run`
	return []string{"/Create", "/SC", "ONLOGON", "/TN", taskName, "/RU", user, "/TR", tr}
}

// IcaclsLockdownArgs returns the icacls arguments that remove inherited
// permissions from dir and grant user full control (the Windows form of 0700).
func IcaclsLockdownArgs(dir, user string) []string {
	return []string{dir, "/inheritance:r", "/grant:r", user + ":(OI)(CI)F"}
}

// checkExe requires an absolute path to an existing regular file without line
// breaks, so the unit or task cannot start something that is not there.
func checkExe(exe string) error {
	if strings.ContainsAny(exe, "\r\n") {
		return fmt.Errorf("install: executable path contains a line break")
	}
	if !filepath.IsAbs(exe) {
		return fmt.Errorf("install: executable path %q is not absolute", exe)
	}
	fi, err := os.Stat(exe)
	if err != nil {
		return fmt.Errorf("install: executable: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("install: executable %q is not a regular file", exe)
	}
	return nil
}

// absStateDir makes dir absolute and rejects line breaks (never silently
// altered, so the directory hardened is the directory the agent reads) and a
// symlink or junction at the path (Chmod would follow it and tighten another
// directory). Other reparse points, such as OneDrive placeholders, are allowed.
func absStateDir(dir string) (string, error) {
	if strings.ContainsAny(dir, "\r\n") {
		return "", fmt.Errorf("install: state dir contains a line break")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("install: state dir: %w", err)
	}
	if fi, err := os.Lstat(abs); err == nil && isLink(fi.Mode()) {
		return "", fmt.Errorf("install: state dir %q is a symlink or junction", abs)
	}
	return abs, nil
}

// isLink reports a symlink or a Windows junction (Go reports junctions as
// ModeIrregular).
func isLink(m os.FileMode) bool {
	return m&(os.ModeSymlink|os.ModeIrregular) != 0
}

// windowsUser joins USERDOMAIN and USERNAME.
func windowsUser() (string, error) {
	name := os.Getenv("USERNAME")
	if name == "" {
		return "", fmt.Errorf("install: USERNAME is not set")
	}
	if d := os.Getenv("USERDOMAIN"); d != "" {
		return d + `\` + name, nil
	}
	return name, nil
}

// runner runs an external command and returns its combined output.
type runner func(name string, args ...string) ([]byte, error)

func execRunner(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...) // #nosec G204 -- name/args come from fixed callers (icacls, schtasks), never user input
	return cmd.CombinedOutput()
}

// Install registers the agent for the current user.
func Install(exe, stateDir string) error {
	return installFor(runtime.GOOS, exe, stateDir, execRunner, os.Stdout)
}

func installFor(goos, exe, stateDir string, run runner, out io.Writer) error {
	if err := checkExe(exe); err != nil {
		return err
	}
	stateDir, err := absStateDir(stateDir)
	if err != nil {
		return err
	}
	if goos == "windows" {
		return installTask(exe, stateDir, run, out)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("install: home dir: %w", err)
	}
	path, err := installUnit(home, exe, stateDir)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "wrote %s\nnext: systemctl --user daemon-reload && systemctl --user enable --now %s\nto keep it running when logged out: loginctl enable-linger $USER\n", path, unitName)
	return nil
}

// installTask creates the state dir, locks it to the current user when it is
// new or empty, and registers the logon task.
func installTask(exe, stateDir string, run runner, out io.Writer) error {
	user, err := windowsUser()
	if err != nil {
		return err
	}
	// schtasks passes no environment, so the logon-run agent always uses the default state dir;
	// an install against any other dir would leave it unable to find its config.
	def, err := taskStateDir()
	if err != nil {
		return err
	}
	if !strings.EqualFold(filepath.Clean(def), filepath.Clean(stateDir)) {
		return fmt.Errorf("install: state dir %q differs from %q, which the logon task will use (schtasks cannot pass %s); unset %s and enrol again",
			stateDir, def, StateDirEnv, StateDirEnv)
	}
	fresh := true
	if ents, err := os.ReadDir(stateDir); err == nil {
		fresh = len(ents) == 0
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("install: state dir: %w", err)
	}
	if fresh { // never rewrite the ACL of a directory that already holds data
		if o, err := run("icacls", IcaclsLockdownArgs(stateDir, user)...); err != nil {
			return fmt.Errorf("install: icacls: %w: %s", err, strings.TrimSpace(string(o)))
		}
	}
	if o, err := run("schtasks", SchtasksCreateArgs(exe, user)...); err != nil {
		return fmt.Errorf("install: schtasks: %w: %s", err, strings.TrimSpace(string(o)))
	}
	_, _ = fmt.Fprintf(out, "registered scheduled task %s (starts at next logon)\nstart it now: schtasks /Run /TN %s\n", taskName, taskName)
	return nil
}

// installUnit writes the unit under home and returns its path.
func installUnit(home, exe, stateDir string) (string, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", fmt.Errorf("install: state dir: %w", err)
	}
	if err := os.Chmod(stateDir, 0o700); err != nil { // #nosec G302 -- directory needs the owner execute bit; 0o700 is owner-only
		return "", fmt.Errorf("install: state dir mode: %w", err)
	}
	dir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("install: unit dir: %w", err)
	}
	path := filepath.Join(dir, unitName)
	tmp, err := os.CreateTemp(dir, unitName+".*.tmp")
	if err != nil {
		return "", fmt.Errorf("install: write unit: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.WriteString(RenderSystemdUserUnit(exe, stateDir)); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("install: write unit: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("install: write unit: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("install: write unit: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return "", fmt.Errorf("install: write unit: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", fmt.Errorf("install: write unit: %w", err)
	}
	return path, nil
}
