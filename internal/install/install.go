// Package install registers the agent to start at login: a scheduled task on
// Windows, a systemd user unit on Linux. Nothing here handles credentials.
package install

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	taskName = "ClaudeSwapAgent"
	unitName = "claude-swap-agent.service"
	// StateDirEnv tells the agent where its state lives. The unit sets it.
	StateDirEnv = "CLAUDESWAP_STATE_DIR"
)

// oneLine drops line breaks so a path cannot inject extra unit directives.
func oneLine(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// unitQuote escapes s for a double-quoted systemd value: backslash and quote
// are escaped, and '%' and '$' are doubled so specifiers and variables are not
// expanded.
func unitQuote(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%", "$", "$$").Replace(oneLine(s))
}

// RenderSystemdUserUnit returns the unit file text for the agent.
func RenderSystemdUserUnit(exe, stateDir string) string {
	return fmt.Sprintf(`[Unit]
Description=Claude Swap agent

[Service]
ExecStart="%s" run
Environment="%s=%s"
WorkingDirectory=%s
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
`, unitQuote(exe), StateDirEnv, unitQuote(stateDir), strings.ReplaceAll(oneLine(stateDir), "%", "%%"))
}

// SchtasksCreateArgs returns the schtasks arguments that register the agent
// to run at logon for user (DOMAIN\name or MACHINE\name). /IT runs it in the
// user's interactive session so no password is needed; /F replaces an existing
// task so a second install succeeds. exe must not contain a double quote.
func SchtasksCreateArgs(exe, user string) []string {
	return []string{"/Create", "/F", "/SC", "ONLOGON", "/RL", "LIMITED", "/IT", "/TN", taskName, "/RU", user, "/TR", `"` + exe + `" run`}
}

// absExe makes exe absolute and rejects characters that break quoting.
func absExe(exe string) (string, error) {
	if strings.ContainsAny(exe, "\"\r\n") {
		return "", fmt.Errorf("install: executable path contains a quote or line break")
	}
	abs, err := filepath.Abs(exe)
	if err != nil {
		return "", fmt.Errorf("install: absolute path: %w", err)
	}
	return abs, nil
}

// windowsUser joins USERDOMAIN and USERNAME for /RU.
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

// Install registers the agent for the current user.
func Install(exe, stateDir string) error {
	exe, err := absExe(exe)
	if err != nil {
		return err
	}
	if stateDir, err = filepath.Abs(stateDir); err != nil {
		return fmt.Errorf("install: state dir: %w", err)
	}
	if runtime.GOOS == "windows" {
		user, err := windowsUser()
		if err != nil {
			return err
		}
		out, err := exec.Command("schtasks", SchtasksCreateArgs(exe, user)...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("install: schtasks: %w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("install: home dir: %w", err)
	}
	path, err := installUnit(home, exe, stateDir)
	if err != nil {
		return err
	}
	fmt.Printf("wrote %s\nnext: systemctl --user daemon-reload && systemctl --user enable --now %s\nto keep it running when logged out: loginctl enable-linger $USER\n", path, unitName)
	return nil
}

// installUnit writes the unit under home and returns its path.
func installUnit(home, exe, stateDir string) (string, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", fmt.Errorf("install: state dir: %w", err)
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		return "", fmt.Errorf("install: state dir mode: %w", err)
	}
	dir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("install: unit dir: %w", err)
	}
	path := filepath.Join(dir, unitName)
	tmp, err := os.CreateTemp(dir, unitName+".*.tmp")
	if err != nil {
		return "", fmt.Errorf("install: write unit: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(RenderSystemdUserUnit(exe, stateDir)); err != nil {
		tmp.Close()
		return "", fmt.Errorf("install: write unit: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("install: write unit: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return "", fmt.Errorf("install: write unit: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", fmt.Errorf("install: write unit: %w", err)
	}
	return path, nil
}
