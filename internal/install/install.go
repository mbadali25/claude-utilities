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
)

// oneLine drops line breaks so a path cannot inject extra unit directives.
func oneLine(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// RenderSystemdUserUnit returns the unit file text for the agent.
func RenderSystemdUserUnit(exe, stateDir string) string {
	return fmt.Sprintf(`[Unit]
Description=Claude Swap agent

[Service]
ExecStart="%s" run
WorkingDirectory=%s
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
`, oneLine(exe), oneLine(stateDir))
}

// SchtasksCreateArgs returns the schtasks arguments that register the agent
// to run at logon for user.
func SchtasksCreateArgs(exe, user string) []string {
	return []string{"/Create", "/SC", "ONLOGON", "/TN", taskName, "/RU", user, "/TR", `"` + exe + `" run`}
}

// Install registers the agent for the current user.
func Install(exe, stateDir string) error {
	if runtime.GOOS == "windows" {
		user := os.Getenv("USERNAME")
		if user == "" {
			return fmt.Errorf("install: USERNAME is not set")
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
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("install: state dir: %w", err)
	}
	dir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("install: unit dir: %w", err)
	}
	path := filepath.Join(dir, unitName)
	if err := os.WriteFile(path, []byte(RenderSystemdUserUnit(exe, stateDir)), 0o644); err != nil {
		return fmt.Errorf("install: write unit: %w", err)
	}
	fmt.Printf("wrote %s\nnext: systemctl --user daemon-reload && systemctl --user enable --now %s\nto keep it running when logged out: loginctl enable-linger $USER\n", path, unitName)
	return nil
}
