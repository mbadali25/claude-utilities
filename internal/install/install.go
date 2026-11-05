// Package install registers the agent to start at login: a scheduled task on
// Windows, a systemd user unit on Linux. Nothing here handles credentials.
package install

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf16"
)

const (
	taskName = "ClaudeSwapAgent"
	unitName = "claude-swap-agent.service"
	// StateDirEnv tells the agent where its state lives. The unit and the
	// scheduled task both set it.
	StateDirEnv = "CLAUDESWAP_STATE_DIR"
)

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

// RenderSystemdUserUnit returns the unit file text for the agent.
func RenderSystemdUserUnit(exe, stateDir string) string {
	return fmt.Sprintf(`[Unit]
Description=Claude Swap agent
After=network-online.target
Wants=network-online.target

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

// RenderTaskXML returns the Task Scheduler definition of the agent task. Unlike
// schtasks switches it can lift the 72-hour limit, keep running on battery and
// restart the agent when it exits. The action runs the agent through cmd so the
// task can set StateDirEnv. exe and stateDir must not contain '"' or '%'
// (checked by checkWindowsPath, along with & ^ ! < > |).
func RenderTaskXML(exe, stateDir, user string) string {
	cmdArgs := fmt.Sprintf(`/d /s /c "set "%s=%s" && "%s" run"`, StateDirEnv, stateDir, exe)
	esc := func(s string) string {
		var b bytes.Buffer
		_ = xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>%[1]s</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>%[1]s</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>%[2]s</Arguments>
    </Exec>
  </Actions>
</Task>
`, esc(user), esc(cmdArgs))
}

// SchtasksCreateArgs returns the schtasks arguments that register the task
// defined in the XML file at xmlPath. /F replaces an existing task so a second
// install succeeds. The XML principal is the interactive user, so no password
// is needed.
func SchtasksCreateArgs(xmlPath string) []string {
	return []string{"/Create", "/F", "/TN", taskName, "/XML", xmlPath}
}

// IcaclsLockdownArgs returns the icacls arguments that remove inherited
// permissions from dir and grant user full control (the Windows form of 0700).
func IcaclsLockdownArgs(dir, user string) []string {
	return []string{dir, "/inheritance:r", "/grant:r", user + ":(OI)(CI)F"}
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

// absStateDir makes dir absolute and rejects line breaks (never silently
// altered, so the directory hardened is the directory the agent reads) and a
// symlink at the path (Chmod would follow it and tighten another directory).
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

// isLink reports a symlink, or a Windows junction/reparse point (Go reports
// those as ModeIrregular).
func isLink(m os.FileMode) bool {
	return m&(os.ModeSymlink|os.ModeIrregular) != 0
}

// checkWindowsPath rejects characters that would break or escape the cmd
// wrapper. Parentheses stay allowed ("Program Files (x86)") because they are
// inert inside the quoted words.
func checkWindowsPath(what, p string) error {
	if strings.ContainsAny(p, "\"%&^!<>|") {
		return fmt.Errorf("install: %s contains a quote or one of %% & ^ ! < > |", what)
	}
	return nil
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
	return exec.Command(name, args...).CombinedOutput()
}

// Install registers the agent for the current user.
func Install(exe, stateDir string) error {
	return installFor(runtime.GOOS, exe, stateDir, execRunner, os.Stdout)
}

func installFor(goos, exe, stateDir string, run runner, out io.Writer) error {
	exe, err := absExe(exe)
	if err != nil {
		return err
	}
	if stateDir, err = absStateDir(stateDir); err != nil {
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
	fmt.Fprintf(out, "wrote %s\nnext: systemctl --user daemon-reload && systemctl --user enable --now %s\nto keep it running when logged out: loginctl enable-linger $USER\n", path, unitName)
	return nil
}

// installTask creates the owner-only state dir and registers the task.
func installTask(exe, stateDir string, run runner, out io.Writer) error {
	if err := checkWindowsPath("executable path", exe); err != nil {
		return err
	}
	if err := checkWindowsPath("state dir", stateDir); err != nil {
		return err
	}
	user, err := windowsUser()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("install: state dir: %w", err)
	}
	if o, err := run("icacls", IcaclsLockdownArgs(stateDir, user)...); err != nil {
		return fmt.Errorf("install: icacls: %w: %s", err, strings.TrimSpace(string(o)))
	}
	xmlFile, err := os.CreateTemp("", "claude-swap-task-*.xml")
	if err != nil {
		return fmt.Errorf("install: task xml: %w", err)
	}
	defer os.Remove(xmlFile.Name())
	_, werr := xmlFile.Write(utf16LE(RenderTaskXML(exe, stateDir, user)))
	if cerr := xmlFile.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("install: task xml: %w", werr)
	}
	if o, err := run("schtasks", SchtasksCreateArgs(xmlFile.Name())...); err != nil {
		return fmt.Errorf("install: schtasks: %w: %s", err, strings.TrimSpace(string(o)))
	}
	fmt.Fprintf(out, "registered scheduled task %s\n", taskName)
	return nil
}

// utf16LE encodes s as UTF-16 little endian with a byte order mark, the
// encoding schtasks /XML expects.
func utf16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 0, 2+2*len(u))
	b = append(b, 0xFF, 0xFE)
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return b
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
	if err := tmp.Sync(); err != nil {
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
