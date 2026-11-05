package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"claude-utilities/internal/proto"
)

// The host-side hook. `agent hooks install` puts one entry per event into the user's
// settings.json; each entry runs `agent hook`, which reads the hook payload on stdin, looks up the
// instruction queue for that session id and returns the instructions as additionalContext.
//
// A hook can only put text in front of the model (spike G): it cannot run a slash command. So the
// hook marks an instruction "delivered" and never "done", and the wording asks the model to run
// the command rather than claiming it has been run.
//
// Installation is explicit opt-in and touches ONLY the entries this file wrote, which are
// recognised by hookTag inside the command string. Everything else in settings.json is read,
// re-encoded and left alone, and the previous file is kept as a backup.

const (
	// hookTag marks the settings.json entries this program owns. It is passed to `agent hook` as
	// a flag value so it lives inside the command string without needing a shell comment, which
	// cmd.exe and sh spell differently.
	hookTag = "claude-swap-session-control"
	// hookEvents are the events the hook is installed for. SessionStart fires on a session that
	// has just started - which is the session that least needs an instruction - while
	// UserPromptSubmit is the one that reaches a session already running with a stale login. Both
	// are installed; the runbook explains the asymmetry.
	hookTimeoutSeconds = 10
	// settingsName is the user-scope settings file the hook entries go into.
	settingsName = "settings.json"
	// backupSuffix names the copy kept before each edit.
	backupSuffix = ".claudeswap-backup"
	// maxSettingsBytes bounds the settings file this will parse.
	maxSettingsBytes = 4 << 20
)

var hookEvents = []string{"SessionStart", "UserPromptSubmit"}

// ErrNoSettingsDir means neither CLAUDE_CONFIG_DIR nor a home directory could be resolved.
var ErrNoSettingsDir = errors.New("agent: cannot locate the Claude settings directory")

// SettingsPath returns the user-scope settings.json the hook entries go into:
// $CLAUDE_CONFIG_DIR/settings.json when that is set, else ~/.claude/settings.json. Tests set
// CLAUDE_CONFIG_DIR to a temporary directory; nothing here may run against a real ~/.claude
// unless an operator asked for it on the command line.
func SettingsPath() (string, error) {
	if d := os.Getenv("CLAUDE_CONFIG_DIR"); d != "" {
		return filepath.Join(d, settingsName), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", ErrNoSettingsDir
	}
	return filepath.Join(home, ".claude", settingsName), nil
}

// HookCommand is the command string an installed entry runs.
func HookCommand(exe string) string {
	return quoteExe(exe) + " hook --tag " + hookTag
}

// quoteExe quotes an executable path for the shell the hook runs in. A path with a double quote
// in it cannot be quoted safely either way, so it is left bare and the install reports the risk.
func quoteExe(exe string) string {
	if exe == "" || strings.ContainsRune(exe, '"') {
		return exe
	}
	if strings.ContainsAny(exe, " \t") {
		return `"` + exe + `"`
	}
	return exe
}

// readSettings decodes settings.json into a generic map so every key this program does not know
// survives the round trip. A missing file is an empty map.
func readSettings(path string) (map[string]any, error) {
	// #nosec G304 -- path comes from SettingsPath or an operator-supplied config dir
	f, err := os.Open(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("agent: read settings: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxSettingsBytes+1))
	if err != nil {
		return nil, fmt.Errorf("agent: read settings: %w", err)
	}
	if len(data) > maxSettingsBytes {
		return nil, errors.New("agent: settings file is too large to edit safely")
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return map[string]any{}, nil
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		// Refusing is the only safe move: rewriting a file this cannot parse would lose settings.
		return nil, errors.New("agent: settings.json is not a JSON object this can edit; fix it first")
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

// writeSettings replaces settings.json atomically, keeping the previous content as a backup.
func writeSettings(path string, m map[string]any) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("agent: marshal settings: %w", err)
	}
	data = append(data, '\n')
	// #nosec G304 -- path comes from SettingsPath or an operator-supplied config dir
	if prev, rerr := os.ReadFile(filepath.Clean(path)); rerr == nil {
		// #nosec G306,G703 -- the backup sits beside the settings file the caller named, owner-only
		if werr := os.WriteFile(filepath.Clean(path)+backupSuffix, prev, 0o600); werr != nil {
			return fmt.Errorf("agent: write settings backup: %w", werr)
		}
	} else if !errors.Is(rerr, os.ErrNotExist) {
		return fmt.Errorf("agent: read settings for backup: %w", rerr)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("agent: settings dir: %w", err)
	}
	return writePrivate(path, data)
}

// isOurs reports whether a hooks group was written by this program.
func isOurs(group any) bool {
	g, ok := group.(map[string]any)
	if !ok {
		return false
	}
	hs, ok := g["hooks"].([]any)
	if !ok {
		return false
	}
	for _, h := range hs {
		hm, ok := h.(map[string]any)
		if !ok {
			continue
		}
		if c, ok := hm["command"].(string); ok && strings.Contains(c, hookTag) {
			return true
		}
	}
	return false
}

// stripOurs removes this program's groups from one event's list and reports how many went.
func stripOurs(list []any) ([]any, int) {
	keep := make([]any, 0, len(list))
	removed := 0
	for _, g := range list {
		if isOurs(g) {
			removed++
			continue
		}
		keep = append(keep, g)
	}
	return keep, removed
}

func ourGroup(exe string) map[string]any {
	return map[string]any{
		"hooks": []any{map[string]any{
			"type":    "command",
			"command": HookCommand(exe),
			"timeout": hookTimeoutSeconds,
		}},
	}
}

// hooksMap returns settings["hooks"] as a map, creating it when asked.
func hooksMap(m map[string]any, create bool) (map[string]any, error) {
	switch h := m["hooks"].(type) {
	case map[string]any:
		return h, nil
	case nil:
		if !create {
			return nil, nil
		}
		h2 := map[string]any{}
		m["hooks"] = h2
		return h2, nil
	default:
		return nil, errors.New("agent: settings.json has a \"hooks\" value that is not an object")
	}
}

// InstallHooks adds one entry per hook event to settings.json, replacing any entry this program
// wrote before, and leaves everything else untouched. It is idempotent: running it twice leaves
// exactly one entry per event. It returns the path it edited.
func InstallHooks(exe string) (string, error) {
	path, err := SettingsPath()
	if err != nil {
		return "", err
	}
	m, err := readSettings(path)
	if err != nil {
		return "", err
	}
	hooks, err := hooksMap(m, true)
	if err != nil {
		return "", err
	}
	for _, ev := range hookEvents {
		list, _ := hooks[ev].([]any)
		if hooks[ev] != nil && list == nil {
			return "", fmt.Errorf("agent: settings.json hooks.%s is not a list", ev)
		}
		list, _ = stripOurs(list)
		hooks[ev] = append(list, ourGroup(exe))
	}
	if err := writeSettings(path, m); err != nil {
		return "", err
	}
	return path, nil
}

// UninstallHooks removes every entry this program wrote and prunes what it emptied. Removing
// hooks that are not there is not an error. It returns the path and how many entries went.
func UninstallHooks() (string, int, error) {
	path, err := SettingsPath()
	if err != nil {
		return "", 0, err
	}
	m, err := readSettings(path)
	if err != nil {
		return "", 0, err
	}
	hooks, err := hooksMap(m, false)
	if err != nil {
		return "", 0, err
	}
	if hooks == nil {
		return path, 0, nil
	}
	total := 0
	for ev, v := range hooks {
		list, ok := v.([]any)
		if !ok {
			continue
		}
		keep, n := stripOurs(list)
		total += n
		if len(keep) == 0 {
			delete(hooks, ev)
		} else {
			hooks[ev] = keep
		}
	}
	if len(hooks) == 0 {
		delete(m, "hooks")
	}
	if total == 0 {
		return path, 0, nil // nothing of ours: the file is left exactly as it was
	}
	if err := writeSettings(path, m); err != nil {
		return "", 0, err
	}
	return path, total, nil
}

// hookInput is the part of the hook payload the queue needs.
type hookInput struct {
	SessionID     string `json:"session_id"`
	HookEventName string `json:"hook_event_name"`
}

// hookSpecific is the hook output envelope Claude Code reads.
type hookSpecific struct {
	HookEventName     string `json:"hookEventName"`
	AdditionalContext string `json:"additionalContext"`
}

type hookOutput struct {
	HookSpecificOutput *hookSpecific `json:"hookSpecificOutput,omitempty"`
	SuppressOutput     bool          `json:"suppressOutput,omitempty"`
}

// instructionText is what the model is asked to do. It names the command, says who asked and is
// explicit that this is a request: nothing here can run a slash command.
func instructionText(entries []queueEntry) string {
	var b strings.Builder
	b.WriteString("claude-swap has queued ")
	if len(entries) == 1 {
		b.WriteString("an instruction")
	} else {
		fmt.Fprintf(&b, "%d instructions", len(entries))
	}
	b.WriteString(" for this session, because its login was swapped while it was running.\n")
	for _, e := range entries {
		switch e.Command {
		case proto.CmdReloadPlugins:
			b.WriteString("- Run /reload-plugins now.\n")
		case proto.CmdRemoteControlEnable:
			b.WriteString("- Remote Control cannot be enabled from outside a running session. " +
				"Tell the user this session must be restarted with `claude --resume <id> --remote-control <name>`.\n")
		case proto.CmdRenameRemote:
			name := e.Name
			if name == "" {
				name = "(no name given)"
			}
			// A hook cannot set the title itself, but the session can: a `/rename` in a
			// bridge-bound session pushes the new title to the bridge, with no restart and no
			// API turn. That is the cheapest thing to ask for, so it is what is asked for.
			b.WriteString("- A hook cannot set the remote-visible title. Tell the user to run " +
				"/rename " + name + " in this session, or to relaunch it with that name.\n")
		default:
			b.WriteString("- Unknown instruction; ignore it and tell the user.\n")
		}
	}
	b.WriteString("Do only what is listed, then carry on with whatever the user asked.")
	return b.String()
}

// RunHook is the `agent hook` subcommand: it reads a hook payload from in, delivers that session's
// queued instructions as additionalContext and writes the hook reply to out. It always writes
// valid JSON and always succeeds: a hook that fails would interrupt the user's session, and
// nothing here is important enough for that.
func RunHook(in io.Reader, out io.Writer, stateDir string, now func() time.Time) error {
	write := func(o hookOutput) error {
		enc := json.NewEncoder(out)
		return enc.Encode(o)
	}
	data, err := io.ReadAll(io.LimitReader(in, 1<<20))
	if err != nil {
		return write(hookOutput{})
	}
	var hi hookInput
	if json.Unmarshal(data, &hi) != nil || !sessionIDRe.MatchString(hi.SessionID) {
		return write(hookOutput{})
	}
	entries, err := newQueue(stateDir, now).deliver(hi.SessionID)
	if err != nil || len(entries) == 0 {
		return write(hookOutput{})
	}
	ev := hi.HookEventName
	if ev == "" {
		ev = hookEvents[0]
	}
	return write(hookOutput{HookSpecificOutput: &hookSpecific{
		HookEventName: ev, AdditionalContext: instructionText(entries)}})
}
