package proto

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestCommandReqNeverPrintsTheName(t *testing.T) {
	r := CommandReq{CommandID: "c1", Command: CmdRenameRemote, SessionID: "s1", PID: 7, Name: "Jane Doe laptop"}
	for _, s := range []string{r.String(), r.GoString(), fmt.Sprintf("%v %+v %s %#v", r, r, r, r)} {
		if strings.Contains(s, "Jane") {
			t.Fatalf("name leaked: %s", s)
		}
	}
	if !strings.Contains(r.String(), "c1") || !strings.Contains(r.String(), CmdRenameRemote) {
		t.Fatalf("command id and command should stay readable: %s", r.String())
	}
}

func TestCommandResNeverPrintsTheHint(t *testing.T) {
	r := CommandRes{CommandID: "c1", Status: StatusUnsupported, Code: CodeRequiresRestart,
		Mechanism: "relaunch", Hint: "claude --resume 1234 --remote-control \"Jane Doe laptop\""}
	for _, s := range []string{r.String(), r.GoString(), fmt.Sprintf("%v %+v %s %#v", r, r, r, r)} {
		if strings.Contains(s, "Jane") || strings.Contains(s, "--resume") {
			t.Fatalf("hint leaked: %s", s)
		}
	}
}

func TestCommandReqRoundTripsOverTheWire(t *testing.T) {
	in := CommandReq{CommandID: "c1", Command: CmdReloadPlugins, SessionID: "s1", PID: 9}
	b, err := Encode(TypeCommandReq, "req-1", in)
	if err != nil {
		t.Fatal(err)
	}
	env, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if env.Type != TypeCommandReq || env.ID != "req-1" {
		t.Fatalf("envelope = %+v", struct{ T, I string }{env.Type, env.ID})
	}
	var out CommandReq
	if err := json.Unmarshal(env.Body, &out); err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("round trip lost data")
	}
}

// An older agent sends a report with no commands field, and a newer one sends an empty slice:
// both must decode, so the field is additive in both directions.
func TestReportCommandsAreAdditive(t *testing.T) {
	var old Report
	if err := json.Unmarshal([]byte(`{"hostId":"h","sessions":[]}`), &old); err != nil {
		t.Fatal(err)
	}
	if len(old.Commands) != 0 {
		t.Fatalf("commands = %v", old.Commands)
	}
	raw, err := json.Marshal(Report{Commands: []SessionCommandStatus{{CommandID: "c1", Status: StatusDelivered}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"commandId":"c1"`) {
		t.Fatalf("commands not marshalled: %s", raw)
	}
	// A report without them must not emit the key at all, so an older hub sees the old shape.
	raw, err = json.Marshal(Report{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "commands") {
		t.Fatalf("empty commands should be omitted: %s", raw)
	}
}

func TestValidCommand(t *testing.T) {
	for _, c := range []string{CmdReloadPlugins, CmdRemoteControlEnable, CmdRenameRemote, CmdRepair,
		CmdRestartSessions} {
		if !ValidCommand(c) {
			t.Errorf("%s should be valid", c)
		}
	}
	for _, c := range []string{"", "reload", "rm -rf /", "RELOAD_PLUGINS"} {
		if ValidCommand(c) {
			t.Errorf("%q should not be valid", c)
		}
	}
}

// A restart-type command is the one class the hub confirms at EVERY scope, so the predicate has to
// name exactly restart_sessions: a command that wrongly reads as restart-type would start
// demanding a confirm nobody asks for, and one that wrongly reads as ordinary would skip the
// confirm that names the sessions.
func TestIsRestartCommand(t *testing.T) {
	if !IsRestartCommand(CmdRestartSessions) {
		t.Errorf("%s should be restart-type", CmdRestartSessions)
	}
	for _, c := range []string{CmdReloadPlugins, CmdRemoteControlEnable, CmdRenameRemote, CmdRepair, "", "restart"} {
		if IsRestartCommand(c) {
			t.Errorf("%q should not be restart-type", c)
		}
	}
}

func TestValidCommandStatus(t *testing.T) {
	for _, s := range []string{StatusQueued, StatusDelivered, StatusDone, StatusFailed, StatusUnsupported} {
		if !ValidCommandStatus(s) {
			t.Errorf("%s should be valid", s)
		}
	}
	for _, s := range []string{"", "ok", "QUEUED"} {
		if ValidCommandStatus(s) {
			t.Errorf("%q should not be valid", s)
		}
	}
}

func TestCleanRemoteNameDropsControlCharactersAndCaps(t *testing.T) {
	if got := CleanRemoteName("  a\x00b\tc  "); got != "a b c" {
		t.Fatalf("got %q", got)
	}
	long := strings.Repeat("é", MaxRemoteName+50)
	if got := CleanRemoteName(long); len([]rune(got)) != MaxRemoteName {
		t.Fatalf("got %d runes", len([]rune(got)))
	}
	if got := CleanRemoteName("\t\n "); got != "" {
		t.Fatalf("whitespace-only name should be empty, got %q", got)
	}
}
