package service

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The unit text is the spec's, character for character, for the spec's own example arguments. A
// golden string rather than a set of Contains checks, so a reordered or dropped directive fails
// loudly and the diff shows exactly which line moved.
const (
	goldenExe    = "/usr/local/bin/claude-swap-server"
	goldenListen = "192.0.2.10:8443"
	goldenData   = "/var/lib/claude-swap/data"
)

const goldenServerUnit = `[Unit]
Description=Claude Swap server
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5
OnFailure=claude-swap-server-failed.service

[Service]
Type=notify
NotifyAccess=main
User=claude-swap
Group=claude-swap
ExecStart=/usr/local/bin/claude-swap-server run --listen 192.0.2.10:8443 --data-dir /var/lib/claude-swap/data
StateDirectory=claude-swap
# No credential line here: service install does not yet know which KEK form this host gets.
# migrate / init / add-slot --type kek-file write the drop-in below and run daemon-reload.
Restart=on-failure
RestartSec=5
RestartSteps=4
RestartMaxDelaySec=120
RestartPreventExitStatus=2 3 4 5
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/claude-swap
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
AmbientCapabilities=
LockPersonality=yes
MemoryDenyWriteExecute=yes

[Install]
WantedBy=multi-user.target
`

// lines returns the unit's lines, so a test can ask "is there a line that starts with X" and not
// "does the text contain X somewhere, perhaps in a comment".
func lines(s string) []string { return strings.Split(strings.TrimRight(s, "\n"), "\n") }

func hasLine(s, want string) bool {
	for _, l := range lines(s) {
		if l == want {
			return true
		}
	}
	return false
}

func countLines(s, want string) int {
	n := 0
	for _, l := range lines(s) {
		if l == want {
			n++
		}
	}
	return n
}

func hasLinePrefix(s, prefix string) bool {
	for _, l := range lines(s) {
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	return false
}

func TestServerUnitMatchesTheGoldenString(t *testing.T) {
	got := mustRender(t, goldenExe, goldenListen, goldenData, false)
	if got != goldenServerUnit {
		t.Fatalf("unit differs from the spec's text.\n--- got ---\n%s\n--- want ---\n%s", got, goldenServerUnit)
	}
}

func TestServerUnitHasNoCredentialLine(t *testing.T) {
	// The drop-in owns it: a unit naming a credential that does not exist fails before ExecStart.
	got := mustRender(t, goldenExe, goldenListen, goldenData, false)
	for _, l := range lines(got) {
		if strings.HasPrefix(l, "LoadCredential") || strings.HasPrefix(l, "ImportCredential") ||
			strings.HasPrefix(l, "SetCredential") {
			t.Fatalf("the unit carries a credential line %q; only the drop-in may", l)
		}
	}
}

func TestServerUnitRestartPreventExitStatusIsFromTheServerTable(t *testing.T) {
	want := "RestartPreventExitStatus=" + ServerTable().RestartPreventExitStatus()
	got := mustRender(t, goldenExe, goldenListen, goldenData, false)
	if !hasLine(got, want) {
		t.Fatalf("unit has no line %q:\n%s", want, got)
	}
	// 243 is systemd's own exec-setup failure and is deliberately NOT relied on: the bound for a
	// missing credential is the start limit, the OnFailure marker and the preflight.
	if strings.Contains(got, "243") {
		t.Fatalf("the unit relies on exit 243, which the plan says it must not:\n%s", got)
	}
}

func TestServerUnitHasTypeNotifyAndNotifyAccessMain(t *testing.T) {
	got := mustRender(t, goldenExe, goldenListen, goldenData, false)
	for _, want := range []string{"Type=notify", "NotifyAccess=main"} {
		if !hasLine(got, want) {
			t.Errorf("unit has no line %q", want)
		}
	}
}

func TestServerUnitHasTheStartLimitPairAndOnFailure(t *testing.T) {
	// 300/5, the same numbers as the spec's block, not the 120/3 an earlier draft carried.
	got := mustRender(t, goldenExe, goldenListen, goldenData, false)
	for _, want := range []string{
		"StartLimitIntervalSec=300",
		"StartLimitBurst=5",
		"OnFailure=" + FailureUnitName,
	} {
		if !hasLine(got, want) {
			t.Errorf("unit has no line %q", want)
		}
	}
	if FailureUnitName != "claude-swap-server-failed.service" {
		t.Errorf("FailureUnitName = %q", FailureUnitName)
	}
}

func TestServerUnitHasTheHardeningDirectives(t *testing.T) {
	got := mustRender(t, goldenExe, goldenListen, goldenData, false)
	for _, want := range []string{
		"ProtectSystem=strict",
		"ProtectHome=yes",
		"ReadWritePaths=/var/lib/claude-swap",
		"CapabilityBoundingSet=",
		"MemoryDenyWriteExecute=yes",
		"NoNewPrivileges=yes",
		"PrivateTmp=yes",
		"PrivateDevices=yes",
	} {
		if !hasLine(got, want) {
			t.Errorf("unit has no line %q", want)
		}
	}
}

func TestServerUnitNeverContainsASecret(t *testing.T) {
	got := mustRender(t, goldenExe, goldenListen, goldenData, true)
	for _, bad := range []string{"CLAUDESWAP_KEY", "CLAUDESWAP_ADMIN_PASSWORD", "password", "passphrase", "token", "Environment="} {
		if strings.Contains(strings.ToLower(got), strings.ToLower(bad)) {
			t.Errorf("unit mentions %q", bad)
		}
	}
}

func TestServerUnitTunnelsAddsTheFlagOnly(t *testing.T) {
	off := mustRender(t, goldenExe, goldenListen, goldenData, false)
	on := mustRender(t, goldenExe, goldenListen, goldenData, true)
	if strings.Contains(off, "--tunnels") {
		t.Fatalf("tunnels off but the unit has the flag:\n%s", off)
	}
	want := "ExecStart=/usr/local/bin/claude-swap-server run --listen 192.0.2.10:8443 --data-dir /var/lib/claude-swap/data --tunnels"
	if !hasLine(on, want) {
		t.Fatalf("tunnels on: no line %q in:\n%s", want, on)
	}
	if strings.Replace(on, " --tunnels", "", 1) != off {
		t.Fatal("tunnels changes more than the one flag")
	}
}

func TestServerUnitDataDirOutsideTheStateDirectoryIsWritable(t *testing.T) {
	// ProtectSystem=strict makes everything read-only but ReadWritePaths, so a data dir the operator
	// put elsewhere would otherwise fail on its first write.
	got := mustRender(t, goldenExe, goldenListen, "/srv/swap data", false)
	if !hasLine(got, `ReadWritePaths=/var/lib/claude-swap "/srv/swap data"`) {
		t.Fatalf("an outside data dir is not writable:\n%s", got)
	}
	if !hasLine(mustRender(t, goldenExe, goldenListen, "/var/lib/claude-swap", false), "ReadWritePaths=/var/lib/claude-swap") {
		t.Fatal("the state directory itself must not be listed twice")
	}
}

// parseExec splits an ExecStart value the way systemd does for the subset the renderer emits:
// whitespace separates words, double quotes group one, a backslash escapes inside quotes (\n is a
// newline), and $$ and %% are the escaped forms of $ and %. It is the test's independent reading of
// the renderer's quoting, so a hostile argument has to survive as ONE argv entry to pass.
func parseExec(t *testing.T, v string) []string {
	t.Helper()
	var argv []string
	var cur strings.Builder
	inWord, inQuote := false, false
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case inQuote && c == '\\' && i+1 < len(v):
			i++
			switch v[i] {
			case 'n':
				cur.WriteByte('\n')
			case 'r':
				cur.WriteByte('\r')
			default:
				cur.WriteByte(v[i])
			}
		case c == '"':
			inQuote, inWord = !inQuote, true
		case !inQuote && (c == ' ' || c == '\t'):
			if inWord {
				argv = append(argv, cur.String())
				cur.Reset()
				inWord = false
			}
		case (c == '$' || c == '%') && i+1 < len(v) && v[i+1] == c:
			cur.WriteByte(c)
			i++
			inWord = true
		case c == '$' || c == '%':
			t.Fatalf("unescaped %q at %d in %s", c, i, v)
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if inQuote {
		t.Fatalf("unterminated quote in %s", v)
	}
	if inWord {
		argv = append(argv, cur.String())
	}
	return argv
}

func execStartOf(t *testing.T, unit string) string {
	t.Helper()
	for _, l := range lines(unit) {
		if v, ok := strings.CutPrefix(l, "ExecStart="); ok {
			return v
		}
	}
	t.Fatalf("no ExecStart in:\n%s", unit)
	return ""
}

func TestServerUnitCannotBeInjectedThroughAnArgument(t *testing.T) {
	// A newline in an argument would start a new directive; a $ or % would be expanded by systemd.
	evilData := "/x\nExecStartPre=/bin/evil\n[Service]"
	evilListen := "$HOME:%h"
	got := mustRender(t, goldenExe, evilListen, evilData, false)
	if hasLinePrefix(got, "ExecStartPre") || countLines(got, "[Service]") != 1 {
		t.Fatalf("an argument injected a directive:\n%s", got)
	}
	argv := parseExec(t, execStartOf(t, got))
	want := []string{goldenExe, "run", "--listen", evilListen, "--data-dir", evilData}
	if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("argv = %q, want %q", argv, want)
	}
}

func TestServerUnitExecutablePrefixCharsAreDefused(t *testing.T) {
	// systemd reads `+ - @ : !` in front of the executable as options before it looks at quotes: `+`
	// would run the server with full privileges outside the sandbox. The first word opening with one
	// is quoted, which turns it into a (relative, and so refused) path.
	for _, exe := range []string{"+/bin/evil", "-/bin/evil", "@/bin/evil", ":/bin/evil", "!/bin/evil"} {
		v := execStartOf(t, mustRender(t, exe, goldenListen, goldenData, false))
		if strings.ContainsRune("@-:+!", rune(v[0])) {
			t.Errorf("exe %q: ExecStart= starts with an option character: %s", exe, v)
		}
		if argv := parseExec(t, v); argv[0] != exe {
			t.Errorf("exe %q: argv[0] = %q", exe, argv[0])
		}
	}
}

func TestServerUnitRelativeDataDirIsRefused(t *testing.T) {
	// A leading - or + on a ReadWritePaths entry is an option applied after unquoting, and a relative
	// path cannot be named there at all, so under ProtectSystem=strict the unit would fail on the
	// first write. Refuse to render it rather than render a unit that cannot work.
	for _, d := range []string{"", "-/etc", "+/etc", "relative/dir", "./data"} {
		got, err := RenderServerUnit(goldenExe, goldenListen, d, false)
		if err == nil {
			t.Errorf("data dir %q: no error, unit:\n%s", d, got)
		}
		if got != "" {
			t.Errorf("data dir %q: rendered a unit alongside the error:\n%s", d, got)
		}
		if err != nil && !errors.Is(err, ErrDataDirNotAbsolute) {
			t.Errorf("data dir %q: err = %v, want ErrDataDirNotAbsolute", d, err)
		}
	}
}

// mustRender renders the server unit for an absolute data dir and fails the test on an error.
func mustRender(t *testing.T, exe, listen, dataDir string, tunnels bool) string {
	t.Helper()
	got, err := RenderServerUnit(exe, listen, dataDir, tunnels)
	if err != nil {
		t.Fatalf("RenderServerUnit(%q): %v", dataDir, err)
	}
	return got
}

func TestFailureUnitCreatesNothingAboveTheLogsDirectory(t *testing.T) {
	// It runs as root; the data dir belongs to the service account. A mkdir -p here would make a
	// missing data dir root-owned 0700 and the service could never start again.
	script := parseExec(t, execStartOf(t, RenderFailureUnit(goldenData)))[2]
	if strings.Contains(script, "mkdir -p") {
		t.Fatalf("the script creates parents:\n%s", script)
	}
	for _, want := range []string{`[ -d "$parent" ]`, `chown --reference="$parent"`} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q:\n%s", want, script)
		}
	}
}

func TestFailureUnitWritesTheMarkerAndNoValues(t *testing.T) {
	got := RenderFailureUnit(goldenData)
	if !hasLine(got, "Type=oneshot") {
		t.Errorf("failure unit is not Type=oneshot:\n%s", got)
	}
	for _, want := range []string{
		MarkerFileName,
		"MONITOR_SERVICE_RESULT", "MONITOR_EXIT_CODE", "MONITOR_EXIT_STATUS",
		"/var/lib/claude-swap/data/logs", // the directory service status reads
		"credential=" + credentialName,   // names the credential on exec status 243, by name only
	} {
		if !strings.Contains(got, want) {
			t.Errorf("failure unit does not mention %q:\n%s", want, got)
		}
	}
	// The failure unit is handed three words and a number by systemd; it must never go near the
	// environment of the failed service, the credential directory or any key.
	for _, bad := range []string{"CREDENTIALS_DIRECTORY", "CLAUDESWAP_KEY", "systemd-creds", "/etc/credstore", "cat "} {
		if strings.Contains(got, bad) {
			t.Errorf("failure unit mentions %q", bad)
		}
	}
	if hasLinePrefix(got, "LoadCredential") {
		t.Error("failure unit loads a credential")
	}
}

func TestFailureUnitMarkerDirIsPassedAsDataNotCode(t *testing.T) {
	// The directory arrives as a positional argument after the script, so a hostile path is one
	// argv entry and never part of the shell program.
	hostile := "/x\"; touch /pwned; echo \"'$(id)`%h"
	got := RenderFailureUnit(hostile)
	argv := parseExec(t, execStartOf(t, got))
	if len(argv) != 5 || argv[0] != "/bin/sh" || argv[1] != "-c" {
		t.Fatalf("argv = %q, want /bin/sh -c <script> <name> <dir>", argv)
	}
	if strings.Contains(argv[2], "pwned") || strings.Contains(argv[2], hostile) {
		t.Fatalf("the hostile path is inside the script:\n%s", argv[2])
	}
	if argv[4] != hostile+"/logs" {
		t.Fatalf("marker dir = %q, want %q", argv[4], hostile+"/logs")
	}
}

func TestFailureUnitScriptReadsOnlyTheMonitorVariablesAndWritesOneFile(t *testing.T) {
	argv := parseExec(t, execStartOf(t, RenderFailureUnit(goldenData)))
	script := argv[2]
	for _, want := range []string{"MONITOR_SERVICE_RESULT", "MONITOR_EXIT_CODE", "MONITOR_EXIT_STATUS", "umask 077", "mv "} {
		if !strings.Contains(script, want) {
			t.Errorf("script does not contain %q:\n%s", want, script)
		}
	}
	// The script is the thing a failed start runs as root: it may not follow a path it was not given.
	for _, bad := range []string{"eval", "$(cat", "source ", "curl", "wget"} {
		if strings.Contains(script, bad) {
			t.Errorf("script contains %q", bad)
		}
	}
}

// runFailureScript runs the failure unit's real script under /bin/sh with a stub chown and returns
// its one journal line and the stub's call log. The stub fails for the logs directory when dirFails
// and for the marker when fileFails, and records every call. logsExist pre-creates the logs
// directory, so the script takes the path where it does not chown the directory.
//
// It needs a Linux userland (GNU date, /proc/uptime), so it skips elsewhere rather than pass without
// having run anything.
func runFailureScript(t *testing.T, logsExist, dirFails, fileFails bool) (out, calls string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the failure script needs a Linux userland")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh on PATH")
	}
	data := filepath.Join(t.TempDir(), "data")
	logs := filepath.Join(data, markerLogsDir)
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	if logsExist {
		if err := os.Mkdir(logs, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	status := func(fails bool) string {
		if fails {
			return "1"
		}
		return "0"
	}
	stubs, callLog := t.TempDir(), filepath.Join(t.TempDir(), "calls")
	stub := "#!/bin/sh\necho \"$*\" >> '" + callLog + "'\n" +
		"case \"$2\" in *" + MarkerFileName + ") exit " + status(fileFails) + " ;; esac\nexit " + status(dirFails) + "\n"
	if err := os.WriteFile(filepath.Join(stubs, "chown"), []byte(stub), 0o700); err != nil {
		t.Fatal(err)
	}
	script := parseExec(t, execStartOf(t, RenderFailureUnit(data)))[2]
	cmd := exec.Command(sh, "-c", script, "claude-swap-server-failed", logs)
	cmd.Env = append(os.Environ(), "PATH="+stubs+string(os.PathListSeparator)+os.Getenv("PATH"),
		"MONITOR_SERVICE_RESULT=exit-code", "MONITOR_EXIT_CODE=exited", "MONITOR_EXIT_STATUS=1")
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("script failed: %v\n%s", err, b)
	}
	if _, err := os.Stat(filepath.Join(logs, MarkerFileName)); err != nil {
		t.Fatalf("marker not written: %v\n%s", err, b)
	}
	c, _ := os.ReadFile(callLog)
	return string(b), string(c)
}

func TestFailureScriptReportsAFailedChownInsteadOfSilencingIt(t *testing.T) {
	// chown --reference is GNU-only. A failure leaves the marker root:root in a directory the service
	// account owns, where the reader cannot open it, so the journal line has to say so. Each row fails
	// exactly one chown, so deleting either call (or its `|| own=failed`) turns a row red.
	for _, c := range []struct {
		name                           string
		logsExist, dirFails, fileFails bool
	}{
		{"the logs directory chown fails", false, true, false},
		{"the marker chown fails after the directory was made", false, false, true},
		{"the marker chown fails on an existing logs directory", true, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			out, _ := runFailureScript(t, c.logsExist, c.dirFails, c.fileFails)
			if !strings.Contains(out, "marker=written") || !strings.Contains(out, "owner=failed") {
				t.Fatalf("a failed chown is not reported: %q", out)
			}
		})
	}
}

func TestFailureScriptReportsOwnerOKWhenChownWorks(t *testing.T) {
	out, calls := runFailureScript(t, false, false, false)
	if !strings.Contains(out, "owner=ok") || strings.Contains(out, "owner=failed") {
		t.Fatalf("a good chown is misreported: %q", out)
	}
	// Both objects take the DATA dir's owner (the parent of logs/), never the logs dir's own: a
	// root-owned logs dir left by an earlier failed run must not hand its owner to the marker.
	got := strings.Split(strings.TrimSpace(calls), "\n")
	if len(got) != 2 {
		t.Fatalf("chown called %d times, want 2 (the directory it made, then the marker):\n%s", len(got), calls)
	}
	for _, l := range got {
		ref, _, _ := strings.Cut(l, " ")
		if !strings.HasPrefix(ref, "--reference=") || strings.HasSuffix(ref, "/"+markerLogsDir) {
			t.Errorf("chown call %q does not reference the data dir", l)
		}
	}
}

func TestUserAddArgsAreExact(t *testing.T) {
	want := []string{"--system", "--home-dir", "/var/lib/claude-swap", "--shell", "/usr/sbin/nologin", "claude-swap"}
	got := UserAddArgs()
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("UserAddArgs = %q, want %q", got, want)
	}
	// A fresh slice each call, so a caller appending to it cannot change the next caller's.
	got[0] = "x"
	if UserAddArgs()[0] != "--system" {
		t.Fatal("UserAddArgs shares its backing array")
	}
}

// TestRenderUnitsForVerify writes the real units to a directory for _verify/cases/service-credential-
// missing.sh and the CI service smoke, which exercise them under systemd. It is skipped unless the case asks, so a normal
// `go test` writes nothing.
func TestRenderUnitsForVerify(t *testing.T) {
	dir := os.Getenv("VERIFY_UNIT_DIR")
	if dir == "" {
		t.Skip("only the _verify case sets VERIFY_UNIT_DIR")
	}
	exe, data := os.Getenv("VERIFY_EXE"), os.Getenv("VERIFY_DATA_DIR")
	if exe == "" || data == "" {
		t.Fatal("VERIFY_EXE and VERIFY_DATA_DIR are required with VERIFY_UNIT_DIR")
	}
	listen := os.Getenv("VERIFY_LISTEN")
	if listen == "" {
		listen = "127.0.0.1:0"
	}
	for name, body := range map[string]string{
		"server.service": mustRender(t, exe, listen, data, false),
		"failed.service": RenderFailureUnit(data),
		// One argument per line, for the CI smoke to hand to useradd without restating them.
		"useradd.args": strings.Join(UserAddArgs(), "\n") + "\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
