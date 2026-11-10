package service

import (
	"errors"
	"path"
	"strings"
)

// ErrDataDirNotAbsolute is RenderServerUnit's refusal of a data dir that is not an absolute path.
var ErrDataDirNotAbsolute = errors.New("service: the data dir must be an absolute path")

// The Linux server's systemd units, as text. Nothing here touches the host: the renderers are pure
// functions, so the unit's exact bytes are a golden string in a test that runs on every OS, and the
// installer that writes them is a separate, root-only step.
//
// The server is a SYSTEM unit, on the four grounds the spec's "systemd unit (system scope)" gives
// and none of which a user unit can meet: credential access, boot without linger, ordering against
// system targets, and a service account that is not a human's. The hardening directives ride along
// because a system unit gets them for free.

const (
	// UnitName is the server's unit.
	UnitName = "claude-swap-server.service"

	// FailureUnitName is the OnFailure= unit. systemd starts it when the server unit enters
	// `failed`, which includes the moment the start limit trips.
	FailureUnitName = "claude-swap-server-failed.service"

	// StateDir is the directory StateDirectory=claude-swap creates, and the whole of what the unit
	// may write.
	StateDir = "/var/lib/claude-swap"

	// ServiceUser is the static system account the server runs as (Decision 4).
	ServiceUser = "claude-swap"

	// markerLogsDir is the directory under the data dir holding last-fatal.json. It is the one
	// `server service status` reads (serviceLogDir in cmd/server), so the OnFailure unit and the
	// reader agree on a path without either importing the other.
	markerLogsDir = "logs"

	// credentialName is the systemd credential name the KEK drop-in hands the server. The failure
	// unit prints it when a start fails for want of a credential; it is a name, never a value.
	credentialName = "vault-kek"
)

// RenderServerUnit renders the server's system unit. exe, listen and dataDir are placed on the
// ExecStart line; tunnels adds --tunnels.
//
// There is deliberately no credential line. `service install` runs before anyone knows which KEK
// form this host gets, and a unit that names a credential that does not exist fails before
// ExecStart. The command that creates the KEK writes the drop-in (dropin.go).
//
// RestartPreventExitStatus comes from the server's table, never from a literal here: the codes are
// the server's own definition (ServerTable) and the agent's unit must not inherit them by copy.
//
// RestartSteps= and RestartMaxDelaySec= need systemd 254. An older systemd ignores them with a
// warning and restarts at a flat RestartSec; the start limit is what bounds a loop either way.
//
// It returns ErrDataDirNotAbsolute for a data dir that is not an absolute path. ProtectSystem=strict
// leaves everything read-only but ReadWritePaths, and a relative path (or one opening with `-` or `+`,
// which systemd reads as an option AFTER unquoting) cannot be named there, so the unit would start and
// then fail on the server's first write. No unit is rendered rather than one that cannot work.
func RenderServerUnit(exe, listen, dataDir string, tunnels bool) (string, error) {
	if !path.IsAbs(dataDir) {
		return "", ErrDataDirNotAbsolute
	}
	exec := []string{exe, "run", "--listen", listen, "--data-dir", dataDir}
	if tunnels {
		exec = append(exec, "--tunnels")
	}
	rw := StateDir
	if !underStateDir(dataDir) {
		// A data dir the operator placed outside the state directory has to be named or its first
		// write fails.
		rw += " " + quoteWord(dataDir, false)
	}

	var b strings.Builder
	line := func(s string) { b.WriteString(s + "\n") }
	line("[Unit]")
	line("Description=Claude Swap server")
	line("After=network-online.target")
	line("Wants=network-online.target")
	line("StartLimitIntervalSec=300")
	line("StartLimitBurst=5")
	line("OnFailure=" + FailureUnitName)
	line("")
	line("[Service]")
	line("Type=notify")
	line("NotifyAccess=main")
	line("User=" + ServiceUser)
	line("Group=" + ServiceUser)
	line("ExecStart=" + unitJoin(exec...))
	line("StateDirectory=claude-swap")
	line("# No credential line here: service install does not yet know which KEK form this host gets.")
	line("# migrate / init / add-slot --type kek-file write the drop-in below and run daemon-reload.")
	line("Restart=on-failure")
	line("RestartSec=5")
	line("RestartSteps=4")
	line("RestartMaxDelaySec=120")
	line("RestartPreventExitStatus=" + ServerTable().RestartPreventExitStatus())
	line("NoNewPrivileges=yes")
	line("PrivateTmp=yes")
	line("ProtectSystem=strict")
	line("ProtectHome=yes")
	line("ReadWritePaths=" + rw)
	line("PrivateDevices=yes")
	line("ProtectKernelTunables=yes")
	line("ProtectControlGroups=yes")
	line("RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX")
	line("CapabilityBoundingSet=")
	line("AmbientCapabilities=")
	line("LockPersonality=yes")
	line("MemoryDenyWriteExecute=yes")
	line("")
	line("[Install]")
	line("WantedBy=multi-user.target")
	return b.String(), nil
}

// failureScript is what the OnFailure unit runs. systemd hands an OnFailure= unit the failed
// unit's result in $MONITOR_SERVICE_RESULT, $MONITOR_EXIT_CODE and $MONITOR_EXIT_STATUS (systemd
// 249 and later; the plan's `$SERVICE_RESULT` is the name an ExecStopPost= of the failed unit itself
// would see, which this unit is not).
//
// It writes the same last-fatal.json the Windows handler writes and prints one line to the journal.
// Neither holds a value: the marker is a code, a token and two instants, the line is the same words
// plus a credential NAME when the status says credentials were the problem.
//
// Written as plain shell with a positional argument for the directory, so the one operator-chosen
// string reaches the program as data ($1), never as text the shell parses.
//
// It runs as root, and the data dir belongs to the service account, so it creates NOTHING above the
// logs directory: a missing data dir is the commonest reason a start fails, and a root-owned 0700
// data dir made by this script would turn that into a permanent one. A logs directory it does create
// (and the marker in it) is handed to the data dir's owner. chown --reference is GNU-only, so a
// failure is not silent: the journal line ends owner=failed, because a marker left root:root in the
// service account's directory is one the reader cannot open.
const failureScript = `umask 077
res="${MONITOR_SERVICE_RESULT:-unknown}"
code="${MONITOR_EXIT_CODE:-unknown}"
st="${MONITOR_EXIT_STATUS:-}"
case "$st" in ''|*[!0-9]*) st=1 ;; esac
[ "$st" -le 255 ] || st=1
reason="$res"
note=""
if [ "$st" -eq 243 ]; then reason=credential-missing; note=" credential=vault-kek"; fi
case "$reason" in ''|*[!a-z0-9-]*) reason=unspecified ;; esac
dir="$1"
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
up=$(cut -d. -f1 /proc/uptime)
boot=$(date -u -d "@$(( $(date +%s) - up ))" +%Y-%m-%dT%H:%M:%SZ)
parent="${dir%/*}"
made=0
if [ -d "$parent" ] && { [ -d "$dir" ] || { mkdir "$dir" && made=1; }; } && printf '{"exit":%s,"reason":"%s","ts":"%s","boot":"%s"}\n' "$st" "$reason" "$now" "$boot" > "$dir/last-fatal.json.tmp" && mv -f "$dir/last-fatal.json.tmp" "$dir/last-fatal.json"; then
  own=ok
  if [ "$made" -eq 1 ]; then chown --reference="$parent" "$dir" 2>/dev/null || own=failed; fi
  chown --reference="$dir" "$dir/last-fatal.json" 2>/dev/null || own=failed
  echo "claude-swap-server failed: result=$res exit_code=$code exit_status=$st reason=$reason$note marker=written owner=$own"
else
  echo "claude-swap-server failed: result=$res exit_code=$code exit_status=$st reason=$reason$note marker=not-written"
fi
`

// RenderFailureUnit renders the Type=oneshot unit OnFailure= starts. dataDir is the server's data
// dir; the marker goes in its logs directory, which is where `service status` looks.
func RenderFailureUnit(dataDir string) string {
	var b strings.Builder
	line := func(s string) { b.WriteString(s + "\n") }
	line("[Unit]")
	line("Description=Claude Swap server failure notice")
	line("")
	line("[Service]")
	line("Type=oneshot")
	line("ExecStart=" + unitJoin("/bin/sh", "-c", failureScript, "claude-swap-server-failed", path.Join(dataDir, markerLogsDir)))
	return b.String()
}

// UserAddArgs are the arguments to `useradd` that create the static service account. The program
// name is not included: pass it to exec.Command as `exec.Command("useradd", service.UserAddArgs()...)`.
// A fresh slice each call.
func UserAddArgs() []string {
	return []string{"--system", "--home-dir", StateDir, "--shell", "/usr/sbin/nologin", ServiceUser}
}

// underStateDir reports whether p is the state directory or inside it.
func underStateDir(p string) bool {
	c := path.Clean(p)
	return c == StateDir || strings.HasPrefix(c, StateDir+"/")
}

// unitJoin renders words as an ExecStart value: each word quoted only when it has to be.
//
// The first word is the executable, and systemd reads the characters `@ - : + !` in FRONT of it as
// options (`+` runs it with full privileges outside the sandbox, `-` swallows its failures, `@`
// changes argv[0]) before it looks at quoting. A word that opens with one is therefore always quoted:
// the quote makes it a plain, and then relative, path, which systemd refuses. `!` is already quoted by
// needsQuote (it is not in the bare set), so only `@ - : +` need the explicit step here.
func unitJoin(words ...string) string {
	out := make([]string, len(words))
	for i, w := range words {
		out[i] = unitQuote(w)
		if i == 0 && w != "" && strings.ContainsRune("@-:+", rune(w[0])) {
			out[i] = quoteWord(w, true)
			if !strings.HasPrefix(out[i], `"`) {
				out[i] = `"` + out[i] + `"`
			}
		}
	}
	return strings.Join(out, " ")
}

// unitQuote renders one word for a unit file. A word made only of characters that cannot matter is
// written bare, so the common case reads like the spec's text. Anything else is double-quoted with
// the escapes systemd documents: a backslash and a quote are escaped, control characters become C
// escapes (a newline in an argument would otherwise start a new directive), and `$` and `%` are
// doubled because systemd expands the first and treats the second as a specifier.
func unitQuote(w string) string { return quoteWord(w, true) }

// quoteWord is unitQuote with the `$` doubling optional: only the Exec* lines expand `$`, so a path
// setting such as ReadWritePaths= must carry it literally.
func quoteWord(w string, expandDollar bool) string {
	if w != "" && !strings.ContainsFunc(w, needsQuote) {
		return w
	}
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(w); i++ {
		c := w[i]
		switch {
		case c == '\\':
			b.WriteString(`\\`)
		case c == '"':
			b.WriteString(`\"`)
		case c == '$' && expandDollar:
			b.WriteString("$$")
		case c == '%':
			b.WriteString("%%")
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\t':
			b.WriteString(`\t`)
		case c < 0x20 || c == 0x7f:
			const hex = "0123456789abcdef"
			b.WriteString(`\x`)
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0xf])
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// needsQuote is true for any rune outside the set that is safe bare in a unit file.
func needsQuote(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return false
	}
	return !strings.ContainsRune("/._:-@=,+", r)
}
