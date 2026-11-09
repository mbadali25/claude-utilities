package service

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"claude-utilities/internal/credfile"
)

const (
	// MarkerFileName is the last-fatal marker's name. It lives in the directory the caller names -
	// `<data-dir>\logs` for the server on Windows, `/var/lib/claude-swap` for the systemd
	// OnFailure unit, `%ProgramData%\claude-swap-agent` for the agent (8.8, never the state dir).
	MarkerFileName = "last-fatal.json"

	// MarkerMaxAge is the window inside which a marker refuses the next start. Ten minutes covers
	// the SCM's whole 5 s + 30 s + stop chain plus three process startups with margin, and is
	// deliberately decoupled from the 86400 s reset period, which only governs how the SCM counts
	// failures. The worst case it accepts is one short-lived attempt per ten minutes, visible in the
	// event log; a 24 h window would have blocked an automatic start for a day after any fatal.
	MarkerMaxAge = 10 * time.Minute

	// BootSkew is how far two readings of the boot instant may differ and still be the same boot.
	// The instant is computed as now minus uptime, so it drifts by the time it takes to read both.
	BootSkew = 2 * time.Second

	// UnspecifiedReason is what a reason that is not a plain token becomes. The marker is read by an
	// operator and pasted into reports: it carries a code, a token, and two instants, and never a
	// path, an address, an identity or a secret.
	UnspecifiedReason = "unspecified"

	// markerMaxBytes bounds the read. The file is four short fields; anything larger is not one.
	markerMaxBytes = 4 << 10
)

// reasonToken is the shape a reason has to have to be written out: a short lower-case token such as
// "vault-locked" or "cert-refused". Anything else is replaced, not trimmed - a trim would still
// leak the first thirty characters of whatever came in.
var reasonToken = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// Marker is the last fatal this binary recorded: the exit code it reported, a reason token, when it
// happened and the boot it happened on. The same shape is written by the Windows service handler and
// by the Linux OnFailure unit, so `service status` reads one file whatever wrote it.
type Marker struct {
	Exit   int       `json:"exit"`
	Reason string    `json:"reason"`
	TS     time.Time `json:"ts"`
	Boot   time.Time `json:"boot"`
}

// MarkerPath is where the marker lives inside dir.
func MarkerPath(dir string) string { return filepath.Join(dir, MarkerFileName) }

// WriteMarker records one fatal, replacing any previous marker. The write is atomic (a temp file in
// the same directory, then a rename), owner-only, and fsynced before the rename so a crash leaves
// either the old marker or the new one and never a half-written file that the next start would have
// to interpret.
//
// The times are stored in UTC truncated to the second, which is the precision the boot instant has.
func WriteMarker(dir string, m Marker) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	m.Reason = cleanReason(m.Reason)
	m.TS = m.TS.UTC().Truncate(time.Second)
	m.Boot = m.Boot.UTC().Truncate(time.Second)
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	b = append(b, '\n')

	f, err := os.CreateTemp(dir, MarkerFileName+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // a no-op once the rename has taken the file away
	if err := writeAndSync(f, b); err != nil {
		return err
	}
	// The ACL matters on Windows, where the mode bits CreateTemp sets only toggle read-only.
	if err := credfile.RestrictFile(tmp); err != nil {
		return err
	}
	return renameWithRetry(tmp, MarkerPath(dir))
}

func writeAndSync(f *os.File, b []byte) error {
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// renameWithRetry replaces dst. On Windows a concurrent reader or writer of the destination can make
// one rename fail transiently, and the marker is written from a service handler that cannot usefully
// report that: a short retry turns it into the atomic replace every other platform gets for free.
func renameWithRetry(src, dst string) error {
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		if err = os.Rename(src, dst); err == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return err
}

// cleanReason keeps a plain token and replaces anything else with UnspecifiedReason.
func cleanReason(reason string) string {
	if reasonToken.MatchString(reason) {
		return reason
	}
	return UnspecifiedReason
}

// ReadMarker reads the marker in dir. ok is false when there is none, when it does not parse, and
// when it parses into something that is not a marker (no timestamp, a reason that is not a token, an
// exit outside the one-byte range a process can report). Those are one answer on purpose: every
// caller does the same thing with them, which is to delete the file and get on with the start.
func ReadMarker(dir string) (Marker, bool) {
	f, err := os.Open(filepath.Clean(MarkerPath(dir)))
	if err != nil {
		return Marker{}, false
	}
	defer func() { _ = f.Close() }()
	b := make([]byte, markerMaxBytes+1)
	n, err := f.Read(b)
	if (err != nil && n == 0) || n > markerMaxBytes {
		return Marker{}, false
	}
	var m Marker
	if err := json.Unmarshal(b[:n], &m); err != nil {
		return Marker{}, false
	}
	if m.TS.IsZero() || m.Exit < 0 || m.Exit > 255 || !reasonToken.MatchString(m.Reason) {
		return Marker{}, false
	}
	return m, true
}

// DeleteMarker removes the marker. An absent one is not an error: `service start` from an operator
// deletes it unconditionally so a deliberate start after a fix always runs.
func DeleteMarker(dir string) error {
	if err := os.Remove(MarkerPath(dir)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// ShouldRefuseStart answers the Windows handler's and the agent service's one question: is this
// start a retry of a fatal that a restart cannot fix?
//
// It refuses only when all three conditions of the marker rule hold: the marker parses, its exit is
// one the caller's table holds, and it is younger than ten minutes AND stamped with this boot. Every
// other case deletes the marker and lets the start proceed - a reboot always gets one honest
// attempt, and so does any start more than ten minutes after the fatal. The deletion is the reason
// this is one function and not three: a caller that forgot it would refuse for ever.
//
// now and boot are parameters rather than reads so the rule is pure and the table-driven test needs
// no platform at all; production passes time.Now() and BootInstant().
func ShouldRefuseStart(dir string, t Table, now, boot time.Time) (Marker, bool) {
	if m, ok := ReadMarker(dir); ok && t.IsNonRestarting(m.Exit) && fresh(m.TS, now) && sameBoot(m.Boot, boot) {
		return m, true
	}
	_ = DeleteMarker(dir)
	return Marker{}, false
}

// fresh is "younger than ten minutes", with the boot skew allowed on the other side: a marker
// stamped a second or two into the future is a clock reading, not a forgery, and anything further
// ahead is treated as stale (fail open: the start proceeds).
func fresh(ts, now time.Time) bool {
	age := now.Sub(ts)
	return age < MarkerMaxAge && age > -BootSkew
}

// sameBoot compares two boot instants within BootSkew. Two zero instants compare equal, which is the
// platform where no boot reader has landed yet: writer and reader then agree, and MarkerMaxAge alone
// bounds the refusal.
func sameBoot(a, b time.Time) bool {
	d := a.Sub(b)
	return d <= BootSkew && d >= -BootSkew
}
