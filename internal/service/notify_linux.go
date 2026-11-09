//go:build linux

package service

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// notifyTimeout bounds the datagram write. systemd's socket is always ready to receive, so a write
// that blocks means something else holds the path; a service must not hang on its own readiness.
const notifyTimeout = 2 * time.Second

// notifySocket is systemd's notification socket, or "" when this process was not started by a
// `Type=notify` unit - the console case, where every call here is a no-op.
func notifySocket() string { return os.Getenv("NOTIFY_SOCKET") }

// NotifyReady sends READY=1. The unit is `Type=notify` with `NotifyAccess=main`, so the caller must
// send this from the main process and only AFTER the last thing that can fail: the data-dir lock,
// EnsureCert, the vault and keyring open, and the bound listener. Sent any earlier, `systemctl
// start` would report success for a server that is about to exit 3.
//
// MAINPID is deliberately not sent: with NotifyAccess=main systemd already knows the pid, and a
// MAINPID from a process that is not the main one is how a notify unit ends up refusing the message.
func NotifyReady() error { return notify("READY=1") }

// NotifyStopping sends STOPPING=1 on a clean shutdown, so systemd distinguishes a deliberate stop
// from a process that fell over.
func NotifyStopping() error { return notify("STOPPING=1") }

// notify writes one state line to the notification socket. An empty NOTIFY_SOCKET is success with
// nothing written, which is what makes a console run and a service run the same code path.
func notify(state string) error {
	addr := notifySocket()
	if addr == "" {
		return nil
	}
	// An abstract socket arrives as "@name" and is addressed with a leading NUL. Go's own
	// syscall.SockaddrUnix already maps a leading "@" to the abstract namespace, so deleting these
	// three lines does not change the behaviour (a mutation confirmed it: the abstract-socket test
	// below passes either way). They stay because that mapping is a lightly documented detail of
	// net/syscall rather than part of net's contract, and because the explicit form is what the
	// sd_notify protocol is written in.
	if strings.HasPrefix(addr, "@") {
		addr = "\x00" + addr[1:]
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		// The socket path is not a secret, but it is a path: the message names the variable instead.
		// net.OpError renders the address it was given, so the cause is unwrapped out of it rather
		// than wrapped whole - otherwise this line says the opposite of what the comment promises.
		return fmt.Errorf("sd_notify: dial the socket named by NOTIFY_SOCKET: %w", withoutAddr(err))
	}
	defer func() { _ = c.Close() }()
	if err := c.SetWriteDeadline(time.Now().Add(notifyTimeout)); err != nil {
		return fmt.Errorf("sd_notify: %w", err)
	}
	if _, err := c.Write([]byte(state + "\n")); err != nil {
		return fmt.Errorf("sd_notify: write %s: %w", state, err)
	}
	return nil
}

// withoutAddr strips the address a net.OpError renders, keeping the cause so errors.Is still finds
// the syscall error underneath. Anything that is not a net.OpError is returned as it came.
func withoutAddr(err error) error {
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		return oe.Err
	}
	return err
}

// JournalStream reports whether this process's standard error IS the journal, which is when the
// server switches to JSON lines. The systemd page requires the value of $JOURNAL_STREAM to be
// compared against fstat of the stream and not merely to be present: a child that inherited the
// variable without inheriting the stream would otherwise change its log format on a lie.
func JournalStream() bool {
	want := os.Getenv("JOURNAL_STREAM")
	if want == "" {
		return false
	}
	wantDev, wantIno, ok := parseDevIno(want)
	if !ok {
		return false
	}
	dev, ino, ok := stderrDevIno()
	return ok && dev == wantDev && ino == wantIno
}

// stderrDevIno is fd 2's device and inode numbers.
func stderrDevIno() (dev, ino uint64, ok bool) {
	var st syscall.Stat_t
	if err := syscall.Fstat(int(os.Stderr.Fd()), &st); err != nil {
		return 0, 0, false
	}
	return uint64(st.Dev), uint64(st.Ino), true
}

// formatDevIno renders the pair the way systemd sets it.
func formatDevIno(dev, ino uint64) string {
	return strconv.FormatUint(dev, 10) + ":" + strconv.FormatUint(ino, 10)
}

// parseDevIno reads "DEVICE:INODE", both decimal. Anything else is not a stream identity.
func parseDevIno(s string) (dev, ino uint64, ok bool) {
	d, i, found := strings.Cut(s, ":")
	if !found || d == "" || i == "" {
		return 0, 0, false
	}
	dev, err := strconv.ParseUint(d, 10, 64)
	if err != nil {
		return 0, 0, false
	}
	ino, err = strconv.ParseUint(i, 10, 64)
	if err != nil {
		return 0, 0, false
	}
	return dev, ino, true
}

// BootInstant is this machine's boot time, from /proc/uptime, rounded to the second. It is the
// marker rule's "same boot" half: a reboot must always get one honest attempt, and comparing an
// instant rather than counting restarts is what survives a service that the SCM or systemd restarts
// at a moment this process cannot see. The zero instant means it could not be read, which
// ShouldRefuseStart treats as "no boot discrimination" rather than as a mismatch.
func BootInstant() time.Time {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return time.Time{}
	}
	first, _, _ := strings.Cut(strings.TrimSpace(string(b)), " ")
	secs, err := strconv.ParseFloat(first, 64)
	if err != nil || secs < 0 {
		return time.Time{}
	}
	return time.Now().Add(-time.Duration(secs * float64(time.Second))).UTC().Truncate(time.Second)
}
