package logx

import (
	"bytes"
	"testing"
)

// run_as is the one key through which a local username may be logged, so it must be on the
// allowlist in every spelling the callers use.
func TestRunAsKeyAllowed(t *testing.T) {
	for _, k := range []string{"run_as", "runAs", "runas"} {
		var buf bytes.Buffer
		New(&buf).Info("x", k, "dadeush")
		if m := logLine(t, &buf); m[k] != "dadeush" {
			t.Fatalf("%s = %v, want dadeush: %s", k, m[k], buf.String())
		}
	}
}

// A plain username key stays dropped: only run_as carries one.
func TestBareUserKeyStillDropped(t *testing.T) {
	var buf bytes.Buffer
	New(&buf).Info("x", "username", "dadeush")
	if m := logLine(t, &buf); m["username"] != dropped {
		t.Fatalf("username = %v, want %s: %s", m["username"], dropped, buf.String())
	}
}
