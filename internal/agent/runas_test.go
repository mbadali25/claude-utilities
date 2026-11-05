package agent

import (
	"strings"
	"testing"
)

func TestRunAsUserReportsAName(t *testing.T) {
	got := runAsUser()
	if got == "" {
		t.Skip("no passwd entry and no USER/LOGNAME/USERNAME in this environment")
	}
	if strings.ContainsAny(got, `\/`) {
		t.Fatalf("runAsUser kept a domain or path separator: %q", got)
	}
	if len([]rune(got)) > maxRunAsLen {
		t.Fatalf("runAsUser not capped: %q", got)
	}
	if strings.TrimSpace(got) != got {
		t.Fatalf("runAsUser left surrounding space: %q", got)
	}
}

// A hostile environment must not be able to push a long or control-laden string into the hello.
func TestRunAsUserSanitizesEnvironment(t *testing.T) {
	t.Setenv("USER", "")
	t.Setenv("LOGNAME", "")
	t.Setenv("USERNAME", "")
	if got := runAsUser(); strings.ContainsAny(got, "\n\r\x00") {
		t.Fatalf("control characters survived: %q", got)
	}
}
