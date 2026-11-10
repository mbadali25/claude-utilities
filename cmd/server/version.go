package main

import (
	"fmt"
	"io"
)

// version is stamped at release time by `-ldflags "-X main.version=TAG"` (.github/workflows/release.yml).
// An unstamped build reports "dev".
var version = "dev"

// versionCmd prints the version and reports true when args is exactly one version request. It runs
// before everything else in main(), so it needs no environment variable, no data dir and no ACL
// policy, and it cannot change any exit code: handled means exit 0. Anything longer falls through
// untouched, so `server run --listen x version` still reaches the flag parser as before.
func versionCmd(args []string, out io.Writer) bool {
	if len(args) != 1 {
		return false
	}
	switch args[0] {
	case "--version", "-version", "version":
		_, _ = fmt.Fprintln(out, "server", version)
		return true
	}
	return false
}
