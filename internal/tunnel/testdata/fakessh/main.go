// Command fakessh stands in for the ssh client in tests. The real spawn path is exercised end to
// end - exec.Command, the argv slice, the stderr pipe, the exit code - with no network, no host
// and no real key in play.
//
// It is scripted by two files BESIDE ITS OWN EXECUTABLE, not by the environment: ExecRunner gives
// a tunnel child an allowlisted environment on purpose, so an env-scripted fake would be testing
// a code path that production does not take.
//
//	<exeDir>/script.json   {"stderr":"...","exit":1,"sleepMs":0}  (optional; default exit 0)
//	<exeDir>/argv.log      one JSON array per invocation, appended
//
// It lives under testdata so the go tool ignores it: `go build ./...` and `go vet ./...` never
// see this main package.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type script struct {
	Stderr  string `json:"stderr"`
	Exit    int    `json:"exit"`
	SleepMS int    `json:"sleepMs"`
}

func main() {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "fakessh: cannot find my own path:", err)
		os.Exit(99)
	}
	dir := filepath.Dir(exe)

	if line, err := json.Marshal(os.Args[1:]); err == nil {
		f, err := os.OpenFile(filepath.Join(dir, "argv.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = f.Write(append(line, '\n'))
			_ = f.Close()
		}
	}

	var s script
	if data, err := os.ReadFile(filepath.Join(dir, "script.json")); err == nil {
		_ = json.Unmarshal(data, &s)
	}
	if s.SleepMS > 0 {
		time.Sleep(time.Duration(s.SleepMS) * time.Millisecond)
	}
	if s.Stderr != "" {
		fmt.Fprint(os.Stderr, s.Stderr)
	}
	os.Exit(s.Exit)
}
