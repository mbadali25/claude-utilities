//go:build windows

package main

import "testing"

// TestToMgrConfigCarriesTheCommandLine: mgr.Service.UpdateConfig sends an empty BinaryPathName as
// NULL, which the SCM reads as "unchanged", so a second `service install` would keep the first
// install's --listen and --data-dir while reporting success.
func TestToMgrConfigCarriesTheCommandLine(t *testing.T) {
	const cmdline = `"C:\bin\server.exe" run --listen 127.0.0.1:8443 --data-dir C:\data`
	if got := toMgrConfig(serviceConfig{BinaryPathName: cmdline}).BinaryPathName; got != cmdline {
		t.Fatalf("BinaryPathName = %q, want %q", got, cmdline)
	}
}

func TestSplitExeAndArgs(t *testing.T) {
	exe, args := splitExeAndArgs(`"C:\Program Files\s.exe" run --listen 127.0.0.1:8443`)
	if exe != `C:\Program Files\s.exe` || len(args) != 3 || args[0] != "run" {
		t.Fatalf("exe=%q args=%q", exe, args)
	}
}

func TestStateNameCoversEveryState(t *testing.T) {
	if got := stateName(4); got != "running" {
		t.Fatalf("stateName(Running) = %q", got)
	}
	if got := stateName(99); got != "state_99" {
		t.Fatalf("an unknown state renders %q", got)
	}
}
