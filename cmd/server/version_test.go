package main

import (
	"bytes"
	"testing"
)

func TestVersionCmd(t *testing.T) {
	old := version
	version = "v1.2.3"
	t.Cleanup(func() { version = old })

	for _, args := range [][]string{{"--version"}, {"-version"}, {"version"}} {
		var out bytes.Buffer
		if !versionCmd(args, &out) {
			t.Fatalf("%v: not handled", args)
		}
		if got, want := out.String(), "server v1.2.3\n"; got != want {
			t.Fatalf("%v: got %q want %q", args, got, want)
		}
	}
}

func TestVersionCmdIgnoresEverythingElse(t *testing.T) {
	for _, args := range [][]string{nil, {}, {"--listen", "x:1"}, {"run", "--version"}, {"--version", "extra"}, {"vault", "version"}} {
		var out bytes.Buffer
		if versionCmd(args, &out) {
			t.Fatalf("%v: handled, must fall through", args)
		}
		if out.Len() != 0 {
			t.Fatalf("%v: wrote %q", args, out.String())
		}
	}
}

func TestVersionDefaultsToDev(t *testing.T) {
	if version != "dev" {
		t.Fatalf("version = %q, want dev when no -X is given", version)
	}
}
