package main

import (
	"bytes"
	"context"
	"testing"
)

func TestDispatchVersion(t *testing.T) {
	old := version
	version = "v1.2.3"
	t.Cleanup(func() { version = old })

	for _, args := range [][]string{{"--version"}, {"-version"}, {"version"}} {
		var out, errOut bytes.Buffer
		if code := dispatch(context.Background(), args, &out, &errOut); code != 0 {
			t.Fatalf("%v: exit %d, want 0", args, code)
		}
		if got, want := out.String(), "agent v1.2.3\n"; got != want {
			t.Fatalf("%v: got %q want %q", args, got, want)
		}
		if errOut.Len() != 0 {
			t.Fatalf("%v: stderr %q", args, errOut.String())
		}
	}
}

func TestDispatchVersionWithExtraArgIsStillUsageError(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := dispatch(context.Background(), []string{"--version", "x"}, &out, &errOut); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout %q", out.String())
	}
}

func TestVersionDefaultsToDev(t *testing.T) {
	if version != "dev" {
		t.Fatalf("version = %q, want dev when no -X is given", version)
	}
}
