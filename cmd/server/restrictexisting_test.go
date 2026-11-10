package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRestrictExistingFilesCountsRegularFilesRecursively(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "tls")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"vault.bin", filepath.Join("tls", "key.pem")} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	n, err := restrictExistingFiles(dir)
	if err != nil || n != 2 {
		t.Fatalf("restrictExistingFiles = %d, %v; want 2 files (directories are not counted), nil", n, err)
	}
}

func TestRestrictExistingFilesEmptyDir(t *testing.T) {
	n, err := restrictExistingFiles(t.TempDir())
	if err != nil || n != 0 {
		t.Fatalf("restrictExistingFiles = %d, %v; want 0, nil", n, err)
	}
}

func TestRestrictExistingFilesMissingDirIsAnError(t *testing.T) {
	if _, err := restrictExistingFiles(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("a missing data dir returned nil: the install would claim a pass it never ran")
	}
}
