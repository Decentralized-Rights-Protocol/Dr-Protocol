package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteNewDoesNotOverwriteExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil { t.Fatal(err) }
	if err := writeNew(path, []byte("replacement"), 0o600); err == nil {
		t.Fatal("writeNew overwrote an existing file")
	}
	got, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	if string(got) != "original" { t.Fatalf("existing file changed: %q", got) }
}

func TestWriteNewCreatesPrivateKeyWithRequestedPermissions(t *testing.T) {
	if os.PathSeparator != '/' { t.Skip("POSIX permission bits are not portable to this platform") }
	path := filepath.Join(t.TempDir(), "private.key")
	if err := writeNew(path, []byte("secret"), 0o600); err != nil { t.Fatal(err) }
	info, err := os.Stat(path)
	if err != nil { t.Fatal(err) }
	if got := info.Mode().Perm(); got != 0o600 { t.Fatalf("private key permissions = %04o, want 0600", got) }
}
