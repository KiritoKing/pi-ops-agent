//go:build linux

package roothelper

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenInspectionPathRejectsSymlinkEscape(t *testing.T) {
	allowed := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	escape := filepath.Join(allowed, "escape")
	if err := os.Symlink(secret, escape); err != nil {
		t.Fatal(err)
	}
	if file, err := openInspectionPath(escape, []string{allowed}, true); err == nil {
		file.Close()
		t.Fatal("secure inspection followed a symlink outside the allowed root")
	}
}

func TestOpenInspectionPathReadsRegularFileBeneathAllowedRoot(t *testing.T) {
	allowed := t.TempDir()
	path := filepath.Join(allowed, "service.log")
	if err := os.WriteFile(path, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := openInspectionPath(path, []string{allowed}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	payload := make([]byte, 2)
	if _, err := file.Read(payload); err != nil {
		t.Fatal(err)
	}
	if string(payload) != "ok" {
		t.Fatalf("unexpected payload: %q", payload)
	}
}
