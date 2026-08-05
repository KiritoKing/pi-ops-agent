package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditChainSurvivesReopenAndDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(map[string]interface{}{"type": "one"}); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(map[string]interface{}{"type": "two"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err != nil {
		t.Fatalf("valid chain did not reopen: %v", err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(payload, []byte(`"two"`), []byte(`"bad"`), 1)
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("tampered audit chain was accepted")
	}
}
