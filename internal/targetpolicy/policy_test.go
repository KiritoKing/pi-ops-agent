package targetpolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

func TestPolicyStrictlyScopesReadsWritesAndBreakglass(t *testing.T) {
	directory := t.TempDir()
	readRoot := filepath.Join(directory, "read")
	writeRoot := filepath.Join(directory, "write")
	outside := filepath.Join(directory, "outside")
	for _, path := range []string{readRoot, writeRoot, outside} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	readFile := filepath.Join(readRoot, "status.txt")
	if err := os.WriteFile(readFile, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy := parseTestPolicy(t, readRoot, writeRoot)
	base := protocol.Request{TargetID: "target-hermes", PolicyRevision: policy.Revision}
	read := base
	read.Method, read.Path = protocol.MethodFileRead, readFile
	if err := policy.Authorize(read); err != nil {
		t.Fatalf("allowed read denied: %v", err)
	}
	write := base
	write.Method = protocol.MethodChangePrepare
	write.Operation = &protocol.FileWrite{OperationKind: "file.write", Path: filepath.Join(writeRoot, "new.conf"), Content: "value"}
	if err := policy.Authorize(write); err != nil {
		t.Fatalf("allowed new file write denied: %v", err)
	}
	escape := base
	escape.Method = protocol.MethodChangePrepare
	escape.Operation = &protocol.FileWrite{OperationKind: "file.write", Path: filepath.Join(outside, "escape.conf"), Content: "value"}
	if err := policy.Authorize(escape); err == nil {
		t.Fatal("write outside target policy was allowed")
	}
	breakglass := base
	breakglass.Method = protocol.MethodChangePrepare
	breakglass.Operation = &protocol.BreakglassScript{OperationKind: "breakglass.script", Script: "true", BackupPaths: []string{writeRoot}}
	if err := policy.Authorize(breakglass); err == nil {
		t.Fatal("remote breakglass was allowed")
	}
}

func TestPolicyRejectsUnknownFieldsAndSymlinkEscape(t *testing.T) {
	directory := t.TempDir()
	readRoot := filepath.Join(directory, "read")
	outside := filepath.Join(directory, "outside")
	if err := os.Mkdir(readRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(readRoot, "link")); err != nil {
		t.Fatal(err)
	}
	policy := parseTestPolicy(t, readRoot, readRoot)
	request := protocol.Request{
		Method: protocol.MethodFileRead, TargetID: "target-hermes", PolicyRevision: policy.Revision,
		Path: filepath.Join(readRoot, "link", "secret"), Deadline: time.Now().Add(time.Minute),
	}
	if err := policy.Authorize(request); err == nil {
		t.Fatal("symlink escape was allowed")
	}
	payload := fmt.Sprintf(`{"version":1,"revision":"policy-12345678","unexpected":true,"targets":[{"id":"target-hermes","account":"hermes-agent","displayName":"Hermes","inspect":{"hostSnapshot":true,"processList":true,"units":[],"readPaths":[%q]},"changes":{"writePaths":[%q],"units":[],"packages":[],"plugins":[]}}]}`, readRoot, readRoot)
	if _, err := Parse([]byte(payload)); err == nil {
		t.Fatal("unknown policy field was accepted")
	}
}

func parseTestPolicy(t *testing.T, readRoot, writeRoot string) *Policy {
	t.Helper()
	payload := fmt.Sprintf(`{"version":1,"revision":"policy-12345678","targets":[{"id":"target-hermes","account":"hermes-agent","displayName":"Hermes","inspect":{"hostSnapshot":true,"processList":true,"units":["hermes.service"],"readPaths":[%q]},"changes":{"writePaths":[%q],"units":["hermes.service"],"packages":["hermes"],"plugins":["adapter.botmux"]}}]}`, readRoot, writeRoot)
	policy, err := Parse([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}
