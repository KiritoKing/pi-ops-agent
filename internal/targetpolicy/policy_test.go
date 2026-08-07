package targetpolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	policy := parseTestPolicy(t, readFile, writeRoot)
	base := protocol.Request{TargetID: "target-managed", PolicyRevision: policy.Revision}
	read := base
	read.Method, read.Path = protocol.MethodFileRead, readFile
	if err := policy.Authorize(read); err != nil {
		t.Fatalf("allowed read denied: %v", err)
	}
	read.Path = filepath.Join(readRoot, "other.txt")
	if err := os.WriteFile(read.Path, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := policy.Authorize(read); err == nil {
		t.Fatal("file read inherited permission from an allowed file parent")
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
		Method: protocol.MethodFileRead, TargetID: "target-managed", PolicyRevision: policy.Revision,
		Path: filepath.Join(readRoot, "link", "secret"), Deadline: time.Now().Add(time.Minute),
	}
	if err := policy.Authorize(request); err == nil {
		t.Fatal("symlink escape was allowed")
	}
	payload := fmt.Sprintf(`{"version":1,"revision":"policy-12345678","unexpected":true,"targets":[{"id":"target-managed","account":"managed_agent","displayName":"Managed workload","inspect":{"hostSnapshot":true,"processList":true,"units":[],"readPaths":[%q]},"changes":{"writePaths":[%q],"units":[],"packages":[],"plugins":[]}}]}`, readRoot, readRoot)
	if _, err := Parse([]byte(payload)); err == nil {
		t.Fatal("unknown policy field was accepted")
	}
}

func TestPolicyAuthorizesOnlyExactPinnedArtifactForItsTarget(t *testing.T) {
	directory := t.TempDir()
	digest := "sha256:" + strings.Repeat("a", 64)
	credentialDigest := "sha256:" + strings.Repeat("b", 64)
	adapterDigest := "sha256:" + strings.Repeat("c", 64)
	payload := fmt.Sprintf(`{"version":1,"revision":"policy-managed-1234","targets":[{"id":"target-managed","account":"managed_agent","displayName":"Managed workload","inspect":{"hostSnapshot":true,"processList":true,"units":[],"readPaths":[%q]},"changes":{"writePaths":[],"units":[],"packages":["docker.io"],"plugins":[{"id":"workload.assistant","kind":"managed-workload","version":"1.0.0","publisher":"example/ops","digest":%q,"credentialBundleDigest":%q},{"id":"adapter.web","kind":"im-adapter","version":"2.0.0","publisher":"example/ops","digest":%q}]}}]}`, directory, digest, credentialDigest, adapterDigest)
	policy, err := Parse([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	request := protocol.Request{
		Method: protocol.MethodChangePrepare, TargetID: "target-managed", PolicyRevision: policy.Revision,
		Operation: &protocol.WorkloadDeploy{
			OperationKind: "workload.deploy", PluginID: "workload.assistant", Version: "1.0.0",
			Publisher: "example/ops", Digest: digest, ArtifactRef: "builtin:" + digest,
		},
	}
	if err := policy.Authorize(request); err != nil {
		t.Fatalf("pinned workload artifact was denied: %v", err)
	}
	request.Operation = &protocol.PluginInstall{
		OperationKind: "plugin.install", PluginID: "workload.assistant", Version: "1.0.0",
		Publisher: "example/ops", Digest: digest, ArtifactRef: "builtin:" + digest,
	}
	if err := policy.Authorize(request); err != nil {
		t.Fatalf("installing a pinned managed-workload package was denied: %v", err)
	}
	request.Operation = &protocol.PluginInstall{
		OperationKind: "plugin.install", PluginID: "adapter.web", Version: "2.0.0",
		Publisher: "example/ops", Digest: adapterDigest, ArtifactRef: "builtin:" + adapterDigest,
	}
	if err := policy.Authorize(request); err != nil {
		t.Fatalf("installing a pinned im-adapter package was denied: %v", err)
	}
	request.Operation = &protocol.WorkloadDeploy{
		OperationKind: "workload.deploy", PluginID: "workload.assistant", Version: "1.0.0",
		Publisher: "other/publisher", Digest: digest, ArtifactRef: "builtin:" + digest,
	}
	if err := policy.Authorize(request); err == nil {
		t.Fatal("workload artifact with an unapproved publisher was allowed")
	}
	artifact, ok := policy.Artifact("target-managed", "managed-workload", "workload.assistant", "1.0.0", "example/ops", digest)
	if !ok || artifact.CredentialBundleDigest != credentialDigest {
		t.Fatalf("could not resolve pinned workload artifact: %#v", artifact)
	}
}

func TestPolicyEnforcesCredentialBundleByArtifactKind(t *testing.T) {
	directory := t.TempDir()
	digest := "sha256:" + strings.Repeat("a", 64)
	credentialDigest := "sha256:" + strings.Repeat("b", 64)
	base := fmt.Sprintf(`{"version":1,"revision":"policy-artifacts-1234","targets":[{"id":"target-managed","account":"managed_agent","displayName":"Managed workload","inspect":{"hostSnapshot":true,"processList":true,"units":[],"readPaths":[%q]},"changes":{"writePaths":[],"units":[],"packages":[],"plugins":[ARTIFACT]}}]}`, directory)
	for _, artifact := range []string{
		fmt.Sprintf(`{"id":"workload.assistant","kind":"managed-workload","version":"1.0.0","publisher":"example/ops","digest":%q}`, digest),
		fmt.Sprintf(`{"id":"adapter.web","kind":"im-adapter","version":"1.0.0","publisher":"example/ops","digest":%q,"credentialBundleDigest":%q}`, digest, credentialDigest),
		fmt.Sprintf(`{"id":"workload.assistant","kind":"container","version":"1.0.0","publisher":"example/ops","digest":%q}`, digest),
	} {
		if _, err := Parse([]byte(strings.Replace(base, "ARTIFACT", artifact, 1))); err == nil {
			t.Fatalf("invalid artifact policy was accepted: %s", artifact)
		}
	}
}

func parseTestPolicy(t *testing.T, readRoot, writeRoot string) *Policy {
	t.Helper()
	digest := "sha256:" + strings.Repeat("c", 64)
	payload := fmt.Sprintf(`{"version":1,"revision":"policy-12345678","targets":[{"id":"target-managed","account":"managed_agent","displayName":"Managed workload","inspect":{"hostSnapshot":true,"processList":true,"units":["managed.service"],"readPaths":[%q]},"changes":{"writePaths":[%q],"units":["managed.service"],"packages":["managed"],"plugins":[{"id":"adapter.web","kind":"im-adapter","version":"1.0.0","publisher":"example/ops","digest":%q}]}}]}`, readRoot, writeRoot, digest)
	policy, err := Parse([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}
