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

var testBaseWorkloadDigest = "sha256:" + strings.Repeat("b", 64)

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
	write.Operation = &protocol.FileWrite{
		OperationKind: "file.write", PluginID: protocol.BaseWorkloadPluginID,
		PluginDigest: testBaseWorkloadDigest, Path: filepath.Join(writeRoot, "new.conf"), Content: "value",
	}
	if err := policy.Authorize(write); err != nil {
		t.Fatalf("allowed new file write denied: %v", err)
	}
	escape := base
	escape.Method = protocol.MethodChangePrepare
	escape.Operation = &protocol.FileWrite{
		OperationKind: "file.write", PluginID: protocol.BaseWorkloadPluginID,
		PluginDigest: testBaseWorkloadDigest, Path: filepath.Join(outside, "escape.conf"), Content: "value",
	}
	if err := policy.Authorize(escape); err == nil {
		t.Fatal("write outside target policy was allowed")
	}
	breakglass := base
	breakglass.Method = protocol.MethodChangePrepare
	breakglass.Operation = &protocol.BreakglassScript{OperationKind: "breakglass.script", Script: "true", BackupPaths: []string{writeRoot}, VerifyScript: "test -d /", Network: false}
	if err := policy.Authorize(breakglass); err == nil {
		t.Fatal("break-glass without an explicit root target policy was allowed")
	}
}

func TestStandingApprovalRequiresAnExplicitExactScope(t *testing.T) {
	directory := t.TempDir()
	legacy := parseTestPolicy(t, directory, directory)
	serviceOperation := &protocol.ServiceAction{
		OperationKind: "service.action", PluginID: protocol.BaseWorkloadPluginID,
		PluginDigest: testBaseWorkloadDigest, Unit: "managed.service", Action: "restart",
	}
	if basis, scope, ok := legacy.StandingApproval("target-managed", serviceOperation); ok || basis != "" || scope != "" {
		t.Fatalf("legacy allowlist became standing authorization: basis=%q scope=%q ok=%t", basis, scope, ok)
	}

	payload := fmt.Sprintf(`{"version":1,"revision":"policy-standing-1234","targets":[{"id":"target-managed","account":"managed_agent","displayName":"Managed workload","inspect":{"hostSnapshot":true,"processList":true,"units":[],"readPaths":[%q]},"changes":{"writePaths":[%q],"units":["managed.service"],"packages":["managed"],"plugins":[]},"authorization":{"standingScopes":["service.action"],"baseWorkloadDigest":%q}}]}`, directory, directory, testBaseWorkloadDigest)
	policy, err := Parse([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	basis, scope, ok := policy.StandingApproval("target-managed", serviceOperation)
	if !ok || basis != "standing-policy:policy-standing-1234:service.action" || scope != "service.action" {
		t.Fatalf("explicit standing scope was not resolved exactly: basis=%q scope=%q ok=%t", basis, scope, ok)
	}
	outside := &protocol.ServiceAction{
		OperationKind: "service.action", PluginID: protocol.BaseWorkloadPluginID,
		PluginDigest: testBaseWorkloadDigest, Unit: "other.service", Action: "restart",
	}
	if _, _, ok := policy.StandingApproval("target-managed", outside); ok {
		t.Fatal("standing scope widened the target service allowlist")
	}
	serviceOperation.PluginDigest = "sha256:" + strings.Repeat("c", 64)
	if _, _, ok := policy.StandingApproval("target-managed", serviceOperation); ok {
		t.Fatal("standing scope accepted a different workload.base digest")
	}
}

func TestStandingApprovalUsesExactPVEGuestActionAndRejectsHumanOnlyKinds(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	payload := fmt.Sprintf(`{"version":1,"revision":"policy-standing-pve","targets":[{"id":"target-pve-root","account":"root","displayName":"PVE root","inspect":{"hostSnapshot":true,"processList":true,"units":[],"readPaths":[]},"changes":{"writePaths":[],"units":[],"packages":[],"plugins":[]},"authorization":{"standingScopes":["pve.guest.start"]},"pve":{"pluginId":"workload.pve","pluginDigest":%q,"nodes":["pve1"],"storages":[],"guests":[{"guestType":"qemu","vmid":100}],"migrationTargets":[],"operations":["pve.guest.start","pve.guest.stop"]}}]}`, digest)
	policy, err := Parse([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	operation := &protocol.PVEGuestAction{
		OperationKind: "pve.guest.action", PluginID: testPVEPluginID, PluginDigest: digest,
		Node: "pve1", GuestType: "qemu", VMID: 100, Action: "start",
	}
	if _, scope, ok := policy.StandingApproval("target-pve-root", operation); !ok || scope != "pve.guest.start" {
		t.Fatalf("PVE start did not receive its exact standing scope: scope=%q ok=%t", scope, ok)
	}
	operation.RecoveryOfChangeID = "pve-change-0123456789abcdef0123456789abcdef"
	if _, _, ok := policy.StandingApproval("target-pve-root", operation); ok {
		t.Fatal("PVE recovery child inherited a standing authorization")
	}
	operation.RecoveryOfChangeID = ""
	operation.Action = "stop"
	if _, _, ok := policy.StandingApproval("target-pve-root", operation); ok {
		t.Fatal("PVE start standing scope authorized stop")
	}

	for _, forbidden := range []string{"package.install", "plugin.register", "plugin.install", "workload.deploy", "breakglass.script"} {
		invalid := strings.Replace(payload, `"pve.guest.start"`, `"`+forbidden+`"`, 1)
		if _, err := Parse([]byte(invalid)); err == nil {
			t.Fatalf("human-only operation %q was accepted as a standing scope", forbidden)
		}
	}
	for _, critical := range []string{
		"pve.guest.stop", "pve.guest.reboot", "pve.snapshot.delete",
		"pve.snapshot.rollback", "pve.guest.restore", "pve.guest.migrate",
	} {
		invalid := strings.Replace(payload, `"pve.guest.start"`, `"`+critical+`"`, 1)
		if _, err := Parse([]byte(invalid)); err == nil {
			t.Fatalf("critical PVE operation %q was accepted as a standing scope", critical)
		}
	}
}

func TestAuthorizationPolicyRejectsNullAndDuplicateStandingScopes(t *testing.T) {
	base := `{"version":1,"revision":"policy-standing-shape","targets":[{"id":"target-managed","account":"managed_agent","displayName":"Managed workload","inspect":{"hostSnapshot":true,"processList":true,"units":[],"readPaths":[]},"changes":{"writePaths":[],"units":[],"packages":[],"plugins":[]},"authorization":{"standingScopes":SCOPES}}]}`
	for _, scopes := range []string{`null`, `["service.action","service.action"]`} {
		if _, err := Parse([]byte(strings.Replace(base, "SCOPES", scopes, 1))); err == nil {
			t.Fatalf("invalid standingScopes %s was accepted", scopes)
		}
	}
	missingBase := strings.Replace(base, "SCOPES", `["service.action"]`, 1)
	if _, err := Parse([]byte(missingBase)); err == nil {
		t.Fatal("standing base operation without baseWorkloadDigest was accepted")
	}
	invalidBase := strings.Replace(
		strings.Replace(base, "SCOPES", `[]`, 1),
		`"standingScopes":[]`, `"standingScopes":[],"baseWorkloadDigest":"sha256:wrong"`, 1,
	)
	if _, err := Parse([]byte(invalidBase)); err == nil {
		t.Fatal("invalid baseWorkloadDigest was accepted")
	}
}

func TestPolicyCannotAuthorizeGenericWritesToAgentControlPlane(t *testing.T) {
	payload := `{"version":1,"revision":"policy-control-1234","targets":[{"id":"target-root-admin","account":"root","displayName":"Root administrator","inspect":{"hostSnapshot":true,"processList":true,"units":[],"readPaths":[]},"changes":{"writePaths":["/etc/ops-agent"],"units":[],"packages":[],"plugins":[]}}]}`
	policy, err := Parse([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/etc/ops-agent/targets.json",
		"/etc/ops-agent/runtime.env",
		"/var/lib/ops-agent/root-state/state.json",
		"/opt/pi-ops-agent/current/bin/ops-root-helper",
		"/etc/systemd/system/ops-root-helper.service",
	} {
		err := policy.AuthorizeOperation("target-root-admin", &protocol.FileWrite{
			OperationKind: "file.write", PluginID: protocol.BaseWorkloadPluginID,
			PluginDigest: testBaseWorkloadDigest, Path: path, Content: "attacker-controlled",
		})
		if err == nil {
			t.Fatalf("generic write to protected control path %s was authorized", path)
		}
	}
}

func TestPolicyMakesManualCapsulesAvailableOnlyForRootTargets(t *testing.T) {
	directory := t.TempDir()
	payload := `{"version":1,"revision":"policy-breakglass-1234","targets":[{"id":"target-root-admin","account":"root","displayName":"Root administrator","inspect":{"hostSnapshot":true,"processList":true,"units":[],"readPaths":[]},"changes":{"writePaths":[],"units":[],"packages":[],"plugins":[]},"authorization":{"standingScopes":[]}}]}`
	policy, err := Parse([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if !policy.BreakglassEnabled() {
		t.Fatal("root target manual capsule capability was not discoverable")
	}
	request := protocol.Request{
		Method: protocol.MethodChangePrepare, TargetID: "target-root-admin", PolicyRevision: policy.Revision,
		Operation: &protocol.BreakglassScript{
			OperationKind: "breakglass.script", Script: "touch " + filepath.Join(directory, "marker"),
			BackupPaths: []string{directory}, VerifyScript: "test -e " + filepath.Join(directory, "marker"), Network: false,
		},
	}
	if err := policy.Authorize(request); err != nil {
		t.Fatalf("offline manual root capsule was denied: %v", err)
	}
	request.Operation.(*protocol.BreakglassScript).Network = true
	if err := policy.Authorize(request); err != nil {
		t.Fatalf("explicit network declaration should be reviewed per change: %v", err)
	}

	nonRoot := strings.Replace(payload, `"account":"root"`, `"account":"operator"`, 1)
	nonRootPolicy, err := Parse([]byte(nonRoot))
	if err != nil {
		t.Fatal(err)
	}
	if nonRootPolicy.BreakglassEnabled() {
		t.Fatal("non-root target advertised a manual root capsule")
	}
	if err := nonRootPolicy.Authorize(request); err == nil {
		t.Fatal("non-root target authorized a manual root capsule")
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
	duplicate := strings.Replace(
		payload,
		`"hostSnapshot":true`,
		`"hostSnapshot":true,"hostSnapshot":false`,
		1,
	)
	duplicate = strings.Replace(duplicate, `,"unexpected":true`, "", 1)
	if _, err := Parse([]byte(duplicate)); err == nil || !strings.Contains(err.Error(), "duplicate JSON field") {
		t.Fatalf("duplicate nested policy field was accepted: %v", err)
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
