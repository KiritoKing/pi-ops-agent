package roothelper

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
	"github.com/KiritoKing/pi-ops-agent/internal/targetpolicy"
)

type breakglassCommand struct {
	name string
	args []string
}

type recordingBreakglassRunner struct {
	commands []breakglassCommand
}

func (r *recordingBreakglassRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.commands = append(r.commands, breakglassCommand{name: name, args: slices.Clone(args)})
	return "", nil
}

func breakglassPolicyForTest(t *testing.T) *targetpolicy.Policy {
	t.Helper()
	payload := `{"version":1,"revision":"policy-breakglass-1234","targets":[{"id":"target-root-admin","account":"root","displayName":"Root administrator","inspect":{"hostSnapshot":true,"processList":true,"units":[],"readPaths":[]},"changes":{"writePaths":[],"units":[],"packages":[],"plugins":[]},"authorization":{"standingScopes":[]}}]}`
	policy, err := targetpolicy.Parse([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestBreakglassRequiresCoreDomainAndRootTarget(t *testing.T) {
	policy := breakglassPolicyForTest(t)
	operation := &protocol.BreakglassScript{
		OperationKind: "breakglass.script", Script: "touch /etc/example",
		BackupPaths: []string{"/etc/example"}, VerifyScript: "test -e /etc/example", Network: false,
	}
	scope := ExecutionScope{TargetID: "target-root-admin", PolicyRevision: policy.Revision}
	executor := &OSExecutor{Policy: policy}
	if err := executor.ValidateOperation(scope, operation); err == nil || !strings.Contains(err.Error(), "broker domain") {
		t.Fatalf("PVE-domain manual root capsule boundary was bypassed: %v", err)
	}
	executor.AllowBreakglass = true
	if err := executor.ValidateOperation(scope, operation); err != nil {
		t.Fatalf("explicit offline break-glass was denied: %v", err)
	}
	operation.Network = true
	if err := executor.ValidateOperation(scope, operation); err != nil {
		t.Fatalf("explicit network declaration should be reviewed per change, not pregranted: %v", err)
	}

	operation.Network = false
	executor.Policy = nil
	if err := executor.ValidateOperation(scope, operation); err == nil {
		t.Fatal("break-glass ran without a root-owned target policy")
	}
}

func TestBreakglassCapsuleIsBoundedAndNeverClaimsCompleteRollback(t *testing.T) {
	stateDir := t.TempDir()
	backupPath := filepath.Join(t.TempDir(), "configuration")
	if err := os.WriteFile(backupPath, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy := breakglassPolicyForTest(t)
	runner := &recordingBreakglassRunner{}
	executor := &OSExecutor{
		StateDir: stateDir, Policy: policy, AllowBreakglass: true, Runner: runner,
		SystemdRunPath: "/test/systemd-run",
	}
	scope := ExecutionScope{
		ChangeID: "change-breakglass-0001", TargetID: "target-root-admin",
		PolicyRevision: policy.Revision,
	}
	operation := &protocol.BreakglassScript{
		OperationKind: "breakglass.script", Script: "touch /etc/example",
		BackupPaths: []string{backupPath}, VerifyScript: "test -e /etc/example", Network: false,
	}
	result, err := executor.Prepare(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	if result.RollbackAvailable {
		t.Fatal("arbitrary root capsule incorrectly claimed a complete rollback")
	}
	if len(result.BackupRefs) != 1 {
		t.Fatalf("break-glass recovery evidence missing: %#v", result.BackupRefs)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := executor.Execute(ctx, scope, operation, result); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Verify(ctx, scope, operation, result); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 3 {
		t.Fatalf("expected tar, script, and verification commands: %#v", runner.commands)
	}
	for _, command := range runner.commands[1:] {
		if command.name != "/test/systemd-run" {
			t.Fatalf("capsule used an unexpected executable: %#v", command)
		}
		joined := strings.Join(command.args, "\n")
		for _, expected := range []string{
			"--property=PrivateNetwork=yes",
			"--property=RuntimeMaxSec=120",
			"--property=ReadOnlyPaths=" + filepath.Join(stateDir, "changes", scope.ChangeID),
			"/bin/bash",
		} {
			if !strings.Contains(joined, expected) {
				t.Fatalf("capsule is missing %q: %#v", expected, command.args)
			}
		}
	}
}

func TestBreakglassCanProceedWithExplicitlyEmptyEvidenceButDoesNotInventIt(t *testing.T) {
	policy := breakglassPolicyForTest(t)
	runner := &recordingBreakglassRunner{}
	executor := &OSExecutor{
		StateDir: t.TempDir(), Policy: policy, AllowBreakglass: true, Runner: runner,
		SystemdRunPath: "/test/systemd-run",
	}
	scope := ExecutionScope{
		ChangeID: "change-breakglass-0003", TargetID: "target-root-admin",
		PolicyRevision: policy.Revision,
	}
	operation := &protocol.BreakglassScript{
		OperationKind: "breakglass.script", Script: "true", BackupPaths: []string{}, Network: false,
	}
	result, err := executor.Prepare(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.BackupRefs) != 0 || result.RollbackAvailable {
		t.Fatalf("empty evidence was invented: %#v", result)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("empty backup list unexpectedly ran a backup command: %#v", runner.commands)
	}
	if err := executor.Execute(context.Background(), scope, operation, result); err != nil {
		t.Fatal(err)
	}
	verification, err := executor.Verify(context.Background(), scope, operation, result)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(verification, "without a caller-provided privileged postcondition") {
		t.Fatalf("missing verification was hidden: %q", verification)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("missing verification unexpectedly ran another capsule: %#v", runner.commands)
	}
}

func TestNetworkDeclarationChangesCapsuleNamespace(t *testing.T) {
	policy := breakglassPolicyForTest(t)
	runner := &recordingBreakglassRunner{}
	executor := &OSExecutor{
		StateDir: t.TempDir(), Policy: policy, AllowBreakglass: true, Runner: runner,
		SystemdRunPath: "/test/systemd-run",
	}
	scope := ExecutionScope{
		ChangeID: "change-breakglass-0002", TargetID: "target-root-admin",
		PolicyRevision: policy.Revision,
	}
	operation := &protocol.BreakglassScript{
		OperationKind: "breakglass.script", Script: "true", BackupPaths: []string{"/etc/hosts"},
		VerifyScript: "true", Network: true,
	}
	if err := executor.ValidateOperation(scope, operation); err != nil {
		t.Fatal(err)
	}
	changeDir := filepath.Join(executor.StateDir, "changes", scope.ChangeID)
	if err := os.MkdirAll(changeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(changeDir, "script.sh")
	if err := os.WriteFile(script, []byte("true\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.runCapsule(context.Background(), scope, script, true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(runner.commands[0].args, "\n"), "PrivateNetwork=yes") {
		t.Fatal("network-approved capsule was placed in the offline namespace")
	}
}
