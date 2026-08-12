package roothelper

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/peercred"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
	"github.com/KiritoKing/pi-ops-agent/internal/targetpolicy"
)

const testPVEPluginID = "workload.pve"

const testPVEUPID = "UPID:pve1:00000001:00000002:00000003:qmstart:100:root@pam:"

type pveCall struct {
	Name string
	Args []string
}

type pveStaticRunner struct{ output string }

func (r pveStaticRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	if name != pveshPath || strings.Join(args, " ") != "get /cluster/status --output-format json" {
		return "", fmt.Errorf("unexpected PVE readiness command: %s %#v", name, args)
	}
	return r.output, nil
}

func TestPVEReadinessAllowsExplicitStandaloneButNotFormerClusterMember(t *testing.T) {
	standalone := &OSExecutor{Runner: pveStaticRunner{output: `[{"type":"node","name":"pve1","local":1,"nodeid":0,"online":1}]`}}
	if err := standalone.requirePVEReady(context.Background(), "pve1"); err != nil {
		t.Fatalf("explicit standalone PVE node was rejected: %v", err)
	}
	formerMember := &OSExecutor{Runner: pveStaticRunner{output: `[{"type":"node","name":"pve1","local":1,"nodeid":2,"online":1}]`}}
	if err := formerMember.requirePVEReady(context.Background(), "pve1"); err == nil {
		t.Fatal("non-zero cluster nodeid bypassed the quorum requirement")
	}
	duplicateCluster := &OSExecutor{Runner: pveStaticRunner{output: `[{"type":"cluster","name":"one","quorate":1},{"type":"cluster","name":"two","quorate":0},{"type":"node","name":"pve1","online":1}]`}}
	if err := duplicateCluster.requirePVEReady(context.Background(), "pve1"); err == nil || !strings.Contains(err.Error(), "duplicate cluster") {
		t.Fatalf("conflicting duplicate cluster rows were accepted: %v", err)
	}
	duplicateNode := &OSExecutor{Runner: pveStaticRunner{output: `[{"type":"cluster","quorate":1},{"type":"node","name":"pve1","online":1},{"type":"node","node":"pve1","online":0}]`}}
	if err := duplicateNode.requirePVEReady(context.Background(), "pve1"); err == nil || !strings.Contains(err.Error(), "duplicate node") {
		t.Fatalf("conflicting duplicate node rows were accepted: %v", err)
	}
}

type pveActionRunner struct {
	calls           []pveCall
	taskExitStatus  string
	locked          bool
	mutationStarted bool
	taskRunning     bool
}

type pveAsyncServiceRunner struct {
	mu                    sync.Mutex
	running               bool
	mutationStarted       bool
	taskExitStatus        string
	taskStatusCalls       int
	activeTaskStatusCalls int
	maxTaskStatusCalls    int
	statusDelay           time.Duration
}

func (r *pveAsyncServiceRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if name != pveshPath {
		return "", fmt.Errorf("unexpected executable %s", name)
	}
	joined := strings.Join(args, " ")
	switch {
	case joined == "get /cluster/status --output-format json":
		return `[{"type":"cluster","quorate":1},{"type":"node","name":"pve1","online":1}]`, nil
	case joined == "get /nodes/pve1/qemu/100/status/current --output-format json":
		r.mu.Lock()
		started := r.mutationStarted
		r.mu.Unlock()
		if started {
			return `{"status":"running"}`, nil
		}
		return `{"status":"stopped"}`, nil
	case joined == "create /nodes/pve1/qemu/100/status/start --output-format json":
		r.mu.Lock()
		r.mutationStarted = true
		r.mu.Unlock()
		return `"` + testPVEUPID + `"`, nil
	case strings.HasPrefix(joined, "get /nodes/pve1/tasks/"+testPVEUPID+"/status "):
		r.mu.Lock()
		r.taskStatusCalls++
		r.activeTaskStatusCalls++
		if r.activeTaskStatusCalls > r.maxTaskStatusCalls {
			r.maxTaskStatusCalls = r.activeTaskStatusCalls
		}
		running, exitStatus := r.running, r.taskExitStatus
		r.mu.Unlock()
		defer func() {
			r.mu.Lock()
			r.activeTaskStatusCalls--
			r.mu.Unlock()
		}()
		delay := r.statusDelay
		if delay <= 0 {
			delay = 2 * time.Millisecond
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(delay):
		}
		if running {
			return `{"status":"running"}`, nil
		}
		if exitStatus == "" {
			exitStatus = "OK"
		}
		return fmt.Sprintf(`{"status":"stopped","exitstatus":%q}`, exitStatus), nil
	default:
		return "", fmt.Errorf("unexpected PVE command: %s", joined)
	}
}

func (r *pveAsyncServiceRunner) finish(exitStatus string) {
	r.mu.Lock()
	r.running = false
	r.taskExitStatus = exitStatus
	r.mu.Unlock()
}

func (r *pveAsyncServiceRunner) statusConcurrency() (calls, maximum int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.taskStatusCalls, r.maxTaskStatusCalls
}

func (r *pveActionRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, pveCall{Name: name, Args: append([]string(nil), args...)})
	joined := strings.Join(args, " ")
	switch {
	case joined == "get /cluster/status --output-format json":
		return `[{"type":"cluster","quorate":1},{"type":"node","name":"pve1","online":1}]`, nil
	case joined == "get /nodes/pve1/qemu/100/status/current --output-format json":
		if r.locked {
			return `{"status":"stopped","lock":"backup"}`, nil
		}
		if r.mutationStarted {
			return `{"status":"running"}`, nil
		}
		return `{"status":"stopped"}`, nil
	case joined == "create /nodes/pve1/qemu/100/status/start --output-format json":
		r.mutationStarted = true
		return `"` + testPVEUPID + `"`, nil
	case strings.HasPrefix(joined, "get /nodes/pve1/tasks/"+testPVEUPID+"/status "):
		if r.taskRunning {
			return `{"status":"running"}`, nil
		}
		exitStatus := r.taskExitStatus
		if exitStatus == "" {
			exitStatus = "OK"
		}
		return fmt.Sprintf(`{"status":"stopped","exitstatus":%q}`, exitStatus), nil
	default:
		return "", fmt.Errorf("unexpected PVE command: %s %s", name, joined)
	}
}

func TestPVEExecutionRechecksLocksAfterApprovalPreparation(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	policy := pveRootPolicy(t, digest, []string{"pve.guest.start"})
	runner := &pveActionRunner{}
	executor := &OSExecutor{StateDir: t.TempDir(), Runner: runner, Policy: policy}
	scope := ExecutionScope{ChangeID: "change-pve-recheck-1", TargetID: "target-pve-root", PolicyRevision: policy.Revision}
	operation := &protocol.PVEGuestAction{
		OperationKind: "pve.guest.action", PluginID: testPVEPluginID,
		PluginDigest: digest, Node: "pve1", GuestType: "qemu", VMID: 100, Action: "start",
	}
	bindPVEPrecondition(t, executor, &scope, operation)
	prepared, err := executor.Prepare(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	runner.locked = true
	if err := executor.Execute(context.Background(), scope, operation, prepared); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("changed PVE lock did not stop mutation: %v", err)
	}
	for _, call := range runner.calls {
		if len(call.Args) >= 2 && call.Args[0] == "create" {
			t.Fatalf("PVE mutation ran after lock changed: %#v", call)
		}
	}
}

func TestPVEFinalPreconditionRecheckBindsSnapshotStatusAndBackupSet(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)

	snapshotRunner := &pveSnapshotRunner{guestStatus: "running"}
	snapshotExecutor := &OSExecutor{
		StateDir: t.TempDir(), Runner: snapshotRunner,
		Policy: pveRootPolicy(t, digest, []string{"pve.snapshot.create"}),
	}
	snapshotScope := ExecutionScope{
		ChangeID: "pve-change-snapshot-final-check", TargetID: "target-pve-root",
		PolicyRevision: snapshotExecutor.Policy.Revision,
	}
	snapshotOperation := &protocol.PVESnapshotCreate{
		OperationKind: "pve.snapshot.create", PluginID: testPVEPluginID,
		PluginDigest: digest, Node: "pve1", GuestType: "qemu", VMID: 100, Snapshot: "new-snapshot",
	}
	bindPVEPrecondition(t, snapshotExecutor, &snapshotScope, snapshotOperation)
	snapshotPrepared, err := snapshotExecutor.Prepare(context.Background(), snapshotScope, snapshotOperation)
	if err != nil {
		t.Fatal(err)
	}
	snapshotRunner.guestStatus = "stopped"
	err = snapshotExecutor.Execute(context.Background(), snapshotScope, snapshotOperation, snapshotPrepared)
	if err == nil || !noMutationStarted(err) || snapshotRunner.primaryStarted {
		t.Fatalf("snapshot.create ignored approved currentStatus drift: err=%v calls=%#v", err, snapshotRunner.calls)
	}
	if _, err := os.Stat(filepath.Join(snapshotExecutor.StateDir, "changes", snapshotScope.ChangeID, "pve-primary-intent.json")); err != nil {
		t.Fatalf("final snapshot check did not run after durable primary intent: %v", err)
	}

	backupRunner := &pveSnapshotRunner{guestStatus: "running"}
	backupExecutor := &OSExecutor{
		StateDir: t.TempDir(), Runner: backupRunner,
		Policy: pveRootPolicy(t, digest, []string{"pve.guest.backup"}),
	}
	backupScope := ExecutionScope{
		ChangeID: "pve-change-backup-final-check", TargetID: "target-pve-root",
		PolicyRevision: backupExecutor.Policy.Revision,
	}
	backupOperation := &protocol.PVEGuestBackup{
		OperationKind: "pve.guest.backup", PluginID: testPVEPluginID,
		PluginDigest: digest, Node: "pve1", GuestType: "qemu", VMID: 100, Storage: "local",
	}
	bindPVEPrecondition(t, backupExecutor, &backupScope, backupOperation)
	backupPrepared, err := backupExecutor.Prepare(context.Background(), backupScope, backupOperation)
	if err != nil {
		t.Fatal(err)
	}
	// Model an unrelated backup appearing after approval. The former partial
	// recheck only observed guest lock and storage readiness.
	backupRunner.backupStarted = true
	err = backupExecutor.Execute(context.Background(), backupScope, backupOperation, backupPrepared)
	if err == nil || !noMutationStarted(err) || backupRunner.primaryStarted {
		t.Fatalf("guest backup ignored approved backup-set drift: err=%v calls=%#v", err, backupRunner.calls)
	}
}

type pveMigrationPlanRunner struct {
	status         string
	primaryStarted bool
}

func (r *pveMigrationPlanRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	joined := strings.Join(args, " ")
	if name != pveshPath {
		return "", fmt.Errorf("unexpected executable %s", name)
	}
	switch {
	case joined == "get /cluster/status --output-format json":
		return `[{"type":"cluster","quorate":1},{"type":"node","name":"pve1","online":1},{"type":"node","name":"pve2","online":1}]`, nil
	case joined == "get /nodes/pve1/qemu/100/status/current --output-format json":
		return fmt.Sprintf(`{"status":%q}`, r.status), nil
	case joined == "get /cluster/resources --type vm --output-format json":
		return `[{"type":"qemu","vmid":100,"node":"pve1"}]`, nil
	case joined == "create /nodes/pve1/qemu/100/migrate --target pve2 --online 1 --output-format json":
		r.primaryStarted = true
		return `"` + testPVEUPID + `"`, nil
	default:
		return "", fmt.Errorf("unexpected migration planning command: %s", joined)
	}
}

func TestPVEFinalPreconditionRecheckBindsMigrationStatusAndMode(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	runner := &pveMigrationPlanRunner{status: "running"}
	executor := &OSExecutor{
		StateDir: t.TempDir(), Runner: runner,
		Policy: pveRootPolicy(t, digest, []string{"pve.guest.migrate"}),
	}
	scope := ExecutionScope{
		ChangeID: "pve-change-migrate-final-check", TargetID: "target-pve-root",
		PolicyRevision: executor.Policy.Revision,
	}
	operation := &protocol.PVEGuestMigrate{
		OperationKind: "pve.guest.migrate", PluginID: testPVEPluginID,
		PluginDigest: digest, Node: "pve1", GuestType: "qemu", VMID: 100,
		TargetNode: "pve2", Online: true,
	}
	bindPVEPrecondition(t, executor, &scope, operation)
	prepared, err := executor.Prepare(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	runner.status = "stopped"
	err = executor.Execute(context.Background(), scope, operation, prepared)
	if err == nil || !noMutationStarted(err) || runner.primaryStarted {
		t.Fatalf("migration ignored approved status/mode drift: err=%v started=%t", err, runner.primaryStarted)
	}
}

func TestPVEGuestActionUsesFixedPveshAndAuthoritativeTaskStatus(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	policy := pveRootPolicy(t, digest, []string{"pve.guest.start"})
	runner := &pveActionRunner{}
	executor := &OSExecutor{StateDir: t.TempDir(), Runner: runner, Policy: policy}
	scope := ExecutionScope{
		ChangeID: "change-pve-action-1234", TargetID: "target-pve-root",
		PolicyRevision: policy.Revision, CapabilityRevision: "capability-pve-v1",
	}
	operation := &protocol.PVEGuestAction{
		OperationKind: "pve.guest.action", PluginID: testPVEPluginID,
		PluginDigest: digest, Node: "pve1", GuestType: "qemu", VMID: 100, Action: "start",
	}
	bindPVEPrecondition(t, executor, &scope, operation)
	prepared, err := executor.Prepare(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.RollbackAvailable {
		t.Fatal("PVE start incorrectly exposed a stale-plan automatic rollback")
	}
	if err := executor.Execute(context.Background(), scope, operation, prepared); err != nil {
		t.Fatal(err)
	}
	verification, err := executor.Verify(context.Background(), scope, operation, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(verification, testPVEUPID) {
		t.Fatalf("verification omitted authoritative UPID: %s", verification)
	}
	primaryIntent, err := os.ReadFile(filepath.Join(executor.StateDir, "changes", scope.ChangeID, "pve-primary-intent.json"))
	if err != nil || !strings.Contains(string(primaryIntent), `"planHash":"`+scope.PlanHash+`"`) ||
		!strings.Contains(string(primaryIntent), `"preconditionDigest":"`+scope.PreconditionDigest+`"`) {
		t.Fatalf("primary PVE intent was not durably plan-bound before API: payload=%s err=%v", primaryIntent, err)
	}
	mutationSeen := false
	for _, call := range runner.calls {
		if call.Name != pveshPath {
			t.Fatalf("PVE workload invoked an unexpected executable: %#v", call)
		}
		if len(call.Args) >= 2 && call.Args[0] == "create" && call.Args[1] == "/nodes/pve1/qemu/100/status/start" {
			mutationSeen = true
			if strings.Join(call.Args[2:], " ") != "--output-format json" {
				t.Fatalf("guest action gained arbitrary arguments: %#v", call.Args)
			}
		}
	}
	if !mutationSeen {
		t.Fatal("fixed PVE guest action was not executed")
	}
}

type pveSnapshotRunner struct {
	calls                  []pveCall
	backupStarted          bool
	primaryStarted         bool
	ambiguous              bool
	guestStatus            string
	guestStatusAfterBackup string
	backupStartError       bool
}

func (r *pveSnapshotRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, pveCall{Name: name, Args: append([]string(nil), args...)})
	joined := strings.Join(args, " ")
	switch {
	case joined == "get /cluster/status --output-format json":
		return `[{"type":"cluster","quorate":1},{"type":"node","name":"pve1","online":1}]`, nil
	case joined == "get /nodes/pve1/qemu/100/status/current --output-format json":
		status := r.guestStatus
		if r.backupStarted && r.guestStatusAfterBackup != "" {
			status = r.guestStatusAfterBackup
		}
		if status == "" {
			status = "running"
		}
		return fmt.Sprintf(`{"status":%q}`, status), nil
	case joined == "get /nodes/pve1/qemu/100/snapshot --output-format json":
		return `[{"name":"safe"},{"name":"current"}]`, nil
	case joined == "get /nodes/pve1/storage/local/status --output-format json":
		return `{"active":1,"enabled":1}`, nil
	case joined == "get /nodes/pve1/storage/local/content --content backup --vmid 100 --output-format json":
		if r.backupStarted {
			if r.ambiguous {
				return `[{"volid":"local:backup/vzdump-qemu-100-2026_08_08-00_00_00.vma.zst","content":"backup","vmid":100},{"volid":"local:backup/vzdump-qemu-100-2026_08_08-00_00_01.vma.zst","content":"backup","vmid":100}]`, nil
			}
			return `[{"volid":"local:backup/vzdump-qemu-100-2026_08_08-00_00_00.vma.zst","content":"backup","vmid":100}]`, nil
		}
		return `[]`, nil
	case joined == "create /nodes/pve1/vzdump --vmid 100 --storage local --mode snapshot --compress zstd --remove 0 --output-format json":
		r.backupStarted = true
		if r.backupStartError {
			return "", errors.New("lost PVE response after request submission")
		}
		return `"` + strings.Replace(testPVEUPID, "qmstart", "vzdump", 1) + `"`, nil
	case joined == "create /nodes/pve1/qemu/100/snapshot/safe/rollback --output-format json":
		r.primaryStarted = true
		return `"` + testPVEUPID + `"`, nil
	case strings.Contains(joined, "/tasks/UPID:pve1:"):
		return `{"status":"stopped","exitstatus":"OK"}`, nil
	default:
		return "", fmt.Errorf("unexpected PVE command: %s %s", name, joined)
	}
}

func TestPVEDestructiveSnapshotRequiresCompletedSafetyBackup(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	policy := pveRootPolicy(t, digest, []string{"pve.snapshot.rollback"})
	runner := &pveSnapshotRunner{}
	executor := &OSExecutor{StateDir: t.TempDir(), Runner: runner, Policy: policy}
	evidence := []string{}
	scope := ExecutionScope{
		ChangeID: "change-pve-snapshot-1", TargetID: "target-pve-root", PolicyRevision: policy.Revision,
		RecordEvidence: func(refs ...string) error {
			evidence = append(evidence, refs...)
			return nil
		},
	}
	operation := &protocol.PVESnapshotRollback{
		OperationKind: "pve.snapshot.rollback", PluginID: testPVEPluginID,
		PluginDigest: digest, Node: "pve1", GuestType: "qemu", VMID: 100,
		Snapshot: "safe", BackupStorage: "local",
	}
	bindPVEPrecondition(t, executor, &scope, operation)
	result, err := executor.Prepare(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	if result.RollbackAvailable || len(result.BackupRefs) != 0 || runner.backupStarted {
		t.Fatalf("destructive snapshot preparation was not read-only: result=%#v calls=%#v", result, runner.calls)
	}
	if err := executor.Execute(context.Background(), scope, operation, result); err != nil {
		t.Fatal(err)
	}
	if !runner.backupStarted || !runner.primaryStarted || len(evidence) != 3 ||
		!strings.HasPrefix(evidence[0], "pve:task:UPID:pve1:") ||
		evidence[1] != "pve:volume:local:backup/vzdump-qemu-100-2026_08_08-00_00_00.vma.zst" ||
		!strings.HasPrefix(evidence[2], "pve:task:UPID:pve1:") {
		t.Fatalf("destructive snapshot execution did not order backup evidence before primary: evidence=%#v calls=%#v", evidence, runner.calls)
	}
	recoveryRecord, err := os.ReadFile(filepath.Join(executor.StateDir, "changes", scope.ChangeID, "pve-safety-backup-task.json"))
	if err != nil || !strings.Contains(string(recoveryRecord), `"operation":"pve.snapshot.rollback"`) || !strings.Contains(string(recoveryRecord), `"upid":"UPID:pve1:`) {
		t.Fatalf("safety backup UPID was not persisted before waiting: payload=%s err=%v", recoveryRecord, err)
	}
	primaryIntent, err := os.ReadFile(filepath.Join(executor.StateDir, "changes", scope.ChangeID, "pve-primary-intent.json"))
	if err != nil || !strings.Contains(string(primaryIntent), `"planHash":"`+scope.PlanHash+`"`) {
		t.Fatalf("destructive primary intent was not plan-bound before primary API: payload=%s err=%v", primaryIntent, err)
	}
	backupIndex, primaryIndex := -1, -1
	for index, call := range runner.calls {
		joined := strings.Join(call.Args, " ")
		if strings.Contains(joined, "/vzdump") && len(call.Args) > 0 && call.Args[0] == "create" {
			backupIndex = index
		}
		if strings.Contains(joined, "/snapshot/safe/rollback") {
			primaryIndex = index
		}
	}
	if backupIndex < 0 || primaryIndex < 0 || backupIndex >= primaryIndex {
		t.Fatalf("primary snapshot mutation did not follow its completed safety backup: %#v", runner.calls)
	}
}

func TestPVESafetyBackupLostUPIDRetainsDurableMutationIntent(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	policy := pveRootPolicy(t, digest, []string{"pve.snapshot.rollback"})
	runner := &pveSnapshotRunner{backupStartError: true}
	executor := &OSExecutor{StateDir: t.TempDir(), Runner: runner, Policy: policy}
	scope := ExecutionScope{
		ChangeID: "pve-change-safety-lost-upid", TargetID: "target-pve-root",
		PolicyRevision: policy.Revision,
	}
	operation := &protocol.PVESnapshotRollback{
		OperationKind: "pve.snapshot.rollback", PluginID: testPVEPluginID,
		PluginDigest: digest, Node: "pve1", GuestType: "qemu", VMID: 100,
		Snapshot: "safe", BackupStorage: "local",
	}
	bindPVEPrecondition(t, executor, &scope, operation)
	prepared, err := executor.Prepare(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	err = executor.Execute(context.Background(), scope, operation, prepared)
	if err == nil || !mutationOutcomeUncertain(err) {
		t.Fatalf("lost safety-backup UPID was not treated as an uncertain mutation: %v", err)
	}
	intent, readErr := os.ReadFile(filepath.Join(
		executor.StateDir, "changes", scope.ChangeID, "pve-safety-backup-intent.json",
	))
	if readErr != nil || !strings.Contains(string(intent), `"operation":"pve.snapshot.rollback"`) ||
		!strings.Contains(string(intent), `"storage":"local"`) {
		t.Fatalf("durable safety-backup intent is missing: payload=%s err=%v", intent, readErr)
	}
	if _, recoverErr := executor.RecoverEvidence(context.Background(), scope, operation); recoverErr == nil || !strings.Contains(recoverErr.Error(), "without a recoverable task UPID") {
		t.Fatalf("recovery accepted an intent whose task UPID is unknown: %v", recoverErr)
	}
}

func TestPVEDestructiveSnapshotRejectsGuestStateDriftAfterSafetyBackup(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	policy := pveRootPolicy(t, digest, []string{"pve.snapshot.rollback"})
	runner := &pveSnapshotRunner{guestStatus: "running", guestStatusAfterBackup: "stopped"}
	executor := &OSExecutor{StateDir: t.TempDir(), Runner: runner, Policy: policy}
	scope := ExecutionScope{
		ChangeID: "pve-change-safety-status-drift", TargetID: "target-pve-root",
		PolicyRevision: policy.Revision,
	}
	operation := &protocol.PVESnapshotRollback{
		OperationKind: "pve.snapshot.rollback", PluginID: testPVEPluginID,
		PluginDigest: digest, Node: "pve1", GuestType: "qemu", VMID: 100,
		Snapshot: "safe", BackupStorage: "local",
	}
	bindPVEPrecondition(t, executor, &scope, operation)
	result, err := executor.Prepare(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	err = executor.Execute(context.Background(), scope, operation, result)
	if err == nil || !strings.Contains(err.Error(), "approved guest status changed") {
		t.Fatalf("guest status drift after the long safety backup was accepted: %v", err)
	}
	if !runner.backupStarted {
		t.Fatal("guest state drift was injected before the safety backup completed")
	}
	for _, call := range runner.calls {
		if strings.Contains(strings.Join(call.Args, " "), "/snapshot/safe/rollback") {
			t.Fatal("destructive snapshot rollback ran after approved guest state drifted")
		}
	}
	recoveryScope := scope
	recoveryScope.MutationDisposition = protocol.PVEMutationDispositionUnknown
	readiness, reconcileErr := executor.ReconcilePVERecoveryParent(context.Background(), recoveryScope, operation)
	if reconcileErr != nil || readiness.MutationDisposition != protocol.PVEMutationDispositionTasksTerminal ||
		len(readiness.TaskEvidence) != 1 || readiness.TaskEvidence[0].Role != "safety-backup" {
		t.Fatalf("durable primary no-start evidence did not permit typed recovery after terminal safety backup: readiness=%#v err=%v", readiness, reconcileErr)
	}
}

func TestPVETaskFailureCannotBeReportedAsSuccess(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	policy := pveRootPolicy(t, digest, []string{"pve.guest.start"})
	runner := &pveActionRunner{taskExitStatus: "ERROR"}
	executor := &OSExecutor{StateDir: t.TempDir(), Runner: runner, Policy: policy}
	scope := ExecutionScope{ChangeID: "change-pve-failure-1", TargetID: "target-pve-root", PolicyRevision: policy.Revision}
	operation := &protocol.PVEGuestAction{
		OperationKind: "pve.guest.action", PluginID: testPVEPluginID,
		PluginDigest: digest, Node: "pve1", GuestType: "qemu", VMID: 100, Action: "start",
	}
	bindPVEPrecondition(t, executor, &scope, operation)
	prepared, err := executor.Prepare(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.Execute(context.Background(), scope, operation, prepared); err == nil || !strings.Contains(err.Error(), "exitstatus") {
		t.Fatalf("failed PVE task was accepted: %v", err)
	}
}

func TestPVEPostUPIDTimeoutIsUncertainAndCannotRollbackRunningTask(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	policy := pveRootPolicy(t, digest, []string{"pve.guest.start"})
	runner := &pveActionRunner{taskRunning: true}
	executor := &OSExecutor{StateDir: t.TempDir(), Runner: runner, Policy: policy}
	scope := ExecutionScope{ChangeID: "pve-change-running-task", TargetID: "target-pve-root", PolicyRevision: policy.Revision}
	operation := &protocol.PVEGuestAction{
		OperationKind: "pve.guest.action", PluginID: testPVEPluginID,
		PluginDigest: digest, Node: "pve1", GuestType: "qemu", VMID: 100, Action: "start",
	}
	bindPVEPrecondition(t, executor, &scope, operation)
	prepared, err := executor.Prepare(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	err = executor.Execute(ctx, scope, operation, prepared)
	if err == nil || !mutationOutcomeUncertain(err) {
		t.Fatalf("post-UPID timeout did not carry an uncertain outcome marker: %v", err)
	}
	if rollbackErr := executor.Rollback(context.Background(), scope, operation, prepared); rollbackErr == nil || !strings.Contains(rollbackErr.Error(), "typed recovery change") {
		t.Fatalf("PVE operation exposed an automatic rollback under the original plan: %v", rollbackErr)
	}
	forged := prepared
	forged.RollbackAvailable = true
	if rollbackErr := executor.Rollback(context.Background(), scope, operation, forged); rollbackErr == nil || !strings.Contains(rollbackErr.Error(), "typed recovery change") {
		t.Fatalf("forged rollbackAvailable enabled PVE compensation: %v", rollbackErr)
	}
	createCalls := 0
	for _, call := range runner.calls {
		if len(call.Args) > 0 && call.Args[0] == "create" {
			createCalls++
		}
	}
	if createCalls != 1 {
		t.Fatalf("a compensating PVE task started before the original task stopped: %d calls", createCalls)
	}
}

func TestPVEApprovalReturnsSignedExecutingAndConvergesWithoutFurtherHTTP(t *testing.T) {
	now := time.Date(2026, 8, 8, 15, 0, 0, 0, time.UTC)
	runner := &pveAsyncServiceRunner{running: true}
	background, stopBackground := context.WithCancel(context.Background())
	defer stopBackground()
	service, executor, receiptPublic := newAsyncPVEService(t, now, runner, background)

	prepared, operation := prepareAsyncPVEChange(t, service, now, "prepare-pve-async-no-http")
	request := pveActionRequest(now, "approve-pve-async-no-http", protocol.MethodChangeApprove, prepared.ChangeID)
	canceledRequest, cancelRequest := context.WithCancel(context.Background())
	cancelRequest()
	startedAt := time.Now()
	response := service.Handle(canceledRequest, peercred.Credential{UID: service.ApproverUID}, request)
	if !response.OK || response.State != StateExecuting || response.Receipt == nil || time.Since(startedAt) > time.Second {
		t.Fatalf("PVE approval did not promptly return a signed EXECUTING response: %#v", response)
	}
	change, ok := service.Store.Change(prepared.ChangeID)
	if !ok || len(change.BackupRefs) != 1 || change.BackupRefs[0] != "pve:task:"+testPVEUPID {
		t.Fatalf("PVE running UPID was not durable before the response: %#v", change)
	}
	if _, err := os.Stat(filepath.Join(executor.StateDir, "changes", change.ID, "pve-task.json")); err != nil {
		t.Fatalf("root-only PVE task record was not durable before the response: %v", err)
	}
	claims := protocol.BrokerReceiptClaims{
		KeyID: "pve-receipt-v1", Domain: DomainPVE, RequestID: request.RequestID,
		Method: protocol.MethodChangeApprove, ServerID: change.ServerID, MachineID: change.MachineID,
		TargetID: change.TargetID, ChangeID: change.ID, PlanHash: change.PlanHash,
	}
	if err := protocol.VerifyBrokerResponse(response, claims, now, receiptPublic); err != nil {
		t.Fatalf("EXECUTING action receipt did not verify: %v", err)
	}

	// No status/action request follows. The only request context was already
	// canceled; the broker-owned worker must still observe and verify terminal
	// state with its own bounded contexts.
	runner.finish("OK")
	committed := waitForPVEChangeState(t, service, change.ID, StateCommitted)
	if !strings.Contains(committed.Verification, testPVEUPID) {
		t.Fatalf("background reconciliation committed without UPID-bound verification: %#v", committed)
	}
	competitor := *committed
	competitor.ID = "pve-change-after-async-commit"
	competitor.State = StatePreparing
	competitor.UpdatedAt = now.Add(time.Second).Format(time.RFC3339Nano)
	if err := service.Store.PutChangeWithResourceLock(&competitor); err != nil {
		t.Fatalf("verified async commit did not release the VMID lock: %v", err)
	}
	_ = operation
}

func TestPVESignedVerifyingStatusEnsuresMissingWorkerAndCommits(t *testing.T) {
	now := time.Date(2026, 8, 8, 15, 15, 0, 0, time.UTC)
	runner := &pveAsyncServiceRunner{running: true}
	firstBackground, stopFirst := context.WithCancel(context.Background())
	service, _, receiptPublic := newAsyncPVEService(t, now, runner, firstBackground)
	prepared, _ := prepareAsyncPVEChange(t, service, now, "prepare-pve-verifying-status")
	approved := service.Handle(
		context.Background(), peercred.Credential{UID: service.ApproverUID},
		pveActionRequest(now, "approve-pve-verifying-status", protocol.MethodChangeApprove, prepared.ChangeID),
	)
	if !approved.OK || approved.State != StateExecuting {
		t.Fatalf("PVE VERIFYING status fixture did not start: %#v", approved)
	}
	stopFirst()
	waitForPVEWorkerCount(t, service, 0)

	// Model a durable terminal-task checkpoint whose former worker disappeared
	// before verification. No startup recovery runs in this process: the signed
	// VERIFYING status itself must idempotently repair worker scheduling.
	runner.finish("OK")
	change, ok := service.Store.Change(prepared.ChangeID)
	if !ok {
		t.Fatal("PVE VERIFYING status fixture change is missing")
	}
	change.State = StateVerifying
	change.UpdatedAt = timestamp(now.Add(time.Second))
	if err := service.Store.PutChange(change); err != nil {
		t.Fatalf("persist VERIFYING fixture: %v", err)
	}
	secondBackground, stopSecond := context.WithCancel(context.Background())
	defer stopSecond()
	service.PVEBackgroundContext = secondBackground

	request := pveActionRequest(
		now, "status-pve-verifying-repair", protocol.MethodChangeStatus, prepared.ChangeID,
	)
	response := service.Handle(
		context.Background(), peercred.Credential{UID: service.AgentUID}, request,
	)
	if !response.OK || response.State != StateVerifying || response.Receipt == nil {
		t.Fatalf("PVE status did not return the signed durable VERIFYING state: %#v", response)
	}
	claims := protocol.BrokerReceiptClaims{
		KeyID: "pve-receipt-v1", Domain: DomainPVE, RequestID: request.RequestID,
		Method: protocol.MethodChangeStatus, ServerID: change.ServerID, MachineID: change.MachineID,
		TargetID: change.TargetID, ChangeID: change.ID, PlanHash: change.PlanHash,
	}
	if err := protocol.VerifyBrokerResponse(response, claims, now, receiptPublic); err != nil {
		t.Fatalf("VERIFYING status receipt did not verify: %v", err)
	}
	committed := waitForPVEChangeState(t, service, change.ID, StateCommitted)
	if !strings.Contains(committed.Verification, testPVEUPID) {
		t.Fatalf("VERIFYING status worker committed without UPID-bound verification: %#v", committed)
	}
}

func TestPVEAsyncRestartResumesSingleflightAndTerminalFailureRetainsLock(t *testing.T) {
	now := time.Date(2026, 8, 8, 15, 30, 0, 0, time.UTC)
	runner := &pveAsyncServiceRunner{running: true}
	firstBackground, stopFirst := context.WithCancel(context.Background())
	first, executor, _ := newAsyncPVEService(t, now, runner, firstBackground)
	prepared, _ := prepareAsyncPVEChange(t, first, now, "prepare-pve-async-restart")
	approved := first.Handle(
		context.Background(), peercred.Credential{UID: first.ApproverUID},
		pveActionRequest(now, "approve-pve-async-restart", protocol.MethodChangeApprove, prepared.ChangeID),
	)
	if !approved.OK || approved.State != StateExecuting {
		t.Fatalf("PVE restart fixture did not reach EXECUTING: %#v", approved)
	}
	stopFirst()
	waitForPVEWorkerCount(t, first, 0)

	reopened, err := OpenStore(first.Store.Directory())
	if err != nil {
		t.Fatal(err)
	}
	secondBackground, stopSecond := context.WithCancel(context.Background())
	defer stopSecond()
	second := &Service{
		AgentUID: first.AgentUID, ApproverUID: first.ApproverUID,
		Store: reopened, Audit: first.Audit, Executor: executor, Policy: first.Policy,
		ReceiptSigner: first.ReceiptSigner, Domain: DomainPVE, Now: first.Now,
		PVEReconcileInterval: 2 * time.Millisecond, PVECommandTimeout: time.Second,
		PVEBackgroundContext: secondBackground,
	}
	if err := second.RecoverInterrupted(); err != nil {
		t.Fatal(err)
	}
	recovered, ok := second.Store.Change(prepared.ChangeID)
	if !ok || recovered.State != StateExecuting {
		t.Fatalf("restart abandoned a durable running PVE task: %#v", recovered)
	}
	var starters sync.WaitGroup
	for index := 0; index < 32; index++ {
		starters.Add(1)
		go func() {
			defer starters.Done()
			second.ensurePVEWorker(prepared.ChangeID)
		}()
	}
	starters.Wait()
	waitForPVETaskStatusCalls(t, runner, 1)
	runner.finish("ERROR")
	failed := waitForPVEChangeState(t, second, prepared.ChangeID, StateRecoveryRequired)
	if failed.MutationDisposition != protocol.PVEMutationDispositionUnknown {
		t.Fatalf("failed terminal task lost its uncertain mutation disposition: %#v", failed)
	}
	if calls, maximum := runner.statusConcurrency(); calls < 1 || maximum != 1 {
		t.Fatalf("PVE restart spawned duplicate task pollers: calls=%d maxConcurrent=%d", calls, maximum)
	}
	competitor := *failed
	competitor.ID = "pve-change-after-async-failure"
	competitor.State = StatePreparing
	competitor.UpdatedAt = now.Add(time.Second).Format(time.RFC3339Nano)
	if err := second.Store.PutChangeWithResourceLock(&competitor); err == nil || !strings.Contains(err.Error(), "locked by unresolved change") {
		t.Fatalf("failed async PVE task did not retain the VMID lock: %v", err)
	}
}

func TestPVEAsyncDaemonShutdownPreservesExecutingButStepTimeoutRequiresRecovery(t *testing.T) {
	now := time.Date(2026, 8, 8, 16, 0, 0, 0, time.UTC)
	t.Run("daemon-shutdown", func(t *testing.T) {
		runner := &pveAsyncServiceRunner{running: true, statusDelay: time.Second}
		background, stopBackground := context.WithCancel(context.Background())
		service, _, _ := newAsyncPVEService(t, now, runner, background)
		prepared, _ := prepareAsyncPVEChange(t, service, now, "prepare-pve-shutdown")
		approved := service.Handle(
			context.Background(), peercred.Credential{UID: service.ApproverUID},
			pveActionRequest(now, "approve-pve-shutdown", protocol.MethodChangeApprove, prepared.ChangeID),
		)
		if !approved.OK || approved.State != StateExecuting {
			t.Fatalf("shutdown fixture did not start: %#v", approved)
		}
		waitForPVETaskStatusCalls(t, runner, 1)
		stopBackground()
		waitForPVEWorkerCount(t, service, 0)
		change, ok := service.Store.Change(prepared.ChangeID)
		if !ok || change.State != StateExecuting || change.MutationDisposition != "" {
			t.Fatalf("daemon cancellation fabricated a PVE task failure: %#v", change)
		}
		competitor := *change
		competitor.ID = "pve-change-during-clean-shutdown"
		competitor.State = StatePreparing
		if err := service.Store.PutChangeWithResourceLock(&competitor); err == nil || !strings.Contains(err.Error(), "locked by unresolved change") {
			t.Fatalf("daemon shutdown lost the running VMID lock: %v", err)
		}
	})

	t.Run("fresh-step-timeout", func(t *testing.T) {
		runner := &pveAsyncServiceRunner{running: true, statusDelay: 100 * time.Millisecond}
		background, stopBackground := context.WithCancel(context.Background())
		defer stopBackground()
		service, _, _ := newAsyncPVEService(t, now, runner, background)
		service.PVECommandTimeout = 5 * time.Millisecond
		prepared, _ := prepareAsyncPVEChange(t, service, now, "prepare-pve-step-timeout")
		approved := service.Handle(
			context.Background(), peercred.Credential{UID: service.ApproverUID},
			pveActionRequest(now, "approve-pve-step-timeout", protocol.MethodChangeApprove, prepared.ChangeID),
		)
		if !approved.OK || approved.State != StateExecuting {
			t.Fatalf("timeout fixture did not start: %#v", approved)
		}
		failed := waitForPVEChangeState(t, service, prepared.ChangeID, StateRecoveryRequired)
		if failed.MutationDisposition != protocol.PVEMutationDispositionUnknown ||
			!strings.Contains(failed.LastError, "context deadline exceeded") {
			t.Fatalf("independent task-query timeout was not retained as uncertainty: %#v", failed)
		}
	})
}

func newAsyncPVEService(
	t *testing.T,
	now time.Time,
	runner *pveAsyncServiceRunner,
	background context.Context,
) (*Service, *OSExecutor, ed25519.PublicKey) {
	t.Helper()
	digest := "sha256:" + strings.Repeat("a", 64)
	policy := pveRootPolicy(t, digest, []string{"pve.guest.start"})
	executor := &OSExecutor{Runner: runner, Policy: policy}
	service := testService(t, now, executor)
	executor.StateDir = service.Store.Directory()
	service.Policy = policy
	service.Domain = DomainPVE
	service.PVEReconcileInterval = 2 * time.Millisecond
	service.PVECommandTimeout = time.Second
	service.PVEBackgroundContext = background
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service.ReceiptSigner, err = NewBrokerReceiptSigner("pve-receipt-v1", DomainPVE, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return service, executor, publicKey
}

func prepareAsyncPVEChange(
	t *testing.T,
	service *Service,
	now time.Time,
	requestID string,
) (protocol.Response, protocol.Operation) {
	t.Helper()
	operation := &protocol.PVEGuestAction{
		OperationKind: "pve.guest.action", PluginID: testPVEPluginID,
		PluginDigest: "sha256:" + strings.Repeat("a", 64), Node: "pve1",
		GuestType: "qemu", VMID: 100, Action: "start",
	}
	request := protocol.Request{
		Version: protocol.Version, RequestID: requestID, Deadline: now.Add(time.Minute),
		Method: protocol.MethodChangePrepare, ServerID: "server-pve-12345678",
		MachineID: "machine-pve-12345678", TargetID: "target-pve-root",
		PolicyRevision: service.Policy.Revision, CapabilityRevision: protocol.CapabilityRevision,
		Operation: operation, Raw: []byte(requestID),
	}
	response := service.Handle(context.Background(), peercred.Credential{UID: service.AgentUID}, request)
	if !response.OK || response.State != StatePendingApproval || response.ChangeID == "" {
		t.Fatalf("prepare async PVE change failed: %#v", response)
	}
	return response, operation
}

func pveActionRequest(now time.Time, requestID string, method protocol.Method, changeID string) protocol.Request {
	return protocol.Request{
		Version: protocol.Version, RequestID: requestID, Deadline: now.Add(time.Minute), Method: method,
		ServerID: "server-pve-12345678", MachineID: "machine-pve-12345678",
		TargetID: "target-pve-root", PolicyRevision: "policy-pve-12345678",
		CapabilityRevision: protocol.CapabilityRevision, ChangeID: changeID, Raw: []byte(requestID),
	}
}

func waitForPVEChangeState(t *testing.T, service *Service, changeID, state string) *Change {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		change, ok := service.Store.Change(changeID)
		if ok && change.State == state {
			return change
		}
		time.Sleep(time.Millisecond)
	}
	change, _ := service.Store.Change(changeID)
	t.Fatalf("PVE change did not reach %s: %#v", state, change)
	return nil
}

func waitForPVEWorkerCount(t *testing.T, service *Service, expected int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		service.pveWorkerMu.Lock()
		count := len(service.pveWorkers)
		service.pveWorkerMu.Unlock()
		if count == expected {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("PVE worker count did not reach %d", expected)
}

func waitForPVETaskStatusCalls(t *testing.T, runner *pveAsyncServiceRunner, minimum int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		calls, _ := runner.statusConcurrency()
		if calls >= minimum {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("PVE worker did not issue %d task status calls", minimum)
}

func TestPVERecoveryReadinessRejectsRunningAndLostUPIDPrimaryTasks(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	operation := &protocol.PVEGuestAction{
		OperationKind: "pve.guest.action", PluginID: testPVEPluginID,
		PluginDigest: digest, Node: "pve1", GuestType: "qemu", VMID: 100, Action: "start",
	}

	runningRunner := &pveActionRunner{taskRunning: true}
	runningExecutor := &OSExecutor{StateDir: t.TempDir(), Runner: runningRunner}
	runningScope := ExecutionScope{
		ChangeID: "pve-change-running-parent", PVEMutationVersion: 1,
		MutationDisposition: protocol.PVEMutationDispositionUnknown,
		PlanHash:            "sha256:" + strings.Repeat("c", 64),
		PreconditionDigest:  "sha256:" + strings.Repeat("d", 64),
	}
	intent, err := pvePrimaryIntent(runningScope, operation, ExecutionResult{})
	if err != nil {
		t.Fatal(err)
	}
	if err := runningExecutor.persistPVETaskIntent(runningScope.ChangeID, "pve-primary-intent.json", intent); err != nil {
		t.Fatal(err)
	}
	if err := runningExecutor.persistPVETaskRecord(runningScope.ChangeID, "pve-task.json", pveTaskRecord{
		Version: pveTaskRecordVersion, Operation: operation.Kind(), Node: "pve1",
		GuestType: "qemu", VMID: 100, UPID: testPVEUPID,
	}); err != nil {
		t.Fatal(err)
	}
	readiness, err := runningExecutor.ReconcilePVERecoveryParent(context.Background(), runningScope, operation)
	if err == nil || !strings.Contains(err.Error(), "is \"running\"") || len(readiness.EvidenceRefs) != 1 {
		t.Fatalf("running parent task was treated as terminal: readiness=%#v err=%v", readiness, err)
	}

	lostExecutor := &OSExecutor{StateDir: t.TempDir(), Runner: &pveActionRunner{}}
	lostScope := ExecutionScope{
		ChangeID: "pve-change-lost-primary-upid", PVEMutationVersion: 1,
		MutationDisposition: protocol.PVEMutationDispositionUnknown,
		PlanHash:            runningScope.PlanHash, PreconditionDigest: runningScope.PreconditionDigest,
	}
	if err := lostExecutor.persistPVETaskIntent(lostScope.ChangeID, "pve-primary-intent.json", intent); err != nil {
		t.Fatal(err)
	}
	if _, err := lostExecutor.ReconcilePVERecoveryParent(context.Background(), lostScope, operation); err == nil ||
		!strings.Contains(err.Error(), "without a recoverable task UPID") {
		t.Fatalf("lost primary UPID allowed recovery lock transfer: %v", err)
	}
}

type pveUnknownClearanceRunner struct {
	calls          []pveCall
	knownStatus    string
	knownQueryErr  error
	activeNode     string
	guestNode      string
	activeOutput   string
	clusterOutput  string
	resourceOutput string
	guestOutput    string
}

func (r *pveUnknownClearanceRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, pveCall{Name: name, Args: append([]string(nil), args...)})
	joined := strings.Join(args, " ")
	switch {
	case strings.HasPrefix(joined, "get /nodes/pve1/tasks/"+testPVEUPID+"/status "):
		if r.knownQueryErr != nil {
			return "", r.knownQueryErr
		}
		status := r.knownStatus
		if status == "" {
			status = "running"
		}
		if status == "stopped" {
			return `{"status":"stopped","exitstatus":"OK"}`, nil
		}
		return fmt.Sprintf(`{"status":%q}`, status), nil
	case joined == "get /nodes/pve1/tasks --source active --vmid 100 --limit 1 --output-format json":
		if r.activeOutput != "" {
			return r.activeOutput, nil
		}
		if r.activeNode == "pve1" {
			return `[{"upid":"UPID:pve1:00000001:00000002:00000003:qmstart:100:root@pam:"}]`, nil
		}
		return `[]`, nil
	case joined == "get /nodes/pve2/tasks --source active --vmid 100 --limit 1 --output-format json":
		if r.activeOutput != "" {
			return r.activeOutput, nil
		}
		if r.activeNode == "pve2" {
			return `[{"upid":"UPID:pve2:00000001:00000002:00000003:qmigrate:100:root@pam:"}]`, nil
		}
		return `[]`, nil
	case joined == "get /cluster/status --output-format json":
		if r.clusterOutput != "" {
			return r.clusterOutput, nil
		}
		return `[{"type":"cluster","name":"cluster1","quorate":1},{"type":"node","name":"pve1","node":"pve1","nodeid":1,"online":1},{"type":"node","name":"pve2","node":"pve2","nodeid":2,"online":1}]`, nil
	case joined == "get /cluster/resources --type vm --output-format json":
		if r.resourceOutput != "" {
			return r.resourceOutput, nil
		}
		node := r.guestNode
		if node == "" {
			node = "pve1"
		}
		return fmt.Sprintf(`[{"type":"qemu","vmid":100,"node":%q}]`, node), nil
	case joined == "get /nodes/pve1/qemu/100/status/current --output-format json",
		joined == "get /nodes/pve2/qemu/100/status/current --output-format json":
		if r.guestOutput != "" {
			return r.guestOutput, nil
		}
		return `{"status":"stopped"}`, nil
	default:
		return "", fmt.Errorf("unexpected PVE unknown-clearance command: %s %s", name, joined)
	}
}

func TestPVEUnknownClearanceRequiresLostUPIDAndExactEmptyNodeTaskQueries(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	operation := &protocol.PVEGuestAction{
		OperationKind: "pve.guest.action", PluginID: testPVEPluginID,
		PluginDigest: digest, Node: "pve1", GuestType: "qemu", VMID: 100, Action: "start",
	}
	scope := ExecutionScope{
		ChangeID: "pve-change-lost-clearance", PVEMutationVersion: 1,
		MutationDisposition: protocol.PVEMutationDispositionUnknown,
		PlanHash:            "sha256:" + strings.Repeat("c", 64), PreconditionDigest: "sha256:" + strings.Repeat("d", 64),
	}
	runner := &pveUnknownClearanceRunner{}
	executor := &OSExecutor{StateDir: t.TempDir(), Runner: runner}
	intent, err := pvePrimaryIntent(scope, operation, ExecutionResult{})
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.persistPVETaskIntent(scope.ChangeID, "pve-primary-intent.json", intent); err != nil {
		t.Fatal(err)
	}
	observation, err := executor.ObservePVEUnknownRecoveryParent(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	if err := observation.Validate(); err != nil || len(observation.ActiveTaskProbes) != 1 || observation.ActiveTaskProbes[0].ActiveCount != 0 {
		t.Fatalf("invalid lost-UPID clearance observation: observation=%#v err=%v", observation, err)
	}
	wanted := "get /nodes/pve1/tasks --source active --vmid 100 --limit 1 --output-format json"
	found := false
	for _, call := range runner.calls {
		if strings.Join(call.Args, " ") == wanted {
			found = true
		}
	}
	if !found {
		t.Fatalf("clearance did not use the exact official node task query: %#v", runner.calls)
	}

	activeRunner := &pveUnknownClearanceRunner{activeNode: "pve1"}
	activeExecutor := &OSExecutor{StateDir: t.TempDir(), Runner: activeRunner}
	if err := activeExecutor.persistPVETaskIntent(scope.ChangeID, "pve-primary-intent.json", intent); err != nil {
		t.Fatal(err)
	}
	if _, err := activeExecutor.ObservePVEUnknownRecoveryParent(context.Background(), scope, operation); err == nil || !strings.Contains(err.Error(), "active task") {
		t.Fatalf("non-empty active task query was cleared: %v", err)
	}
}

func TestPVEUnknownClearanceRejectsInvalidAuthoritativeQueryShapes(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	operation := &protocol.PVEGuestAction{
		OperationKind: "pve.guest.action", PluginID: testPVEPluginID,
		PluginDigest: digest, Node: "pve1", GuestType: "qemu", VMID: 100, Action: "start",
	}
	for _, test := range []struct {
		name   string
		runner *pveUnknownClearanceRunner
		want   string
	}{
		{name: "active-null", runner: &pveUnknownClearanceRunner{activeOutput: `null`}, want: "non-null array"},
		{name: "active-object", runner: &pveUnknownClearanceRunner{activeOutput: `{}`}, want: "non-null array"},
		{name: "active-malformed", runner: &pveUnknownClearanceRunner{activeOutput: `not-json`}, want: "non-null array"},
		{name: "cluster-null", runner: &pveUnknownClearanceRunner{clusterOutput: `null`}, want: "non-null array"},
		{name: "cluster-object", runner: &pveUnknownClearanceRunner{clusterOutput: `{}`}, want: "non-null array"},
		{name: "cluster-duplicate", runner: &pveUnknownClearanceRunner{clusterOutput: `[{"type":"cluster","name":"one","quorate":1},{"type":"cluster","name":"two","quorate":0},{"type":"node","name":"pve1","online":1}]`}, want: "duplicate cluster"},
		{name: "node-duplicate", runner: &pveUnknownClearanceRunner{clusterOutput: `[{"type":"cluster","quorate":1},{"type":"node","name":"pve1","online":1},{"type":"node","node":"pve1","online":0}]`}, want: "duplicate node"},
		{name: "resources-null", runner: &pveUnknownClearanceRunner{resourceOutput: `null`}, want: "non-null array"},
		{name: "resources-object", runner: &pveUnknownClearanceRunner{resourceOutput: `{}`}, want: "non-null array"},
		{name: "guest-null", runner: &pveUnknownClearanceRunner{guestOutput: `null`}, want: "non-null object"},
		{name: "guest-array", runner: &pveUnknownClearanceRunner{guestOutput: `[]`}, want: "non-null object"},
	} {
		t.Run(test.name, func(t *testing.T) {
			scope := ExecutionScope{
				ChangeID: "pve-change-query-shape-" + test.name, PVEMutationVersion: 1,
				MutationDisposition: protocol.PVEMutationDispositionUnknown,
				PlanHash:            "sha256:" + strings.Repeat("c", 64),
				PreconditionDigest:  "sha256:" + strings.Repeat("d", 64),
			}
			executor := &OSExecutor{StateDir: t.TempDir(), Runner: test.runner}
			intent, err := pvePrimaryIntent(scope, operation, ExecutionResult{})
			if err != nil {
				t.Fatal(err)
			}
			if err := executor.persistPVETaskIntent(scope.ChangeID, "pve-primary-intent.json", intent); err != nil {
				t.Fatal(err)
			}
			if _, err := executor.ObservePVEUnknownRecoveryParent(context.Background(), scope, operation); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("invalid authoritative %s response was accepted: %v", test.name, err)
			}
		})
	}
}

func TestPVEUnknownClearanceNeverOverridesKnownUPIDRunningOrQueryFailure(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	operation := &protocol.PVEGuestAction{
		OperationKind: "pve.guest.action", PluginID: testPVEPluginID,
		PluginDigest: digest, Node: "pve1", GuestType: "qemu", VMID: 100, Action: "start",
	}
	for _, test := range []struct {
		name   string
		runner *pveUnknownClearanceRunner
		want   string
	}{
		{name: "running", runner: &pveUnknownClearanceRunner{knownStatus: "running"}, want: "can never be cleared"},
		{name: "query-failure", runner: &pveUnknownClearanceRunner{knownQueryErr: errors.New("API unavailable")}, want: "could not be queried and can never be cleared"},
		{name: "terminal", runner: &pveUnknownClearanceRunner{knownStatus: "stopped"}, want: "normal terminal-task reconciliation"},
	} {
		t.Run(test.name, func(t *testing.T) {
			scope := ExecutionScope{
				ChangeID: "pve-change-known-clearance-" + test.name, PVEMutationVersion: 1,
				MutationDisposition: protocol.PVEMutationDispositionUnknown,
				PlanHash:            "sha256:" + strings.Repeat("c", 64), PreconditionDigest: "sha256:" + strings.Repeat("d", 64),
			}
			executor := &OSExecutor{StateDir: t.TempDir(), Runner: test.runner}
			intent, err := pvePrimaryIntent(scope, operation, ExecutionResult{})
			if err != nil {
				t.Fatal(err)
			}
			if err := executor.persistPVETaskIntent(scope.ChangeID, "pve-primary-intent.json", intent); err != nil {
				t.Fatal(err)
			}
			if err := executor.persistPVETaskRecord(scope.ChangeID, "pve-task.json", pveTaskRecord{
				Version: pveTaskRecordVersion, Operation: operation.Kind(), Node: "pve1",
				GuestType: "qemu", VMID: 100, UPID: testPVEUPID,
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := executor.ObservePVEUnknownRecoveryParent(context.Background(), scope, operation); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("known UPID was overridden by clearance: %v", err)
			}
		})
	}
}

func TestPVEUnknownClearanceQueriesBothMigrationNodesAndBindsGuestLocation(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	operation := &protocol.PVEGuestMigrate{
		OperationKind: "pve.guest.migrate", PluginID: testPVEPluginID,
		PluginDigest: digest, Node: "pve1", TargetNode: "pve2", GuestType: "qemu", VMID: 100, Online: true,
	}
	scope := ExecutionScope{
		ChangeID: "pve-change-lost-migrate", PVEMutationVersion: 1,
		MutationDisposition: protocol.PVEMutationDispositionUnknown,
		PlanHash:            "sha256:" + strings.Repeat("c", 64), PreconditionDigest: "sha256:" + strings.Repeat("d", 64),
	}
	runner := &pveUnknownClearanceRunner{guestNode: "pve2"}
	executor := &OSExecutor{StateDir: t.TempDir(), Runner: runner}
	intent, err := pvePrimaryIntent(scope, operation, ExecutionResult{})
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.persistPVETaskIntent(scope.ChangeID, "pve-primary-intent.json", intent); err != nil {
		t.Fatal(err)
	}
	observation, err := executor.ObservePVEUnknownRecoveryParent(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	if len(observation.ActiveTaskProbes) != 2 || len(observation.GuestStates) != 1 || observation.GuestStates[0].Node != "pve2" {
		t.Fatalf("migration clearance did not bind both nodes and current guest location: %#v", observation)
	}
	runner.activeNode = "pve2"
	if _, err := executor.ObservePVEUnknownRecoveryParent(context.Background(), scope, operation); err == nil || !strings.Contains(err.Error(), "pve2 has an active task") {
		t.Fatalf("active task on migration target was ignored: %v", err)
	}
}

func TestPVEPrimaryIntentPersistenceFailureIsKnownNoMutation(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	policy := pveRootPolicy(t, digest, []string{"pve.guest.start"})
	runner := &pveActionRunner{}
	stateFile := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(stateFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	executor := &OSExecutor{StateDir: stateFile, Runner: runner, Policy: policy}
	scope := ExecutionScope{ChangeID: "pve-change-intent-write-fail", TargetID: "target-pve-root", PolicyRevision: policy.Revision}
	operation := &protocol.PVEGuestAction{
		OperationKind: "pve.guest.action", PluginID: testPVEPluginID,
		PluginDigest: digest, Node: "pve1", GuestType: "qemu", VMID: 100, Action: "start",
	}
	bindPVEPrecondition(t, executor, &scope, operation)
	prepared, err := executor.Prepare(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	err = executor.Execute(context.Background(), scope, operation, prepared)
	if err == nil || !noMutationStarted(err) || !strings.Contains(err.Error(), "intent before API") {
		t.Fatalf("primary intent persistence failure was not classified no-mutation: %v", err)
	}
	if runner.mutationStarted {
		t.Fatal("PVE API ran after primary intent persistence failed")
	}
}

func TestPVESafetyBackupRequiresOneUniqueVolume(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	policy := pveRootPolicy(t, digest, []string{"pve.snapshot.rollback"})
	runner := &pveSnapshotRunner{ambiguous: true}
	executor := &OSExecutor{StateDir: t.TempDir(), Runner: runner, Policy: policy}
	scope := ExecutionScope{ChangeID: "pve-change-ambiguous-backup", TargetID: "target-pve-root", PolicyRevision: policy.Revision}
	operation := &protocol.PVESnapshotRollback{
		OperationKind: "pve.snapshot.rollback", PluginID: testPVEPluginID,
		PluginDigest: digest, Node: "pve1", GuestType: "qemu", VMID: 100,
		Snapshot: "safe", BackupStorage: "local",
	}
	bindPVEPrecondition(t, executor, &scope, operation)
	prepared, err := executor.Prepare(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	err = executor.Execute(context.Background(), scope, operation, prepared)
	if err == nil || !mutationOutcomeUncertain(err) || !strings.Contains(err.Error(), "uniquely attributable") {
		t.Fatalf("ambiguous safety backup volume was accepted: %v", err)
	}
	for _, call := range runner.calls {
		if strings.Contains(strings.Join(call.Args, " "), "/snapshot/safe/rollback") {
			t.Fatal("destructive snapshot action ran without unique backup volume evidence")
		}
	}
}

type pveRecoveryRunner struct{}

func (pveRecoveryRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	joined := strings.Join(args, " ")
	if name != pveshPath {
		return "", fmt.Errorf("unexpected executable %s", name)
	}
	switch {
	case strings.Contains(joined, "/tasks/"+testPVEUPID+"/status"):
		return `{"status":"stopped","exitstatus":"OK"}`, nil
	case joined == "get /nodes/pve1/storage/local/content --content backup --vmid 100 --output-format json":
		return `[{"volid":"local:backup/vzdump-qemu-100-2026_08_08-00_00_00.vma.zst","content":"backup","vmid":100}]`, nil
	default:
		return "", fmt.Errorf("unexpected recovery command: %s", joined)
	}
}

func TestPVECrashRecoveryReconcilesTaskAndVolumeEvidenceAndKeepsLock(t *testing.T) {
	now := time.Date(2026, 8, 8, 3, 0, 0, 0, time.UTC)
	digest := "sha256:" + strings.Repeat("a", 64)
	executor := &OSExecutor{Runner: pveRecoveryRunner{}}
	service := testService(t, now, executor)
	service.Domain = DomainPVE
	executor.StateDir = service.Store.Directory()
	operation := &protocol.PVEGuestBackup{
		OperationKind: "pve.guest.backup", PluginID: testPVEPluginID,
		PluginDigest: digest, Node: "pve1", GuestType: "qemu", VMID: 100, Storage: "local",
	}
	payload, err := protocol.MarshalOperation(operation)
	if err != nil {
		t.Fatal(err)
	}
	preconditionFields := []protocol.ApprovalPlanField{{Name: "currentStatus", Value: "running"}}
	preconditionDigest, err := protocol.ApprovalPreconditionDigest(preconditionFields)
	if err != nil {
		t.Fatal(err)
	}
	change := &Change{
		ID: "pve-change-crash-recovery", PlanHash: "sha256:" + strings.Repeat("b", 64),
		Kind: operation.Kind(), Summary: operation.Summary(), Operation: payload,
		State: StateExecuting, PreparedAt: now.Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano),
		ResourceKey: pveResourceKey(operation), PreconditionDigest: preconditionDigest,
		PreconditionFields: preconditionFields,
	}
	if err := service.Store.PutChange(change); err != nil {
		t.Fatal(err)
	}
	record := pveTaskRecord{
		Version: pveTaskRecordVersion, Operation: operation.Kind(), Node: "pve1", GuestType: "qemu",
		VMID: 100, UPID: testPVEUPID, Storage: "local", BeforeVolumes: []string{},
	}
	if err := executor.persistPVETaskRecord(change.ID, "pve-task.json", record); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(service.Store.Directory())
	if err != nil {
		t.Fatal(err)
	}
	service.Store = reopened
	if err := service.RecoverInterrupted(); err != nil {
		t.Fatal(err)
	}
	recovered, _ := service.Store.Change(change.ID)
	if recovered.State != StateRecoveryRequired || len(recovered.BackupRefs) != 2 ||
		recovered.BackupRefs[0] != "pve:task:"+testPVEUPID || !strings.HasPrefix(recovered.BackupRefs[1], "pve:volume:local:backup/") {
		t.Fatalf("crash recovery lost PVE task or volume evidence: %#v", recovered)
	}
	competitor := *recovered
	competitor.ID = "pve-change-competing"
	competitor.State = StatePreparing
	if err := service.Store.PutChangeWithResourceLock(&competitor); err == nil || !strings.Contains(err.Error(), "locked by unresolved change") {
		t.Fatalf("recovery-required PVE change did not retain durable lock: %v", err)
	}
}

type pveMigrationVerifyRunner struct{}

func (pveMigrationVerifyRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	joined := strings.Join(args, " ")
	if name != pveshPath {
		return "", fmt.Errorf("unexpected executable %s", name)
	}
	switch {
	case strings.Contains(joined, "/tasks/"+testPVEUPID+"/status"):
		return `{"status":"stopped","exitstatus":"OK"}`, nil
	case joined == "get /cluster/resources --type vm --output-format json":
		return `[{"type":"qemu","vmid":100,"node":"pve2"}]`, nil
	case joined == "get /nodes/pve2/qemu/100/status/current --output-format json":
		return `{"status":"stopped"}`, nil
	default:
		return "", fmt.Errorf("unexpected migration verification command: %s", joined)
	}
}

type pveRestoreVerifyRunner struct{ status string }

func (r pveRestoreVerifyRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	joined := strings.Join(args, " ")
	if name != pveshPath {
		return "", fmt.Errorf("unexpected executable %s", name)
	}
	switch {
	case strings.Contains(joined, "/tasks/"+testPVEUPID+"/status"):
		return `{"status":"stopped","exitstatus":"OK"}`, nil
	case joined == "get /nodes/pve1/qemu/100/status/current --output-format json":
		return fmt.Sprintf(`{"status":%q}`, r.status), nil
	default:
		return "", fmt.Errorf("unexpected restore verification command: %s", joined)
	}
}

func TestPVERestoreVerificationRequiresStoppedGuest(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	executor := &OSExecutor{StateDir: t.TempDir(), Runner: pveRestoreVerifyRunner{status: "running"}}
	scope := ExecutionScope{ChangeID: "pve-change-restore-verify"}
	operation := &protocol.PVEGuestRestore{
		OperationKind: "pve.guest.restore", PluginID: testPVEPluginID, PluginDigest: digest,
		Node: "pve1", GuestType: "qemu", VMID: 100,
		BackupVolume: "local:backup/vzdump-qemu-100-2026_08_08-00_00_00.vma.zst", Storage: "local-lvm",
	}
	if err := executor.persistPVETaskRecord(scope.ChangeID, "pve-task.json", pveTaskRecord{
		Version: pveTaskRecordVersion, Operation: operation.Kind(), Node: "pve1", GuestType: "qemu", VMID: 100, UPID: testPVEUPID,
	}); err != nil {
		t.Fatal(err)
	}
	_, err := executor.Verify(context.Background(), scope, operation, ExecutionResult{})
	if err == nil || !strings.Contains(err.Error(), "expected stopped and unlocked") {
		t.Fatalf("restore committed despite --start 0 postcondition drift: %v", err)
	}
}

func TestPVEMigrationVerificationPreservesApprovedGuestState(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	executor := &OSExecutor{StateDir: t.TempDir(), Runner: pveMigrationVerifyRunner{}}
	scope := ExecutionScope{ChangeID: "pve-change-migrate-verify"}
	operation := &protocol.PVEGuestMigrate{
		OperationKind: "pve.guest.migrate", PluginID: testPVEPluginID, PluginDigest: digest,
		Node: "pve1", GuestType: "qemu", VMID: 100, TargetNode: "pve2", Online: true,
	}
	if err := executor.persistPVETaskRecord(scope.ChangeID, "pve-task.json", pveTaskRecord{
		Version: pveTaskRecordVersion, Operation: operation.Kind(), Node: "pve1", GuestType: "qemu", VMID: 100, UPID: testPVEUPID,
	}); err != nil {
		t.Fatal(err)
	}
	rollback, _ := json.Marshal(pveRollback{
		Version: pveTaskRecordVersion, Operation: operation.Kind(), Node: "pve1", GuestType: "qemu", VMID: 100, PreviousStatus: "running",
	})
	_, err := executor.Verify(context.Background(), scope, operation, ExecutionResult{RollbackData: rollback})
	if err == nil || !strings.Contains(err.Error(), "expected approved state") {
		t.Fatalf("migration committed with an unexpected stopped guest: %v", err)
	}
}

func bindPVEPrecondition(t *testing.T, executor *OSExecutor, scope *ExecutionScope, operation protocol.Operation) {
	t.Helper()
	planned, err := executor.PlanOperation(context.Background(), *scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	scope.PreconditionDigest = planned.Digest
	if scope.PlanHash == "" {
		scope.PlanHash = "sha256:" + strings.Repeat("f", 64)
	}
	if scope.PVEMutationVersion == 0 {
		scope.PVEMutationVersion = 1
	}
}

func TestPVERestoreAndMigrationSpecsContainNoShellOrRawArgv(t *testing.T) {
	restore := &protocol.PVEGuestRestore{
		OperationKind: "pve.guest.restore", PluginID: testPVEPluginID,
		PluginDigest: "sha256:" + strings.Repeat("a", 64), Node: "pve1", GuestType: "lxc", VMID: 101,
		BackupVolume: "local:backup/vzdump-lxc-101-2026_08_08-00_00_00.tar.zst", Storage: "local-lvm",
	}
	verb, path, args, err := pveMutationSpec(restore)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if verb != "create" || path != "/nodes/pve1/lxc" || strings.Contains(joined, " sh ") || strings.Contains(joined, "-c") || !strings.Contains(joined, "--restore 1") {
		t.Fatalf("unsafe or incomplete PVE restore spec: %s %s %#v", verb, path, args)
	}
	localDiskMigration := &protocol.PVEGuestMigrate{
		OperationKind: "pve.guest.migrate", PluginID: testPVEPluginID,
		PluginDigest: "sha256:" + strings.Repeat("a", 64), Node: "pve1", GuestType: "qemu",
		VMID: 100, TargetNode: "pve2", WithLocalDisks: true,
	}
	if _, err := (&OSExecutor{}).PlanOperation(context.Background(), ExecutionScope{}, localDiskMigration); err == nil || !strings.Contains(err.Error(), "target-storage mapping") {
		t.Fatalf("local-disk migration bypassed storage policy: %v", err)
	}
}

func pveRootPolicy(t *testing.T, digest string, operations []string) *targetpolicy.Policy {
	t.Helper()
	payload := fmt.Sprintf(`{"version":1,"revision":"policy-pve-12345678","targets":[{"id":"target-pve-root","account":"root","displayName":"PVE root","inspect":{"hostSnapshot":true,"processList":true,"units":[],"readPaths":[]},"changes":{"writePaths":[],"units":[],"packages":[],"plugins":[]},"pve":{"pluginId":"workload.pve","pluginDigest":%q,"nodes":["pve1","pve2"],"storages":["local","local-lvm"],"guests":[{"guestType":"qemu","vmid":100},{"guestType":"lxc","vmid":101}],"migrationTargets":["pve2"],"operations":%s}}]}`, digest, mustJSONForTest(t, operations))
	policy, err := targetpolicy.Parse([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func mustJSONForTest(t *testing.T, value interface{}) string {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}
