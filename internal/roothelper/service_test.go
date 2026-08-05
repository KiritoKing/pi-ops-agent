package roothelper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/audit"
	"github.com/KiritoKing/pi-ops-agent/internal/peercred"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

type fakeExecutor struct {
	result        ExecutionResult
	prepareErr    error
	executeErr    error
	verifyErr     error
	rollbackErr   error
	executeHook   func(string, ExecutionResult)
	rollbackHook  func(context.Context)
	preparations  int
	executions    int
	verifications int
	rollbacks     int
}

func (f *fakeExecutor) Prepare(context.Context, string, protocol.Operation) (ExecutionResult, error) {
	f.preparations++
	return f.result, f.prepareErr
}
func (f *fakeExecutor) Execute(_ context.Context, changeID string, _ protocol.Operation, result ExecutionResult) error {
	f.executions++
	if f.executeHook != nil {
		f.executeHook(changeID, result)
	}
	return f.executeErr
}
func (f *fakeExecutor) Verify(context.Context, string, protocol.Operation, ExecutionResult) (string, error) {
	f.verifications++
	return "verified", f.verifyErr
}
func (f *fakeExecutor) Rollback(ctx context.Context, _ string, _ protocol.Operation, _ ExecutionResult) error {
	f.rollbacks++
	if f.rollbackHook != nil {
		f.rollbackHook(ctx)
	}
	return f.rollbackErr
}

func TestApprovalIsSeparatedFromAgentAndIdempotent(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	executor := &fakeExecutor{result: ExecutionResult{RollbackAvailable: true, RollbackData: json.RawMessage(`{}`)}}
	service := testService(t, now, executor)
	agent := peercred.Credential{PID: 10, UID: 1001, GID: 1001}
	approver := peercred.Credential{PID: 1, UID: 0, GID: 0}
	prepared := service.Handle(context.Background(), agent, parseRequest(t, now, "prepare-0001", `"method":"change.prepare","operation":{"kind":"package.install","package":"nginx"}`))
	if !prepared.OK || prepared.State != StatePendingApproval || prepared.ChangeID == "" {
		t.Fatalf("prepare response: %#v", prepared)
	}
	agentApproval := service.Handle(context.Background(), agent, parseRequest(t, now, "approve-agent-0001", fmt.Sprintf(`"method":"change.approve","changeId":%q`, prepared.ChangeID)))
	if agentApproval.OK || executor.executions != 0 {
		t.Fatal("agent UID approved a privileged change")
	}
	approvalRequest := parseRequest(t, now, "approve-root-0001", fmt.Sprintf(`"method":"change.approve","changeId":%q`, prepared.ChangeID))
	approved := service.Handle(context.Background(), approver, approvalRequest)
	if !approved.OK || approved.State != StateCommitted || executor.preparations != 1 || executor.executions != 1 || executor.verifications != 1 {
		t.Fatalf("approve response=%#v executions=%d verifies=%d", approved, executor.executions, executor.verifications)
	}
	replayed := service.Handle(context.Background(), approver, approvalRequest)
	if !replayed.OK || replayed.AuditID != approved.AuditID || executor.executions != 1 {
		t.Fatal("idempotent approval replay executed the change twice")
	}
}

func TestRollbackMetadataIsDurableBeforeMutation(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	executor := &fakeExecutor{result: ExecutionResult{
		BackupRefs:   []string{"/var/lib/ops-agent/root-helper/changes/test/backup"},
		RollbackData: json.RawMessage(`{"old":"state"}`), RollbackAvailable: true,
	}}
	service := testService(t, now, executor)
	executor.executeHook = func(changeID string, expected ExecutionResult) {
		change, ok := service.Store.Change(changeID)
		if !ok {
			t.Fatal("change was missing at mutation barrier")
		}
		if change.State != StateExecuting || !change.RollbackAvailable || len(change.BackupRefs) != 1 || string(change.RollbackData) != string(expected.RollbackData) {
			t.Fatalf("mutation started before durable rollback metadata: %#v", change)
		}
	}
	prepared := service.Handle(context.Background(), peercred.Credential{UID: 1001}, parseRequest(t, now, "prepare-barrier-0001", `"method":"change.prepare","operation":{"kind":"package.install","package":"nginx"}`))
	approved := service.Handle(context.Background(), peercred.Credential{UID: 0}, parseRequest(t, now, "approve-barrier-0001", fmt.Sprintf(`"method":"change.approve","changeId":%q`, prepared.ChangeID)))
	if !approved.OK || executor.executions != 1 {
		t.Fatalf("approve response=%#v executions=%d", approved, executor.executions)
	}
}

func TestAutomaticRollbackUsesIndependentBoundedContext(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	executor := &fakeExecutor{
		result:     ExecutionResult{RollbackData: json.RawMessage(`{}`), RollbackAvailable: true},
		executeErr: context.Canceled,
	}
	service := testService(t, now, executor)
	service.RollbackTimeout = 250 * time.Millisecond
	executor.rollbackHook = func(ctx context.Context) {
		if ctx.Err() != nil {
			t.Fatalf("rollback inherited canceled request context: %v", ctx.Err())
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > service.RollbackTimeout+50*time.Millisecond {
			t.Fatalf("rollback context is not independently bounded: deadline=%v ok=%v", deadline, ok)
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	prepared := service.Handle(context.Background(), peercred.Credential{UID: 1001}, parseRequest(t, now, "prepare-cancel-0001", `"method":"change.prepare","operation":{"kind":"package.install","package":"nginx"}`))
	approved := service.Handle(canceled, peercred.Credential{UID: 0}, parseRequest(t, now, "approve-cancel-0001", fmt.Sprintf(`"method":"change.approve","changeId":%q`, prepared.ChangeID)))
	if approved.State != StateRolledBack || executor.rollbacks != 1 {
		t.Fatalf("canceled request did not complete independent rollback: %#v", approved)
	}
}

func TestVerificationFailureRollsBack(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	executor := &fakeExecutor{result: ExecutionResult{RollbackAvailable: true, RollbackData: json.RawMessage(`{}`)}, verifyErr: errors.New("health check failed")}
	service := testService(t, now, executor)
	prepared := service.Handle(context.Background(), peercred.Credential{UID: 1001}, parseRequest(t, now, "prepare-0002", `"method":"change.prepare","operation":{"kind":"service.action","unit":"nginx.service","action":"restart"}`))
	approved := service.Handle(context.Background(), peercred.Credential{UID: 0}, parseRequest(t, now, "approve-root-0002", fmt.Sprintf(`"method":"change.approve","changeId":%q`, prepared.ChangeID)))
	if approved.OK || approved.State != StateRolledBack || executor.rollbacks != 1 {
		t.Fatalf("failure response=%#v rollbacks=%d", approved, executor.rollbacks)
	}
}

func TestStartupRecoveryFailsClosed(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	service := testService(t, now, &fakeExecutor{})
	ids := make([]string, 0, 3)
	for index, state := range []string{StatePreparing, StateExecuting, StateVerifying, StateRollingBack} {
		requestID := fmt.Sprintf("prepare-recovery-%04d", index)
		prepared := service.Handle(context.Background(), peercred.Credential{UID: 1001}, parseRequest(t, now, requestID, `"method":"change.prepare","operation":{"kind":"package.install","package":"nginx"}`))
		change, ok := service.Store.Change(prepared.ChangeID)
		if !ok {
			t.Fatal("prepared change missing")
		}
		change.State = state
		if state != StatePreparing {
			change.BackupRefs = []string{"/backup/" + state}
			change.RollbackData = json.RawMessage(`{"prepared":true}`)
			change.RollbackAvailable = true
		}
		if err := service.Store.PutChange(change); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, change.ID)
	}
	if err := service.RecoverInterrupted(); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		recovered, _ := service.Store.Change(id)
		if recovered.State != StateRecoveryRequired || recovered.LastError == "" {
			t.Fatalf("interrupted change did not fail closed: %#v", recovered)
		}
		if recovered.RollbackAvailable && (len(recovered.BackupRefs) == 0 || len(recovered.RollbackData) == 0) {
			t.Fatalf("recovery lost rollback metadata: %#v", recovered)
		}
	}
}

func TestCriticalPathsAndServicesAreDenied(t *testing.T) {
	executor := &OSExecutor{AllowedRoots: []string{"/etc", "/opt"}}
	for _, path := range []string{"/etc/shadow", "/etc/ssh/sshd_config", "/etc/sudoers.d/example", "/etc/sysctl.d/99-agent.conf"} {
		if err := executor.ensureAllowedPath(path); err == nil {
			t.Fatalf("critical path %s was allowed", path)
		}
	}
	for _, unit := range []string{"ops-agentd.service", "sshd.service", "dbus.service", "NetworkManager.service", "nftables.service"} {
		if !isCriticalService(unit) {
			t.Fatalf("critical service %s was allowed", unit)
		}
	}
}

func testService(t *testing.T, now time.Time, executor Executor) *Service {
	t.Helper()
	directory := t.TempDir()
	store, err := OpenStore(filepath.Join(directory, "state"))
	if err != nil {
		t.Fatal(err)
	}
	log, err := audit.Open(filepath.Join(directory, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return &Service{AgentUID: 1001, ApproverUID: 0, Store: store, Audit: log, Executor: executor, Now: func() time.Time { return now }}
}

func parseRequest(t *testing.T, now time.Time, id, fields string) protocol.Request {
	t.Helper()
	payload := fmt.Sprintf(`{"version":1,"requestId":%q,"deadline":%q,%s}`, id, now.Add(time.Minute).Format(time.RFC3339Nano), fields)
	request, err := protocol.ParseRequest([]byte(payload), now)
	if err != nil {
		t.Fatal(err)
	}
	return request
}
