package roothelper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/audit"
	"github.com/KiritoKing/pi-ops-agent/internal/peercred"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
	"github.com/KiritoKing/pi-ops-agent/internal/targetpolicy"
)

type fakeExecutor struct {
	result        ExecutionResult
	prepareErr    error
	executeErr    error
	verifyErr     error
	rollbackErr   error
	prepareHook   func(ExecutionScope)
	executeHook   func(string, ExecutionResult)
	rollbackHook  func(context.Context)
	preparations  int
	executions    int
	verifications int
	rollbacks     int
	lastScope     ExecutionScope
}

var testRootBaseDigest = "sha256:" + strings.Repeat("b", 64)

func baseServicePrepareFields(unit, action string) string {
	return fmt.Sprintf(
		`"method":"change.prepare","operation":{"kind":"service.action","pluginId":"workload.base","pluginDigest":%q,"unit":%q,"action":%q}`,
		testRootBaseDigest, unit, action,
	)
}

type fakeUncertainError struct{ message string }

func (e fakeUncertainError) Error() string                  { return e.message }
func (e fakeUncertainError) MutationOutcomeUncertain() bool { return true }

type fakeNoMutationError struct{ message string }

func (e fakeNoMutationError) Error() string           { return e.message }
func (e fakeNoMutationError) NoMutationStarted() bool { return true }

type fakeRestoredUncertainError struct{ message string }

func (e fakeRestoredUncertainError) Error() string                  { return e.message }
func (e fakeRestoredUncertainError) MutationOutcomeUncertain() bool { return true }
func (e fakeRestoredUncertainError) MutationAttempted() bool        { return true }
func (e fakeRestoredUncertainError) ExchangeRestored() bool         { return true }

type fakePVEExecutor struct {
	fakeExecutor
	reconcileErr    error
	reconciliations int
}

type concurrentExecutor struct {
	started    chan string
	release    <-chan struct{}
	executions atomic.Int32
}

func (e *concurrentExecutor) Prepare(context.Context, ExecutionScope, protocol.Operation) (ExecutionResult, error) {
	return ExecutionResult{}, nil
}

func (e *concurrentExecutor) Execute(ctx context.Context, scope ExecutionScope, _ protocol.Operation, _ ExecutionResult) error {
	e.executions.Add(1)
	e.started <- scope.ChangeID
	select {
	case <-e.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (*concurrentExecutor) Verify(context.Context, ExecutionScope, protocol.Operation, ExecutionResult) (string, error) {
	return "verified", nil
}

func (*concurrentExecutor) Rollback(context.Context, ExecutionScope, protocol.Operation, ExecutionResult) error {
	return nil
}

func (f *fakePVEExecutor) PlanOperation(_ context.Context, _ ExecutionScope, operation protocol.Operation) (OperationPrecondition, error) {
	if !isPVEOperation(operation) {
		return OperationPrecondition{}, nil
	}
	fields := []protocol.ApprovalPlanField{
		{Name: "currentStatus", Value: "stopped"},
		{Name: "currentLock", Value: "unlocked"},
	}
	digest, err := protocol.ApprovalPreconditionDigest(fields)
	return OperationPrecondition{Digest: digest, Fields: fields}, err
}

func (f *fakePVEExecutor) ReconcilePVERecoveryParent(_ context.Context, scope ExecutionScope, _ protocol.Operation) (PVERecoveryReadiness, error) {
	f.reconciliations++
	if f.reconcileErr != nil {
		return PVERecoveryReadiness{}, f.reconcileErr
	}
	if scope.MutationDisposition == protocol.PVEMutationDispositionNotStarted {
		return PVERecoveryReadiness{MutationDisposition: protocol.PVEMutationDispositionNotStarted}, nil
	}
	return PVERecoveryReadiness{
		MutationDisposition: protocol.PVEMutationDispositionTasksTerminal,
		TaskEvidence: []protocol.PVERecoveryTaskEvidence{{
			Role: "primary", Node: "pve1", UPID: testPVEUPID, Status: "stopped",
			ExitStatus: "OK", ObservedAt: "2026-08-08T00:00:00Z",
		}},
		EvidenceRefs: []string{"pve:task:" + testPVEUPID},
	}, nil
}

func (f *fakeExecutor) Prepare(_ context.Context, scope ExecutionScope, _ protocol.Operation) (ExecutionResult, error) {
	f.preparations++
	f.lastScope = scope
	if f.prepareHook != nil {
		f.prepareHook(scope)
	}
	return f.result, f.prepareErr
}
func (f *fakeExecutor) Execute(_ context.Context, scope ExecutionScope, _ protocol.Operation, result ExecutionResult) error {
	f.executions++
	if f.executeHook != nil {
		f.executeHook(scope.ChangeID, result)
	}
	return f.executeErr
}
func (f *fakeExecutor) Verify(context.Context, ExecutionScope, protocol.Operation, ExecutionResult) (string, error) {
	f.verifications++
	return "verified", f.verifyErr
}
func (f *fakeExecutor) Rollback(ctx context.Context, _ ExecutionScope, _ protocol.Operation, _ ExecutionResult) error {
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

func TestExplicitStandingPolicyExecutesDuringPrepareWithDurableBasis(t *testing.T) {
	now := time.Date(2026, 8, 8, 13, 0, 0, 0, time.UTC)
	executor := &fakeExecutor{result: ExecutionResult{
		RollbackData: json.RawMessage(`{"previous":"state"}`), RollbackAvailable: true,
	}}
	service, auditPath := testServiceWithAuditPath(t, now, executor)
	service.Policy = testStandingTargetPolicy(t, t.TempDir(), "policy-standing-v1", "service.action")
	agent := peercred.Credential{UID: service.AgentUID}
	request := parseRemoteRequestWithPolicy(t, now, "prepare-standing-0001", "agent", service.Policy.Revision,
		baseServicePrepareFields("example.service", "restart"))
	executor.executeHook = func(changeID string, _ ExecutionResult) {
		fingerprint := sha256.Sum256(request.Raw)
		cached, ok, err := service.Store.Cached(request.RequestID, agent.UID, hex.EncodeToString(fingerprint[:]))
		if err != nil || !ok || cached.ChangeID != changeID || cached.State != StatePendingApproval {
			t.Fatalf("standing mutation started before the durable replay barrier: cached=%#v ok=%t err=%v", cached, ok, err)
		}
	}
	response := service.Handle(context.Background(), agent, request)
	if !response.OK || response.State != StateCommitted || executor.preparations != 1 ||
		executor.executions != 1 || executor.verifications != 1 {
		t.Fatalf("standing prepare did not commit exactly once: response=%#v executor=%#v", response, executor)
	}
	change, ok := service.Store.Change(response.ChangeID)
	if !ok {
		t.Fatal("standing change was not persisted")
	}
	if change.ApprovedByUID != nil || change.AuthorizationBasis != "standing-policy:policy-standing-v1:service.action" ||
		change.AuthorizationScope != "service.action" || change.AuthorizedAt != now.Format(time.RFC3339Nano) {
		t.Fatalf("standing authorization basis was not durable: %#v", change)
	}
	if executor.lastScope.ApprovedBy != change.AuthorizationBasis || !executor.lastScope.ApprovedAt.Equal(now) {
		t.Fatalf("executor did not receive the standing authorization basis: %#v", executor.lastScope)
	}

	statusRequest := parseRemoteRequestWithPolicy(t, now, "status-standing-0001", "agent", service.Policy.Revision,
		fmt.Sprintf(`"method":"change.status","changeId":%q`, response.ChangeID))
	status := service.Handle(context.Background(), agent, statusRequest)
	data, ok := status.Data.(changeStatusData)
	if !status.OK || !ok || data.AuthorizationBasis != change.AuthorizationBasis ||
		data.AuthorizationScope != change.AuthorizationScope || data.AuthorizedAt != change.AuthorizedAt {
		t.Fatalf("standing authorization was missing from status: %#v", status)
	}
	auditPayload, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(auditPayload), `"authorizationBasis":"standing-policy:policy-standing-v1:service.action"`) ||
		!strings.Contains(string(auditPayload), `"authorizationScope":"service.action"`) {
		t.Fatalf("standing authorization was missing from audit: %s", auditPayload)
	}

	replayed := service.Handle(context.Background(), agent, request)
	if !replayed.OK || replayed.ChangeID != response.ChangeID || executor.executions != 1 {
		t.Fatalf("standing prepare replay executed twice: response=%#v executions=%d", replayed, executor.executions)
	}
}

func TestStandingPolicyDoesNotAuthorizeRollback(t *testing.T) {
	now := time.Date(2026, 8, 8, 13, 30, 0, 0, time.UTC)
	executor := &fakeExecutor{result: ExecutionResult{RollbackData: json.RawMessage(`{}`), RollbackAvailable: true}}
	service := testService(t, now, executor)
	service.Policy = testStandingTargetPolicy(t, t.TempDir(), "policy-standing-rollback", "service.action")
	agent := peercred.Credential{UID: service.AgentUID}
	prepared := service.Handle(context.Background(), agent, parseRemoteRequestWithPolicy(
		t, now, "prepare-standing-rollback", "agent", service.Policy.Revision,
		baseServicePrepareFields("example.service", "restart"),
	))
	if !prepared.OK || prepared.State != StateCommitted {
		t.Fatalf("standing change did not commit: %#v", prepared)
	}
	deniedRollback := service.Handle(context.Background(), agent, parseRemoteRequestWithPolicy(
		t, now, "rollback-standing-agent", "agent", service.Policy.Revision,
		fmt.Sprintf(`"method":"change.rollback","changeId":%q`, prepared.ChangeID),
	))
	if deniedRollback.OK || executor.rollbacks != 0 {
		t.Fatalf("agent used standing policy to authorize rollback: %#v", deniedRollback)
	}
	manualRollback := parseRemoteRequestWithPolicy(
		t, now, "rollback-standing-local", "agent", service.Policy.Revision,
		fmt.Sprintf(`"method":"change.rollback","changeId":%q`, prepared.ChangeID),
	)
	manualRollback.CallerRole = ""
	rolledBack := service.Handle(context.Background(), peercred.Credential{UID: service.ApproverUID}, manualRollback)
	if !rolledBack.OK || rolledBack.State != StateRolledBack || executor.rollbacks != 1 {
		t.Fatalf("manual rollback after standing execution failed: %#v", rolledBack)
	}
}

func TestRollbackMetadataAndExecutionAuditAreDurableBeforeMutation(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	executor := &fakeExecutor{result: ExecutionResult{
		BackupRefs:   []string{"/var/lib/ops-agent/root-helper/changes/test/backup"},
		RollbackData: json.RawMessage(`{"old":"state"}`), RollbackAvailable: true,
	}}
	service, auditPath := testServiceWithAuditPath(t, now, executor)
	executor.executeHook = func(changeID string, expected ExecutionResult) {
		change, ok := service.Store.Change(changeID)
		if !ok {
			t.Fatal("change was missing at mutation barrier")
		}
		if change.State != StateExecuting || !change.RollbackAvailable || len(change.BackupRefs) != 1 || string(change.RollbackData) != string(expected.RollbackData) {
			t.Fatalf("mutation started before durable rollback metadata: %#v", change)
		}
		auditPayload, err := os.ReadFile(auditPath)
		if err != nil || !strings.Contains(string(auditPayload), `"type":"change_execution_started"`) ||
			!strings.Contains(string(auditPayload), `"changeId":"`+changeID+`"`) {
			t.Fatalf("mutation started before its execution audit was durable: payload=%s err=%v", auditPayload, err)
		}
	}
	prepared := service.Handle(context.Background(), peercred.Credential{UID: 1001}, parseRequest(t, now, "prepare-barrier-0001", `"method":"change.prepare","operation":{"kind":"package.install","package":"nginx"}`))
	approved := service.Handle(context.Background(), peercred.Credential{UID: 0}, parseRequest(t, now, "approve-barrier-0001", fmt.Sprintf(`"method":"change.approve","changeId":%q`, prepared.ChangeID)))
	if !approved.OK || executor.executions != 1 {
		t.Fatalf("approve response=%#v executions=%d", approved, executor.executions)
	}
}

func TestMutationBarrierAndExecutionAuditFailuresNeverReachExecutor(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 10, 0, 0, time.UTC)

	t.Run("execution-audit", func(t *testing.T) {
		executor := &fakeExecutor{result: ExecutionResult{RollbackData: json.RawMessage(`{}`)}}
		service, auditPath := testServiceWithAuditPath(t, now, executor)
		executor.prepareHook = func(ExecutionScope) {
			if err := os.Remove(auditPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(auditPath, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		prepared := service.Handle(context.Background(), peercred.Credential{UID: 1001}, parseRequest(t, now, "prepare-audit-barrier", `"method":"change.prepare","operation":{"kind":"package.install","package":"nginx"}`))
		response := service.Handle(context.Background(), peercred.Credential{UID: 0}, parseRequest(t, now, "approve-audit-barrier", fmt.Sprintf(`"method":"change.approve","changeId":%q`, prepared.ChangeID)))
		if response.OK || response.State != "" || executor.executions != 0 {
			t.Fatalf("executor ran without a durable execution audit: response=%#v executions=%d", response, executor.executions)
		}
	})

	t.Run("store-barrier", func(t *testing.T) {
		executor := &fakeExecutor{result: ExecutionResult{RollbackData: json.RawMessage(`{}`)}}
		service := testService(t, now, executor)
		executor.prepareHook = func(ExecutionScope) {
			blocked := service.Store.dir + ".blocked"
			if err := os.Rename(service.Store.dir, blocked); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(service.Store.dir, []byte("blocked"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		prepared := service.Handle(context.Background(), peercred.Credential{UID: 1001}, parseRequest(t, now, "prepare-store-barrier", `"method":"change.prepare","operation":{"kind":"package.install","package":"nginx"}`))
		response := service.Handle(context.Background(), peercred.Credential{UID: 0}, parseRequest(t, now, "approve-store-barrier", fmt.Sprintf(`"method":"change.approve","changeId":%q`, prepared.ChangeID)))
		if response.OK || response.Error == "" || executor.executions != 0 {
			t.Fatalf("executor ran without a durable store barrier: response=%#v executions=%d", response, executor.executions)
		}
	})
}

func TestKnownNoMutationExecutionFailureReleasesResourceLock(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 20, 0, 0, time.UTC)
	executor := &fakePVEExecutor{fakeExecutor: fakeExecutor{
		result:     ExecutionResult{RollbackAvailable: false, RollbackData: json.RawMessage(`{}`)},
		executeErr: fakeNoMutationError{message: "approved PVE precondition drifted before the API call"},
	}}
	service := testService(t, now, executor)
	service.Domain = DomainPVE
	operation := fmt.Sprintf(`"method":"change.prepare","operation":{"kind":"pve.guest.action","pluginId":"workload.pve","pluginDigest":"sha256:%s","node":"pve1","guestType":"qemu","vmid":100,"action":"start"}`, strings.Repeat("a", 64))
	first := service.Handle(context.Background(), peercred.Credential{UID: 1001}, parseRequest(t, now, "prepare-pve-no-mutation-1", operation))
	failed := service.Handle(context.Background(), peercred.Credential{UID: 0}, parseRequest(t, now, "approve-pve-no-mutation-1", fmt.Sprintf(`"method":"change.approve","changeId":%q`, first.ChangeID)))
	if failed.State != StateRolledBack || !strings.Contains(failed.Error, "precondition drifted") {
		t.Fatalf("known no-mutation failure retained a recovery lock: %#v", failed)
	}
	second := service.Handle(context.Background(), peercred.Credential{UID: 1001}, parseRequest(t, now, "prepare-pve-no-mutation-2", operation))
	secondFailure := service.Handle(context.Background(), peercred.Credential{UID: 0}, parseRequest(t, now, "approve-pve-no-mutation-2", fmt.Sprintf(`"method":"change.approve","changeId":%q`, second.ChangeID)))
	if strings.Contains(secondFailure.Error, "locked by unresolved change") {
		t.Fatalf("known no-mutation failure did not release its resource lock: %#v", secondFailure)
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
	prepared := service.Handle(context.Background(), peercred.Credential{UID: 1001}, parseRequest(t, now, "prepare-0002", baseServicePrepareFields("nginx.service", "restart")))
	approved := service.Handle(context.Background(), peercred.Credential{UID: 0}, parseRequest(t, now, "approve-root-0002", fmt.Sprintf(`"method":"change.approve","changeId":%q`, prepared.ChangeID)))
	if approved.OK || approved.State != StateRolledBack || executor.rollbacks != 1 {
		t.Fatalf("failure response=%#v rollbacks=%d", approved, executor.rollbacks)
	}
}

func TestUncertainExecutionNeverAutomaticallyRollsBack(t *testing.T) {
	now := time.Date(2026, 8, 8, 1, 0, 0, 0, time.UTC)
	executor := &fakeExecutor{
		result:     ExecutionResult{RollbackAvailable: true, RollbackData: json.RawMessage(`{}`)},
		executeErr: fakeUncertainError{message: "task status unavailable after start"},
	}
	service := testService(t, now, executor)
	prepared := service.Handle(context.Background(), peercred.Credential{UID: 1001}, parseRequest(t, now, "prepare-uncertain-1", `"method":"change.prepare","operation":{"kind":"package.install","package":"nginx"}`))
	response := service.Handle(context.Background(), peercred.Credential{UID: 0}, parseRequest(t, now, "approve-uncertain-1", fmt.Sprintf(`"method":"change.approve","changeId":%q`, prepared.ChangeID)))
	if response.State != StateRecoveryRequired || executor.rollbacks != 0 {
		t.Fatalf("uncertain task was automatically rolled back: response=%#v rollbacks=%d", response, executor.rollbacks)
	}
}

func TestRestoredExchangeFailureKeepsStructuredMutationEvidence(t *testing.T) {
	now := time.Date(2026, 8, 8, 1, 15, 0, 0, time.UTC)
	executor := &fakeExecutor{
		result: ExecutionResult{RollbackAvailable: true, RollbackData: json.RawMessage(`{}`)},
		executeErr: fakeRestoredUncertainError{
			message: "restored exchange ended in an unapproved third state",
		},
	}
	service, auditPath := testServiceWithAuditPath(t, now, executor)
	prepared := service.Handle(context.Background(), peercred.Credential{UID: 1001}, parseRequest(t, now, "prepare-restored-1", `"method":"change.prepare","operation":{"kind":"package.install","package":"nginx"}`))
	response := service.Handle(context.Background(), peercred.Credential{UID: 0}, parseRequest(t, now, "approve-restored-1", fmt.Sprintf(`"method":"change.approve","changeId":%q`, prepared.ChangeID)))
	if response.State != StateRecoveryRequired || executor.rollbacks != 0 {
		t.Fatalf("restored uncertain exchange did not retain recovery state: %#v", response)
	}
	payload, err := os.ReadFile(auditPath)
	if err != nil || !bytes.Contains(payload, []byte(`"mutationAttempted":true`)) ||
		!bytes.Contains(payload, []byte(`"exchangeRestored":true`)) {
		t.Fatalf("restored exchange evidence missing from audit: %v %s", err, payload)
	}
}

func TestPVEPreparationFailureReleasesOnlyCertainNoMutationLock(t *testing.T) {
	now := time.Date(2026, 8, 8, 1, 30, 0, 0, time.UTC)
	operation := fmt.Sprintf(`"method":"change.prepare","operation":{"kind":"pve.guest.action","pluginId":"workload.pve","pluginDigest":"sha256:%s","node":"pve1","guestType":"qemu","vmid":100,"action":"start"}`, strings.Repeat("a", 64))

	certainExecutor := &fakePVEExecutor{fakeExecutor: fakeExecutor{prepareErr: errors.New("precondition changed before any task")}}
	certainService := testService(t, now, certainExecutor)
	certainService.Domain = DomainPVE
	first := certainService.Handle(context.Background(), peercred.Credential{UID: 1001}, parseRequest(t, now, "prepare-pve-certain-1", operation))
	if !first.OK || !strings.HasPrefix(first.ChangeID, "pve-change-") {
		t.Fatalf("PVE domain did not use its isolated change id: %#v", first)
	}
	status := certainService.Handle(context.Background(), peercred.Credential{UID: 1001}, parseRequest(t, now, "status-pve-certain-1", fmt.Sprintf(`"method":"change.status","changeId":%q`, first.ChangeID)))
	metadata, ok := status.Data.(changeStatusData)
	if !status.OK || !ok || metadata.Plan == nil || metadata.Plan.PreconditionDigest == "" ||
		len(metadata.Plan.Steps) != 1 || metadata.Plan.Steps[0].Fields[len(metadata.Plan.Steps[0].Fields)-2].Name != "precondition.currentStatus" {
		t.Fatalf("PVE status omitted broker-observed approval preconditions: %#v", status)
	}
	failed := certainService.Handle(context.Background(), peercred.Credential{UID: 0}, parseRequest(t, now, "approve-pve-certain-1", fmt.Sprintf(`"method":"change.approve","changeId":%q`, first.ChangeID)))
	if failed.State != StateRolledBack || !strings.Contains(failed.Error, "no mutation started") {
		t.Fatalf("certain pre-mutation failure did not end terminally: %#v", failed)
	}
	second := certainService.Handle(context.Background(), peercred.Credential{UID: 1001}, parseRequest(t, now, "prepare-pve-certain-2", operation))
	secondFailure := certainService.Handle(context.Background(), peercred.Credential{UID: 0}, parseRequest(t, now, "approve-pve-certain-2", fmt.Sprintf(`"method":"change.approve","changeId":%q`, second.ChangeID)))
	if strings.Contains(secondFailure.Error, "locked by unresolved change") {
		t.Fatalf("certain pre-mutation failure retained the resource lock: %#v", secondFailure)
	}

	uncertainExecutor := &fakePVEExecutor{fakeExecutor: fakeExecutor{prepareErr: fakeUncertainError{message: "safety backup task started but status is unknown"}}}
	uncertainService := testService(t, now, uncertainExecutor)
	uncertainService.Domain = DomainPVE
	uncertain := uncertainService.Handle(context.Background(), peercred.Credential{UID: 1001}, parseRequest(t, now, "prepare-pve-uncertain-1", operation))
	uncertainFailure := uncertainService.Handle(context.Background(), peercred.Credential{UID: 0}, parseRequest(t, now, "approve-pve-uncertain-1", fmt.Sprintf(`"method":"change.approve","changeId":%q`, uncertain.ChangeID)))
	if uncertainFailure.State != StateRecoveryRequired {
		t.Fatalf("uncertain preparation did not require recovery: %#v", uncertainFailure)
	}
	blocked := uncertainService.Handle(context.Background(), peercred.Credential{UID: 1001}, parseRequest(t, now, "prepare-pve-uncertain-2", operation))
	blockedApproval := uncertainService.Handle(context.Background(), peercred.Credential{UID: 0}, parseRequest(t, now, "approve-pve-uncertain-2", fmt.Sprintf(`"method":"change.approve","changeId":%q`, blocked.ChangeID)))
	if !strings.Contains(blockedApproval.Error, "locked by unresolved change") {
		t.Fatalf("unresolved PVE preparation did not retain its resource lock: %#v", blockedApproval)
	}
}

func TestPVERecoveryChainTransfersClusterVMIDLockAndNeverUsesStanding(t *testing.T) {
	now := time.Date(2026, 8, 8, 1, 45, 0, 0, time.UTC)
	digest := "sha256:" + strings.Repeat("a", 64)
	executor := &fakePVEExecutor{fakeExecutor: fakeExecutor{
		result:     ExecutionResult{RollbackAvailable: false},
		executeErr: fakeUncertainError{message: "PVE task terminal state is unknown"},
	}}
	service := testService(t, now, executor)
	service.Domain = DomainPVE
	agent := peercred.Credential{UID: service.AgentUID}
	approver := peercred.Credential{UID: service.ApproverUID}
	prepare := func(requestID, guestType, recoveryOf string) protocol.Response {
		recovery := ""
		if recoveryOf != "" {
			recovery = fmt.Sprintf(`,"recoveryOfChangeId":%q`, recoveryOf)
		}
		payload := fmt.Sprintf(`"method":"change.prepare","operation":{"kind":"pve.guest.action","pluginId":"workload.pve","pluginDigest":%q%s,"node":"pve1","guestType":%q,"vmid":100,"action":"start"}`, digest, recovery, guestType)
		return service.Handle(context.Background(), agent, parseRequest(t, now, requestID, payload))
	}
	approve := func(requestID, changeID string) protocol.Response {
		return service.Handle(context.Background(), approver, parseRequest(t, now, requestID,
			fmt.Sprintf(`"method":"change.approve","changeId":%q`, changeID)))
	}

	parentPrepared := prepare("prepare-pve-chain-parent", "qemu", "")
	parentFailed := approve("approve-pve-chain-parent", parentPrepared.ChangeID)
	if parentFailed.State != StateRecoveryRequired {
		t.Fatalf("parent did not retain the unresolved VMID lock: %#v", parentFailed)
	}

	executor.executeErr = fakeNoMutationError{message: "recovery precondition drifted before API"}
	childPrepared := prepare("prepare-pve-chain-child", "lxc", parentPrepared.ChangeID)
	if !childPrepared.OK || childPrepared.State != StatePendingApproval {
		t.Fatalf("valid recovery child did not remain separately approvable: %#v", childPrepared)
	}
	childFailed := approve("approve-pve-chain-child", childPrepared.ChangeID)
	if childFailed.State != StateRecoveryRequired {
		t.Fatalf("failed recovery child released the transferred lock: %#v", childFailed)
	}
	parent, _ := service.Store.Change(parentPrepared.ChangeID)
	if parent.State != StateSuperseded || parent.Resolution == nil ||
		parent.Resolution.ChildChangeID != childPrepared.ChangeID ||
		service.Store.state.ResourceLocks["pve/vmid/100"] != childPrepared.ChangeID {
		t.Fatalf("parent was not durably superseded by the failed child: parent=%#v locks=%#v", parent, service.Store.state.ResourceLocks)
	}
	parentStatus := service.Handle(context.Background(), agent, parseRequest(t, now, "status-pve-chain-parent",
		fmt.Sprintf(`"method":"change.status","changeId":%q`, parentPrepared.ChangeID)))
	parentData, ok := parentStatus.Data.(changeStatusData)
	if !parentStatus.OK || parentStatus.State != StateSuperseded || !ok || parentData.Resolution == nil ||
		parentData.Resolution.ChildPlanHash != parent.Resolution.ChildPlanHash {
		t.Fatalf("signed status omitted recovery resolution evidence: %#v", parentStatus)
	}

	ordinary := prepare("prepare-pve-chain-ordinary", "qemu", "")
	blocked := approve("approve-pve-chain-ordinary", ordinary.ChangeID)
	if !strings.Contains(blocked.Error, childPrepared.ChangeID) {
		t.Fatalf("ordinary change bypassed the recovery child's VMID lock: %#v", blocked)
	}
	rejected := service.Handle(context.Background(), approver, parseRequest(t, now, "reject-pve-chain-ordinary",
		fmt.Sprintf(`"method":"change.reject","changeId":%q`, ordinary.ChangeID)))
	if !rejected.OK || service.Store.state.ResourceLocks["pve/vmid/100"] != childPrepared.ChangeID {
		t.Fatalf("rejecting a competing pending change disturbed the recovery lock: response=%#v locks=%#v", rejected, service.Store.state.ResourceLocks)
	}

	executor.executeErr = nil
	grandchild := prepare("prepare-pve-chain-grandchild", "qemu", childPrepared.ChangeID)
	committed := approve("approve-pve-chain-grandchild", grandchild.ChangeID)
	if !committed.OK || committed.State != StateCommitted {
		t.Fatalf("separately approved recovery grandchild did not commit: %#v", committed)
	}
	child, _ := service.Store.Change(childPrepared.ChangeID)
	if child.State != StateSuperseded || child.Resolution == nil ||
		child.Resolution.ChildChangeID != grandchild.ChangeID || len(service.Store.state.ResourceLocks) != 0 {
		t.Fatalf("committed recovery did not resolve the chain and release its child-owned lock: child=%#v locks=%#v", child, service.Store.state.ResourceLocks)
	}
}

func TestPVERecoveryStatusCrossBoundaryFixtures(t *testing.T) {
	for _, basis := range []string{"no-mutation", "local-unknown"} {
		t.Run(basis, func(t *testing.T) {
			now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
			dir := t.TempDir()
			store, err := OpenStoreWithLimits(filepath.Join(dir, "state"), testStoreLimits(&now))
			if err != nil {
				t.Fatal(err)
			}
			parent := testPVEStoredChange(t, "pve-change-status-parent-0001", StateRecoveryRequired, now, "qemu", 100, "")
			parent.PVEMutationVersion = 1
			parent.MutationDisposition = protocol.PVEMutationDispositionUnknown
			child := testPVEStoredChange(t, "pve-change-status-child-00001", StatePendingApproval, now, "qemu", 100, parent.ID)
			child.PVEMutationVersion = 1
			if err := store.PutChangeWithResourceLock(parent); err != nil {
				t.Fatal(err)
			}
			if err := store.PutChange(child); err != nil {
				t.Fatal(err)
			}
			child.State = StatePreparing
			child.AuthorizationBasis = "approval-key:approver-test-v1"
			child.AuthorizedAt = timestamp(now)
			if basis == "no-mutation" {
				err = store.PutRecoveryChangeAndTransferResource(child, PVERecoveryReadiness{
					MutationDisposition: protocol.PVEMutationDispositionNotStarted,
				})
			} else {
				observation, observationErr := protocol.NewPVERecoveryClearanceObservation(
					"qemu", 100,
					[]protocol.PVERecoveryActiveTaskProbe{{Node: "pve1", VMID: 100, ActiveCount: 0}},
					[]protocol.PVERecoveryGuestState{{Node: "pve1", GuestType: "qemu", VMID: 100, Status: "stopped"}},
					[]protocol.PVERecoveryClusterState{{Type: "node", Name: "pve1", Node: "pve1", NodeID: 0, Local: 1, Online: 1}},
				)
				if observationErr != nil {
					t.Fatal(observationErr)
				}
				challenge, challengeErr := protocol.FinalizePVERecoveryClearanceChallenge(protocol.PVERecoveryClearanceChallenge{
					Kind: "pve.recovery-clearance-challenge/v1", ClearanceID: "pve-clearance-00112233445566778899aabbccddeeff",
					ParentChangeID: parent.ID, ChildChangeID: child.ID, ChildPlanHash: child.PlanHash,
					ResourceKey: child.ResourceKey, Observation: observation,
					IssuedAt: timestamp(now), ExpiresAt: timestamp(now.Add(time.Minute)),
				})
				if challengeErr != nil {
					t.Fatal(challengeErr)
				}
				err = store.PutRecoveryChangeAndTransferResourceWithClearance(child, challenge)
			}
			if err != nil {
				t.Fatal(err)
			}
			service := testService(t, now, &fakeExecutor{})
			service.Store = store
			service.Domain = DomainPVE
			response, snapshot := service.status(peercred.Credential{UID: service.AgentUID}, protocol.Request{
				Version: protocol.Version, RequestID: "status-cross-boundary-" + basis,
				Method: protocol.MethodChangeStatus, ServerID: parent.ServerID, MachineID: parent.MachineID,
				TargetID: parent.TargetID, PolicyRevision: parent.PolicyRevision,
				CapabilityRevision: parent.CapabilityRevision, ChangeID: parent.ID,
			})
			if !response.OK || response.State != StateSuperseded || snapshot == nil || snapshot.State != response.State {
				t.Fatalf("real Store transfer did not produce a status response: %#v", response)
			}
			payload, err := json.Marshal(response.Data)
			if err != nil {
				t.Fatal(err)
			}
			fixtureName := "pve-recovery-status-" + basis + ".json"
			expectedPayload, err := os.ReadFile(filepath.Join("..", "..", "test", "fixtures", fixtureName))
			if err != nil {
				t.Fatal(err)
			}
			var actualValue, expectedValue interface{}
			if err := json.Unmarshal(payload, &actualValue); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(expectedPayload, &expectedValue); err != nil {
				t.Fatal(err)
			}
			actualCanonical, _ := json.Marshal(actualValue)
			expectedCanonical, _ := json.Marshal(expectedValue)
			if string(actualCanonical) != string(expectedCanonical) {
				t.Fatalf("real Store transfer status drifted from shared %s fixture:\nactual=%s\nexpected=%s", basis, payload, expectedPayload)
			}
		})
	}
}

func TestPVERecoveryApprovalKeepsParentLockWhileParentTaskIsRunningAcrossRestart(t *testing.T) {
	now := time.Date(2026, 8, 8, 1, 55, 0, 0, time.UTC)
	digest := "sha256:" + strings.Repeat("a", 64)
	executor := &fakePVEExecutor{fakeExecutor: fakeExecutor{
		executeErr: fakeUncertainError{message: "parent PVE task is still running"},
	}}
	service := testService(t, now, executor)
	service.Domain = DomainPVE
	agent := peercred.Credential{UID: service.AgentUID}
	approver := peercred.Credential{UID: service.ApproverUID}
	prepare := func(requestID, recoveryOf string) protocol.Response {
		recovery := ""
		if recoveryOf != "" {
			recovery = fmt.Sprintf(`,"recoveryOfChangeId":%q`, recoveryOf)
		}
		return service.Handle(context.Background(), agent, parseRequest(t, now, requestID, fmt.Sprintf(
			`"method":"change.prepare","operation":{"kind":"pve.guest.action","pluginId":"workload.pve","pluginDigest":%q%s,"node":"pve1","guestType":"qemu","vmid":100,"action":"start"}`,
			digest, recovery,
		)))
	}
	parentPrepared := prepare("prepare-running-parent", "")
	parentFailed := service.Handle(context.Background(), approver, parseRequest(t, now, "approve-running-parent",
		fmt.Sprintf(`"method":"change.approve","changeId":%q`, parentPrepared.ChangeID)))
	if parentFailed.State != StateRecoveryRequired || executor.executions != 1 {
		t.Fatalf("parent did not enter recovery with one attempted execution: response=%#v executions=%d", parentFailed, executor.executions)
	}
	executor.reconcileErr = errors.New("PVE primary task is running")
	childPrepared := prepare("prepare-running-child", parentPrepared.ChangeID)
	childDenied := service.Handle(context.Background(), approver, parseRequest(t, now, "approve-running-child",
		fmt.Sprintf(`"method":"change.approve","changeId":%q`, childPrepared.ChangeID)))
	if childDenied.OK || !strings.Contains(childDenied.Error, "running") || executor.executions != 1 {
		t.Fatalf("running parent allowed a child executor call: response=%#v executions=%d", childDenied, executor.executions)
	}
	parent, _ := service.Store.Change(parentPrepared.ChangeID)
	child, _ := service.Store.Change(childPrepared.ChangeID)
	if parent.State != StateRecoveryRequired || child.State != StatePendingApproval ||
		service.Store.state.ResourceLocks["pve/vmid/100"] != parent.ID || parent.Resolution != nil {
		t.Fatalf("failed readiness check transferred or released the parent lock: parent=%#v child=%#v locks=%#v", parent, child, service.Store.state.ResourceLocks)
	}
	reopened, err := OpenStore(service.Store.Directory())
	if err != nil {
		t.Fatal(err)
	}
	if reopened.state.ResourceLocks["pve/vmid/100"] != parent.ID || reopened.state.Changes[parent.ID].State != StateRecoveryRequired {
		t.Fatalf("restart changed the running parent's lock ownership: %#v", reopened.state)
	}
}

func TestRootBrokerOperationDomainsRejectCrossDomainRequests(t *testing.T) {
	now := time.Date(2026, 8, 8, 2, 0, 0, 0, time.UTC)
	pveOperation := fmt.Sprintf(`"method":"change.prepare","operation":{"kind":"pve.guest.action","pluginId":"workload.pve","pluginDigest":"sha256:%s","node":"pve1","guestType":"qemu","vmid":100,"action":"start"}`, strings.Repeat("a", 64))
	core := testService(t, now, &fakePVEExecutor{})
	if response := core.Handle(context.Background(), peercred.Credential{UID: 1001}, parseRequest(t, now, "prepare-domain-core", pveOperation)); !strings.Contains(response.Error, "core root broker rejects PVE") {
		t.Fatalf("core broker accepted PVE operation: %#v", response)
	}
	pve := testService(t, now, &fakePVEExecutor{})
	pve.Domain = DomainPVE
	if response := pve.Handle(context.Background(), peercred.Credential{UID: 1001}, parseRequest(t, now, "prepare-domain-pve", `"method":"change.prepare","operation":{"kind":"package.install","package":"nginx"}`)); !strings.Contains(response.Error, "PVE root broker rejects core") {
		t.Fatalf("PVE broker accepted core operation: %#v", response)
	}
}

func TestPrepareRejectsCallerSelectedCapabilityRevision(t *testing.T) {
	now := time.Date(2026, 8, 8, 2, 15, 0, 0, time.UTC)
	service := testService(t, now, &fakeExecutor{})
	request := parseRequest(t, now, "prepare-capability-mismatch", `"serverId":"server-12345678","machineId":"machine-12345678","targetId":"target-service","policyRevision":"policy-12345678","capabilityRevision":"capability-caller-selected-v1","callerRole":"agent","method":"change.prepare","operation":{"kind":"package.install","package":"nginx"}`)
	response := service.Handle(context.Background(), peercred.Credential{UID: 1001}, request)
	if response.OK || !strings.Contains(response.Error, "does not match the broker implementation") {
		t.Fatalf("broker accepted caller-selected capability revision: %#v", response)
	}
}

func TestLongChangesDoNotBlockStatusOrUnrelatedChanges(t *testing.T) {
	now := time.Now().UTC()
	release := make(chan struct{})
	executor := &concurrentExecutor{started: make(chan string, 2), release: release}
	service := testService(t, now, executor)
	prepare := func(id, pkg string) protocol.Response {
		return service.Handle(context.Background(), peercred.Credential{UID: 1001}, parseRequest(t, now, id, fmt.Sprintf(`"method":"change.prepare","operation":{"kind":"package.install","package":%q}`, pkg)))
	}
	first := prepare("prepare-concurrent-first", "nginx")
	second := prepare("prepare-concurrent-second", "curl")
	responses := make(chan protocol.Response, 2)
	for index, changeID := range []string{first.ChangeID, second.ChangeID} {
		requestID := fmt.Sprintf("approve-concurrent-%d", index)
		go func() {
			responses <- service.Handle(context.Background(), peercred.Credential{UID: 0}, parseRequest(t, now, requestID, fmt.Sprintf(`"method":"change.approve","changeId":%q`, changeID)))
		}()
	}
	for index := 0; index < 2; index++ {
		select {
		case <-executor.started:
		case <-time.After(time.Second):
			t.Fatal("an unrelated change was blocked behind a long-running change")
		}
	}
	statusDeadline := time.Now().Add(250 * time.Millisecond)
	statusContext, cancelStatus := context.WithDeadline(context.Background(), statusDeadline)
	defer cancelStatus()
	statusPayload := fmt.Sprintf(
		`{"version":1,"requestId":"status-concurrent-first","deadline":%q,"method":"change.status","changeId":%q}`,
		statusDeadline.Format(time.RFC3339Nano), first.ChangeID,
	)
	statusRequest, err := protocol.ParseRequest([]byte(statusPayload), now)
	if err != nil {
		t.Fatal(err)
	}
	statusResult := make(chan protocol.Response, 1)
	go func() {
		statusResult <- service.Handle(statusContext, peercred.Credential{UID: 1001}, statusRequest)
	}()
	select {
	case status := <-statusResult:
		if !status.OK || status.State != StateExecuting {
			t.Fatalf("status did not observe an executing change: %#v", status)
		}
	case <-statusContext.Done():
		close(release)
		t.Fatalf("status was blocked behind a long-running change past its request/context deadline: %v", statusContext.Err())
	}
	close(release)
	for index := 0; index < 2; index++ {
		if response := <-responses; !response.OK || response.State != StateCommitted {
			t.Fatalf("concurrent change failed: %#v", response)
		}
	}
}

func TestRequestSingleflightAndPerChangeMutationLock(t *testing.T) {
	now := time.Date(2026, 8, 8, 2, 45, 0, 0, time.UTC)
	release := make(chan struct{})
	executor := &concurrentExecutor{started: make(chan string, 2), release: release}
	service := testService(t, now, executor)
	prepared := service.Handle(context.Background(), peercred.Credential{UID: 1001}, parseRequest(t, now, "prepare-singleflight", `"method":"change.prepare","operation":{"kind":"package.install","package":"nginx"}`))
	approval := parseRequest(t, now, "approve-singleflight", fmt.Sprintf(`"method":"change.approve","changeId":%q`, prepared.ChangeID))
	responses := make(chan protocol.Response, 3)
	go func() { responses <- service.Handle(context.Background(), peercred.Credential{UID: 0}, approval) }()
	<-executor.started
	go func() { responses <- service.Handle(context.Background(), peercred.Credential{UID: 0}, approval) }()
	go func() {
		responses <- service.Handle(context.Background(), peercred.Credential{UID: 0}, parseRequest(t, now, "approve-same-change-other-id", fmt.Sprintf(`"method":"change.approve","changeId":%q`, prepared.ChangeID)))
	}()
	select {
	case response := <-responses:
		t.Fatalf("duplicate or same-change mutation returned before the owner completed: %#v", response)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	var committed int
	for index := 0; index < 3; index++ {
		response := <-responses
		if response.OK && response.State == StateCommitted {
			committed++
		}
	}
	if executor.executions.Load() != 1 || committed != 2 {
		t.Fatalf("singleflight/change lock did not execute exactly once: executions=%d committedResponses=%d", executor.executions.Load(), committed)
	}
}

func TestRequestAdmissionAndCacheFailureDoNotLeakInflight(t *testing.T) {
	now := time.Date(2026, 8, 8, 3, 0, 0, 0, time.UTC)
	service := testService(t, now, &fakeExecutor{})
	service.MaxInflightRequests = 1
	service.MaxInflightPerUID = 1
	current, _, err := service.beginRequest(context.Background(), "inflight-bounded-1", 1001, "fingerprint-1", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.beginRequest(context.Background(), "inflight-bounded-2", 1001, "fingerprint-2", false); err == nil || !strings.Contains(err.Error(), "concurrency") {
		t.Fatalf("inflight request quota was not enforced: %v", err)
	}
	service.finishRequest("inflight-bounded-1", current, protocol.Response{Version: protocol.Version, RequestID: "inflight-bounded-1", OK: true})

	current, _, err = service.beginRequest(context.Background(), "cache-failure-bounded", 1001, "fingerprint-3", true)
	if err != nil {
		t.Fatal(err)
	}
	service.Store.dir = filepath.Join(service.Store.dir, "missing", "directory")
	result := protocol.Response{Version: protocol.Version, RequestID: "cache-failure-bounded", OK: true}
	if err := service.Store.Cache("cache-failure-bounded", 1001, "fingerprint-3", result, now.Add(time.Minute)); err == nil {
		t.Fatal("cache persistence failure was not induced")
	}
	service.finishRequest("cache-failure-bounded", current, protocol.Response{Version: protocol.Version, RequestID: "cache-failure-bounded", Error: "persist failed"})
	if len(service.inflightRequests) != 0 || len(service.inflightByUID) != 0 {
		t.Fatalf("cache failure leaked inflight entries: requests=%d uids=%d", len(service.inflightRequests), len(service.inflightByUID))
	}
	if replay, ok, err := service.Store.Cached("cache-failure-bounded", 1001, "fingerprint-3"); err != nil || !ok || !replay.OK {
		t.Fatalf("cache failure lost the bounded volatile replay guard: response=%#v ok=%v err=%v", replay, ok, err)
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
	for _, path := range []string{
		"/etc/shadow", "/etc/ssh/sshd_config", "/etc/sudoers.d/example", "/etc/sysctl.d/99-agent.conf",
		"/etc/ops-agent/targets.json", "/var/lib/ops-agent/root-state/state.json",
		"/opt/pi-ops-agent/current/bin/ops-root-helper", "/etc/systemd/system/ops-root-helper.service",
	} {
		if err := executor.ensureAllowedPath(path); err == nil {
			t.Fatalf("critical path %s was allowed", path)
		}
	}
	for _, unit := range []string{
		"ops-agentd.service", "ops-agent-server.service", "ops-root-helper.service",
		"ops-pve-root-helper.service", "agentd-approval-reviewer.service", "agentd-guardian.service",
		"sshd.service", "dbus.service", "NetworkManager.service", "nftables.service",
	} {
		if !isCriticalService(unit) {
			t.Fatalf("critical service %s was allowed", unit)
		}
	}
}

func TestRemoteApprovalRoleAndChangeScopeAreEnforced(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	policyPayload := fmt.Sprintf(`{"version":1,"revision":"policy-12345678","targets":[{"id":"target-service","account":"service_agent","displayName":"Service","inspect":{"hostSnapshot":true,"processList":false,"units":[],"readPaths":[%q]},"changes":{"writePaths":[%q],"units":[],"packages":["example"],"plugins":[]}}]}`, directory, directory)
	policy, err := targetpolicy.Parse([]byte(policyPayload))
	if err != nil {
		t.Fatal(err)
	}
	executor := &fakeExecutor{result: ExecutionResult{RollbackAvailable: true, RollbackData: json.RawMessage(`{}`)}}
	service := testService(t, now, executor)
	service.Policy = policy
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service.Approval = &ApprovalVerifier{KeyID: "approver-test-v1", PublicKey: publicKey}
	serverPeer := peercred.Credential{UID: service.AgentUID}
	prepared := service.Handle(context.Background(), serverPeer, parseRemoteRequest(t, now, "prepare-remote-0001", "agent", `"method":"change.prepare","operation":{"kind":"package.install","package":"example"}`))
	if !prepared.OK {
		t.Fatalf("remote prepare failed: %#v", prepared)
	}
	agentApproval := service.Handle(context.Background(), serverPeer, parseRemoteRequest(t, now, "approve-remote-agent", "agent", fmt.Sprintf(`"method":"change.approve","changeId":%q`, prepared.ChangeID)))
	if agentApproval.OK || executor.executions != 0 {
		t.Fatal("agent mTLS role approved a remote change")
	}
	wrongTargetPayload := fmt.Sprintf(`{"version":1,"requestId":"approve-wrong-target","deadline":%q,"method":"change.approve","serverId":"server-12345678","machineId":"machine-12345678","targetId":"target-other","policyRevision":"policy-12345678","callerRole":"approver","changeId":%q}`, now.Add(time.Minute).Format(time.RFC3339Nano), prepared.ChangeID)
	wrongTarget, err := protocol.ParseRequest([]byte(wrongTargetPayload), now)
	if err != nil {
		t.Fatal(err)
	}
	if response := service.Handle(context.Background(), serverPeer, wrongTarget); response.OK {
		t.Fatal("approval with another target was accepted")
	}
	change, ok := service.Store.Change(prepared.ChangeID)
	if !ok {
		t.Fatal("prepared remote change is missing")
	}
	grant := signedGrant(t, privateKey, now, "approve", change)
	grantJSON, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	approved := service.Handle(context.Background(), serverPeer, parseRemoteRequest(t, now, "approve-remote-valid", "approver", fmt.Sprintf(`"method":"change.approve","changeId":%q,"approval":%s`, prepared.ChangeID, grantJSON)))
	if !approved.OK || approved.State != StateCommitted || executor.executions != 1 {
		t.Fatalf("valid remote approval failed: %#v", approved)
	}
}

func TestRemoteApprovalWithoutVerifierFailsClosed(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	service := &Service{
		AgentUID: 1001, ApproverUID: 0,
		Policy: testTargetPolicy(t, t.TempDir(), "policy-no-approval-verifier"),
	}
	request := protocol.Request{
		CallerRole: "approver",
		Approval:   &protocol.ApprovalGrant{},
	}
	change := &Change{ID: "change-no-approval-verifier"}
	err := service.authorizeApproval(peercred.Credential{UID: service.AgentUID}, request,
		change, "approve", now)
	if err == nil || !strings.Contains(err.Error(), "configured approval verifier") {
		t.Fatalf("remote approval without verifier did not fail closed: %v", err)
	}
}

func TestHistoricalChangeActionsSurvivePolicyRevisionDrift(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	policyV1 := testTargetPolicy(t, directory, "policy-history-v1")
	policyV2 := testTargetPolicy(t, directory, "policy-history-v2")
	executor := &fakeExecutor{result: ExecutionResult{RollbackAvailable: true, RollbackData: json.RawMessage(`{}`)}}
	service := testService(t, now, executor)
	service.Policy = policyV1
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service.Approval = &ApprovalVerifier{KeyID: "approver-test-v1", PublicKey: publicKey}
	serverPeer := peercred.Credential{UID: service.AgentUID}

	pending := service.Handle(context.Background(), serverPeer, parseRemoteRequestWithPolicy(t, now, "prepare-history-pending", "agent", policyV1.Revision, `"method":"change.prepare","operation":{"kind":"package.install","package":"example"}`))
	committed := service.Handle(context.Background(), serverPeer, parseRemoteRequestWithPolicy(t, now, "prepare-history-commit", "agent", policyV1.Revision, `"method":"change.prepare","operation":{"kind":"package.install","package":"example"}`))
	if !pending.OK || !committed.OK {
		t.Fatalf("prepare historical changes: pending=%#v committed=%#v", pending, committed)
	}
	committedChange, _ := service.Store.Change(committed.ChangeID)
	approveGrant := signedGrant(t, privateKey, now, "approve", committedChange)
	approveJSON, err := json.Marshal(approveGrant)
	if err != nil {
		t.Fatal(err)
	}
	approved := service.Handle(context.Background(), serverPeer, parseRemoteRequestWithPolicy(t, now, "approve-history-commit", "approver", policyV1.Revision, fmt.Sprintf(`"method":"change.approve","changeId":%q,"approval":%s`, committed.ChangeID, approveJSON)))
	if !approved.OK || approved.State != StateCommitted {
		t.Fatalf("commit before policy drift: %#v", approved)
	}

	service.Policy = policyV2
	status := service.Handle(context.Background(), serverPeer, parseRemoteRequestWithPolicy(t, now, "status-history-current", "agent", policyV2.Revision, fmt.Sprintf(`"method":"change.status","changeId":%q`, pending.ChangeID)))
	if !status.OK {
		t.Fatalf("historical status failed after policy drift: %#v", status)
	}
	data, ok := status.Data.(changeStatusData)
	if !ok || data.PolicyRevision != policyV1.Revision {
		t.Fatalf("historical status lost original policy revision: %#v", status.Data)
	}

	pendingChange, _ := service.Store.Change(pending.ChangeID)
	staleApproveGrant := signedGrant(t, privateKey, now, "approve", pendingChange)
	staleApproveJSON, err := json.Marshal(staleApproveGrant)
	if err != nil {
		t.Fatal(err)
	}
	staleApprove := service.Handle(context.Background(), serverPeer, parseRemoteRequestWithPolicy(t, now, "approve-history-stale", "approver", policyV2.Revision, fmt.Sprintf(`"method":"change.approve","changeId":%q,"approval":%s`, pending.ChangeID, staleApproveJSON)))
	if staleApprove.OK || executor.executions != 1 {
		t.Fatalf("old-revision change was approved under current policy: %#v", staleApprove)
	}

	rejectGrant := signedGrant(t, privateKey, now, "reject", pendingChange)
	rejectJSON, err := json.Marshal(rejectGrant)
	if err != nil {
		t.Fatal(err)
	}
	rejected := service.Handle(context.Background(), serverPeer, parseRemoteRequestWithPolicy(t, now, "reject-history-current", "approver", policyV2.Revision, fmt.Sprintf(`"method":"change.reject","changeId":%q,"approval":%s`, pending.ChangeID, rejectJSON)))
	if !rejected.OK || rejected.State != StateRejected {
		t.Fatalf("historical reject failed after policy drift: %#v", rejected)
	}

	rollbackGrant := signedGrant(t, privateKey, now, "rollback", committedChange)
	rollbackJSON, err := json.Marshal(rollbackGrant)
	if err != nil {
		t.Fatal(err)
	}
	rolledBack := service.Handle(context.Background(), serverPeer, parseRemoteRequestWithPolicy(t, now, "rollback-history-current", "approver", policyV2.Revision, fmt.Sprintf(`"method":"change.rollback","changeId":%q,"approval":%s`, committed.ChangeID, rollbackJSON)))
	if !rolledBack.OK || rolledBack.State != StateRolledBack || executor.rollbacks != 1 {
		t.Fatalf("historical rollback failed after policy drift: response=%#v rollbacks=%d", rolledBack, executor.rollbacks)
	}
}

func TestV01PersistedPluginOperationsOpenButCannotExecuteOrReuseUnsafeRollback(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	stateDirectory := filepath.Join(directory, "state")
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	installOperation := json.RawMessage(fmt.Sprintf(`{"kind":"plugin.install","pluginId":"adapter.botmux","version":"0.1.0","digest":%q,"catalogPath":"/opt/pi-ops-agent/current/catalog/adapter.botmux.json"}`, digest))
	configureOperation := json.RawMessage(fmt.Sprintf(`{"kind":"plugin.configure","pluginId":"adapter.botmux","version":"0.1.0","digest":%q,"settings":[{"name":"TOKEN_FILE","value":"/run/token"}]}`, digest))
	changes := map[string]*Change{
		"legacy-install": {
			ID: "legacy-install", PlanHash: protocol.LegacyPlanHashV02("", "", "", "", "", installOperation),
			Kind: "plugin.install", Summary: "legacy install", Operation: installOperation,
			State: StateCommitted, PreparedAt: "2026-08-01T00:00:00Z", UpdatedAt: "2026-08-01T00:00:00Z",
			RollbackData: json.RawMessage(`{}`), RollbackAvailable: true,
		},
		"legacy-configure": {
			ID: "legacy-configure", PlanHash: protocol.LegacyPlanHashV02("", "", "", "", "", configureOperation),
			Kind: "plugin.configure", Summary: "legacy configure", Operation: configureOperation,
			State: StateCommitted, PreparedAt: "2026-08-01T00:00:00Z", UpdatedAt: "2026-08-01T00:00:00Z",
			RollbackData: json.RawMessage(`{}`), RollbackAvailable: true,
		},
		"legacy-pending": {
			ID: "legacy-pending", PlanHash: protocol.LegacyPlanHashV02("", "", "", "", "", installOperation),
			Kind: "plugin.install", Summary: "legacy pending", Operation: installOperation,
			State: StatePendingApproval, PreparedAt: "2026-08-01T00:00:00Z", UpdatedAt: "2026-08-01T00:00:00Z",
		},
	}
	statePayload, err := json.Marshal(map[string]interface{}{"changes": changes, "requests": map[string]interface{}{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDirectory, "state.json"), []byte(statePayload), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(stateDirectory)
	if err != nil {
		t.Fatalf("open v0.1 store: %v", err)
	}
	log, err := audit.Open(filepath.Join(directory, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	executor := &fakeExecutor{}
	service := &Service{AgentUID: 1001, ApproverUID: 0, Store: store, Audit: log, Executor: executor, Now: func() time.Time { return now }}
	approver := peercred.Credential{UID: 0}

	rolledBack := service.Handle(context.Background(), approver, parseRequest(t, now, "rollback-legacy-install", `"method":"change.rollback","changeId":"legacy-install"`))
	if rolledBack.OK || executor.rollbacks != 0 || !strings.Contains(rolledBack.Error, "compatibility matrix") {
		t.Fatalf("unsafe legacy install rollback was reused: response=%#v rollbacks=%d", rolledBack, executor.rollbacks)
	}
	unsupported := service.Handle(context.Background(), approver, parseRequest(t, now, "rollback-legacy-config", `"method":"change.rollback","changeId":"legacy-configure"`))
	if unsupported.OK || executor.rollbacks != 0 || !strings.Contains(unsupported.Error, "legacy") {
		t.Fatalf("unsafe legacy configure rollback was attempted: %#v", unsupported)
	}
	approve := service.Handle(context.Background(), approver, parseRequest(t, now, "approve-legacy-pending", `"method":"change.approve","changeId":"legacy-pending"`))
	if approve.OK || executor.preparations != 0 || executor.executions != 0 || !strings.Contains(approve.Error, "legacy") {
		t.Fatalf("legacy pending operation executed after upgrade: %#v", approve)
	}
}

func TestLegacyBaseOperationsExposeRecoveryOnlyStatusAndPermitOnlyRecoveryActions(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	directory := t.TempDir()
	stateDirectory := filepath.Join(directory, "state")
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	preparedAt := now.Add(-time.Minute).Format(time.RFC3339Nano)
	serviceOperation := json.RawMessage(`{"kind":"service.action","unit":"demo.service","action":"restart"}`)
	fileOperation := json.RawMessage(`{"kind":"file.write","path":"/etc/demo.conf","content":"safe\n","mode":"0640"}`)
	changes := map[string]*Change{
		"change-legacy-service": {
			ID: "change-legacy-service", PlanHash: protocol.LegacyPlanHashV02("", "", "", "", "", serviceOperation), Kind: "service.action",
			Summary:   "legacy service restart",
			Operation: serviceOperation,
			State:     StateRecoveryRequired, PreparedAt: preparedAt, UpdatedAt: preparedAt,
			Verification: "legacy verification was interrupted", RollbackAvailable: true,
			RollbackData: json.RawMessage(`{"active":true}`),
			LastError:    "broker restarted during verification",
		},
		"change-legacy-file": {
			ID: "change-legacy-file", PlanHash: protocol.LegacyPlanHashV02("", "", "", "", "", fileOperation), Kind: "file.write",
			Summary:   "legacy file write",
			Operation: fileOperation,
			State:     StatePendingApproval, PreparedAt: preparedAt, UpdatedAt: preparedAt,
			RollbackAvailable: false,
		},
	}
	payload, err := json.Marshal(map[string]interface{}{
		"changes":  changes,
		"requests": map[string]interface{}{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDirectory, "state.json"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStoreWithLimits(stateDirectory, StoreLimits{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("open legacy base store: %v", err)
	}
	log, err := audit.Open(filepath.Join(directory, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	executor := &fakeExecutor{}
	service := &Service{
		AgentUID: 1001, ApproverUID: 0, Store: store, Audit: log,
		Executor: executor, Now: func() time.Time { return now },
	}
	approver := peercred.Credential{UID: 0}

	for _, changeID := range []string{"change-legacy-service", "change-legacy-file"} {
		status := service.Handle(context.Background(), approver, parseRequest(
			t, now, "status-"+changeID, fmt.Sprintf(`"method":"change.status","changeId":%q`, changeID),
		))
		data, ok := status.Data.(changeStatusData)
		if !status.OK || !ok || !data.RecoveryOnly || data.Plan != nil || data.RecoveryDescriptor == nil || data.BackupRefs == nil {
			t.Fatalf("legacy base status was not explicit recovery-only metadata: response=%#v data=%#v", status, data)
		}
	}

	approve := service.Handle(context.Background(), approver, parseRequest(
		t, now, "approve-legacy-file", `"method":"change.approve","changeId":"change-legacy-file"`,
	))
	if approve.OK || executor.executions != 0 || !strings.Contains(approve.Error, "recovery-only") {
		t.Fatalf("legacy file write was approved: %#v", approve)
	}
	rejected := service.Handle(context.Background(), approver, parseRequest(
		t, now, "reject-legacy-file", `"method":"change.reject","changeId":"change-legacy-file"`,
	))
	if !rejected.OK || rejected.State != StateRejected {
		t.Fatalf("legacy file write could not be rejected: %#v", rejected)
	}
	rolledBack := service.Handle(context.Background(), approver, parseRequest(
		t, now, "rollback-legacy-service", `"method":"change.rollback","changeId":"change-legacy-service"`,
	))
	if !rolledBack.OK || rolledBack.State != StateRolledBack || executor.rollbacks != 1 {
		t.Fatalf("legacy service recovery rollback failed: response=%#v rollbacks=%d", rolledBack, executor.rollbacks)
	}
}

func TestExactLegacyPlanHashClassifiesCurrentShapeAsRecoveryOnlyButRejectsArbitraryMismatch(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	directory := t.TempDir()
	store, err := OpenStore(filepath.Join(directory, "state"))
	if err != nil {
		t.Fatal(err)
	}
	log, err := audit.Open(filepath.Join(directory, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	operation := json.RawMessage(`{"kind":"package.install","package":"example","version":"1.2.3"}`)
	preparedAt := now.Add(-time.Minute).Format(time.RFC3339Nano)
	legacy := &Change{
		ID: "change-legacy-package", Kind: "package.install", Summary: "legacy package install",
		Operation: operation, PlanHash: protocol.LegacyPlanHashV02("", "", "", "", "", operation),
		State: StateCommitted, PreparedAt: preparedAt, UpdatedAt: preparedAt,
		RollbackData: json.RawMessage(`{"installed":false}`), RollbackAvailable: true,
	}
	corrupt := *legacy
	corrupt.ID = "change-corrupt-package"
	corrupt.PlanHash = "sha256:" + strings.Repeat("f", 64)
	if err := store.PutChange(legacy); err != nil {
		t.Fatal(err)
	}
	if err := store.PutChange(&corrupt); err != nil {
		t.Fatal(err)
	}
	executor := &fakeExecutor{}
	service := &Service{
		AgentUID: 1001, ApproverUID: 0, Store: store, Audit: log,
		Executor: executor, Now: func() time.Time { return now },
	}
	approver := peercred.Credential{UID: 0}
	status := service.Handle(context.Background(), approver, parseRequest(
		t, now, "status-legacy-package", `"method":"change.status","changeId":"change-legacy-package"`,
	))
	data, ok := status.Data.(changeStatusData)
	if !status.OK || !ok || !data.RecoveryOnly || data.Plan != nil || data.RecoveryDescriptor == nil ||
		data.RollbackAvailable || data.RollbackUnavailableReason == "" {
		t.Fatalf("exact legacy current-shape plan was not safely classified: response=%#v data=%#v", status, data)
	}
	rollback := service.Handle(context.Background(), approver, parseRequest(
		t, now, "rollback-legacy-package", `"method":"change.rollback","changeId":"change-legacy-package"`,
	))
	if rollback.OK || executor.rollbacks != 0 || !strings.Contains(rollback.Error, "compatibility matrix") {
		t.Fatalf("unsupported legacy current-shape rollback executed: response=%#v rollbacks=%d", rollback, executor.rollbacks)
	}
	corruptStatus := service.Handle(context.Background(), approver, parseRequest(
		t, now, "status-corrupt-package", `"method":"change.status","changeId":"change-corrupt-package"`,
	))
	if corruptStatus.OK || !strings.Contains(corruptStatus.Error, "neither") {
		t.Fatalf("arbitrary planHash mismatch was treated as recovery authority: %#v", corruptStatus)
	}
	corruptRollback := service.Handle(context.Background(), approver, parseRequest(
		t, now, "rollback-corrupt-package", `"method":"change.rollback","changeId":"change-corrupt-package"`,
	))
	if corruptRollback.OK || executor.rollbacks != 0 || !strings.Contains(corruptRollback.Error, "neither") {
		t.Fatalf("arbitrary planHash mismatch reached rollback: response=%#v rollbacks=%d", corruptRollback, executor.rollbacks)
	}
}

func signedGrant(t *testing.T, privateKey ed25519.PrivateKey, now time.Time, action string, change *Change) protocol.ApprovalGrant {
	t.Helper()
	grant := protocol.ApprovalGrant{
		Version: protocol.Version, KeyID: "approver-test-v1", Action: action,
		ServerID: change.ServerID, MachineID: change.MachineID, TargetID: change.TargetID,
		ChangeID: change.ID, PlanHash: change.PlanHash, PolicyRevision: change.PolicyRevision,
		CapabilityRevision: change.CapabilityRevision,
		IssuedAt:           now.UTC().Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).UTC().Format(time.RFC3339Nano),
		Nonce: "nonce-" + action + "-" + change.ID,
	}
	payload, err := grant.ApprovalPayload()
	if err != nil {
		t.Fatal(err)
	}
	grant.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return grant
}

func testTargetPolicy(t *testing.T, directory, revision string) *targetpolicy.Policy {
	t.Helper()
	payload := fmt.Sprintf(`{"version":1,"revision":%q,"targets":[{"id":"target-service","account":"service_agent","displayName":"Service","inspect":{"hostSnapshot":true,"processList":false,"units":[],"readPaths":[%q]},"changes":{"writePaths":[%q],"units":[],"packages":["example"],"plugins":[]}}]}`, revision, directory, directory)
	policy, err := targetpolicy.Parse([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func testStandingTargetPolicy(t *testing.T, directory, revision, scope string) *targetpolicy.Policy {
	t.Helper()
	payload := fmt.Sprintf(`{"version":1,"revision":%q,"targets":[{"id":"target-service","account":"service_agent","displayName":"Service","inspect":{"hostSnapshot":true,"processList":false,"units":[],"readPaths":[%q]},"changes":{"writePaths":[%q],"units":["example.service"],"packages":["example"],"plugins":[]},"authorization":{"standingScopes":[%q],"baseWorkloadDigest":%q}}]}`, revision, directory, directory, scope, testRootBaseDigest)
	policy, err := targetpolicy.Parse([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func testService(t *testing.T, now time.Time, executor Executor) *Service {
	service, _ := testServiceWithAuditPath(t, now, executor)
	return service
}

func testServiceWithAuditPath(t *testing.T, now time.Time, executor Executor) (*Service, string) {
	t.Helper()
	directory := t.TempDir()
	store, err := OpenStoreWithLimits(filepath.Join(directory, "state"), StoreLimits{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(directory, "audit.jsonl")
	log, err := audit.Open(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	return &Service{
		AgentUID: 1001, ApproverUID: 0, Store: store, Audit: log, Executor: executor,
		Now: func() time.Time { return now },
	}, auditPath
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

func parseRemoteRequest(t *testing.T, now time.Time, id, role, fields string) protocol.Request {
	return parseRemoteRequestWithPolicy(t, now, id, role, "policy-12345678", fields)
}

func parseRemoteRequestWithPolicy(t *testing.T, now time.Time, id, role, policyRevision, fields string) protocol.Request {
	t.Helper()
	payload := fmt.Sprintf(`{"version":1,"requestId":%q,"deadline":%q,"serverId":"server-12345678","machineId":"machine-12345678","targetId":"target-service","policyRevision":%q,"capabilityRevision":%q,"callerRole":%q,%s}`, id, now.Add(time.Minute).Format(time.RFC3339Nano), policyRevision, protocol.CapabilityRevision, role, fields)
	request, err := protocol.ParseRequest([]byte(payload), now)
	if err != nil {
		t.Fatal(err)
	}
	return request
}
