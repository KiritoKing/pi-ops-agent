package roothelper

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/peercred"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
	"github.com/KiritoKing/pi-ops-agent/internal/targetpolicy"
)

const workloadServiceDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

type workloadServiceRunner struct {
	activeState string
	subState    string
	unitUser    string
	calls       [][]string
	actionErr   error
}

func (r *workloadServiceRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	if slices.Contains(args, "show") {
		return fmt.Sprintf("LoadState=loaded\nActiveState=%s\nSubState=%s\nUser=%s\n", r.activeState, r.subState, r.unitUser), nil
	}
	for _, action := range []string{"start", "stop", "restart", "reload", "reset-failed"} {
		if !slices.Contains(args, action) {
			continue
		}
		if r.actionErr != nil {
			return "", r.actionErr
		}
		if action == "stop" || action == "reset-failed" {
			r.activeState, r.subState = "inactive", "dead"
		} else {
			r.activeState, r.subState = "active", "running"
		}
		return "", nil
	}
	return "", errors.New("unexpected workload service command")
}

func TestWorkloadServiceUserManagerPlanExecuteAndVerify(t *testing.T) {
	policy := workloadServiceTargetPolicy(t, "user", "restart")
	runner := &workloadServiceRunner{activeState: "active", subState: "running"}
	executor := &OSExecutor{
		Policy: policy, Runner: runner,
		LookupWorkloadAccount: func(account string) (int, string, error) {
			if account != "alice" {
				return 0, "", errors.New("unexpected account")
			}
			return 1001, "/home/alice", nil
		},
	}
	operation := workloadServiceOperation("user", "restart")
	scope := ExecutionScope{TargetID: "target-alice", PolicyRevision: policy.Revision, CapabilityRevision: protocol.CapabilityRevision}
	planned, err := executor.PlanOperation(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	if planned.Digest == "" || len(planned.Fields) != 5 || planned.Fields[0].Name != "accountUid" || planned.Fields[0].Value != "1001" {
		t.Fatalf("unexpected workload service precondition: %#v", planned)
	}
	scope.PreconditionDigest = planned.Digest
	prepared, err := executor.Prepare(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.RollbackAvailable {
		t.Fatal("workload service action incorrectly advertised automatic rollback")
	}
	if err := executor.Execute(context.Background(), scope, operation, prepared); err != nil {
		t.Fatal(err)
	}
	verification, err := executor.Verify(context.Background(), scope, operation, prepared)
	if err != nil || verification != "service is active/running" {
		t.Fatalf("unexpected verification %q: %v", verification, err)
	}
	if len(runner.calls) < 4 {
		t.Fatalf("expected plan, prepare, execute and verify calls, got %#v", runner.calls)
	}
	for _, call := range runner.calls {
		if call[0] != "/usr/sbin/runuser" || !slices.Contains(call, "/usr/bin/systemctl") || slices.Contains(call, "-c") {
			t.Fatalf("user-manager call escaped the fixed argv profile: %#v", call)
		}
	}
	joined := strings.Join(runner.calls[0], "\x00")
	for _, expected := range []string{"--user\x00alice\x00--\x00/usr/bin/env\x00-i", "XDG_RUNTIME_DIR=/run/user/1001", "/usr/bin/systemctl\x00--user\x00show", "--\x00example.service"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("user-manager call omitted %q: %#v", expected, runner.calls[0])
		}
	}
	if err := executor.Rollback(context.Background(), scope, operation, prepared); err == nil || !strings.Contains(err.Error(), "rollback is unavailable") {
		t.Fatalf("workload service rollback did not fail closed: %v", err)
	}
	if err := executor.Rollback(context.Background(), scope, operation, ExecutionResult{RollbackAvailable: true}); err == nil || !strings.Contains(err.Error(), "new typed change") {
		t.Fatalf("workload service rollback escaped the typed compensation boundary: %v", err)
	}
}

func TestWorkloadServicePreconditionDriftFailsBeforeMutation(t *testing.T) {
	policy := workloadServiceTargetPolicy(t, "user", "restart")
	runner := &workloadServiceRunner{activeState: "active", subState: "running"}
	executor := &OSExecutor{
		Policy: policy, Runner: runner,
		LookupWorkloadAccount: func(string) (int, string, error) { return 1001, "/home/alice", nil },
	}
	operation := workloadServiceOperation("user", "restart")
	scope := ExecutionScope{TargetID: "target-alice", PolicyRevision: policy.Revision, CapabilityRevision: protocol.CapabilityRevision}
	planned, err := executor.PlanOperation(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	runner.activeState, runner.subState = "inactive", "dead"
	scope.PreconditionDigest = planned.Digest
	if _, err := executor.Prepare(context.Background(), scope, operation); err == nil {
		t.Fatal("changed service state was accepted after approval")
	}
	for _, call := range runner.calls {
		if slices.Contains(call, "restart") {
			t.Fatalf("service mutated despite precondition drift: %#v", runner.calls)
		}
	}
}

func TestWorkloadServiceReloadAndResetFailedHaveExactStateTransitions(t *testing.T) {
	for _, test := range []struct {
		action       string
		starting     string
		startingSub  string
		verification string
	}{
		{action: "reload", starting: "active", startingSub: "running", verification: "service is active/running"},
		{action: "reset-failed", starting: "failed", startingSub: "failed", verification: "service failure state cleared: inactive/dead"},
	} {
		t.Run(test.action, func(t *testing.T) {
			policy := workloadServiceStandingTargetPolicy(t, "system", test.action)
			runner := &workloadServiceRunner{activeState: test.starting, subState: test.startingSub, unitUser: "alice"}
			executor := &OSExecutor{
				Policy: policy, Runner: runner,
				LookupWorkloadAccount: func(string) (int, string, error) { return 1001, "/home/alice", nil },
			}
			operation := workloadServiceOperation("system", test.action)
			scope := ExecutionScope{TargetID: "target-alice", PolicyRevision: policy.Revision, CapabilityRevision: protocol.CapabilityRevision}
			planned, err := executor.PlanOperation(context.Background(), scope, operation)
			if err != nil {
				t.Fatal(err)
			}
			scope.PreconditionDigest = planned.Digest
			prepared, err := executor.Prepare(context.Background(), scope, operation)
			if err != nil {
				t.Fatal(err)
			}
			if err := executor.Execute(context.Background(), scope, operation, prepared); err != nil {
				t.Fatal(err)
			}
			verification, err := executor.Verify(context.Background(), scope, operation, prepared)
			if err != nil || verification != test.verification {
				t.Fatalf("unexpected verification %q: %v", verification, err)
			}
			if _, _, standing := policy.StandingApproval("target-alice", operation); standing {
				t.Fatalf("%s unexpectedly inherited standing authorization", test.action)
			}
		})
	}
}

func TestWorkloadServicePreconditionDriftAfterPrepareFailsBeforeSystemctlAction(t *testing.T) {
	policy := workloadServiceTargetPolicy(t, "user", "restart")
	runner := &workloadServiceRunner{activeState: "active", subState: "running"}
	executor := &OSExecutor{
		Policy: policy, Runner: runner,
		LookupWorkloadAccount: func(string) (int, string, error) { return 1001, "/home/alice", nil },
	}
	operation := workloadServiceOperation("user", "restart")
	scope := ExecutionScope{TargetID: "target-alice", PolicyRevision: policy.Revision, CapabilityRevision: protocol.CapabilityRevision}
	planned, err := executor.PlanOperation(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	scope.PreconditionDigest = planned.Digest
	prepared, err := executor.Prepare(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	runner.activeState, runner.subState = "inactive", "dead"
	if err := executor.Execute(context.Background(), scope, operation, prepared); err == nil || !strings.Contains(err.Error(), "changed after preparation") {
		t.Fatalf("post-prepare service state drift was not rejected: %v", err)
	}
	for _, call := range runner.calls {
		if slices.Contains(call, "restart") {
			t.Fatalf("service action ran after post-prepare precondition drift: %#v", runner.calls)
		}
	}
}

func TestWorkloadSystemServiceMustRunAsApprovedAccount(t *testing.T) {
	policy := workloadServiceTargetPolicy(t, "system", "restart")
	runner := &workloadServiceRunner{activeState: "active", subState: "running", unitUser: "bob"}
	executor := &OSExecutor{
		Policy: policy, Runner: runner,
		LookupWorkloadAccount: func(string) (int, string, error) { return 1001, "/home/alice", nil },
	}
	operation := workloadServiceOperation("system", "restart")
	scope := ExecutionScope{TargetID: "target-alice", PolicyRevision: policy.Revision, CapabilityRevision: protocol.CapabilityRevision}
	if _, err := executor.PlanOperation(context.Background(), scope, operation); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("system unit account mismatch was not rejected: %v", err)
	}
}

func TestWorkloadServiceActionErrorIsOutcomeUncertain(t *testing.T) {
	policy := workloadServiceTargetPolicy(t, "system", "restart")
	runner := &workloadServiceRunner{activeState: "active", subState: "running", unitUser: "alice", actionErr: errors.New("timeout")}
	executor := &OSExecutor{
		Policy: policy, Runner: runner,
		LookupWorkloadAccount: func(string) (int, string, error) { return 1001, "/home/alice", nil },
	}
	operation := workloadServiceOperation("system", "restart")
	scope := ExecutionScope{TargetID: "target-alice", PolicyRevision: policy.Revision, CapabilityRevision: protocol.CapabilityRevision}
	planned, err := executor.PlanOperation(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	scope.PreconditionDigest = planned.Digest
	if err := executor.Execute(context.Background(), scope, operation, ExecutionResult{}); err == nil || !mutationOutcomeUncertain(err) {
		t.Fatalf("systemctl action error was not marked uncertain: %v", err)
	}
}

func TestWorkloadServiceBrokerPersistsAuthoritativeDigestBoundPlan(t *testing.T) {
	now := time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)
	policy := workloadServicePolicyForTarget(t, "target-service", "user", "restart")
	runner := &workloadServiceRunner{activeState: "active", subState: "running"}
	executor := &OSExecutor{
		Policy: policy, Runner: runner,
		LookupWorkloadAccount: func(string) (int, string, error) { return 1001, "/home/alice", nil },
	}
	service := testService(t, now, executor)
	service.Policy = policy
	operation := `"method":"change.prepare","operation":{"kind":"workload.service.action","pluginId":"workload.example-service","pluginDigest":"` + workloadServiceDigest + `","account":"alice","manager":"user","unit":"example.service","action":"restart"}`
	prepared := service.Handle(
		context.Background(),
		peercred.Credential{UID: service.AgentUID},
		parseRemoteRequestWithPolicy(t, now, "prepare-service-plan", "agent", policy.Revision, operation),
	)
	if !prepared.OK || prepared.State != StatePendingApproval || prepared.ChangeID == "" {
		t.Fatalf("workload service prepare failed: %#v", prepared)
	}
	status := service.Handle(
		context.Background(),
		peercred.Credential{UID: service.AgentUID},
		parseRemoteRequestWithPolicy(t, now, "status-service-plan", "agent", policy.Revision, `"method":"change.status","changeId":"`+prepared.ChangeID+`"`),
	)
	metadata, ok := status.Data.(changeStatusData)
	if !status.OK || !ok || metadata.Plan == nil {
		t.Fatalf("workload service status omitted its approval plan: %#v", status)
	}
	plan := metadata.Plan
	if plan.PluginDigest != workloadServiceDigest || plan.PreconditionDigest == "" || len(plan.Steps) != 1 || plan.Steps[0].Reversible {
		t.Fatalf("workload service plan lost digest, precondition, or no-rollback semantics: %#v", plan)
	}
	fields := make(map[string]string, len(plan.Steps[0].Fields))
	for _, field := range plan.Steps[0].Fields {
		fields[field.Name] = field.Value
	}
	for name, expected := range map[string]string{
		"pluginId": "workload.example-service", "pluginDigest": workloadServiceDigest,
		"account": "alice", "manager": "user", "unit": "example.service",
		"action": "restart", "precondition.accountUid": "1001",
		"precondition.activeState": "active", "precondition.subState": "running",
	} {
		if fields[name] != expected {
			t.Fatalf("approval plan field %s=%q, want %q: %#v", name, fields[name], expected, fields)
		}
	}
}

func workloadServiceOperation(manager, action string) *protocol.WorkloadServiceAction {
	return &protocol.WorkloadServiceAction{
		OperationKind: "workload.service.action", PluginID: "workload.example-service",
		PluginDigest: workloadServiceDigest, Account: "alice", Manager: manager,
		Unit: "example.service", Action: action,
	}
}

func workloadServiceTargetPolicy(t *testing.T, manager, action string) *targetpolicy.Policy {
	return workloadServicePolicyForTarget(t, "target-alice", manager, action)
}

func workloadServiceStandingTargetPolicy(t *testing.T, manager, action string) *targetpolicy.Policy {
	t.Helper()
	payload := `{"version":1,"revision":"policy-service-standing-v1","targets":[{"id":"target-alice","account":"alice","displayName":"Alice services","inspect":{"hostSnapshot":false,"processList":false,"units":[],"readPaths":[]},"changes":{"writePaths":[],"units":[],"packages":[],"plugins":[]},"authorization":{"standingScopes":["workload.service.action"]},"serviceWorkloads":[{"pluginId":"workload.example-service","pluginDigest":"` + workloadServiceDigest + `","account":"alice","manager":"` + manager + `","units":["example.service"],"operations":["` + action + `"]}]}]}`
	policy, err := targetpolicy.Parse([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func workloadServicePolicyForTarget(t *testing.T, targetID, manager, action string) *targetpolicy.Policy {
	t.Helper()
	payload := `{"version":1,"revision":"policy-service-v1","targets":[{"id":"` + targetID + `","account":"alice","displayName":"Alice services","inspect":{"hostSnapshot":false,"processList":false,"units":[],"readPaths":[]},"changes":{"writePaths":[],"units":[],"packages":[],"plugins":[]},"serviceWorkloads":[{"pluginId":"workload.example-service","pluginDigest":"` + workloadServiceDigest + `","account":"alice","manager":"` + manager + `","units":["example.service"],"operations":["` + action + `"]}]}]}`
	policy, err := targetpolicy.Parse([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}
