package roothelper

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/audit"
	"github.com/KiritoKing/pi-ops-agent/internal/peercred"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
	"github.com/KiritoKing/pi-ops-agent/internal/targetpolicy"
)

type clearanceTestExecutor struct {
	fakePVEExecutor
	observation    protocol.PVERecoveryClearanceObservation
	observeErr     error
	observeCalls   int
	driftAt        int
	blockAt        int
	observeStarted chan struct{}
	observeRelease <-chan struct{}
}

func (e *clearanceTestExecutor) ObservePVEUnknownRecoveryParent(context.Context, ExecutionScope, protocol.Operation) (protocol.PVERecoveryClearanceObservation, error) {
	e.observeCalls++
	if e.blockAt != 0 && e.observeCalls == e.blockAt {
		if e.observeStarted != nil {
			e.observeStarted <- struct{}{}
		}
		if e.observeRelease != nil {
			<-e.observeRelease
		}
	}
	if e.observeErr != nil {
		return protocol.PVERecoveryClearanceObservation{}, e.observeErr
	}
	result := e.observation
	if e.driftAt != 0 && e.observeCalls >= e.driftAt {
		result.GuestStates = append([]protocol.PVERecoveryGuestState(nil), result.GuestStates...)
		if len(result.GuestStates) == 0 {
			result.GuestStates = []protocol.PVERecoveryGuestState{{Node: "pve1", GuestType: "qemu", VMID: 100, Status: "running"}}
		} else if result.GuestStates[0].Status == "stopped" {
			result.GuestStates[0].Status = "running"
		} else {
			result.GuestStates[0].Status = "stopped"
		}
		var err error
		result, err = protocol.NewPVERecoveryClearanceObservation(result.GuestType, result.VMID, result.ActiveTaskProbes, result.GuestStates, result.ClusterStates)
		if err != nil {
			return protocol.PVERecoveryClearanceObservation{}, err
		}
	}
	return result, nil
}

type pveClearanceFixture struct {
	service    *Service
	executor   *clearanceTestExecutor
	parent     *Change
	child      *Change
	privateKey ed25519.PrivateKey
	now        *time.Time
}

func newPVEClearanceFixture(t *testing.T) pveClearanceFixture {
	t.Helper()
	current := time.Date(2026, 8, 8, 14, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	limits := testStoreLimits(&current)
	limits.Now = func() time.Time { return current }
	store, err := OpenStoreWithLimits(filepath.Join(directory, "state"), limits)
	if err != nil {
		t.Fatal(err)
	}
	log, err := audit.Open(filepath.Join(directory, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	observation, err := protocol.NewPVERecoveryClearanceObservation(
		"qemu", 100,
		[]protocol.PVERecoveryActiveTaskProbe{{Node: "pve1", VMID: 100, ActiveCount: 0}},
		[]protocol.PVERecoveryGuestState{{Node: "pve1", GuestType: "qemu", VMID: 100, Status: "stopped"}},
		[]protocol.PVERecoveryClusterState{{Type: "node", Name: "pve1", Node: "pve1", NodeID: 0, Local: 1, Online: 1}},
	)
	if err != nil {
		t.Fatal(err)
	}
	executor := &clearanceTestExecutor{
		fakePVEExecutor: fakePVEExecutor{fakeExecutor: fakeExecutor{}, reconcileErr: fmt.Errorf("primary intent exists without a recoverable task UPID")},
		observation:     observation,
	}
	policy := pveClearancePolicy(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{
		AgentUID: 1001, ApproverUID: 0, Store: store, Audit: log, Executor: executor,
		Policy: policy, Approval: &ApprovalVerifier{KeyID: "approver-test-v1", PublicKey: publicKey},
		Domain: DomainPVE, Now: func() time.Time { return current }, PVERecoveryClearanceTTL: 90 * time.Second,
	}
	parent := testPVEStoredChange(t, "pve-change-parent-clearance-0001", StateRecoveryRequired, current, "qemu", 100, "")
	parent.PVEMutationVersion = 1
	parent.MutationDisposition = protocol.PVEMutationDispositionUnknown
	child := testPVEStoredChange(t, "pve-change-child-clearance-00001", StatePendingApproval, current, "qemu", 100, parent.ID)
	child.PVEMutationVersion = 1
	if err := store.PutChangeWithResourceLock(parent); err != nil {
		t.Fatal(err)
	}
	if err := store.PutChange(child); err != nil {
		t.Fatal(err)
	}
	return pveClearanceFixture{service: service, executor: executor, parent: parent, child: child, privateKey: privateKey, now: &current}
}

func installOSPVEClearanceExecutor(t *testing.T, fixture pveClearanceFixture, runner *pveUnknownClearanceRunner) {
	t.Helper()
	operation, err := protocol.ParseStoredOperation(fixture.parent.Operation)
	if err != nil {
		t.Fatal(err)
	}
	executor := &OSExecutor{StateDir: t.TempDir(), Runner: runner, Policy: fixture.service.Policy}
	scope := executionScope(fixture.parent)
	intent, err := pvePrimaryIntent(scope, operation, ExecutionResult{})
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.persistPVETaskIntent(scope.ChangeID, "pve-primary-intent.json", intent); err != nil {
		t.Fatal(err)
	}
	fixture.service.Executor = executor
}

func pveClearancePolicy(t *testing.T) *targetpolicy.Policy {
	t.Helper()
	payload := fmt.Sprintf(`{"version":1,"revision":"policy-pve-12345678","targets":[{"id":"target-pve-root","account":"root","displayName":"PVE root","inspect":{"hostSnapshot":true,"processList":true,"units":[],"readPaths":[]},"changes":{"writePaths":[],"units":[],"packages":[],"plugins":[]},"pve":{"pluginId":"workload.pve","pluginDigest":"sha256:%s","nodes":["pve1"],"storages":["local"],"guests":[{"guestType":"qemu","vmid":100}],"migrationTargets":[],"operations":["pve.guest.start"]}}]}`, strings.Repeat("d", 64))
	policy, err := targetpolicy.Parse([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func parsePVEClearanceRemoteRequest(t *testing.T, now time.Time, requestID string, method protocol.Method, childID string, fields string) protocol.Request {
	t.Helper()
	extra := ""
	if fields != "" {
		extra = "," + fields
	}
	payload := fmt.Sprintf(`{"version":1,"requestId":%q,"deadline":%q,"method":%q,"serverId":"server-pve-12345678","machineId":"machine-pve-12345678","targetId":"target-pve-root","policyRevision":"policy-pve-12345678","capabilityRevision":%q,"callerRole":"approver","changeId":%q%s}`,
		requestID, now.Add(time.Minute).Format(time.RFC3339Nano), method, protocol.CapabilityRevision, childID, extra)
	request, err := protocol.ParseRequest([]byte(payload), now)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func (f pveClearanceFixture) prepareAndConfirm(t *testing.T, suffix string) (protocol.PVERecoveryClearanceChallenge, string) {
	t.Helper()
	peer := peercred.Credential{UID: f.service.AgentUID}
	prepared := f.service.Handle(context.Background(), peer, parsePVEClearanceRemoteRequest(
		t, *f.now, "clearance-prepare-"+suffix, protocol.MethodPVERecoveryClearancePrepare, f.child.ID, "",
	))
	result, ok := prepared.Data.(protocol.PVERecoveryClearancePrepareResult)
	if !prepared.OK || !ok || !result.Required || result.Challenge == nil {
		t.Fatalf("PVE clearance challenge failed: %#v", prepared)
	}
	challenge := *result.Challenge
	approval := signedPVERecoveryClearanceApproval(t, f.privateKey, *f.now, f.child, challenge, "clearance-nonce-"+suffix+"-1234567890")
	payload, err := json.Marshal(approval)
	if err != nil {
		t.Fatal(err)
	}
	confirmed := f.service.Handle(context.Background(), peer, parsePVEClearanceRemoteRequest(
		t, *f.now, "clearance-confirm-"+suffix, protocol.MethodPVERecoveryClearanceConfirm, f.child.ID,
		"\"clearanceApproval\":"+string(payload),
	))
	grant, ok := confirmed.Data.(protocol.PVERecoveryClearanceGrant)
	if !confirmed.OK || !ok || !protocol.ValidPVERecoveryClearanceToken(grant.ClearanceToken) {
		t.Fatalf("PVE clearance confirmation failed: %#v", confirmed)
	}
	return challenge, grant.ClearanceToken
}

func signedPVERecoveryClearanceApproval(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	now time.Time,
	child *Change,
	challenge protocol.PVERecoveryClearanceChallenge,
	nonce string,
) protocol.PVERecoveryClearanceApproval {
	t.Helper()
	approval := protocol.PVERecoveryClearanceApproval{
		Version: protocol.Version, KeyID: "approver-test-v1", Action: protocol.PVERecoveryClearanceAction,
		ServerID: child.ServerID, MachineID: child.MachineID, TargetID: child.TargetID,
		ClearanceID: challenge.ClearanceID, ParentChangeID: challenge.ParentChangeID,
		ChildChangeID: child.ID, ChildPlanHash: child.PlanHash, ResourceKey: child.ResourceKey,
		ChallengeDigest: challenge.ChallengeDigest, PolicyRevision: child.PolicyRevision,
		CapabilityRevision: child.CapabilityRevision,
		IssuedAt:           now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		Nonce: nonce,
	}
	payload, err := approval.ApprovalPayload()
	if err != nil {
		t.Fatal(err)
	}
	approval.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	if err := approval.ValidateShape(); err != nil {
		t.Fatal(err)
	}
	return approval
}

func signedPVEClearanceChangeGrant(t *testing.T, privateKey ed25519.PrivateKey, now time.Time, child *Change, nonce string) protocol.ApprovalGrant {
	t.Helper()
	grant := protocol.ApprovalGrant{
		Version: protocol.Version, KeyID: "approver-test-v1", Action: "approve",
		ServerID: child.ServerID, MachineID: child.MachineID, TargetID: child.TargetID,
		ChangeID: child.ID, PlanHash: child.PlanHash, PolicyRevision: child.PolicyRevision,
		CapabilityRevision: child.CapabilityRevision,
		IssuedAt:           now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		Nonce: nonce,
	}
	payload, err := grant.ApprovalPayload()
	if err != nil {
		t.Fatal(err)
	}
	grant.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return grant
}

func approvePVEClearanceChild(t *testing.T, fixture pveClearanceFixture, requestID, token, nonce string) protocol.Response {
	t.Helper()
	grant := signedPVEClearanceChangeGrant(t, fixture.privateKey, *fixture.now, fixture.child, nonce)
	payload, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	fields := fmt.Sprintf(`"approval":%s,"clearanceToken":%q`, payload, token)
	return fixture.service.Handle(context.Background(), peercred.Credential{UID: fixture.service.AgentUID}, parsePVEClearanceRemoteRequest(
		t, *fixture.now, requestID, protocol.MethodChangeApprove, fixture.child.ID, fields,
	))
}

func TestPVEUnknownClearanceTransfersOnceAndPreservesUnknownParentDisposition(t *testing.T) {
	fixture := newPVEClearanceFixture(t)
	challenge, token := fixture.prepareAndConfirm(t, "transfer")
	approved := approvePVEClearanceChild(t, fixture, "approve-clearance-transfer", token, "approve-clearance-transfer-nonce")
	if !approved.OK || approved.State != StateCommitted || fixture.executor.executions != 1 {
		t.Fatalf("confirmed PVE unknown clearance did not execute exactly once: response=%#v executions=%d", approved, fixture.executor.executions)
	}
	parent, _ := fixture.service.Store.Change(fixture.parent.ID)
	if parent.State != StateSuperseded || parent.MutationDisposition != protocol.PVEMutationDispositionUnknown || parent.Resolution == nil ||
		parent.Resolution.Basis != "local-unknown-clearance" || parent.Resolution.ParentChangeID != fixture.parent.ID ||
		parent.Resolution.ChildChangeID != fixture.child.ID || parent.Resolution.ChildPlanHash != fixture.child.PlanHash ||
		parent.Resolution.ResourceKey != fixture.child.ResourceKey ||
		parent.Resolution.ClearanceObservationDigest != challenge.Observation.ObservationDigest ||
		parent.Resolution.ActiveTaskDigest != challenge.Observation.ActiveTaskDigest ||
		parent.Resolution.GuestStateDigest != challenge.Observation.GuestStateDigest ||
		parent.Resolution.ClusterStateDigest != challenge.Observation.ClusterStateDigest {
		t.Fatalf("durable unknown-clearance resolution lost an exact binding: %#v", parent)
	}
	if len(fixture.service.Store.state.ResourceLocks) != 0 {
		t.Fatalf("committed clearance child retained the VMID lock: %#v", fixture.service.Store.state.ResourceLocks)
	}
	if err := fixture.service.validatePVERecoveryClearanceReference(fixture.child, token, *fixture.now); err == nil {
		t.Fatal("consumed PVE recovery clearance token remained reusable")
	}
}

func TestPVEUnknownClearanceRejectsNullActiveTaskListAtEveryObservation(t *testing.T) {
	prepareChallenge := func(t *testing.T, fixture pveClearanceFixture, suffix string) protocol.PVERecoveryClearanceChallenge {
		t.Helper()
		response := fixture.service.Handle(context.Background(), peercred.Credential{UID: fixture.service.AgentUID}, parsePVEClearanceRemoteRequest(
			t, *fixture.now, "clearance-prepare-null-active-"+suffix,
			protocol.MethodPVERecoveryClearancePrepare, fixture.child.ID, "",
		))
		result, ok := response.Data.(protocol.PVERecoveryClearancePrepareResult)
		if !response.OK || !ok || !result.Required || result.Challenge == nil {
			t.Fatalf("valid setup observation did not produce a challenge: %#v", response)
		}
		return *result.Challenge
	}

	t.Run("prepare", func(t *testing.T) {
		fixture := newPVEClearanceFixture(t)
		runner := &pveUnknownClearanceRunner{activeOutput: `null`}
		installOSPVEClearanceExecutor(t, fixture, runner)
		response := fixture.service.Handle(context.Background(), peercred.Credential{UID: fixture.service.AgentUID}, parsePVEClearanceRemoteRequest(
			t, *fixture.now, "clearance-prepare-null-active", protocol.MethodPVERecoveryClearancePrepare, fixture.child.ID, "",
		))
		if response.OK || !strings.Contains(response.Error, "non-null array") {
			t.Fatalf("prepare accepted null active-task inventory: %#v", response)
		}
	})

	t.Run("confirm", func(t *testing.T) {
		fixture := newPVEClearanceFixture(t)
		runner := &pveUnknownClearanceRunner{}
		installOSPVEClearanceExecutor(t, fixture, runner)
		challenge := prepareChallenge(t, fixture, "confirm")
		approval := signedPVERecoveryClearanceApproval(
			t, fixture.privateKey, *fixture.now, fixture.child, challenge,
			"clearance-null-active-confirm-nonce",
		)
		payload, err := json.Marshal(approval)
		if err != nil {
			t.Fatal(err)
		}
		runner.activeOutput = `null`
		response := fixture.service.Handle(context.Background(), peercred.Credential{UID: fixture.service.AgentUID}, parsePVEClearanceRemoteRequest(
			t, *fixture.now, "clearance-confirm-null-active", protocol.MethodPVERecoveryClearanceConfirm,
			fixture.child.ID, "\"clearanceApproval\":"+string(payload),
		))
		if response.OK || !strings.Contains(response.Error, "non-null array") {
			t.Fatalf("confirm accepted null active-task inventory: %#v", response)
		}
	})

	t.Run("final", func(t *testing.T) {
		fixture := newPVEClearanceFixture(t)
		runner := &pveUnknownClearanceRunner{}
		installOSPVEClearanceExecutor(t, fixture, runner)
		_, token := fixture.prepareAndConfirm(t, "null-active-final")
		runner.activeOutput = `null`
		response := approvePVEClearanceChild(
			t, fixture, "approve-clearance-null-active-final", token,
			"approve-clearance-null-active-final-nonce",
		)
		if response.OK || !strings.Contains(response.Error, "non-null array") {
			t.Fatalf("final observation accepted null active-task inventory: %#v", response)
		}
		parent, _ := fixture.service.Store.Change(fixture.parent.ID)
		child, _ := fixture.service.Store.Change(fixture.child.ID)
		if parent.State != StateRecoveryRequired || parent.Resolution != nil || child.State != StatePendingApproval ||
			fixture.service.Store.state.ResourceLocks[fixture.parent.ResourceKey] != fixture.parent.ID {
			t.Fatalf("null final observation partially transferred recovery chain: parent=%#v child=%#v locks=%#v", parent, child, fixture.service.Store.state.ResourceLocks)
		}
	})
}

func TestPVEUnknownClearanceTokenCannotCrossToAdminRole(t *testing.T) {
	fixture := newPVEClearanceFixture(t)
	_, token := fixture.prepareAndConfirm(t, "role")
	grant := signedPVEClearanceChangeGrant(t, fixture.privateKey, *fixture.now, fixture.child, "approve-clearance-role-nonce")
	payload, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	request := parsePVEClearanceRemoteRequest(
		t, *fixture.now, "approve-clearance-admin-role", protocol.MethodChangeApprove, fixture.child.ID,
		fmt.Sprintf(`"approval":%s,"clearanceToken":%q`, payload, token),
	)
	request.CallerRole = "admin"
	denied := fixture.service.Handle(
		context.Background(), peercred.Credential{UID: fixture.service.AgentUID}, request,
	)
	if denied.OK || !strings.Contains(denied.Error, "approver role") || fixture.executor.executions != 0 {
		t.Fatalf("admin role consumed a PVE unknown-clearance grant: response=%#v executions=%d", denied, fixture.executor.executions)
	}
	parent, _ := fixture.service.Store.Change(fixture.parent.ID)
	child, _ := fixture.service.Store.Change(fixture.child.ID)
	if parent.State != StateRecoveryRequired || child.State != StatePendingApproval ||
		fixture.service.Store.state.ResourceLocks[fixture.parent.ResourceKey] != fixture.parent.ID {
		t.Fatalf("admin clearance attempt changed durable chain: parent=%#v child=%#v locks=%#v", parent, child, fixture.service.Store.state.ResourceLocks)
	}
}

func TestPVEUnknownClearanceDriftRevokesGrantBeforeAtomicTransfer(t *testing.T) {
	fixture := newPVEClearanceFixture(t)
	_, token := fixture.prepareAndConfirm(t, "drift")
	fixture.executor.driftAt = fixture.executor.observeCalls + 1
	denied := approvePVEClearanceChild(t, fixture, "approve-clearance-drift", token, "approve-clearance-drift-nonce")
	if denied.OK || !strings.Contains(denied.Error, "observation changed") || fixture.executor.executions != 0 {
		t.Fatalf("drifted PVE state reached child execution: response=%#v executions=%d", denied, fixture.executor.executions)
	}
	parent, _ := fixture.service.Store.Change(fixture.parent.ID)
	child, _ := fixture.service.Store.Change(fixture.child.ID)
	if parent.State != StateRecoveryRequired || parent.Resolution != nil || child.State != StatePendingApproval ||
		fixture.service.Store.state.ResourceLocks[fixture.parent.ResourceKey] != fixture.parent.ID {
		t.Fatalf("failed clearance transfer changed durable chain: parent=%#v child=%#v locks=%#v", parent, child, fixture.service.Store.state.ResourceLocks)
	}
	if err := fixture.service.validatePVERecoveryClearanceReference(fixture.child, token, *fixture.now); err == nil {
		t.Fatal("state drift did not revoke the one-shot clearance")
	}
}

func TestPVEUnknownClearanceExpiresRevokesAndDoesNotSurviveRestart(t *testing.T) {
	t.Run("expiry", func(t *testing.T) {
		fixture := newPVEClearanceFixture(t)
		_, token := fixture.prepareAndConfirm(t, "expiry")
		*fixture.now = fixture.now.Add(2 * time.Minute)
		if err := fixture.service.validatePVERecoveryClearanceReference(fixture.child, token, *fixture.now); err == nil {
			t.Fatal("expired PVE recovery clearance remained valid")
		}
	})
	t.Run("restart", func(t *testing.T) {
		fixture := newPVEClearanceFixture(t)
		_, token := fixture.prepareAndConfirm(t, "restart")
		// A new broker process intentionally starts without any volatile
		// clearances. Construct a fresh Service instead of copying mutexes from
		// the old process representation.
		restarted := &Service{}
		if err := restarted.validatePVERecoveryClearanceReference(fixture.child, token, *fixture.now); err == nil {
			t.Fatal("volatile PVE recovery clearance survived broker restart")
		}
	})
	t.Run("reject", func(t *testing.T) {
		fixture := newPVEClearanceFixture(t)
		_, token := fixture.prepareAndConfirm(t, "reject")
		grant := signedPVEClearanceChangeGrant(t, fixture.privateKey, *fixture.now, fixture.child, "reject-clearance-grant-nonce")
		grant.Action = "reject"
		payload, err := grant.ApprovalPayload()
		if err != nil {
			t.Fatal(err)
		}
		grant.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(fixture.privateKey, payload))
		encoded, _ := json.Marshal(grant)
		rejected := fixture.service.Handle(context.Background(), peercred.Credential{UID: fixture.service.AgentUID}, parsePVEClearanceRemoteRequest(
			t, *fixture.now, "reject-clearance-child", protocol.MethodChangeReject, fixture.child.ID, "\"approval\":"+string(encoded),
		))
		if !rejected.OK || rejected.State != StateRejected {
			t.Fatalf("reject PVE recovery child failed: %#v", rejected)
		}
		if err := fixture.service.validatePVERecoveryClearanceReference(fixture.child, token, *fixture.now); err == nil {
			t.Fatal("rejecting recovery child did not revoke its clearance")
		}
	})
}

func TestPVEUnknownClearanceCannotCrossChildPlanOrResource(t *testing.T) {
	fixture := newPVEClearanceFixture(t)
	_, token := fixture.prepareAndConfirm(t, "binding")
	for name, mutate := range map[string]func(*Change){
		"child":    func(change *Change) { change.ID = "pve-change-other-clearance-child" },
		"plan":     func(change *Change) { change.PlanHash = "sha256:" + strings.Repeat("a", 64) },
		"resource": func(change *Change) { change.ResourceKey = "pve/vmid/101" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneChange(fixture.child)
			mutate(candidate)
			if err := fixture.service.validatePVERecoveryClearanceReference(candidate, token, *fixture.now); err == nil {
				t.Fatalf("clearance token crossed %s binding", name)
			}
		})
	}
}

func TestPVEUnknownClearanceConcurrentRevocationFailsClosedWithoutTransfer(t *testing.T) {
	fixture := newPVEClearanceFixture(t)
	_, token := fixture.prepareAndConfirm(t, "concurrent-revoke")
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	fixture.executor.blockAt = fixture.executor.observeCalls + 1
	fixture.executor.observeStarted = started
	fixture.executor.observeRelease = release
	grant := signedPVEClearanceChangeGrant(t, fixture.privateKey, *fixture.now, fixture.child, "approve-clearance-concurrent-nonce")
	payload, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	request := parsePVEClearanceRemoteRequest(
		t, *fixture.now, "approve-clearance-concurrent-revoke", protocol.MethodChangeApprove, fixture.child.ID,
		fmt.Sprintf(`"approval":%s,"clearanceToken":%q`, payload, token),
	)
	response := make(chan protocol.Response, 1)
	go func() {
		response <- fixture.service.Handle(context.Background(), peercred.Credential{UID: fixture.service.AgentUID}, request)
	}()
	<-started
	fixture.service.revokePVERecoveryClearances(fixture.child.ID)
	close(release)
	denied := <-response
	if denied.OK || (!strings.Contains(denied.Error, "revoked") && !strings.Contains(denied.Error, "expired")) || fixture.executor.executions != 0 {
		t.Fatalf("concurrent clearance revocation did not fail closed: response=%#v executions=%d", denied, fixture.executor.executions)
	}
	parent, _ := fixture.service.Store.Change(fixture.parent.ID)
	child, _ := fixture.service.Store.Change(fixture.child.ID)
	if parent.State != StateRecoveryRequired || parent.Resolution != nil || child.State != StatePendingApproval ||
		fixture.service.Store.state.ResourceLocks[fixture.parent.ResourceKey] != fixture.parent.ID {
		t.Fatalf("concurrent revocation partially transferred recovery chain: parent=%#v child=%#v locks=%#v", parent, child, fixture.service.Store.state.ResourceLocks)
	}
}
