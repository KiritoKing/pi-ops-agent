package approvalsubmit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/pluginregistry"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

const testPVEPluginID = "workload.pve"

var testNow = time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)

type fakeRemote struct {
	plans                 []protocol.ApprovalPlan
	recoveryStatus        *statusWire
	scope                 Request
	state                 string
	actionState           string
	rollback              bool
	statusCalls           int
	actionCalls           int
	grant                 protocol.ApprovalGrant
	receiptPrivateKey     ed25519.PrivateKey
	mutateStatus          func(HelperResponse) HelperResponse
	mutateAction          func(HelperResponse) HelperResponse
	recoveryParentID      string
	clearanceRequired     bool
	clearanceChallenge    *protocol.PVERecoveryClearanceChallenge
	clearancePrepareCalls int
	clearanceConfirmCalls int
	clearanceActionToken  string
	clearanceApproval     protocol.PVERecoveryClearanceApproval
	clearanceConfirmError string
}

func (f *fakeRemote) Status(_ context.Context, _ Request, requestID string, _ time.Time) (HelperResponse, error) {
	index := f.statusCalls
	f.statusCalls++
	if f.recoveryStatus != nil {
		data, _ := json.Marshal(f.recoveryStatus)
		response := HelperResponse{
			Version: 1, RequestID: requestID, OK: true, ChangeID: f.scope.ChangeID,
			AuditID: "audit-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			State:   f.state, Summary: "authoritative recovery-only status", Data: data,
		}
		response = signFakeBrokerResponse(response, f.scope, protocol.MethodChangeStatus, f.recoveryStatus.PlanHash, f.receiptPrivateKey)
		if f.mutateStatus != nil {
			response = f.mutateStatus(response)
		}
		return response, nil
	}
	if index >= len(f.plans) {
		return HelperResponse{}, errors.New("unexpected status call")
	}
	response := makeStatusResponse(requestID, f.scope, f.plans[index], f.state, f.rollback)
	if f.recoveryParentID != "" {
		var wire statusWire
		if err := json.Unmarshal(response.Data, &wire); err != nil {
			return HelperResponse{}, err
		}
		wire.RecoveryOfChangeID = f.recoveryParentID
		wire.PVEMutationVersion = 1
		response.Data, _ = json.Marshal(wire)
	}
	response = signFakeBrokerResponse(response, f.scope, protocol.MethodChangeStatus, f.plans[index].PlanHash, f.receiptPrivateKey)
	if f.mutateStatus != nil {
		response = f.mutateStatus(response)
	}
	return response, nil
}

func (f *fakeRemote) PreparePVERecoveryClearance(_ context.Context, request Request, requestID string, _ time.Time) (HelperResponse, error) {
	f.clearancePrepareCalls++
	result := protocol.PVERecoveryClearancePrepareResult{Kind: "pve.recovery-clearance-prepare-result/v1", Required: f.clearanceRequired}
	if f.clearanceRequired {
		if f.clearanceChallenge == nil {
			return HelperResponse{}, errors.New("test clearance challenge is missing")
		}
		challenge := *f.clearanceChallenge
		result.Challenge = &challenge
	}
	data, _ := json.Marshal(result)
	response := HelperResponse{
		Version: protocol.Version, RequestID: requestID, OK: true,
		AuditID: "audit-cccccccccccccccccccccccccccccccc", ChangeID: request.ChangeID,
		State: "PENDING_APPROVAL", Data: data,
	}
	return signFakeBrokerResponse(response, f.scope, protocol.MethodPVERecoveryClearancePrepare, f.plans[0].PlanHash, f.receiptPrivateKey), nil
}

func (f *fakeRemote) ConfirmPVERecoveryClearance(_ context.Context, request Request, requestID string, _ time.Time, approval protocol.PVERecoveryClearanceApproval) (HelperResponse, error) {
	f.clearanceConfirmCalls++
	f.clearanceApproval = approval
	response := HelperResponse{
		Version: protocol.Version, RequestID: requestID, OK: f.clearanceConfirmError == "",
		AuditID: "audit-dddddddddddddddddddddddddddddddd", ChangeID: request.ChangeID,
		State: "PENDING_APPROVAL", Error: f.clearanceConfirmError,
	}
	if response.OK {
		grant := protocol.PVERecoveryClearanceGrant{
			Kind: "pve.recovery-clearance-grant/v1", ClearanceToken: "pve-clearance-fedcba9876543210fedcba9876543210",
			ChallengeDigest: f.clearanceChallenge.ChallengeDigest, ExpiresAt: f.clearanceChallenge.ExpiresAt,
		}
		response.Data, _ = json.Marshal(grant)
	}
	return signFakeBrokerResponse(response, f.scope, protocol.MethodPVERecoveryClearanceConfirm, f.plans[0].PlanHash, f.receiptPrivateKey), nil
}

func (f *fakeRemote) ActionWithPVERecoveryClearance(ctx context.Context, request Request, requestID string, deadline time.Time, grant protocol.ApprovalGrant, token string) (HelperResponse, error) {
	f.clearanceActionToken = token
	return f.Action(ctx, request, requestID, deadline, grant)
}

func (f *fakeRemote) Action(_ context.Context, request Request, requestID string, _ time.Time, grant protocol.ApprovalGrant) (HelperResponse, error) {
	f.actionCalls++
	f.grant = grant
	state := "COMMITTED"
	if f.actionState != "" {
		state = f.actionState
	}
	if request.Action == ActionReject {
		state = "REJECTED"
	} else if request.Action == ActionRollback {
		state = "ROLLED_BACK"
	}
	response := HelperResponse{
		Version: 1, RequestID: requestID, OK: true,
		AuditID:  "audit-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ChangeID: request.ChangeID, State: state,
	}
	response = signFakeBrokerResponse(response, f.scope, actionMethod(request.Action), grant.PlanHash, f.receiptPrivateKey)
	if f.mutateAction != nil {
		response = f.mutateAction(response)
	}
	return response, nil
}

type fakeConfirmer struct {
	err          error
	plan         []byte
	confirmation string
	calls        int
}

type sequenceConfirmer struct {
	plans         [][]byte
	confirmations []string
	onConfirm     func(int)
	errAt         int
}

func (f *sequenceConfirmer) Confirm(plan []byte, confirmation string) error {
	f.plans = append(f.plans, append([]byte(nil), plan...))
	f.confirmations = append(f.confirmations, confirmation)
	call := len(f.confirmations)
	if f.onConfirm != nil {
		f.onConfirm(call)
	}
	if f.errAt == call {
		return errors.New("injected exact confirmation failure")
	}
	return nil
}

type fakeApprovalReviewer struct {
	review  ApprovalReview
	err     error
	request ApprovalReviewRequest
	calls   int
}

func (f *fakeApprovalReviewer) Review(_ context.Context, request ApprovalReviewRequest) (ApprovalReview, error) {
	f.calls++
	f.request = request
	if f.err != nil {
		return ApprovalReview{}, f.err
	}
	if f.review.Version == 0 {
		return manualReview(request), nil
	}
	return f.review, nil
}

func (f *fakeConfirmer) Confirm(plan []byte, confirmation string) error {
	f.calls++
	f.plan = append([]byte(nil), plan...)
	f.confirmation = confirmation
	return f.err
}

func TestParseArgsAllowsOnlyFixedSelectors(t *testing.T) {
	request := testRequest(ActionApprove)
	parsed, err := ParseArgs([]string{
		"--action", "approve", "--server-id", request.ServerID, "--machine-id", request.MachineID,
		"--target-id", request.TargetID, "--change-id", request.ChangeID,
		"--user-intent-b64", base64.RawURLEncoding.EncodeToString([]byte(request.UserIntent)),
	})
	if err != nil || parsed != request {
		t.Fatalf("parse fixed args: request=%#v err=%v", parsed, err)
	}
	_, err = ParseArgs([]string{
		"--action", "approve", "--server-id", request.ServerID, "--machine-id", request.MachineID,
		"--target-id", request.TargetID, "--change-id", request.ChangeID,
		"--url", "https://attacker.invalid",
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unexpected URL selector was accepted: %v", err)
	}
}

func TestParseArgsRejectsNonCanonicalOrOversizedIntent(t *testing.T) {
	request := testRequest(ActionApprove)
	base := []string{
		"--action", "approve", "--server-id", request.ServerID, "--machine-id", request.MachineID,
		"--target-id", request.TargetID, "--change-id", request.ChangeID,
	}
	for _, encoded := range []string{
		base64.URLEncoding.EncodeToString([]byte("intent with padding")),
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{'x'}, MaxUserIntentBytes+1)),
	} {
		if _, err := ParseArgs(append(append([]string(nil), base...), "--user-intent-b64", encoded)); err == nil {
			t.Fatalf("invalid user intent encoding was accepted: %q", encoded[:16])
		}
	}
}

func TestStrictDecodeRejectsDuplicateFields(t *testing.T) {
	payload := []byte(`{"version":1,"version":1,"servers":[]}`)
	if _, err := parseRegistry(payload); err == nil || !strings.Contains(err.Error(), "duplicate JSON field") {
		t.Fatalf("registry accepted a duplicate JSON field: %v", err)
	}
}

func TestParseStatusAcceptsBoundStandingAuthorizationMetadata(t *testing.T) {
	request := testRequest(ActionRollback)
	plan := testPlan("nginx")
	response := makeStatusResponse("approval-status-standing", request, plan, "COMMITTED", true)
	var data map[string]interface{}
	if err := json.Unmarshal(response.Data, &data); err != nil {
		t.Fatal(err)
	}
	data["authorizationBasis"] = "standing-policy:policy-12345678:service.action"
	data["authorizationScope"] = "service.action"
	data["authorizedAt"] = "2026-08-08T00:00:00Z"
	response.Data, _ = json.Marshal(data)
	status, err := parseStatus(response, request)
	if err != nil {
		t.Fatal(err)
	}
	if status.AuthorizationScope != "service.action" ||
		status.AuthorizationBasis != "standing-policy:policy-12345678:service.action" {
		t.Fatalf("standing authorization metadata was lost: %#v", status)
	}

	data["authorizedAt"] = "not-a-time"
	response.Data, _ = json.Marshal(data)
	if _, err := parseStatus(response, request); err == nil {
		t.Fatal("invalid standing authorization time was accepted")
	}
}

func TestParseStatusBindsPVETerminalRecoveryEvidence(t *testing.T) {
	request := Request{
		Action: ActionReject, ServerID: "server-pve-12345678", MachineID: "machine-pve-12345678",
		TargetID: "target-pve-root", ChangeID: "pve-change-0123456789abcdef0123456789abcdef",
		UserIntent: "inspect the resolved PVE recovery parent",
	}
	operation := &protocol.PVEGuestAction{
		OperationKind: "pve.guest.action", PluginID: testPVEPluginID,
		PluginDigest: "sha256:" + strings.Repeat("a", 64), Node: "pve1",
		GuestType: "qemu", VMID: 100, Action: "start",
	}
	plan, err := protocol.BuildApprovalPlan(operation, "policy-pve-12345678", protocol.CapabilityRevision)
	if err != nil {
		t.Fatal(err)
	}
	planPayload, _ := json.Marshal(plan)
	rollback := false
	recoveryOnly := false
	upid := "UPID:pve1:00000001:00000002:00000003:qmstart:100:root@pam:"
	wire := statusWire{
		ServerID: request.ServerID, MachineID: request.MachineID, TargetID: request.TargetID,
		PolicyRevision: plan.PolicyRevision, CapabilityRevision: plan.CapabilityRevision,
		PlanHash: plan.PlanHash, Kind: operation.Kind(), BackupRefs: []string{"pve:task:" + upid},
		RollbackAvailable: &rollback, RecoveryOnly: &recoveryOnly, Plan: planPayload,
		PVEMutationVersion: 1, MutationDisposition: protocol.PVEMutationDispositionTasksTerminal,
		Resolution: &protocol.PVERecoveryResolution{
			Kind:                      "pve.recovery-transfer/v1",
			ChildChangeID:             "pve-change-fedcba9876543210fedcba9876543210",
			ChildPlanHash:             "sha256:" + strings.Repeat("b", 64),
			TransferredAt:             "2026-08-08T00:00:00Z",
			ParentMutationDisposition: protocol.PVEMutationDispositionTasksTerminal,
			ParentTaskEvidence: []protocol.PVERecoveryTaskEvidence{{
				Role: "primary", Node: "pve1", UPID: upid, Status: "stopped",
				ExitStatus: "ERROR", ObservedAt: "2026-08-08T00:00:00Z",
			}},
		},
	}
	data, _ := json.Marshal(wire)
	response := HelperResponse{
		Version: 1, RequestID: "pve-status-recovery", OK: true, ChangeID: request.ChangeID,
		State: "SUPERSEDED", Summary: "resolved PVE recovery parent", Data: data,
	}
	status, err := parseStatus(response, request)
	if err != nil || status.MutationDisposition != protocol.PVEMutationDispositionTasksTerminal ||
		status.Resolution == nil || status.Resolution.ParentTaskEvidence[0].ExitStatus != "ERROR" {
		t.Fatalf("valid PVE terminal recovery evidence was rejected: status=%#v err=%v", status, err)
	}
	wire.MutationDisposition = protocol.PVEMutationDispositionUnknown
	response.Data, _ = json.Marshal(wire)
	if _, err := parseStatus(response, request); err == nil || !strings.Contains(err.Error(), "does not bind") {
		t.Fatalf("mismatched PVE mutation disposition was accepted: %v", err)
	}
}

func TestSubmitRejectsNonRootAndWrongAuthoritativeIdentity(t *testing.T) {
	request := testRequest(ActionApprove)
	loadCalls := 0
	submitter := Submitter{
		EffectiveUID: func() int { return 1000 },
		LoadServer: func(Request) (LoadedServer, error) {
			loadCalls++
			return LoadedServer{}, nil
		},
	}
	if _, err := submitter.Submit(context.Background(), request); err == nil || loadCalls != 0 {
		t.Fatalf("non-root identity reached credential loading: calls=%d err=%v", loadCalls, err)
	}

	privateKey := testPrivateKey(t)
	remote := &fakeRemote{
		plans: []protocol.ApprovalPlan{testPlan("nginx")},
		scope: Request{Action: request.Action, ServerID: request.ServerID, MachineID: "machine-wrong000", TargetID: request.TargetID, ChangeID: request.ChangeID},
		state: "PENDING_APPROVAL",
	}
	confirmer := &fakeConfirmer{}
	submitter = testSubmitter(request, remote, confirmer, privateKey)
	if _, err := submitter.Submit(context.Background(), request); err == nil || !strings.Contains(err.Error(), "scope") {
		t.Fatalf("wrong authoritative identity was accepted: %v", err)
	}
	if confirmer.calls != 0 || remote.actionCalls != 0 {
		t.Fatal("wrong identity reached human confirmation or action")
	}
}

func TestSubmitStopsWhenExactConfirmationIsMissing(t *testing.T) {
	request := testRequest(ActionApprove)
	privateKey := testPrivateKey(t)
	remote := &fakeRemote{plans: []protocol.ApprovalPlan{testPlan("nginx")}, scope: request, state: "PENDING_APPROVAL"}
	confirmer := &fakeConfirmer{err: errors.New("confirmation did not match")}
	signingLoads := 0
	submitter := testSubmitter(request, remote, confirmer, privateKey)
	originalLoad := submitter.LoadServer
	submitter.LoadServer = func(request Request) (LoadedServer, error) {
		server, err := originalLoad(request)
		server.SigningKey = func() (ed25519.PrivateKey, error) {
			signingLoads++
			return privateKey, nil
		}
		return server, err
	}
	if _, err := submitter.Submit(context.Background(), request); err == nil || !strings.Contains(err.Error(), "confirmation") {
		t.Fatalf("missing confirmation was accepted: %v", err)
	}
	if remote.statusCalls != 1 || remote.actionCalls != 0 || signingLoads != 0 {
		t.Fatalf("confirmation failure crossed the signing boundary: status=%d action=%d signing=%d", remote.statusCalls, remote.actionCalls, signingLoads)
	}
}

func TestSubmitFailsClosedOnIndependentReviewerDecisionOrBindingMismatch(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(ApprovalReview) ApprovalReview
		want   string
	}{
		{
			name: "reject", want: "rejected",
			mutate: func(review ApprovalReview) ApprovalReview {
				review.Recommendation = ReviewReject
				review.ReviewDigest, _ = approvalReviewDigest(review)
				return review
			},
		},
		{
			name: "split", want: "split",
			mutate: func(review ApprovalReview) ApprovalReview {
				review.Recommendation = ReviewSplitRequired
				review.ReviewDigest, _ = approvalReviewDigest(review)
				return review
			},
		},
		{
			name: "plan mismatch", want: "exact request",
			mutate: func(review ApprovalReview) ApprovalReview {
				review.PlanHash = "sha256:" + strings.Repeat("f", 64)
				review.ReviewDigest, _ = approvalReviewDigest(review)
				return review
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := testRequest(ActionApprove)
			plan := testPlan("nginx")
			remote := &fakeRemote{plans: []protocol.ApprovalPlan{plan}, scope: request, state: "PENDING_APPROVAL"}
			confirmer := &fakeConfirmer{}
			reviewRequest := ApprovalReviewRequest{
				Version: 1, ReviewID: "review-5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
				UserIntent: request.UserIntent, Plan: plan,
			}
			reviewer := &fakeApprovalReviewer{review: test.mutate(manualReview(reviewRequest))}
			submitter := testSubmitter(request, remote, confirmer, testPrivateKey(t))
			submitter.Reviewer = reviewer
			if _, err := submitter.Submit(context.Background(), request); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("reviewer result crossed the root boundary: %v", err)
			}
			if confirmer.calls != 0 || remote.actionCalls != 0 {
				t.Fatal("invalid review reached TTY confirmation or the action endpoint")
			}
		})
	}
}

func TestRejectSkipsReviewerButKeepsRootTTYConfirmation(t *testing.T) {
	request := testRequest(ActionReject)
	plan := testPlan("nginx")
	remote := &fakeRemote{plans: []protocol.ApprovalPlan{plan, plan}, scope: request, state: "PENDING_APPROVAL"}
	confirmer := &fakeConfirmer{}
	reviewer := &fakeApprovalReviewer{err: errors.New("must not be called")}
	submitter := testSubmitter(request, remote, confirmer, testPrivateKey(t))
	submitter.Reviewer = reviewer
	result, err := submitter.Submit(context.Background(), request)
	if err != nil || result.State != "REJECTED" || reviewer.calls != 0 || confirmer.calls != 1 {
		t.Fatalf("reject path changed unexpectedly: result=%#v review=%d confirm=%d err=%v", result, reviewer.calls, confirmer.calls, err)
	}
}

func TestRecoveryOnlyStatusPermitsRejectOrRollbackButNeverApprove(t *testing.T) {
	for _, action := range []Action{ActionReject, ActionRollback} {
		request := testRequest(action)
		state := "PENDING_APPROVAL"
		rollback := false
		if action == ActionRollback {
			state, rollback = "RECOVERY_REQUIRED", true
		}
		response := makeRecoveryStatusResponse("approval-status-recovery", request, state, rollback)
		status, err := parseStatus(response, request)
		if err != nil || !status.RecoveryOnly || status.Plan != nil {
			t.Fatalf("%s recovery-only status was rejected: status=%#v err=%v", action, status, err)
		}
	}

	request := testRequest(ActionApprove)
	response := makeRecoveryStatusResponse("approval-status-recovery", request, "PENDING_APPROVAL", false)
	if _, err := parseStatus(response, request); err == nil || !strings.Contains(err.Error(), "cannot be approved") {
		t.Fatalf("recovery-only approve was accepted: %v", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(response.Data, &data); err != nil {
		t.Fatal(err)
	}
	data["recoveryOnly"] = false
	response.Data, _ = json.Marshal(data)
	if _, err := parseStatus(response, testRequest(ActionReject)); err == nil || !strings.Contains(err.Error(), "ApprovalPlan") {
		t.Fatalf("planless non-recovery status was accepted: %v", err)
	}
	delete(data, "recoveryOnly")
	response.Data, _ = json.Marshal(data)
	if _, err := parseStatus(response, testRequest(ActionReject)); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("status without an explicit recovery-only marker was accepted: %v", err)
	}
	data["recoveryOnly"] = true
	data["plan"] = testPlan("substituted-plan")
	response.Data, _ = json.Marshal(data)
	if _, err := parseStatus(response, testRequest(ActionReject)); err == nil || !strings.Contains(err.Error(), "unexpectedly contains") {
		t.Fatalf("recovery-only status with a live plan was accepted: %v", err)
	}
	tampered := makeRecoveryStatusResponse("approval-status-recovery", testRequest(ActionReject), "PENDING_APPROVAL", false)
	if err := json.Unmarshal(tampered.Data, &data); err != nil {
		t.Fatal(err)
	}
	delete(data, "plan")
	delete(data, "recoveryDescriptor")
	tampered.Data, _ = json.Marshal(data)
	if _, err := parseStatus(tampered, testRequest(ActionReject)); err == nil || !strings.Contains(err.Error(), "recovery descriptor") {
		t.Fatalf("recovery-only status without a signed descriptor was accepted: %v", err)
	}
}

func TestRecoveryOnlyRollbackSkipsReviewerButKeepsSignedStatusAndRootTTYBinding(t *testing.T) {
	request := testRequest(ActionRollback)
	rollback := true
	remote := &fakeRemote{
		recoveryStatus: recoveryStatusWire(request, rollback), scope: request,
		state: "RECOVERY_REQUIRED", rollback: rollback,
	}
	confirmer := &fakeConfirmer{}
	reviewer := &fakeApprovalReviewer{err: errors.New("legacy recovery has no canonical plan")}
	submitter := testSubmitter(request, remote, confirmer, testPrivateKey(t))
	submitter.Reviewer = reviewer
	result, err := submitter.Submit(context.Background(), request)
	if err != nil || !result.OK || result.State != "ROLLED_BACK" {
		t.Fatalf("recovery-only rollback failed: result=%#v err=%v", result, err)
	}
	if reviewer.calls != 0 || confirmer.calls != 1 || remote.statusCalls != 2 || remote.actionCalls != 1 {
		t.Fatalf("unexpected recovery boundary calls: reviewer=%d confirmer=%d status=%d action=%d", reviewer.calls, confirmer.calls, remote.statusCalls, remote.actionCalls)
	}
	if !bytes.Contains(confirmer.plan, []byte(`"recoveryOnly": true`)) ||
		!bytes.Contains(confirmer.plan, []byte("LEGACY RECOVERY ONLY")) ||
		!bytes.Contains(confirmer.plan, []byte(`"recoveryDescriptor"`)) ||
		!bytes.Contains(confirmer.plan, []byte(`"rollbackDataDigest"`)) ||
		!bytes.Contains(confirmer.plan, []byte(`"compensationAction": "service.stop"`)) ||
		!bytes.Contains(confirmer.plan, []byte(`"summary": "authoritative recovery-only status"`)) ||
		!bytes.Contains(confirmer.plan, []byte(request.ChangeID)) ||
		remote.grant.PlanHash != remote.recoveryStatus.PlanHash ||
		confirmer.confirmation != ConfirmationText(request, remote.recoveryStatus.PlanHash) {
		t.Fatalf("recovery-only display or grant lost authoritative binding: display=%s grant=%#v confirmation=%q", confirmer.plan, remote.grant, confirmer.confirmation)
	}
}

func TestRecoveryOnlyRejectSkipsReviewerButStillRequiresRootTTY(t *testing.T) {
	request := testRequest(ActionReject)
	rollback := false
	remote := &fakeRemote{
		recoveryStatus: recoveryStatusWire(request, rollback), scope: request,
		state: "PENDING_APPROVAL", rollback: rollback,
	}
	confirmer := &fakeConfirmer{}
	reviewer := &fakeApprovalReviewer{err: errors.New("must not be called")}
	submitter := testSubmitter(request, remote, confirmer, testPrivateKey(t))
	submitter.Reviewer = reviewer
	result, err := submitter.Submit(context.Background(), request)
	if err != nil || result.State != "REJECTED" || reviewer.calls != 0 || confirmer.calls != 1 {
		t.Fatalf("recovery-only reject path failed: result=%#v review=%d confirm=%d err=%v", result, reviewer.calls, confirmer.calls, err)
	}
}

func TestUnixApprovalReviewerUsesOneStrictBoundFrame(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	serverError := make(chan error, 1)
	go func() {
		defer server.Close()
		payload, readErr := protocol.ReadFrame(server)
		if readErr != nil {
			serverError <- readErr
			return
		}
		var request ApprovalReviewRequest
		if decodeErr := strictDecode(payload, &request); decodeErr != nil {
			serverError <- decodeErr
			return
		}
		response, marshalErr := json.Marshal(struct {
			OK     bool           `json:"ok"`
			Review ApprovalReview `json:"review"`
		}{OK: true, Review: manualReview(request)})
		if marshalErr != nil {
			serverError <- marshalErr
			return
		}
		serverError <- protocol.WriteFrame(server, response)
	}()
	request := ApprovalReviewRequest{
		Version: 1, ReviewID: "review-12345678123456781234567812345678",
		UserIntent: "restart only after checking health", Plan: testPlan("nginx"),
	}
	review, err := (UnixApprovalReviewer{
		Timeout:     2 * time.Second,
		DialContext: func(context.Context, string, string) (net.Conn, error) { return client, nil },
	}).Review(context.Background(), request)
	if err != nil || review.PlanHash != request.Plan.PlanHash || review.UserIntentDigest == "" {
		t.Fatalf("strict framed reviewer call failed: review=%#v err=%v", review, err)
	}
	if err := <-serverError; err != nil {
		t.Fatal(err)
	}
}

func TestReviewerCanonicalDigestMatchesTypeScriptVectors(t *testing.T) {
	for _, test := range []struct {
		intent string
		want   string
	}{
		{
			intent: "restart only after checking health",
			want:   "sha256:99b26d62bfaed8a0f1b639782e2c2961fcbca7cd5ad88383ce39a9136caedfe4",
		},
		{
			intent: "审查 <x>&\u2028line\n",
			want:   "sha256:29c9ade2db09cfbebbbb39ab2fb5ccf454065034f972fafb56e9674a43897315",
		},
	} {
		got, err := canonicalDigest(map[string]any{"userIntent": test.intent})
		if err != nil || got != test.want {
			t.Fatalf("cross-language user-intent digest mismatch: got=%s want=%s err=%v", got, test.want, err)
		}
	}
	review := ApprovalReview{
		Version: 1, ReviewID: "review-12345678123456781234567812345678",
		PlanHash:         "sha256:" + strings.Repeat("a", 64),
		UserIntentDigest: "sha256:99b26d62bfaed8a0f1b639782e2c2961fcbca7cd5ad88383ce39a9136caedfe4",
		MinimumRisk:      "high", Risk: "high", Recommendation: ReviewManual,
		CanAuthorize: false, Findings: []ApprovalReviewFinding{},
		Explanation: "Manual review is required and this reviewer cannot authorize the change.",
	}
	if got, err := approvalReviewDigest(review); err != nil || got != "sha256:f360301742d9af37740c39f68bc73f0031f54e88ce10c540db7f469edbf13cdc" {
		t.Fatalf("cross-language review digest mismatch: got=%s err=%v", got, err)
	}
}

func TestReviewerResponseRejectsUnknownFieldsAndDigestTamper(t *testing.T) {
	request := ApprovalReviewRequest{
		Version: 1, ReviewID: "review-12345678123456781234567812345678",
		UserIntent: "restart only after checking health", Plan: testPlan("nginx"),
	}
	review := manualReview(request)
	reviewPayload, err := json.Marshal(review)
	if err != nil {
		t.Fatal(err)
	}
	unknown := []byte(`{"ok":true,"review":` + strings.TrimSuffix(string(reviewPayload), "}") + `,"command":"sh"}}`)
	if _, err := parseReviewerResponse(unknown, request); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("reviewer response accepted an unknown field: %v", err)
	}
	review.ReviewDigest = "sha256:" + strings.Repeat("0", 64)
	tampered, _ := json.Marshal(struct {
		OK     bool           `json:"ok"`
		Review ApprovalReview `json:"review"`
	}{OK: true, Review: review})
	if _, err := parseReviewerResponse(tampered, request); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("reviewer response accepted digest tampering: %v", err)
	}
}

func TestSubmitRejectsApprovalPlanDrift(t *testing.T) {
	request := testRequest(ActionApprove)
	first := testPlan("nginx")
	second := testPlan("openssh-server")
	// A compromised presentation layer changing fields while retaining the
	// advertised planHash must still be detected before the key is loaded.
	second.PlanHash = first.PlanHash
	remote := &fakeRemote{plans: []protocol.ApprovalPlan{first, second}, scope: request, state: "PENDING_APPROVAL"}
	confirmer := &fakeConfirmer{}
	signingLoads := 0
	submitter := testSubmitter(request, remote, confirmer, testPrivateKey(t))
	originalLoad := submitter.LoadServer
	submitter.LoadServer = func(request Request) (LoadedServer, error) {
		server, err := originalLoad(request)
		server.SigningKey = func() (ed25519.PrivateKey, error) {
			signingLoads++
			return testPrivateKey(t), nil
		}
		return server, err
	}
	if _, err := submitter.Submit(context.Background(), request); err == nil ||
		(!strings.Contains(err.Error(), "drifted") && !strings.Contains(err.Error(), "displayed fields")) {
		t.Fatalf("plan drift was accepted: %v", err)
	}
	if remote.statusCalls != 2 || remote.actionCalls != 0 || signingLoads != 0 {
		t.Fatalf("plan drift crossed signing boundary: status=%d action=%d signing=%d", remote.statusCalls, remote.actionCalls, signingLoads)
	}
}

func TestSubmitRejectsStableServerPlanSubstitution(t *testing.T) {
	request := testRequest(ActionApprove)
	authoritative := testPlan("dangerous-package")
	substituted := testPlan("harmless-package")
	substituted.PlanHash = authoritative.PlanHash
	remote := &fakeRemote{
		plans: []protocol.ApprovalPlan{substituted, substituted},
		scope: request, state: "PENDING_APPROVAL",
	}
	confirmer := &fakeConfirmer{}
	submitter := testSubmitter(request, remote, confirmer, testPrivateKey(t))
	if _, err := submitter.Submit(context.Background(), request); err == nil ||
		!strings.Contains(err.Error(), "displayed fields") {
		t.Fatalf("stable server plan substitution was accepted: %v", err)
	}
	if confirmer.calls != 0 || remote.actionCalls != 0 {
		t.Fatal("server plan substitution reached human confirmation or the signing boundary")
	}
}

func TestSubmitRejectsUnsignedOrTamperedPreReviewStatus(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(HelperResponse) HelperResponse
	}{
		{
			name: "unsigned",
			mutate: func(response HelperResponse) HelperResponse {
				response.Receipt = nil
				return response
			},
		},
		{
			name: "result substitution",
			mutate: func(response HelperResponse) HelperResponse {
				response.Summary = "server-fabricated safe summary"
				return response
			},
		},
		{
			name: "method substitution",
			mutate: func(response HelperResponse) HelperResponse {
				receipt := *response.Receipt
				receipt.Method = protocol.MethodChangeApprove
				receipt.Action = "approve"
				response.Receipt = &receipt
				return response
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := testRequest(ActionApprove)
			remote := &fakeRemote{
				plans: []protocol.ApprovalPlan{testPlan("nginx")}, scope: request,
				state: "PENDING_APPROVAL", mutateStatus: test.mutate,
			}
			confirmer := &fakeConfirmer{}
			reviewer := &fakeApprovalReviewer{}
			submitter := testSubmitter(request, remote, confirmer, testPrivateKey(t))
			submitter.Reviewer = reviewer
			if _, err := submitter.Submit(context.Background(), request); err == nil ||
				(!strings.Contains(err.Error(), "receipt") && !strings.Contains(err.Error(), "digest")) {
				t.Fatalf("untrusted pre-review status was accepted: %v", err)
			}
			if reviewer.calls != 0 || confirmer.calls != 0 || remote.actionCalls != 0 {
				t.Fatalf("untrusted status crossed reviewer/TTY/action boundary: review=%d confirm=%d action=%d", reviewer.calls, confirmer.calls, remote.actionCalls)
			}
		})
	}
}

func TestSubmitRejectsServerFabricatedFinalActionResult(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(HelperResponse) HelperResponse
	}{
		{
			name: "unsigned committed",
			mutate: func(response HelperResponse) HelperResponse {
				response.Receipt = nil
				return response
			},
		},
		{
			name: "terminal state substitution",
			mutate: func(response HelperResponse) HelperResponse {
				response.State = "ROLLED_BACK"
				return response
			},
		},
		{
			name: "request substitution",
			mutate: func(response HelperResponse) HelperResponse {
				receipt := *response.Receipt
				receipt.RequestID = "approval-action-attacker-0001"
				response.Receipt = &receipt
				return response
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := testRequest(ActionApprove)
			plan := testPlan("nginx")
			remote := &fakeRemote{
				plans: []protocol.ApprovalPlan{plan, plan}, scope: request,
				state: "PENDING_APPROVAL", mutateAction: test.mutate,
			}
			confirmer := &fakeConfirmer{}
			submitter := testSubmitter(request, remote, confirmer, testPrivateKey(t))
			if result, err := submitter.Submit(context.Background(), request); err == nil || result.OK {
				t.Fatalf("server-fabricated terminal result was accepted: result=%#v err=%v", result, err)
			}
			if confirmer.calls != 1 || remote.actionCalls != 1 {
				t.Fatalf("test did not reach the final broker boundary: confirm=%d action=%d", confirmer.calls, remote.actionCalls)
			}
		})
	}
}

func TestSubmitSignsAllAuthoritativeFieldsAndPostsAction(t *testing.T) {
	request := testRequest(ActionApprove)
	privateKey := testPrivateKey(t)
	plan := testPlan("nginx\u202e")
	remote := &fakeRemote{plans: []protocol.ApprovalPlan{plan, plan}, scope: request, state: "PENDING_APPROVAL"}
	confirmer := &fakeConfirmer{}
	submitter := testSubmitter(request, remote, confirmer, privateKey)
	result, err := submitter.Submit(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.State != "COMMITTED" || remote.actionCalls != 1 {
		t.Fatalf("action response=%#v calls=%d", result, remote.actionCalls)
	}
	grant := remote.grant
	if grant.Action != "approve" || grant.ServerID != request.ServerID || grant.MachineID != request.MachineID ||
		grant.TargetID != request.TargetID || grant.ChangeID != request.ChangeID || grant.PlanHash != plan.PlanHash ||
		grant.PolicyRevision != plan.PolicyRevision || grant.CapabilityRevision != plan.CapabilityRevision ||
		grant.KeyID != "local-approver-v1" {
		t.Fatalf("approval grant lost authoritative fields: %#v", grant)
	}
	issuedAt, _ := time.Parse(time.RFC3339Nano, grant.IssuedAt)
	expiresAt, _ := time.Parse(time.RFC3339Nano, grant.ExpiresAt)
	if !issuedAt.Equal(testNow) || expiresAt.Sub(issuedAt) != approvalTTL {
		t.Fatalf("approval validity window is not short and exact: %s -> %s", grant.IssuedAt, grant.ExpiresAt)
	}
	payload, err := grant.ApprovalPayload()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawStdEncoding.DecodeString(grant.Signature)
	if err != nil || !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), payload, signature) {
		t.Fatal("approval signature did not cover the stable protocol payload")
	}
	if confirmer.confirmation != ConfirmationText(request, plan.PlanHash) || !strings.Contains(string(confirmer.plan), `\u202e`) {
		t.Fatalf("TTY plan or exact confirmation was not canonical and terminal-safe: %q %s", confirmer.confirmation, confirmer.plan)
	}
}

func TestSubmitAcceptsSignedPVEExecutingWithoutClaimingCommit(t *testing.T) {
	request := testRequest(ActionApprove)
	request.ChangeID = "pve-change-0123456789abcdef0123456789abcdef"
	privateKey := testPrivateKey(t)
	plan := testPlan("pve-async-placeholder")
	remote := &fakeRemote{
		plans: []protocol.ApprovalPlan{plan, plan}, scope: request,
		state: "PENDING_APPROVAL", actionState: "EXECUTING",
	}
	submitter := testSubmitter(request, remote, &fakeConfirmer{}, privateKey)
	result, err := submitter.Submit(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.State != "EXECUTING" || result.State == "COMMITTED" || remote.actionCalls != 1 {
		t.Fatalf("signed PVE async acceptance was changed into a terminal claim: %#v", result)
	}
}

func TestSubmitSelectsPinnedPVEReceiptDomain(t *testing.T) {
	request := testRequest(ActionApprove)
	request.ChangeID = "pve-change-12345678"
	plan := testPlan("pve-operation-fixture")
	remote := &fakeRemote{plans: []protocol.ApprovalPlan{plan, plan}, scope: request, state: "PENDING_APPROVAL"}
	confirmer := &fakeConfirmer{}
	submitter := testSubmitter(request, remote, confirmer, testPrivateKey(t))
	result, err := submitter.Submit(context.Background(), request)
	if err != nil || !result.OK || result.Receipt == nil || result.Receipt.Domain != "pve" || result.Receipt.KeyID != "pve-receipt-v1" {
		t.Fatalf("PVE action did not use its pinned receipt domain: result=%#v err=%v", result, err)
	}

	remote = &fakeRemote{plans: []protocol.ApprovalPlan{plan}, scope: request, state: "PENDING_APPROVAL"}
	submitter = testSubmitter(request, remote, confirmer, testPrivateKey(t))
	originalLoad := submitter.LoadServer
	submitter.LoadServer = func(request Request) (LoadedServer, error) {
		server, err := originalLoad(request)
		server.ReceiptDomain = "core"
		return server, err
	}
	if _, err := submitter.Submit(context.Background(), request); err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("PVE response was accepted under the core receipt domain: %v", err)
	}
}

func TestSubmitPVEUnknownClearanceRequiresSecondExactTTYAndFreshStatus(t *testing.T) {
	request := testRequest(ActionApprove)
	request.ChangeID = "pve-change-child-12345678"
	plan := testPVERecoveryPlan()
	challenge := testPVERecoveryClearanceChallenge(t, request, plan, testNow.Add(time.Minute))
	remote := &fakeRemote{
		plans: []protocol.ApprovalPlan{plan, plan, plan}, scope: request, state: "PENDING_APPROVAL",
		recoveryParentID: challenge.ParentChangeID, clearanceRequired: true, clearanceChallenge: &challenge,
	}
	confirmer := &sequenceConfirmer{}
	privateKey := testPrivateKey(t)
	submitter := testSubmitter(request, remote, confirmer, privateKey)
	result, err := submitter.Submit(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.State != "COMMITTED" || remote.statusCalls != 3 ||
		remote.clearancePrepareCalls != 1 || remote.clearanceConfirmCalls != 1 || remote.actionCalls != 1 {
		t.Fatalf("PVE clearance flow did not cross every authoritative barrier: result=%#v status=%d prepare=%d confirm=%d action=%d",
			result, remote.statusCalls, remote.clearancePrepareCalls, remote.clearanceConfirmCalls, remote.actionCalls)
	}
	if len(confirmer.confirmations) != 2 || confirmer.confirmations[0] != ConfirmationText(request, plan.PlanHash) ||
		confirmer.confirmations[1] != pveRecoveryClearanceConfirmationText(request, challenge) {
		t.Fatalf("PVE clearance did not require two exact independent TTY confirmations: %#v", confirmer.confirmations)
	}
	if !bytes.Contains(confirmer.plans[1], []byte(challenge.ChallengeDigest)) ||
		!bytes.Contains(confirmer.plans[1], []byte("STARTED_OR_UNKNOWN")) {
		t.Fatalf("second TTY omitted authoritative unknown-result evidence: %s", confirmer.plans[1])
	}
	if remote.clearanceActionToken != "pve-clearance-fedcba9876543210fedcba9876543210" {
		t.Fatalf("normal approval did not carry the one-shot confirmed token: %q", remote.clearanceActionToken)
	}
	approval := remote.clearanceApproval
	if approval.ParentChangeID != challenge.ParentChangeID || approval.ChildChangeID != request.ChangeID ||
		approval.ChildPlanHash != plan.PlanHash || approval.ResourceKey != challenge.ResourceKey ||
		approval.ChallengeDigest != challenge.ChallengeDigest || approval.Action != protocol.PVERecoveryClearanceAction {
		t.Fatalf("clearance signature lost exact challenge binding: %#v", approval)
	}
	payload, err := approval.ApprovalPayload()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawStdEncoding.DecodeString(approval.Signature)
	if err != nil || !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), payload, signature) {
		t.Fatal("PVE recovery clearance approval signature did not cover its stable payload")
	}
}

func TestSubmitPVEUnknownClearanceFailsClosedOnExpiryOrConfirmDrift(t *testing.T) {
	for _, test := range []struct {
		name         string
		expiresAt    time.Time
		confirmError string
		advance      time.Duration
		want         string
	}{
		{name: "challenge-expired-after-second-tty", expiresAt: testNow.Add(10 * time.Second), advance: 11 * time.Second, want: "expired"},
		{name: "broker-observation-drift", expiresAt: testNow.Add(time.Minute), confirmError: "guest or cluster observation changed", want: "observation changed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := testRequest(ActionApprove)
			request.ChangeID = "pve-change-child-12345678"
			plan := testPVERecoveryPlan()
			challenge := testPVERecoveryClearanceChallenge(t, request, plan, test.expiresAt)
			remote := &fakeRemote{
				plans: []protocol.ApprovalPlan{plan, plan, plan}, scope: request, state: "PENDING_APPROVAL",
				recoveryParentID: challenge.ParentChangeID, clearanceRequired: true, clearanceChallenge: &challenge,
				clearanceConfirmError: test.confirmError,
			}
			current := testNow
			confirmer := &sequenceConfirmer{onConfirm: func(call int) {
				if call == 2 {
					current = current.Add(test.advance)
				}
			}}
			submitter := testSubmitter(request, remote, confirmer, testPrivateKey(t))
			submitter.Now = func() time.Time { return current }
			if result, err := submitter.Submit(context.Background(), request); err == nil || result.OK || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expired or drifted clearance reached action: result=%#v err=%v", result, err)
			}
			if len(confirmer.confirmations) != 2 || remote.actionCalls != 0 {
				t.Fatalf("negative clearance test did not stop after second TTY: confirms=%d actions=%d", len(confirmer.confirmations), remote.actionCalls)
			}
			if test.confirmError == "" && remote.clearanceConfirmCalls != 0 {
				t.Fatal("expired challenge was sent to broker confirmation")
			}
			if test.confirmError != "" && remote.clearanceConfirmCalls != 1 {
				t.Fatal("broker drift test did not reach authoritative confirmation")
			}
		})
	}
}

func testPVERecoveryPlan() protocol.ApprovalPlan {
	plan := protocol.ApprovalPlan{
		Version: protocol.Version, PolicyRevision: "policy-12345678", CapabilityRevision: "capability-12345678",
		PluginDigest: "sha256:" + strings.Repeat("d", 64),
		Steps: []protocol.ApprovalPlanStep{{
			ID: "step-1", Operation: "pve.guest.action", Reversible: false,
			Fields: []protocol.ApprovalPlanField{
				{Name: "pluginId", Value: "workload.pve"}, {Name: "pluginDigest", Value: "sha256:" + strings.Repeat("d", 64)},
				{Name: "recoveryOfChangeId", Value: "pve-change-parent-1234567"},
				{Name: "node", Value: "pve1"}, {Name: "guestType", Value: "qemu"}, {Name: "vmid", Value: "100"}, {Name: "action", Value: "start"},
			},
		}},
	}
	plan.PlanHash, _ = protocol.CanonicalApprovalPlanHash(plan)
	return plan
}

func testPVERecoveryClearanceChallenge(t *testing.T, request Request, plan protocol.ApprovalPlan, expiresAt time.Time) protocol.PVERecoveryClearanceChallenge {
	t.Helper()
	observation, err := protocol.NewPVERecoveryClearanceObservation(
		"qemu", 100,
		[]protocol.PVERecoveryActiveTaskProbe{{Node: "pve1", VMID: 100, ActiveCount: 0}},
		[]protocol.PVERecoveryGuestState{{Node: "pve1", GuestType: "qemu", VMID: 100, Status: "stopped"}},
		[]protocol.PVERecoveryClusterState{{Type: "node", Name: "pve1", Node: "pve1", NodeID: 0, Local: 1, Online: 1}},
	)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := protocol.FinalizePVERecoveryClearanceChallenge(protocol.PVERecoveryClearanceChallenge{
		Kind: "pve.recovery-clearance-challenge/v1", ClearanceID: "pve-clearance-0123456789abcdef0123456789abcdef",
		ParentChangeID: "pve-change-parent-1234567", ChildChangeID: request.ChangeID,
		ChildPlanHash: plan.PlanHash, ResourceKey: "pve/vmid/100", Observation: observation,
		IssuedAt: testNow.Format(time.RFC3339Nano), ExpiresAt: expiresAt.Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	return challenge
}

func TestHTTPSRemoteUsesFixedActionEndpoint(t *testing.T) {
	reference := testRequest(ActionApprove)
	requestID := "approval-action-12345678"
	var seenPath string
	var seenMethod string
	baseURL, _ := url.Parse("https://approval.example:7443")
	remote := &HTTPSRemote{baseURL: baseURL, client: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		seenPath, seenMethod = request.URL.EscapedPath(), request.Method
		if request.URL.RawQuery != "" {
			t.Errorf("action endpoint had unexpected query: %s", request.URL.RawQuery)
		}
		payload, _ := io.ReadAll(io.LimitReader(request.Body, protocol.MaxFrameBytes+1))
		if !bytes.Contains(payload, []byte(`"action":"approve"`)) || !bytes.Contains(payload, []byte(`"machineId":"machine-12345678"`)) {
			t.Errorf("action body lost fixed scope or grant: %s", payload)
		}
		responsePayload, _ := json.Marshal(HelperResponse{Version: 1, RequestID: requestID, OK: true, ChangeID: reference.ChangeID, State: "COMMITTED"})
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(responsePayload)),
		}, nil
	})}}
	grant := protocol.ApprovalGrant{Action: "approve"}
	result, err := remote.Action(context.Background(), reference, requestID, time.Now().Add(30*time.Second), grant)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || seenMethod != http.MethodPost || seenPath != "/v1/changes/change-12345678/approve" {
		t.Fatalf("unexpected action endpoint: method=%s path=%s result=%#v", seenMethod, seenPath, result)
	}
}

func TestHTTPSRemoteRequiresExactTLS13(t *testing.T) {
	reference := testRequest(ActionApprove)
	_, err := NewHTTPSRemote(LoadedServer{
		Registration: testRegistration(reference),
		TLSConfig:    &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13},
	})
	if err == nil || !strings.Contains(err.Error(), "TLS 1.3") {
		t.Fatalf("non-exact TLS range was accepted: %v", err)
	}
}

func TestRootOwnedFileReaderRejectsPublicPrivateKeyAndSymlink(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "approval.key")
	if err := os.WriteFile(path, []byte("private"), 0o644); err != nil {
		t.Fatal(err)
	}
	owner := uint32(os.Geteuid())
	if _, err := readOwnedFile(path, owner, 1024, true); err == nil || !strings.Contains(err.Error(), "private key") {
		t.Fatalf("public private key was accepted: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if payload, err := readOwnedFile(path, owner, 1024, true); err != nil || string(payload) != "private" {
		t.Fatalf("private root-equivalent test file was rejected: %q %v", payload, err)
	}
	symlink := filepath.Join(directory, "link")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readOwnedFile(symlink, owner, 1024, true); err == nil {
		t.Fatal("symlinked private key was accepted")
	}
}

func TestRegistryAndApprovalPlanRejectUnknownOrMissingSecurityFields(t *testing.T) {
	reference := testRequest(ActionApprove)
	registrationPayload, _ := json.Marshal(testRegistration(reference))
	registryPayload := []byte(`{"version":1,"servers":[` + string(registrationPayload) + `],"command":"sh"}`)
	if _, err := parseRegistry(registryPayload); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("registry accepted an unknown command field: %v", err)
	}
	registration := testRegistration(reference)
	registration.ObserverCertPath = "/etc/ops-agent/tls/observer.crt"
	registrationPayload, _ = json.Marshal(registration)
	registryPayload = []byte(`{"version":1,"servers":[` + string(registrationPayload) + `]}`)
	if _, err := parseRegistry(registryPayload); err == nil || !strings.Contains(err.Error(), "both observer") {
		t.Fatalf("registry accepted a partial observer credential: %v", err)
	}
	registration = testRegistration(reference)
	registration.CoreReceiptPublicKeyPath = ""
	registrationPayload, _ = json.Marshal(registration)
	registryPayload = []byte(`{"version":1,"servers":[` + string(registrationPayload) + `]}`)
	if _, err := parseRegistry(registryPayload); err == nil || !strings.Contains(err.Error(), "both core") {
		t.Fatalf("registry accepted a partial core receipt verifier: %v", err)
	}
	registration = testRegistration(reference)
	registration.PVEReceiptKeyID = registration.CoreReceiptKeyID
	registrationPayload, _ = json.Marshal(registration)
	registryPayload = []byte(`{"version":1,"servers":[` + string(registrationPayload) + `]}`)
	if _, err := parseRegistry(registryPayload); err == nil || !strings.Contains(err.Error(), "separate") {
		t.Fatalf("registry allowed core and PVE to share a receipt key: %v", err)
	}
	registration = testRegistration(reference)
	registration.PVEReceiptKeyID, registration.PVEReceiptPublicKeyPath = "", ""
	registrationPayload, _ = json.Marshal(registration)
	registryPayload = []byte(`{"version":1,"servers":[` + string(registrationPayload) + `]}`)
	if _, err := parseRegistry(registryPayload); err != nil {
		t.Fatalf("non-PVE registration was forced to configure a PVE receipt key: %v", err)
	}

	planPayload, _ := json.Marshal(testPlan("nginx"))
	withoutReversible := bytes.Replace(planPayload, []byte(`,"reversible":false`), nil, 1)
	if bytes.Equal(planPayload, withoutReversible) {
		t.Fatalf("test fixture did not contain reversible: %s", planPayload)
	}
	if _, err := parseApprovalPlan(withoutReversible); err == nil || !strings.Contains(err.Error(), "reversible") {
		t.Fatalf("ApprovalPlan without reversible was accepted: %v", err)
	}
}

func TestReceiptPublicKeyParserAcceptsOnlyOneEd25519PublicPEM(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	payload := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	parsed, err := parseEd25519PublicKey(payload)
	if err != nil || !parsed.Equal(publicKey) {
		t.Fatalf("valid receipt public key was rejected: %v", err)
	}
	if _, err := parseEd25519PublicKey(append(payload, payload...)); err == nil {
		t.Fatal("multiple receipt public keys were accepted")
	}
	if _, err := parseEd25519PublicKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err == nil {
		t.Fatal("receipt public verifier accepted a private-key PEM label")
	}
}

func testSubmitter(reference Request, remote Remote, confirmer Confirmer, privateKey ed25519.PrivateKey) Submitter {
	receiptPrivateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	if fake, ok := remote.(*fakeRemote); ok {
		fake.receiptPrivateKey = receiptPrivateKey
	}
	receiptDomain, _ := brokerDomainForChangeID(reference.ChangeID)
	return Submitter{
		EffectiveUID: func() int { return 0 },
		LoadServer: func(Request) (LoadedServer, error) {
			return LoadedServer{
				Registration:  testRegistration(reference),
				ReceiptDomain: receiptDomain, ReceiptKeyID: receiptDomain + "-receipt-v1",
				ReceiptPublicKey: append(ed25519.PublicKey(nil), receiptPrivateKey.Public().(ed25519.PublicKey)...),
				SigningKey: func() (ed25519.PrivateKey, error) {
					return append(ed25519.PrivateKey(nil), privateKey...), nil
				},
			}, nil
		},
		NewRemote: func(LoadedServer) (Remote, error) { return remote, nil },
		LeaseRuntimePlugin: func(pluginID, digest string) (pluginregistry.RuntimeRegistration, RuntimePluginLease, error) {
			return pluginregistry.RuntimeRegistration{Registration: pluginregistry.Registration{
				PluginID: pluginID, Kind: pluginregistry.KindWorkload, Digest: digest,
			}}, io.NopCloser(strings.NewReader("")), nil
		},
		Confirmer: confirmer,
		Reviewer:  &fakeApprovalReviewer{},
		Now:       func() time.Time { return testNow },
		Random:    bytes.NewReader(bytes.Repeat([]byte{0x5a}, 512)),
	}
}

func testRequest(action Action) Request {
	return Request{
		Action: action, ServerID: "server-12345678", MachineID: "machine-12345678",
		TargetID: "target-service", ChangeID: "change-12345678",
		UserIntent: "restart the exact service only after checking health",
	}
}

func manualReview(request ApprovalReviewRequest) ApprovalReview {
	intentDigest, _ := canonicalDigest(map[string]any{"userIntent": request.UserIntent})
	review := ApprovalReview{
		Version: 1, ReviewID: request.ReviewID, PlanHash: request.Plan.PlanHash,
		UserIntentDigest: intentDigest, MinimumRisk: "high", Risk: "high",
		Recommendation: ReviewManual, CanAuthorize: false, Findings: []ApprovalReviewFinding{},
		Explanation: "Manual review is required and this reviewer cannot authorize the change.",
	}
	review.ReviewDigest, _ = approvalReviewDigest(review)
	return review
}

func testRegistration(reference Request) ServerRegistration {
	return ServerRegistration{
		ServerID: reference.ServerID, MachineID: reference.MachineID, BaseURL: "https://127.0.0.1:7443",
		CAPath: "/etc/ops-agent/tls/ca.crt", CertPath: "/etc/ops-agent/tls/agent.crt", KeyPath: "/etc/ops-agent/tls/agent.key",
		ApproverCertPath: "/etc/ops-agent/approver/approver.crt", ApproverKeyPath: "/etc/ops-agent/approver/approver.key",
		ApprovalSigningKeyPath: "/etc/ops-agent/approver/approval.key.pem", ApprovalKeyID: "local-approver-v1",
		CoreReceiptKeyID: "core-receipt-v1", CoreReceiptPublicKeyPath: "/etc/ops-agent/broker-receipts/core-public.pem",
		PVEReceiptKeyID: "pve-receipt-v1", PVEReceiptPublicKeyPath: "/etc/ops-agent/broker-receipts/pve-public.pem",
		Enabled: true,
	}
}

func testPlan(packageName string) protocol.ApprovalPlan {
	plan := protocol.ApprovalPlan{
		Version:        1,
		PolicyRevision: "policy-12345678", CapabilityRevision: "capability-12345678",
		Steps: []protocol.ApprovalPlanStep{{
			ID: "step-1", Operation: "package.install", Reversible: false,
			Fields: []protocol.ApprovalPlanField{{Name: "package", Value: packageName}},
		}},
	}
	plan.PlanHash, _ = protocol.CanonicalApprovalPlanHash(plan)
	return plan
}

func makeStatusResponse(requestID string, scope Request, plan protocol.ApprovalPlan, state string, rollback bool) HelperResponse {
	planPayload, _ := json.Marshal(plan)
	data, _ := json.Marshal(statusWire{
		ServerID: scope.ServerID, MachineID: scope.MachineID, TargetID: scope.TargetID,
		PolicyRevision: plan.PolicyRevision, CapabilityRevision: plan.CapabilityRevision,
		PlanHash: plan.PlanHash, Kind: plan.Steps[0].Operation, BackupRefs: []string{},
		Verification: "", RollbackAvailable: &rollback, RecoveryOnly: new(bool), Plan: planPayload,
	})
	return HelperResponse{
		Version: 1, RequestID: requestID, OK: true, ChangeID: scope.ChangeID,
		AuditID: "audit-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		State:   state, Summary: "authoritative status", Data: data,
	}
}

func recoveryStatusWire(scope Request, rollback bool) *statusWire {
	recoveryOnly := true
	reason := ""
	objects := []protocol.RecoveryBackupObject{{
		Reference: "/var/lib/ops-agent/backups/change-12345678",
		Digest:    "sha256:" + strings.Repeat("d", 64),
	}}
	if !rollback {
		reason = "the persisted change has no durable rollback evidence"
		objects[0].Digest = ""
	}
	return &statusWire{
		ServerID: scope.ServerID, MachineID: scope.MachineID, TargetID: scope.TargetID,
		PolicyRevision: "policy-legacy-v2", CapabilityRevision: "capability-legacy-v2",
		PlanHash: "sha256:" + strings.Repeat("c", 64), Kind: "service.action",
		BackupRefs:        []string{"/var/lib/ops-agent/backups/change-12345678"},
		Verification:      "legacy service state requires operator recovery",
		RollbackAvailable: &rollback, LastError: "broker restarted during verification",
		RollbackUnavailableReason: reason,
		RecoveryOnly:              &recoveryOnly,
		RecoveryDescriptor: &protocol.RecoveryDescriptor{
			Version: protocol.Version, CompatibilityVersion: protocol.LegacyPlanCompatibilityV02,
			OriginalKind: "service.action", OriginalTarget: "demo.service", OriginalAction: "service.restart",
			CompensationTarget: "demo.service", CompensationAction: "service.stop",
			RollbackDataDigest: "sha256:" + strings.Repeat("e", 64), BackupObjects: objects,
			RollbackCompatible: rollback, UnavailableReason: reason,
		},
	}
}

func makeRecoveryStatusResponse(requestID string, scope Request, state string, rollback bool) HelperResponse {
	data, _ := json.Marshal(recoveryStatusWire(scope, rollback))
	return HelperResponse{
		Version: 1, RequestID: requestID, OK: true, ChangeID: scope.ChangeID,
		AuditID: "audit-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		State:   state, Summary: "authoritative recovery-only status", Data: data,
	}
}

func signFakeBrokerResponse(response HelperResponse, scope Request, method protocol.Method, planHash string, privateKey ed25519.PrivateKey) HelperResponse {
	domain, _ := brokerDomainForChangeID(scope.ChangeID)
	signed, err := protocol.SignBrokerResponse(protocolResponse(response), protocol.BrokerReceiptClaims{
		KeyID: domain + "-receipt-v1", Domain: domain, RequestID: response.RequestID, Method: method,
		ServerID: scope.ServerID, MachineID: scope.MachineID, TargetID: scope.TargetID,
		ChangeID: scope.ChangeID, PlanHash: planHash,
	}, testNow, privateKey)
	if err != nil {
		panic(err)
	}
	response.Receipt = signed.Receipt
	return response
}

func testPrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
