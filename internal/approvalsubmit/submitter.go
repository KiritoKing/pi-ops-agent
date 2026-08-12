package approvalsubmit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

const approvalTTL = 2 * time.Minute

type Confirmer interface {
	Confirm(plan []byte, exactText string) error
}

type Submitter struct {
	EffectiveUID       func() int
	LoadServer         func(Request) (LoadedServer, error)
	NewRemote          func(LoadedServer) (Remote, error)
	LeaseRuntimePlugin RuntimePluginLeaseAcquirer
	Confirmer          Confirmer
	Reviewer           ApprovalReviewer
	Now                func() time.Time
	Random             io.Reader
}

func NewDefaultSubmitter() Submitter {
	return Submitter{
		EffectiveUID:       os.Geteuid,
		LoadServer:         LoadFixedServer,
		NewRemote:          NewHTTPSRemote,
		LeaseRuntimePlugin: leaseFixedRuntimePlugin,
		Confirmer:          DeviceConfirmer{},
		Reviewer:           UnixApprovalReviewer{},
		Now:                time.Now,
		Random:             rand.Reader,
	}
}

func (s Submitter) Submit(ctx context.Context, request Request) (HelperResponse, error) {
	if s.EffectiveUID == nil || s.EffectiveUID() != 0 {
		return HelperResponse{}, errors.New("agentd-approval-submit must run with effective UID 0")
	}
	if err := request.Validate(); err != nil {
		return HelperResponse{}, err
	}
	if s.LoadServer == nil || s.NewRemote == nil || s.LeaseRuntimePlugin == nil || s.Confirmer == nil ||
		s.Reviewer == nil || s.Now == nil || s.Random == nil {
		return HelperResponse{}, errors.New("approval submitter is not fully initialized")
	}
	server, err := s.LoadServer(request)
	if err != nil {
		return HelperResponse{}, err
	}
	if server.Registration.ServerID != request.ServerID || server.Registration.MachineID != request.MachineID || !server.Registration.Enabled {
		return HelperResponse{}, errors.New("loaded server registration does not match the exact requested identity")
	}
	remote, err := s.NewRemote(server)
	if err != nil {
		return HelperResponse{}, err
	}
	first, firstStatus, err := s.fetchStatus(ctx, remote, server, request)
	if err != nil {
		return HelperResponse{}, err
	}
	if !first.OK {
		return first, nil
	}
	if err := validateActionState(request.Action, firstStatus); err != nil {
		return HelperResponse{}, err
	}
	var runtimePluginLease RuntimePluginLease
	if request.Action == ActionApprove {
		runtimePluginLease, err = s.acquireApprovalRuntimePluginLease(firstStatus)
		if err != nil {
			return HelperResponse{}, err
		}
		if runtimePluginLease != nil {
			defer func() { _ = runtimePluginLease.Close() }()
		}
	}
	if request.Action != ActionReject && !firstStatus.RecoveryOnly {
		if err := s.requireIndependentReview(ctx, request, firstStatus); err != nil {
			return HelperResponse{}, err
		}
	}
	display, err := confirmationDisplayJSON(request, firstStatus)
	if err != nil {
		return HelperResponse{}, err
	}
	confirmation := ConfirmationText(request, firstStatus.PlanHash)
	if err := s.Confirmer.Confirm(display, confirmation); err != nil {
		return HelperResponse{}, err
	}
	second, secondStatus, err := s.fetchStatus(ctx, remote, server, request)
	if err != nil {
		return HelperResponse{}, err
	}
	if !second.OK {
		return HelperResponse{}, errors.New("authoritative status became unsuccessful after human confirmation")
	}
	if err := validateActionState(request.Action, secondStatus); err != nil {
		return HelperResponse{}, err
	}
	if !sameStatusBinding(firstStatus, secondStatus) {
		return HelperResponse{}, errors.New("authoritative change or ApprovalPlan drifted during human confirmation")
	}
	if server.SigningKey == nil {
		return HelperResponse{}, errors.New("approval signing key loader is unavailable")
	}
	privateKey, err := server.SigningKey()
	if err != nil {
		return HelperResponse{}, err
	}
	defer clear(privateKey)
	clearanceToken := ""
	if request.Action == ActionApprove && secondStatus.RecoveryOfChangeID != "" {
		clearanceRemote, ok := remote.(PVERecoveryClearanceRemote)
		if !ok {
			return HelperResponse{}, errors.New("PVE recovery approval endpoint does not support local unknown-result clearance")
		}
		clearanceToken, err = s.obtainPVERecoveryClearance(ctx, remote, clearanceRemote, server, request, secondStatus, privateKey)
		if err != nil {
			return HelperResponse{}, err
		}
	}
	grant, err := signApprovalGrant(
		request, secondStatus, server.Registration.ApprovalKeyID, privateKey,
		s.Now().UTC(), s.Random,
	)
	if err != nil {
		return HelperResponse{}, err
	}
	requestID, err := randomID(s.Random, "approval-action-")
	if err != nil {
		return HelperResponse{}, err
	}
	now := s.Now().UTC()
	actionTimeout := 9 * time.Minute
	if request.Action == ActionReject {
		actionTimeout = 30 * time.Second
	}
	var result HelperResponse
	if clearanceToken != "" {
		result, err = remote.(PVERecoveryClearanceRemote).ActionWithPVERecoveryClearance(ctx, request, requestID, now.Add(actionTimeout), grant, clearanceToken)
	} else {
		result, err = remote.Action(ctx, request, requestID, now.Add(actionTimeout), grant)
	}
	if err != nil {
		return HelperResponse{}, err
	}
	if err := validateHelperResponse(result, requestID); err != nil {
		return HelperResponse{}, err
	}
	if err := s.verifyBrokerResponse(server, request, requestID, actionMethod(request.Action), secondStatus.PlanHash, result); err != nil {
		return HelperResponse{}, fmt.Errorf("verify authoritative action receipt: %w", err)
	}
	if (result.OK && result.ChangeID != request.ChangeID) || (!result.OK && result.ChangeID != "" && result.ChangeID != request.ChangeID) {
		return HelperResponse{}, errors.New("action response changeId does not match the requested change")
	}
	if result.OK {
		validState := result.State == map[Action]string{
			ActionApprove: "COMMITTED", ActionReject: "REJECTED", ActionRollback: "ROLLED_BACK",
		}[request.Action]
		// A PVE approval is complete once the broker has durably bound and
		// signed the running UPID. The local submitter must not keep the HTTPS
		// request open for the lifetime of a backup or migration; only a later
		// signed change.status=COMMITTED is success for the operation itself.
		if request.Action == ActionApprove && strings.HasPrefix(request.ChangeID, "pve-change-") &&
			result.State == "EXECUTING" {
			validState = true
		}
		if !validState {
			return HelperResponse{}, fmt.Errorf("successful %s response has unexpected state %q", request.Action, result.State)
		}
	}
	return result, nil
}

func (s Submitter) requireIndependentReview(ctx context.Context, request Request, status ChangeStatus) error {
	if status.RecoveryOnly || status.Plan == nil {
		return errors.New("recovery-only change has no live ApprovalPlan for independent review")
	}
	reviewID, err := randomID(s.Random, "review-")
	if err != nil {
		return err
	}
	reviewRequest := ApprovalReviewRequest{
		Version: protocol.Version, ReviewID: reviewID, UserIntent: request.UserIntent, Plan: *status.Plan,
	}
	review, err := s.Reviewer.Review(ctx, reviewRequest)
	if err != nil {
		return fmt.Errorf("independent approval review failed: %w", err)
	}
	if err := validateApprovalReview(reviewRequest, review); err != nil {
		return fmt.Errorf("independent approval review is invalid: %w", err)
	}
	switch review.Recommendation {
	case ReviewManual:
		return nil
	case ReviewReject:
		return errors.New("independent approval reviewer rejected the canonical plan")
	case ReviewSplitRequired:
		return errors.New("independent approval reviewer requires the canonical plan to be split")
	default:
		return errors.New("independent approval reviewer returned an unsupported recommendation")
	}
}

func (s Submitter) fetchStatus(ctx context.Context, remote Remote, server LoadedServer, request Request) (HelperResponse, ChangeStatus, error) {
	requestID, err := randomID(s.Random, "approval-status-")
	if err != nil {
		return HelperResponse{}, ChangeStatus{}, err
	}
	response, err := remote.Status(ctx, request, requestID, s.Now().UTC().Add(30*time.Second))
	if err != nil {
		return HelperResponse{}, ChangeStatus{}, err
	}
	if err := validateHelperResponse(response, requestID); err != nil {
		return HelperResponse{}, ChangeStatus{}, err
	}
	if !response.OK {
		if response.Receipt == nil {
			return HelperResponse{}, ChangeStatus{}, errors.New("unsuccessful status response has no authoritative broker receipt")
		}
		if err := s.verifyBrokerResponse(server, request, requestID, protocol.MethodChangeStatus, response.Receipt.PlanHash, response); err != nil {
			return HelperResponse{}, ChangeStatus{}, fmt.Errorf("verify unsuccessful status receipt: %w", err)
		}
		return response, ChangeStatus{}, nil
	}
	status, err := parseStatus(response, request)
	if err != nil {
		return HelperResponse{}, ChangeStatus{}, err
	}
	if err := s.verifyBrokerResponse(server, request, requestID, protocol.MethodChangeStatus, status.PlanHash, response); err != nil {
		return HelperResponse{}, ChangeStatus{}, fmt.Errorf("verify authoritative status receipt: %w", err)
	}
	return response, status, nil
}

func (s Submitter) verifyBrokerResponse(server LoadedServer, request Request, requestID string, method protocol.Method, planHash string, response HelperResponse) error {
	domain, err := brokerDomainForChangeID(request.ChangeID)
	if err != nil {
		return err
	}
	if server.ReceiptDomain != domain || !protocol.ValidBrokerReceiptKeyID(server.ReceiptKeyID) ||
		len(server.ReceiptPublicKey) != ed25519.PublicKeySize {
		return errors.New("loaded server has no matching pinned broker receipt verifier")
	}
	claims := protocol.BrokerReceiptClaims{
		KeyID: server.ReceiptKeyID, Domain: domain, RequestID: requestID, Method: method,
		ServerID: request.ServerID, MachineID: request.MachineID, TargetID: request.TargetID,
		ChangeID: request.ChangeID, PlanHash: planHash,
	}
	return protocol.VerifyBrokerResponse(protocolResponse(response), claims, s.Now().UTC(), server.ReceiptPublicKey)
}

func protocolResponse(response HelperResponse) protocol.Response {
	var data interface{}
	if len(response.Data) > 0 {
		data = json.RawMessage(response.Data)
	}
	return protocol.Response{
		Version: response.Version, RequestID: response.RequestID, OK: response.OK,
		AuditID: response.AuditID, ChangeID: response.ChangeID, State: response.State,
		Summary: response.Summary, Data: data, Error: response.Error, Receipt: response.Receipt,
	}
}

func actionMethod(action Action) protocol.Method {
	switch action {
	case ActionApprove:
		return protocol.MethodChangeApprove
	case ActionReject:
		return protocol.MethodChangeReject
	case ActionRollback:
		return protocol.MethodChangeRollback
	default:
		return ""
	}
}

func validateActionState(action Action, status ChangeStatus) error {
	switch action {
	case ActionApprove, ActionReject:
		if status.State != "PENDING_APPROVAL" {
			return fmt.Errorf("change state %q is not eligible for %s", status.State, action)
		}
	case ActionRollback:
		if status.State != "COMMITTED" && status.State != "RECOVERY_REQUIRED" {
			return fmt.Errorf("change state %q is not eligible for rollback", status.State)
		}
		if !status.RollbackAvailable {
			return errors.New("authoritative status says rollback is unavailable")
		}
	default:
		return errors.New("unsupported approval action")
	}
	return nil
}

func sameStatusBinding(first, second ChangeStatus) bool {
	firstJSON, firstErr := json.Marshal(first)
	secondJSON, secondErr := json.Marshal(second)
	if firstErr != nil || secondErr != nil || len(firstJSON) != len(secondJSON) {
		return false
	}
	return subtle.ConstantTimeCompare(firstJSON, secondJSON) == 1
}

// signApprovalGrant is separate from orchestration so tests can verify the
// exact stable protocol payload without exposing a generic signing command.
func signApprovalGrant(request Request, status ChangeStatus, keyID string, privateKey ed25519.PrivateKey, now time.Time, random io.Reader) (protocol.ApprovalGrant, error) {
	if !approvalKeyIDPattern.MatchString(keyID) || len(privateKey) != ed25519.PrivateKeySize {
		return protocol.ApprovalGrant{}, errors.New("approval signing identity is invalid")
	}
	nonceBytes := make([]byte, 24)
	if _, err := io.ReadFull(random, nonceBytes); err != nil {
		return protocol.ApprovalGrant{}, fmt.Errorf("generate approval nonce: %w", err)
	}
	now = now.UTC()
	grant := protocol.ApprovalGrant{
		Version: protocol.Version, KeyID: keyID, Action: string(request.Action),
		ServerID: request.ServerID, MachineID: request.MachineID, TargetID: request.TargetID,
		ChangeID: request.ChangeID, PlanHash: status.PlanHash, PolicyRevision: status.PolicyRevision,
		CapabilityRevision: status.CapabilityRevision,
		IssuedAt:           now.Format(time.RFC3339Nano), ExpiresAt: now.Add(approvalTTL).Format(time.RFC3339Nano),
		Nonce: base64.RawURLEncoding.EncodeToString(nonceBytes),
	}
	payload, err := grant.ApprovalPayload()
	if err != nil {
		return protocol.ApprovalGrant{}, err
	}
	grant.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	if err := grant.ValidateShape(); err != nil {
		return protocol.ApprovalGrant{}, err
	}
	return grant, nil
}

func randomID(source io.Reader, prefix string) (string, error) {
	bytes := make([]byte, 16)
	if _, err := io.ReadFull(source, bytes); err != nil {
		return "", fmt.Errorf("generate request ID: %w", err)
	}
	return prefix + hex.EncodeToString(bytes), nil
}

func ConfirmationText(request Request, planHash string) string {
	return strings.ToUpper(string(request.Action)) + " " + request.ServerID + " " + request.MachineID + " " + request.TargetID + " " + request.ChangeID + " " + planHash
}

func canonicalPlanJSON(plan protocol.ApprovalPlan) ([]byte, error) {
	payload, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return nil, err
	}
	// Escape all non-ASCII bytes before writing untrusted plan fields to a
	// terminal. JSON already escapes C0 controls; ASCII-only output additionally
	// avoids bidi and homoglyph ambiguity in the approval display.
	return []byte(asciiOnlyJSON(string(payload))), nil
}

type recoveryOnlyDisplay struct {
	Version                   int                         `json:"version"`
	RecoveryOnly              bool                        `json:"recoveryOnly"`
	Warning                   string                      `json:"warning"`
	RequestedAction           Action                      `json:"requestedAction"`
	ServerID                  string                      `json:"serverId"`
	MachineID                 string                      `json:"machineId"`
	TargetID                  string                      `json:"targetId"`
	ChangeID                  string                      `json:"changeId"`
	State                     string                      `json:"state"`
	Kind                      string                      `json:"kind"`
	Summary                   string                      `json:"summary"`
	PlanHash                  string                      `json:"planHash"`
	PolicyRevision            string                      `json:"policyRevision"`
	CapabilityRevision        string                      `json:"capabilityRevision"`
	BackupRefs                []string                    `json:"backupRefs"`
	Verification              string                      `json:"verification"`
	RollbackAvailable         bool                        `json:"rollbackAvailable"`
	RollbackUnavailableReason string                      `json:"rollbackUnavailableReason,omitempty"`
	RecoveryDescriptor        protocol.RecoveryDescriptor `json:"recoveryDescriptor"`
	LastError                 string                      `json:"lastError"`
	AuthorizationBasis        string                      `json:"authorizationBasis,omitempty"`
	AuthorizationScope        string                      `json:"authorizationScope,omitempty"`
	AuthorizedAt              string                      `json:"authorizedAt,omitempty"`
}

func confirmationDisplayJSON(request Request, status ChangeStatus) ([]byte, error) {
	if !status.RecoveryOnly {
		if status.Plan == nil {
			return nil, errors.New("authoritative change has no live ApprovalPlan")
		}
		return canonicalPlanJSON(*status.Plan)
	}
	if request.Action != ActionReject && request.Action != ActionRollback {
		return nil, errors.New("recovery-only authoritative change permits only reject or rollback")
	}
	if status.RecoveryDescriptor == nil {
		return nil, errors.New("recovery-only authoritative change has no signed recovery descriptor")
	}
	payload, err := json.MarshalIndent(recoveryOnlyDisplay{
		Version: protocol.Version, RecoveryOnly: true,
		Warning:         "LEGACY RECOVERY ONLY: no current canonical ApprovalPlan exists; this action cannot approve or replay the stored mutation and may only reject it or apply stored rollback",
		RequestedAction: request.Action,
		ServerID:        status.ServerID, MachineID: status.MachineID, TargetID: status.TargetID,
		ChangeID: request.ChangeID, State: status.State, Kind: status.Kind, Summary: status.Summary,
		PlanHash: status.PlanHash, PolicyRevision: status.PolicyRevision,
		CapabilityRevision: status.CapabilityRevision,
		BackupRefs:         append([]string(nil), status.BackupRefs...), Verification: status.Verification,
		RollbackAvailable:         status.RollbackAvailable,
		RollbackUnavailableReason: status.RollbackUnavailableReason,
		RecoveryDescriptor:        *status.RecoveryDescriptor,
		LastError:                 status.LastError,
		AuthorizationBasis:        status.AuthorizationBasis,
		AuthorizationScope:        status.AuthorizationScope, AuthorizedAt: status.AuthorizedAt,
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	return []byte(asciiOnlyJSON(string(payload))), nil
}

func asciiOnlyJSON(value string) string {
	var builder strings.Builder
	for _, char := range value {
		if (char >= 0x20 && char <= 0x7e) || char == '\n' || char == '\r' || char == '\t' {
			builder.WriteRune(char)
			continue
		}
		if char <= 0xffff {
			fmt.Fprintf(&builder, `\u%04x`, char)
			continue
		}
		char -= 0x10000
		fmt.Fprintf(&builder, `\u%04x\u%04x`, 0xd800+(char>>10), 0xdc00+(char&0x3ff))
	}
	return builder.String()
}
