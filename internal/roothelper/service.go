package roothelper

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/audit"
	"github.com/KiritoKing/pi-ops-agent/internal/peercred"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
	"github.com/KiritoKing/pi-ops-agent/internal/targetpolicy"
)

const (
	StatePendingApproval  = "PENDING_APPROVAL"
	StateRejected         = "REJECTED"
	StatePreparing        = "PREPARING"
	StateExecuting        = "EXECUTING"
	StateVerifying        = "VERIFYING"
	StateCommitted        = "COMMITTED"
	StateRollingBack      = "ROLLING_BACK"
	StateRolledBack       = "ROLLED_BACK"
	StateRecoveryRequired = "RECOVERY_REQUIRED"
	StateSuperseded       = "SUPERSEDED"
	DomainCore            = "core"
	DomainPVE             = "pve"
)

type Service struct {
	requestMu               sync.Mutex
	inflightRequests        map[string]*inflightRequest
	inflightByUID           map[uint32]int
	changeMu                sync.Mutex
	changeLocks             map[string]*changeLock
	pveWorkerMu             sync.Mutex
	pveWorkers              map[string]struct{}
	clearanceMu             sync.Mutex
	pveRecoveryClearances   map[string]*pveRecoveryClearanceRecord
	AgentUID                uint32
	ApproverUID             uint32
	Store                   *Store
	Audit                   *audit.Log
	Executor                Executor
	Inspector               Inspector
	Policy                  *targetpolicy.Policy
	Approval                *ApprovalVerifier
	ReceiptSigner           *BrokerReceiptSigner
	Now                     func() time.Time
	RollbackTimeout         time.Duration
	PVEReconcileInterval    time.Duration
	PVECommandTimeout       time.Duration
	PVEBackgroundContext    context.Context
	PVERecoveryClearanceTTL time.Duration
	Domain                  string
	ChangeIDPrefix          string
	MaxInflightRequests     int
	MaxInflightPerUID       int
}

type inflightRequest struct {
	uid         uint32
	fingerprint string
	persistent  bool
	done        chan struct{}
	response    protocol.Response
}

type changeLock struct {
	mu   sync.Mutex
	refs int
}

func (s *Service) RecoverInterrupted() error {
	if s.Store == nil || s.Audit == nil {
		return errors.New("root-helper is not initialized")
	}
	if err := s.Store.DurabilityError(); err != nil {
		return err
	}
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	changes, err := s.Store.recoverInterrupted(now)
	if err != nil {
		return err
	}
	recoveryCtx, cancelRecovery := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelRecovery()
	for _, change := range changes {
		if err := s.validateChangeDomain(&change); err != nil {
			return err
		}
		operation, operationErr := protocol.ParseStoredOperation(change.Operation)
		if operationErr == nil {
			if _, ok := s.Executor.(PVEAsyncExecutor); ok && isPVEOperation(operation) &&
				change.PVEMutationVersion >= 1 &&
				(change.State == StateExecuting || change.State == StateVerifying) {
				if _, err := s.Audit.Append(map[string]interface{}{
					"type": "pve_execution_resumed", "changeId": change.ID,
					"planHash": change.PlanHash, "state": change.State,
					"resourceKey": change.ResourceKey,
				}); err != nil {
					return err
				}
				s.ensurePVEWorker(change.ID)
				continue
			}
			if reconciler, ok := s.Executor.(InterruptedChangeReconciler); ok {
				result := ExecutionResult{
					BackupRefs: change.BackupRefs, RollbackData: change.RollbackData,
					RollbackAvailable: change.RollbackAvailable, Verification: change.Verification,
				}
				reconciliation, reconcileErr := reconciler.ReconcileInterruptedChange(recoveryCtx, executionScope(&change), operation, result)
				if reconcileErr == nil && reconciliation.State != "" {
					if reconciliation.State != StateCommitted && reconciliation.State != StateRolledBack {
						return errors.New("interrupted change reconciler returned an unsafe terminal state")
					}
					if mergeErr := mergeChangeEvidence(&change, reconciliation.EvidenceRefs...); mergeErr != nil {
						return mergeErr
					}
					change.State = reconciliation.State
					change.Verification = reconciliation.Verification
					change.LastError = ""
					change.UpdatedAt = timestamp(now)
					if err := s.Store.PutChangeAndReleaseResource(&change); err != nil {
						return err
					}
				} else if reconcileErr != nil {
					detail := reconcileErr.Error()
					if len(detail) > 2048 {
						detail = detail[:2048] + "..."
					}
					message := "interrupted state reconciliation failed: " + detail
					if !strings.Contains(change.LastError, message) {
						if change.LastError != "" {
							change.LastError += "; "
						}
						change.LastError += message
					}
					_ = s.Store.PutChange(&change)
				}
			}
			if provider, ok := s.Executor.(RecoveryEvidenceProvider); ok {
				refs, evidenceErr := provider.RecoverEvidence(recoveryCtx, executionScope(&change), operation)
				if mergeErr := mergeChangeEvidence(&change, refs...); mergeErr != nil && evidenceErr == nil {
					evidenceErr = mergeErr
				}
				if len(refs) > 0 {
					_ = s.Store.PutChange(&change)
				}
				if evidenceErr != nil {
					detail := evidenceErr.Error()
					if len(detail) > 2048 {
						detail = detail[:2048] + "..."
					}
					message := "recovery evidence reconciliation failed: " + detail
					if !strings.Contains(change.LastError, message) {
						if change.LastError != "" {
							change.LastError += "; "
						}
						change.LastError += message
					}
					if len(change.LastError) > 8192 {
						change.LastError = change.LastError[len(change.LastError)-8192:]
					}
					_ = s.Store.PutChange(&change)
				}
			}
		}
		if _, err := s.Audit.Append(map[string]interface{}{
			"type":                "interrupted_change_recovered",
			"changeId":            change.ID,
			"planHash":            change.PlanHash,
			"state":               change.State,
			"error":               change.LastError,
			"backupRefs":          change.BackupRefs,
			"mutationDisposition": change.MutationDisposition,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) Handle(ctx context.Context, peer peercred.Credential, request protocol.Request) (response protocol.Response) {
	response = protocol.Response{Version: protocol.Version, RequestID: request.RequestID}
	if s.Store == nil || s.Audit == nil || s.Executor == nil {
		response.Error = "root-helper is not initialized"
		return response
	}
	if err := s.Store.DurabilityError(); err != nil {
		response.Error = err.Error()
		return response
	}
	if s.ReceiptSigner != nil && !s.ReceiptSigner.ConfiguredFor(s.effectiveDomain()) {
		response.Error = "root broker receipt signer does not match its operation domain"
		return response
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	if !request.Deadline.After(now()) {
		response.Error = "request deadline expired"
		return response
	}
	if err := s.validateRequestDomain(request); err != nil {
		response.Error = err.Error()
		return response
	}
	if s.Policy != nil && requiresCurrentPolicy(request.Method) {
		if err := s.Policy.Authorize(request); err != nil {
			response.Error = err.Error()
			return response
		}
	}
	fingerprint := sha256.Sum256(request.Raw)
	fingerprintText := hex.EncodeToString(fingerprint[:])
	persistentRequest := persistsRequestResult(request.Method)
	inflight, cached, err := s.beginRequest(ctx, request.RequestID, peer.UID, fingerprintText, persistentRequest)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	if inflight == nil {
		if s.ReceiptSigner != nil && protocol.IsBrokerReceiptMethod(request.Method) {
			planHash := ""
			valid := request.Method == protocol.MethodWorkloadCommandInspect
			if !valid {
				change, ok := s.Store.Change(request.ChangeID)
				if ok {
					planHash, valid = change.PlanHash, true
				}
			}
			if !valid || s.ReceiptSigner.Verify(request, cached, planHash, now()) != nil {
				return protocol.Response{Version: protocol.Version, RequestID: request.RequestID, Error: "cached broker response has no valid receipt"}
			}
		}
		return cached
	}
	defer func() {
		s.finishRequest(request.RequestID, inflight, response)
	}()

	var result protocol.Response
	var statusSnapshot *Change
	switch request.Method {
	case protocol.MethodChangePrepare:
		result = s.prepare(ctx, peer, request, fingerprintText, now())
	case protocol.MethodChangeStatus:
		result, statusSnapshot = s.status(peer, request)
	case protocol.MethodChangeApprove:
		unlock := s.lockChange(request.ChangeID)
		result = s.approve(ctx, peer, request, now())
		unlock()
	case protocol.MethodPVERecoveryClearancePrepare:
		unlock := s.lockChange(request.ChangeID)
		result = s.preparePVERecoveryClearance(ctx, peer, request, now())
		unlock()
	case protocol.MethodPVERecoveryClearanceConfirm:
		unlock := s.lockChange(request.ChangeID)
		result = s.confirmPVERecoveryClearance(ctx, peer, request, now())
		unlock()
	case protocol.MethodChangeReject:
		unlock := s.lockChange(request.ChangeID)
		result = s.reject(peer, request, now())
		if result.OK {
			s.revokePVERecoveryClearances(request.ChangeID)
		}
		unlock()
	case protocol.MethodChangeRollback:
		unlock := s.lockChange(request.ChangeID)
		result = s.rollback(ctx, peer, request, now())
		unlock()
	case protocol.MethodHostSnapshot, protocol.MethodProcessList, protocol.MethodSystemdUnit, protocol.MethodJournalTail, protocol.MethodFileMetadata, protocol.MethodFileRead,
		protocol.MethodPVEClusterStatus, protocol.MethodPVENodeStatus, protocol.MethodPVEStorageStatus, protocol.MethodPVETaskStatus, protocol.MethodPVEGuestStatus:
		result = s.inspect(ctx, peer, request)
	case protocol.MethodWorkloadCommandInspect:
		result = s.inspectWorkloadCommand(ctx, peer, request)
	default:
		result = response
		result.Error = "method is not served by root-helper"
	}
	if result.RequestID == "" {
		result.RequestID = request.RequestID
	}
	if result.Version == 0 {
		result.Version = protocol.Version
	}
	if result.AuditID == "" {
		eventType := "request_denied"
		if result.Error == "" {
			eventType = "request_completed"
		}
		if auditID, err := s.appendAudit(peer, request, map[string]interface{}{
			"type":     eventType,
			"changeId": request.ChangeID,
			"error":    result.Error,
		}); err == nil {
			result.AuditID = auditID
		} else {
			return protocol.Response{Version: protocol.Version, RequestID: request.RequestID, Error: "write audit: " + err.Error()}
		}
	}
	if s.ReceiptSigner != nil && protocol.IsBrokerReceiptMethod(request.Method) {
		var signed protocol.Response
		var err error
		if request.Method == protocol.MethodChangeStatus {
			// statusSnapshot is the exact validated Store clone used to build and
			// audit result. Signing that immutable observation avoids a second Store
			// read racing a fast worker transition without blocking observation on
			// the worker's long-running per-change mutation lock.
			signed, err = s.signBrokerResponseFromChangeSnapshot(request, result, statusSnapshot, now())
		} else {
			signed, err = s.signBrokerResponse(request, result, now())
		}
		if err != nil {
			_, _ = s.appendAudit(peer, request, map[string]interface{}{
				"type": "broker_receipt_signing_failed", "changeId": request.ChangeID, "error": err.Error(),
			})
			result = protocol.Response{Version: protocol.Version, RequestID: request.RequestID, Error: "broker receipt unavailable"}
		} else {
			result = signed
		}
	}
	if persistentRequest {
		if err := s.Store.Cache(request.RequestID, peer.UID, fingerprintText, result, request.Deadline); err != nil {
			response = protocol.Response{Version: protocol.Version, RequestID: request.RequestID, Error: "persist request result: " + err.Error()}
			return response
		}
	}
	response = result
	if response.OK && (response.State == StateExecuting || response.State == StateVerifying) && response.ChangeID != "" {
		// Signing and replay-cache persistence above must observe the exact active
		// state returned to the caller. Start (or idempotently ensure) the worker
		// only afterwards so a fast poll or verification cannot race receipt
		// construction. A signed VERIFYING status can therefore repair a missing
		// worker just as a signed EXECUTING response can.
		s.ensurePVEWorker(response.ChangeID)
	}
	return response
}

func (s *Service) signBrokerResponse(request protocol.Request, result protocol.Response, issuedAt time.Time) (protocol.Response, error) {
	if request.Method == protocol.MethodWorkloadCommandInspect {
		if result.ChangeID != "" || result.State != "" {
			return protocol.Response{}, errors.New("workload command inspection returned change state")
		}
		return s.ReceiptSigner.Sign(request, result, "", issuedAt)
	}
	change, ok := s.Store.Change(request.ChangeID)
	if !ok {
		return protocol.Response{}, errors.New("authoritative change is unavailable for receipt signing")
	}
	return s.signBrokerResponseFromChangeSnapshot(request, result, change, issuedAt)
}

func (s *Service) signBrokerResponseFromChangeSnapshot(request protocol.Request, result protocol.Response, change *Change, issuedAt time.Time) (protocol.Response, error) {
	if change == nil {
		return protocol.Response{}, errors.New("authoritative change is unavailable for receipt signing")
	}
	if err := matchChangeIdentity(change, request); err != nil {
		return protocol.Response{}, err
	}
	if err := s.validateChangeDomain(change); err != nil {
		return protocol.Response{}, err
	}
	if result.ChangeID != "" && result.ChangeID != change.ID {
		return protocol.Response{}, errors.New("broker result change ID does not match durable state")
	}
	if result.State != "" && result.State != change.State {
		return protocol.Response{}, errors.New("broker result state changed before receipt signing")
	}
	result.ChangeID = change.ID
	result.State = change.State
	return s.ReceiptSigner.Sign(request, result, change.PlanHash, issuedAt)
}

func (s *Service) beginRequest(ctx context.Context, requestID string, uid uint32, fingerprint string, persistent bool) (*inflightRequest, protocol.Response, error) {
	s.requestMu.Lock()
	if s.inflightRequests == nil {
		s.inflightRequests = make(map[string]*inflightRequest)
	}
	if s.inflightByUID == nil {
		s.inflightByUID = make(map[uint32]int)
	}
	if current, ok := s.inflightRequests[requestID]; ok {
		if current.uid != uid || current.fingerprint != fingerprint {
			s.requestMu.Unlock()
			return nil, protocol.Response{}, errors.New("requestId replayed by another peer or with different content")
		}
		s.requestMu.Unlock()
		select {
		case <-current.done:
			return nil, current.response, nil
		case <-ctx.Done():
			return nil, protocol.Response{}, fmt.Errorf("wait for in-flight request: %w", ctx.Err())
		}
	}
	if persistent {
		cached, ok, err := s.Store.Cached(requestID, uid, fingerprint)
		if err != nil {
			s.requestMu.Unlock()
			return nil, protocol.Response{}, err
		}
		if ok {
			s.requestMu.Unlock()
			return nil, cached, nil
		}
	}
	maxGlobal, maxPerUID := s.MaxInflightRequests, s.MaxInflightPerUID
	if maxGlobal <= 0 {
		maxGlobal = 64
	}
	if maxPerUID <= 0 {
		maxPerUID = 16
	}
	if len(s.inflightRequests) >= maxGlobal || s.inflightByUID[uid] >= maxPerUID {
		s.requestMu.Unlock()
		return nil, protocol.Response{}, errors.New("root broker request concurrency limit reached")
	}
	if persistent {
		if err := s.Store.ReserveRequest(requestID); err != nil {
			s.requestMu.Unlock()
			return nil, protocol.Response{}, err
		}
	}
	current := &inflightRequest{uid: uid, fingerprint: fingerprint, persistent: persistent, done: make(chan struct{})}
	s.inflightRequests[requestID] = current
	s.inflightByUID[uid]++
	s.requestMu.Unlock()
	return current, protocol.Response{}, nil
}

func (s *Service) finishRequest(requestID string, current *inflightRequest, response protocol.Response) {
	s.requestMu.Lock()
	defer s.requestMu.Unlock()
	current.response = response
	close(current.done)
	if s.inflightRequests[requestID] == current {
		delete(s.inflightRequests, requestID)
		s.inflightByUID[current.uid]--
		if s.inflightByUID[current.uid] == 0 {
			delete(s.inflightByUID, current.uid)
		}
	}
	if current.persistent {
		s.Store.ReleaseRequest(requestID)
	}
}

func persistsRequestResult(method protocol.Method) bool {
	switch method {
	case protocol.MethodChangePrepare, protocol.MethodChangeApprove, protocol.MethodChangeReject, protocol.MethodChangeRollback:
		return true
	default:
		return false
	}
}

func (s *Service) lockChange(changeID string) func() {
	s.changeMu.Lock()
	if s.changeLocks == nil {
		s.changeLocks = make(map[string]*changeLock)
	}
	lock, ok := s.changeLocks[changeID]
	if !ok {
		lock = &changeLock{}
		s.changeLocks[changeID] = lock
	}
	lock.refs++
	s.changeMu.Unlock()

	lock.mu.Lock()
	return func() {
		lock.mu.Unlock()
		s.changeMu.Lock()
		lock.refs--
		if lock.refs == 0 && s.changeLocks[changeID] == lock {
			delete(s.changeLocks, changeID)
		}
		s.changeMu.Unlock()
	}
}

func (s *Service) prepare(ctx context.Context, peer peercred.Credential, request protocol.Request, fingerprint string, now time.Time) protocol.Response {
	if !s.isAgentOrApprover(peer.UID) {
		return denied(request, "peer may not prepare changes")
	}
	capabilityRevision := s.effectiveCapabilityRevision()
	if request.CapabilityRevision != "" && request.CapabilityRevision != capabilityRevision {
		return denied(request, "capabilityRevision does not match the broker implementation")
	}
	if validator, ok := s.Executor.(OperationValidator); ok {
		scope := ExecutionScope{TargetID: request.TargetID, PolicyRevision: request.PolicyRevision, CapabilityRevision: capabilityRevision}
		if err := validator.ValidateOperation(scope, request.Operation); err != nil {
			return denied(request, err.Error())
		}
	}
	precondition := OperationPrecondition{}
	if planner, ok := s.Executor.(OperationPlanner); ok {
		planned, err := planner.PlanOperation(ctx, ExecutionScope{
			TargetID: request.TargetID, PolicyRevision: request.PolicyRevision,
			CapabilityRevision: capabilityRevision,
		}, request.Operation)
		if err != nil {
			return denied(request, "prepare authoritative precondition: "+err.Error())
		}
		precondition = planned
	}
	if requiresAuthoritativePrecondition(request.Operation) && (precondition.Digest == "" || len(precondition.Fields) == 0) {
		return denied(request, "operation has no authoritative precondition")
	}
	payload, err := protocol.MarshalOperation(request.Operation)
	if err != nil {
		return failed(request, err)
	}
	approvalPlan, err := protocol.BuildApprovalPlanWithPreconditions(
		request.Operation, request.PolicyRevision, capabilityRevision,
		precondition.Digest, precondition.Fields,
	)
	if err != nil {
		return failed(request, fmt.Errorf("build canonical approval plan: %w", err))
	}
	changeID, err := randomChangeID(s.effectiveChangeIDPrefix())
	if err != nil {
		return failed(request, err)
	}
	change := &Change{
		ID: changeID, ServerID: request.ServerID, MachineID: request.MachineID,
		TargetID: request.TargetID, PolicyRevision: request.PolicyRevision,
		CapabilityRevision: capabilityRevision, PreconditionDigest: precondition.Digest,
		PreconditionFields: append([]protocol.ApprovalPlanField(nil), precondition.Fields...),
		ResourceKey:        operationResourceKey(request.Operation), RecoveryOfChangeID: protocol.PVERecoveryOfChangeID(request.Operation),
		PlanHash: approvalPlan.PlanHash,
		Kind:     request.Operation.Kind(), Summary: request.Operation.Summary(), Operation: payload,
		State: StatePendingApproval, PreparedAt: timestamp(now), UpdatedAt: timestamp(now),
	}
	if isPVEOperation(request.Operation) {
		// v1 guarantees a root-fsynced primary intent before every primary PVE
		// mutation API. Recovery reconciliation may rely on the absence of that
		// intent only for changes carrying this durable version marker.
		change.PVEMutationVersion = 1
	}
	if change.RecoveryOfChangeID != "" {
		if err := s.Store.ValidateRecoveryCandidate(change); err != nil {
			return denied(request, "prepare PVE recovery chain: "+err.Error())
		}
	}
	if err := s.Store.PutChange(change); err != nil {
		return failed(request, err)
	}
	auditID, err := s.appendAudit(peer, request, map[string]interface{}{
		"type": "change_prepared", "changeId": change.ID, "planHash": change.PlanHash,
		"kind": change.Kind, "summary": change.Summary, "recoveryOfChangeId": change.RecoveryOfChangeID,
	})
	if err != nil {
		return failed(request, err)
	}
	prepared := protocol.Response{Version: protocol.Version, RequestID: request.RequestID, OK: true, AuditID: auditID, ChangeID: change.ID, State: change.State, Summary: change.Summary + "; planHash=" + change.PlanHash}
	var basis, standingScope string
	standing := false
	if s.Policy != nil && change.RecoveryOfChangeID == "" {
		basis, standingScope, standing = s.Policy.StandingApproval(request.TargetID, request.Operation)
	}
	if !standing {
		return prepared
	}
	// Standing authorization makes prepare a mutating call. Persist a replay
	// barrier before starting so a broker crash after commit cannot cause the same
	// requestId to create and execute a second change. A retry may see this
	// conservative PENDING response and can resolve the durable terminal state via
	// change.status.
	if err := s.Store.Cache(request.RequestID, peer.UID, fingerprint, prepared, request.Deadline); err != nil {
		return protocol.Response{
			Version: protocol.Version, RequestID: request.RequestID, ChangeID: change.ID,
			State: change.State, Error: "persist standing authorization replay barrier: " + err.Error(),
		}
	}
	return s.executeAuthorizedChange(ctx, peer, request, change, request.Operation, basis, standingScope, nil, now, PVERecoveryReadiness{})
}

func (s *Service) status(peer peercred.Credential, request protocol.Request) (protocol.Response, *Change) {
	if !s.isAgentOrApprover(peer.UID) {
		return denied(request, "peer may not inspect changes"), nil
	}
	change, ok := s.Store.Change(request.ChangeID)
	if !ok {
		return denied(request, "change not found"), nil
	}
	if err := matchChangeIdentity(change, request); err != nil {
		return denied(request, err.Error()), nil
	}
	if err := s.validateChangeDomain(change); err != nil {
		return denied(request, err.Error()), nil
	}
	auditID, err := s.appendAudit(peer, request, map[string]interface{}{"type": "change_status", "changeId": change.ID, "state": change.State})
	if err != nil {
		return failed(request, err), change
	}
	classification, classificationErr := classifyPersistedPlan(change)
	if classificationErr != nil {
		return denied(request, classificationErr.Error()), change
	}
	rollbackAvailable := change.RollbackAvailable
	rollbackUnavailableReason := ""
	var recoveryDescriptor *protocol.RecoveryDescriptor
	if classification.RecoveryOnly {
		descriptor := buildLegacyRecoveryDescriptor(change, classification.Operation, s.Executor)
		if err := descriptor.Validate(); err != nil {
			return failed(request, fmt.Errorf("construct recovery descriptor: %w", err)), change
		}
		recoveryDescriptor = &descriptor
		rollbackAvailable = change.RollbackAvailable && descriptor.RollbackCompatible
		if !rollbackAvailable {
			rollbackUnavailableReason = descriptor.UnavailableReason
		}
	}
	data := changeStatusData{
		ServerID: change.ServerID, MachineID: change.MachineID, TargetID: change.TargetID,
		PolicyRevision: change.PolicyRevision, CapabilityRevision: change.CapabilityRevision,
		PlanHash: change.PlanHash, Kind: change.Kind,
		BackupRefs:   append([]string{}, change.BackupRefs...),
		Verification: change.Verification, RollbackAvailable: rollbackAvailable,
		RollbackUnavailableReason: rollbackUnavailableReason,
		AuthorizationBasis:        change.AuthorizationBasis, AuthorizationScope: change.AuthorizationScope,
		AuthorizedAt: change.AuthorizedAt, LastError: change.LastError,
		RecoveryOfChangeID: change.RecoveryOfChangeID, Resolution: change.Resolution,
		PVEMutationVersion: change.PVEMutationVersion, MutationDisposition: change.MutationDisposition,
		RecoveryOnly: classification.RecoveryOnly, RecoveryDescriptor: recoveryDescriptor,
		Plan: classification.Plan,
	}
	return protocol.Response{Version: protocol.Version, RequestID: request.RequestID, OK: true, AuditID: auditID, ChangeID: change.ID, State: change.State, Summary: change.Summary, Data: data}, change
}

type changeStatusData struct {
	ServerID                  string                          `json:"serverId"`
	MachineID                 string                          `json:"machineId"`
	TargetID                  string                          `json:"targetId"`
	PolicyRevision            string                          `json:"policyRevision"`
	CapabilityRevision        string                          `json:"capabilityRevision"`
	PlanHash                  string                          `json:"planHash"`
	Kind                      string                          `json:"kind"`
	BackupRefs                []string                        `json:"backupRefs"`
	Verification              string                          `json:"verification"`
	RollbackAvailable         bool                            `json:"rollbackAvailable"`
	RollbackUnavailableReason string                          `json:"rollbackUnavailableReason,omitempty"`
	AuthorizationBasis        string                          `json:"authorizationBasis,omitempty"`
	AuthorizationScope        string                          `json:"authorizationScope,omitempty"`
	AuthorizedAt              string                          `json:"authorizedAt,omitempty"`
	LastError                 string                          `json:"lastError,omitempty"`
	RecoveryOfChangeID        string                          `json:"recoveryOfChangeId,omitempty"`
	Resolution                *protocol.PVERecoveryResolution `json:"resolution,omitempty"`
	PVEMutationVersion        int                             `json:"pveMutationVersion,omitempty"`
	MutationDisposition       string                          `json:"mutationDisposition,omitempty"`
	RecoveryOnly              bool                            `json:"recoveryOnly"`
	RecoveryDescriptor        *protocol.RecoveryDescriptor    `json:"recoveryDescriptor,omitempty"`
	Plan                      *protocol.ApprovalPlan          `json:"plan,omitempty"`
}

func (s *Service) approve(ctx context.Context, peer peercred.Credential, request protocol.Request, now time.Time) protocol.Response {
	change, ok := s.Store.Change(request.ChangeID)
	if !ok {
		return denied(request, "change not found")
	}
	if err := matchChangeScope(change, request); err != nil {
		return denied(request, err.Error())
	}
	if err := s.validateChangeDomain(change); err != nil {
		return denied(request, err.Error())
	}
	if change.State != StatePendingApproval {
		return denied(request, "change is not pending approval")
	}
	if change.RecoveryOfChangeID != "" {
		unlockParent := s.lockChange(change.RecoveryOfChangeID)
		defer unlockParent()
	}
	classification, err := classifyPersistedPlan(change)
	if err != nil {
		return denied(request, err.Error())
	}
	if classification.RecoveryOnly {
		return denied(request, "legacy persisted operations are recovery-only and cannot be approved or executed")
	}
	operation := classification.Operation
	if change.CapabilityRevision != s.effectiveCapabilityRevision() {
		return denied(request, "change capabilityRevision is no longer supported by this broker")
	}
	canonicalPlan, err := protocol.BuildApprovalPlanWithPreconditions(
		operation, change.PolicyRevision, change.CapabilityRevision,
		change.PreconditionDigest, change.PreconditionFields,
	)
	if err != nil || canonicalPlan.PlanHash != change.PlanHash {
		return denied(request, "stored change no longer matches its canonical approval plan")
	}
	readiness := PVERecoveryReadiness{}
	if change.RecoveryOfChangeID != "" {
		if err := s.Store.ValidateRecoveryCandidate(change); err != nil {
			return denied(request, "approve PVE recovery chain: "+err.Error())
		}
		if request.ClearanceToken != "" {
			if request.CallerRole != "approver" {
				return denied(request, "PVE recovery clearance requires the model-external approver role")
			}
			if err := s.validatePVERecoveryClearanceReference(change, request.ClearanceToken, now); err != nil {
				return denied(request, "approve PVE recovery unknown clearance: "+err.Error())
			}
		} else {
			readiness, err = s.reconcilePVERecoveryParent(ctx, peer, request, change, now)
			if err != nil {
				return denied(request, "approve PVE recovery parent readiness: "+err.Error())
			}
		}
	} else if request.ClearanceToken != "" {
		return denied(request, "PVE recovery clearance cannot authorize an ordinary change")
	}
	if err := s.authorizeApproval(peer, request, change, "approve", now); err != nil {
		return denied(request, err.Error())
	}
	approvedBy := approvalIdentity(peer, request)
	uid := peer.UID
	return s.executeAuthorizedChange(ctx, peer, request, change, operation, approvedBy, "", &uid, now, readiness)
}

func (s *Service) reconcilePVERecoveryParent(
	ctx context.Context,
	peer peercred.Credential,
	request protocol.Request,
	child *Change,
	now time.Time,
) (PVERecoveryReadiness, error) {
	parent, ok := s.Store.Change(child.RecoveryOfChangeID)
	if !ok {
		return PVERecoveryReadiness{}, errors.New("PVE recovery parent change not found")
	}
	classification, err := classifyPersistedPlan(parent)
	if err != nil {
		return PVERecoveryReadiness{}, err
	}
	if classification.RecoveryOnly || !isPVEOperation(classification.Operation) {
		return PVERecoveryReadiness{}, errors.New("legacy or non-PVE parent requires a dedicated local recovery clearance")
	}
	provider, ok := s.Executor.(PVERecoveryReadinessProvider)
	if !ok {
		return PVERecoveryReadiness{}, errors.New("PVE executor cannot prove parent task terminal state")
	}
	readiness, reconcileErr := provider.ReconcilePVERecoveryParent(ctx, executionScope(parent), classification.Operation)
	if mergeErr := mergeChangeEvidence(parent, readiness.EvidenceRefs...); mergeErr != nil && reconcileErr == nil {
		reconcileErr = mergeErr
	}
	if reconcileErr == nil {
		if err := readiness.Validate(); err != nil {
			reconcileErr = err
		} else {
			parent.MutationDisposition = readiness.MutationDisposition
		}
	}
	if len(readiness.EvidenceRefs) > 0 || reconcileErr == nil {
		parent.UpdatedAt = timestamp(now)
		if err := s.Store.PutChange(parent); err != nil {
			return PVERecoveryReadiness{}, fmt.Errorf("persist PVE parent reconciliation: %w", err)
		}
	}
	if reconcileErr != nil {
		_, _ = s.appendAudit(peer, request, map[string]interface{}{
			"type": "pve_recovery_parent_not_ready", "changeId": child.ID,
			"parentChangeId": parent.ID, "mutationDisposition": parent.MutationDisposition,
			"evidenceRefs": readiness.EvidenceRefs, "error": reconcileErr.Error(),
		})
		return PVERecoveryReadiness{}, reconcileErr
	}
	if _, err := s.appendAudit(peer, request, map[string]interface{}{
		"type": "pve_recovery_parent_reconciled", "changeId": child.ID,
		"parentChangeId": parent.ID, "mutationDisposition": readiness.MutationDisposition,
		"taskEvidence": readiness.TaskEvidence, "evidenceRefs": readiness.EvidenceRefs,
	}); err != nil {
		return PVERecoveryReadiness{}, fmt.Errorf("audit PVE parent reconciliation: %w", err)
	}
	return readiness, nil
}

func (s *Service) recheckTransferredPVERecoveryParent(ctx context.Context, child *Change, expected PVERecoveryReadiness) error {
	parent, ok := s.Store.Change(child.RecoveryOfChangeID)
	if !ok || parent.State != StateSuperseded || parent.Resolution == nil ||
		parent.Resolution.ChildChangeID != child.ID || parent.Resolution.ChildPlanHash != child.PlanHash {
		return errors.New("durable PVE recovery transfer evidence changed")
	}
	operation, err := protocol.ParseStoredOperation(parent.Operation)
	if err != nil {
		return err
	}
	provider, ok := s.Executor.(PVERecoveryReadinessProvider)
	if !ok {
		return errors.New("PVE executor cannot recheck parent task terminal state")
	}
	actual, err := provider.ReconcilePVERecoveryParent(ctx, executionScope(parent), operation)
	if err != nil {
		return err
	}
	if err := actual.Validate(); err != nil {
		return err
	}
	if !samePVERecoveryReadiness(expected, actual) {
		return errors.New("PVE parent terminal task evidence changed across lock transfer")
	}
	return nil
}

func samePVERecoveryReadiness(left, right PVERecoveryReadiness) bool {
	if left.MutationDisposition != right.MutationDisposition || len(left.TaskEvidence) != len(right.TaskEvidence) {
		return false
	}
	for index := range left.TaskEvidence {
		leftEvidence, rightEvidence := left.TaskEvidence[index], right.TaskEvidence[index]
		if leftEvidence.Role != rightEvidence.Role || leftEvidence.Node != rightEvidence.Node ||
			leftEvidence.UPID != rightEvidence.UPID || leftEvidence.Status != rightEvidence.Status ||
			leftEvidence.ExitStatus != rightEvidence.ExitStatus {
			return false
		}
	}
	return true
}

func (s *Service) executeAuthorizedChange(
	ctx context.Context,
	peer peercred.Credential,
	request protocol.Request,
	change *Change,
	operation protocol.Operation,
	authorizationBasis string,
	authorizationScope string,
	approvedByUID *uint32,
	now time.Time,
	recoveryReadiness PVERecoveryReadiness,
) protocol.Response {
	if authorizationBasis == "" {
		return denied(request, "change authorization basis is missing")
	}
	change.ApprovedByUID = approvedByUID
	change.AuthorizationBasis = authorizationBasis
	change.AuthorizationScope = authorizationScope
	change.AuthorizedAt = timestamp(now)
	change.State = StatePreparing
	change.UpdatedAt = timestamp(now)
	var lockErr error
	usedUnknownClearance := false
	if change.RecoveryOfChangeID != "" {
		if request.ClearanceToken != "" {
			lockErr = s.transferPVERecoveryWithClearance(ctx, change, request.ClearanceToken, now)
			usedUnknownClearance = lockErr == nil
		} else {
			lockErr = s.Store.PutRecoveryChangeAndTransferResource(change, recoveryReadiness)
		}
	} else {
		lockErr = s.Store.PutChangeWithResourceLock(change)
	}
	if lockErr != nil {
		return failed(request, lockErr)
	}
	if _, err := s.appendAudit(peer, request, map[string]interface{}{
		"type": "change_approved", "changeId": change.ID, "planHash": change.PlanHash,
		"authorizationBasis": authorizationBasis, "authorizationScope": authorizationScope,
		"recoveryOfChangeId": change.RecoveryOfChangeID,
	}); err != nil {
		change.State = StateRolledBack
		change.LastError = "approval audit failed before mutation; no mutation started: " + err.Error()
		change.UpdatedAt = timestamp(now)
		if change.RecoveryOfChangeID != "" {
			change.State = StateRecoveryRequired
			change.MutationDisposition = protocol.PVEMutationDispositionNotStarted
			change.LastError = "recovery child approval was durable but its audit failed before mutation; the child retains the VMID lock: " + err.Error()
			_ = s.Store.PutChange(change)
		} else {
			_ = s.Store.PutChangeAndReleaseResource(change)
		}
		return failed(request, err)
	}
	if change.RecoveryOfChangeID != "" && !usedUnknownClearance {
		if err := s.recheckTransferredPVERecoveryParent(ctx, change, recoveryReadiness); err != nil {
			change.State = StateRecoveryRequired
			change.MutationDisposition = protocol.PVEMutationDispositionNotStarted
			change.LastError = "recovery parent terminal proof could not be rechecked after lock transfer; no child mutation started: " + err.Error()
			change.UpdatedAt = timestamp(now)
			_ = s.Store.PutChange(change)
			auditID, _ := s.appendAudit(peer, request, map[string]interface{}{
				"type": "pve_recovery_parent_recheck_failed", "changeId": change.ID,
				"parentChangeId": change.RecoveryOfChangeID, "state": change.State,
				"noMutation": true, "error": change.LastError,
			})
			return protocol.Response{Version: protocol.Version, RequestID: request.RequestID, AuditID: auditID, ChangeID: change.ID, State: change.State, Error: change.LastError}
		}
	}
	scope := executionScope(change)
	scope.ApprovedBy, scope.ApprovedAt = authorizationBasis, now.UTC()
	scope.RecordEvidence = s.evidenceRecorder(peer, request, change, now)
	result, prepareErr := s.Executor.Prepare(ctx, scope, operation)
	if prepareErr != nil {
		uncertain := mutationOutcomeUncertain(prepareErr)
		change.State = StateRolledBack
		change.LastError = "preparation failed before mutation; no mutation started: " + prepareErr.Error()
		if uncertain || change.RecoveryOfChangeID != "" {
			change.State = StateRecoveryRequired
			change.MutationDisposition = protocol.PVEMutationDispositionUnknown
			if change.RecoveryOfChangeID != "" && !uncertain {
				change.MutationDisposition = protocol.PVEMutationDispositionNotStarted
				change.LastError = "recovery child preparation failed after parent lock transfer; the child retains the VMID lock: " + prepareErr.Error()
			} else {
				change.LastError = "preparation task outcome requires recovery before mutation: " + prepareErr.Error()
			}
		}
		change.UpdatedAt = timestamp(now)
		if change.State == StateRecoveryRequired {
			_ = s.Store.PutChange(change)
		} else {
			_ = s.Store.PutChangeAndReleaseResource(change)
		}
		auditID, _ := s.appendAudit(peer, request, map[string]interface{}{
			"type": "change_preparation_failed", "changeId": change.ID, "state": change.State,
			"noMutation": !uncertain, "error": change.LastError,
			"authorizationBasis": authorizationBasis, "authorizationScope": authorizationScope,
		})
		return protocol.Response{Version: protocol.Version, RequestID: request.RequestID, AuditID: auditID, ChangeID: change.ID, State: change.State, Error: change.LastError}
	}
	if err := mergeChangeEvidence(change, result.BackupRefs...); err != nil {
		change.State = StateRecoveryRequired
		if isPVEOperation(operation) {
			change.MutationDisposition = protocol.PVEMutationDispositionNotStarted
		}
		change.LastError = "invalid preparation evidence: " + err.Error()
		_ = s.Store.PutChange(change)
		return failed(request, errors.New(change.LastError))
	}
	change.RollbackData, change.RollbackAvailable = result.RollbackData, result.RollbackAvailable
	change.State = StateExecuting
	change.UpdatedAt = timestamp(now)
	// This fsync-backed store write is the mutation barrier. Execute must never run
	// before authoritative rollback metadata and EXECUTING are durable.
	if err := s.Store.PutChange(change); err != nil {
		change.State = StateRolledBack
		change.LastError = "persist mutation barrier failed before mutation; no mutation started: " + err.Error()
		change.UpdatedAt = timestamp(now)
		if change.RecoveryOfChangeID != "" {
			change.State = StateRecoveryRequired
			change.MutationDisposition = protocol.PVEMutationDispositionNotStarted
			change.LastError = "persist recovery child mutation barrier failed after parent lock transfer; the child remains conservatively unresolved: " + err.Error()
			_ = s.Store.PutChange(change)
		} else {
			_ = s.Store.PutChangeAndReleaseResource(change)
		}
		return failed(request, fmt.Errorf("persist mutation barrier: %w", err))
	}
	if _, err := s.appendAudit(peer, request, map[string]interface{}{
		"type": "change_execution_started", "changeId": change.ID, "planHash": change.PlanHash,
		"backupRefs": change.BackupRefs, "rollbackAvailable": change.RollbackAvailable,
		"authorizationBasis": authorizationBasis, "authorizationScope": authorizationScope,
	}); err != nil {
		change.State = StateRolledBack
		change.LastError = "execution audit failed before mutation; no mutation started: " + err.Error()
		change.UpdatedAt = timestamp(now)
		if change.RecoveryOfChangeID != "" {
			change.State = StateRecoveryRequired
			change.MutationDisposition = protocol.PVEMutationDispositionNotStarted
			change.LastError = "recovery child execution audit failed after parent lock transfer; the child retains the VMID lock: " + err.Error()
			_ = s.Store.PutChange(change)
		} else {
			_ = s.Store.PutChangeAndReleaseResource(change)
		}
		return failed(request, err)
	}
	if asyncExecutor, ok := s.Executor.(PVEAsyncExecutor); ok && isPVEOperation(operation) {
		stepCtx, cancelStep := s.pveStepContext()
		step, stepErr := asyncExecutor.StepPVEExecution(stepCtx, scope, operation, result)
		cancelStep()
		if stepErr != nil {
			return s.handleFailure(
				peer, request, change, operation, result,
				"PVE execution start failed: "+stepErr.Error(), mutationOutcomeUncertain(stepErr),
				noMutationStarted(stepErr), false, false, s.currentTime(),
			)
		}
		if err := step.Validate(); err != nil || step.Complete {
			if err == nil {
				err = errors.New("PVE executor completed without first exposing a durable running UPID")
			}
			return s.handleFailure(
				peer, request, change, operation, result,
				"invalid PVE async execution step: "+err.Error(), true, false,
				false, false, s.currentTime(),
			)
		}
		if _, err := applyPVEExecutionResult(change, step.Result); err != nil {
			return s.handleFailure(
				peer, request, change, operation, result,
				"persist PVE execution checkpoint: "+err.Error(), true, false,
				false, false, s.currentTime(),
			)
		}
		change.UpdatedAt = timestamp(s.currentTime())
		if err := s.Store.PutChange(change); err != nil {
			return s.handleFailure(
				peer, request, change, operation, step.Result,
				"persist PVE running task checkpoint: "+err.Error(), true, false,
				false, false, s.currentTime(),
			)
		}
		auditID, err := s.appendAudit(peer, request, map[string]interface{}{
			"type": "pve_execution_detached", "changeId": change.ID,
			"planHash": change.PlanHash, "state": change.State, "taskRole": step.Role,
			"node": step.Node, "upid": step.UPID, "resourceKey": change.ResourceKey,
		})
		if err != nil {
			return s.handleFailure(
				peer, request, change, operation, step.Result,
				"audit detached PVE execution: "+err.Error(), true, false,
				false, false, s.currentTime(),
			)
		}
		return protocol.Response{
			Version: protocol.Version, RequestID: request.RequestID, OK: true,
			AuditID: auditID, ChangeID: change.ID, State: change.State,
			Summary: "PVE task started and is executing asynchronously; query the signed change status for completion",
		}
	}
	executionErr := s.Executor.Execute(ctx, scope, operation, result)
	if executionErr != nil {
		mutationAttempted, exchangeRestored := mutationAttemptEvidence(executionErr)
		return s.handleFailure(
			peer, request, change, operation, result,
			"execution failed: "+executionErr.Error(),
			mutationOutcomeUncertain(executionErr), noMutationStarted(executionErr),
			mutationAttempted, exchangeRestored, now,
		)
	}
	change.State, change.UpdatedAt = StateVerifying, timestamp(now)
	if err := s.Store.PutChange(change); err != nil {
		return failed(request, err)
	}
	verification, verifyErr := s.Executor.Verify(ctx, scope, operation, result)
	if result.Verification != "" && verification == "" {
		verification = result.Verification
	}
	change.Verification = verification
	if verifyErr != nil {
		return s.handleFailure(
			peer, request, change, operation, result,
			"verification failed: "+verifyErr.Error(), mutationOutcomeUncertain(verifyErr), false,
			false, false, now,
		)
	}
	change.State, change.UpdatedAt = StateCommitted, timestamp(now)
	if err := s.Store.PutChangeAndReleaseResource(change); err != nil {
		return failed(request, err)
	}
	auditID, err := s.appendAudit(peer, request, map[string]interface{}{
		"type": "change_committed", "changeId": change.ID, "planHash": change.PlanHash,
		"verification": change.Verification, "backupRefs": change.BackupRefs,
		"authorizationBasis": authorizationBasis, "authorizationScope": authorizationScope,
	})
	if err != nil {
		return failed(request, err)
	}
	return protocol.Response{Version: protocol.Version, RequestID: request.RequestID, OK: true, AuditID: auditID, ChangeID: change.ID, State: change.State, Summary: "change committed: " + change.Summary}
}

func (s *Service) currentTime() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) pveStepContext() (context.Context, context.CancelFunc) {
	base := s.PVEBackgroundContext
	if base == nil {
		base = context.Background()
	}
	timeout := s.PVECommandTimeout
	if timeout <= 0 || timeout > 2*time.Minute {
		timeout = 30 * time.Second
	}
	return context.WithTimeout(base, timeout)
}

func (s *Service) pveReconcileInterval() time.Duration {
	interval := s.PVEReconcileInterval
	if interval <= 0 || interval > time.Minute {
		return time.Second
	}
	return interval
}

func (s *Service) ensurePVEWorker(changeID string) {
	if changeID == "" {
		return
	}
	if _, ok := s.Executor.(PVEAsyncExecutor); !ok {
		return
	}
	base := s.PVEBackgroundContext
	if base == nil {
		base = context.Background()
	}
	select {
	case <-base.Done():
		return
	default:
	}
	s.pveWorkerMu.Lock()
	if s.pveWorkers == nil {
		s.pveWorkers = make(map[string]struct{})
	}
	if _, running := s.pveWorkers[changeID]; running {
		s.pveWorkerMu.Unlock()
		return
	}
	s.pveWorkers[changeID] = struct{}{}
	s.pveWorkerMu.Unlock()
	go func() {
		defer func() {
			s.pveWorkerMu.Lock()
			delete(s.pveWorkers, changeID)
			s.pveWorkerMu.Unlock()
		}()
		s.runPVEWorker(base, changeID)
	}()
}

func (s *Service) runPVEWorker(base context.Context, changeID string) {
	asyncExecutor, ok := s.Executor.(PVEAsyncExecutor)
	if !ok {
		return
	}
	waitBeforeStep := true
	for {
		if waitBeforeStep {
			timer := time.NewTimer(s.pveReconcileInterval())
			select {
			case <-base.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return
			case <-timer.C:
			}
		}
		waitBeforeStep = true
		unlock := s.lockChange(changeID)
		change, exists := s.Store.Change(changeID)
		if !exists || (change.State != StateExecuting && change.State != StateVerifying) {
			unlock()
			return
		}
		classification, err := classifyPersistedPlan(change)
		if err != nil || classification.RecoveryOnly || !isPVEOperation(classification.Operation) ||
			change.PVEMutationVersion < 1 {
			if err == nil {
				err = errors.New("durable async worker found a non-current PVE plan")
			}
			s.failPVEBackground(change, ExecutionResult{
				BackupRefs: change.BackupRefs, RollbackData: change.RollbackData,
				RollbackAvailable: change.RollbackAvailable, Verification: change.Verification,
			}, err, false, false)
			unlock()
			return
		}
		operation := classification.Operation
		result := ExecutionResult{
			BackupRefs:        append([]string(nil), change.BackupRefs...),
			RollbackData:      append([]byte(nil), change.RollbackData...),
			RollbackAvailable: change.RollbackAvailable, Verification: change.Verification,
		}
		scope := executionScope(change)
		scope.ApprovedBy = change.AuthorizationBasis
		if approvedAt, parseErr := time.Parse(time.RFC3339Nano, change.AuthorizedAt); parseErr == nil {
			scope.ApprovedAt = approvedAt
		}
		scope.RecordEvidence = s.pveBackgroundEvidenceRecorder(change)
		if change.State == StateExecuting {
			stepCtx, cancelStep := s.pveStepContext()
			step, stepErr := asyncExecutor.StepPVEExecution(stepCtx, scope, operation, result)
			cancelStep()
			if stepErr != nil {
				if base.Err() != nil && errors.Is(stepErr, base.Err()) {
					// A daemon shutdown cancels only the in-process observer. The
					// durable UPID and VMID lock remain EXECUTING for restart; treating
					// SIGTERM as a task failure would fabricate RECOVERY_REQUIRED.
					unlock()
					return
				}
				s.failPVEBackground(
					change, result, fmt.Errorf("PVE async execution failed: %w", stepErr),
					mutationOutcomeUncertain(stepErr), noMutationStarted(stepErr),
				)
				unlock()
				return
			}
			if err := step.Validate(); err != nil {
				s.failPVEBackground(change, result, fmt.Errorf("invalid PVE async step: %w", err), true, false)
				unlock()
				return
			}
			changed, err := applyPVEExecutionResult(change, step.Result)
			if err != nil {
				s.failPVEBackground(change, result, fmt.Errorf("apply PVE async checkpoint: %w", err), true, false)
				unlock()
				return
			}
			if step.Running {
				if changed {
					change.UpdatedAt = timestamp(s.currentTime())
					if err := s.Store.PutChange(change); err != nil {
						s.failPVEBackground(change, step.Result, fmt.Errorf("persist PVE async checkpoint: %w", err), true, false)
						unlock()
						return
					}
					_, _ = s.Audit.Append(map[string]interface{}{
						"type": "pve_execution_checkpoint", "changeId": change.ID,
						"state": change.State, "taskRole": step.Role, "node": step.Node,
						"upid": step.UPID, "backupRefs": change.BackupRefs,
					})
				}
				unlock()
				continue
			}
			change.State = StateVerifying
			change.UpdatedAt = timestamp(s.currentTime())
			if err := s.Store.PutChange(change); err != nil {
				s.failPVEBackground(change, step.Result, fmt.Errorf("persist PVE terminal-task checkpoint: %w", err), true, false)
				unlock()
				return
			}
			if _, err := s.Audit.Append(map[string]interface{}{
				"type": "pve_execution_tasks_terminal", "changeId": change.ID,
				"planHash": change.PlanHash, "state": change.State, "backupRefs": change.BackupRefs,
			}); err != nil {
				s.failPVEBackground(change, step.Result, fmt.Errorf("audit PVE terminal-task checkpoint: %w", err), true, false)
				unlock()
				return
			}
			result = step.Result
			waitBeforeStep = false
			unlock()
			continue
		}

		verifyCtx, cancelVerify := s.pveStepContext()
		verification, verifyErr := s.Executor.Verify(verifyCtx, scope, operation, result)
		cancelVerify()
		if result.Verification != "" && verification == "" {
			verification = result.Verification
		}
		change.Verification = verification
		if verifyErr != nil {
			if base.Err() != nil && errors.Is(verifyErr, base.Err()) {
				unlock()
				return
			}
			s.failPVEBackground(
				change, result, fmt.Errorf("PVE async verification failed: %w", verifyErr),
				mutationOutcomeUncertain(verifyErr), false,
			)
			unlock()
			return
		}
		change.State = StateCommitted
		change.LastError = ""
		change.UpdatedAt = timestamp(s.currentTime())
		if err := s.Store.PutChangeAndReleaseResource(change); err != nil {
			// The resource must remain locked on a pre-commit store error. The
			// fail-stop Store also prevents any later mutation after an uncertain
			// post-rename durability result.
			s.failPVEBackground(change, result, fmt.Errorf("persist PVE async commit: %w", err), true, false)
			unlock()
			return
		}
		_, _ = s.Audit.Append(map[string]interface{}{
			"type": "change_committed", "source": "pve-broker-reconciler",
			"changeId": change.ID, "planHash": change.PlanHash,
			"verification": change.Verification, "backupRefs": change.BackupRefs,
			"authorizationBasis": change.AuthorizationBasis,
			"authorizationScope": change.AuthorizationScope,
		})
		unlock()
		return
	}
}

func applyPVEExecutionResult(change *Change, result ExecutionResult) (bool, error) {
	if result.RollbackAvailable {
		return false, errors.New("PVE async execution cannot expose automatic rollback")
	}
	beforeRefs := append([]string(nil), change.BackupRefs...)
	if err := mergeChangeEvidence(change, result.BackupRefs...); err != nil {
		return false, err
	}
	changed := !sameStrings(beforeRefs, change.BackupRefs) ||
		!bytes.Equal(change.RollbackData, result.RollbackData) ||
		change.RollbackAvailable != result.RollbackAvailable
	change.RollbackData = append([]byte(nil), result.RollbackData...)
	change.RollbackAvailable = false
	return changed, nil
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (s *Service) pveBackgroundEvidenceRecorder(change *Change) func(...string) error {
	return func(refs ...string) error {
		if err := mergeChangeEvidence(change, refs...); err != nil {
			return err
		}
		change.UpdatedAt = timestamp(s.currentTime())
		if err := s.Store.PutChange(change); err != nil {
			return err
		}
		_, err := s.Audit.Append(map[string]interface{}{
			"type": "change_evidence_recorded", "source": "pve-broker-reconciler",
			"changeId": change.ID, "evidenceRefs": refs,
		})
		return err
	}
}

func (s *Service) failPVEBackground(
	change *Change,
	result ExecutionResult,
	err error,
	uncertain bool,
	noMutation bool,
) {
	_, _ = applyPVEExecutionResult(change, result)
	change.State = StateRecoveryRequired
	change.MutationDisposition = protocol.PVEMutationDispositionUnknown
	if noMutation && !uncertain {
		change.MutationDisposition = protocol.PVEMutationDispositionNotStarted
		if change.RecoveryOfChangeID == "" {
			change.State = StateRolledBack
		}
	}
	change.LastError = err.Error()
	if len(change.LastError) > 8192 {
		change.LastError = change.LastError[:8192]
	}
	change.UpdatedAt = timestamp(s.currentTime())
	if change.State == StateRolledBack {
		_ = s.Store.PutChangeAndReleaseResource(change)
	} else {
		_ = s.Store.PutChange(change)
	}
	_, _ = s.Audit.Append(map[string]interface{}{
		"type": "change_failed", "source": "pve-broker-reconciler",
		"changeId": change.ID, "state": change.State, "error": change.LastError,
		"backupRefs": change.BackupRefs, "noMutation": noMutation && !uncertain,
		"mutationDisposition": change.MutationDisposition,
		"authorizationBasis":  change.AuthorizationBasis,
		"authorizationScope":  change.AuthorizationScope,
	})
}

func (s *Service) reject(peer peercred.Credential, request protocol.Request, now time.Time) protocol.Response {
	change, ok := s.Store.Change(request.ChangeID)
	if !ok {
		return denied(request, "change not found")
	}
	if err := matchChangeIdentity(change, request); err != nil {
		return denied(request, err.Error())
	}
	if err := s.validateChangeDomain(change); err != nil {
		return denied(request, err.Error())
	}
	if change.State != StatePendingApproval {
		return denied(request, "change is not pending approval")
	}
	if err := s.authorizeApproval(peer, request, change, "reject", now); err != nil {
		return denied(request, err.Error())
	}
	change.State, change.UpdatedAt = StateRejected, timestamp(now)
	if err := s.Store.PutRejectedChange(change); err != nil {
		return failed(request, err)
	}
	auditID, err := s.appendAudit(peer, request, map[string]interface{}{"type": "change_rejected", "changeId": change.ID, "planHash": change.PlanHash})
	if err != nil {
		return failed(request, err)
	}
	return protocol.Response{Version: protocol.Version, RequestID: request.RequestID, OK: true, AuditID: auditID, ChangeID: change.ID, State: change.State, Summary: "change rejected"}
}

func (s *Service) rollback(ctx context.Context, peer peercred.Credential, request protocol.Request, now time.Time) protocol.Response {
	change, ok := s.Store.Change(request.ChangeID)
	if !ok {
		return denied(request, "change not found")
	}
	if err := matchChangeIdentity(change, request); err != nil {
		return denied(request, err.Error())
	}
	if err := s.validateChangeDomain(change); err != nil {
		return denied(request, err.Error())
	}
	if change.State != StateCommitted && change.State != StateRecoveryRequired {
		return denied(request, "change is not eligible for rollback")
	}
	if !change.RollbackAvailable {
		return denied(request, "rollback is unavailable for this change")
	}
	classification, err := classifyPersistedPlan(change)
	if err != nil {
		return denied(request, err.Error())
	}
	operation := classification.Operation
	if isPVEOperation(operation) {
		return denied(request, "PVE compensation must be prepared as a new typed change with current preconditions and approval")
	}
	if classification.RecoveryOnly {
		descriptor := buildLegacyRecoveryDescriptor(change, operation, s.Executor)
		if err := descriptor.Validate(); err != nil || !descriptor.RollbackCompatible {
			if descriptor.UnavailableReason != "" {
				return denied(request, "automated legacy rollback is unavailable: "+descriptor.UnavailableReason)
			}
			return denied(request, "automated legacy rollback is unavailable")
		}
	} else if !protocol.StoredRollbackSupported(operation) {
		return denied(request, "automated rollback is unavailable for this persisted operation")
	}
	if err := s.authorizeApproval(peer, request, change, "rollback", now); err != nil {
		return denied(request, err.Error())
	}
	change.State, change.UpdatedAt = StateRollingBack, timestamp(now)
	if err := s.Store.PutChange(change); err != nil {
		return failed(request, err)
	}
	result := ExecutionResult{BackupRefs: change.BackupRefs, RollbackData: change.RollbackData, RollbackAvailable: change.RollbackAvailable, Verification: change.Verification}
	rollbackCtx, cancel := s.rollbackContext()
	defer cancel()
	if err := s.Executor.Rollback(rollbackCtx, executionScope(change), operation, result); err != nil {
		change.State = StateRecoveryRequired
		change.LastError = "rollback failed: " + err.Error()
		change.UpdatedAt = timestamp(now)
		_ = s.Store.PutChange(change)
		return failed(request, errors.New(change.LastError))
	}
	change.State, change.UpdatedAt, change.LastError = StateRolledBack, timestamp(now), ""
	if err := s.Store.PutChangeAndReleaseResource(change); err != nil {
		return failed(request, err)
	}
	auditID, err := s.appendAudit(peer, request, map[string]interface{}{"type": "change_rolled_back", "changeId": change.ID, "planHash": change.PlanHash})
	if err != nil {
		return failed(request, err)
	}
	return protocol.Response{Version: protocol.Version, RequestID: request.RequestID, OK: true, AuditID: auditID, ChangeID: change.ID, State: change.State, Summary: "change rolled back"}
}

func (s *Service) handleFailure(peer peercred.Credential, request protocol.Request, change *Change, operation protocol.Operation, result ExecutionResult, message string, uncertain bool, noMutation bool, mutationAttempted bool, exchangeRestored bool, now time.Time) protocol.Response {
	change.LastError, change.State, change.UpdatedAt = message, StateRecoveryRequired, timestamp(now)
	if isPVEOperation(operation) {
		change.MutationDisposition = protocol.PVEMutationDispositionUnknown
		if noMutation && !uncertain {
			change.MutationDisposition = protocol.PVEMutationDispositionNotStarted
		}
	}
	if noMutation && !uncertain && change.RecoveryOfChangeID == "" {
		change.State = StateRolledBack
	} else if result.RollbackAvailable && !uncertain {
		change.State = StateRollingBack
		_ = s.Store.PutChange(change)
		rollbackCtx, cancel := s.rollbackContext()
		err := s.Executor.Rollback(rollbackCtx, executionScope(change), operation, result)
		cancel()
		if err == nil {
			change.State = StateRolledBack
		} else {
			change.LastError += "; rollback failed: " + err.Error()
			change.State = StateRecoveryRequired
		}
	}
	if change.State == StateRolledBack {
		_ = s.Store.PutChangeAndReleaseResource(change)
	} else {
		_ = s.Store.PutChange(change)
	}
	auditID, _ := s.appendAudit(peer, request, map[string]interface{}{
		"type": "change_failed", "changeId": change.ID, "state": change.State,
		"error": change.LastError, "backupRefs": change.BackupRefs, "noMutation": noMutation && !uncertain,
		"mutationAttempted": mutationAttempted, "exchangeRestored": exchangeRestored,
		"authorizationBasis": change.AuthorizationBasis, "authorizationScope": change.AuthorizationScope,
		"mutationDisposition": change.MutationDisposition,
	})
	return protocol.Response{Version: protocol.Version, RequestID: request.RequestID, AuditID: auditID, ChangeID: change.ID, State: change.State, Error: change.LastError}
}

func (s *Service) rollbackContext() (context.Context, context.CancelFunc) {
	timeout := s.RollbackTimeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	return context.WithTimeout(context.Background(), timeout)
}

func executionScope(change *Change) ExecutionScope {
	return ExecutionScope{
		ChangeID: change.ID, TargetID: change.TargetID,
		PolicyRevision: change.PolicyRevision, CapabilityRevision: change.CapabilityRevision,
		PreconditionDigest: change.PreconditionDigest, PlanHash: change.PlanHash,
		PVEMutationVersion: change.PVEMutationVersion, MutationDisposition: change.MutationDisposition,
	}
}

func (s *Service) effectiveDomain() string {
	if s.Domain == "" {
		return DomainCore
	}
	return s.Domain
}

func (s *Service) effectiveCapabilityRevision() string {
	return protocol.CapabilityRevision
}

func (s *Service) effectiveChangeIDPrefix() string {
	if s.ChangeIDPrefix != "" {
		return s.ChangeIDPrefix
	}
	if s.effectiveDomain() == DomainPVE {
		return "pve-change-"
	}
	return "change-"
}

func (s *Service) validateRequestDomain(request protocol.Request) error {
	domain := s.effectiveDomain()
	if domain != DomainCore && domain != DomainPVE {
		return errors.New("root broker has an invalid operation domain")
	}
	expectedPrefix := "change-"
	if domain == DomainPVE {
		expectedPrefix = "pve-change-"
	}
	if s.effectiveChangeIDPrefix() != expectedPrefix {
		return errors.New("root broker change id prefix does not match its operation domain")
	}
	isInspection := isPVEInspectionMethod(request.Method)
	isPreparePVE := request.Method == protocol.MethodChangePrepare && isPVEOperation(request.Operation)
	isChangeAction := request.Method == protocol.MethodChangeStatus || request.Method == protocol.MethodChangeApprove ||
		request.Method == protocol.MethodChangeReject || request.Method == protocol.MethodChangeRollback ||
		request.Method == protocol.MethodPVERecoveryClearancePrepare || request.Method == protocol.MethodPVERecoveryClearanceConfirm
	if domain == DomainPVE {
		if isInspection || isPreparePVE || isChangeAction {
			return nil
		}
		return errors.New("PVE root broker rejects core operations")
	}
	if isInspection || isPreparePVE {
		return errors.New("core root broker rejects PVE operations")
	}
	return nil
}

func (s *Service) validateChangeDomain(change *Change) error {
	operation, err := protocol.ParseStoredOperation(change.Operation)
	if err != nil {
		return err
	}
	isPVE := isPVEOperation(operation)
	if s.effectiveDomain() == DomainPVE && !isPVE {
		return errors.New("PVE root broker rejects a core change")
	}
	if s.effectiveDomain() == DomainPVE && !strings.HasPrefix(change.ID, "pve-change-") {
		return errors.New("PVE root broker rejects a change outside its id domain")
	}
	if s.effectiveDomain() == DomainCore && isPVE {
		return errors.New("core root broker rejects a PVE change")
	}
	return nil
}

func isPVEInspectionMethod(method protocol.Method) bool {
	switch method {
	case protocol.MethodPVEClusterStatus, protocol.MethodPVENodeStatus, protocol.MethodPVEStorageStatus,
		protocol.MethodPVETaskStatus, protocol.MethodPVEGuestStatus:
		return true
	default:
		return false
	}
}

func (s *Service) evidenceRecorder(peer peercred.Credential, request protocol.Request, change *Change, approvedAt time.Time) func(...string) error {
	return func(refs ...string) error {
		if err := mergeChangeEvidence(change, refs...); err != nil {
			return err
		}
		updatedAt := approvedAt
		if s.Now != nil {
			updatedAt = s.Now()
		} else {
			updatedAt = time.Now()
		}
		change.UpdatedAt = timestamp(updatedAt)
		if err := s.Store.PutChange(change); err != nil {
			return err
		}
		_, err := s.appendAudit(peer, request, map[string]interface{}{
			"type": "change_evidence_recorded", "changeId": change.ID, "evidenceRefs": refs,
		})
		return err
	}
}

func mergeChangeEvidence(change *Change, refs ...string) error {
	seen := make(map[string]struct{}, len(change.BackupRefs)+len(refs))
	for _, ref := range change.BackupRefs {
		seen[ref] = struct{}{}
	}
	for _, ref := range refs {
		if strings.HasPrefix(change.ResourceKey, "pve/") {
			if !validPVEEvidenceRef(ref) {
				return fmt.Errorf("invalid PVE evidence reference")
			}
		} else if ref == "" || len(ref) > 4096 || strings.ContainsAny(ref, "\x00\r\n") {
			return fmt.Errorf("invalid recovery evidence reference")
		}
		if _, exists := seen[ref]; exists {
			continue
		}
		if len(change.BackupRefs) >= 32 {
			return errors.New("too many PVE evidence references")
		}
		change.BackupRefs = append(change.BackupRefs, ref)
		seen[ref] = struct{}{}
	}
	return nil
}

func approvalIdentity(peer peercred.Credential, request protocol.Request) string {
	if request.Approval != nil {
		return "approval-key:" + request.Approval.KeyID
	}
	return "local-uid:" + strconv.FormatUint(uint64(peer.UID), 10)
}

func (s *Service) isAgentOrApprover(uid uint32) bool {
	return uid == s.AgentUID || uid == s.ApproverUID
}
func (s *Service) authorizeApproval(peer peercred.Credential, request protocol.Request, change *Change, action string, now time.Time) error {
	if peer.UID == s.ApproverUID && request.CallerRole == "" {
		return nil
	}
	if s.Policy == nil || peer.UID != s.AgentUID || (request.CallerRole != "approver" && request.CallerRole != "admin") {
		return errors.New("only the configured local approver or a signed remote approval may authorize this action")
	}
	if request.Approval == nil {
		return errors.New("remote change action requires a signed approval grant")
	}
	if s.Approval == nil {
		return errors.New("remote change action requires a configured approval verifier")
	}
	if err := s.Approval.Verify(*request.Approval, action, change, now); err != nil {
		return err
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, request.Approval.ExpiresAt)
	if err != nil {
		return errors.New("approval grant expiry is invalid")
	}
	if err := s.Store.UseApprovalNonce(request.Approval.Nonce, change.ID, expiresAt); err != nil {
		return err
	}
	return nil
}
func (s *Service) isAdmin(peer peercred.Credential, request protocol.Request) bool {
	if peer.UID == s.ApproverUID && request.CallerRole == "" {
		return true
	}
	return s.Policy != nil && peer.UID == s.AgentUID && request.CallerRole == "admin"
}
func matchChangeScope(change *Change, request protocol.Request) error {
	if err := matchChangeIdentity(change, request); err != nil {
		return err
	}
	if change.PolicyRevision != request.PolicyRevision {
		return errors.New("change scope does not match server, machine, target, or policy revision")
	}
	return nil
}

func matchChangeIdentity(change *Change, request protocol.Request) error {
	if change.ServerID != request.ServerID || change.MachineID != request.MachineID || change.TargetID != request.TargetID {
		return errors.New("change scope does not match server, machine, or target")
	}
	return nil
}

func requiresCurrentPolicy(method protocol.Method) bool {
	switch method {
	case protocol.MethodChangeStatus, protocol.MethodChangeReject, protocol.MethodChangeRollback:
		return false
	default:
		return true
	}
}
func (s *Service) appendAudit(peer peercred.Credential, request protocol.Request, event interface{}) (string, error) {
	return s.Audit.Append(map[string]interface{}{
		"peer":      map[string]interface{}{"pid": peer.PID, "uid": peer.UID, "gid": peer.GID},
		"requestId": request.RequestID, "method": request.Method, "serverId": request.ServerID,
		"machineId": request.MachineID, "targetId": request.TargetID, "policyRevision": request.PolicyRevision,
		"callerRole": request.CallerRole, "event": event,
	})
}
func denied(request protocol.Request, message string) protocol.Response {
	return protocol.Response{Version: protocol.Version, RequestID: request.RequestID, Error: message}
}
func failed(request protocol.Request, err error) protocol.Response {
	return protocol.Response{Version: protocol.Version, RequestID: request.RequestID, Error: err.Error()}
}
func randomChangeID(prefix string) (string, error) {
	if prefix != "change-" && prefix != "pve-change-" {
		return "", errors.New("unsupported change id prefix")
	}
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value), nil
}
