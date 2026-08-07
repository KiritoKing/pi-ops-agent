package roothelper

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
)

type Service struct {
	mu              sync.Mutex
	AgentUID        uint32
	ApproverUID     uint32
	Store           *Store
	Audit           *audit.Log
	Executor        Executor
	Inspector       Inspector
	Policy          *targetpolicy.Policy
	Approval        *ApprovalVerifier
	Now             func() time.Time
	RollbackTimeout time.Duration
}

func (s *Service) RecoverInterrupted() error {
	if s.Store == nil || s.Audit == nil {
		return errors.New("root-helper is not initialized")
	}
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	changes, err := s.Store.recoverInterrupted(now)
	if err != nil {
		return err
	}
	for _, change := range changes {
		if _, err := s.Audit.Append(map[string]interface{}{
			"type":       "interrupted_change_recovered",
			"changeId":   change.ID,
			"planHash":   change.PlanHash,
			"state":      change.State,
			"error":      change.LastError,
			"backupRefs": change.BackupRefs,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) Handle(ctx context.Context, peer peercred.Credential, request protocol.Request) protocol.Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	response := protocol.Response{Version: protocol.Version, RequestID: request.RequestID}
	if s.Store == nil || s.Audit == nil || s.Executor == nil {
		response.Error = "root-helper is not initialized"
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
	if s.Policy != nil && requiresCurrentPolicy(request.Method) {
		if err := s.Policy.Authorize(request); err != nil {
			response.Error = err.Error()
			return response
		}
	}
	fingerprint := sha256.Sum256(request.Raw)
	fingerprintText := hex.EncodeToString(fingerprint[:])
	if cached, ok, err := s.Store.Cached(request.RequestID, peer.UID, fingerprintText); err != nil {
		response.Error = err.Error()
		return response
	} else if ok {
		return cached
	}

	var result protocol.Response
	switch request.Method {
	case protocol.MethodChangePrepare:
		result = s.prepare(peer, request, now())
	case protocol.MethodChangeStatus:
		result = s.status(peer, request)
	case protocol.MethodChangeApprove:
		result = s.approve(ctx, peer, request, now())
	case protocol.MethodChangeReject:
		result = s.reject(peer, request, now())
	case protocol.MethodChangeRollback:
		result = s.rollback(ctx, peer, request, now())
	case protocol.MethodHostSnapshot, protocol.MethodProcessList, protocol.MethodSystemdUnit, protocol.MethodJournalTail, protocol.MethodFileMetadata, protocol.MethodFileRead:
		result = s.inspect(ctx, peer, request)
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
	if err := s.Store.Cache(request.RequestID, peer.UID, fingerprintText, result); err != nil {
		return protocol.Response{Version: protocol.Version, RequestID: request.RequestID, Error: "persist request result: " + err.Error()}
	}
	return result
}

func (s *Service) prepare(peer peercred.Credential, request protocol.Request, now time.Time) protocol.Response {
	if !s.isAgentOrApprover(peer.UID) {
		return denied(request, "peer may not prepare changes")
	}
	if validator, ok := s.Executor.(OperationValidator); ok {
		scope := ExecutionScope{TargetID: request.TargetID, PolicyRevision: request.PolicyRevision, CapabilityRevision: request.CapabilityRevision}
		if err := validator.ValidateOperation(scope, request.Operation); err != nil {
			return denied(request, err.Error())
		}
	}
	payload, err := protocol.MarshalOperation(request.Operation)
	if err != nil {
		return failed(request, err)
	}
	planInput := append([]byte(request.ServerID+"\x00"+request.MachineID+"\x00"+request.TargetID+"\x00"+request.PolicyRevision+"\x00"+request.CapabilityRevision+"\x00"), payload...)
	plan := sha256.Sum256(planInput)
	changeID, err := randomChangeID()
	if err != nil {
		return failed(request, err)
	}
	change := &Change{ID: changeID, ServerID: request.ServerID, MachineID: request.MachineID, TargetID: request.TargetID, PolicyRevision: request.PolicyRevision, CapabilityRevision: request.CapabilityRevision, PlanHash: "sha256:" + hex.EncodeToString(plan[:]), Kind: request.Operation.Kind(), Summary: request.Operation.Summary(), Operation: payload, State: StatePendingApproval, PreparedAt: timestamp(now), UpdatedAt: timestamp(now)}
	if err := s.Store.PutChange(change); err != nil {
		return failed(request, err)
	}
	auditID, err := s.appendAudit(peer, request, map[string]interface{}{"type": "change_prepared", "changeId": change.ID, "planHash": change.PlanHash, "kind": change.Kind, "summary": change.Summary})
	if err != nil {
		return failed(request, err)
	}
	return protocol.Response{Version: protocol.Version, RequestID: request.RequestID, OK: true, AuditID: auditID, ChangeID: change.ID, State: change.State, Summary: change.Summary + "; planHash=" + change.PlanHash}
}

func (s *Service) status(peer peercred.Credential, request protocol.Request) protocol.Response {
	if !s.isAgentOrApprover(peer.UID) {
		return denied(request, "peer may not inspect changes")
	}
	change, ok := s.Store.Change(request.ChangeID)
	if !ok {
		return denied(request, "change not found")
	}
	if err := matchChangeIdentity(change, request); err != nil {
		return denied(request, err.Error())
	}
	auditID, err := s.appendAudit(peer, request, map[string]interface{}{"type": "change_status", "changeId": change.ID, "state": change.State})
	if err != nil {
		return failed(request, err)
	}
	data := map[string]interface{}{"serverId": change.ServerID, "machineId": change.MachineID, "targetId": change.TargetID, "policyRevision": change.PolicyRevision, "planHash": change.PlanHash, "kind": change.Kind, "backupRefs": change.BackupRefs, "verification": change.Verification, "rollbackAvailable": change.RollbackAvailable}
	if change.LastError != "" {
		data["lastError"] = change.LastError
	}
	return protocol.Response{Version: protocol.Version, RequestID: request.RequestID, OK: true, AuditID: auditID, ChangeID: change.ID, State: change.State, Summary: change.Summary, Data: data}
}

func (s *Service) approve(ctx context.Context, peer peercred.Credential, request protocol.Request, now time.Time) protocol.Response {
	change, ok := s.Store.Change(request.ChangeID)
	if !ok {
		return denied(request, "change not found")
	}
	if err := matchChangeScope(change, request); err != nil {
		return denied(request, err.Error())
	}
	if change.State != StatePendingApproval {
		return denied(request, "change is not pending approval")
	}
	operation, err := protocol.ParseStoredOperation(change.Operation)
	if err != nil {
		return failed(request, err)
	}
	if protocol.IsStoredOnlyOperation(operation) {
		return denied(request, "legacy persisted operations are recovery-only and cannot be approved or executed")
	}
	if err := s.authorizeApproval(peer, request, change, "approve", now); err != nil {
		return denied(request, err.Error())
	}
	uid := peer.UID
	change.ApprovedByUID = &uid
	change.State = StatePreparing
	change.UpdatedAt = timestamp(now)
	if err := s.Store.PutChange(change); err != nil {
		return failed(request, err)
	}
	if _, err := s.appendAudit(peer, request, map[string]interface{}{"type": "change_approved", "changeId": change.ID, "planHash": change.PlanHash}); err != nil {
		return failed(request, err)
	}
	scope := executionScope(change)
	result, prepareErr := s.Executor.Prepare(ctx, scope, operation)
	if prepareErr != nil {
		change.State = StateRecoveryRequired
		change.LastError = "backup preparation failed before mutation: " + prepareErr.Error()
		change.UpdatedAt = timestamp(now)
		_ = s.Store.PutChange(change)
		auditID, _ := s.appendAudit(peer, request, map[string]interface{}{
			"type": "change_preparation_failed", "changeId": change.ID, "error": change.LastError,
		})
		return protocol.Response{Version: protocol.Version, RequestID: request.RequestID, AuditID: auditID, ChangeID: change.ID, State: change.State, Error: change.LastError}
	}
	change.BackupRefs, change.RollbackData, change.RollbackAvailable = result.BackupRefs, result.RollbackData, result.RollbackAvailable
	change.State = StateExecuting
	change.UpdatedAt = timestamp(now)
	// This fsync-backed store write is the mutation barrier. Execute must never run
	// before authoritative rollback metadata and EXECUTING are durable.
	if err := s.Store.PutChange(change); err != nil {
		return failed(request, fmt.Errorf("persist mutation barrier: %w", err))
	}
	if _, err := s.appendAudit(peer, request, map[string]interface{}{
		"type": "change_execution_started", "changeId": change.ID, "planHash": change.PlanHash,
		"backupRefs": change.BackupRefs, "rollbackAvailable": change.RollbackAvailable,
	}); err != nil {
		return failed(request, err)
	}
	executionErr := s.Executor.Execute(ctx, scope, operation, result)
	if executionErr != nil {
		return s.handleFailure(peer, request, change, operation, result, "execution failed: "+executionErr.Error(), now)
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
		return s.handleFailure(peer, request, change, operation, result, "verification failed: "+verifyErr.Error(), now)
	}
	change.State, change.UpdatedAt = StateCommitted, timestamp(now)
	if err := s.Store.PutChange(change); err != nil {
		return failed(request, err)
	}
	auditID, err := s.appendAudit(peer, request, map[string]interface{}{"type": "change_committed", "changeId": change.ID, "planHash": change.PlanHash, "verification": change.Verification, "backupRefs": change.BackupRefs})
	if err != nil {
		return failed(request, err)
	}
	return protocol.Response{Version: protocol.Version, RequestID: request.RequestID, OK: true, AuditID: auditID, ChangeID: change.ID, State: change.State, Summary: "change committed: " + change.Summary}
}

func (s *Service) reject(peer peercred.Credential, request protocol.Request, now time.Time) protocol.Response {
	change, ok := s.Store.Change(request.ChangeID)
	if !ok {
		return denied(request, "change not found")
	}
	if err := matchChangeIdentity(change, request); err != nil {
		return denied(request, err.Error())
	}
	if change.State != StatePendingApproval {
		return denied(request, "change is not pending approval")
	}
	if err := s.authorizeApproval(peer, request, change, "reject", now); err != nil {
		return denied(request, err.Error())
	}
	change.State, change.UpdatedAt = StateRejected, timestamp(now)
	if err := s.Store.PutChange(change); err != nil {
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
	if change.State != StateCommitted && change.State != StateRecoveryRequired {
		return denied(request, "change is not eligible for rollback")
	}
	if !change.RollbackAvailable {
		return denied(request, "rollback is unavailable for this change")
	}
	operation, err := protocol.ParseStoredOperation(change.Operation)
	if err != nil {
		return failed(request, err)
	}
	if !protocol.StoredRollbackSupported(operation) {
		return denied(request, "automated rollback is unavailable for this legacy persisted operation")
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
	if err := s.Store.PutChange(change); err != nil {
		return failed(request, err)
	}
	auditID, err := s.appendAudit(peer, request, map[string]interface{}{"type": "change_rolled_back", "changeId": change.ID, "planHash": change.PlanHash})
	if err != nil {
		return failed(request, err)
	}
	return protocol.Response{Version: protocol.Version, RequestID: request.RequestID, OK: true, AuditID: auditID, ChangeID: change.ID, State: change.State, Summary: "change rolled back"}
}

func (s *Service) handleFailure(peer peercred.Credential, request protocol.Request, change *Change, operation protocol.Operation, result ExecutionResult, message string, now time.Time) protocol.Response {
	change.LastError, change.State, change.UpdatedAt = message, StateRecoveryRequired, timestamp(now)
	if result.RollbackAvailable {
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
	_ = s.Store.PutChange(change)
	auditID, _ := s.appendAudit(peer, request, map[string]interface{}{"type": "change_failed", "changeId": change.ID, "state": change.State, "error": change.LastError, "backupRefs": change.BackupRefs})
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
	}
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
	if err := s.Approval.Verify(*request.Approval, action, change, now); err != nil {
		return err
	}
	if err := s.Store.UseApprovalNonce(request.Approval.Nonce, change.ID); err != nil {
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
func randomChangeID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "change-" + hex.EncodeToString(value), nil
}
