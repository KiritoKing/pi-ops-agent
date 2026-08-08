package roothelper

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/peercred"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

const (
	defaultPVERecoveryClearanceTTL = 90 * time.Second
	maxPVERecoveryClearances       = 64
)

type pveRecoveryClearanceRecord struct {
	challenge           protocol.PVERecoveryClearanceChallenge
	confirmed           bool
	token               string
	approvalFingerprint string
}

func (s *Service) preparePVERecoveryClearance(
	ctx context.Context,
	peer peercred.Credential,
	request protocol.Request,
	now time.Time,
) protocol.Response {
	if err := s.authorizePVERecoveryClearanceControl(peer, request); err != nil {
		return denied(request, err.Error())
	}
	child, operation, err := s.pveRecoveryClearanceChild(request)
	if err != nil {
		return denied(request, err.Error())
	}
	unlockParent := s.lockChange(child.RecoveryOfChangeID)
	defer unlockParent()
	if err := s.Store.ValidateRecoveryCandidate(child); err != nil {
		return denied(request, "prepare PVE recovery clearance: "+err.Error())
	}
	if _, err := s.reconcilePVERecoveryParent(ctx, peer, request, child, now); err == nil {
		result := protocol.PVERecoveryClearancePrepareResult{
			Kind: "pve.recovery-clearance-prepare-result/v1", Required: false,
		}
		auditID, auditErr := s.appendAudit(peer, request, map[string]interface{}{
			"type": "pve_recovery_clearance_not_required", "changeId": child.ID,
			"parentChangeId": child.RecoveryOfChangeID,
		})
		if auditErr != nil {
			return failed(request, fmt.Errorf("audit PVE recovery clearance result: %w", auditErr))
		}
		return protocol.Response{Version: protocol.Version, RequestID: request.RequestID, OK: true, AuditID: auditID, ChangeID: child.ID, State: child.State, Data: result}
	}

	parent, ok := s.Store.Change(child.RecoveryOfChangeID)
	if !ok || parent.State != StateRecoveryRequired || parent.MutationDisposition != protocol.PVEMutationDispositionUnknown {
		return denied(request, "PVE recovery parent is no longer unresolved STARTED_OR_UNKNOWN")
	}
	parentClassification, err := classifyPersistedPlan(parent)
	if err != nil || parentClassification.RecoveryOnly || !isPVEOperation(parentClassification.Operation) {
		return denied(request, "legacy or invalid PVE recovery parent cannot receive this clearance")
	}
	provider, ok := s.Executor.(PVEUnknownRecoveryClearanceProvider)
	if !ok {
		return denied(request, "PVE executor cannot collect unknown-recovery clearance evidence")
	}
	observation, err := provider.ObservePVEUnknownRecoveryParent(ctx, executionScope(parent), parentClassification.Operation)
	if err != nil {
		return denied(request, "prepare PVE recovery clearance observation: "+err.Error())
	}
	if err := observation.Validate(); err != nil {
		return denied(request, "PVE recovery clearance observation is invalid: "+err.Error())
	}
	// Re-read the child after all live queries so a challenge cannot bind stale
	// canonical plan state.
	currentChild, currentOperation, err := s.pveRecoveryClearanceChild(request)
	if err != nil || currentChild.ID != child.ID || currentChild.PlanHash != child.PlanHash || currentOperation.Kind() != operation.Kind() {
		return denied(request, "PVE recovery child drifted while collecting clearance evidence")
	}
	clearanceID, err := randomPVERecoveryClearanceID()
	if err != nil {
		return failed(request, err)
	}
	ttl := s.PVERecoveryClearanceTTL
	if ttl <= 0 || ttl > 2*time.Minute {
		ttl = defaultPVERecoveryClearanceTTL
	}
	now = now.UTC()
	challenge, err := protocol.FinalizePVERecoveryClearanceChallenge(protocol.PVERecoveryClearanceChallenge{
		Kind: "pve.recovery-clearance-challenge/v1", ClearanceID: clearanceID,
		ParentChangeID: child.RecoveryOfChangeID, ChildChangeID: child.ID,
		ChildPlanHash: child.PlanHash, ResourceKey: child.ResourceKey, Observation: observation,
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(ttl).Format(time.RFC3339Nano),
	})
	if err != nil {
		return failed(request, err)
	}
	s.clearanceMu.Lock()
	s.prunePVERecoveryClearancesLocked(now)
	if s.pveRecoveryClearances == nil {
		s.pveRecoveryClearances = make(map[string]*pveRecoveryClearanceRecord)
	}
	for id, record := range s.pveRecoveryClearances {
		if record.challenge.ChildChangeID == child.ID {
			delete(s.pveRecoveryClearances, id)
		}
	}
	if len(s.pveRecoveryClearances) >= maxPVERecoveryClearances {
		s.clearanceMu.Unlock()
		return denied(request, "PVE recovery clearance capacity is exhausted")
	}
	s.pveRecoveryClearances[clearanceID] = &pveRecoveryClearanceRecord{challenge: challenge}
	s.clearanceMu.Unlock()
	auditID, err := s.appendAudit(peer, request, map[string]interface{}{
		"type": "pve_recovery_clearance_challenged", "changeId": child.ID,
		"parentChangeId": child.RecoveryOfChangeID, "resourceKey": child.ResourceKey,
		"challengeDigest":    challenge.ChallengeDigest,
		"observationDigest":  challenge.Observation.ObservationDigest,
		"activeTaskDigest":   challenge.Observation.ActiveTaskDigest,
		"guestStateDigest":   challenge.Observation.GuestStateDigest,
		"clusterStateDigest": challenge.Observation.ClusterStateDigest,
		"expiresAt":          challenge.ExpiresAt,
	})
	if err != nil {
		s.revokePVERecoveryClearances(child.ID)
		return failed(request, fmt.Errorf("audit PVE recovery clearance challenge: %w", err))
	}
	result := protocol.PVERecoveryClearancePrepareResult{
		Kind: "pve.recovery-clearance-prepare-result/v1", Required: true, Challenge: &challenge,
	}
	return protocol.Response{Version: protocol.Version, RequestID: request.RequestID, OK: true, AuditID: auditID, ChangeID: child.ID, State: child.State, Data: result}
}

func (s *Service) confirmPVERecoveryClearance(
	ctx context.Context,
	peer peercred.Credential,
	request protocol.Request,
	now time.Time,
) protocol.Response {
	if err := s.authorizePVERecoveryClearanceControl(peer, request); err != nil {
		return denied(request, err.Error())
	}
	if request.ClearanceApproval == nil || s.Approval == nil {
		return denied(request, "PVE recovery clearance confirmation requires a trusted signed approval")
	}
	child, _, err := s.pveRecoveryClearanceChild(request)
	if err != nil {
		return denied(request, err.Error())
	}
	unlockParent := s.lockChange(child.RecoveryOfChangeID)
	defer unlockParent()
	now = now.UTC()
	approval := *request.ClearanceApproval
	fingerprint, err := pveClearanceApprovalFingerprint(approval)
	if err != nil {
		return denied(request, err.Error())
	}
	s.clearanceMu.Lock()
	s.prunePVERecoveryClearancesLocked(now)
	record, ok := s.pveRecoveryClearances[approval.ClearanceID]
	if !ok {
		s.clearanceMu.Unlock()
		return denied(request, "PVE recovery clearance challenge is missing, expired, stale, or was revoked")
	}
	challenge := record.challenge
	if record.confirmed {
		if record.approvalFingerprint != fingerprint {
			s.clearanceMu.Unlock()
			return denied(request, "PVE recovery clearance confirmation was replayed with different content")
		}
		grant := protocol.PVERecoveryClearanceGrant{
			Kind: "pve.recovery-clearance-grant/v1", ClearanceToken: record.token,
			ChallengeDigest: challenge.ChallengeDigest, ExpiresAt: challenge.ExpiresAt,
		}
		s.clearanceMu.Unlock()
		return s.confirmedPVERecoveryClearanceResponse(peer, request, child, grant, true)
	}
	s.clearanceMu.Unlock()
	if err := s.Approval.VerifyPVERecoveryClearance(approval, challenge, child, now); err != nil {
		return denied(request, err.Error())
	}
	if err := s.Store.ValidateRecoveryCandidate(child); err != nil {
		s.revokePVERecoveryClearances(child.ID)
		return denied(request, "PVE recovery chain drifted before clearance confirmation: "+err.Error())
	}
	parent, ok := s.Store.Change(child.RecoveryOfChangeID)
	if !ok || parent.MutationDisposition != protocol.PVEMutationDispositionUnknown {
		s.revokePVERecoveryClearances(child.ID)
		return denied(request, "PVE recovery parent disposition drifted before clearance confirmation")
	}
	classification, err := classifyPersistedPlan(parent)
	if err != nil || classification.RecoveryOnly || !isPVEOperation(classification.Operation) {
		s.revokePVERecoveryClearances(child.ID)
		return denied(request, "PVE recovery parent is no longer eligible for clearance")
	}
	provider, ok := s.Executor.(PVEUnknownRecoveryClearanceProvider)
	if !ok {
		return denied(request, "PVE executor cannot re-observe unknown-recovery clearance state")
	}
	actual, err := provider.ObservePVEUnknownRecoveryParent(ctx, executionScope(parent), classification.Operation)
	if err != nil || !samePVERecoveryClearanceObservation(challenge.Observation, actual) {
		s.revokePVERecoveryClearances(child.ID)
		if err != nil {
			return denied(request, "PVE recovery clearance state could not be re-observed: "+err.Error())
		}
		return denied(request, "PVE recovery clearance state changed before confirmation")
	}
	expiresAt, _ := time.Parse(time.RFC3339Nano, approval.ExpiresAt)
	if err := s.Store.UseApprovalNonce(approval.Nonce, child.ID, expiresAt); err != nil {
		return denied(request, err.Error())
	}
	token, err := randomPVERecoveryClearanceID()
	if err != nil {
		return failed(request, err)
	}
	s.clearanceMu.Lock()
	s.prunePVERecoveryClearancesLocked(now)
	record, ok = s.pveRecoveryClearances[approval.ClearanceID]
	if !ok || record.confirmed || record.challenge.ChallengeDigest != challenge.ChallengeDigest {
		s.clearanceMu.Unlock()
		return denied(request, "PVE recovery clearance challenge changed during confirmation")
	}
	record.confirmed, record.token, record.approvalFingerprint = true, token, fingerprint
	grant := protocol.PVERecoveryClearanceGrant{
		Kind: "pve.recovery-clearance-grant/v1", ClearanceToken: token,
		ChallengeDigest: challenge.ChallengeDigest, ExpiresAt: challenge.ExpiresAt,
	}
	s.clearanceMu.Unlock()
	return s.confirmedPVERecoveryClearanceResponse(peer, request, child, grant, false)
}

func (s *Service) confirmedPVERecoveryClearanceResponse(
	peer peercred.Credential,
	request protocol.Request,
	child *Change,
	grant protocol.PVERecoveryClearanceGrant,
	replayed bool,
) protocol.Response {
	auditID, err := s.appendAudit(peer, request, map[string]interface{}{
		"type": "pve_recovery_clearance_confirmed", "changeId": child.ID,
		"parentChangeId": child.RecoveryOfChangeID, "challengeDigest": grant.ChallengeDigest,
		"expiresAt": grant.ExpiresAt, "idempotentReplay": replayed,
	})
	if err != nil {
		s.revokePVERecoveryClearances(child.ID)
		return failed(request, fmt.Errorf("audit PVE recovery clearance confirmation: %w", err))
	}
	return protocol.Response{Version: protocol.Version, RequestID: request.RequestID, OK: true, AuditID: auditID, ChangeID: child.ID, State: child.State, Data: grant}
}

func (s *Service) validatePVERecoveryClearanceReference(change *Change, token string, now time.Time) error {
	if token == "" || !protocol.ValidPVERecoveryClearanceToken(token) {
		return errors.New("PVE recovery clearance token is missing or invalid")
	}
	s.clearanceMu.Lock()
	defer s.clearanceMu.Unlock()
	s.prunePVERecoveryClearancesLocked(now.UTC())
	record := s.pveRecoveryClearanceByTokenLocked(token)
	if record == nil || !record.confirmed || record.challenge.ChildChangeID != change.ID ||
		record.challenge.ParentChangeID != change.RecoveryOfChangeID || record.challenge.ChildPlanHash != change.PlanHash ||
		record.challenge.ResourceKey != change.ResourceKey {
		return errors.New("PVE recovery clearance grant is missing, stale, expired, or does not bind this change")
	}
	return nil
}

func (s *Service) transferPVERecoveryWithClearance(
	ctx context.Context,
	change *Change,
	token string,
	now time.Time,
) error {
	if err := s.validatePVERecoveryClearanceReference(change, token, now); err != nil {
		return err
	}
	s.clearanceMu.Lock()
	record := s.pveRecoveryClearanceByTokenLocked(token)
	if record == nil || !record.confirmed || record.token != token ||
		record.challenge.ChildChangeID != change.ID || record.challenge.ParentChangeID != change.RecoveryOfChangeID ||
		record.challenge.ChildPlanHash != change.PlanHash || record.challenge.ResourceKey != change.ResourceKey {
		s.clearanceMu.Unlock()
		return errors.New("PVE unknown-clearance grant was revoked or rebound before final observation")
	}
	challenge := record.challenge
	s.clearanceMu.Unlock()
	parent, ok := s.Store.Change(change.RecoveryOfChangeID)
	if !ok || parent.State != StateRecoveryRequired || parent.MutationDisposition != protocol.PVEMutationDispositionUnknown {
		s.revokePVERecoveryClearances(change.ID)
		return errors.New("PVE recovery parent changed before unknown-clearance transfer")
	}
	classification, err := classifyPersistedPlan(parent)
	if err != nil || classification.RecoveryOnly || !isPVEOperation(classification.Operation) {
		s.revokePVERecoveryClearances(change.ID)
		return errors.New("PVE recovery parent is no longer eligible for unknown-clearance transfer")
	}
	provider, ok := s.Executor.(PVEUnknownRecoveryClearanceProvider)
	if !ok {
		return errors.New("PVE executor cannot perform final unknown-clearance observation")
	}
	actual, err := provider.ObservePVEUnknownRecoveryParent(ctx, executionScope(parent), classification.Operation)
	if err != nil || !samePVERecoveryClearanceObservation(challenge.Observation, actual) {
		s.revokePVERecoveryClearances(change.ID)
		if err != nil {
			return fmt.Errorf("final PVE unknown-clearance observation failed: %w", err)
		}
		return errors.New("PVE unknown-clearance observation changed before atomic lock transfer")
	}
	currentNow := now.UTC()
	if s.Now != nil {
		currentNow = s.Now().UTC()
	}
	s.clearanceMu.Lock()
	defer s.clearanceMu.Unlock()
	s.prunePVERecoveryClearancesLocked(currentNow)
	record = s.pveRecoveryClearanceByTokenLocked(token)
	if record == nil || !record.confirmed || record.token != token ||
		record.challenge.ChallengeDigest != challenge.ChallengeDigest ||
		record.challenge.ChildChangeID != change.ID || record.challenge.ParentChangeID != change.RecoveryOfChangeID ||
		record.challenge.ChildPlanHash != change.PlanHash || record.challenge.ResourceKey != change.ResourceKey {
		return errors.New("PVE unknown-clearance grant expired or was revoked before lock transfer")
	}
	if err := s.Store.PutRecoveryChangeAndTransferResourceWithClearance(change, challenge); err != nil {
		return err
	}
	delete(s.pveRecoveryClearances, challenge.ClearanceID)
	return nil
}

func (s *Service) pveRecoveryClearanceChild(request protocol.Request) (*Change, protocol.Operation, error) {
	child, ok := s.Store.Change(request.ChangeID)
	if !ok {
		return nil, nil, errors.New("PVE recovery child change not found")
	}
	if err := matchChangeScope(child, request); err != nil {
		return nil, nil, err
	}
	if err := s.validateChangeDomain(child); err != nil {
		return nil, nil, err
	}
	if child.State != StatePendingApproval || child.RecoveryOfChangeID == "" {
		return nil, nil, errors.New("PVE recovery clearance requires a pending recovery child")
	}
	classification, err := classifyPersistedPlan(child)
	if err != nil || classification.RecoveryOnly || !isPVEOperation(classification.Operation) {
		return nil, nil, errors.New("PVE recovery clearance child has no current canonical PVE plan")
	}
	canonical, err := protocol.BuildApprovalPlanWithPreconditions(
		classification.Operation, child.PolicyRevision, child.CapabilityRevision,
		child.PreconditionDigest, child.PreconditionFields,
	)
	if err != nil || canonical.PlanHash != child.PlanHash {
		return nil, nil, errors.New("PVE recovery clearance child no longer matches its canonical plan")
	}
	return child, classification.Operation, nil
}

func (s *Service) authorizePVERecoveryClearanceControl(peer peercred.Credential, request protocol.Request) error {
	if s.effectiveDomain() != DomainPVE || s.Policy == nil || peer.UID != s.AgentUID || request.CallerRole != "approver" {
		return errors.New("PVE recovery clearance is restricted to the model-external local approver path")
	}
	return nil
}

func (s *Service) revokePVERecoveryClearances(changeID string) {
	s.clearanceMu.Lock()
	defer s.clearanceMu.Unlock()
	for id, record := range s.pveRecoveryClearances {
		if record.challenge.ChildChangeID == changeID {
			delete(s.pveRecoveryClearances, id)
		}
	}
}

func (s *Service) prunePVERecoveryClearancesLocked(now time.Time) {
	for id, record := range s.pveRecoveryClearances {
		expires, err := time.Parse(time.RFC3339Nano, record.challenge.ExpiresAt)
		if err != nil || !now.Before(expires) {
			delete(s.pveRecoveryClearances, id)
		}
	}
}

func (s *Service) pveRecoveryClearanceByTokenLocked(token string) *pveRecoveryClearanceRecord {
	for _, record := range s.pveRecoveryClearances {
		if record.token == token {
			return record
		}
	}
	return nil
}

func samePVERecoveryClearanceObservation(left, right protocol.PVERecoveryClearanceObservation) bool {
	return left.ObservationDigest == right.ObservationDigest &&
		left.ActiveTaskDigest == right.ActiveTaskDigest && left.GuestStateDigest == right.GuestStateDigest &&
		left.ClusterStateDigest == right.ClusterStateDigest && left.Validate() == nil && right.Validate() == nil
}

func randomPVERecoveryClearanceID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate PVE recovery clearance identifier: %w", err)
	}
	return "pve-clearance-" + hex.EncodeToString(value), nil
}

func pveClearanceApprovalFingerprint(approval protocol.PVERecoveryClearanceApproval) (string, error) {
	payload, err := json.Marshal(approval)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}
