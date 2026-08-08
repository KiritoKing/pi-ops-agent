package approvalsubmit

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

type pveRecoveryClearanceDisplay struct {
	Version   int                                    `json:"version"`
	Warning   string                                 `json:"warning"`
	Challenge protocol.PVERecoveryClearanceChallenge `json:"challenge"`
}

func (s Submitter) obtainPVERecoveryClearance(
	ctx context.Context,
	remote Remote,
	clearanceRemote PVERecoveryClearanceRemote,
	server LoadedServer,
	request Request,
	status ChangeStatus,
	privateKey ed25519.PrivateKey,
) (string, error) {
	prepareID, err := randomID(s.Random, "clearance-prepare-")
	if err != nil {
		return "", err
	}
	prepare, err := clearanceRemote.PreparePVERecoveryClearance(ctx, request, prepareID, s.Now().UTC().Add(30*time.Second))
	if err != nil {
		return "", err
	}
	if err := validateHelperResponse(prepare, prepareID); err != nil {
		return "", err
	}
	if err := s.verifyBrokerResponse(server, request, prepareID, protocol.MethodPVERecoveryClearancePrepare, status.PlanHash, prepare); err != nil {
		return "", fmt.Errorf("verify PVE recovery clearance preparation receipt: %w", err)
	}
	if !prepare.OK {
		return "", fmt.Errorf("PVE recovery clearance preparation denied: %s", prepare.Error)
	}
	if prepare.ChangeID != request.ChangeID || prepare.State != "PENDING_APPROVAL" {
		return "", errors.New("PVE recovery clearance preparation returned a mismatched change state")
	}
	var prepared protocol.PVERecoveryClearancePrepareResult
	if err := strictDecode(prepare.Data, &prepared); err != nil {
		return "", fmt.Errorf("decode PVE recovery clearance preparation: %w", err)
	}
	if prepared.Kind != "pve.recovery-clearance-prepare-result/v1" {
		return "", errors.New("PVE recovery clearance preparation has an invalid kind")
	}
	if !prepared.Required {
		if prepared.Challenge != nil {
			return "", errors.New("unneeded PVE recovery clearance unexpectedly contains a challenge")
		}
		return "", nil
	}
	if prepared.Challenge == nil {
		return "", errors.New("required PVE recovery clearance has no challenge")
	}
	challenge := *prepared.Challenge
	if err := challenge.Validate(); err != nil {
		return "", fmt.Errorf("validate PVE recovery clearance challenge: %w", err)
	}
	if challenge.ParentChangeID != status.RecoveryOfChangeID || challenge.ChildChangeID != request.ChangeID ||
		challenge.ChildPlanHash != status.PlanHash {
		return "", errors.New("PVE recovery clearance challenge does not match the authoritative child and parent")
	}
	display, err := json.MarshalIndent(pveRecoveryClearanceDisplay{
		Version:   protocol.Version,
		Warning:   "LOCAL UNKNOWN-RESULT CLEARANCE: the parent remains STARTED_OR_UNKNOWN. This one-shot authorization transfers the VMID lock only if active tasks are still empty and the exact guest/cluster state is unchanged.",
		Challenge: challenge,
	}, "", "  ")
	if err != nil {
		return "", err
	}
	display = []byte(asciiOnlyJSON(string(display)))
	confirmation := pveRecoveryClearanceConfirmationText(request, challenge)
	if err := s.Confirmer.Confirm(display, confirmation); err != nil {
		return "", err
	}
	// The normal ApprovalPlan was already confirmed once. Refetch it after the
	// independent unknown-result confirmation so neither human decision can be
	// replayed onto a changed child.
	third, thirdStatus, err := s.fetchStatus(ctx, remote, server, request)
	if err != nil {
		return "", err
	}
	if !third.OK || !sameStatusBinding(status, thirdStatus) {
		return "", errors.New("authoritative PVE recovery child drifted during unknown-result confirmation")
	}
	approval, err := signPVERecoveryClearanceApproval(
		request, status, challenge, server.Registration.ApprovalKeyID, privateKey, s.Now().UTC(), s.Random,
	)
	if err != nil {
		return "", err
	}
	confirmID, err := randomID(s.Random, "clearance-confirm-")
	if err != nil {
		return "", err
	}
	confirmed, err := clearanceRemote.ConfirmPVERecoveryClearance(ctx, request, confirmID, s.Now().UTC().Add(30*time.Second), approval)
	if err != nil {
		return "", err
	}
	if err := validateHelperResponse(confirmed, confirmID); err != nil {
		return "", err
	}
	if err := s.verifyBrokerResponse(server, request, confirmID, protocol.MethodPVERecoveryClearanceConfirm, status.PlanHash, confirmed); err != nil {
		return "", fmt.Errorf("verify PVE recovery clearance confirmation receipt: %w", err)
	}
	if !confirmed.OK {
		return "", fmt.Errorf("PVE recovery clearance confirmation denied: %s", confirmed.Error)
	}
	if confirmed.ChangeID != request.ChangeID || confirmed.State != "PENDING_APPROVAL" {
		return "", errors.New("PVE recovery clearance confirmation returned a mismatched change state")
	}
	var grant protocol.PVERecoveryClearanceGrant
	if err := strictDecode(confirmed.Data, &grant); err != nil {
		return "", fmt.Errorf("decode PVE recovery clearance grant: %w", err)
	}
	if grant.Kind != "pve.recovery-clearance-grant/v1" || !protocol.ValidPVERecoveryClearanceToken(grant.ClearanceToken) ||
		grant.ChallengeDigest != challenge.ChallengeDigest || grant.ExpiresAt != challenge.ExpiresAt {
		return "", errors.New("PVE recovery clearance grant does not match the exact confirmed challenge")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, grant.ExpiresAt)
	if err != nil || !s.Now().UTC().Before(expiresAt) {
		return "", errors.New("PVE recovery clearance grant is already expired")
	}
	return grant.ClearanceToken, nil
}

func signPVERecoveryClearanceApproval(
	request Request,
	status ChangeStatus,
	challenge protocol.PVERecoveryClearanceChallenge,
	keyID string,
	privateKey ed25519.PrivateKey,
	now time.Time,
	random io.Reader,
) (protocol.PVERecoveryClearanceApproval, error) {
	if !approvalKeyIDPattern.MatchString(keyID) || len(privateKey) != ed25519.PrivateKeySize || random == nil {
		return protocol.PVERecoveryClearanceApproval{}, errors.New("PVE recovery clearance signing identity is invalid")
	}
	if err := challenge.Validate(); err != nil {
		return protocol.PVERecoveryClearanceApproval{}, err
	}
	challengeExpiry, _ := time.Parse(time.RFC3339Nano, challenge.ExpiresAt)
	now = now.UTC()
	expiresAt := now.Add(approvalTTL)
	if challengeExpiry.Before(expiresAt) {
		expiresAt = challengeExpiry
	}
	if !expiresAt.After(now) {
		return protocol.PVERecoveryClearanceApproval{}, errors.New("PVE recovery clearance challenge expired before signing")
	}
	nonce := make([]byte, 24)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return protocol.PVERecoveryClearanceApproval{}, fmt.Errorf("generate PVE recovery clearance nonce: %w", err)
	}
	approval := protocol.PVERecoveryClearanceApproval{
		Version: protocol.Version, KeyID: keyID, Action: protocol.PVERecoveryClearanceAction,
		ServerID: request.ServerID, MachineID: request.MachineID, TargetID: request.TargetID,
		ClearanceID: challenge.ClearanceID, ParentChangeID: challenge.ParentChangeID,
		ChildChangeID: challenge.ChildChangeID, ChildPlanHash: challenge.ChildPlanHash,
		ResourceKey: challenge.ResourceKey, ChallengeDigest: challenge.ChallengeDigest,
		PolicyRevision: status.PolicyRevision, CapabilityRevision: status.CapabilityRevision,
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: expiresAt.Format(time.RFC3339Nano),
		Nonce: base64.RawURLEncoding.EncodeToString(nonce),
	}
	payload, err := approval.ApprovalPayload()
	if err != nil {
		return protocol.PVERecoveryClearanceApproval{}, err
	}
	approval.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	if err := approval.ValidateShape(); err != nil {
		return protocol.PVERecoveryClearanceApproval{}, err
	}
	return approval, nil
}

func pveRecoveryClearanceConfirmationText(request Request, challenge protocol.PVERecoveryClearanceChallenge) string {
	return strings.Join([]string{
		"CLEAR-PVE-UNKNOWN", request.ServerID, request.MachineID, request.TargetID,
		challenge.ParentChangeID, challenge.ChildChangeID, challenge.ChildPlanHash,
		challenge.ResourceKey, challenge.ChallengeDigest,
	}, " ")
}
