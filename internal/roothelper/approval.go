package roothelper

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

type ApprovalVerifier struct {
	KeyID     string
	PublicKey ed25519.PublicKey
}

func LoadApprovalVerifier(keyID, path string, requireRootOwner bool) (*ApprovalVerifier, error) {
	if keyID == "" || path == "" {
		return nil, errors.New("approval key id and public key path are required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("approval public key must be a regular file that is not group or world writable")
	}
	if requireRootOwner {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return nil, errors.New("approval public key must be owned by root")
		}
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(payload)
	if block == nil || len(rest) != 0 || block.Type != "PUBLIC KEY" {
		return nil, errors.New("approval public key must contain one PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse approval public key: %w", err)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("approval public key must be Ed25519")
	}
	return &ApprovalVerifier{KeyID: keyID, PublicKey: publicKey}, nil
}

func (v *ApprovalVerifier) Verify(grant protocol.ApprovalGrant, action string, change *Change, now time.Time) error {
	if v == nil || len(v.PublicKey) != ed25519.PublicKeySize || grant.KeyID != v.KeyID {
		return errors.New("approval signing key is not trusted")
	}
	if err := grant.ValidateShape(); err != nil {
		return err
	}
	issuedAt, _ := time.Parse(time.RFC3339Nano, grant.IssuedAt)
	expiresAt, _ := time.Parse(time.RFC3339Nano, grant.ExpiresAt)
	if now.Before(issuedAt.Add(-30*time.Second)) || !now.Before(expiresAt) {
		return errors.New("approval grant is not currently valid")
	}
	if grant.Action != action || grant.ServerID != change.ServerID || grant.MachineID != change.MachineID || grant.TargetID != change.TargetID || grant.ChangeID != change.ID || grant.PlanHash != change.PlanHash || grant.PolicyRevision != change.PolicyRevision || grant.CapabilityRevision != change.CapabilityRevision {
		return errors.New("approval grant does not match the authoritative change")
	}
	payload, err := grant.ApprovalPayload()
	if err != nil {
		return err
	}
	signature, err := base64.RawStdEncoding.DecodeString(grant.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(v.PublicKey, payload, signature) {
		return errors.New("approval grant signature is invalid")
	}
	return nil
}

func (v *ApprovalVerifier) VerifyPVERecoveryClearance(
	approval protocol.PVERecoveryClearanceApproval,
	challenge protocol.PVERecoveryClearanceChallenge,
	change *Change,
	now time.Time,
) error {
	if v == nil || len(v.PublicKey) != ed25519.PublicKeySize || approval.KeyID != v.KeyID {
		return errors.New("PVE recovery clearance signing key is not trusted")
	}
	if err := approval.ValidateShape(); err != nil {
		return err
	}
	if err := challenge.Validate(); err != nil {
		return err
	}
	issuedAt, _ := time.Parse(time.RFC3339Nano, approval.IssuedAt)
	expiresAt, _ := time.Parse(time.RFC3339Nano, approval.ExpiresAt)
	challengeExpiry, _ := time.Parse(time.RFC3339Nano, challenge.ExpiresAt)
	if now.Before(issuedAt.Add(-30*time.Second)) || !now.Before(expiresAt) || expiresAt.After(challengeExpiry) {
		return errors.New("PVE recovery clearance approval is not currently valid")
	}
	if change == nil || approval.Action != protocol.PVERecoveryClearanceAction ||
		approval.ServerID != change.ServerID || approval.MachineID != change.MachineID || approval.TargetID != change.TargetID ||
		approval.ClearanceID != challenge.ClearanceID || approval.ParentChangeID != challenge.ParentChangeID ||
		approval.ChildChangeID != change.ID || approval.ChildChangeID != challenge.ChildChangeID ||
		approval.ChildPlanHash != change.PlanHash || approval.ChildPlanHash != challenge.ChildPlanHash ||
		approval.ResourceKey != change.ResourceKey || approval.ResourceKey != challenge.ResourceKey ||
		approval.ChallengeDigest != challenge.ChallengeDigest || approval.PolicyRevision != change.PolicyRevision ||
		approval.CapabilityRevision != change.CapabilityRevision {
		return errors.New("PVE recovery clearance approval does not match the authoritative challenge")
	}
	payload, err := approval.ApprovalPayload()
	if err != nil {
		return err
	}
	signature, err := base64.RawStdEncoding.DecodeString(approval.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(v.PublicKey, payload, signature) {
		return errors.New("PVE recovery clearance approval signature is invalid")
	}
	return nil
}
