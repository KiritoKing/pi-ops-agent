package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"unicode/utf8"
)

const LegacyPlanCompatibilityV02 = "legacy-plan-v0.1-v0.2"

// ValidateUniqueJSONKeys applies the protocol package's duplicate-key guard to
// persisted compatibility evidence before a strict typed decode.
func ValidateUniqueJSONKeys(payload []byte) error {
	return rejectDuplicateJSONKeys(payload)
}

// RecoveryBackupObject binds a broker-owned recovery object to the signed
// recovery descriptor. Digest is required for an object that participates in
// an automated recovery action; unavailable legacy records may expose only the
// bounded reference so an operator can locate evidence without trusting it.
type RecoveryBackupObject struct {
	Reference string `json:"reference"`
	Digest    string `json:"digest,omitempty"`
}

// RecoveryDescriptor is the only approval-facing representation of a legacy
// persisted mutation. It intentionally contains no executable payload. The
// broker reconstructs it from its durable record and signs it as part of the
// change.status response.
type RecoveryDescriptor struct {
	Version              int                    `json:"version"`
	CompatibilityVersion string                 `json:"compatibilityVersion"`
	OriginalKind         string                 `json:"originalKind"`
	OriginalTarget       string                 `json:"originalTarget"`
	OriginalAction       string                 `json:"originalAction"`
	CompensationTarget   string                 `json:"compensationTarget"`
	CompensationAction   string                 `json:"compensationAction"`
	RollbackDataDigest   string                 `json:"rollbackDataDigest"`
	BackupObjects        []RecoveryBackupObject `json:"backupObjects"`
	RollbackCompatible   bool                   `json:"rollbackCompatible"`
	UnavailableReason    string                 `json:"unavailableReason,omitempty"`
}

// LegacyPlanHashV02 reproduces the exact v0.1/v0.2 persisted plan-hash
// algorithm. It is only a classifier for already persisted records; callers
// must never use it to authorize or prepare a new change.
func LegacyPlanHashV02(serverID, machineID, targetID, policyRevision, capabilityRevision string, operation []byte) string {
	prefix := serverID + "\x00" + machineID + "\x00" + targetID + "\x00" + policyRevision + "\x00" + capabilityRevision + "\x00"
	payload := make([]byte, 0, len(prefix)+len(operation))
	payload = append(payload, prefix...)
	payload = append(payload, operation...)
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func (d RecoveryDescriptor) Validate() error {
	if d.Version != Version || d.CompatibilityVersion != LegacyPlanCompatibilityV02 ||
		!validRecoveryText(d.OriginalKind, 128) || !validRecoveryText(d.OriginalTarget, 4096) ||
		!validRecoveryText(d.OriginalAction, 128) || !validRecoveryText(d.CompensationTarget, 4096) ||
		!validRecoveryText(d.CompensationAction, 128) || !digestPattern.MatchString(d.RollbackDataDigest) ||
		d.BackupObjects == nil || len(d.BackupObjects) > 64 || len(d.UnavailableReason) > 2048 ||
		(d.UnavailableReason != "" && (!utf8.ValidString(d.UnavailableReason) || containsRecoveryControl(d.UnavailableReason))) {
		return errors.New("recovery descriptor is invalid or exceeds a protocol bound")
	}
	if d.RollbackCompatible == (d.UnavailableReason != "") {
		return errors.New("recovery descriptor compatibility and unavailable reason disagree")
	}
	seen := make(map[string]struct{}, len(d.BackupObjects))
	for _, object := range d.BackupObjects {
		if !validRecoveryText(object.Reference, 4096) || (object.Digest != "" && !digestPattern.MatchString(object.Digest)) {
			return errors.New("recovery descriptor contains an invalid backup object")
		}
		if _, duplicate := seen[object.Reference]; duplicate {
			return errors.New("recovery descriptor contains duplicate backup objects")
		}
		seen[object.Reference] = struct{}{}
		if d.RollbackCompatible && object.Digest == "" {
			return errors.New("compatible recovery descriptor has an unbound backup object")
		}
	}
	return nil
}

func validRecoveryText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) && !containsRecoveryControl(value)
}

func containsRecoveryControl(value string) bool {
	return strings.ContainsFunc(value, func(r rune) bool {
		return r < 0x20 || (r >= 0x7f && r <= 0x9f) || r == '\u2028' || r == '\u2029' ||
			(r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069')
	})
}
