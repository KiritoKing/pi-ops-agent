package roothelper

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

type persistedPlanClassification struct {
	Operation    protocol.Operation
	Plan         *protocol.ApprovalPlan
	RecoveryOnly bool
}

func classifyPersistedPlan(change *Change) (persistedPlanClassification, error) {
	if change == nil {
		return persistedPlanClassification{}, errors.New("stored change is unavailable")
	}
	operation, err := protocol.ParseStoredOperation(change.Operation)
	if err != nil {
		return persistedPlanClassification{}, fmt.Errorf("decode stored operation: %w", err)
	}
	if operation.Kind() != change.Kind {
		return persistedPlanClassification{}, errors.New("stored operation kind does not match the change kind")
	}
	if !protocol.IsStoredOnlyOperation(operation) {
		plan, planErr := protocol.BuildApprovalPlanWithPreconditions(
			operation, change.PolicyRevision, change.CapabilityRevision,
			change.PreconditionDigest, change.PreconditionFields,
		)
		if planErr == nil && plan.PlanHash == change.PlanHash {
			return persistedPlanClassification{Operation: operation, Plan: &plan}, nil
		}
	}
	legacyHash := protocol.LegacyPlanHashV02(
		change.ServerID, change.MachineID, change.TargetID, change.PolicyRevision,
		change.CapabilityRevision, change.Operation,
	)
	if legacyHash == change.PlanHash {
		return persistedPlanClassification{Operation: operation, RecoveryOnly: true}, nil
	}
	return persistedPlanClassification{}, errors.New("stored change matches neither its current canonical plan nor the exact legacy v0.2 plan hash")
}

type legacyFileRecoveryInspector interface {
	InspectLegacyFileRecovery(ExecutionScope, *protocol.FileWrite, ExecutionResult) ([]protocol.RecoveryBackupObject, error)
}

type legacyFileRollback struct {
	Existed    bool   `json:"existed"`
	BackupPath string `json:"backupPath,omitempty"`
	Mode       uint32 `json:"mode,omitempty"`
	UID        int    `json:"uid,omitempty"`
	GID        int    `json:"gid,omitempty"`
}

func isLegacyFileRollbackShape(payload []byte) bool {
	_, err := decodeLegacyFileRollback(payload)
	return err == nil
}

func decodeLegacyFileRollback(payload []byte) (legacyFileRollback, error) {
	var wire struct {
		Existed    *bool  `json:"existed"`
		BackupPath string `json:"backupPath,omitempty"`
		Mode       uint32 `json:"mode,omitempty"`
		UID        int    `json:"uid,omitempty"`
		GID        int    `json:"gid,omitempty"`
	}
	if err := strictRecoveryDecode(payload, &wire); err != nil {
		return legacyFileRollback{}, err
	}
	if wire.Existed == nil {
		return legacyFileRollback{}, errors.New("legacy file rollback evidence is missing existed")
	}
	return legacyFileRollback{
		Existed: *wire.Existed, BackupPath: wire.BackupPath, Mode: wire.Mode, UID: wire.UID, GID: wire.GID,
	}, nil
}

func decodeLegacyServiceRollback(payload []byte) (serviceRollback, error) {
	var wire struct {
		Active *bool `json:"active"`
	}
	if err := strictRecoveryDecode(payload, &wire); err != nil {
		return serviceRollback{}, err
	}
	if wire.Active == nil {
		return serviceRollback{}, errors.New("legacy service rollback evidence is missing active")
	}
	return serviceRollback{Active: *wire.Active}, nil
}

func buildLegacyRecoveryDescriptor(change *Change, operation protocol.Operation, executor Executor) protocol.RecoveryDescriptor {
	target, action := legacyOriginalTargetAction(change, operation)
	descriptor := protocol.RecoveryDescriptor{
		Version: protocol.Version, CompatibilityVersion: protocol.LegacyPlanCompatibilityV02,
		OriginalKind: operation.Kind(), OriginalTarget: target, OriginalAction: action,
		CompensationTarget: target, CompensationAction: "manual.recovery-required",
		RollbackDataDigest: digestRecoveryBytes(change.RollbackData),
		BackupObjects:      recoveryObjectsWithoutDigest(change.BackupRefs),
		UnavailableReason:  "this legacy operation is not in the broker's automated recovery compatibility matrix",
	}
	if !change.RollbackAvailable {
		descriptor.UnavailableReason = "the persisted change has no durable rollback evidence"
		return descriptor
	}
	result := ExecutionResult{
		BackupRefs: append([]string(nil), change.BackupRefs...), RollbackData: append(json.RawMessage(nil), change.RollbackData...),
		RollbackAvailable: change.RollbackAvailable, Verification: change.Verification,
	}
	switch value := operation.(type) {
	case *protocol.ServiceAction:
		if !protocol.IsStoredOnlyOperation(value) {
			descriptor.UnavailableReason = "only the v0.1/v0.2 service.action schema is recovery compatible"
			return descriptor
		}
		rollback, err := decodeLegacyServiceRollback(change.RollbackData)
		if err != nil {
			descriptor.UnavailableReason = "legacy service rollback evidence is invalid"
			return descriptor
		}
		if len(change.BackupRefs) != 0 {
			descriptor.UnavailableReason = "legacy service rollback contains unexpected backup objects"
			return descriptor
		}
		if validator, ok := executor.(OperationValidator); ok {
			if err := validator.ValidateOperation(executionScope(change), value); err != nil {
				descriptor.UnavailableReason = boundedRecoveryReason("legacy service target is no longer permitted: ", err)
				return descriptor
			}
		}
		if rollback.Active {
			descriptor.CompensationAction = "service.start"
		} else {
			descriptor.CompensationAction = "service.stop"
		}
		descriptor.BackupObjects = []protocol.RecoveryBackupObject{}
		descriptor.RollbackCompatible = true
		descriptor.UnavailableReason = ""
		return descriptor
	case *protocol.FileWrite:
		if !protocol.IsStoredOnlyOperation(value) {
			descriptor.UnavailableReason = "only the v0.1/v0.2 file.write schema is recovery compatible"
			return descriptor
		}
		if !isLegacyFileRollbackShape(change.RollbackData) {
			descriptor.UnavailableReason = "legacy file rollback evidence is invalid"
			return descriptor
		}
		inspector, ok := executor.(legacyFileRecoveryInspector)
		if !ok {
			descriptor.UnavailableReason = "the active executor cannot prove legacy file commit identity"
			return descriptor
		}
		objects, err := inspector.InspectLegacyFileRecovery(executionScope(change), value, result)
		if err != nil {
			descriptor.UnavailableReason = boundedRecoveryReason("legacy file recovery proof failed: ", err)
			return descriptor
		}
		rollback, _ := decodeLegacyFileRollback(change.RollbackData)
		if rollback.Existed {
			descriptor.CompensationAction = "file.restore"
		} else {
			descriptor.CompensationAction = "file.remove"
		}
		descriptor.BackupObjects = objects
		descriptor.RollbackCompatible = true
		descriptor.UnavailableReason = ""
		return descriptor
	default:
		return descriptor
	}
}

func legacyOriginalTargetAction(change *Change, operation protocol.Operation) (string, string) {
	switch value := operation.(type) {
	case *protocol.PackageInstall:
		return value.Package, "package.install"
	case *protocol.ServiceAction:
		return value.Unit, "service." + value.Action
	case *protocol.WorkloadServiceAction:
		return value.Account + ":" + value.Unit, "service." + value.Action
	case *protocol.FileWrite:
		return value.Path, "file.write"
	case *protocol.PluginInstall:
		return value.PluginID + "@" + value.Version, "plugin.install"
	case *protocol.PluginRegister:
		return value.PluginID + "@" + value.Version, "plugin.register"
	case *protocol.WorkloadDeploy:
		return value.PluginID + "@" + value.Version, "workload.deploy"
	case *protocol.BreakglassScript:
		return "/", "breakglass.execute"
	default:
		var fields map[string]json.RawMessage
		if json.Unmarshal(change.Operation, &fields) == nil {
			for _, name := range []string{"pluginId", "path", "unit", "package"} {
				var candidate string
				if json.Unmarshal(fields[name], &candidate) == nil && candidate != "" {
					return candidate, operation.Kind()
				}
			}
		}
		return change.TargetID, operation.Kind()
	}
}

func digestRecoveryBytes(payload []byte) string {
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func recoveryObjectsWithoutDigest(references []string) []protocol.RecoveryBackupObject {
	objects := make([]protocol.RecoveryBackupObject, 0, len(references))
	for _, reference := range references {
		objects = append(objects, protocol.RecoveryBackupObject{Reference: reference})
	}
	return objects
}

func strictRecoveryDecode(payload []byte, target interface{}) error {
	if len(payload) == 0 {
		return errors.New("rollback data is missing")
	}
	if err := protocol.ValidateUniqueJSONKeys(payload); err != nil {
		return fmt.Errorf("rollback data has ambiguous JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("rollback data contains trailing JSON")
	}
	return nil
}

func boundedRecoveryReason(prefix string, err error) string {
	reason := prefix + err.Error()
	reason = strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) || (r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069') {
			return ' '
		}
		return r
	}, reason)
	if len(reason) > 2048 {
		reason = reason[:2045] + "..."
	}
	return reason
}
