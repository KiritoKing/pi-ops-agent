package roothelper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

const pveTaskRecordVersion = 1

type pveGuestStatus struct {
	Status string `json:"status"`
	Lock   string `json:"lock"`
}

type pveTaskStatus struct {
	Status     string `json:"status"`
	ExitStatus string `json:"exitstatus"`
}

type pveClusterStatus struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Node    string `json:"node"`
	NodeID  int    `json:"nodeid"`
	Local   int    `json:"local"`
	Online  int    `json:"online"`
	Quorate int    `json:"quorate"`
}

type pveStorageStatus struct {
	Active  int `json:"active"`
	Enabled int `json:"enabled"`
}

type pveStorageContent struct {
	VolID   string `json:"volid"`
	Content string `json:"content"`
	VMID    int    `json:"vmid"`
}

type pveGuestResource struct {
	Type string `json:"type"`
	VMID int    `json:"vmid"`
	Node string `json:"node"`
}

type pveSnapshot struct {
	Name string `json:"name"`
}

type pveRollback struct {
	Version          int      `json:"version"`
	Operation        string   `json:"operation"`
	Node             string   `json:"node"`
	GuestType        string   `json:"guestType"`
	VMID             int      `json:"vmid"`
	PreviousStatus   string   `json:"previousStatus,omitempty"`
	Snapshot         string   `json:"snapshot,omitempty"`
	SafetyBackupUPID string   `json:"safetyBackupUpid,omitempty"`
	Storage          string   `json:"storage,omitempty"`
	BeforeVolumes    []string `json:"beforeVolumes,omitempty"`
}

type pveTaskRecord struct {
	Version       int      `json:"version"`
	Operation     string   `json:"operation"`
	Node          string   `json:"node"`
	GuestType     string   `json:"guestType"`
	VMID          int      `json:"vmid"`
	UPID          string   `json:"upid"`
	Storage       string   `json:"storage,omitempty"`
	BeforeVolumes []string `json:"beforeVolumes,omitempty"`
	VolumeRef     string   `json:"volumeRef,omitempty"`
}

// pveTaskIntent is written and fsynced before invoking a mutating PVE API.
// It deliberately contains no caller-controlled argv. If the API call loses
// its UPID, recovery can prove that a mutation may have started and must keep
// the guest resource locked for manual reconciliation.
type pveTaskIntent struct {
	Version            int      `json:"version"`
	Operation          string   `json:"operation"`
	PlanHash           string   `json:"planHash"`
	PreconditionDigest string   `json:"preconditionDigest"`
	Node               string   `json:"node"`
	GuestType          string   `json:"guestType"`
	VMID               int      `json:"vmid"`
	Storage            string   `json:"storage,omitempty"`
	BeforeVolumes      []string `json:"beforeVolumes,omitempty"`
}

type pveUncertainError struct{ err error }

func (e pveUncertainError) Error() string                  { return e.err.Error() }
func (e pveUncertainError) Unwrap() error                  { return e.err }
func (e pveUncertainError) MutationOutcomeUncertain() bool { return true }

func uncertainPVE(format string, arguments ...interface{}) error {
	return pveUncertainError{err: fmt.Errorf(format, arguments...)}
}

type pveNoMutationError struct{ err error }

func (e pveNoMutationError) Error() string           { return e.err.Error() }
func (e pveNoMutationError) Unwrap() error           { return e.err }
func (e pveNoMutationError) NoMutationStarted() bool { return true }

func noMutationPVE(format string, arguments ...interface{}) error {
	return pveNoMutationError{err: fmt.Errorf(format, arguments...)}
}

func isPVEOperation(operation protocol.Operation) bool {
	switch operation.(type) {
	case *protocol.PVEGuestAction, *protocol.PVESnapshotCreate, *protocol.PVESnapshotDelete,
		*protocol.PVESnapshotRollback, *protocol.PVEGuestBackup, *protocol.PVEGuestRestore,
		*protocol.PVEGuestMigrate:
		return true
	default:
		return false
	}
}

func pveResourceKey(operation protocol.Operation) string {
	if !isPVEOperation(operation) {
		return ""
	}
	_, _, vmid := pveOperationGuest(operation)
	// PVE VMIDs are cluster-global and migration changes the node. Omitting the
	// node and guest type keeps an unresolved operation locked across migration
	// and prevents qemu/lxc aliases from concurrently claiming the same VMID.
	return fmt.Sprintf("pve/vmid/%d", vmid)
}

func validPVEEvidenceRef(ref string) bool {
	if len(ref) == 0 || len(ref) > 1024 || strings.ContainsAny(ref, "\x00\r\n") {
		return false
	}
	if strings.HasPrefix(ref, "pve:task:") {
		upid := strings.TrimPrefix(ref, "pve:task:")
		parts := strings.Split(upid, ":")
		return len(parts) >= 3 && protocol.ValidPVEUPIDForNode(upid, parts[1])
	}
	if strings.HasPrefix(ref, "pve:volume:") {
		volume := strings.TrimPrefix(ref, "pve:volume:")
		return strings.Contains(volume, ":backup/vzdump-") && !strings.Contains(volume, "..")
	}
	return false
}

func (e *OSExecutor) PlanOperation(ctx context.Context, scope ExecutionScope, operation protocol.Operation) (OperationPrecondition, error) {
	if workloadService, ok := operation.(*protocol.WorkloadServiceAction); ok {
		return e.planWorkloadService(ctx, scope, workloadService)
	}
	if jsonConfig, ok := operation.(*protocol.WorkloadJSONConfigEdit); ok {
		return e.planWorkloadJSONConfig(ctx, scope, jsonConfig)
	}
	if !isPVEOperation(operation) {
		return OperationPrecondition{}, nil
	}
	if migration, ok := operation.(*protocol.PVEGuestMigrate); ok && migration.WithLocalDisks {
		return OperationPrecondition{}, errors.New("PVE local-disk migration requires a narrower target-storage mapping and is not enabled")
	}
	if err := e.ValidateOperation(scope, operation); err != nil {
		return OperationPrecondition{}, err
	}
	fields, err := e.pvePreconditionFields(ctx, operation)
	if err != nil {
		return OperationPrecondition{}, err
	}
	digest, err := protocol.ApprovalPreconditionDigest(fields)
	if err != nil {
		return OperationPrecondition{}, err
	}
	return OperationPrecondition{Digest: digest, Fields: fields}, nil
}

func (e *OSExecutor) pvePreconditionFields(ctx context.Context, operation protocol.Operation) ([]protocol.ApprovalPlanField, error) {
	node, guestType, vmid := pveOperationGuest(operation)
	if err := e.requirePVEReady(ctx, node); err != nil {
		return nil, err
	}
	fields := []protocol.ApprovalPlanField{
		{Name: "observedNode", Value: node},
		{Name: "guestType", Value: guestType},
		{Name: "vmid", Value: strconv.Itoa(vmid)},
	}
	guestFields := func() (pveGuestStatus, error) {
		status, err := e.readPVEGuestStatus(ctx, node, guestType, vmid)
		if err != nil {
			return status, err
		}
		if err := requireUnlockedPVEGuest(status); err != nil {
			return status, err
		}
		fields = append(fields,
			protocol.ApprovalPlanField{Name: "currentStatus", Value: status.Status},
			protocol.ApprovalPlanField{Name: "currentLock", Value: "unlocked"},
		)
		return status, nil
	}
	storageFields := func(name, storage string) error {
		if err := e.requirePVEStorage(ctx, node, storage); err != nil {
			return err
		}
		fields = append(fields,
			protocol.ApprovalPlanField{Name: name, Value: storage},
			protocol.ApprovalPlanField{Name: name + "State", Value: "active-enabled"},
		)
		return nil
	}
	backupSetFields := func(storage string) error {
		volumes, err := e.pveBackupVolumes(ctx, node, storage, guestType, vmid)
		if err != nil {
			return err
		}
		fields = append(fields,
			protocol.ApprovalPlanField{Name: "existingBackupCount", Value: strconv.Itoa(len(volumes))},
			protocol.ApprovalPlanField{Name: "existingBackupsDigest", Value: digestPVEStrings(volumes)},
		)
		return nil
	}

	switch value := operation.(type) {
	case *protocol.PVEGuestAction:
		status, err := guestFields()
		if err != nil {
			return nil, err
		}
		switch value.Action {
		case "start":
			if status.Status != "stopped" {
				return nil, errors.New("PVE guest must be stopped before start")
			}
		case "shutdown", "stop", "reboot":
			if status.Status != "running" {
				return nil, errors.New("PVE guest must be running for the requested action")
			}
		}
	case *protocol.PVESnapshotCreate:
		if _, err := guestFields(); err != nil {
			return nil, err
		}
		exists, err := e.pveSnapshotExists(ctx, node, guestType, vmid, value.Snapshot)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, errors.New("PVE snapshot already exists")
		}
		fields = append(fields, protocol.ApprovalPlanField{Name: "snapshotState", Value: "absent"})
	case *protocol.PVESnapshotDelete:
		if _, err := guestFields(); err != nil {
			return nil, err
		}
		exists, err := e.pveSnapshotExists(ctx, node, guestType, vmid, value.Snapshot)
		if err != nil || !exists {
			return nil, errors.New("approved PVE snapshot does not exist")
		}
		fields = append(fields, protocol.ApprovalPlanField{Name: "snapshotState", Value: "present"})
		if err := storageFields("backupStorage", value.BackupStorage); err != nil {
			return nil, err
		}
		if err := backupSetFields(value.BackupStorage); err != nil {
			return nil, err
		}
	case *protocol.PVESnapshotRollback:
		if _, err := guestFields(); err != nil {
			return nil, err
		}
		exists, err := e.pveSnapshotExists(ctx, node, guestType, vmid, value.Snapshot)
		if err != nil || !exists {
			return nil, errors.New("approved PVE snapshot does not exist")
		}
		fields = append(fields, protocol.ApprovalPlanField{Name: "snapshotState", Value: "present"})
		if err := storageFields("backupStorage", value.BackupStorage); err != nil {
			return nil, err
		}
		if err := backupSetFields(value.BackupStorage); err != nil {
			return nil, err
		}
	case *protocol.PVEGuestBackup:
		if _, err := guestFields(); err != nil {
			return nil, err
		}
		if err := storageFields("destinationStorage", value.Storage); err != nil {
			return nil, err
		}
		if err := backupSetFields(value.Storage); err != nil {
			return nil, err
		}
	case *protocol.PVEGuestRestore:
		exists, existingNode, err := e.pveGuestExists(ctx, guestType, vmid)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, fmt.Errorf("PVE restore VMID is already present on node %s", existingNode)
		}
		fields = append(fields, protocol.ApprovalPlanField{Name: "currentStatus", Value: "absent-cluster-wide"})
		if err := storageFields("destinationStorage", value.Storage); err != nil {
			return nil, err
		}
		backupStorage := strings.SplitN(value.BackupVolume, ":", 2)[0]
		if err := storageFields("sourceBackupStorage", backupStorage); err != nil {
			return nil, err
		}
		volumeExists, err := e.pveBackupVolumeExists(ctx, node, backupStorage, guestType, vmid, value.BackupVolume)
		if err != nil || !volumeExists {
			return nil, errors.New("approved PVE backup volume does not exist")
		}
		fields = append(fields, protocol.ApprovalPlanField{Name: "backupVolumeState", Value: "present"})
	case *protocol.PVEGuestMigrate:
		if value.WithLocalDisks {
			return nil, errors.New("PVE local-disk migration requires a narrower target-storage mapping and is not enabled")
		}
		status, err := guestFields()
		if err != nil {
			return nil, err
		}
		if err := e.requirePVEReady(ctx, value.TargetNode); err != nil {
			return nil, fmt.Errorf("PVE migration target is not ready: %w", err)
		}
		exists, existingNode, err := e.pveGuestExists(ctx, guestType, vmid)
		if err != nil || !exists || existingNode != node {
			return nil, errors.New("PVE guest is not uniquely present on the approved source node")
		}
		if guestType == "qemu" && value.Online != (status.Status == "running") {
			return nil, errors.New("QEMU online migration flag must match the current running state")
		}
		if guestType == "lxc" && value.Restart != (status.Status == "running") {
			return nil, errors.New("LXC restart migration flag must match the current running state")
		}
		fields = append(fields,
			protocol.ApprovalPlanField{Name: "targetNode", Value: value.TargetNode},
			protocol.ApprovalPlanField{Name: "targetNodeState", Value: "online-ready"},
			protocol.ApprovalPlanField{Name: "expectedFinalStatus", Value: status.Status},
		)
	default:
		return nil, errors.New("unsupported PVE operation")
	}
	return fields, nil
}

func (e *OSExecutor) requireApprovedPVEPrecondition(ctx context.Context, scope ExecutionScope, operation protocol.Operation) error {
	if scope.PreconditionDigest == "" {
		return errors.New("PVE operation is missing its approved precondition digest")
	}
	planned, err := e.PlanOperation(ctx, scope, operation)
	if err != nil {
		return err
	}
	if planned.Digest != scope.PreconditionDigest {
		return errors.New("PVE authoritative precondition changed after approval")
	}
	return nil
}

func digestPVEStrings(values []string) string {
	copyOfValues := append([]string(nil), values...)
	sort.Strings(copyOfValues)
	payload, _ := json.Marshal(copyOfValues)
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func (e *OSExecutor) preparePVE(ctx context.Context, scope ExecutionScope, operation protocol.Operation) (ExecutionResult, error) {
	if err := e.requireApprovedPVEPrecondition(ctx, scope, operation); err != nil {
		return ExecutionResult{}, err
	}
	node, guestType, vmid := pveOperationGuest(operation)
	if err := e.requirePVEReady(ctx, node); err != nil {
		return ExecutionResult{}, err
	}
	rollback := pveRollback{
		Version: pveTaskRecordVersion, Operation: operation.Kind(), Node: node,
		GuestType: guestType, VMID: vmid,
	}

	switch value := operation.(type) {
	case *protocol.PVEGuestAction:
		status, err := e.readPVEGuestStatus(ctx, value.Node, value.GuestType, value.VMID)
		if err != nil {
			return ExecutionResult{}, err
		}
		if err := requireUnlockedPVEGuest(status); err != nil {
			return ExecutionResult{}, err
		}
		rollback.PreviousStatus = status.Status
		switch value.Action {
		case "start":
			if status.Status == "running" {
				return ExecutionResult{}, errors.New("PVE guest is already running")
			}
		case "shutdown", "stop", "reboot":
			if status.Status != "running" {
				return ExecutionResult{}, errors.New("PVE guest must be running for the requested action")
			}
		}
		payload, _ := json.Marshal(rollback)
		// A compensating lifecycle action is a new availability-impacting PVE
		// mutation. It must be prepared from current state and approved as a new
		// typed change rather than hidden behind the original planHash.
		return ExecutionResult{RollbackData: payload, RollbackAvailable: false}, nil
	case *protocol.PVESnapshotCreate:
		if err := e.requireUnlockedPVEGuestRef(ctx, value.Node, value.GuestType, value.VMID); err != nil {
			return ExecutionResult{}, err
		}
		exists, err := e.pveSnapshotExists(ctx, value.Node, value.GuestType, value.VMID, value.Snapshot)
		if err != nil {
			return ExecutionResult{}, err
		}
		if exists {
			return ExecutionResult{}, errors.New("PVE snapshot already exists")
		}
		rollback.Snapshot = value.Snapshot
		payload, _ := json.Marshal(rollback)
		// Deleting the newly created snapshot is itself destructive and requires
		// an explicit snapshot.delete plan with an approved safety-backup storage.
		return ExecutionResult{RollbackData: payload, RollbackAvailable: false}, nil
	case *protocol.PVESnapshotDelete:
		return e.prepareDestructivePVESnapshot(ctx, scope, rollback, value.Node, value.GuestType, value.VMID, value.Snapshot, value.BackupStorage)
	case *protocol.PVESnapshotRollback:
		return e.prepareDestructivePVESnapshot(ctx, scope, rollback, value.Node, value.GuestType, value.VMID, value.Snapshot, value.BackupStorage)
	case *protocol.PVEGuestBackup:
		if err := e.requireUnlockedPVEGuestRef(ctx, value.Node, value.GuestType, value.VMID); err != nil {
			return ExecutionResult{}, err
		}
		if err := e.requirePVEStorage(ctx, value.Node, value.Storage); err != nil {
			return ExecutionResult{}, err
		}
		before, err := e.pveBackupVolumes(ctx, value.Node, value.Storage, value.GuestType, value.VMID)
		if err != nil {
			return ExecutionResult{}, err
		}
		rollback.Storage, rollback.BeforeVolumes = value.Storage, before
		payload, _ := json.Marshal(rollback)
		return ExecutionResult{RollbackData: payload}, nil
	case *protocol.PVEGuestRestore:
		if err := e.requirePVEStorage(ctx, value.Node, value.Storage); err != nil {
			return ExecutionResult{}, err
		}
		backupStorage := strings.SplitN(value.BackupVolume, ":", 2)[0]
		if err := e.requirePVEStorage(ctx, value.Node, backupStorage); err != nil {
			return ExecutionResult{}, fmt.Errorf("PVE backup storage is not ready: %w", err)
		}
		exists, _, err := e.pveGuestExists(ctx, value.GuestType, value.VMID)
		if err != nil {
			return ExecutionResult{}, err
		}
		if exists {
			return ExecutionResult{}, errors.New("PVE restore only permits a new, currently unused VMID")
		}
		return ExecutionResult{BackupRefs: []string{"pve:volume:" + value.BackupVolume}}, nil
	case *protocol.PVEGuestMigrate:
		status, err := e.readPVEGuestStatus(ctx, value.Node, value.GuestType, value.VMID)
		if err != nil {
			return ExecutionResult{}, err
		}
		if err := requireUnlockedPVEGuest(status); err != nil {
			return ExecutionResult{}, err
		}
		if err := e.requirePVEReady(ctx, value.TargetNode); err != nil {
			return ExecutionResult{}, fmt.Errorf("PVE migration target is not ready: %w", err)
		}
		exists, existingNode, err := e.pveGuestExists(ctx, value.GuestType, value.VMID)
		if err != nil {
			return ExecutionResult{}, err
		}
		if !exists || existingNode != value.Node {
			return ExecutionResult{}, errors.New("PVE guest is not uniquely present on the approved source node")
		}
		rollback.PreviousStatus = status.Status
		payload, _ := json.Marshal(rollback)
		return ExecutionResult{RollbackData: payload}, nil
	default:
		return ExecutionResult{}, errors.New("unsupported PVE operation")
	}
}

func (e *OSExecutor) prepareDestructivePVESnapshot(ctx context.Context, scope ExecutionScope, rollback pveRollback, node, guestType string, vmid int, snapshot, storage string) (ExecutionResult, error) {
	status, err := e.readPVEGuestStatus(ctx, node, guestType, vmid)
	if err != nil {
		return ExecutionResult{}, err
	}
	if err := requireUnlockedPVEGuest(status); err != nil {
		return ExecutionResult{}, err
	}
	rollback.PreviousStatus = status.Status
	exists, err := e.pveSnapshotExists(ctx, node, guestType, vmid, snapshot)
	if err != nil {
		return ExecutionResult{}, err
	}
	if !exists {
		return ExecutionResult{}, errors.New("approved PVE snapshot does not exist")
	}
	if err := e.requirePVEStorage(ctx, node, storage); err != nil {
		return ExecutionResult{}, err
	}
	before, err := e.pveBackupVolumes(ctx, node, storage, guestType, vmid)
	if err != nil {
		return ExecutionResult{}, err
	}
	rollback.Snapshot = snapshot
	rollback.Storage, rollback.BeforeVolumes = storage, before
	payload, _ := json.Marshal(rollback)
	return ExecutionResult{RollbackData: payload, RollbackAvailable: false}, nil
}

// executeDestructivePVESnapshotSafetyBackup is step one of the authorized
// mutation. Service.executeAuthorizedChange must have durably crossed the
// EXECUTING barrier and written change_execution_started before this method is
// reachable. The root-only intent is fsynced before the PVE API call; once a
// UPID exists, both the task record and the authoritative Change evidence are
// updated before waiting for task completion.
func (e *OSExecutor) executeDestructivePVESnapshotSafetyBackup(
	ctx context.Context,
	scope ExecutionScope,
	operation protocol.Operation,
	result ExecutionResult,
) (ExecutionResult, error) {
	rollback, err := decodePVERollback(result.RollbackData)
	if err != nil {
		return result, noMutationPVE("decode approved PVE safety-backup baseline: %w", err)
	}
	node, guestType, vmid := pveOperationGuest(operation)
	expectedSnapshot, expectedStorage := "", ""
	switch value := operation.(type) {
	case *protocol.PVESnapshotDelete:
		expectedSnapshot, expectedStorage = value.Snapshot, value.BackupStorage
	case *protocol.PVESnapshotRollback:
		expectedSnapshot, expectedStorage = value.Snapshot, value.BackupStorage
	default:
		return result, noMutationPVE("PVE safety backup is not valid for %s", operation.Kind())
	}
	if rollback.Operation != operation.Kind() || rollback.Node != node || rollback.GuestType != guestType ||
		rollback.VMID != vmid || rollback.Snapshot != expectedSnapshot || rollback.Storage != expectedStorage ||
		(rollback.PreviousStatus != "running" && rollback.PreviousStatus != "stopped") {
		return result, noMutationPVE("approved PVE safety-backup baseline does not match the operation")
	}
	for _, volume := range rollback.BeforeVolumes {
		if !validPVEBackupVolumeForGuest(volume, rollback.Storage, guestType, vmid) {
			return result, noMutationPVE("approved PVE safety-backup baseline contains an invalid volume")
		}
	}
	intent := pveTaskIntent{
		Version: pveTaskRecordVersion, Operation: rollback.Operation, Node: node,
		PlanHash: scope.PlanHash, PreconditionDigest: scope.PreconditionDigest,
		GuestType: guestType, VMID: vmid, Storage: rollback.Storage,
		BeforeVolumes: append([]string(nil), rollback.BeforeVolumes...),
	}
	if err := e.persistPVETaskIntent(scope.ChangeID, "pve-safety-backup-intent.json", intent); err != nil {
		return result, noMutationPVE("persist PVE safety-backup mutation intent before API: %w", err)
	}
	upid, err := e.startPVETask(ctx, node, "create", "/nodes/"+node+"/vzdump", pveBackupArgs(vmid, rollback.Storage)...)
	if err != nil {
		return result, uncertainPVE("start PVE safety backup before destructive snapshot action; task outcome requires recovery: %w", err)
	}
	record := pveTaskRecord{
		Version: pveTaskRecordVersion, Operation: rollback.Operation, Node: node,
		GuestType: guestType, VMID: vmid, UPID: upid, Storage: rollback.Storage,
		BeforeVolumes: append([]string(nil), rollback.BeforeVolumes...),
	}
	if err := e.persistPVETaskEvidence(scope, "pve-safety-backup-task.json", record, "pve:task:"+upid); err != nil {
		return result, uncertainPVE("PVE safety backup task %s started but all recovery evidence could not be persisted: %w", upid, err)
	}
	if err := e.waitPVETask(ctx, node, upid); err != nil {
		return result, uncertainPVE("PVE safety backup task %s did not reach stopped/OK: %w", upid, err)
	}
	volume, err := e.resolvePVEBackupVolume(ctx, node, rollback.Storage, guestType, vmid, rollback.BeforeVolumes)
	if err != nil {
		return result, uncertainPVE("PVE safety backup task %s completed but its unique backup volume is unresolved: %w", upid, err)
	}
	record.VolumeRef = volume
	if err := e.persistPVETaskEvidence(scope, "pve-safety-backup-task.json", record, "pve:volume:"+volume); err != nil {
		return result, uncertainPVE("persist PVE safety backup volume evidence: %w", err)
	}
	rollback.SafetyBackupUPID = upid
	payload, _ := json.Marshal(rollback)
	result.BackupRefs = []string{"pve:task:" + upid, "pve:volume:" + volume}
	result.RollbackData = payload
	result.RollbackAvailable = false
	return result, nil
}

func (e *OSExecutor) executePVE(ctx context.Context, scope ExecutionScope, operation protocol.Operation, result ExecutionResult) error {
	destructiveSnapshot := false
	switch operation.(type) {
	case *protocol.PVESnapshotDelete, *protocol.PVESnapshotRollback:
		destructiveSnapshot = true
		if err := e.requireApprovedPVEPrecondition(ctx, scope, operation); err != nil {
			return noMutationPVE("PVE preconditions changed before safety backup: %w", err)
		}
		updated, err := e.executeDestructivePVESnapshotSafetyBackup(ctx, scope, operation, result)
		if err != nil {
			return err
		}
		result = updated
	}
	verb, path, args, err := pveMutationSpec(operation)
	if err != nil {
		return err
	}
	intent, err := pvePrimaryIntent(scope, operation, result)
	if err != nil {
		if destructiveSnapshot {
			return fmt.Errorf("build PVE primary mutation intent after safety backup: %w", err)
		}
		return noMutationPVE("build PVE primary mutation intent before API: %w", err)
	}
	if err := e.persistPVETaskIntent(scope.ChangeID, "pve-primary-intent.json", intent); err != nil {
		if destructiveSnapshot {
			return fmt.Errorf("persist PVE primary mutation intent after safety backup: %w", err)
		}
		return noMutationPVE("persist PVE primary mutation intent before API: %w", err)
	}
	// The fsynced intent is ordered before this complete final observation. No
	// further PVE read or storage operation occurs between the check and API.
	if destructiveSnapshot {
		if err := e.requireApprovedDestructivePVESnapshotState(ctx, operation, result); err != nil {
			if markerErr := e.persistPVETaskIntent(scope.ChangeID, "pve-primary-no-start.json", intent); markerErr != nil {
				return fmt.Errorf("PVE preconditions changed after safety backup: %v; persist primary no-start evidence: %w", err, markerErr)
			}
			return fmt.Errorf("PVE preconditions changed after safety backup: %w", err)
		}
	} else if err := e.requireApprovedPVEPrecondition(ctx, scope, operation); err != nil {
		return noMutationPVE("PVE preconditions changed after preparation: %w", err)
	}
	upid, err := e.startPVETask(ctx, pveOperationNode(operation), verb, path, args...)
	if err != nil {
		return uncertainPVE("start PVE primary task after durable intent; task outcome requires recovery: %w", err)
	}
	node, guestType, vmid := pveOperationGuest(operation)
	record := pveTaskRecord{
		Version: pveTaskRecordVersion, Operation: operation.Kind(), Node: node,
		GuestType: guestType, VMID: vmid, UPID: upid,
	}
	if _, ok := operation.(*protocol.PVEGuestBackup); ok {
		metadata, decodeErr := decodePVERollback(result.RollbackData)
		if decodeErr != nil || metadata.Storage == "" {
			return uncertainPVE("PVE backup task %s started but its approved volume baseline is invalid", upid)
		}
		record.Storage, record.BeforeVolumes = metadata.Storage, append([]string(nil), metadata.BeforeVolumes...)
	}
	if err := e.persistPVETaskEvidence(scope, "pve-task.json", record, "pve:task:"+upid); err != nil {
		return uncertainPVE("PVE task %s started but all recovery evidence could not be persisted: %w", upid, err)
	}
	if err := e.waitPVETask(ctx, pveOperationNode(operation), upid); err != nil {
		return err
	}
	if record.Storage != "" {
		volume, err := e.resolvePVEBackupVolume(ctx, node, record.Storage, guestType, vmid, record.BeforeVolumes)
		if err != nil {
			return uncertainPVE("PVE backup task %s completed but its unique backup volume is unresolved: %w", upid, err)
		}
		record.VolumeRef = volume
		if err := e.persistPVETaskEvidence(scope, "pve-task.json", record, "pve:volume:"+volume); err != nil {
			return uncertainPVE("persist PVE backup volume evidence: %w", err)
		}
	}
	return nil
}

// StepPVEExecution advances a PVE mutation without ever waiting for a running
// UPID. Durable intent/task files are the phase journal: on restart their
// presence determines whether it is safe to start the next API call, resume a
// known task, or fail closed because an intent has no recoverable UPID.
func (e *OSExecutor) StepPVEExecution(
	ctx context.Context,
	scope ExecutionScope,
	operation protocol.Operation,
	result ExecutionResult,
) (PVEExecutionStep, error) {
	if e.Runner == nil {
		e.Runner = ExecRunner{}
	}
	if !isPVEOperation(operation) {
		return PVEExecutionStep{}, errors.New("async PVE execution requires a PVE operation")
	}
	if err := e.ValidateOperation(scope, operation); err != nil {
		return PVEExecutionStep{}, err
	}
	switch operation.(type) {
	case *protocol.PVESnapshotDelete, *protocol.PVESnapshotRollback:
		return e.stepDestructivePVESnapshot(ctx, scope, operation, result)
	default:
		return e.stepPVEPrimary(ctx, scope, operation, result, false)
	}
}

func (e *OSExecutor) stepDestructivePVESnapshot(
	ctx context.Context,
	scope ExecutionScope,
	operation protocol.Operation,
	result ExecutionResult,
) (PVEExecutionStep, error) {
	safetyIntent, safetyIntentExists, err := e.optionalPVETaskIntent(
		scope, "pve-safety-backup-intent.json", "safety-backup", operation,
	)
	if err != nil {
		return PVEExecutionStep{}, uncertainPVE("read PVE safety-backup intent: %w", err)
	}
	safetyRecord, safetyRecordExists, err := e.optionalPVETaskRecord(
		scope.ChangeID, "pve-safety-backup-task.json", operation,
	)
	if err != nil {
		return PVEExecutionStep{}, uncertainPVE("read PVE safety-backup task evidence: %w", err)
	}
	if safetyRecordExists && !safetyIntentExists {
		return PVEExecutionStep{}, uncertainPVE("PVE safety-backup task exists without its durable mutation intent")
	}
	if !safetyIntentExists {
		if err := e.requireApprovedPVEPrecondition(ctx, scope, operation); err != nil {
			return PVEExecutionStep{}, noMutationPVE("PVE preconditions changed before safety backup: %w", err)
		}
		record, startErr := e.startPVESafetyBackupTask(ctx, scope, operation, result)
		if startErr != nil {
			return PVEExecutionStep{}, startErr
		}
		return runningPVEStep(result, "safety-backup", record), nil
	}
	_ = safetyIntent // strict read above authenticates the durable phase journal.
	if !safetyRecordExists {
		return PVEExecutionStep{}, uncertainPVE("PVE safety-backup intent exists without a recoverable task UPID")
	}
	if safetyRecord.VolumeRef == "" {
		running, pollErr := e.pollPVETask(ctx, safetyRecord.Node, safetyRecord.UPID)
		if pollErr != nil {
			return PVEExecutionStep{}, pollErr
		}
		if running {
			return runningPVEStep(result, "safety-backup", safetyRecord), nil
		}
		volume, resolveErr := e.resolvePVEBackupVolume(
			ctx, safetyRecord.Node, safetyRecord.Storage, safetyRecord.GuestType,
			safetyRecord.VMID, safetyRecord.BeforeVolumes,
		)
		if resolveErr != nil {
			return PVEExecutionStep{}, uncertainPVE(
				"PVE safety backup task %s completed but its unique backup volume is unresolved: %w",
				safetyRecord.UPID, resolveErr,
			)
		}
		safetyRecord.VolumeRef = volume
		if err := e.persistPVETaskEvidence(
			scope, "pve-safety-backup-task.json", safetyRecord, "pve:volume:"+volume,
		); err != nil {
			return PVEExecutionStep{}, uncertainPVE("persist PVE safety backup volume evidence: %w", err)
		}
	}
	updated, err := pveSafetyBackupExecutionResult(operation, result, safetyRecord)
	if err != nil {
		return PVEExecutionStep{}, uncertainPVE("reconstruct PVE safety-backup checkpoint: %w", err)
	}
	return e.stepPVEPrimary(ctx, scope, operation, updated, true)
}

func (e *OSExecutor) stepPVEPrimary(
	ctx context.Context,
	scope ExecutionScope,
	operation protocol.Operation,
	result ExecutionResult,
	afterSafetyBackup bool,
) (PVEExecutionStep, error) {
	_, intentExists, err := e.optionalPVETaskIntent(scope, "pve-primary-intent.json", "primary", operation)
	if err != nil {
		return PVEExecutionStep{}, uncertainPVE("read PVE primary intent: %w", err)
	}
	record, recordExists, err := e.optionalPVETaskRecord(scope.ChangeID, "pve-task.json", operation)
	if err != nil {
		return PVEExecutionStep{}, uncertainPVE("read PVE primary task evidence: %w", err)
	}
	if recordExists && !intentExists {
		return PVEExecutionStep{}, uncertainPVE("PVE primary task exists without its durable mutation intent")
	}
	if !intentExists {
		record, err = e.startPVEPrimaryTask(ctx, scope, operation, result, afterSafetyBackup)
		if err != nil {
			return PVEExecutionStep{}, err
		}
		return runningPVEStep(result, "primary", record), nil
	}
	if !recordExists {
		if afterSafetyBackup {
			if _, noStart, markerErr := e.optionalPVETaskIntent(
				scope, "pve-primary-no-start.json", "primary", operation,
			); markerErr != nil {
				return PVEExecutionStep{}, uncertainPVE("read PVE primary no-start evidence: %w", markerErr)
			} else if noStart {
				return PVEExecutionStep{}, errors.New("PVE primary mutation did not start after its safety backup; typed recovery is required")
			}
		}
		return PVEExecutionStep{}, uncertainPVE("PVE primary intent exists without a recoverable task UPID")
	}
	running, err := e.pollPVETask(ctx, record.Node, record.UPID)
	if err != nil {
		return PVEExecutionStep{}, err
	}
	if running {
		return runningPVEStep(result, "primary", record), nil
	}
	result.BackupRefs = appendUniquePVERefs(result.BackupRefs, "pve:task:"+record.UPID)
	if record.Storage != "" && record.VolumeRef == "" {
		volume, resolveErr := e.resolvePVEBackupVolume(
			ctx, record.Node, record.Storage, record.GuestType, record.VMID, record.BeforeVolumes,
		)
		if resolveErr != nil {
			return PVEExecutionStep{}, uncertainPVE(
				"PVE backup task %s completed but its unique backup volume is unresolved: %w",
				record.UPID, resolveErr,
			)
		}
		record.VolumeRef = volume
		if err := e.persistPVETaskEvidence(scope, "pve-task.json", record, "pve:volume:"+volume); err != nil {
			return PVEExecutionStep{}, uncertainPVE("persist PVE backup volume evidence: %w", err)
		}
	}
	if record.VolumeRef != "" {
		result.BackupRefs = appendUniquePVERefs(result.BackupRefs, "pve:volume:"+record.VolumeRef)
	}
	return PVEExecutionStep{Result: result, Complete: true}, nil
}

func (e *OSExecutor) startPVESafetyBackupTask(
	ctx context.Context,
	scope ExecutionScope,
	operation protocol.Operation,
	result ExecutionResult,
) (pveTaskRecord, error) {
	rollback, err := decodePVERollback(result.RollbackData)
	if err != nil {
		return pveTaskRecord{}, noMutationPVE("decode approved PVE safety-backup baseline: %w", err)
	}
	node, guestType, vmid := pveOperationGuest(operation)
	expectedSnapshot, expectedStorage := "", ""
	switch value := operation.(type) {
	case *protocol.PVESnapshotDelete:
		expectedSnapshot, expectedStorage = value.Snapshot, value.BackupStorage
	case *protocol.PVESnapshotRollback:
		expectedSnapshot, expectedStorage = value.Snapshot, value.BackupStorage
	default:
		return pveTaskRecord{}, noMutationPVE("PVE safety backup is not valid for %s", operation.Kind())
	}
	if rollback.Operation != operation.Kind() || rollback.Node != node || rollback.GuestType != guestType ||
		rollback.VMID != vmid || rollback.Snapshot != expectedSnapshot || rollback.Storage != expectedStorage ||
		(rollback.PreviousStatus != "running" && rollback.PreviousStatus != "stopped") {
		return pveTaskRecord{}, noMutationPVE("approved PVE safety-backup baseline does not match the operation")
	}
	for _, volume := range rollback.BeforeVolumes {
		if !validPVEBackupVolumeForGuest(volume, rollback.Storage, guestType, vmid) {
			return pveTaskRecord{}, noMutationPVE("approved PVE safety-backup baseline contains an invalid volume")
		}
	}
	intent := pveTaskIntent{
		Version: pveTaskRecordVersion, Operation: rollback.Operation, Node: node,
		PlanHash: scope.PlanHash, PreconditionDigest: scope.PreconditionDigest,
		GuestType: guestType, VMID: vmid, Storage: rollback.Storage,
		BeforeVolumes: append([]string(nil), rollback.BeforeVolumes...),
	}
	if err := e.persistPVETaskIntent(scope.ChangeID, "pve-safety-backup-intent.json", intent); err != nil {
		return pveTaskRecord{}, noMutationPVE("persist PVE safety-backup mutation intent before API: %w", err)
	}
	upid, err := e.startPVETask(ctx, node, "create", "/nodes/"+node+"/vzdump", pveBackupArgs(vmid, rollback.Storage)...)
	if err != nil {
		return pveTaskRecord{}, uncertainPVE("start PVE safety backup before destructive snapshot action; task outcome requires recovery: %w", err)
	}
	record := pveTaskRecord{
		Version: pveTaskRecordVersion, Operation: rollback.Operation, Node: node,
		GuestType: guestType, VMID: vmid, UPID: upid, Storage: rollback.Storage,
		BeforeVolumes: append([]string(nil), rollback.BeforeVolumes...),
	}
	if err := e.persistPVETaskEvidence(scope, "pve-safety-backup-task.json", record, "pve:task:"+upid); err != nil {
		return pveTaskRecord{}, uncertainPVE("PVE safety backup task %s started but all recovery evidence could not be persisted: %w", upid, err)
	}
	return record, nil
}

func (e *OSExecutor) startPVEPrimaryTask(
	ctx context.Context,
	scope ExecutionScope,
	operation protocol.Operation,
	result ExecutionResult,
	afterSafetyBackup bool,
) (pveTaskRecord, error) {
	verb, path, args, err := pveMutationSpec(operation)
	if err != nil {
		return pveTaskRecord{}, err
	}
	intent, err := pvePrimaryIntent(scope, operation, result)
	if err != nil {
		if afterSafetyBackup {
			return pveTaskRecord{}, fmt.Errorf("build PVE primary mutation intent after safety backup: %w", err)
		}
		return pveTaskRecord{}, noMutationPVE("build PVE primary mutation intent before API: %w", err)
	}
	if err := e.persistPVETaskIntent(scope.ChangeID, "pve-primary-intent.json", intent); err != nil {
		if afterSafetyBackup {
			return pveTaskRecord{}, fmt.Errorf("persist PVE primary mutation intent after safety backup: %w", err)
		}
		return pveTaskRecord{}, noMutationPVE("persist PVE primary mutation intent before API: %w", err)
	}
	if afterSafetyBackup {
		if err := e.requireApprovedDestructivePVESnapshotState(ctx, operation, result); err != nil {
			if markerErr := e.persistPVETaskIntent(scope.ChangeID, "pve-primary-no-start.json", intent); markerErr != nil {
				return pveTaskRecord{}, fmt.Errorf("PVE preconditions changed after safety backup: %v; persist primary no-start evidence: %w", err, markerErr)
			}
			return pveTaskRecord{}, fmt.Errorf("PVE preconditions changed after safety backup: %w", err)
		}
	} else if err := e.requireApprovedPVEPrecondition(ctx, scope, operation); err != nil {
		return pveTaskRecord{}, noMutationPVE("PVE preconditions changed after preparation: %w", err)
	}
	node, guestType, vmid := pveOperationGuest(operation)
	upid, err := e.startPVETask(ctx, node, verb, path, args...)
	if err != nil {
		return pveTaskRecord{}, uncertainPVE("start PVE primary task after durable intent; task outcome requires recovery: %w", err)
	}
	record := pveTaskRecord{
		Version: pveTaskRecordVersion, Operation: operation.Kind(), Node: node,
		GuestType: guestType, VMID: vmid, UPID: upid,
	}
	if _, ok := operation.(*protocol.PVEGuestBackup); ok {
		metadata, decodeErr := decodePVERollback(result.RollbackData)
		if decodeErr != nil || metadata.Storage == "" {
			return pveTaskRecord{}, uncertainPVE("PVE backup task %s started but its approved volume baseline is invalid", upid)
		}
		record.Storage = metadata.Storage
		record.BeforeVolumes = append([]string(nil), metadata.BeforeVolumes...)
	}
	if err := e.persistPVETaskEvidence(scope, "pve-task.json", record, "pve:task:"+upid); err != nil {
		return pveTaskRecord{}, uncertainPVE("PVE task %s started but all recovery evidence could not be persisted: %w", upid, err)
	}
	return record, nil
}

func (e *OSExecutor) optionalPVETaskIntent(
	scope ExecutionScope,
	filename string,
	role string,
	operation protocol.Operation,
) (pveTaskIntent, bool, error) {
	value, err := e.readPVETaskIntent(scope, filename, role, operation)
	if errors.Is(err, os.ErrNotExist) {
		return pveTaskIntent{}, false, nil
	}
	return value, err == nil, err
}

func (e *OSExecutor) optionalPVETaskRecord(
	changeID string,
	filename string,
	operation protocol.Operation,
) (pveTaskRecord, bool, error) {
	value, err := e.readPVETaskRecord(changeID, filename, operation)
	if errors.Is(err, os.ErrNotExist) {
		return pveTaskRecord{}, false, nil
	}
	return value, err == nil, err
}

func runningPVEStep(result ExecutionResult, role string, record pveTaskRecord) PVEExecutionStep {
	result.BackupRefs = appendUniquePVERefs(result.BackupRefs, "pve:task:"+record.UPID)
	if record.VolumeRef != "" {
		result.BackupRefs = appendUniquePVERefs(result.BackupRefs, "pve:volume:"+record.VolumeRef)
	}
	return PVEExecutionStep{
		Result: result, Running: true, Role: role, Node: record.Node, UPID: record.UPID,
	}
}

func appendUniquePVERefs(existing []string, refs ...string) []string {
	result := append([]string(nil), existing...)
	for _, ref := range refs {
		if !slices.Contains(result, ref) {
			result = append(result, ref)
		}
	}
	return result
}

func pveSafetyBackupExecutionResult(
	operation protocol.Operation,
	result ExecutionResult,
	record pveTaskRecord,
) (ExecutionResult, error) {
	rollback, err := decodePVERollback(result.RollbackData)
	if err != nil {
		return result, err
	}
	node, guestType, vmid := pveOperationGuest(operation)
	if record.VolumeRef == "" || rollback.Operation != operation.Kind() || rollback.Node != node ||
		rollback.GuestType != guestType || rollback.VMID != vmid || record.Node != node ||
		record.GuestType != guestType || record.VMID != vmid || record.Storage != rollback.Storage ||
		!slices.Equal(record.BeforeVolumes, rollback.BeforeVolumes) {
		return result, errors.New("PVE safety-backup task does not match its approved baseline")
	}
	rollback.SafetyBackupUPID = record.UPID
	payload, err := json.Marshal(rollback)
	if err != nil {
		return result, err
	}
	result.RollbackData = payload
	result.RollbackAvailable = false
	result.BackupRefs = appendUniquePVERefs(
		result.BackupRefs, "pve:task:"+record.UPID, "pve:volume:"+record.VolumeRef,
	)
	return result, nil
}

func pvePrimaryIntent(scope ExecutionScope, operation protocol.Operation, result ExecutionResult) (pveTaskIntent, error) {
	node, guestType, vmid := pveOperationGuest(operation)
	intent := pveTaskIntent{
		Version: pveTaskRecordVersion, Operation: operation.Kind(), Node: node,
		PlanHash: scope.PlanHash, PreconditionDigest: scope.PreconditionDigest,
		GuestType: guestType, VMID: vmid,
	}
	if _, ok := operation.(*protocol.PVEGuestBackup); ok {
		metadata, err := decodePVERollback(result.RollbackData)
		if err != nil || metadata.Operation != operation.Kind() || metadata.Node != node ||
			metadata.GuestType != guestType || metadata.VMID != vmid || metadata.Storage == "" {
			return pveTaskIntent{}, errors.New("approved PVE backup baseline is invalid")
		}
		intent.Storage = metadata.Storage
		intent.BeforeVolumes = append([]string(nil), metadata.BeforeVolumes...)
	}
	return intent, nil
}

// requireApprovedDestructivePVESnapshotState permits exactly the one backup
// volume produced by the approved safety-backup substep. Every other
// root-observed field remains bound to what the human approved, including the
// guest running state. This avoids treating the whole precondition digest as
// disposable merely because one expected set member was added.
func (e *OSExecutor) requireApprovedDestructivePVESnapshotState(
	ctx context.Context,
	operation protocol.Operation,
	result ExecutionResult,
) error {
	rollback, err := decodePVERollback(result.RollbackData)
	if err != nil {
		return fmt.Errorf("decode safety-backup evidence: %w", err)
	}
	node, guestType, vmid := pveOperationGuest(operation)
	if rollback.Operation != operation.Kind() || rollback.Node != node || rollback.GuestType != guestType ||
		rollback.VMID != vmid || (rollback.PreviousStatus != "running" && rollback.PreviousStatus != "stopped") ||
		!protocol.ValidPVEStorage(rollback.Storage) {
		return errors.New("safety-backup evidence is not bound to the approved guest")
	}
	if err := e.requirePVEReady(ctx, node); err != nil {
		return err
	}
	status, err := e.readPVEGuestStatus(ctx, node, guestType, vmid)
	if err != nil {
		return err
	}
	if err := requireUnlockedPVEGuest(status); err != nil {
		return err
	}
	if status.Status != rollback.PreviousStatus {
		return fmt.Errorf("approved guest status changed from %q to %q", rollback.PreviousStatus, status.Status)
	}
	exists, err := e.pveSnapshotExists(ctx, node, guestType, vmid, rollback.Snapshot)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("approved PVE snapshot no longer exists after safety backup")
	}
	if err := e.requirePVEStorage(ctx, node, rollback.Storage); err != nil {
		return err
	}
	createdVolume := ""
	for _, ref := range result.BackupRefs {
		if !strings.HasPrefix(ref, "pve:volume:") {
			continue
		}
		if createdVolume != "" {
			return errors.New("safety backup has more than one recorded volume")
		}
		createdVolume = strings.TrimPrefix(ref, "pve:volume:")
	}
	if !validPVEBackupVolumeForGuest(createdVolume, rollback.Storage, guestType, vmid) {
		return errors.New("safety backup has no valid guest-bound volume evidence")
	}
	actual, err := e.pveBackupVolumes(ctx, node, rollback.Storage, guestType, vmid)
	if err != nil {
		return err
	}
	expected := append(append([]string(nil), rollback.BeforeVolumes...), createdVolume)
	sort.Strings(expected)
	if !slices.Equal(actual, expected) {
		return errors.New("backup volume set changed beyond the approved safety backup")
	}
	return nil
}

func pveMutationSpec(operation protocol.Operation) (string, string, []string, error) {
	node, guestType, vmid := pveOperationGuest(operation)
	base := pveGuestPath(node, guestType, vmid)
	switch value := operation.(type) {
	case *protocol.PVEGuestAction:
		return "create", base + "/status/" + value.Action, nil, nil
	case *protocol.PVESnapshotCreate:
		args := []string{"--snapname", value.Snapshot}
		if value.Description != "" {
			args = append(args, "--description", value.Description)
		}
		if value.GuestType == "qemu" {
			args = append(args, "--vmstate", "0")
		}
		return "create", base + "/snapshot", args, nil
	case *protocol.PVESnapshotDelete:
		return "delete", base + "/snapshot/" + value.Snapshot, nil, nil
	case *protocol.PVESnapshotRollback:
		return "create", base + "/snapshot/" + value.Snapshot + "/rollback", nil, nil
	case *protocol.PVEGuestBackup:
		return "create", "/nodes/" + value.Node + "/vzdump", pveBackupArgs(value.VMID, value.Storage), nil
	case *protocol.PVEGuestRestore:
		args := []string{"--vmid", strconv.Itoa(value.VMID), "--storage", value.Storage, "--start", "0"}
		if value.GuestType == "qemu" {
			args = append(args, "--archive", value.BackupVolume)
		} else {
			args = append(args, "--ostemplate", value.BackupVolume, "--restore", "1")
		}
		return "create", "/nodes/" + value.Node + "/" + value.GuestType, args, nil
	case *protocol.PVEGuestMigrate:
		args := []string{"--target", value.TargetNode}
		if value.GuestType == "qemu" {
			if value.Online {
				args = append(args, "--online", "1")
			}
			if value.WithLocalDisks {
				args = append(args, "--with-local-disks", "1")
			}
		} else if value.Restart {
			args = append(args, "--restart", "1")
		}
		return "create", base + "/migrate", args, nil
	default:
		return "", "", nil, errors.New("unsupported PVE operation")
	}
}

func pveBackupArgs(vmid int, storage string) []string {
	return []string{
		"--vmid", strconv.Itoa(vmid), "--storage", storage,
		"--mode", "snapshot", "--compress", "zstd", "--remove", "0",
	}
}

func (e *OSExecutor) verifyPVE(ctx context.Context, scope ExecutionScope, operation protocol.Operation, result ExecutionResult) (string, error) {
	record, err := e.readPVETask(scope.ChangeID, operation)
	if err != nil {
		return "", uncertainPVE("read PVE primary task evidence: %w", err)
	}
	if err := e.waitPVETask(ctx, record.Node, record.UPID); err != nil {
		return "", err
	}
	node, guestType, vmid := pveOperationGuest(operation)
	switch value := operation.(type) {
	case *protocol.PVEGuestAction:
		status, err := e.readPVEGuestStatus(ctx, node, guestType, vmid)
		if err != nil {
			return "", uncertainPVE("read PVE guest state after lifecycle task: %w", err)
		}
		expected := "running"
		if value.Action == "shutdown" || value.Action == "stop" {
			expected = "stopped"
		}
		if status.Status != expected || status.Lock != "" {
			return "", fmt.Errorf("PVE guest state is %q with lock %q; expected %q and unlocked", status.Status, status.Lock, expected)
		}
	case *protocol.PVESnapshotCreate:
		exists, err := e.pveSnapshotExists(ctx, node, guestType, vmid, value.Snapshot)
		if err != nil {
			return "", uncertainPVE("read PVE snapshot after create task: %w", err)
		}
		if !exists {
			return "", errors.New("PVE snapshot is absent after the create task")
		}
	case *protocol.PVESnapshotDelete:
		exists, err := e.pveSnapshotExists(ctx, node, guestType, vmid, value.Snapshot)
		if err != nil {
			return "", uncertainPVE("read PVE snapshot after delete task: %w", err)
		}
		if exists {
			return "", errors.New("PVE snapshot still exists after the delete task")
		}
	case *protocol.PVESnapshotRollback:
		if err := e.requireUnlockedPVEGuestRef(ctx, node, guestType, vmid); err != nil {
			return "", uncertainPVE("read PVE guest after snapshot rollback: %w", err)
		}
	case *protocol.PVEGuestBackup:
		if record.VolumeRef == "" {
			return "", uncertainPVE("PVE backup task has no unique volume evidence")
		}
		exists, err := e.pveBackupVolumeExists(ctx, node, record.Storage, guestType, vmid, record.VolumeRef)
		if err != nil {
			return "", uncertainPVE("verify PVE backup volume: %w", err)
		}
		if !exists {
			return "", errors.New("PVE backup volume disappeared after the completed task")
		}
	case *protocol.PVEGuestRestore:
		status, err := e.readPVEGuestStatus(ctx, node, guestType, vmid)
		if err != nil {
			return "", uncertainPVE("read restored PVE guest: %w", err)
		}
		if status.Status != "stopped" || status.Lock != "" {
			return "", fmt.Errorf("restored PVE guest is %q with lock %q; expected stopped and unlocked", status.Status, status.Lock)
		}
	case *protocol.PVEGuestMigrate:
		metadata, err := decodePVERollback(result.RollbackData)
		if err != nil || (metadata.PreviousStatus != "running" && metadata.PreviousStatus != "stopped") {
			return "", errors.New("PVE migration is missing its approved previous state")
		}
		exists, existingNode, err := e.pveGuestExists(ctx, guestType, vmid)
		if err != nil {
			return "", uncertainPVE("locate PVE guest after migration: %w", err)
		}
		if !exists || existingNode != value.TargetNode {
			return "", errors.New("PVE guest did not settle on the approved migration target")
		}
		if err := e.requireUnlockedPVEGuestRef(ctx, value.TargetNode, guestType, vmid); err != nil {
			return "", uncertainPVE("read PVE guest on migration target: %w", err)
		}
		status, err := e.readPVEGuestStatus(ctx, value.TargetNode, guestType, vmid)
		if err != nil {
			return "", uncertainPVE("read PVE guest final migration state: %w", err)
		}
		if status.Status != metadata.PreviousStatus {
			return "", fmt.Errorf("PVE migrated guest state is %q; expected approved state %q", status.Status, metadata.PreviousStatus)
		}
	}
	verification := "PVE task " + record.UPID + " reached stopped/OK and postconditions passed"
	if record.VolumeRef != "" {
		verification += "; backup volume=" + record.VolumeRef
	}
	return verification, nil
}

func (e *OSExecutor) requirePVEReady(ctx context.Context, node string) error {
	var entries []pveClusterStatus
	if err := e.pveGetList(ctx, "/cluster/status", &entries); err != nil {
		return err
	}
	if err := validatePVEClusterStatusEntries(entries); err != nil {
		return err
	}
	clustered, quorate, online, standalone := false, false, false, false
	for _, entry := range entries {
		if entry.Type == "cluster" {
			clustered = true
			quorate = entry.Quorate == 1
		}
		entryNode := entry.Node
		if entryNode == "" {
			entryNode = entry.Name
		}
		if entry.Type == "node" && entryNode == node && entry.Online == 1 {
			online = true
			// A node that has never joined a Corosync cluster has no cluster
			// row, is the local row, and uses nodeid 0. This is the only
			// quorum-free mode accepted; a former cluster member with a
			// non-zero nodeid cannot silently fall back to standalone mode.
			standalone = entry.Local == 1 && entry.NodeID == 0
		}
	}
	if clustered && !quorate {
		return errors.New("PVE cluster is not quorate")
	}
	if !online {
		return errors.New("approved PVE node is not online")
	}
	if !clustered && !standalone {
		return errors.New("PVE node is neither a quorate cluster member nor an explicit standalone node")
	}
	return nil
}

func (e *OSExecutor) requirePVEStorage(ctx context.Context, node, storage string) error {
	var status pveStorageStatus
	if err := e.pveGetObject(ctx, "/nodes/"+node+"/storage/"+storage+"/status", &status); err != nil {
		return err
	}
	if status.Active != 1 || status.Enabled != 1 {
		return errors.New("approved PVE storage is not active and enabled")
	}
	return nil
}

func (e *OSExecutor) requireUnlockedPVEGuestRef(ctx context.Context, node, guestType string, vmid int) error {
	status, err := e.readPVEGuestStatus(ctx, node, guestType, vmid)
	if err != nil {
		return err
	}
	return requireUnlockedPVEGuest(status)
}

func requireUnlockedPVEGuest(status pveGuestStatus) error {
	if status.Status != "running" && status.Status != "stopped" {
		return fmt.Errorf("PVE guest has unsupported state %q", status.Status)
	}
	if status.Lock != "" {
		return fmt.Errorf("PVE guest is locked: %s", status.Lock)
	}
	return nil
}

func (e *OSExecutor) readPVEGuestStatus(ctx context.Context, node, guestType string, vmid int) (pveGuestStatus, error) {
	var status pveGuestStatus
	err := e.pveGetObject(ctx, pveGuestPath(node, guestType, vmid)+"/status/current", &status)
	return status, err
}

func (e *OSExecutor) pveGuestExists(ctx context.Context, guestType string, vmid int) (bool, string, error) {
	var resources []pveGuestResource
	if err := e.pveGetList(ctx, "/cluster/resources", &resources, "--type", "vm"); err != nil {
		return false, "", err
	}
	foundNode := ""
	for _, resource := range resources {
		if resource.VMID != vmid {
			continue
		}
		if resource.Type != guestType {
			return false, "", fmt.Errorf("PVE VMID %d is occupied by guest type %s", vmid, resource.Type)
		}
		if resource.Type == guestType {
			if foundNode != "" && foundNode != resource.Node {
				return false, "", errors.New("PVE guest identity appears on multiple nodes")
			}
			foundNode = resource.Node
		}
	}
	return foundNode != "", foundNode, nil
}

func (e *OSExecutor) pveSnapshotExists(ctx context.Context, node, guestType string, vmid int, snapshot string) (bool, error) {
	var snapshots []pveSnapshot
	if err := e.pveGetList(ctx, pveGuestPath(node, guestType, vmid)+"/snapshot", &snapshots); err != nil {
		return false, err
	}
	for _, item := range snapshots {
		if item.Name == snapshot {
			return true, nil
		}
	}
	return false, nil
}

func (e *OSExecutor) startPVETask(ctx context.Context, node, verb, path string, args ...string) (string, error) {
	output, err := e.pveCommand(ctx, verb, path, args...)
	if err != nil {
		return "", uncertainPVE("PVE mutation request may have reached the API without a recoverable UPID: %w", err)
	}
	var upid string
	if err := decodePVEValue(output, &upid); err != nil {
		return "", uncertainPVE("PVE mutation response has no recoverable task UPID: %w", err)
	}
	if !protocol.ValidPVEUPIDForNode(upid, node) {
		return "", uncertainPVE("PVE mutation did not return a valid node-bound task UPID")
	}
	return upid, nil
}

func (e *OSExecutor) waitPVETask(ctx context.Context, node, upid string) error {
	for {
		running, err := e.pollPVETask(ctx, node, upid)
		if err != nil {
			return err
		}
		if !running {
			return nil
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return uncertainPVE("wait for PVE task %s: %w", upid, ctx.Err())
		case <-timer.C:
		}
	}
}

// pollPVETask performs exactly one authoritative node-bound task observation.
// A running result is not an error and is intentionally returned to the
// broker-owned reconciler instead of sleeping under a caller's HTTP context.
func (e *OSExecutor) pollPVETask(ctx context.Context, node, upid string) (bool, error) {
	var status pveTaskStatus
	if err := e.pveGetObject(ctx, "/nodes/"+node+"/tasks/"+upid+"/status", &status); err != nil {
		return false, uncertainPVE("query PVE task %s status: %w", upid, err)
	}
	if status.Status == "running" {
		return true, nil
	}
	if status.Status != "stopped" {
		return false, uncertainPVE("PVE task %s returned unsupported status %q", upid, status.Status)
	}
	if status.ExitStatus != "OK" {
		return false, fmt.Errorf("PVE task %s stopped with exitstatus %q", upid, status.ExitStatus)
	}
	return false, nil
}

func (e *OSExecutor) pveGetList(ctx context.Context, path string, target interface{}, args ...string) error {
	return e.pveGetShaped(ctx, path, target, '[', "array", args...)
}

func (e *OSExecutor) pveGetObject(ctx context.Context, path string, target interface{}, args ...string) error {
	return e.pveGetShaped(ctx, path, target, '{', "object", args...)
}

func (e *OSExecutor) pveGetShaped(ctx context.Context, path string, target interface{}, opening byte, shape string, args ...string) error {
	output, err := e.pveCommand(ctx, "get", path, args...)
	if err != nil {
		return err
	}
	trimmed := bytes.TrimSpace([]byte(output))
	if len(trimmed) == 0 || trimmed[0] != opening {
		return fmt.Errorf("PVE JSON response for %s must be a non-null %s", path, shape)
	}
	return decodePVEValue(output, target)
}

func (e *OSExecutor) pveCommand(ctx context.Context, verb, path string, args ...string) (string, error) {
	commandArgs := []string{verb, path}
	commandArgs = append(commandArgs, args...)
	commandArgs = append(commandArgs, "--output-format", "json")
	output, err := e.Runner.Run(ctx, pveshPath, commandArgs...)
	if err != nil {
		return "", fmt.Errorf("pvesh %s failed: %w", verb, err)
	}
	if len(output) > maxCommandOutput {
		return "", errors.New("PVE command output exceeds the limit")
	}
	return output, nil
}

func decodePVEValue(output string, target interface{}) error {
	decoder := json.NewDecoder(bytes.NewReader([]byte(output)))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("PVE JSON response has a trailing value")
	}
	return nil
}

func recordPVEEvidence(scope ExecutionScope, refs ...string) error {
	if scope.RecordEvidence == nil {
		return nil
	}
	return scope.RecordEvidence(refs...)
}

func (e *OSExecutor) persistPVETaskEvidence(scope ExecutionScope, filename string, record pveTaskRecord, refs ...string) error {
	// Attempt both independent durable sinks. A filesystem failure must not
	// prevent the authoritative Change store from retaining the UPID, and an
	// audit/store failure must not discard the root-only task record.
	recordErr := e.persistPVETaskRecord(scope.ChangeID, filename, record)
	changeErr := recordPVEEvidence(scope, refs...)
	return errors.Join(recordErr, changeErr)
}

func (e *OSExecutor) pveBackupVolumes(ctx context.Context, node, storage, guestType string, vmid int) ([]string, error) {
	var contents []pveStorageContent
	if err := e.pveGetList(ctx, "/nodes/"+node+"/storage/"+storage+"/content", &contents,
		"--content", "backup", "--vmid", strconv.Itoa(vmid)); err != nil {
		return nil, err
	}
	volumes := make([]string, 0, len(contents))
	for _, content := range contents {
		if content.Content != "" && content.Content != "backup" {
			continue
		}
		if content.VMID != 0 && content.VMID != vmid {
			continue
		}
		if validPVEBackupVolumeForGuest(content.VolID, storage, guestType, vmid) {
			volumes = append(volumes, content.VolID)
		}
	}
	sort.Strings(volumes)
	for index := 1; index < len(volumes); index++ {
		if volumes[index] == volumes[index-1] {
			return nil, errors.New("PVE storage returned a duplicate backup volume")
		}
	}
	return volumes, nil
}

func validPVEBackupVolumeForGuest(volume, storage, guestType string, vmid int) bool {
	prefix := fmt.Sprintf("%s:backup/vzdump-%s-%d-", storage, guestType, vmid)
	return len(volume) <= 512 && strings.HasPrefix(volume, prefix) && !strings.ContainsAny(volume, "\x00\r\n") && !strings.Contains(volume, "..")
}

func (e *OSExecutor) resolvePVEBackupVolume(ctx context.Context, node, storage, guestType string, vmid int, before []string) (string, error) {
	after, err := e.pveBackupVolumes(ctx, node, storage, guestType, vmid)
	if err != nil {
		return "", err
	}
	known := make(map[string]struct{}, len(before))
	for _, volume := range before {
		if !validPVEBackupVolumeForGuest(volume, storage, guestType, vmid) {
			return "", errors.New("PVE backup baseline contains an invalid volume")
		}
		known[volume] = struct{}{}
	}
	created := make([]string, 0, 1)
	for _, volume := range after {
		if _, exists := known[volume]; !exists {
			created = append(created, volume)
		}
	}
	if len(created) != 1 {
		return "", fmt.Errorf("PVE backup produced %d uniquely attributable volumes", len(created))
	}
	return created[0], nil
}

func (e *OSExecutor) pveBackupVolumeExists(ctx context.Context, node, storage, guestType string, vmid int, volume string) (bool, error) {
	volumes, err := e.pveBackupVolumes(ctx, node, storage, guestType, vmid)
	if err != nil {
		return false, err
	}
	for _, candidate := range volumes {
		if candidate == volume {
			return true, nil
		}
	}
	return false, nil
}

func (e *OSExecutor) persistPVETaskRecord(changeID, filename string, record pveTaskRecord) error {
	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}
	directory := filepath.Join(e.StateDir, "changes", changeID)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	return atomicReplace(filepath.Join(directory, filename), payload, 0o600, -1, -1)
}

func (e *OSExecutor) persistPVETaskIntent(changeID, filename string, intent pveTaskIntent) error {
	payload, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	directory := filepath.Join(e.StateDir, "changes", changeID)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	return atomicReplace(filepath.Join(directory, filename), payload, 0o600, -1, -1)
}

func (e *OSExecutor) readPVETaskIntent(scope ExecutionScope, filename, role string, operation protocol.Operation) (pveTaskIntent, error) {
	path := filepath.Join(e.StateDir, "changes", scope.ChangeID, filename)
	payload, err := os.ReadFile(path)
	if err != nil {
		return pveTaskIntent{}, err
	}
	var intent pveTaskIntent
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&intent); err != nil {
		return pveTaskIntent{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return pveTaskIntent{}, errors.New("PVE task intent has a trailing value")
	}
	node, guestType, vmid := pveOperationGuest(operation)
	if intent.Version != pveTaskRecordVersion || intent.Operation != operation.Kind() || intent.Node != node ||
		intent.GuestType != guestType || intent.VMID != vmid || intent.PlanHash != scope.PlanHash ||
		intent.PreconditionDigest != scope.PreconditionDigest || !validSecureFileDigest(intent.PlanHash) ||
		!validSecureFileDigest(intent.PreconditionDigest) {
		return pveTaskIntent{}, errors.New("PVE task intent does not match the approved operation")
	}
	expectedStorage := ""
	switch role {
	case "safety-backup":
		switch value := operation.(type) {
		case *protocol.PVESnapshotDelete:
			expectedStorage = value.BackupStorage
		case *protocol.PVESnapshotRollback:
			expectedStorage = value.BackupStorage
		default:
			return pveTaskIntent{}, errors.New("unexpected PVE safety-backup intent for operation")
		}
	case "primary":
		if value, ok := operation.(*protocol.PVEGuestBackup); ok {
			expectedStorage = value.Storage
		}
	default:
		return pveTaskIntent{}, errors.New("unsupported PVE task intent role")
	}
	if intent.Storage != expectedStorage {
		return pveTaskIntent{}, errors.New("PVE task intent storage does not match the approved operation")
	}
	if expectedStorage == "" && len(intent.BeforeVolumes) != 0 {
		return pveTaskIntent{}, errors.New("PVE task intent has an unexpected backup baseline")
	}
	for _, volume := range intent.BeforeVolumes {
		if !validPVEBackupVolumeForGuest(volume, intent.Storage, guestType, vmid) {
			return pveTaskIntent{}, errors.New("PVE task intent has an invalid backup baseline")
		}
	}
	return intent, nil
}

func (e *OSExecutor) readPVETask(changeID string, operation protocol.Operation) (pveTaskRecord, error) {
	return e.readPVETaskRecord(changeID, "pve-task.json", operation)
}

func (e *OSExecutor) readPVETaskRecord(changeID, filename string, operation protocol.Operation) (pveTaskRecord, error) {
	path := filepath.Join(e.StateDir, "changes", changeID, filename)
	payload, err := os.ReadFile(path)
	if err != nil {
		return pveTaskRecord{}, err
	}
	var record pveTaskRecord
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return pveTaskRecord{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return pveTaskRecord{}, errors.New("PVE task recovery record has a trailing value")
	}
	node, guestType, vmid := pveOperationGuest(operation)
	if record.Version != pveTaskRecordVersion || record.Operation != operation.Kind() || record.Node != node ||
		record.GuestType != guestType || record.VMID != vmid || !protocol.ValidPVEUPIDForNode(record.UPID, record.Node) {
		return pveTaskRecord{}, errors.New("PVE task recovery record does not match the approved operation")
	}
	if record.Storage != "" {
		if !protocol.ValidPVEStorage(record.Storage) {
			return pveTaskRecord{}, errors.New("PVE task recovery record has an invalid storage")
		}
		for _, volume := range record.BeforeVolumes {
			if !validPVEBackupVolumeForGuest(volume, record.Storage, record.GuestType, record.VMID) {
				return pveTaskRecord{}, errors.New("PVE task recovery record has an invalid backup baseline")
			}
		}
		if record.VolumeRef != "" && !validPVEBackupVolumeForGuest(record.VolumeRef, record.Storage, record.GuestType, record.VMID) {
			return pveTaskRecord{}, errors.New("PVE task recovery record has an invalid backup volume")
		}
	} else if len(record.BeforeVolumes) != 0 || record.VolumeRef != "" {
		return pveTaskRecord{}, errors.New("PVE task recovery record has volume evidence without storage")
	}
	return record, nil
}

func (e *OSExecutor) RecoverEvidence(ctx context.Context, scope ExecutionScope, operation protocol.Operation) ([]string, error) {
	if !isPVEOperation(operation) {
		return nil, nil
	}
	readiness, err := e.ReconcilePVERecoveryParent(ctx, scope, operation)
	return readiness.EvidenceRefs, err
}

// ReconcilePVERecoveryParent proves that no known PVE task can still mutate
// the parent's VMID. It queries every durable UPID and rejects running,
// unsupported, unqueryable, and lost-UPID intents. For mutation protocol v1,
// the fsynced primary intent is ordered before the primary API call, so its
// absence is authoritative evidence that that phase was never attempted.
func (e *OSExecutor) ReconcilePVERecoveryParent(
	ctx context.Context,
	scope ExecutionScope,
	operation protocol.Operation,
) (PVERecoveryReadiness, error) {
	result := PVERecoveryReadiness{EvidenceRefs: make([]string, 0, 4)}
	if !isPVEOperation(operation) {
		return result, errors.New("PVE recovery readiness requires a PVE operation")
	}
	type taskSlot struct {
		role       string
		intentFile string
		taskFile   string
	}
	slots := []taskSlot{
		{role: "safety-backup", intentFile: "pve-safety-backup-intent.json", taskFile: "pve-safety-backup-task.json"},
		{role: "primary", intentFile: "pve-primary-intent.json", taskFile: "pve-task.json"},
	}
	artifactCount := 0
	primaryIntent, primaryTask, primaryNoStart := false, false, false
	for _, slot := range slots {
		_, intentErr := e.readPVETaskIntent(scope, slot.intentFile, slot.role, operation)
		intentExists := intentErr == nil
		if intentErr != nil && !errors.Is(intentErr, os.ErrNotExist) {
			return result, fmt.Errorf("read PVE %s task intent: %w", slot.role, intentErr)
		}
		record, recordErr := e.readPVETaskRecord(scope.ChangeID, slot.taskFile, operation)
		recordExists := recordErr == nil
		if recordErr != nil && !errors.Is(recordErr, os.ErrNotExist) {
			return result, fmt.Errorf("read PVE %s task record: %w", slot.role, recordErr)
		}
		if intentExists {
			artifactCount++
		}
		if recordExists {
			artifactCount++
		}
		if slot.role == "primary" {
			primaryIntent, primaryTask = intentExists, recordExists
			marker, markerErr := e.readPVETaskIntent(scope, "pve-primary-no-start.json", slot.role, operation)
			primaryNoStart = markerErr == nil
			if markerErr != nil && !errors.Is(markerErr, os.ErrNotExist) {
				return result, fmt.Errorf("read PVE primary no-start evidence: %w", markerErr)
			}
			if primaryNoStart {
				artifactCount++
				intent, err := e.readPVETaskIntent(scope, slot.intentFile, slot.role, operation)
				if err != nil || !samePVETaskIntent(intent, marker) || recordExists {
					return result, errors.New("PVE primary no-start evidence does not match one unresolved intent")
				}
			}
		}
		if intentExists && !recordExists && scope.MutationDisposition != protocol.PVEMutationDispositionNotStarted &&
			!(slot.role == "primary" && primaryNoStart) {
			return result, fmt.Errorf("PVE %s intent exists without a recoverable task UPID; local recovery clearance is required", slot.role)
		}
		if !recordExists {
			continue
		}
		if scope.MutationDisposition == protocol.PVEMutationDispositionNotStarted {
			return result, fmt.Errorf("PVE mutation is marked not-started but has a %s task record", slot.role)
		}
		result.EvidenceRefs = append(result.EvidenceRefs, "pve:task:"+record.UPID)
		var status pveTaskStatus
		if err := e.pveGetObject(ctx, "/nodes/"+record.Node+"/tasks/"+record.UPID+"/status", &status); err != nil {
			return result, fmt.Errorf("query PVE %s task %s terminal state: %w", slot.role, record.UPID, err)
		}
		if status.Status != "stopped" {
			return result, fmt.Errorf("PVE %s task %s is %q; parent VMID lock cannot transfer", slot.role, record.UPID, status.Status)
		}
		if status.ExitStatus == "" || len(status.ExitStatus) > 256 || strings.ContainsAny(status.ExitStatus, "\x00\r\n") {
			return result, fmt.Errorf("PVE %s task %s has no bounded terminal exit status", slot.role, record.UPID)
		}
		result.TaskEvidence = append(result.TaskEvidence, protocol.PVERecoveryTaskEvidence{
			Role: slot.role, Node: record.Node, UPID: record.UPID, Status: status.Status,
			ExitStatus: status.ExitStatus, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
		})
		if record.Storage != "" && status.ExitStatus == "OK" {
			if record.VolumeRef == "" {
				volume, err := e.resolvePVEBackupVolume(ctx, record.Node, record.Storage, record.GuestType, record.VMID, record.BeforeVolumes)
				if err != nil {
					return result, fmt.Errorf("resolve terminal PVE %s backup volume: %w", slot.role, err)
				}
				record.VolumeRef = volume
				if err := e.persistPVETaskRecord(scope.ChangeID, slot.taskFile, record); err != nil {
					return result, fmt.Errorf("persist terminal PVE %s backup volume: %w", slot.role, err)
				}
			}
			result.EvidenceRefs = append(result.EvidenceRefs, "pve:volume:"+record.VolumeRef)
		}
	}

	if scope.MutationDisposition == protocol.PVEMutationDispositionNotStarted {
		result.MutationDisposition = protocol.PVEMutationDispositionNotStarted
		result.TaskEvidence = nil
		if err := result.Validate(); err != nil {
			return result, err
		}
		return result, nil
	}
	if len(result.TaskEvidence) == 0 {
		if scope.PVEMutationVersion >= 1 && artifactCount == 0 {
			result.MutationDisposition = protocol.PVEMutationDispositionNotStarted
			if err := result.Validate(); err != nil {
				return result, err
			}
			return result, nil
		}
		return result, errors.New("PVE parent has no terminal task proof; local recovery clearance is required")
	}
	if scope.PVEMutationVersion < 1 {
		switch operation.(type) {
		case *protocol.PVESnapshotDelete, *protocol.PVESnapshotRollback:
			if !primaryTask {
				return result, errors.New("legacy destructive PVE parent has no primary task proof; local recovery clearance is required")
			}
		}
	}
	if primaryIntent && !primaryTask && !primaryNoStart {
		return result, errors.New("PVE primary intent has no task UPID; local recovery clearance is required")
	}
	result.MutationDisposition = protocol.PVEMutationDispositionTasksTerminal
	if err := result.Validate(); err != nil {
		return result, err
	}
	return result, nil
}

// ObservePVEUnknownRecoveryParent is the only path that can produce the state
// bound into a local unknown-result clearance. It accepts only an unresolved
// STARTED_OR_UNKNOWN parent for which there is no known UPID: either a valid
// fsynced intent lost its response, or a legacy mutation has no durable task
// proof. Every known UPID is queried and then rejected regardless of terminal
// state so running and unqueryable tasks can never be bypassed by clearance.
func (e *OSExecutor) ObservePVEUnknownRecoveryParent(
	ctx context.Context,
	scope ExecutionScope,
	operation protocol.Operation,
) (protocol.PVERecoveryClearanceObservation, error) {
	if !isPVEOperation(operation) || scope.MutationDisposition != protocol.PVEMutationDispositionUnknown {
		return protocol.PVERecoveryClearanceObservation{}, errors.New("PVE unknown clearance requires a STARTED_OR_UNKNOWN PVE parent")
	}
	type taskSlot struct {
		role       string
		intentFile string
		taskFile   string
	}
	slots := []taskSlot{
		{role: "safety-backup", intentFile: "pve-safety-backup-intent.json", taskFile: "pve-safety-backup-task.json"},
		{role: "primary", intentFile: "pve-primary-intent.json", taskFile: "pve-task.json"},
	}
	lostUPIDIntent := false
	artifactCount := 0
	for _, slot := range slots {
		intent, intentErr := e.readPVETaskIntent(scope, slot.intentFile, slot.role, operation)
		intentExists := intentErr == nil
		if intentErr != nil && !errors.Is(intentErr, os.ErrNotExist) {
			return protocol.PVERecoveryClearanceObservation{}, fmt.Errorf("read PVE %s task intent for clearance: %w", slot.role, intentErr)
		}
		record, recordErr := e.readPVETaskRecord(scope.ChangeID, slot.taskFile, operation)
		recordExists := recordErr == nil
		if recordErr != nil && !errors.Is(recordErr, os.ErrNotExist) {
			return protocol.PVERecoveryClearanceObservation{}, fmt.Errorf("read PVE %s task record for clearance: %w", slot.role, recordErr)
		}
		if intentExists {
			artifactCount++
		}
		if recordExists {
			artifactCount++
			var status pveTaskStatus
			if err := e.pveGetObject(ctx, "/nodes/"+record.Node+"/tasks/"+record.UPID+"/status", &status); err != nil {
				return protocol.PVERecoveryClearanceObservation{}, fmt.Errorf("known PVE %s task %s could not be queried and can never be cleared: %w", slot.role, record.UPID, err)
			}
			if status.Status != "stopped" {
				return protocol.PVERecoveryClearanceObservation{}, fmt.Errorf("known PVE %s task %s is %q and can never be cleared", slot.role, record.UPID, status.Status)
			}
			return protocol.PVERecoveryClearanceObservation{}, fmt.Errorf("known PVE %s task %s is terminal and must use normal terminal-task reconciliation", slot.role, record.UPID)
		}
		if slot.role == "primary" {
			marker, markerErr := e.readPVETaskIntent(scope, "pve-primary-no-start.json", slot.role, operation)
			if markerErr == nil {
				artifactCount++
				if !intentExists || !samePVETaskIntent(intent, marker) {
					return protocol.PVERecoveryClearanceObservation{}, errors.New("PVE primary no-start marker does not bind one exact intent")
				}
				return protocol.PVERecoveryClearanceObservation{}, errors.New("PVE primary no-start proof must use normal no-mutation reconciliation")
			}
			if !errors.Is(markerErr, os.ErrNotExist) {
				return protocol.PVERecoveryClearanceObservation{}, fmt.Errorf("read PVE primary no-start marker for clearance: %w", markerErr)
			}
		}
		if intentExists {
			lostUPIDIntent = true
		}
	}
	if !lostUPIDIntent {
		if scope.PVEMutationVersion >= 1 && artifactCount == 0 {
			return protocol.PVERecoveryClearanceObservation{}, errors.New("PVE mutation protocol v1 has no task intent and must use normal no-mutation reconciliation")
		}
		if scope.PVEMutationVersion >= 1 {
			return protocol.PVERecoveryClearanceObservation{}, errors.New("PVE mutation protocol v1 has no eligible lost-UPID intent")
		}
		// Legacy mutation versions did not durably record pre-call intent. Their
		// no-proof outcome remains eligible only after the same live observations
		// below and an explicit local clearance.
	}

	node, guestType, vmid := pveOperationGuest(operation)
	nodes := []string{node}
	if migration, ok := operation.(*protocol.PVEGuestMigrate); ok {
		nodes = append(nodes, migration.TargetNode)
	}
	sort.Strings(nodes)
	nodes = slices.Compact(nodes)
	activeProbes := make([]protocol.PVERecoveryActiveTaskProbe, 0, len(nodes))
	for _, candidate := range nodes {
		var active []json.RawMessage
		if err := e.pveGetList(ctx, "/nodes/"+candidate+"/tasks", &active,
			"--source", "active", "--vmid", strconv.Itoa(vmid), "--limit", "1"); err != nil {
			return protocol.PVERecoveryClearanceObservation{}, fmt.Errorf("query exact active PVE tasks on node %s: %w", candidate, err)
		}
		if len(active) != 0 {
			return protocol.PVERecoveryClearanceObservation{}, fmt.Errorf("node %s has an active task for VMID %d", candidate, vmid)
		}
		activeProbes = append(activeProbes, protocol.PVERecoveryActiveTaskProbe{Node: candidate, VMID: vmid, ActiveCount: 0})
	}

	var cluster []pveClusterStatus
	if err := e.pveGetList(ctx, "/cluster/status", &cluster); err != nil {
		return protocol.PVERecoveryClearanceObservation{}, fmt.Errorf("collect PVE cluster state for clearance: %w", err)
	}
	if err := validatePVEClusterStatusEntries(cluster); err != nil {
		return protocol.PVERecoveryClearanceObservation{}, fmt.Errorf("validate PVE cluster state for clearance: %w", err)
	}
	selectedCluster := make([]protocol.PVERecoveryClusterState, 0, len(nodes)+1)
	clustered, quorate := false, false
	onlineNodes := make(map[string]bool, len(nodes))
	standaloneNodes := make(map[string]bool, len(nodes))
	for _, entry := range cluster {
		entryNode := entry.Node
		if entryNode == "" && entry.Type == "node" {
			entryNode = entry.Name
		}
		include := entry.Type == "cluster"
		if entry.Type == "cluster" {
			clustered, quorate = true, entry.Quorate == 1
		}
		if entry.Type == "node" && slices.Contains(nodes, entryNode) {
			include = true
			onlineNodes[entryNode] = entry.Online == 1
			standaloneNodes[entryNode] = entry.Local == 1 && entry.NodeID == 0
		}
		if include {
			selectedCluster = append(selectedCluster, protocol.PVERecoveryClusterState{
				Type: entry.Type, Name: entry.Name, Node: entry.Node, NodeID: entry.NodeID,
				Local: entry.Local, Online: entry.Online, Quorate: entry.Quorate,
			})
		}
	}
	if clustered && !quorate {
		return protocol.PVERecoveryClearanceObservation{}, errors.New("PVE cluster is not quorate during recovery clearance")
	}
	for _, candidate := range nodes {
		if !onlineNodes[candidate] {
			return protocol.PVERecoveryClearanceObservation{}, fmt.Errorf("PVE node %s is not online during recovery clearance", candidate)
		}
		if !clustered && !standaloneNodes[candidate] {
			return protocol.PVERecoveryClearanceObservation{}, fmt.Errorf("PVE node %s is not an explicit standalone node", candidate)
		}
	}

	var resources []pveGuestResource
	if err := e.pveGetList(ctx, "/cluster/resources", &resources, "--type", "vm"); err != nil {
		return protocol.PVERecoveryClearanceObservation{}, fmt.Errorf("collect PVE guest location for clearance: %w", err)
	}
	guestStates := make([]protocol.PVERecoveryGuestState, 0, 1)
	seenGuestNode := ""
	for _, resource := range resources {
		if resource.VMID != vmid {
			continue
		}
		if resource.Type != guestType {
			return protocol.PVERecoveryClearanceObservation{}, fmt.Errorf("PVE VMID %d is occupied by unexpected guest type %s", vmid, resource.Type)
		}
		if !slices.Contains(nodes, resource.Node) {
			return protocol.PVERecoveryClearanceObservation{}, fmt.Errorf("PVE guest %s/%d moved outside approved recovery nodes to %s", guestType, vmid, resource.Node)
		}
		if seenGuestNode != "" && seenGuestNode != resource.Node {
			return protocol.PVERecoveryClearanceObservation{}, errors.New("PVE guest identity appears on multiple nodes during recovery clearance")
		}
		seenGuestNode = resource.Node
		status, err := e.readPVEGuestStatus(ctx, resource.Node, guestType, vmid)
		if err != nil {
			return protocol.PVERecoveryClearanceObservation{}, fmt.Errorf("collect PVE guest state on node %s: %w", resource.Node, err)
		}
		if status.Status != "running" && status.Status != "stopped" {
			return protocol.PVERecoveryClearanceObservation{}, fmt.Errorf("PVE guest has unsupported state %q during recovery clearance", status.Status)
		}
		if status.Lock != "" {
			return protocol.PVERecoveryClearanceObservation{}, fmt.Errorf("PVE guest remains locked during recovery clearance: %s", status.Lock)
		}
		guestStates = append(guestStates, protocol.PVERecoveryGuestState{
			Node: resource.Node, GuestType: guestType, VMID: vmid, Status: status.Status, Lock: status.Lock,
		})
	}
	return protocol.NewPVERecoveryClearanceObservation(guestType, vmid, activeProbes, guestStates, selectedCluster)
}

func validatePVEClusterStatusEntries(entries []pveClusterStatus) error {
	seenCluster := false
	seenNodes := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		switch entry.Type {
		case "cluster":
			if seenCluster {
				return errors.New("PVE cluster status contains duplicate cluster identity")
			}
			seenCluster = true
		case "node":
			node := entry.Node
			if node == "" {
				node = entry.Name
			}
			if !protocol.ValidPVENode(node) {
				return errors.New("PVE cluster status contains an invalid node identity")
			}
			if _, duplicate := seenNodes[node]; duplicate {
				return errors.New("PVE cluster status contains duplicate node identity")
			}
			seenNodes[node] = struct{}{}
		default:
			return errors.New("PVE cluster status contains an unsupported entry type")
		}
	}
	return nil
}

func samePVETaskIntent(left, right pveTaskIntent) bool {
	return left.Version == right.Version && left.Operation == right.Operation && left.PlanHash == right.PlanHash &&
		left.PreconditionDigest == right.PreconditionDigest && left.Node == right.Node &&
		left.GuestType == right.GuestType && left.VMID == right.VMID && left.Storage == right.Storage &&
		slices.Equal(left.BeforeVolumes, right.BeforeVolumes)
}

func decodePVERollback(payload []byte) (pveRollback, error) {
	var rollback pveRollback
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&rollback); err != nil {
		return rollback, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return rollback, errors.New("PVE rollback metadata has a trailing value")
	}
	if rollback.Version != pveTaskRecordVersion {
		return rollback, errors.New("PVE rollback metadata has an unsupported version")
	}
	return rollback, nil
}

func pveOperationNode(operation protocol.Operation) string {
	node, _, _ := pveOperationGuest(operation)
	return node
}

func pveOperationGuest(operation protocol.Operation) (string, string, int) {
	switch value := operation.(type) {
	case *protocol.PVEGuestAction:
		return value.Node, value.GuestType, value.VMID
	case *protocol.PVESnapshotCreate:
		return value.Node, value.GuestType, value.VMID
	case *protocol.PVESnapshotDelete:
		return value.Node, value.GuestType, value.VMID
	case *protocol.PVESnapshotRollback:
		return value.Node, value.GuestType, value.VMID
	case *protocol.PVEGuestBackup:
		return value.Node, value.GuestType, value.VMID
	case *protocol.PVEGuestRestore:
		return value.Node, value.GuestType, value.VMID
	case *protocol.PVEGuestMigrate:
		return value.Node, value.GuestType, value.VMID
	}
	return "", "", 0
}
