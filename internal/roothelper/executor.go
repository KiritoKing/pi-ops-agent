package roothelper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/pluginpkg"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
	"github.com/KiritoKing/pi-ops-agent/internal/targetpolicy"
)

const maxCommandOutput = 64 * 1024

type ExecutionResult struct {
	BackupRefs        []string
	RollbackData      json.RawMessage
	RollbackAvailable bool
	Verification      string
}

type ExecutionScope struct {
	ChangeID            string
	TargetID            string
	PolicyRevision      string
	CapabilityRevision  string
	PreconditionDigest  string
	PlanHash            string
	PVEMutationVersion  int
	MutationDisposition string
	ApprovedBy          string
	ApprovedAt          time.Time
	RecordEvidence      func(...string) error
}

type OperationPrecondition struct {
	Digest string
	Fields []protocol.ApprovalPlanField
}

type Executor interface {
	Prepare(context.Context, ExecutionScope, protocol.Operation) (ExecutionResult, error)
	Execute(context.Context, ExecutionScope, protocol.Operation, ExecutionResult) error
	Verify(context.Context, ExecutionScope, protocol.Operation, ExecutionResult) (string, error)
	Rollback(context.Context, ExecutionScope, protocol.Operation, ExecutionResult) error
}

// PVEExecutionStep is one durable step of a long-running PVE mutation. The
// production PVE executor starts at most one API task per call and returns as
// soon as its node-bound UPID has been written to both recovery sinks. The
// service owns polling and calls StepPVEExecution again with a fresh,
// broker-owned context; an HTTP request context therefore never owns the
// lifetime of an already-started PVE task.
type PVEExecutionStep struct {
	Result   ExecutionResult
	Running  bool
	Complete bool
	Role     string
	Node     string
	UPID     string
}

func (s PVEExecutionStep) Validate() error {
	if s.Running == s.Complete {
		return errors.New("PVE execution step must be either running or complete")
	}
	if s.Running {
		if (s.Role != "safety-backup" && s.Role != "primary") ||
			!protocol.ValidPVENode(s.Node) || !protocol.ValidPVEUPIDForNode(s.UPID, s.Node) {
			return errors.New("running PVE execution step has invalid task identity")
		}
		return nil
	}
	if s.Role != "" || s.Node != "" || s.UPID != "" {
		return errors.New("completed PVE execution step unexpectedly carries a running task")
	}
	return nil
}

// PVEAsyncExecutor is deliberately narrower than Executor: it is only the
// durable task-start/poll state machine used by the PVE-domain broker. Test or
// alternate executors that do not implement it retain the synchronous Executor
// contract.
type PVEAsyncExecutor interface {
	StepPVEExecution(context.Context, ExecutionScope, protocol.Operation, ExecutionResult) (PVEExecutionStep, error)
}

type OperationValidator interface {
	ValidateOperation(ExecutionScope, protocol.Operation) error
}

// OperationPlanner performs bounded, read-only observations before approval.
// Its digest is included in the plan hash and must be rechecked after approval.
type OperationPlanner interface {
	PlanOperation(context.Context, ExecutionScope, protocol.Operation) (OperationPrecondition, error)
}

// RecoveryEvidenceProvider reconciles durable executor records after a broker
// restart. It may return partial evidence with an error; the caller must retain
// the resource lock and RECOVERY_REQUIRED state in that case.
type RecoveryEvidenceProvider interface {
	RecoverEvidence(context.Context, ExecutionScope, protocol.Operation) ([]string, error)
}

// InterruptedChangeReconciler may close only an exact, operation-specific
// before/after state after the Store has conservatively moved an interrupted
// mutation to RECOVERY_REQUIRED. Unknown state must return an error and retain
// the durable resource lock.
type InterruptedChangeReconciliation struct {
	State        string
	Verification string
	EvidenceRefs []string
}

type InterruptedChangeReconciler interface {
	ReconcileInterruptedChange(context.Context, ExecutionScope, protocol.Operation, ExecutionResult) (InterruptedChangeReconciliation, error)
}

// PVERecoveryReadiness is authoritative root-observed evidence that an
// unresolved parent can no longer have a task mutating its cluster-global
// VMID. Unknown, running, unqueryable, and lost-UPID outcomes are deliberately
// not representable as ready.
type PVERecoveryReadiness struct {
	MutationDisposition string
	TaskEvidence        []protocol.PVERecoveryTaskEvidence
	EvidenceRefs        []string
}

func (r PVERecoveryReadiness) Validate() error {
	if r.MutationDisposition != protocol.PVEMutationDispositionNotStarted &&
		r.MutationDisposition != protocol.PVEMutationDispositionTasksTerminal {
		return errors.New("PVE recovery readiness has no safe mutation disposition")
	}
	if (r.MutationDisposition == protocol.PVEMutationDispositionNotStarted && len(r.TaskEvidence) != 0) ||
		(r.MutationDisposition == protocol.PVEMutationDispositionTasksTerminal && len(r.TaskEvidence) == 0) {
		return errors.New("PVE recovery readiness task evidence does not match its disposition")
	}
	seenRoles := make(map[string]struct{}, len(r.TaskEvidence))
	seenUPIDs := make(map[string]struct{}, len(r.TaskEvidence))
	for _, evidence := range r.TaskEvidence {
		if err := evidence.Validate(); err != nil {
			return err
		}
		if _, duplicate := seenRoles[evidence.Role]; duplicate {
			return errors.New("PVE recovery readiness contains duplicate task roles")
		}
		if _, duplicate := seenUPIDs[evidence.UPID]; duplicate {
			return errors.New("PVE recovery readiness contains duplicate task evidence")
		}
		seenRoles[evidence.Role] = struct{}{}
		seenUPIDs[evidence.UPID] = struct{}{}
	}
	for _, ref := range r.EvidenceRefs {
		if !validPVEEvidenceRef(ref) {
			return errors.New("PVE recovery readiness contains invalid evidence")
		}
	}
	return nil
}

type PVERecoveryReadinessProvider interface {
	ReconcilePVERecoveryParent(context.Context, ExecutionScope, protocol.Operation) (PVERecoveryReadiness, error)
}

// PVEUnknownRecoveryClearanceProvider is broker-internal. It is deliberately
// separate from workload providers: only the privileged PVE broker may use it
// to observe a narrowly eligible lost-UPID/no-proof parent before a local
// administrator confirms an exact, short-lived clearance challenge.
type PVEUnknownRecoveryClearanceProvider interface {
	ObservePVEUnknownRecoveryParent(context.Context, ExecutionScope, protocol.Operation) (protocol.PVERecoveryClearanceObservation, error)
}

type uncertainMutationError interface {
	MutationOutcomeUncertain() bool
}

func mutationOutcomeUncertain(err error) bool {
	var uncertain uncertainMutationError
	return errors.As(err, &uncertain) && uncertain.MutationOutcomeUncertain()
}

type noMutationStartedError interface {
	NoMutationStarted() bool
}

func noMutationStarted(err error) bool {
	var knownNoMutation noMutationStartedError
	return errors.As(err, &knownNoMutation) && knownNoMutation.NoMutationStarted()
}

type mutationAttemptEvidenceError interface {
	MutationAttempted() bool
	ExchangeRestored() bool
}

func mutationAttemptEvidence(err error) (bool, bool) {
	var evidence mutationAttemptEvidenceError
	if !errors.As(err, &evidence) {
		return false, false
	}
	return evidence.MutationAttempted(), evidence.ExchangeRestored()
}

type CommandRunner interface {
	Run(context.Context, string, ...string) (string, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive"}
	var output limitedBuffer
	command.Stdout, command.Stderr = &output, &output
	err := command.Run()
	if err != nil {
		return output.String(), fmt.Errorf("%s failed: %w", filepath.Base(name), err)
	}
	return output.String(), nil
}

type OSExecutor struct {
	StateDir              string
	AllowedRoots          []string
	AllowBreakglass       bool
	Runner                CommandRunner
	PluginRoot            string
	PluginCatalog         string
	PluginBinRoot         string
	Policy                *targetpolicy.Policy
	PluginCredentialRoot  string
	SourcePluginRoot      string
	SourcePluginRegistry  string
	SystemdRunPath        string
	SystemctlPath         string
	RunuserPath           string
	EnvPath               string
	LookupWorkloadAccount func(string) (int, string, error)
	JSONConfigRunner      JSONConfigProofRunner
}

func (e *OSExecutor) Prepare(ctx context.Context, scope ExecutionScope, operation protocol.Operation) (ExecutionResult, error) {
	if e.Runner == nil {
		e.Runner = ExecRunner{}
	}
	if err := e.ValidateOperation(scope, operation); err != nil {
		return ExecutionResult{}, err
	}
	switch value := operation.(type) {
	case *protocol.PackageInstall:
		return e.preparePackage(ctx, value)
	case *protocol.ServiceAction:
		return e.prepareService(ctx, value)
	case *protocol.WorkloadServiceAction:
		return e.prepareWorkloadService(ctx, scope, value)
	case *protocol.WorkloadJSONConfigEdit:
		return e.prepareWorkloadJSONConfig(ctx, scope, value)
	case *protocol.FileWrite:
		return e.prepareFile(scope.ChangeID, value)
	case *protocol.PluginInstall:
		return e.preparePluginInstall(scope.ChangeID, value)
	case *protocol.PluginRegister:
		return e.preparePluginRegister(scope, value)
	case *protocol.WorkloadDeploy:
		return e.prepareWorkload(ctx, scope, value)
	case *protocol.BreakglassScript:
		return e.prepareBreakglass(ctx, scope.ChangeID, value)
	case *protocol.PVEGuestAction, *protocol.PVESnapshotCreate, *protocol.PVESnapshotDelete,
		*protocol.PVESnapshotRollback, *protocol.PVEGuestBackup, *protocol.PVEGuestRestore, *protocol.PVEGuestMigrate:
		return e.preparePVE(ctx, scope, operation)
	default:
		return ExecutionResult{}, errors.New("executor received an unsupported operation")
	}
}

func (e *OSExecutor) Execute(ctx context.Context, scope ExecutionScope, operation protocol.Operation, result ExecutionResult) error {
	if e.Runner == nil {
		e.Runner = ExecRunner{}
	}
	if err := e.ValidateOperation(scope, operation); err != nil {
		return err
	}
	switch value := operation.(type) {
	case *protocol.PackageInstall:
		return e.installSpecificPackage(ctx, value.Package, value.Version)
	case *protocol.ServiceAction:
		_, err := e.systemctl(ctx, value.Action, value.Unit)
		return err
	case *protocol.WorkloadServiceAction:
		return e.executeWorkloadService(ctx, scope, value)
	case *protocol.WorkloadJSONConfigEdit:
		return e.executeWorkloadJSONConfig(ctx, scope, value, result)
	case *protocol.FileWrite:
		return e.executeFile(scope, value, result)
	case *protocol.PluginInstall:
		return e.executePluginInstall(scope.ChangeID, value)
	case *protocol.PluginRegister:
		return e.executePluginRegister(scope, value)
	case *protocol.WorkloadDeploy:
		return e.executeWorkload(ctx, scope, value, result)
	case *protocol.BreakglassScript:
		scriptPath := filepath.Join(e.StateDir, "changes", scope.ChangeID, "script.sh")
		_, err := e.runCapsule(ctx, scope, scriptPath, value.Network)
		return err
	case *protocol.PVEGuestAction, *protocol.PVESnapshotCreate, *protocol.PVESnapshotDelete,
		*protocol.PVESnapshotRollback, *protocol.PVEGuestBackup, *protocol.PVEGuestRestore, *protocol.PVEGuestMigrate:
		return e.executePVE(ctx, scope, operation, result)
	default:
		return errors.New("executor received an unsupported operation")
	}
}

func (e *OSExecutor) ValidateOperation(scope ExecutionScope, operation protocol.Operation) error {
	switch value := operation.(type) {
	case *protocol.PackageInstall:
		return nil
	case *protocol.ServiceAction:
		if isCriticalService(value.Unit) {
			return errors.New("R3 service is not remotely mutable")
		}
		return nil
	case *protocol.WorkloadServiceAction:
		if e.Policy == nil || scope.PolicyRevision != e.Policy.Revision {
			return errors.New("workload service actions require the active root-owned target policy")
		}
		return e.Policy.AuthorizeOperation(scope.TargetID, operation)
	case *protocol.WorkloadJSONConfigEdit:
		if e.Policy == nil || scope.PolicyRevision != e.Policy.Revision {
			return errors.New("workload JSON config edits require the active root-owned target policy")
		}
		return e.Policy.AuthorizeOperation(scope.TargetID, operation)
	case *protocol.FileWrite:
		return e.ensureAllowedPath(value.Path)
	case *protocol.PluginInstall:
		packageInfo, err := e.inspectArtifact(value.ArtifactRef, value.PluginID, value.Version, value.Publisher, value.Digest)
		if err != nil {
			return err
		}
		if e.Policy != nil {
			if _, ok := e.Policy.Artifact(scope.TargetID, packageInfo.Manifest.Kind, value.PluginID, value.Version, value.Publisher, value.Digest); !ok {
				return errors.New("plugin artifact is not pinned by the target policy")
			}
		}
		return nil
	case *protocol.PluginRegister:
		_, err := e.inspectPluginRegistration(value)
		return err
	case *protocol.WorkloadDeploy:
		_, _, err := e.authorizedWorkload(scope, value)
		return err
	case *protocol.BreakglassScript:
		if !e.AllowBreakglass {
			return errors.New("manual root capsules are unavailable in this broker domain")
		}
		if e.Policy == nil || scope.PolicyRevision != e.Policy.Revision {
			return errors.New("manual root capsules require the active root-owned target policy")
		}
		return e.Policy.AuthorizeOperation(scope.TargetID, operation)
	case *protocol.PVEGuestAction, *protocol.PVESnapshotCreate, *protocol.PVESnapshotDelete,
		*protocol.PVESnapshotRollback, *protocol.PVEGuestBackup, *protocol.PVEGuestRestore, *protocol.PVEGuestMigrate:
		if e.Policy == nil || scope.PolicyRevision != e.Policy.Revision {
			return errors.New("PVE operations require the active root-owned target policy")
		}
		return e.Policy.AuthorizeOperation(scope.TargetID, operation)
	default:
		return errors.New("unsupported operation")
	}
}

func (e *OSExecutor) Verify(ctx context.Context, scope ExecutionScope, operation protocol.Operation, result ExecutionResult) (string, error) {
	switch value := operation.(type) {
	case *protocol.PackageInstall:
		version, installed, err := e.packageVersion(ctx, value.Package)
		if err != nil || !installed {
			return "", errors.New("package is not installed after change")
		}
		if value.Version != "" && version != value.Version {
			return "", fmt.Errorf("installed version %q does not match %q", version, value.Version)
		}
		return "installed version " + version, nil
	case *protocol.ServiceAction:
		state, err := e.systemctl(ctx, "is-active", value.Unit)
		active := strings.TrimSpace(state) == "active"
		if value.Action == "stop" {
			if active {
				return "", errors.New("service is still active")
			}
			return "service is inactive", nil
		}
		if err != nil || !active {
			return "", errors.New("service is not active after change")
		}
		return "service is active", nil
	case *protocol.WorkloadServiceAction:
		return e.verifyWorkloadService(ctx, value)
	case *protocol.WorkloadJSONConfigEdit:
		return e.verifyWorkloadJSONConfig(ctx, scope, value, result)
	case *protocol.FileWrite:
		var rollback fileRollback
		if err := json.Unmarshal(result.RollbackData, &rollback); err != nil {
			return "", fmt.Errorf("decode prepared file metadata: %w", err)
		}
		commit, err := readAllowedFileCommit(rollback.CommitPath)
		if err != nil {
			return "", fmt.Errorf("read committed file identity: %w", err)
		}
		payload, mode, err := readCommittedAllowedFile(value.Path, e.AllowedRoots, rollback.snapshot(), commit)
		if err != nil {
			return "", err
		}
		expected, actual := sha256.Sum256([]byte(value.Content)), sha256.Sum256(payload)
		if expected != actual {
			return "", errors.New("written file digest mismatch")
		}
		if value.Mode != "" {
			approved, parseErr := strconv.ParseUint(value.Mode, 8, 12)
			if parseErr != nil || mode.Perm() != os.FileMode(approved).Perm() {
				return "", errors.New("written file mode does not match the approved non-executable mode")
			}
		}
		return "sha256:" + hex.EncodeToString(actual[:]), nil
	case *protocol.PluginInstall:
		packageInfo, err := e.inspectArtifact(value.ArtifactRef, value.PluginID, value.Version, value.Publisher, value.Digest)
		if err != nil {
			return "", err
		}
		destination := filepath.Join(e.pluginRoot(), value.PluginID, value.Version)
		if err := verifyInstalledArtifact(destination, packageInfo); err != nil {
			return "", err
		}
		current, err := os.Readlink(filepath.Join(e.pluginRoot(), value.PluginID, "current"))
		if err != nil || current != value.Version {
			return "", errors.New("installed plugin current pointer does not match the approved version")
		}
		if packageInfo.Manifest.Kind == "im-adapter" {
			entrypoint := filepath.Join(destination, filepath.FromSlash(packageInfo.Manifest.Entrypoint))
			if info, statErr := os.Stat(entrypoint); statErr != nil || !info.Mode().IsRegular() {
				return "", errors.New("installed adapter entrypoint is missing or not a regular file")
			}
			launcher := filepath.Join(e.pluginBinRoot(), adapterLauncherName(value.PluginID))
			if info, statErr := os.Stat(launcher); statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o755 {
				return "", errors.New("installed adapter launcher is missing or has unsafe permissions")
			}
		}
		return "installed " + value.PluginID + " " + value.Version + " " + value.Digest, nil
	case *protocol.PluginRegister:
		return e.verifyPluginRegistration(value)
	case *protocol.WorkloadDeploy:
		return e.verifyWorkload(ctx, scope, value, result)
	case *protocol.BreakglassScript:
		if value.VerifyScript == "" {
			return "manual root capsule completed without a caller-provided privileged postcondition script", nil
		}
		path := filepath.Join(e.StateDir, "changes", resultID(result), "verify.sh")
		if err := writePrivateFile(path, []byte(value.VerifyScript), 0o700); err != nil {
			return "", err
		}
		_, err := e.runCapsule(ctx, scope, path, value.Network)
		if err != nil {
			return "", err
		}
		return "caller-provided privileged postcondition script exited successfully", nil
	case *protocol.PVEGuestAction, *protocol.PVESnapshotCreate, *protocol.PVESnapshotDelete,
		*protocol.PVESnapshotRollback, *protocol.PVEGuestBackup, *protocol.PVEGuestRestore, *protocol.PVEGuestMigrate:
		return e.verifyPVE(ctx, scope, operation, result)
	default:
		return "", errors.New("unsupported verification operation")
	}
}

func (e *OSExecutor) Rollback(ctx context.Context, scope ExecutionScope, operation protocol.Operation, result ExecutionResult) error {
	if isPVEOperation(operation) {
		return errors.New("PVE compensation requires a newly prepared and approved typed recovery change")
	}
	if !result.RollbackAvailable {
		return errors.New("rollback is unavailable")
	}
	switch value := operation.(type) {
	case *protocol.PackageInstall:
		var rollback packageRollback
		if err := json.Unmarshal(result.RollbackData, &rollback); err != nil {
			return err
		}
		if rollback.Installed {
			return e.installSpecificPackage(ctx, value.Package, rollback.Version)
		}
		return e.removePackage(ctx, value.Package)
	case *protocol.ServiceAction:
		var rollback serviceRollback
		if err := json.Unmarshal(result.RollbackData, &rollback); err != nil {
			return err
		}
		if rollback.Active {
			_, err := e.systemctl(ctx, "start", value.Unit)
			return err
		}
		_, err := e.systemctl(ctx, "stop", value.Unit)
		return err
	case *protocol.WorkloadServiceAction:
		return errors.New("workload service compensation requires a new typed change")
	case *protocol.WorkloadJSONConfigEdit:
		return e.rollbackWorkloadJSONConfig(ctx, scope, value, result)
	case *protocol.FileWrite:
		if protocol.IsStoredOnlyOperation(value) {
			return e.rollbackLegacyFile(scope, value, result)
		}
		var rollback fileRollback
		if err := json.Unmarshal(result.RollbackData, &rollback); err != nil {
			return err
		}
		commit, err := readAllowedFileCommit(rollback.CommitPath)
		if err != nil {
			return fmt.Errorf("read committed file identity for rollback: %w", err)
		}
		if !rollback.Existed {
			return removeAllowedFile(value.Path, e.AllowedRoots, rollback.snapshot(), commit)
		}
		payload, err := os.ReadFile(rollback.BackupPath)
		if err != nil {
			return err
		}
		return restoreAllowedFile(value.Path, e.AllowedRoots, rollback.snapshot(), commit, payload)
	case *protocol.PluginInstall:
		return e.rollbackPluginInstall(value, result)
	case *protocol.PluginRegister:
		return e.rollbackPluginRegistration(value, result)
	case *protocol.WorkloadDeploy:
		return e.rollbackWorkload(ctx, scope, value, result)
	case *protocol.BreakglassScript:
		var rollback breakglassRollback
		if err := json.Unmarshal(result.RollbackData, &rollback); err != nil {
			return err
		}
		_, err := e.Runner.Run(ctx, "/bin/tar", "--xattrs", "--acls", "--selinux", "-xpf", rollback.Archive, "-C", "/")
		return err
	default:
		return errors.New("unsupported rollback operation")
	}
}

func (e *OSExecutor) InspectLegacyFileRecovery(scope ExecutionScope, operation *protocol.FileWrite, result ExecutionResult) ([]protocol.RecoveryBackupObject, error) {
	proof, err := e.inspectLegacyFileRecovery(scope, operation, result)
	if err != nil {
		return nil, err
	}
	if proof.BackupDigest == "" {
		return []protocol.RecoveryBackupObject{}, nil
	}
	return []protocol.RecoveryBackupObject{{Reference: proof.BackupPath, Digest: proof.BackupDigest}}, nil
}

func (e *OSExecutor) rollbackLegacyFile(scope ExecutionScope, operation *protocol.FileWrite, result ExecutionResult) error {
	proof, err := e.inspectLegacyFileRecovery(scope, operation, result)
	if err != nil {
		return err
	}
	if !proof.Rollback.Existed {
		return removeAllowedFile(operation.Path, e.AllowedRoots, proof.Snapshot, proof.Commit)
	}
	return restoreAllowedFile(operation.Path, e.AllowedRoots, proof.Snapshot, proof.Commit, proof.Backup)
}

type legacyFileRecoveryProof struct {
	Rollback     legacyFileRollback
	Snapshot     allowedFileSnapshot
	Commit       allowedFileCommit
	BackupPath   string
	Backup       []byte
	BackupDigest string
}

func (e *OSExecutor) inspectLegacyFileRecovery(scope ExecutionScope, operation *protocol.FileWrite, result ExecutionResult) (legacyFileRecoveryProof, error) {
	if operation == nil || !protocol.IsStoredOnlyOperation(operation) {
		return legacyFileRecoveryProof{}, errors.New("legacy file recovery requires the stored v0.1/v0.2 file.write schema")
	}
	if err := e.ensureAllowedPath(operation.Path); err != nil {
		return legacyFileRecoveryProof{}, err
	}
	rollback, err := decodeLegacyFileRollback(result.RollbackData)
	if err != nil {
		return legacyFileRecoveryProof{}, fmt.Errorf("decode legacy file rollback evidence: %w", err)
	}
	changeDirectory := filepath.Join(e.StateDir, "changes", scope.ChangeID)
	expectedBackup := filepath.Join(changeDirectory, "file.backup")
	if filepath.Clean(changeDirectory) != changeDirectory || !filepath.IsAbs(changeDirectory) {
		return legacyFileRecoveryProof{}, errors.New("legacy file recovery state directory is invalid")
	}
	if rollback.Existed {
		if rollback.BackupPath != expectedBackup || len(result.BackupRefs) != 1 || result.BackupRefs[0] != expectedBackup {
			return legacyFileRecoveryProof{}, errors.New("legacy file backup reference is not the exact broker-owned change object")
		}
		if rollback.Mode&^uint32(0o777) != 0 || rollback.Mode&0o111 != 0 || rollback.UID < 0 || rollback.GID < 0 {
			return legacyFileRecoveryProof{}, errors.New("legacy file restore owner or mode is invalid")
		}
	} else if rollback.BackupPath != "" || len(result.BackupRefs) != 0 {
		return legacyFileRecoveryProof{}, errors.New("legacy file removal contains unexpected backup references")
	}
	expectedMode := uint32(0o644)
	if rollback.Existed {
		expectedMode = rollback.Mode
	}
	if operation.Mode != "" {
		parsed, err := strconv.ParseUint(operation.Mode, 8, 12)
		if err != nil {
			return legacyFileRecoveryProof{}, errors.New("legacy file operation mode is invalid")
		}
		expectedMode = uint32(parsed)
	}
	return inspectLegacyAllowedFile(
		operation.Path, e.AllowedRoots, secureFilePayloadDigest([]byte(operation.Content)),
		expectedMode, rollback, expectedBackup,
	)
}

type packageRollback struct {
	Installed bool   `json:"installed"`
	Version   string `json:"version,omitempty"`
}
type serviceRollback struct {
	Active bool `json:"active"`
}
type fileRollback struct {
	Existed       bool   `json:"existed"`
	BackupPath    string `json:"backupPath,omitempty"`
	CommitPath    string `json:"commitPath"`
	Mode          uint32 `json:"mode,omitempty"`
	UID           int    `json:"uid,omitempty"`
	GID           int    `json:"gid,omitempty"`
	ParentDev     uint64 `json:"parentDev"`
	ParentIno     uint64 `json:"parentIno"`
	TargetDev     uint64 `json:"targetDev,omitempty"`
	TargetIno     uint64 `json:"targetIno,omitempty"`
	ContentDigest string `json:"contentDigest,omitempty"`
}

func (r fileRollback) snapshot() allowedFileSnapshot {
	return allowedFileSnapshot{
		Existed: r.Existed, Mode: r.Mode, UID: r.UID, GID: r.GID,
		ParentDev: r.ParentDev, ParentIno: r.ParentIno, TargetDev: r.TargetDev, TargetIno: r.TargetIno,
		ContentDigest: r.ContentDigest,
	}
}

type breakglassRollback struct {
	ChangeID string `json:"changeId"`
	Archive  string `json:"archive"`
}

type pluginInstallRollback struct {
	Destination    string `json:"destination"`
	CurrentLink    string `json:"currentLink"`
	PreviousLink   string `json:"previousLink,omitempty"`
	WrapperPath    string `json:"wrapperPath,omitempty"`
	WrapperBackup  string `json:"wrapperBackup,omitempty"`
	WrapperExisted bool   `json:"wrapperExisted"`
}

func (e *OSExecutor) preparePackage(ctx context.Context, operation *protocol.PackageInstall) (ExecutionResult, error) {
	oldVersion, installed, err := e.packageVersion(ctx, operation.Package)
	if err != nil {
		return ExecutionResult{}, err
	}
	rollback, _ := json.Marshal(packageRollback{Installed: installed, Version: oldVersion})
	return ExecutionResult{RollbackData: rollback, RollbackAvailable: true}, nil
}

func (e *OSExecutor) installSpecificPackage(ctx context.Context, packageName, version string) error {
	if path, err := exec.LookPath("apt-get"); err == nil {
		target := packageName
		if version != "" {
			target += "=" + version
		}
		_, err = e.runPackageManager(ctx, packageName, path, "install", "-y", "--no-install-recommends", "--", target)
		return err
	}
	for _, manager := range []string{"dnf", "yum", "zypper"} {
		if path, err := exec.LookPath(manager); err == nil {
			target := packageName
			if version != "" {
				target += "-" + version
			}
			args := []string{"install", "-y", "--", target}
			if manager == "zypper" {
				args = []string{"--non-interactive", "install", "--", target}
			}
			_, err = e.runPackageManager(ctx, packageName, path, args...)
			return err
		}
	}
	return errors.New("no supported package manager found")
}

func (e *OSExecutor) removePackage(ctx context.Context, packageName string) error {
	if path, err := exec.LookPath("apt-get"); err == nil {
		_, err = e.runPackageManager(ctx, packageName, path, "remove", "-y", "--", packageName)
		return err
	}
	for _, manager := range []string{"dnf", "yum", "zypper"} {
		if path, err := exec.LookPath(manager); err == nil {
			args := []string{"remove", "-y", "--", packageName}
			if manager == "zypper" {
				args = []string{"--non-interactive", "remove", "--", packageName}
			}
			_, err = e.runPackageManager(ctx, packageName, path, args...)
			return err
		}
	}
	return errors.New("no supported package manager found")
}

func (e *OSExecutor) runPackageManager(ctx context.Context, packageName, manager string, managerArgs ...string) (string, error) {
	systemdRun, err := exec.LookPath("systemd-run")
	if err != nil {
		return "", errors.New("systemd-run is required for networked package changes")
	}
	unit := "ops-agent-package-" + safeUnitFragment(packageName)
	args := []string{
		"--quiet", "--wait", "--pipe", "--collect", "--service-type=exec", "--unit=" + unit,
		"--property=PrivateNetwork=no", "--property=PrivateTmp=yes", "--property=PrivateDevices=yes",
		"--property=ProtectHome=read-only", "--property=NoNewPrivileges=yes",
		"--property=ProtectKernelTunables=yes", "--property=ProtectKernelModules=yes",
		"--property=ProtectKernelLogs=yes", "--property=ProtectControlGroups=yes",
		"--property=RestrictRealtime=yes", "--property=RestrictSUIDSGID=yes",
		"--property=LockPersonality=yes", "--property=SystemCallArchitectures=native",
		"--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
		"--", manager,
	}
	args = append(args, managerArgs...)
	return e.Runner.Run(ctx, systemdRun, args...)
}

func (e *OSExecutor) packageVersion(ctx context.Context, packageName string) (string, bool, error) {
	if path, err := exec.LookPath("dpkg-query"); err == nil {
		output, err := e.Runner.Run(ctx, path, "-W", "-f=${Status}\t${Version}", "--", packageName)
		if err != nil {
			return "", false, nil
		}
		parts := strings.Split(strings.TrimSpace(output), "\t")
		if len(parts) == 2 && parts[0] == "install ok installed" {
			return parts[1], true, nil
		}
		return "", false, nil
	}
	if path, err := exec.LookPath("rpm"); err == nil {
		output, err := e.Runner.Run(ctx, path, "-q", "--qf", "%{VERSION}-%{RELEASE}", "--", packageName)
		if err != nil {
			return "", false, nil
		}
		return strings.TrimSpace(output), true, nil
	}
	return "", false, errors.New("no supported package database found")
}

func (e *OSExecutor) prepareService(ctx context.Context, operation *protocol.ServiceAction) (ExecutionResult, error) {
	state, _ := e.systemctl(ctx, "is-active", operation.Unit)
	rollback, _ := json.Marshal(serviceRollback{Active: strings.TrimSpace(state) == "active"})
	return ExecutionResult{RollbackData: rollback, RollbackAvailable: true}, nil
}

func (e *OSExecutor) systemctl(ctx context.Context, action, unit string) (string, error) {
	path, err := exec.LookPath("systemctl")
	if err != nil {
		return "", err
	}
	return e.Runner.Run(ctx, path, action, "--", unit)
}

func (e *OSExecutor) prepareFile(changeID string, operation *protocol.FileWrite) (ExecutionResult, error) {
	if err := e.ensureAllowedPath(operation.Path); err != nil {
		return ExecutionResult{}, err
	}
	changeDir := filepath.Join(e.StateDir, "changes", changeID)
	if err := os.MkdirAll(changeDir, 0o700); err != nil {
		return ExecutionResult{}, err
	}
	if err := syncSecureDirectory(e.StateDir); err != nil {
		return ExecutionResult{}, fmt.Errorf("persist file.write changes root: %w", err)
	}
	if err := syncSecureDirectory(filepath.Dir(changeDir)); err != nil {
		return ExecutionResult{}, fmt.Errorf("persist file.write change directory: %w", err)
	}
	backupPath := filepath.Join(changeDir, "file.backup")
	commitPath := filepath.Join(changeDir, "file.commit.json")
	if _, err := os.Lstat(commitPath); err == nil {
		return ExecutionResult{}, errors.New("file.write committed identity already exists before execution")
	} else if !errors.Is(err, os.ErrNotExist) {
		return ExecutionResult{}, err
	}
	snapshot, err := captureAllowedFile(operation.Path, e.AllowedRoots, backupPath)
	if err != nil {
		return ExecutionResult{}, err
	}
	rollback := fileRollback{
		Existed: snapshot.Existed, Mode: snapshot.Mode, UID: snapshot.UID, GID: snapshot.GID,
		ParentDev: snapshot.ParentDev, ParentIno: snapshot.ParentIno,
		TargetDev: snapshot.TargetDev, TargetIno: snapshot.TargetIno, ContentDigest: snapshot.ContentDigest,
		CommitPath: commitPath,
	}
	if snapshot.Existed {
		rollback.BackupPath = backupPath
	}
	encoded, _ := json.Marshal(rollback)
	result := ExecutionResult{RollbackData: encoded, RollbackAvailable: true}
	if rollback.BackupPath != "" {
		result.BackupRefs = []string{rollback.BackupPath}
	}
	return result, nil
}

func (e *OSExecutor) executeFile(scope ExecutionScope, operation *protocol.FileWrite, result ExecutionResult) error {
	var rollback fileRollback
	if err := json.Unmarshal(result.RollbackData, &rollback); err != nil {
		return fmt.Errorf("decode prepared file metadata: %w", err)
	}
	mode := os.FileMode(0o644)
	uid, gid := -1, -1
	if rollback.Existed {
		mode, uid, gid = os.FileMode(rollback.Mode), rollback.UID, rollback.GID
	}
	if operation.Mode != "" {
		parsed, err := strconv.ParseUint(operation.Mode, 8, 32)
		if err != nil {
			return err
		}
		mode = os.FileMode(parsed)
	}
	commit, err := replacePreparedAllowedFile(operation.Path, e.AllowedRoots, rollback.snapshot(), []byte(operation.Content), mode, uid, gid)
	if err != nil {
		return err
	}
	if err := writeAllowedFileCommit(rollback.CommitPath, commit); err != nil {
		return uncertainFileMutation("persist file.write committed identity", err)
	}
	if scope.RecordEvidence != nil {
		if err := scope.RecordEvidence(rollback.CommitPath); err != nil {
			return uncertainFileMutation("record file.write committed identity evidence", err)
		}
	}
	return nil
}

func (e *OSExecutor) preparePluginInstall(changeID string, operation *protocol.PluginInstall) (ExecutionResult, error) {
	packageInfo, err := e.inspectArtifact(operation.ArtifactRef, operation.PluginID, operation.Version, operation.Publisher, operation.Digest)
	if err != nil {
		return ExecutionResult{}, err
	}
	destination := filepath.Join(e.pluginRoot(), operation.PluginID, operation.Version)
	if _, err := os.Lstat(destination); err == nil {
		return ExecutionResult{}, errors.New("plugin version is already installed")
	} else if !errors.Is(err, os.ErrNotExist) {
		return ExecutionResult{}, err
	}
	changeDir := filepath.Join(e.StateDir, "changes", changeID)
	if err := os.MkdirAll(changeDir, 0o700); err != nil {
		return ExecutionResult{}, err
	}
	rollback := pluginInstallRollback{
		Destination: destination,
		CurrentLink: filepath.Join(e.pluginRoot(), operation.PluginID, "current"),
	}
	if previous, err := os.Readlink(rollback.CurrentLink); err == nil {
		rollback.PreviousLink = previous
	} else if !errors.Is(err, os.ErrNotExist) {
		return ExecutionResult{}, errors.New("plugin current pointer is not a symbolic link")
	}
	if packageInfo.Manifest.Kind == "im-adapter" {
		rollback.WrapperPath = filepath.Join(e.pluginBinRoot(), adapterLauncherName(operation.PluginID))
		if info, err := os.Lstat(rollback.WrapperPath); err == nil {
			if !info.Mode().IsRegular() {
				return ExecutionResult{}, errors.New("existing adapter launcher is not a regular file")
			}
			rollback.WrapperExisted = true
			rollback.WrapperBackup = filepath.Join(changeDir, "adapter-launcher.backup")
			if err := copyFile(rollback.WrapperPath, rollback.WrapperBackup, 0o600); err != nil {
				return ExecutionResult{}, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return ExecutionResult{}, err
		}
	}
	payload, _ := json.Marshal(rollback)
	refs := []string{}
	if rollback.WrapperBackup != "" {
		refs = append(refs, rollback.WrapperBackup)
	}
	return ExecutionResult{BackupRefs: refs, RollbackData: payload, RollbackAvailable: true}, nil
}

func (e *OSExecutor) executePluginInstall(changeID string, operation *protocol.PluginInstall) error {
	packageInfo, err := e.inspectArtifact(operation.ArtifactRef, operation.PluginID, operation.Version, operation.Publisher, operation.Digest)
	if err != nil {
		return err
	}
	pluginDirectory := filepath.Join(e.pluginRoot(), operation.PluginID)
	if err := os.MkdirAll(pluginDirectory, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(e.pluginRoot(), 0o755); err != nil {
		return err
	}
	if err := os.Chmod(pluginDirectory, 0o755); err != nil {
		return err
	}
	staging := filepath.Join(pluginDirectory, ".staging-"+safeUnitFragment(changeID))
	if err := os.RemoveAll(staging); err != nil {
		return err
	}
	if err := packageInfo.Extract(staging); err != nil {
		_ = os.RemoveAll(staging)
		return err
	}
	if err := atomicReplace(filepath.Join(staging, ".artifact-digest"), []byte(operation.Digest+"\n"), 0o644, -1, -1); err != nil {
		_ = os.RemoveAll(staging)
		return err
	}
	destination := filepath.Join(pluginDirectory, operation.Version)
	if err := os.Rename(staging, destination); err != nil {
		_ = os.RemoveAll(staging)
		return err
	}
	temporaryLink := filepath.Join(pluginDirectory, ".current-"+safeUnitFragment(changeID))
	_ = os.Remove(temporaryLink)
	if err := os.Symlink(operation.Version, temporaryLink); err != nil {
		return err
	}
	if err := os.Rename(temporaryLink, filepath.Join(pluginDirectory, "current")); err != nil {
		return err
	}
	if packageInfo.Manifest.Kind == "im-adapter" {
		if err := os.MkdirAll(e.pluginBinRoot(), 0o755); err != nil {
			return err
		}
		if err := os.Chmod(e.pluginBinRoot(), 0o755); err != nil {
			return err
		}
		entrypoint := filepath.Join(e.pluginRoot(), operation.PluginID, "current", filepath.FromSlash(packageInfo.Manifest.Entrypoint))
		launcher := "#!/bin/sh\nset -eu\nexport OPS_AGENT_CORE_ROOT=/opt/pi-ops-agent/current\nexec /opt/pi-ops-agent/current/runtime/node " + shellSingleQuote(entrypoint) + " \"$@\"\n"
		if err := atomicReplace(filepath.Join(e.pluginBinRoot(), adapterLauncherName(operation.PluginID)), []byte(launcher), 0o755, -1, -1); err != nil {
			return err
		}
	}
	return nil
}

func (e *OSExecutor) inspectArtifact(reference, id, version, publisher, digest string) (*pluginpkg.Package, error) {
	packageInfo, err := pluginpkg.InspectArtifactRef(e.pluginCatalog(), reference)
	if err != nil {
		return nil, err
	}
	if err := packageInfo.ValidateExpected(id, version, digest); err != nil {
		return nil, err
	}
	if packageInfo.Manifest.Publisher != publisher {
		return nil, errors.New("plugin package publisher does not match the prepared operation")
	}
	return packageInfo, nil
}

func verifyInstalledArtifact(destination string, packageInfo *pluginpkg.Package) error {
	info, err := os.Lstat(destination)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("installed plugin version directory is missing or invalid")
	}
	digest, err := os.ReadFile(filepath.Join(destination, ".artifact-digest"))
	if err != nil || strings.TrimSpace(string(digest)) != packageInfo.Digest {
		return errors.New("installed plugin artifact digest marker does not match the catalog package")
	}
	manifest, err := os.Lstat(filepath.Join(destination, "manifest.json"))
	if err != nil || !manifest.Mode().IsRegular() || manifest.Mode().Perm()&0o022 != 0 {
		return errors.New("installed plugin manifest is missing")
	}
	return nil
}

func adapterLauncherName(pluginID string) string {
	suffix := strings.TrimPrefix(pluginID, "adapter.")
	return "ops-agent-" + strings.ReplaceAll(suffix, ".", "-")
}

func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func (e *OSExecutor) rollbackPluginInstall(operation *protocol.PluginInstall, result ExecutionResult) error {
	var rollback pluginInstallRollback
	if err := json.Unmarshal(result.RollbackData, &rollback); err != nil {
		return err
	}
	expectedDestination := filepath.Join(e.pluginRoot(), operation.PluginID, operation.Version)
	if rollback.Destination != expectedDestination || filepath.Clean(rollback.Destination) != rollback.Destination {
		return errors.New("plugin rollback destination does not match the operation")
	}
	if err := os.RemoveAll(rollback.Destination); err != nil {
		return err
	}
	_ = os.Remove(rollback.CurrentLink)
	if rollback.PreviousLink != "" {
		if err := os.Symlink(rollback.PreviousLink, rollback.CurrentLink); err != nil {
			return err
		}
	}
	if rollback.WrapperPath != "" {
		if rollback.WrapperExisted {
			payload, err := os.ReadFile(rollback.WrapperBackup)
			if err != nil {
				return err
			}
			return atomicReplace(rollback.WrapperPath, payload, 0o755, -1, -1)
		}
		if err := os.Remove(rollback.WrapperPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (e *OSExecutor) pluginRoot() string {
	if e.PluginRoot != "" {
		return e.PluginRoot
	}
	return "/opt/pi-ops-agent/plugins"
}

func (e *OSExecutor) pluginCatalog() string {
	if e.PluginCatalog != "" {
		return e.PluginCatalog
	}
	return "/opt/pi-ops-agent/current/catalog"
}

func (e *OSExecutor) pluginBinRoot() string {
	if e.PluginBinRoot != "" {
		return e.PluginBinRoot
	}
	return "/opt/pi-ops-agent/bin"
}

func (e *OSExecutor) prepareBreakglass(ctx context.Context, changeID string, operation *protocol.BreakglassScript) (ExecutionResult, error) {
	changeDir := filepath.Join(e.StateDir, "changes", changeID)
	if err := os.MkdirAll(changeDir, 0o700); err != nil {
		return ExecutionResult{}, err
	}
	archive := ""
	backupRefs := []string{}
	if len(operation.BackupPaths) > 0 {
		archive = filepath.Join(changeDir, "backup.tar")
		args := []string{"--xattrs", "--acls", "--selinux", "-cpf", archive, "--absolute-names", "--"}
		args = append(args, operation.BackupPaths...)
		if _, err := e.Runner.Run(ctx, "/bin/tar", args...); err != nil {
			return ExecutionResult{}, err
		}
		backupRefs = append(backupRefs, archive)
	}
	scriptPath := filepath.Join(changeDir, "script.sh")
	if err := writePrivateFile(scriptPath, []byte(operation.Script), 0o700); err != nil {
		return ExecutionResult{}, err
	}
	rollback, _ := json.Marshal(breakglassRollback{ChangeID: changeID, Archive: archive})
	// This archive is recovery evidence for the explicitly named paths, not a
	// complete inverse for arbitrary root effects such as service, disk, account,
	// network, or external-state mutations.
	result := ExecutionResult{BackupRefs: backupRefs, RollbackData: rollback, RollbackAvailable: false}
	return result, nil
}

func (e *OSExecutor) runCapsule(ctx context.Context, scope ExecutionScope, scriptPath string, network bool) (string, error) {
	path := e.SystemdRunPath
	if path == "" {
		path = "/usr/bin/systemd-run"
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("systemd-run path must be a clean absolute path")
	}
	if e.Policy == nil || scope.PolicyRevision != e.Policy.Revision {
		return "", errors.New("break-glass target policy changed before capsule execution")
	}
	target, ok := e.Policy.Target(scope.TargetID)
	if !ok || target.Account != "root" {
		return "", errors.New("manual root capsules require an active root target")
	}
	runtimeSeconds := int64(600)
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return "", context.DeadlineExceeded
		}
		runtimeSeconds = int64(remaining.Round(time.Second) / time.Second)
		if runtimeSeconds < 1 {
			runtimeSeconds = 1
		}
		if runtimeSeconds > 600 {
			runtimeSeconds = 600
		}
	}
	changeDirectory := filepath.Join(e.StateDir, "changes", scope.ChangeID)
	args := []string{
		"--quiet", "--wait", "--pipe", "--collect", "--service-type=exec",
		"--unit=ops-agent-change-" + safeUnitFragment(scope.ChangeID),
		"--property=PrivateTmp=yes", "--property=UMask=0077",
		"--property=RuntimeMaxSec=" + strconv.FormatInt(runtimeSeconds, 10),
		"--property=TimeoutStopSec=30s", "--property=ReadOnlyPaths=" + changeDirectory,
	}
	if !network {
		args = append(args, "--property=PrivateNetwork=yes")
	}
	args = append(args, "/bin/bash", "--noprofile", "--norc", scriptPath)
	return e.Runner.Run(ctx, path, args...)
}

func (e *OSExecutor) ensureAllowedPath(path string) error {
	clean := filepath.Clean(path)
	if isCriticalPath(clean) {
		return errors.New("R3 identity, remote-entry, network, disk, or kernel path is not remotely mutable")
	}
	for _, root := range e.AllowedRoots {
		root = filepath.Clean(root)
		relative, err := filepath.Rel(root, clean)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			parent, err := filepath.EvalSymlinks(filepath.Dir(clean))
			if err != nil {
				return fmt.Errorf("resolve target parent: %w", err)
			}
			resolvedRoot, err := filepath.EvalSymlinks(root)
			if err != nil {
				return fmt.Errorf("resolve allowed root: %w", err)
			}
			resolvedTarget := filepath.Join(parent, filepath.Base(clean))
			if protocol.IsProtectedHostControlPath(resolvedTarget) {
				return errors.New("resolved target enters the agent control plane")
			}
			resolvedRelative, err := filepath.Rel(resolvedRoot, parent)
			if err == nil && resolvedRelative != ".." && !strings.HasPrefix(resolvedRelative, ".."+string(filepath.Separator)) {
				return nil
			}
			return errors.New("target parent escapes the allowed root through a symlink")
		}
	}
	return errors.New("path is outside configured write roots")
}

func isCriticalPath(path string) bool {
	if protocol.IsProtectedHostControlPath(path) {
		return true
	}
	critical := []string{
		"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
		"/etc/sudoers", "/etc/sudoers.d", "/etc/ssh", "/etc/pam.d",
		"/etc/security", "/etc/fstab", "/etc/crypttab", "/etc/ld.so.preload",
		"/etc/modprobe.d", "/etc/sysctl.d",
	}
	for _, denied := range critical {
		if path == denied || strings.HasPrefix(path, denied+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func isCriticalService(unit string) bool {
	_, denied := map[string]struct{}{
		"ops-root-helper.service": {}, "ops-pve-root-helper.service": {},
		"ops-systemd-helper.service": {}, "ops-agent-server.service": {}, "ops-agentd.service": {},
		"agentd-approval-reviewer.service": {}, "agentd-guardian.service": {},
		"ops-agent-healthcheck.service": {},
		"ssh.service":                   {}, "sshd.service": {}, "dbus.service": {}, "systemd-logind.service": {},
		"network.service": {}, "networking.service": {}, "networkmanager.service": {}, "systemd-networkd.service": {},
		"firewalld.service": {}, "nftables.service": {}, "iptables.service": {}, "ufw.service": {},
	}[strings.ToLower(unit)]
	return denied
}

func resultID(result ExecutionResult) string {
	var rollback breakglassRollback
	if json.Unmarshal(result.RollbackData, &rollback) == nil {
		return rollback.ChangeID
	}
	return "unknown"
}

func atomicReplace(path string, payload []byte, mode os.FileMode, uid, gid int) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".ops-agent-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if uid >= 0 || gid >= 0 {
		if err := temporary.Chown(uid, gid); err != nil {
			temporary.Close()
			return err
		}
	}
	if _, err := temporary.Write(payload); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func copyFile(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		output.Close()
		return err
	}
	return output.Close()
}

func writePrivateFile(path string, payload []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, payload, mode)
}

func safeUnitFragment(value string) string {
	var builder strings.Builder
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' {
			builder.WriteRune(char)
		}
	}
	if builder.Len() > 48 {
		return builder.String()[:48]
	}
	return builder.String()
}

type limitedBuffer struct {
	payload   []byte
	truncated bool
}

func (b *limitedBuffer) Write(payload []byte) (int, error) {
	remaining := maxCommandOutput - len(b.payload)
	if remaining > 0 {
		if len(payload) < remaining {
			remaining = len(payload)
		}
		b.payload = append(b.payload, payload[:remaining]...)
	}
	if len(payload) > remaining {
		b.truncated = true
	}
	return len(payload), nil
}
func (b *limitedBuffer) String() string {
	if b.truncated {
		return string(b.payload) + "\n[TRUNCATED]"
	}
	return string(b.payload)
}
