package roothelper

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

const legacyReplayRetention = 11 * time.Minute

type Change struct {
	ID                  string                          `json:"id"`
	ServerID            string                          `json:"serverId,omitempty"`
	MachineID           string                          `json:"machineId,omitempty"`
	TargetID            string                          `json:"targetId,omitempty"`
	PolicyRevision      string                          `json:"policyRevision,omitempty"`
	CapabilityRevision  string                          `json:"capabilityRevision,omitempty"`
	PreconditionDigest  string                          `json:"preconditionDigest,omitempty"`
	PreconditionFields  []protocol.ApprovalPlanField    `json:"preconditionFields,omitempty"`
	ResourceKey         string                          `json:"resourceKey,omitempty"`
	RecoveryOfChangeID  string                          `json:"recoveryOfChangeId,omitempty"`
	PVEMutationVersion  int                             `json:"pveMutationVersion,omitempty"`
	MutationDisposition string                          `json:"mutationDisposition,omitempty"`
	Resolution          *protocol.PVERecoveryResolution `json:"resolution,omitempty"`
	PlanHash            string                          `json:"planHash"`
	Kind                string                          `json:"kind"`
	Summary             string                          `json:"summary"`
	Operation           json.RawMessage                 `json:"operation"`
	State               string                          `json:"state"`
	PreparedAt          string                          `json:"preparedAt"`
	UpdatedAt           string                          `json:"updatedAt"`
	ApprovedByUID       *uint32                         `json:"approvedByUid,omitempty"`
	AuthorizationBasis  string                          `json:"authorizationBasis,omitempty"`
	AuthorizationScope  string                          `json:"authorizationScope,omitempty"`
	AuthorizedAt        string                          `json:"authorizedAt,omitempty"`
	BackupRefs          []string                        `json:"backupRefs,omitempty"`
	RollbackData        json.RawMessage                 `json:"rollbackData,omitempty"`
	RollbackAvailable   bool                            `json:"rollbackAvailable"`
	Verification        string                          `json:"verification,omitempty"`
	LastError           string                          `json:"lastError,omitempty"`
}

type requestRecord struct {
	UID         uint32            `json:"uid"`
	Fingerprint string            `json:"fingerprint"`
	Response    protocol.Response `json:"response"`
	ExpiresAt   string            `json:"expiresAt,omitempty"`
}

type approvalNonceRecord struct {
	ChangeID  string `json:"changeId"`
	ExpiresAt string `json:"expiresAt,omitempty"`
}

func (r *approvalNonceRecord) UnmarshalJSON(payload []byte) error {
	var legacy string
	if json.Unmarshal(payload, &legacy) == nil {
		r.ChangeID = legacy
		return nil
	}
	type wire approvalNonceRecord
	var value wire
	if err := json.Unmarshal(payload, &value); err != nil {
		return err
	}
	*r = approvalNonceRecord(value)
	return nil
}

type persistedState struct {
	Changes        map[string]*Change             `json:"changes"`
	Requests       map[string]requestRecord       `json:"requests"`
	ApprovalNonces map[string]approvalNonceRecord `json:"approvalNonces,omitempty"`
	ResourceLocks  map[string]string              `json:"resourceLocks,omitempty"`
}

type StoreLimits struct {
	MaxChanges        int
	MaxPendingChanges int
	MaxRequests       int
	MaxApprovalNonces int
	MaxStateBytes     int
	PendingChangeTTL  time.Duration
	TerminalChangeTTL time.Duration
	RequestTTL        time.Duration
	ApprovalNonceTTL  time.Duration
	Now               func() time.Time
}

func defaultStoreLimits() StoreLimits {
	return StoreLimits{
		MaxChanges: 2048, MaxPendingChanges: 512, MaxRequests: 4096,
		MaxApprovalNonces: 4096, MaxStateBytes: 64 * 1024 * 1024,
		PendingChangeTTL: 30 * 24 * time.Hour, TerminalChangeTTL: 90 * 24 * time.Hour,
		RequestTTL: 15 * time.Minute, ApprovalNonceTTL: 10 * time.Minute,
		Now: time.Now,
	}
}

func normalizeStoreLimits(limits StoreLimits) (StoreLimits, error) {
	defaults := defaultStoreLimits()
	if limits.MaxChanges == 0 {
		limits.MaxChanges = defaults.MaxChanges
	}
	if limits.MaxPendingChanges == 0 {
		limits.MaxPendingChanges = defaults.MaxPendingChanges
	}
	if limits.MaxRequests == 0 {
		limits.MaxRequests = defaults.MaxRequests
	}
	if limits.MaxApprovalNonces == 0 {
		limits.MaxApprovalNonces = defaults.MaxApprovalNonces
	}
	if limits.MaxStateBytes == 0 {
		limits.MaxStateBytes = defaults.MaxStateBytes
	}
	if limits.PendingChangeTTL == 0 {
		limits.PendingChangeTTL = defaults.PendingChangeTTL
	}
	if limits.TerminalChangeTTL == 0 {
		limits.TerminalChangeTTL = defaults.TerminalChangeTTL
	}
	if limits.RequestTTL == 0 {
		limits.RequestTTL = defaults.RequestTTL
	}
	if limits.ApprovalNonceTTL == 0 {
		limits.ApprovalNonceTTL = defaults.ApprovalNonceTTL
	}
	if limits.Now == nil {
		limits.Now = defaults.Now
	}
	if limits.MaxChanges <= 0 || limits.MaxPendingChanges <= 0 || limits.MaxPendingChanges > limits.MaxChanges ||
		limits.MaxRequests <= 0 || limits.MaxApprovalNonces <= 0 || limits.MaxStateBytes < protocol.MaxFrameBytes ||
		limits.PendingChangeTTL <= 0 || limits.TerminalChangeTTL <= 0 || limits.RequestTTL < 10*time.Minute ||
		limits.ApprovalNonceTTL < 5*time.Minute {
		return StoreLimits{}, errors.New("invalid root-helper store limits")
	}
	return limits, nil
}

type Store struct {
	mu               sync.Mutex
	dir              string
	path             string
	state            persistedState
	limits           StoreLimits
	reservations     map[string]struct{}
	volatileRequests map[string]requestRecord
	// durabilityFailure is set only after state.json has been atomically
	// replaced but the containing directory could not be opened or synced. At
	// that point the candidate is the sole authoritative in-process state, but
	// crash durability is unknown. The broker must fail closed until this store
	// is reopened and the on-disk state is validated again.
	durabilityFailure error
	// persistFault is nil in production and lets package tests inject failures
	// around persistence stages. It is deliberately unexported so runtime
	// configuration cannot weaken or bypass durable state writes.
	persistFault func(string) error
}

func OpenStore(dir string) (*Store, error) {
	return OpenStoreWithLimits(dir, StoreLimits{})
}

func OpenStoreWithLimits(dir string, configured StoreLimits) (*Store, error) {
	limits, err := normalizeStoreLimits(configured)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	store := &Store{
		dir: dir, path: filepath.Join(dir, "state.json"), limits: limits,
		state: emptyPersistedState(), reservations: make(map[string]struct{}),
		volatileRequests: make(map[string]requestRecord),
	}
	payload, err := os.ReadFile(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	if len(payload) > limits.MaxStateBytes*2 {
		return nil, fmt.Errorf("root-helper state exceeds the bounded migration limit")
	}
	if err := json.Unmarshal(payload, &store.state); err != nil {
		return nil, fmt.Errorf("decode root-helper state: %w", err)
	}
	store.initializeMaps()
	info, err := os.Stat(store.path)
	if err != nil {
		return nil, err
	}
	legacyExpiry := info.ModTime().Add(legacyReplayRetention)
	for requestID, record := range store.state.Requests {
		if record.ExpiresAt == "" {
			record.ExpiresAt = timestamp(legacyExpiry)
			store.state.Requests[requestID] = record
		}
	}
	for nonce, record := range store.state.ApprovalNonces {
		if record.ExpiresAt == "" {
			record.ExpiresAt = timestamp(legacyExpiry)
			store.state.ApprovalNonces[nonce] = record
		}
	}
	if err := migrateLegacyPVEResourceKeys(&store.state); err != nil {
		return nil, err
	}
	// Older v1 files may contain parentTaskEvidence:null because an empty Go
	// slice was cloned through nil. Normalize that one local persisted-state
	// representation before strict validation and rewrite it canonically as [].
	normalizePVERecoveryResolutionEvidence(&store.state)
	if err := store.validateState(); err != nil {
		return nil, err
	}
	candidate := clonePersistedState(store.state)
	store.pruneState(&candidate, limits.Now())
	if err := store.enforceChangeQuotas(&candidate, ""); err != nil {
		return nil, err
	}
	if len(candidate.Requests) > limits.MaxRequests || len(candidate.ApprovalNonces) > limits.MaxApprovalNonces {
		return nil, errors.New("root-helper replay state exceeds configured quota after TTL pruning")
	}
	if err := store.commitStateLocked(candidate); err != nil {
		return nil, err
	}
	return store, nil
}

func emptyPersistedState() persistedState {
	return persistedState{
		Changes: make(map[string]*Change), Requests: make(map[string]requestRecord),
		ApprovalNonces: make(map[string]approvalNonceRecord), ResourceLocks: make(map[string]string),
	}
}

func (s *Store) initializeMaps() {
	if s.state.Changes == nil {
		s.state.Changes = make(map[string]*Change)
	}
	if s.state.Requests == nil {
		s.state.Requests = make(map[string]requestRecord)
	}
	if s.state.ApprovalNonces == nil {
		s.state.ApprovalNonces = make(map[string]approvalNonceRecord)
	}
	if s.state.ResourceLocks == nil {
		s.state.ResourceLocks = make(map[string]string)
	}
}

// migrateLegacyPVEResourceKeys upgrades the v0.3 prerelease key shape
// pve/{qemu|lxc}/VMID to the cluster-global pve/vmid/VMID identity. Proxmox
// VMIDs are global across guest types, so two legacy locks that collapse onto
// the same VMID are ambiguous and must fail closed instead of selecting an
// owner.
func migrateLegacyPVEResourceKeys(state *persistedState) error {
	for id, change := range state.Changes {
		operation, err := protocol.ParseStoredOperation(change.Operation)
		if err != nil {
			return fmt.Errorf("decode persisted operation for PVE resource migration %q: %w", id, err)
		}
		clusterKey, legacyKey, ok := pvePersistedResourceKeys(operation)
		if !ok {
			continue
		}
		if change.ResourceKey != "" && change.ResourceKey != legacyKey && change.ResourceKey != clusterKey {
			return fmt.Errorf("persisted PVE resource key for %q is not recognized", id)
		}
		change.ResourceKey = clusterKey
		if change.State == StateRecoveryRequired && change.MutationDisposition == "" {
			// Older state did not distinguish a proven no-start failure from an
			// interrupted or lost-UPID mutation. Never infer safety from text.
			change.MutationDisposition = protocol.PVEMutationDispositionUnknown
		}
	}

	normalized := make(map[string]string, len(state.ResourceLocks))
	for key, owner := range state.ResourceLocks {
		change, exists := state.Changes[owner]
		if !exists {
			return fmt.Errorf("persisted resource lock %q has no matching change", key)
		}
		operation, err := protocol.ParseStoredOperation(change.Operation)
		if err != nil {
			return fmt.Errorf("decode persisted lock owner %q: %w", owner, err)
		}
		clusterKey, legacyKey, pve := pvePersistedResourceKeys(operation)
		normalizedKey := key
		if pve {
			if key != legacyKey && key != clusterKey {
				return fmt.Errorf("persisted PVE lock %q for %q is not recognized", key, owner)
			}
			normalizedKey = clusterKey
		}
		if previous, collision := normalized[normalizedKey]; collision && previous != owner {
			return fmt.Errorf("legacy PVE resource locks for cluster-global %s conflict between %s and %s", normalizedKey, previous, owner)
		}
		normalized[normalizedKey] = owner
	}
	state.ResourceLocks = normalized
	return nil
}

func pvePersistedResourceKeys(operation protocol.Operation) (clusterKey string, legacyKey string, ok bool) {
	var guestType string
	var vmid int
	switch value := operation.(type) {
	case *protocol.PVEGuestAction:
		guestType, vmid = value.GuestType, value.VMID
	case *protocol.PVESnapshotCreate:
		guestType, vmid = value.GuestType, value.VMID
	case *protocol.PVESnapshotDelete:
		guestType, vmid = value.GuestType, value.VMID
	case *protocol.PVESnapshotRollback:
		guestType, vmid = value.GuestType, value.VMID
	case *protocol.PVEGuestBackup:
		guestType, vmid = value.GuestType, value.VMID
	case *protocol.PVEGuestRestore:
		guestType, vmid = value.GuestType, value.VMID
	case *protocol.PVEGuestMigrate:
		guestType, vmid = value.GuestType, value.VMID
	default:
		return "", "", false
	}
	return fmt.Sprintf("pve/vmid/%d", vmid), fmt.Sprintf("pve/%s/%d", guestType, vmid), true
}

func (s *Store) validateState() error {
	for id, change := range s.state.Changes {
		if change == nil || change.ID != id {
			return fmt.Errorf("invalid persisted change %q", id)
		}
		if _, err := time.Parse(time.RFC3339Nano, change.PreparedAt); err != nil {
			return fmt.Errorf("invalid prepared time for %q", id)
		}
		if _, err := time.Parse(time.RFC3339Nano, change.UpdatedAt); err != nil {
			return fmt.Errorf("invalid updated time for %q", id)
		}
		if change.AuthorizationBasis == "" {
			if change.AuthorizationScope != "" || change.AuthorizedAt != "" {
				return fmt.Errorf("persisted change %q has incomplete authorization metadata", id)
			}
		} else {
			if len(change.AuthorizationBasis) > 256 || len(change.AuthorizationScope) > 128 ||
				strings.ContainsAny(change.AuthorizationBasis+change.AuthorizationScope, "\x00\r\n") {
				return fmt.Errorf("persisted change %q has invalid authorization metadata", id)
			}
			if _, err := time.Parse(time.RFC3339Nano, change.AuthorizedAt); err != nil {
				return fmt.Errorf("persisted change %q has invalid authorization time", id)
			}
		}
		operation, err := protocol.ParseStoredOperation(change.Operation)
		if err != nil {
			return fmt.Errorf("invalid persisted operation for %q: %w", id, err)
		}
		if operation.Kind() != change.Kind {
			return fmt.Errorf("persisted operation kind for %q does not match change kind", id)
		}
		recoveryOfChangeID := protocol.PVERecoveryOfChangeID(operation)
		if change.RecoveryOfChangeID != recoveryOfChangeID {
			return fmt.Errorf("persisted recovery parent for %q does not match its operation", id)
		}
		if requiresAuthoritativePrecondition(operation) && (change.PreconditionDigest == "" || len(change.PreconditionFields) == 0) {
			return fmt.Errorf("persisted change %q has no authoritative precondition", id)
		}
		resourceKey := operationResourceKey(operation)
		if isPVEOperation(operation) {
			if change.PVEMutationVersion < 0 || change.PVEMutationVersion > 1 {
				return fmt.Errorf("persisted PVE mutation protocol version for %q is invalid", id)
			}
			switch change.MutationDisposition {
			case "", protocol.PVEMutationDispositionNotStarted, protocol.PVEMutationDispositionTasksTerminal,
				protocol.PVEMutationDispositionUnknown:
			default:
				return fmt.Errorf("persisted PVE mutation disposition for %q is invalid", id)
			}
			if change.State == StateRecoveryRequired && change.MutationDisposition == "" {
				return fmt.Errorf("persisted unresolved PVE change %q has no mutation disposition", id)
			}
		} else if change.PVEMutationVersion != 0 || change.MutationDisposition != "" {
			return fmt.Errorf("non-PVE change %q has PVE mutation metadata", id)
		}
		if change.ResourceKey != "" && change.ResourceKey != resourceKey {
			return fmt.Errorf("persisted resource key for %q does not match its operation", id)
		}
		change.ResourceKey = resourceKey
		if len(change.PreconditionFields) > 0 {
			digest, digestErr := protocol.ApprovalPreconditionDigest(change.PreconditionFields)
			if digestErr != nil || digest != change.PreconditionDigest {
				return fmt.Errorf("persisted precondition for %q is invalid", id)
			}
		}
		if change.Resolution == nil && change.State == StateSuperseded {
			return fmt.Errorf("persisted superseded change %q has no recovery resolution", id)
		}
		if change.Resolution != nil {
			if change.State != StateSuperseded || change.Resolution.ChildChangeID == id || change.Resolution.Validate() != nil {
				return fmt.Errorf("persisted recovery resolution for %q is invalid", id)
			}
			if change.Resolution.Basis == "local-unknown-clearance" &&
				(change.Resolution.ParentChangeID != id || change.Resolution.ResourceKey != change.ResourceKey) {
				return fmt.Errorf("persisted local unknown-clearance resolution for %q does not bind its parent and resource", id)
			}
			if change.MutationDisposition != change.Resolution.ParentMutationDisposition {
				return fmt.Errorf("persisted recovery resolution for %q does not bind its parent mutation disposition", id)
			}
			for _, evidence := range change.Resolution.ParentTaskEvidence {
				if !slices.Contains(change.BackupRefs, "pve:task:"+evidence.UPID) {
					return fmt.Errorf("persisted recovery resolution for %q has task evidence absent from backup refs", id)
				}
			}
		}
	}
	for id, change := range s.state.Changes {
		if change.RecoveryOfChangeID != "" {
			parent, exists := s.state.Changes[change.RecoveryOfChangeID]
			if !exists || parent.ResourceKey == "" || parent.ResourceKey != change.ResourceKey ||
				parent.ServerID != change.ServerID || parent.MachineID != change.MachineID || parent.TargetID != change.TargetID {
				return fmt.Errorf("persisted recovery change %q has no matching parent scope", id)
			}
			selected := parent.Resolution != nil && parent.Resolution.ChildChangeID == id &&
				parent.Resolution.ChildPlanHash == change.PlanHash
			if selected {
				if parent.State != StateSuperseded || change.State == StatePendingApproval || change.State == StateRejected || change.State == StateRolledBack {
					return fmt.Errorf("persisted recovery transfer from %q to %q has invalid states", parent.ID, id)
				}
			} else if change.State != StatePendingApproval && change.State != StateRejected {
				return fmt.Errorf("persisted recovery change %q did not receive its parent's lock", id)
			}
		}
		if change.Resolution != nil {
			child, exists := s.state.Changes[change.Resolution.ChildChangeID]
			if !exists || child.RecoveryOfChangeID != id || child.PlanHash != change.Resolution.ChildPlanHash ||
				child.ResourceKey != change.ResourceKey {
				return fmt.Errorf("persisted recovery resolution for %q has no matching child evidence", id)
			}
		}
	}
	if err := validateRecoveryChainAcyclic(s.state.Changes); err != nil {
		return err
	}
	for resourceKey, changeID := range s.state.ResourceLocks {
		change, exists := s.state.Changes[changeID]
		if !exists || change.ResourceKey != resourceKey {
			return fmt.Errorf("persisted resource lock %q has no matching change", resourceKey)
		}
	}
	for requestID, record := range s.state.Requests {
		if requestID == "" || record.Fingerprint == "" {
			return fmt.Errorf("invalid persisted request %q", requestID)
		}
		if _, err := time.Parse(time.RFC3339Nano, record.ExpiresAt); err != nil {
			return fmt.Errorf("invalid persisted request expiry %q", requestID)
		}
	}
	for nonce, record := range s.state.ApprovalNonces {
		if nonce == "" || record.ChangeID == "" {
			return fmt.Errorf("invalid persisted approval nonce")
		}
		if _, err := time.Parse(time.RFC3339Nano, record.ExpiresAt); err != nil {
			return fmt.Errorf("invalid persisted approval nonce expiry")
		}
	}
	return nil
}

func validateRecoveryChainAcyclic(changes map[string]*Change) error {
	for id := range changes {
		seen := make(map[string]struct{})
		current := id
		for current != "" {
			if _, duplicate := seen[current]; duplicate {
				return fmt.Errorf("persisted PVE recovery chain contains a cycle at %q", current)
			}
			seen[current] = struct{}{}
			change, exists := changes[current]
			if !exists {
				break
			}
			current = change.RecoveryOfChangeID
		}
	}
	return nil
}

func (s *Store) Directory() string { return s.dir }

func (s *Store) Change(id string) (*Change, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	change, ok := s.state.Changes[id]
	if !ok {
		return nil, false
	}
	protected := changeReferencedAsRecoveryParent(&s.state, id) || changeSelectedAsRecoveryChild(&s.state, id)
	if change.ResourceKey != "" && s.state.ResourceLocks[change.ResourceKey] == id {
		protected = true
	}
	if !protected && s.changeExpired(change, s.limits.Now()) {
		return nil, false
	}
	return cloneChange(change), true
}

func (s *Store) PutChange(change *Change) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := clonePersistedState(s.state)
	s.pruneState(&candidate, s.limits.Now())
	candidate.Changes[change.ID] = cloneChange(change)
	if err := s.enforceChangeQuotas(&candidate, change.ID); err != nil {
		return err
	}
	return s.commitStateLocked(candidate)
}

func (s *Store) ValidateRecoveryCandidate(change *Change) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := validateRecoveryCandidateState(s.state, change)
	return err
}

func (s *Store) PutChangeWithResourceLock(change *Change) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if change.RecoveryOfChangeID != "" {
		return errors.New("PVE recovery change requires an atomic parent lock transfer")
	}
	candidate := clonePersistedState(s.state)
	s.pruneState(&candidate, s.limits.Now())
	if change.ResourceKey != "" {
		if owner, exists := candidate.ResourceLocks[change.ResourceKey]; exists && owner != change.ID {
			return fmt.Errorf("resource %s is locked by unresolved change %s", change.ResourceKey, owner)
		}
		candidate.ResourceLocks[change.ResourceKey] = change.ID
	}
	candidate.Changes[change.ID] = cloneChange(change)
	if err := s.enforceChangeQuotas(&candidate, change.ID); err != nil {
		return err
	}
	return s.commitStateLocked(candidate)
}

// PutRecoveryChangeAndTransferResource atomically marks the RECOVERY_REQUIRED
// parent as superseded, binds its canonical resolution evidence to the child,
// and transfers the cluster-global VMID lock. A crash can therefore observe
// either the old parent owner or the new child owner, never a released gap.
func (s *Store) PutRecoveryChangeAndTransferResource(change *Change, readiness PVERecoveryReadiness) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := clonePersistedState(s.state)
	s.pruneState(&candidate, s.limits.Now())
	parent, err := validateRecoveryCandidateState(candidate, change)
	if err != nil {
		return err
	}
	if change.State != StatePreparing || change.AuthorizationBasis == "" {
		return errors.New("PVE recovery lock transfer requires an authorized PREPARING child")
	}
	if err := readiness.Validate(); err != nil {
		return fmt.Errorf("PVE recovery parent readiness is invalid: %w", err)
	}
	parentOperation, err := protocol.ParseStoredOperation(parent.Operation)
	if err != nil {
		return fmt.Errorf("decode PVE recovery parent operation: %w", err)
	}
	parentNode, _, _ := pveOperationGuest(parentOperation)
	for _, evidence := range readiness.TaskEvidence {
		if evidence.Node != parentNode {
			return errors.New("PVE recovery task evidence is outside the parent operation node")
		}
		if evidence.Role == "safety-backup" {
			switch parentOperation.(type) {
			case *protocol.PVESnapshotDelete, *protocol.PVESnapshotRollback:
			default:
				return errors.New("PVE recovery safety-backup evidence is invalid for the parent operation")
			}
		}
	}
	if err := mergeChangeEvidence(parent, readiness.EvidenceRefs...); err != nil {
		return fmt.Errorf("bind PVE recovery parent evidence: %w", err)
	}
	parent.State = StateSuperseded
	parent.UpdatedAt = change.UpdatedAt
	parent.MutationDisposition = readiness.MutationDisposition
	parent.Resolution = &protocol.PVERecoveryResolution{
		Kind: "pve.recovery-transfer/v1", ChildChangeID: change.ID,
		ChildPlanHash: change.PlanHash, TransferredAt: change.UpdatedAt,
		ParentMutationDisposition: readiness.MutationDisposition,
		ParentTaskEvidence:        append([]protocol.PVERecoveryTaskEvidence{}, readiness.TaskEvidence...),
	}
	candidate.Changes[parent.ID] = parent
	candidate.Changes[change.ID] = cloneChange(change)
	candidate.ResourceLocks[change.ResourceKey] = change.ID
	if err := s.enforceChangeQuotas(&candidate, change.ID); err != nil {
		return err
	}
	return s.commitStateLocked(candidate)
}

// PutRecoveryChangeAndTransferResourceWithClearance is the durable half of a
// broker-held, one-shot local unknown clearance. The caller keeps the volatile
// clearance lock held across this transaction, so a crash observes either the
// unresolved parent or this complete SUPERSEDED/child-lock state. The parent
// disposition deliberately remains STARTED_OR_UNKNOWN; clearance is not task
// evidence and must never rewrite history as known-safe execution.
func (s *Store) PutRecoveryChangeAndTransferResourceWithClearance(
	change *Change,
	challenge protocol.PVERecoveryClearanceChallenge,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := clonePersistedState(s.state)
	s.pruneState(&candidate, s.limits.Now())
	parent, err := validateRecoveryCandidateState(candidate, change)
	if err != nil {
		return err
	}
	if change.State != StatePreparing || change.AuthorizationBasis == "" {
		return errors.New("PVE recovery clearance transfer requires an authorized PREPARING child")
	}
	if err := challenge.Validate(); err != nil {
		return fmt.Errorf("PVE recovery clearance challenge is invalid: %w", err)
	}
	if challenge.ParentChangeID != parent.ID || challenge.ChildChangeID != change.ID ||
		challenge.ChildPlanHash != change.PlanHash || challenge.ResourceKey != change.ResourceKey {
		return errors.New("PVE recovery clearance does not bind the exact parent, child, plan, and resource")
	}
	if parent.MutationDisposition != protocol.PVEMutationDispositionUnknown {
		return errors.New("PVE recovery clearance parent is no longer STARTED_OR_UNKNOWN")
	}
	parent.State = StateSuperseded
	parent.UpdatedAt = change.UpdatedAt
	parent.Resolution = &protocol.PVERecoveryResolution{
		Kind: "pve.recovery-transfer/v1", Basis: "local-unknown-clearance",
		ParentChangeID: parent.ID, ChildChangeID: change.ID, ChildPlanHash: change.PlanHash,
		ResourceKey: change.ResourceKey, TransferredAt: change.UpdatedAt,
		ParentMutationDisposition:  protocol.PVEMutationDispositionUnknown,
		ParentTaskEvidence:         []protocol.PVERecoveryTaskEvidence{},
		ClearanceObservationDigest: challenge.Observation.ObservationDigest,
		ActiveTaskDigest:           challenge.Observation.ActiveTaskDigest,
		GuestStateDigest:           challenge.Observation.GuestStateDigest,
		ClusterStateDigest:         challenge.Observation.ClusterStateDigest,
	}
	candidate.Changes[parent.ID] = parent
	candidate.Changes[change.ID] = cloneChange(change)
	candidate.ResourceLocks[change.ResourceKey] = change.ID
	if err := s.enforceChangeQuotas(&candidate, change.ID); err != nil {
		return err
	}
	return s.commitStateLocked(candidate)
}

func validateRecoveryCandidateState(state persistedState, change *Change) (*Change, error) {
	if change == nil || change.RecoveryOfChangeID == "" || change.RecoveryOfChangeID == change.ID ||
		!strings.HasPrefix(change.ID, "pve-change-") || !strings.HasPrefix(change.RecoveryOfChangeID, "pve-change-") ||
		!strings.HasPrefix(change.ResourceKey, "pve/vmid/") {
		return nil, errors.New("invalid PVE recovery change identity")
	}
	parent, exists := state.Changes[change.RecoveryOfChangeID]
	if !exists {
		return nil, errors.New("PVE recovery parent change not found")
	}
	if parent.State != StateRecoveryRequired || parent.Resolution != nil {
		return nil, errors.New("PVE recovery parent is not unresolved RECOVERY_REQUIRED state")
	}
	if parent.ResourceKey != change.ResourceKey || parent.ServerID != change.ServerID ||
		parent.MachineID != change.MachineID || parent.TargetID != change.TargetID {
		return nil, errors.New("PVE recovery parent does not match the same endpoint, target, and cluster-global VMID")
	}
	if owner, locked := state.ResourceLocks[change.ResourceKey]; !locked || owner != parent.ID {
		return nil, errors.New("PVE recovery parent no longer owns the cluster-global VMID lock")
	}
	return cloneChange(parent), nil
}

// PutRejectedChange persists a never-executed rejection without disturbing a
// lock held by another unresolved change. It only releases the resource when
// this exact change already owns it.
func (s *Store) PutRejectedChange(change *Change) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := clonePersistedState(s.state)
	s.pruneState(&candidate, s.limits.Now())
	if owner, exists := candidate.ResourceLocks[change.ResourceKey]; exists && owner == change.ID {
		delete(candidate.ResourceLocks, change.ResourceKey)
	}
	candidate.Changes[change.ID] = cloneChange(change)
	if err := s.enforceChangeQuotas(&candidate, change.ID); err != nil {
		return err
	}
	return s.commitStateLocked(candidate)
}

func (s *Store) PutChangeAndReleaseResource(change *Change) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := clonePersistedState(s.state)
	s.pruneState(&candidate, s.limits.Now())
	if change.ResourceKey != "" {
		if owner, exists := candidate.ResourceLocks[change.ResourceKey]; exists {
			if owner != change.ID {
				return fmt.Errorf("resource %s is owned by another change", change.ResourceKey)
			}
			delete(candidate.ResourceLocks, change.ResourceKey)
		}
	}
	candidate.Changes[change.ID] = cloneChange(change)
	if err := s.enforceChangeQuotas(&candidate, change.ID); err != nil {
		return err
	}
	return s.commitStateLocked(candidate)
}

func (s *Store) Cached(requestID string, uid uint32, fingerprint string) (protocol.Response, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.limits.Now()
	record, ok := s.state.Requests[requestID]
	if !ok {
		record, ok = s.volatileRequests[requestID]
	}
	if !ok || recordExpired(record.ExpiresAt, now) {
		return protocol.Response{}, false, nil
	}
	if record.UID != uid || record.Fingerprint != fingerprint {
		return protocol.Response{}, false, errors.New("requestId replayed by another peer or with different content")
	}
	return record.Response, true, nil
}

func (s *Store) ReserveRequest(requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.limits.Now()
	if record, ok := s.state.Requests[requestID]; ok && !recordExpired(record.ExpiresAt, now) {
		return nil
	}
	if record, ok := s.volatileRequests[requestID]; ok && !recordExpired(record.ExpiresAt, now) {
		return nil
	}
	if _, ok := s.reservations[requestID]; ok {
		return nil
	}
	activeRecords := 0
	for _, record := range s.state.Requests {
		if !recordExpired(record.ExpiresAt, now) {
			activeRecords++
		}
	}
	for _, record := range s.volatileRequests {
		if !recordExpired(record.ExpiresAt, now) {
			activeRecords++
		}
	}
	if activeRecords+len(s.reservations) >= s.limits.MaxRequests {
		return errors.New("request replay cache quota is exhausted")
	}
	s.reservations[requestID] = struct{}{}
	return nil
}

func (s *Store) ReleaseRequest(requestID string) {
	s.mu.Lock()
	delete(s.reservations, requestID)
	s.mu.Unlock()
}

func (s *Store) Cache(requestID string, uid uint32, fingerprint string, response protocol.Response, deadline time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer delete(s.reservations, requestID)
	now := s.limits.Now()
	expiresAt := deadline
	maximum := now.Add(s.limits.RequestTTL)
	if expiresAt.After(maximum) {
		expiresAt = maximum
	}
	record := requestRecord{UID: uid, Fingerprint: fingerprint, Response: response, ExpiresAt: timestamp(expiresAt)}
	candidate := clonePersistedState(s.state)
	s.pruneState(&candidate, now)
	candidate.Requests[requestID] = record
	if len(candidate.Requests) > s.limits.MaxRequests {
		return errors.New("request replay cache quota is exhausted")
	}
	if err := s.commitStateLocked(candidate); err != nil {
		// A pre-rename cache write failure can retain a bounded volatile replay
		// guard. A post-rename failure has already committed candidate in this
		// process and put the whole store into fail-stop mode, so treating it as
		// an ordinary uncommitted cache miss would be unsafe.
		if s.durabilityFailure != nil {
			return err
		}
		s.pruneVolatileLocked(now)
		if len(s.volatileRequests) < s.limits.MaxRequests {
			s.volatileRequests[requestID] = record
		}
		return err
	}
	delete(s.volatileRequests, requestID)
	return nil
}

func (s *Store) UseApprovalNonce(nonce, changeID string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.limits.Now()
	candidate := clonePersistedState(s.state)
	s.pruneState(&candidate, now)
	if previous, exists := candidate.ApprovalNonces[nonce]; exists && !recordExpired(previous.ExpiresAt, now) {
		return fmt.Errorf("approval nonce was already used for %s", previous.ChangeID)
	}
	maximum := now.Add(s.limits.ApprovalNonceTTL)
	if expiresAt.After(maximum) {
		expiresAt = maximum
	}
	if !expiresAt.After(now) {
		return errors.New("approval nonce expiry is not in the future")
	}
	if len(candidate.ApprovalNonces) >= s.limits.MaxApprovalNonces {
		return errors.New("approval nonce quota is exhausted")
	}
	candidate.ApprovalNonces[nonce] = approvalNonceRecord{ChangeID: changeID, ExpiresAt: timestamp(expiresAt)}
	return s.commitStateLocked(candidate)
}

func (s *Store) recoverInterrupted(now time.Time) ([]Change, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := clonePersistedState(s.state)
	s.pruneState(&candidate, now)
	var recovered []Change
	for _, change := range candidate.Changes {
		operation, operationErr := protocol.ParseStoredOperation(change.Operation)
		pve := operationErr == nil && isPVEOperation(operation)
		switch change.State {
		case StateExecuting, StateVerifying:
			// PVE mutation protocol v1 journals each API attempt with a durable
			// intent and then a node-bound UPID. Keep an in-flight v1 change in
			// its exact state so the restarted broker can resume that journal;
			// converting it to RECOVERY_REQUIRED merely because the HTTP-serving
			// process restarted would abandon a still-running task.
			if pve && change.PVEMutationVersion >= 1 {
				recovered = append(recovered, *cloneChange(change))
				break
			}
			fallthrough
		case StatePreparing, StateRollingBack:
			previous := change.State
			change.State = StateRecoveryRequired
			if pve {
				change.MutationDisposition = protocol.PVEMutationDispositionUnknown
				if previous == StatePreparing && change.PVEMutationVersion >= 1 {
					change.MutationDisposition = protocol.PVEMutationDispositionNotStarted
				}
			}
			change.UpdatedAt = timestamp(now)
			change.LastError = "helper restarted while change was " + previous + "; operator review or explicit rollback is required"
			recovered = append(recovered, *cloneChange(change))
		case StateRecoveryRequired:
			recovered = append(recovered, *cloneChange(change))
		}
		retainResource := change.State == StateRecoveryRequired ||
			(pve && change.PVEMutationVersion >= 1 &&
				(change.State == StateExecuting || change.State == StateVerifying))
		if retainResource && change.ResourceKey != "" {
			if owner, exists := candidate.ResourceLocks[change.ResourceKey]; exists && owner != change.ID {
				return nil, fmt.Errorf("resource %s has conflicting unresolved changes %s and %s", change.ResourceKey, owner, change.ID)
			}
			candidate.ResourceLocks[change.ResourceKey] = change.ID
		}
	}
	if err := s.enforceChangeQuotas(&candidate, ""); err != nil {
		return nil, err
	}
	if err := s.commitStateLocked(candidate); err != nil {
		return nil, err
	}
	return recovered, nil
}

func (s *Store) pruneState(state *persistedState, now time.Time) {
	for requestID, record := range state.Requests {
		if recordExpired(record.ExpiresAt, now) {
			delete(state.Requests, requestID)
		}
	}
	for nonce, record := range state.ApprovalNonces {
		if recordExpired(record.ExpiresAt, now) {
			delete(state.ApprovalNonces, nonce)
		}
	}
	for changeID, change := range state.Changes {
		if _, locked := state.ResourceLocks[change.ResourceKey]; change.ResourceKey != "" && locked {
			continue
		}
		if changeReferencedAsRecoveryParent(state, changeID) || changeSelectedAsRecoveryChild(state, changeID) {
			continue
		}
		if s.changeExpired(change, now) {
			delete(state.Changes, changeID)
		}
	}
}

func (s *Store) changeExpired(change *Change, now time.Time) bool {
	updatedAt, err := time.Parse(time.RFC3339Nano, change.UpdatedAt)
	if err != nil || now.Before(updatedAt) {
		return false
	}
	age := now.Sub(updatedAt)
	switch change.State {
	case StatePendingApproval:
		return age >= s.limits.PendingChangeTTL
	case StateRejected, StateCommitted, StateRolledBack, StateSuperseded:
		return age >= s.limits.TerminalChangeTTL
	default:
		return false
	}
}

func (s *Store) enforceChangeQuotas(state *persistedState, preserveID string) error {
	pendingCount := 0
	for _, change := range state.Changes {
		if change.State == StatePendingApproval {
			pendingCount++
		}
	}
	pendingCandidates := changeIDsByAge(state, func(change *Change) bool {
		return change.State == StatePendingApproval && change.ID != preserveID && !changeHasActiveReplayRecord(state, change.ID)
	})
	for pendingCount > s.limits.MaxPendingChanges && len(pendingCandidates) > 0 {
		delete(state.Changes, pendingCandidates[0])
		pendingCandidates = pendingCandidates[1:]
		pendingCount--
	}
	if pendingCount > s.limits.MaxPendingChanges {
		return errors.New("pending change quota is exhausted by unexpired replay records")
	}
	if len(state.Changes) <= s.limits.MaxChanges {
		return nil
	}
	candidates := changeIDsByAge(state, func(change *Change) bool {
		if change.ID == preserveID || changeHasActiveReplayRecord(state, change.ID) {
			return false
		}
		if changeReferencedAsRecoveryParent(state, change.ID) || changeSelectedAsRecoveryChild(state, change.ID) {
			return false
		}
		if change.ResourceKey != "" {
			if _, locked := state.ResourceLocks[change.ResourceKey]; locked {
				return false
			}
		}
		switch change.State {
		case StateRejected, StateRolledBack, StateSuperseded, StatePendingApproval:
			return true
		case StateCommitted:
			return !change.RollbackAvailable
		default:
			return false
		}
	})
	for len(state.Changes) > s.limits.MaxChanges && len(candidates) > 0 {
		delete(state.Changes, candidates[0])
		candidates = candidates[1:]
	}
	if len(state.Changes) > s.limits.MaxChanges {
		return errors.New("change state quota is exhausted by rollback or recovery records")
	}
	return nil
}

func changeReferencedAsRecoveryParent(state *persistedState, changeID string) bool {
	for _, child := range state.Changes {
		if child.RecoveryOfChangeID == changeID {
			return true
		}
	}
	return false
}

// changeSelectedAsRecoveryChild is the reverse edge of a durable resolution.
// Pruning either endpoint independently would leave a dangling chain that
// fails validation on restart. Closed recovery chains are retained as one
// audit object instead of relying on nondeterministic map iteration.
func changeSelectedAsRecoveryChild(state *persistedState, changeID string) bool {
	for _, parent := range state.Changes {
		if parent.Resolution != nil && parent.Resolution.ChildChangeID == changeID {
			return true
		}
	}
	return false
}

func changeHasActiveReplayRecord(state *persistedState, changeID string) bool {
	for _, record := range state.Requests {
		if record.Response.ChangeID == changeID {
			return true
		}
	}
	return false
}

func changeIDsByAge(state *persistedState, include func(*Change) bool) []string {
	ids := make([]string, 0)
	for id, change := range state.Changes {
		if include(change) {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		left, leftErr := time.Parse(time.RFC3339Nano, state.Changes[ids[i]].UpdatedAt)
		right, rightErr := time.Parse(time.RFC3339Nano, state.Changes[ids[j]].UpdatedAt)
		if leftErr != nil || rightErr != nil || left.Equal(right) {
			return ids[i] < ids[j]
		}
		return left.Before(right)
	})
	return ids
}

func recordExpired(expiresAt string, now time.Time) bool {
	expiry, err := time.Parse(time.RFC3339Nano, expiresAt)
	return err != nil || !now.Before(expiry)
}

func (s *Store) pruneVolatileLocked(now time.Time) {
	for requestID, record := range s.volatileRequests {
		if recordExpired(record.ExpiresAt, now) {
			delete(s.volatileRequests, requestID)
		}
	}
}

func cloneChange(change *Change) *Change {
	clone := *change
	if change.ApprovedByUID != nil {
		approvedByUID := *change.ApprovedByUID
		clone.ApprovedByUID = &approvedByUID
	}
	clone.Operation = append(json.RawMessage(nil), change.Operation...)
	clone.RollbackData = append(json.RawMessage(nil), change.RollbackData...)
	clone.BackupRefs = append([]string(nil), change.BackupRefs...)
	clone.PreconditionFields = append([]protocol.ApprovalPlanField(nil), change.PreconditionFields...)
	if change.Resolution != nil {
		resolution := *change.Resolution
		resolution.ParentTaskEvidence = append([]protocol.PVERecoveryTaskEvidence{}, change.Resolution.ParentTaskEvidence...)
		clone.Resolution = &resolution
	}
	return &clone
}

func normalizePVERecoveryResolutionEvidence(state *persistedState) {
	for _, change := range state.Changes {
		if change != nil && change.Resolution != nil && change.Resolution.ParentTaskEvidence == nil {
			change.Resolution.ParentTaskEvidence = []protocol.PVERecoveryTaskEvidence{}
		}
	}
}

func clonePersistedState(state persistedState) persistedState {
	clone := emptyPersistedState()
	for id, change := range state.Changes {
		clone.Changes[id] = cloneChange(change)
	}
	for id, record := range state.Requests {
		clone.Requests[id] = record
	}
	for nonce, record := range state.ApprovalNonces {
		clone.ApprovalNonces[nonce] = record
	}
	for key, owner := range state.ResourceLocks {
		clone.ResourceLocks[key] = owner
	}
	return clone
}

func (s *Store) commitStateLocked(candidate persistedState) error {
	if err := s.durabilityErrorLocked(); err != nil {
		return err
	}
	renamed, err := s.persistStateLocked(candidate)
	if renamed {
		// os.Rename is the runtime commit point. Once it succeeds, state.json is
		// the candidate and no caller may keep using or rewrite the predecessor,
		// even if the following directory fsync reports an error.
		s.state = candidate
	}
	if err == nil {
		return nil
	}
	if !renamed {
		return err
	}
	s.durabilityFailure = err
	return s.durabilityErrorLocked()
}

func (s *Store) durabilityErrorLocked() error {
	if s.durabilityFailure == nil {
		return nil
	}
	return fmt.Errorf("root-helper store durability is uncertain after state rename; restart and reopen the store before continuing: %w", s.durabilityFailure)
}

// DurabilityError reports the fail-stop condition caused by a post-rename
// directory durability failure. Callers must reopen the store before serving
// another broker request; there is intentionally no in-process reset method.
func (s *Store) DurabilityError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.durabilityErrorLocked()
}

func (s *Store) persistStateLocked(state persistedState) (bool, error) {
	payload, err := json.Marshal(state)
	if err != nil {
		return false, err
	}
	if len(payload) > s.limits.MaxStateBytes {
		return false, errors.New("root-helper state exceeds configured byte quota")
	}
	temporary, err := os.CreateTemp(s.dir, ".state-*.tmp")
	if err != nil {
		return false, err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return false, err
	}
	if s.persistFault != nil {
		if err := s.persistFault("write"); err != nil {
			temporary.Close()
			return false, err
		}
	}
	if _, err := temporary.Write(payload); err != nil {
		temporary.Close()
		return false, err
	}
	if s.persistFault != nil {
		if err := s.persistFault("file-sync"); err != nil {
			temporary.Close()
			return false, err
		}
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	if s.persistFault != nil {
		if err := s.persistFault("rename"); err != nil {
			return false, err
		}
	}
	if err := os.Rename(name, s.path); err != nil {
		return false, err
	}
	if s.persistFault != nil {
		if err := s.persistFault("directory-open"); err != nil {
			return true, err
		}
	}
	directory, err := os.Open(s.dir)
	if err != nil {
		return true, err
	}
	defer directory.Close()
	if s.persistFault != nil {
		if err := s.persistFault("directory-sync"); err != nil {
			return true, err
		}
	}
	if err := directory.Sync(); err != nil {
		return true, err
	}
	return true, nil
}

func timestamp(now time.Time) string { return now.UTC().Format(time.RFC3339Nano) }
