package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	MethodPVEClusterStatus Method = "pve.cluster.status"
	MethodPVENodeStatus    Method = "pve.node.status"
	MethodPVEStorageStatus Method = "pve.storage.status"
	MethodPVETaskStatus    Method = "pve.task.status"
	MethodPVEGuestStatus   Method = "pve.guest.status"

	// These two methods are an approver-only broker control flow. They are not
	// operations and are intentionally absent from every source workload and
	// provider interface.
	MethodPVERecoveryClearancePrepare Method = "pve.recovery.clearance.prepare"
	MethodPVERecoveryClearanceConfirm Method = "pve.recovery.clearance.confirm"
)

const (
	PVEMutationDispositionNotStarted    = "NO_MUTATION_STARTED"
	PVEMutationDispositionTasksTerminal = "TASKS_TERMINAL"
	PVEMutationDispositionUnknown       = "STARTED_OR_UNKNOWN"
)

type PVERecoveryTaskEvidence struct {
	Role       string `json:"role"`
	Node       string `json:"node"`
	UPID       string `json:"upid"`
	Status     string `json:"status"`
	ExitStatus string `json:"exitStatus"`
	ObservedAt string `json:"observedAt"`
}

func (e PVERecoveryTaskEvidence) Validate() error {
	if (e.Role != "safety-backup" && e.Role != "primary") || !ValidPVENode(e.Node) ||
		!ValidPVEUPIDForNode(e.UPID, e.Node) || e.Status != "stopped" ||
		e.ExitStatus == "" || len(e.ExitStatus) > 256 || strings.ContainsAny(e.ExitStatus, "\x00\r\n") {
		return errors.New("invalid PVE terminal task evidence")
	}
	if _, err := time.Parse(time.RFC3339Nano, e.ObservedAt); err != nil {
		return errors.New("invalid PVE terminal task evidence time")
	}
	return nil
}

type PVERecoveryResolution struct {
	Kind                       string                    `json:"kind"`
	Basis                      string                    `json:"basis,omitempty"`
	ParentChangeID             string                    `json:"parentChangeId,omitempty"`
	ChildChangeID              string                    `json:"childChangeId"`
	ChildPlanHash              string                    `json:"childPlanHash"`
	ResourceKey                string                    `json:"resourceKey,omitempty"`
	TransferredAt              string                    `json:"transferredAt"`
	ParentMutationDisposition  string                    `json:"parentMutationDisposition"`
	ParentTaskEvidence         []PVERecoveryTaskEvidence `json:"parentTaskEvidence"`
	ClearanceObservationDigest string                    `json:"clearanceObservationDigest,omitempty"`
	ActiveTaskDigest           string                    `json:"activeTaskDigest,omitempty"`
	GuestStateDigest           string                    `json:"guestStateDigest,omitempty"`
	ClusterStateDigest         string                    `json:"clusterStateDigest,omitempty"`
}

func (r PVERecoveryResolution) Validate() error {
	if r.Kind != "pve.recovery-transfer/v1" ||
		!strings.HasPrefix(r.ChildChangeID, "pve-change-") || !changeIDPattern.MatchString(r.ChildChangeID) ||
		!digestPattern.MatchString(r.ChildPlanHash) {
		return errors.New("invalid PVE recovery resolution identity")
	}
	// parentTaskEvidence is a required canonical JSON array. Go's json decoder
	// maps both a missing field and JSON null to a nil slice; rejecting nil here
	// keeps signed/status boundaries aligned with the TypeScript parser, while
	// still allowing an explicit [] for a proven no-task outcome.
	if r.ParentTaskEvidence == nil {
		return errors.New("PVE recovery resolution parentTaskEvidence must be a non-null array")
	}
	if _, err := time.Parse(time.RFC3339Nano, r.TransferredAt); err != nil {
		return errors.New("invalid PVE recovery resolution time")
	}
	if r.Basis == "local-unknown-clearance" {
		if !strings.HasPrefix(r.ParentChangeID, "pve-change-") || !changeIDPattern.MatchString(r.ParentChangeID) ||
			r.ParentChangeID == r.ChildChangeID ||
			!validPVEResourceKey(r.ResourceKey) || r.ParentMutationDisposition != PVEMutationDispositionUnknown ||
			len(r.ParentTaskEvidence) != 0 || !digestPattern.MatchString(r.ClearanceObservationDigest) ||
			!digestPattern.MatchString(r.ActiveTaskDigest) || !digestPattern.MatchString(r.GuestStateDigest) ||
			!digestPattern.MatchString(r.ClusterStateDigest) {
			return errors.New("invalid local PVE unknown-clearance recovery resolution")
		}
	} else {
		// Empty basis is retained for already persisted v1 terminal-proof
		// resolutions. New local unknown clearances must always be explicit.
		if r.Basis != "" || r.ParentChangeID != "" || r.ResourceKey != "" ||
			r.ClearanceObservationDigest != "" || r.ActiveTaskDigest != "" ||
			r.GuestStateDigest != "" || r.ClusterStateDigest != "" {
			return errors.New("invalid PVE recovery resolution basis")
		}
		if r.ParentMutationDisposition != PVEMutationDispositionNotStarted &&
			r.ParentMutationDisposition != PVEMutationDispositionTasksTerminal {
			return errors.New("invalid PVE recovery parent mutation disposition")
		}
		if (r.ParentMutationDisposition == PVEMutationDispositionNotStarted && len(r.ParentTaskEvidence) != 0) ||
			(r.ParentMutationDisposition == PVEMutationDispositionTasksTerminal && len(r.ParentTaskEvidence) == 0) {
			return errors.New("PVE recovery resolution task evidence does not match its mutation disposition")
		}
	}
	seenRoles := make(map[string]struct{}, len(r.ParentTaskEvidence))
	seenUPIDs := make(map[string]struct{}, len(r.ParentTaskEvidence))
	for _, evidence := range r.ParentTaskEvidence {
		if err := evidence.Validate(); err != nil {
			return err
		}
		if _, duplicate := seenRoles[evidence.Role]; duplicate {
			return errors.New("duplicate PVE recovery task evidence role")
		}
		if _, duplicate := seenUPIDs[evidence.UPID]; duplicate {
			return errors.New("duplicate PVE recovery task evidence UPID")
		}
		seenRoles[evidence.Role] = struct{}{}
		seenUPIDs[evidence.UPID] = struct{}{}
	}
	return nil
}

var (
	pveNodePattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	pveStoragePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	pveSnapshotPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	pveUPIDPattern     = regexp.MustCompile(`^UPID:[A-Za-z0-9][A-Za-z0-9._-]{0,63}:[A-Fa-f0-9]+:[A-Fa-f0-9]+:[A-Fa-f0-9]+:[A-Za-z0-9._-]+:[^/:]{0,128}:[^/:]{1,128}:$`)
	pveBackupVolume    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}:backup/vzdump-(qemu|lxc)-[1-9][0-9]{2,8}-[A-Za-z0-9_.:+-]+\.(vma|tar)(\.(zst|gz|lzo))?$`)
	pveClearanceID     = regexp.MustCompile(`^pve-clearance-[a-f0-9]{32}$`)
	pveResourceKey     = regexp.MustCompile(`^pve/vmid/[1-9][0-9]{2,8}$`)
)

const PVERecoveryClearanceAction = "local-unknown-clearance"

// PVERecoveryActiveTaskProbe records the exact node-local active-task query
// whose empty result is required before a lost-UPID recovery chain may move.
// ActiveCount is intentionally constrained to zero; a non-empty result is a
// denial, not approval evidence.
type PVERecoveryActiveTaskProbe struct {
	Node        string `json:"node"`
	VMID        int    `json:"vmid"`
	ActiveCount int    `json:"activeCount"`
}

type PVERecoveryGuestState struct {
	Node      string `json:"node"`
	GuestType string `json:"guestType"`
	VMID      int    `json:"vmid"`
	Status    string `json:"status"`
	Lock      string `json:"lock,omitempty"`
}

type PVERecoveryClusterState struct {
	Type    string `json:"type"`
	Name    string `json:"name,omitempty"`
	Node    string `json:"node,omitempty"`
	NodeID  int    `json:"nodeId"`
	Local   int    `json:"local"`
	Online  int    `json:"online"`
	Quorate int    `json:"quorate"`
}

// PVERecoveryClearanceObservation contains only bounded, typed state. The
// three component digests are independently rebound immediately before the
// atomic parent/child lock transfer.
type PVERecoveryClearanceObservation struct {
	GuestType          string                       `json:"guestType"`
	VMID               int                          `json:"vmid"`
	ActiveTaskProbes   []PVERecoveryActiveTaskProbe `json:"activeTaskProbes"`
	GuestStates        []PVERecoveryGuestState      `json:"guestStates"`
	ClusterStates      []PVERecoveryClusterState    `json:"clusterStates"`
	ActiveTaskDigest   string                       `json:"activeTaskDigest"`
	GuestStateDigest   string                       `json:"guestStateDigest"`
	ClusterStateDigest string                       `json:"clusterStateDigest"`
	ObservationDigest  string                       `json:"observationDigest"`
}

func NewPVERecoveryClearanceObservation(
	guestType string,
	vmid int,
	active []PVERecoveryActiveTaskProbe,
	guests []PVERecoveryGuestState,
	cluster []PVERecoveryClusterState,
) (PVERecoveryClearanceObservation, error) {
	result := PVERecoveryClearanceObservation{
		GuestType: guestType, VMID: vmid,
		ActiveTaskProbes: append([]PVERecoveryActiveTaskProbe(nil), active...),
		GuestStates:      append([]PVERecoveryGuestState(nil), guests...),
		ClusterStates:    append([]PVERecoveryClusterState(nil), cluster...),
	}
	sort.Slice(result.ActiveTaskProbes, func(i, j int) bool { return result.ActiveTaskProbes[i].Node < result.ActiveTaskProbes[j].Node })
	sort.Slice(result.GuestStates, func(i, j int) bool {
		if result.GuestStates[i].Node == result.GuestStates[j].Node {
			return result.GuestStates[i].GuestType < result.GuestStates[j].GuestType
		}
		return result.GuestStates[i].Node < result.GuestStates[j].Node
	})
	sort.Slice(result.ClusterStates, func(i, j int) bool {
		left, right := result.ClusterStates[i], result.ClusterStates[j]
		return left.Type+"\x00"+left.Node+"\x00"+left.Name < right.Type+"\x00"+right.Node+"\x00"+right.Name
	})
	if err := validatePVERecoveryObservationFields(result); err != nil {
		return PVERecoveryClearanceObservation{}, err
	}
	var err error
	result.ActiveTaskDigest, err = pveRecoveryDigest("active-tasks-v1", result.ActiveTaskProbes)
	if err != nil {
		return PVERecoveryClearanceObservation{}, err
	}
	result.GuestStateDigest, err = pveRecoveryDigest("guest-state-v1", struct {
		GuestType string                  `json:"guestType"`
		VMID      int                     `json:"vmid"`
		States    []PVERecoveryGuestState `json:"states"`
	}{result.GuestType, result.VMID, result.GuestStates})
	if err != nil {
		return PVERecoveryClearanceObservation{}, err
	}
	result.ClusterStateDigest, err = pveRecoveryDigest("cluster-state-v1", result.ClusterStates)
	if err != nil {
		return PVERecoveryClearanceObservation{}, err
	}
	result.ObservationDigest, err = pveRecoveryDigest("observation-v1", struct {
		Active  string `json:"active"`
		Guest   string `json:"guest"`
		Cluster string `json:"cluster"`
	}{result.ActiveTaskDigest, result.GuestStateDigest, result.ClusterStateDigest})
	if err != nil {
		return PVERecoveryClearanceObservation{}, err
	}
	return result, nil
}

func (o PVERecoveryClearanceObservation) Validate() error {
	rebuilt, err := NewPVERecoveryClearanceObservation(o.GuestType, o.VMID, o.ActiveTaskProbes, o.GuestStates, o.ClusterStates)
	if err != nil {
		return err
	}
	if rebuilt.ActiveTaskDigest != o.ActiveTaskDigest || rebuilt.GuestStateDigest != o.GuestStateDigest ||
		rebuilt.ClusterStateDigest != o.ClusterStateDigest || rebuilt.ObservationDigest != o.ObservationDigest {
		return errors.New("PVE recovery clearance observation digest mismatch")
	}
	return nil
}

func validatePVERecoveryObservationFields(o PVERecoveryClearanceObservation) error {
	if !ValidPVEGuestType(o.GuestType) || !ValidPVEVMID(o.VMID) || len(o.ActiveTaskProbes) == 0 || len(o.ActiveTaskProbes) > 2 || len(o.GuestStates) > 2 || len(o.ClusterStates) == 0 || len(o.ClusterStates) > 4 {
		return errors.New("invalid PVE recovery clearance observation bounds")
	}
	seenNodes := make(map[string]struct{}, len(o.ActiveTaskProbes))
	for _, probe := range o.ActiveTaskProbes {
		if !ValidPVENode(probe.Node) || probe.VMID != o.VMID || probe.ActiveCount != 0 {
			return errors.New("PVE recovery clearance requires an exact empty active-task query")
		}
		if _, exists := seenNodes[probe.Node]; exists {
			return errors.New("duplicate PVE active-task probe node")
		}
		seenNodes[probe.Node] = struct{}{}
	}
	seenGuests := make(map[string]struct{}, len(o.GuestStates))
	for _, guest := range o.GuestStates {
		if _, ok := seenNodes[guest.Node]; !ok || guest.GuestType != o.GuestType || guest.VMID != o.VMID ||
			(guest.Status != "running" && guest.Status != "stopped") || len(guest.Lock) > 128 || strings.ContainsAny(guest.Lock, "\x00\r\n") {
			return errors.New("invalid PVE recovery guest observation")
		}
		key := guest.Node + "\x00" + guest.GuestType
		if _, exists := seenGuests[key]; exists {
			return errors.New("duplicate PVE recovery guest observation")
		}
		seenGuests[key] = struct{}{}
	}
	seenCluster := false
	seenClusterNodes := make(map[string]struct{}, len(o.ClusterStates))
	for _, entry := range o.ClusterStates {
		if entry.Type != "cluster" && entry.Type != "node" {
			return errors.New("invalid PVE recovery cluster observation type")
		}
		if len(entry.Name) > 128 || len(entry.Node) > 64 || strings.ContainsAny(entry.Name+entry.Node, "\x00\r\n") ||
			(entry.Node != "" && !ValidPVENode(entry.Node)) || entry.NodeID < 0 || entry.Local < 0 || entry.Local > 1 || entry.Online < 0 || entry.Online > 1 || entry.Quorate < 0 || entry.Quorate > 1 {
			return errors.New("invalid PVE recovery cluster observation")
		}
		if entry.Type == "cluster" {
			if seenCluster {
				return errors.New("duplicate PVE recovery cluster identity")
			}
			seenCluster = true
			continue
		}
		node := entry.Node
		if node == "" {
			node = entry.Name
		}
		if !ValidPVENode(node) {
			return errors.New("invalid PVE recovery cluster node identity")
		}
		if _, duplicate := seenClusterNodes[node]; duplicate {
			return errors.New("duplicate PVE recovery cluster node identity")
		}
		seenClusterNodes[node] = struct{}{}
	}
	return nil
}

func pveRecoveryDigest(domain string, value interface{}) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.New()
	digest.Write([]byte("agentd-pve-recovery-" + domain + "\x00"))
	digest.Write(payload)
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

type PVERecoveryClearanceChallenge struct {
	Kind            string                          `json:"kind"`
	ClearanceID     string                          `json:"clearanceId"`
	ParentChangeID  string                          `json:"parentChangeId"`
	ChildChangeID   string                          `json:"childChangeId"`
	ChildPlanHash   string                          `json:"childPlanHash"`
	ResourceKey     string                          `json:"resourceKey"`
	Observation     PVERecoveryClearanceObservation `json:"observation"`
	IssuedAt        string                          `json:"issuedAt"`
	ExpiresAt       string                          `json:"expiresAt"`
	ChallengeDigest string                          `json:"challengeDigest"`
}

func (c PVERecoveryClearanceChallenge) Validate() error {
	if c.Kind != "pve.recovery-clearance-challenge/v1" || !pveClearanceID.MatchString(c.ClearanceID) ||
		!strings.HasPrefix(c.ParentChangeID, "pve-change-") || !changeIDPattern.MatchString(c.ParentChangeID) ||
		!strings.HasPrefix(c.ChildChangeID, "pve-change-") || !changeIDPattern.MatchString(c.ChildChangeID) ||
		!digestPattern.MatchString(c.ChildPlanHash) || !validPVEResourceKey(c.ResourceKey) || c.ParentChangeID == c.ChildChangeID {
		return errors.New("invalid PVE recovery clearance challenge identity")
	}
	if err := c.Observation.Validate(); err != nil {
		return err
	}
	issued, issuedErr := time.Parse(time.RFC3339Nano, c.IssuedAt)
	expires, expiresErr := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	if issuedErr != nil || expiresErr != nil || !expires.After(issued) || expires.Sub(issued) > 2*time.Minute {
		return errors.New("invalid PVE recovery clearance challenge window")
	}
	expected, err := c.digest()
	if err != nil || expected != c.ChallengeDigest {
		return errors.New("PVE recovery clearance challenge digest mismatch")
	}
	return nil
}

func (c PVERecoveryClearanceChallenge) digest() (string, error) {
	unsigned := struct {
		Kind, ClearanceID, ParentChangeID, ChildChangeID, ChildPlanHash, ResourceKey string
		Observation                                                                  PVERecoveryClearanceObservation
		IssuedAt, ExpiresAt                                                          string
	}{c.Kind, c.ClearanceID, c.ParentChangeID, c.ChildChangeID, c.ChildPlanHash, c.ResourceKey, c.Observation, c.IssuedAt, c.ExpiresAt}
	return pveRecoveryDigest("clearance-challenge-v1", unsigned)
}

func FinalizePVERecoveryClearanceChallenge(challenge PVERecoveryClearanceChallenge) (PVERecoveryClearanceChallenge, error) {
	challenge.ChallengeDigest = ""
	digest, err := challenge.digest()
	if err != nil {
		return PVERecoveryClearanceChallenge{}, err
	}
	challenge.ChallengeDigest = digest
	if err := challenge.Validate(); err != nil {
		return PVERecoveryClearanceChallenge{}, err
	}
	return challenge, nil
}

type PVERecoveryClearanceApproval struct {
	Version            int    `json:"version"`
	KeyID              string `json:"keyId"`
	Action             string `json:"action"`
	ServerID           string `json:"serverId"`
	MachineID          string `json:"machineId"`
	TargetID           string `json:"targetId"`
	ClearanceID        string `json:"clearanceId"`
	ParentChangeID     string `json:"parentChangeId"`
	ChildChangeID      string `json:"childChangeId"`
	ChildPlanHash      string `json:"childPlanHash"`
	ResourceKey        string `json:"resourceKey"`
	ChallengeDigest    string `json:"challengeDigest"`
	PolicyRevision     string `json:"policyRevision"`
	CapabilityRevision string `json:"capabilityRevision"`
	IssuedAt           string `json:"issuedAt"`
	ExpiresAt          string `json:"expiresAt"`
	Nonce              string `json:"nonce"`
	Signature          string `json:"signature"`
}

func (a PVERecoveryClearanceApproval) ApprovalPayload() ([]byte, error) {
	unsigned := struct {
		Version            int    `json:"version"`
		KeyID              string `json:"keyId"`
		Action             string `json:"action"`
		ServerID           string `json:"serverId"`
		MachineID          string `json:"machineId"`
		TargetID           string `json:"targetId"`
		ClearanceID        string `json:"clearanceId"`
		ParentChangeID     string `json:"parentChangeId"`
		ChildChangeID      string `json:"childChangeId"`
		ChildPlanHash      string `json:"childPlanHash"`
		ResourceKey        string `json:"resourceKey"`
		ChallengeDigest    string `json:"challengeDigest"`
		PolicyRevision     string `json:"policyRevision"`
		CapabilityRevision string `json:"capabilityRevision"`
		IssuedAt           string `json:"issuedAt"`
		ExpiresAt          string `json:"expiresAt"`
		Nonce              string `json:"nonce"`
	}{a.Version, a.KeyID, a.Action, a.ServerID, a.MachineID, a.TargetID, a.ClearanceID, a.ParentChangeID, a.ChildChangeID, a.ChildPlanHash, a.ResourceKey, a.ChallengeDigest, a.PolicyRevision, a.CapabilityRevision, a.IssuedAt, a.ExpiresAt, a.Nonce}
	return json.Marshal(unsigned)
}

func (a PVERecoveryClearanceApproval) ValidateShape() error {
	if a.Version != Version || !approvalKeyIDPattern.MatchString(a.KeyID) || a.Action != PVERecoveryClearanceAction ||
		!identityPattern.MatchString(a.ServerID) || !identityPattern.MatchString(a.MachineID) || !identityPattern.MatchString(a.TargetID) ||
		!pveClearanceID.MatchString(a.ClearanceID) || !strings.HasPrefix(a.ParentChangeID, "pve-change-") || !changeIDPattern.MatchString(a.ParentChangeID) ||
		!strings.HasPrefix(a.ChildChangeID, "pve-change-") || !changeIDPattern.MatchString(a.ChildChangeID) || !digestPattern.MatchString(a.ChildPlanHash) ||
		!validPVEResourceKey(a.ResourceKey) || !digestPattern.MatchString(a.ChallengeDigest) || !identityPattern.MatchString(a.PolicyRevision) ||
		!identityPattern.MatchString(a.CapabilityRevision) || !noncePattern.MatchString(a.Nonce) || len(a.Signature) < 80 || len(a.Signature) > 160 {
		return errors.New("invalid PVE recovery clearance approval")
	}
	issued, issuedErr := time.Parse(time.RFC3339Nano, a.IssuedAt)
	expires, expiresErr := time.Parse(time.RFC3339Nano, a.ExpiresAt)
	if issuedErr != nil || expiresErr != nil || !expires.After(issued) || expires.Sub(issued) > 2*time.Minute {
		return errors.New("invalid PVE recovery clearance approval window")
	}
	return nil
}

type PVERecoveryClearancePrepareResult struct {
	Kind      string                         `json:"kind"`
	Required  bool                           `json:"required"`
	Challenge *PVERecoveryClearanceChallenge `json:"challenge,omitempty"`
}

type PVERecoveryClearanceGrant struct {
	Kind            string `json:"kind"`
	ClearanceToken  string `json:"clearanceToken"`
	ChallengeDigest string `json:"challengeDigest"`
	ExpiresAt       string `json:"expiresAt"`
}

func ValidPVERecoveryClearanceToken(value string) bool { return pveClearanceID.MatchString(value) }
func validPVEResourceKey(value string) bool            { return pveResourceKey.MatchString(value) }

func ValidPVENode(value string) bool    { return pveNodePattern.MatchString(value) }
func ValidPVEStorage(value string) bool { return pveStoragePattern.MatchString(value) }
func ValidPVEGuestType(value string) bool {
	return value == "qemu" || value == "lxc"
}
func ValidPVEVMID(value int) bool                { return value >= 100 && value <= 999999999 }
func ValidPVEUPIDForNode(upid, node string) bool { return validPVEUPID(upid, node) }

// IsPVERequest is the single routing predicate used by the network server to
// keep PVE work on its dedicated privileged broker. Change references use a
// separate prefix so status and approval actions cannot be misrouted after the
// original operation body is no longer present in the HTTP request.
func IsPVERequest(request Request) bool {
	switch request.Method {
	case MethodPVEClusterStatus, MethodPVENodeStatus, MethodPVEStorageStatus, MethodPVETaskStatus, MethodPVEGuestStatus:
		return true
	case MethodChangePrepare:
		return IsPVEOperation(request.Operation)
	case MethodChangeStatus, MethodChangeApprove, MethodChangeReject, MethodChangeRollback:
		return strings.HasPrefix(request.ChangeID, "pve-change-")
	case MethodPVERecoveryClearancePrepare, MethodPVERecoveryClearanceConfirm:
		return strings.HasPrefix(request.ChangeID, "pve-change-")
	default:
		return false
	}
}

func IsPVEOperation(operation Operation) bool {
	switch operation.(type) {
	case *PVEGuestAction, *PVESnapshotCreate, *PVESnapshotDelete, *PVESnapshotRollback,
		*PVEGuestBackup, *PVEGuestRestore, *PVEGuestMigrate:
		return true
	default:
		return false
	}
}

// PVERecoveryOfChangeID returns the optional, canonical-plan-bound parent of a
// typed PVE recovery change. An empty value denotes an ordinary change. The
// root broker is authoritative for validating the referenced durable state;
// this helper deliberately does not turn the reference into authorization.
func PVERecoveryOfChangeID(operation Operation) string {
	switch value := operation.(type) {
	case *PVEGuestAction:
		return value.RecoveryOfChangeID
	case *PVESnapshotCreate:
		return value.RecoveryOfChangeID
	case *PVESnapshotDelete:
		return value.RecoveryOfChangeID
	case *PVESnapshotRollback:
		return value.RecoveryOfChangeID
	case *PVEGuestBackup:
		return value.RecoveryOfChangeID
	case *PVEGuestRestore:
		return value.RecoveryOfChangeID
	case *PVEGuestMigrate:
		return value.RecoveryOfChangeID
	default:
		return ""
	}
}

// PVEInspection carries only the fields selected by the inspection method's
// tagged-union arm. It never accepts a raw API path or pvesh argument list.
type PVEInspection struct {
	PluginID     string
	PluginDigest string
	Node         string
	Storage      string
	GuestType    string
	VMID         int
	UPID         string
}

func parsePVEInspection(payload []byte, method Method) (PVEInspection, error) {
	var result PVEInspection
	switch method {
	case MethodPVEClusterStatus:
		var wire struct {
			wireBase
			PluginID     string `json:"pluginId"`
			PluginDigest string `json:"pluginDigest"`
		}
		if err := strictDecode(payload, &wire); err != nil {
			return result, err
		}
		result.PluginID, result.PluginDigest = wire.PluginID, wire.PluginDigest
	case MethodPVENodeStatus:
		var wire struct {
			wireBase
			PluginID     string `json:"pluginId"`
			PluginDigest string `json:"pluginDigest"`
			Node         string `json:"node"`
		}
		if err := strictDecode(payload, &wire); err != nil {
			return result, err
		}
		if !ValidPVENode(wire.Node) {
			return result, errors.New("invalid PVE node")
		}
		result.PluginID, result.PluginDigest, result.Node = wire.PluginID, wire.PluginDigest, wire.Node
	case MethodPVEStorageStatus:
		var wire struct {
			wireBase
			PluginID     string `json:"pluginId"`
			PluginDigest string `json:"pluginDigest"`
			Node         string `json:"node"`
			Storage      string `json:"storage"`
		}
		if err := strictDecode(payload, &wire); err != nil {
			return result, err
		}
		if !ValidPVENode(wire.Node) || !ValidPVEStorage(wire.Storage) {
			return result, errors.New("invalid PVE node or storage")
		}
		result.PluginID, result.PluginDigest, result.Node, result.Storage = wire.PluginID, wire.PluginDigest, wire.Node, wire.Storage
	case MethodPVETaskStatus:
		var wire struct {
			wireBase
			PluginID     string `json:"pluginId"`
			PluginDigest string `json:"pluginDigest"`
			Node         string `json:"node"`
			UPID         string `json:"upid"`
		}
		if err := strictDecode(payload, &wire); err != nil {
			return result, err
		}
		if !ValidPVENode(wire.Node) || !validPVEUPID(wire.UPID, wire.Node) {
			return result, errors.New("invalid PVE node or task UPID")
		}
		result.PluginID, result.PluginDigest, result.Node, result.UPID = wire.PluginID, wire.PluginDigest, wire.Node, wire.UPID
	case MethodPVEGuestStatus:
		var wire struct {
			wireBase
			PluginID     string `json:"pluginId"`
			PluginDigest string `json:"pluginDigest"`
			Node         string `json:"node"`
			GuestType    string `json:"guestType"`
			VMID         int    `json:"vmid"`
		}
		if err := strictDecode(payload, &wire); err != nil {
			return result, err
		}
		if !ValidPVENode(wire.Node) || !ValidPVEGuestType(wire.GuestType) || !ValidPVEVMID(wire.VMID) {
			return result, errors.New("invalid PVE guest reference")
		}
		result.PluginID, result.PluginDigest, result.Node, result.GuestType, result.VMID = wire.PluginID, wire.PluginDigest, wire.Node, wire.GuestType, wire.VMID
	default:
		return result, errors.New("unsupported PVE inspection method")
	}
	if !validPVEPlugin(result.PluginID, result.PluginDigest) {
		return result, errors.New("PVE inspection is not bound to an approved workload digest")
	}
	return result, nil
}

func validPVEUPID(upid, node string) bool {
	return len(upid) <= 512 && pveUPIDPattern.MatchString(upid) && strings.HasPrefix(upid, "UPID:"+node+":")
}

type PVEGuestAction struct {
	OperationKind      string `json:"kind"`
	PluginID           string `json:"pluginId"`
	PluginDigest       string `json:"pluginDigest"`
	RecoveryOfChangeID string `json:"recoveryOfChangeId,omitempty"`
	Node               string `json:"node"`
	GuestType          string `json:"guestType"`
	VMID               int    `json:"vmid"`
	Action             string `json:"action"`
}

func (o PVEGuestAction) Kind() string { return "pve.guest.action" }
func (o PVEGuestAction) Summary() string {
	return fmt.Sprintf("PVE %s guest %s/%d on node %s", o.Action, o.GuestType, o.VMID, o.Node)
}
func (o PVEGuestAction) Validate() error {
	if o.OperationKind != o.Kind() || !validPVEPlugin(o.PluginID, o.PluginDigest) || !validPVERecoveryParent(o.RecoveryOfChangeID) || !validPVEGuest(o.Node, o.GuestType, o.VMID) {
		return errors.New("invalid pve.guest.action operation")
	}
	switch o.Action {
	case "start", "shutdown", "stop", "reboot":
		return nil
	default:
		return errors.New("invalid PVE guest action")
	}
}

type PVESnapshotCreate struct {
	OperationKind      string `json:"kind"`
	PluginID           string `json:"pluginId"`
	PluginDigest       string `json:"pluginDigest"`
	RecoveryOfChangeID string `json:"recoveryOfChangeId,omitempty"`
	Node               string `json:"node"`
	GuestType          string `json:"guestType"`
	VMID               int    `json:"vmid"`
	Snapshot           string `json:"snapshot"`
	Description        string `json:"description,omitempty"`
}

func (o PVESnapshotCreate) Kind() string { return "pve.snapshot.create" }
func (o PVESnapshotCreate) Summary() string {
	return fmt.Sprintf("create PVE snapshot %s for %s/%d on node %s", o.Snapshot, o.GuestType, o.VMID, o.Node)
}
func (o PVESnapshotCreate) Validate() error {
	if o.OperationKind != o.Kind() || !validPVEPlugin(o.PluginID, o.PluginDigest) || !validPVERecoveryParent(o.RecoveryOfChangeID) || !validPVEGuest(o.Node, o.GuestType, o.VMID) || !validPVESnapshot(o.Snapshot) || !boundedPVEText(o.Description, 1024) {
		return errors.New("invalid pve.snapshot.create operation")
	}
	return nil
}

type PVESnapshotDelete struct {
	OperationKind      string `json:"kind"`
	PluginID           string `json:"pluginId"`
	PluginDigest       string `json:"pluginDigest"`
	RecoveryOfChangeID string `json:"recoveryOfChangeId,omitempty"`
	Node               string `json:"node"`
	GuestType          string `json:"guestType"`
	VMID               int    `json:"vmid"`
	Snapshot           string `json:"snapshot"`
	BackupStorage      string `json:"backupStorage"`
}

func (o PVESnapshotDelete) Kind() string { return "pve.snapshot.delete" }
func (o PVESnapshotDelete) Summary() string {
	return fmt.Sprintf("delete PVE snapshot %s for %s/%d on node %s after backup", o.Snapshot, o.GuestType, o.VMID, o.Node)
}
func (o PVESnapshotDelete) Validate() error {
	if o.OperationKind != o.Kind() || !validPVEPlugin(o.PluginID, o.PluginDigest) || !validPVERecoveryParent(o.RecoveryOfChangeID) || !validPVEGuest(o.Node, o.GuestType, o.VMID) || !validPVESnapshot(o.Snapshot) || !ValidPVEStorage(o.BackupStorage) {
		return errors.New("invalid pve.snapshot.delete operation")
	}
	return nil
}

type PVESnapshotRollback struct {
	OperationKind      string `json:"kind"`
	PluginID           string `json:"pluginId"`
	PluginDigest       string `json:"pluginDigest"`
	RecoveryOfChangeID string `json:"recoveryOfChangeId,omitempty"`
	Node               string `json:"node"`
	GuestType          string `json:"guestType"`
	VMID               int    `json:"vmid"`
	Snapshot           string `json:"snapshot"`
	BackupStorage      string `json:"backupStorage"`
}

func (o PVESnapshotRollback) Kind() string { return "pve.snapshot.rollback" }
func (o PVESnapshotRollback) Summary() string {
	return fmt.Sprintf("roll back PVE guest %s/%d on node %s to snapshot %s after backup", o.GuestType, o.VMID, o.Node, o.Snapshot)
}
func (o PVESnapshotRollback) Validate() error {
	if o.OperationKind != o.Kind() || !validPVEPlugin(o.PluginID, o.PluginDigest) || !validPVERecoveryParent(o.RecoveryOfChangeID) || !validPVEGuest(o.Node, o.GuestType, o.VMID) || !validPVESnapshot(o.Snapshot) || !ValidPVEStorage(o.BackupStorage) {
		return errors.New("invalid pve.snapshot.rollback operation")
	}
	return nil
}

type PVEGuestBackup struct {
	OperationKind      string `json:"kind"`
	PluginID           string `json:"pluginId"`
	PluginDigest       string `json:"pluginDigest"`
	RecoveryOfChangeID string `json:"recoveryOfChangeId,omitempty"`
	Node               string `json:"node"`
	GuestType          string `json:"guestType"`
	VMID               int    `json:"vmid"`
	Storage            string `json:"storage"`
}

func (o PVEGuestBackup) Kind() string { return "pve.guest.backup" }
func (o PVEGuestBackup) Summary() string {
	return fmt.Sprintf("back up PVE guest %s/%d on node %s to storage %s", o.GuestType, o.VMID, o.Node, o.Storage)
}
func (o PVEGuestBackup) Validate() error {
	if o.OperationKind != o.Kind() || !validPVEPlugin(o.PluginID, o.PluginDigest) || !validPVERecoveryParent(o.RecoveryOfChangeID) || !validPVEGuest(o.Node, o.GuestType, o.VMID) || !ValidPVEStorage(o.Storage) {
		return errors.New("invalid pve.guest.backup operation")
	}
	return nil
}

type PVEGuestRestore struct {
	OperationKind      string `json:"kind"`
	PluginID           string `json:"pluginId"`
	PluginDigest       string `json:"pluginDigest"`
	RecoveryOfChangeID string `json:"recoveryOfChangeId,omitempty"`
	Node               string `json:"node"`
	GuestType          string `json:"guestType"`
	VMID               int    `json:"vmid"`
	BackupVolume       string `json:"backupVolume"`
	Storage            string `json:"storage"`
}

func (o PVEGuestRestore) Kind() string { return "pve.guest.restore" }
func (o PVEGuestRestore) Summary() string {
	return fmt.Sprintf("restore new PVE guest %s/%d on node %s from a pinned backup volume", o.GuestType, o.VMID, o.Node)
}
func (o PVEGuestRestore) Validate() error {
	if o.OperationKind != o.Kind() || !validPVEPlugin(o.PluginID, o.PluginDigest) || !validPVERecoveryParent(o.RecoveryOfChangeID) || !validPVEGuest(o.Node, o.GuestType, o.VMID) || !ValidPVEStorage(o.Storage) || !validPVEBackupVolume(o.BackupVolume, o.GuestType, o.VMID) {
		return errors.New("invalid pve.guest.restore operation")
	}
	return nil
}

type PVEGuestMigrate struct {
	OperationKind      string `json:"kind"`
	PluginID           string `json:"pluginId"`
	PluginDigest       string `json:"pluginDigest"`
	RecoveryOfChangeID string `json:"recoveryOfChangeId,omitempty"`
	Node               string `json:"node"`
	GuestType          string `json:"guestType"`
	VMID               int    `json:"vmid"`
	TargetNode         string `json:"targetNode"`
	Online             bool   `json:"online"`
	Restart            bool   `json:"restart"`
	WithLocalDisks     bool   `json:"withLocalDisks"`
}

func (o PVEGuestMigrate) Kind() string { return "pve.guest.migrate" }
func (o PVEGuestMigrate) Summary() string {
	return fmt.Sprintf("migrate PVE guest %s/%d from node %s to node %s", o.GuestType, o.VMID, o.Node, o.TargetNode)
}
func (o PVEGuestMigrate) Validate() error {
	if o.OperationKind != o.Kind() || !validPVEPlugin(o.PluginID, o.PluginDigest) || !validPVERecoveryParent(o.RecoveryOfChangeID) || !validPVEGuest(o.Node, o.GuestType, o.VMID) || !ValidPVENode(o.TargetNode) || o.TargetNode == o.Node {
		return errors.New("invalid pve.guest.migrate operation")
	}
	if o.GuestType == "qemu" && o.Restart {
		return errors.New("QEMU migration does not accept the LXC restart flag")
	}
	if o.GuestType == "lxc" && (o.Online || o.WithLocalDisks) {
		return errors.New("LXC migration does not accept QEMU online or local-disk flags")
	}
	return nil
}

func validPVEPlugin(id, digest string) bool {
	return ValidWorkloadPluginID(id) && digestPattern.MatchString(digest)
}

func validPVERecoveryParent(value string) bool {
	return value == "" || (strings.HasPrefix(value, "pve-change-") && changeIDPattern.MatchString(value))
}

func validPVEGuest(node, guestType string, vmid int) bool {
	return ValidPVENode(node) && ValidPVEGuestType(guestType) && ValidPVEVMID(vmid)
}

func validPVESnapshot(value string) bool {
	return value != "current" && pveSnapshotPattern.MatchString(value)
}

func boundedPVEText(value string, maximum int) bool {
	if len(value) > maximum {
		return false
	}
	return !strings.HasPrefix(value, "-") && !strings.ContainsAny(value, "\x00\r\n")
}

func validPVEBackupVolume(value, guestType string, vmid int) bool {
	if len(value) > 256 || !pveBackupVolume.MatchString(value) {
		return false
	}
	marker := fmt.Sprintf("/vzdump-%s-%d-", guestType, vmid)
	return strings.Contains(value, marker)
}
