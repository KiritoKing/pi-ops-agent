package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

const testPVEPluginID = "workload.pve"

func TestPVEInspectionTaggedUnionIsStrictAndNodeBound(t *testing.T) {
	now := time.Date(2026, 8, 8, 2, 0, 0, 0, time.UTC)
	deadline := now.Add(time.Minute).Format(time.RFC3339Nano)
	digest := "sha256:" + strings.Repeat("a", 64)
	upid := "UPID:pve1:00000001:00000002:00000003:vzdump:100:root@pam:"
	payload := fmt.Sprintf(`{"version":1,"requestId":"request-pve-task-1","deadline":%q,"method":"pve.task.status","pluginId":"workload.example-pve","pluginDigest":%q,"node":"pve1","upid":%q}`, deadline, digest, upid)
	request, err := ParseRequest([]byte(payload), now)
	if err != nil {
		t.Fatal(err)
	}
	if request.Method != MethodPVETaskStatus || request.PVE.Node != "pve1" || request.PVE.UPID != upid {
		t.Fatalf("unexpected PVE task request: %#v", request)
	}
	for _, invalid := range []string{
		strings.Replace(payload, `"node":"pve1"`, `"node":"pve2"`, 1),
		strings.Replace(payload, `"pluginId":"workload.example-pve",`, "", 1),
		strings.Replace(payload, `"workload.example-pve"`, `"adapter.example-pve"`, 1),
		strings.Replace(payload, `"workload.example-pve"`, `"workload.Example-pve"`, 1),
		strings.Replace(payload, `"upid":`, `"argv":["get","/nodes"],"upid":`, 1),
		fmt.Sprintf(`{"version":1,"requestId":"request-pve-cluster","deadline":%q,"method":"pve.cluster.status","pluginId":"workload.example-pve","pluginDigest":%q,"node":"pve1"}`, deadline, digest),
	} {
		if _, err := ParseRequest([]byte(invalid), now); err == nil {
			t.Fatalf("unsafe PVE inspection was accepted: %s", invalid)
		}
	}
}

func TestPVEOperationsRejectRawArgumentsAndUnsafeRestoreOrMigration(t *testing.T) {
	now := time.Date(2026, 8, 8, 2, 0, 0, 0, time.UTC)
	deadline := now.Add(time.Minute).Format(time.RFC3339Nano)
	digest := "sha256:" + strings.Repeat("a", 64)
	valid := fmt.Sprintf(`{"version":1,"requestId":"request-pve-restore","deadline":%q,"method":"change.prepare","operation":{"kind":"pve.guest.restore","pluginId":"workload.example-pve","pluginDigest":%q,"node":"pve1","guestType":"qemu","vmid":100,"backupVolume":"local:backup/vzdump-qemu-100-2026_08_08-00_00_00.vma.zst","storage":"local-lvm"}}`, deadline, digest)
	request, err := ParseRequest([]byte(valid), now)
	if err != nil {
		t.Fatal(err)
	}
	if operation, ok := request.Operation.(*PVEGuestRestore); !ok || operation.PluginDigest != digest {
		t.Fatalf("unexpected PVE restore operation: %#v", request.Operation)
	}

	invalid := []string{
		strings.Replace(valid, `"node":"pve1"`, `"argv":["--force"],"node":"pve1"`, 1),
		strings.Replace(valid, `"workload.example-pve"`, `"adapter.example-pve"`, 1),
		strings.Replace(valid, `"workload.example-pve"`, `"workload.example-pve-"`, 1),
		strings.Replace(valid, "vzdump-qemu-100-", "vzdump-qemu-101-", 1),
		strings.Replace(valid, `"backupVolume":"local:backup/`, `"backupVolume":"local:../../`, 1),
		fmt.Sprintf(`{"version":1,"requestId":"request-pve-migrate","deadline":%q,"method":"change.prepare","operation":{"kind":"pve.guest.migrate","pluginId":"workload.example-pve","pluginDigest":%q,"node":"pve1","guestType":"lxc","vmid":101,"targetNode":"pve2","online":true,"restart":false,"withLocalDisks":false}}`, deadline, digest),
	}
	for _, payload := range invalid {
		if _, err := ParseRequest([]byte(payload), now); err == nil {
			t.Fatalf("unsafe PVE operation was accepted: %s", payload)
		}
	}
}

func TestPVECustomWorkloadIdentityIsCanonicalPlanBound(t *testing.T) {
	digest := "sha256:" + strings.Repeat("c", 64)
	operation := &PVEGuestAction{
		OperationKind: "pve.guest.action", PluginID: "workload.example-pve",
		PluginDigest: digest, Node: "pve1", GuestType: "qemu", VMID: 100, Action: "start",
	}
	plan, err := BuildApprovalPlan(operation, "policy-12345678", CapabilityRevision)
	if err != nil {
		t.Fatal(err)
	}
	if plan.PluginDigest != digest || plan.Steps[0].Fields[0] != (ApprovalPlanField{Name: "pluginId", Value: "workload.example-pve"}) {
		t.Fatalf("custom PVE workload identity was omitted from approval plan: %#v", plan)
	}
	other := *operation
	other.PluginID = testPVEPluginID
	otherPlan, err := BuildApprovalPlan(&other, "policy-12345678", CapabilityRevision)
	if err != nil {
		t.Fatal(err)
	}
	if otherPlan.PlanHash == plan.PlanHash {
		t.Fatal("PVE workload identity did not change the canonical plan hash")
	}
}

func TestPVERecoveryParentIsStrictAndPVEChangeBound(t *testing.T) {
	now := time.Date(2026, 8, 8, 3, 0, 0, 0, time.UTC)
	deadline := now.Add(time.Minute).Format(time.RFC3339Nano)
	digest := "sha256:" + strings.Repeat("a", 64)
	parent := "pve-change-0123456789abcdef0123456789abcdef"
	valid := fmt.Sprintf(`{"version":1,"requestId":"request-pve-recovery","deadline":%q,"method":"change.prepare","operation":{"kind":"pve.guest.action","pluginId":"workload.pve","pluginDigest":%q,"recoveryOfChangeId":%q,"node":"pve1","guestType":"qemu","vmid":100,"action":"start"}}`, deadline, digest, parent)
	request, err := ParseRequest([]byte(valid), now)
	if err != nil {
		t.Fatal(err)
	}
	if PVERecoveryOfChangeID(request.Operation) != parent {
		t.Fatalf("recovery parent was not preserved: %#v", request.Operation)
	}
	for _, invalid := range []string{
		strings.Replace(valid, parent, "change-0123456789abcdef0123456789abcdef", 1),
		strings.Replace(valid, parent, "pve-change-"+strings.Repeat("a", 151), 1),
		strings.Replace(valid, `"recoveryOfChangeId":`, `"recoveryOfChangeId":123,"duplicate":`, 1),
	} {
		if _, err := ParseRequest([]byte(invalid), now); err == nil {
			t.Fatalf("invalid PVE recovery parent was accepted: %s", invalid)
		}
	}
}

func TestPVERecoveryResolutionRequiresBoundTerminalEvidence(t *testing.T) {
	upid := "UPID:pve1:00000001:00000002:00000003:qmstart:100:root@pam:"
	resolution := PVERecoveryResolution{
		Kind:                      "pve.recovery-transfer/v1",
		ChildChangeID:             "pve-change-0123456789abcdef0123456789abcdef",
		ChildPlanHash:             "sha256:" + strings.Repeat("a", 64),
		TransferredAt:             "2026-08-08T03:00:00Z",
		ParentMutationDisposition: PVEMutationDispositionTasksTerminal,
		ParentTaskEvidence: []PVERecoveryTaskEvidence{{
			Role: "primary", Node: "pve1", UPID: upid, Status: "stopped",
			ExitStatus: "ERROR", ObservedAt: "2026-08-08T03:00:00Z",
		}},
	}
	if err := resolution.Validate(); err != nil {
		t.Fatal(err)
	}
	resolution.ParentTaskEvidence = nil
	if err := resolution.Validate(); err == nil {
		t.Fatal("terminal recovery resolution without task evidence was accepted")
	}
	resolution.ParentMutationDisposition = PVEMutationDispositionNotStarted
	if err := resolution.Validate(); err == nil || !strings.Contains(err.Error(), "non-null array") {
		t.Fatalf("nil no-mutation task evidence was accepted across the JSON boundary: %v", err)
	}
	resolution.ParentTaskEvidence = []PVERecoveryTaskEvidence{}
	if err := resolution.Validate(); err != nil {
		t.Fatalf("known no-mutation recovery resolution was rejected: %v", err)
	}
}

func TestPVEUnknownClearanceObservationAndResolutionAreDigestBound(t *testing.T) {
	observation, err := NewPVERecoveryClearanceObservation(
		"qemu", 100,
		[]PVERecoveryActiveTaskProbe{{Node: "pve1", VMID: 100, ActiveCount: 0}},
		[]PVERecoveryGuestState{{Node: "pve1", GuestType: "qemu", VMID: 100, Status: "stopped"}},
		[]PVERecoveryClusterState{{Type: "node", Name: "pve1", Node: "pve1", NodeID: 0, Local: 1, Online: 1}},
	)
	if err != nil || observation.Validate() != nil {
		t.Fatalf("valid PVE unknown-clearance observation failed: %#v err=%v", observation, err)
	}
	tampered := observation
	tampered.GuestStates = append([]PVERecoveryGuestState(nil), observation.GuestStates...)
	tampered.GuestStates[0].Status = "running"
	if err := tampered.Validate(); err == nil {
		t.Fatal("PVE clearance guest-state tampering preserved the old digest")
	}
	active := append([]PVERecoveryActiveTaskProbe{}, observation.ActiveTaskProbes...)
	active[0].ActiveCount = 1
	if _, err := NewPVERecoveryClearanceObservation("qemu", 100, active, observation.GuestStates, observation.ClusterStates); err == nil {
		t.Fatal("non-empty active-task result was representable as clearance evidence")
	}
	duplicateCluster := append([]PVERecoveryClusterState{}, observation.ClusterStates...)
	duplicateCluster = append(duplicateCluster,
		PVERecoveryClusterState{Type: "cluster", Name: "cluster1", Quorate: 1},
		PVERecoveryClusterState{Type: "cluster", Name: "other", Quorate: 1},
	)
	if _, err := NewPVERecoveryClearanceObservation("qemu", 100, observation.ActiveTaskProbes, observation.GuestStates, duplicateCluster); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate cluster identity was accepted: %v", err)
	}
	duplicateNode := append([]PVERecoveryClusterState{}, observation.ClusterStates...)
	duplicateNode = append(duplicateNode, PVERecoveryClusterState{Type: "node", Name: "pve1", Node: "pve1", NodeID: 0, Local: 1, Online: 0})
	if _, err := NewPVERecoveryClearanceObservation("qemu", 100, observation.ActiveTaskProbes, observation.GuestStates, duplicateNode); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("conflicting duplicate node identity was accepted: %v", err)
	}

	resolution := PVERecoveryResolution{
		Kind: "pve.recovery-transfer/v1", Basis: "local-unknown-clearance",
		ParentChangeID: "pve-change-parent-12345678", ChildChangeID: "pve-change-child-123456789",
		ChildPlanHash: "sha256:" + strings.Repeat("a", 64), ResourceKey: "pve/vmid/100",
		TransferredAt: "2026-08-08T03:00:00Z", ParentMutationDisposition: PVEMutationDispositionUnknown,
		ParentTaskEvidence: []PVERecoveryTaskEvidence{}, ClearanceObservationDigest: observation.ObservationDigest,
		ActiveTaskDigest: observation.ActiveTaskDigest, GuestStateDigest: observation.GuestStateDigest,
		ClusterStateDigest: observation.ClusterStateDigest,
	}
	if err := resolution.Validate(); err != nil {
		t.Fatal(err)
	}
	resolution.ParentTaskEvidence = nil
	if err := resolution.Validate(); err == nil || !strings.Contains(err.Error(), "non-null array") {
		t.Fatalf("local unknown-clearance accepted null task evidence: %v", err)
	}
	resolution.ParentTaskEvidence = []PVERecoveryTaskEvidence{}
	parentID := resolution.ParentChangeID
	resolution.ParentChangeID = resolution.ChildChangeID
	if err := resolution.Validate(); err == nil {
		t.Fatal("PVE unknown-clearance resolution accepted the child as its own parent")
	}
	resolution.ParentChangeID = parentID
	resolution.Basis = "first-party-override"
	if err := resolution.Validate(); err == nil {
		t.Fatal("unknown PVE recovery resolution basis was accepted")
	}
	resolution.Basis = ""
	if err := resolution.Validate(); err == nil {
		t.Fatal("STARTED_OR_UNKNOWN resolution was accepted without explicit local clearance basis")
	}
}

func TestPVEUnknownClearanceCrossBoundaryFixture(t *testing.T) {
	payload, err := os.ReadFile("../../test/fixtures/pve-local-unknown-clearance-resolution.json")
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var resolution PVERecoveryResolution
	if err := decoder.Decode(&resolution); err != nil {
		t.Fatalf("shared Go/TypeScript PVE clearance fixture did not decode strictly: %v", err)
	}
	if err := resolution.Validate(); err != nil {
		t.Fatalf("shared Go/TypeScript PVE clearance fixture is invalid: %v", err)
	}
	if resolution.Basis != "local-unknown-clearance" ||
		resolution.ParentChangeID != "pve-change-0123456789abcdef0123456789abcdef" ||
		resolution.ResourceKey != "pve/vmid/100" {
		t.Fatalf("shared fixture lost exact clearance bindings: %#v", resolution)
	}
}

func TestPVERecoveryClearanceControlMessagesAreStrictAndApproverBound(t *testing.T) {
	now := time.Date(2026, 8, 8, 4, 0, 0, 0, time.UTC)
	deadline := now.Add(time.Minute).Format(time.RFC3339Nano)
	prepare := fmt.Sprintf(`{"version":1,"requestId":"clearance-prepare-request","deadline":%q,"method":"pve.recovery.clearance.prepare","serverId":"server-12345678","machineId":"machine-12345678","targetId":"target-pve-root","policyRevision":"policy-pve-12345678","capabilityRevision":%q,"callerRole":"approver","changeId":"pve-change-child-123456789"}`, deadline, CapabilityRevision)
	request, err := ParseRequest([]byte(prepare), now)
	if err != nil || request.Method != MethodPVERecoveryClearancePrepare || request.ChangeID != "pve-change-child-123456789" {
		t.Fatalf("strict clearance prepare did not parse: request=%#v err=%v", request, err)
	}
	if _, err := ParseRequest([]byte(strings.Replace(prepare, `"changeId":`, `"command":"pvesh get /nodes","changeId":`, 1)), now); err == nil {
		t.Fatal("unknown PVE clearance control field was accepted")
	}
	if _, err := ParseRequest([]byte(strings.Replace(prepare, `"callerRole":"approver"`, `"callerRole":"observer"`, 1)), now); err == nil {
		t.Fatal("observer parsed a PVE clearance control request")
	}

	approval := PVERecoveryClearanceApproval{
		Version: Version, KeyID: "approver-test-v1", Action: PVERecoveryClearanceAction,
		ServerID: "server-12345678", MachineID: "machine-12345678", TargetID: "target-pve-root",
		ClearanceID:    "pve-clearance-0123456789abcdef0123456789abcdef",
		ParentChangeID: "pve-change-parent-12345678", ChildChangeID: "pve-change-child-123456789",
		ChildPlanHash: "sha256:" + strings.Repeat("a", 64), ResourceKey: "pve/vmid/100",
		ChallengeDigest: "sha256:" + strings.Repeat("b", 64), PolicyRevision: "policy-pve-12345678",
		CapabilityRevision: CapabilityRevision, IssuedAt: now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), Nonce: "clearance-protocol-nonce-1234",
		Signature: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	encoded, err := json.Marshal(approval)
	if err != nil {
		t.Fatal(err)
	}
	confirm := fmt.Sprintf(`{"version":1,"requestId":"clearance-confirm-request","deadline":%q,"method":"pve.recovery.clearance.confirm","serverId":"server-12345678","machineId":"machine-12345678","targetId":"target-pve-root","policyRevision":"policy-pve-12345678","capabilityRevision":%q,"callerRole":"approver","changeId":"pve-change-child-123456789","clearanceApproval":%s}`, deadline, CapabilityRevision, encoded)
	confirmed, err := ParseRequest([]byte(confirm), now)
	if err != nil || confirmed.ClearanceApproval == nil || confirmed.ClearanceApproval.ChallengeDigest != approval.ChallengeDigest {
		t.Fatalf("strict clearance confirmation did not parse: request=%#v err=%v", confirmed, err)
	}
	wrongChild := strings.Replace(confirm, `"changeId":"pve-change-child-123456789"`, `"changeId":"pve-change-other-123456789"`, 1)
	if _, err := ParseRequest([]byte(wrongChild), now); err == nil {
		t.Fatal("clearance approval crossed its child request binding")
	}
}
