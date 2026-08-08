package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestApprovalPlanShowsBoundedFileBodyAndBindsArtifact(t *testing.T) {
	content := "token=must-not-appear"
	baseDigest := "sha256:" + strings.Repeat("a", 64)
	plan, err := BuildApprovalPlan(&FileWrite{
		OperationKind: "file.write",
		PluginID:      BaseWorkloadPluginID,
		PluginDigest:  baseDigest,
		Path:          "/etc/example.conf",
		Content:       content,
		Mode:          "0640",
	}, "policy-12345678", "capability-12345678")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), content) || !strings.Contains(string(payload), approvalContentDigest(content)) {
		t.Fatalf("approval plan did not show and digest the exact content: %s", payload)
	}
	if !digestPattern.MatchString(plan.PlanHash) || plan.CapabilityRevision != "capability-12345678" {
		t.Fatalf("approval plan lost authoritative scope: %#v", plan)
	}
	if plan.PluginDigest != baseDigest || plan.Steps[0].Fields[0].Value != BaseWorkloadPluginID {
		t.Fatalf("approval plan lost the base workload provenance: %#v", plan)
	}
	recomputed, err := CanonicalApprovalPlanHash(plan)
	if err != nil || recomputed != plan.PlanHash {
		t.Fatalf("approval plan hash does not bind the displayed plan: %s %v", recomputed, err)
	}
	tampered := plan
	tampered.Steps = append([]ApprovalPlanStep(nil), plan.Steps...)
	tampered.Steps[0].Fields = append([]ApprovalPlanField(nil), plan.Steps[0].Fields...)
	tampered.Steps[0].Fields[0].Value = "/etc/another.conf"
	tamperedHash, err := CanonicalApprovalPlanHash(tampered)
	if err != nil || tamperedHash == plan.PlanHash {
		t.Fatal("displayed-plan tampering did not change the canonical plan hash")
	}

	digest := "sha256:" + strings.Repeat("b", 64)
	pluginPlan, err := BuildApprovalPlan(&PluginInstall{
		OperationKind: "plugin.install",
		PluginID:      "adapter.example",
		Version:       "1.0.0",
		Publisher:     "example",
		Digest:        digest,
		ArtifactRef:   "builtin:" + digest,
	}, "policy-12345678", "capability-12345678")
	if err != nil {
		t.Fatal(err)
	}
	if pluginPlan.PluginDigest != digest {
		t.Fatalf("plugin digest is not bound into the approval plan: %#v", pluginPlan)
	}

	registrationPlan, err := BuildApprovalPlan(&PluginRegister{
		OperationKind: "plugin.register", PluginID: "workload.example", PluginKind: "workload",
		Version: "1.2.3", Publisher: "example/ops", Digest: digest,
		Capabilities:    []string{"demo.echo", "target.inspect"},
		RequestedScopes: []string{"control.target.inspect", "control.target.prepare"},
	}, "policy-12345678", "capability-12345678")
	if err != nil {
		t.Fatal(err)
	}
	if registrationPlan.PluginDigest != digest || len(registrationPlan.Steps) != 1 ||
		registrationPlan.Steps[0].Fields[2].Value != "1.2.3" ||
		registrationPlan.Steps[0].Fields[3].Value != "example/ops" ||
		registrationPlan.Steps[0].Fields[5].Value != "demo.echo\ntarget.inspect" ||
		registrationPlan.Steps[0].Fields[6].Value != "control.target.inspect\ncontrol.target.prepare" {
		t.Fatalf("source plugin approval plan lost its digest or scopes: %#v", registrationPlan)
	}
	const pluginRegisterGolden = "sha256:a865c0c3d1601ef7feb51fbe30d213337ee731a4af85c4ae45dc2a7e71c29418"
	if registrationPlan.PlanHash != pluginRegisterGolden {
		t.Fatalf("plugin.register Go/TypeScript golden plan hash changed: got %s want %s", registrationPlan.PlanHash, pluginRegisterGolden)
	}
}

func TestApprovalPlanRejectsLegacyOperation(t *testing.T) {
	_, err := BuildApprovalPlan(&legacyPluginRemove{
		OperationKind: "plugin.remove",
		PluginID:      "adapter.example",
		Version:       "0.1.0",
		Digest:        "sha256:" + strings.Repeat("c", 64),
	}, "policy-12345678", "capability-12345678")
	if err == nil {
		t.Fatal("legacy recovery-only operation received a live approval plan")
	}
}

func TestAdapterRegistrationPlanShowsFullRuntimeAuthority(t *testing.T) {
	digest := "sha256:" + strings.Repeat("c", 64)
	plan, err := BuildApprovalPlan(&PluginRegister{
		OperationKind: "plugin.register", PluginID: "adapter.example", PluginKind: "adapter",
		Version: "1.2.3", Publisher: "example/ops", Digest: digest,
		Capabilities: []string{
			"adapter.inbound.text", "adapter.outbound.send", "adapter.session.bind", "approval.status",
		},
		RequestedScopes: []string{
			"adapter.inbound.text.example", "adapter.outbound.send.example",
			"adapter.session.bind.example", "approval.status.remote",
		},
	}, "policy-12345678", "capability-12345678")
	if err != nil {
		t.Fatal(err)
	}
	fields := make(map[string]string, len(plan.Steps[0].Fields))
	for _, field := range plan.Steps[0].Fields {
		fields[field.Name] = field.Value
	}
	if fields["adapterRuntimeIdentity"] != "ops-adapter-example" ||
		fields["adapterExecution"] != "source-process" ||
		fields["adapterFilesystemAuthority"] != "host-as-runtime-uid" ||
		fields["adapterNetworkAuthority"] != "host" ||
		fields["adapterCredentialAuthority"] != "runtime-uid-readable" ||
		fields["adapterActionScopeEnforcement"] != "digest-review-and-typed-ipc-contract" ||
		fields["adapterDirectPlatformAuthority"] != "full-runtime-uid-authority;not-os-action-sandboxed" {
		t.Fatalf("adapter registration plan omitted runtime authority: %#v", fields)
	}
	recomputed, err := CanonicalApprovalPlanHash(plan)
	if err != nil || recomputed != plan.PlanHash {
		t.Fatalf("adapter authority fields are not plan-hash-bound: %s %v", recomputed, err)
	}
}

func TestPVEApprovalPlanShowsSafetyBackupAndAuthoritativePrecondition(t *testing.T) {
	digest := "sha256:" + strings.Repeat("d", 64)
	fields := []ApprovalPlanField{
		{Name: "currentStatus", Value: "running"},
		{Name: "snapshotState", Value: "present"},
	}
	preconditionDigest, err := ApprovalPreconditionDigest(fields)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildApprovalPlanWithPreconditions(&PVESnapshotRollback{
		OperationKind: "pve.snapshot.rollback", PluginID: testPVEPluginID, PluginDigest: digest,
		Node: "pve1", GuestType: "qemu", VMID: 100, Snapshot: "known-good", BackupStorage: "local",
	}, "policy-12345678", "capability-12345678", preconditionDigest, fields)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Steps) != 2 || plan.Steps[0].Operation != "pve.guest.backup" ||
		plan.Steps[1].Operation != "pve.snapshot.rollback" || plan.PreconditionDigest != preconditionDigest {
		t.Fatalf("PVE destructive plan did not expose both atomic steps: %#v", plan)
	}
	if plan.Steps[1].Fields[len(plan.Steps[1].Fields)-2].Name != "precondition.currentStatus" {
		t.Fatalf("PVE plan omitted authoritative current state: %#v", plan.Steps[1].Fields)
	}

	action, err := BuildApprovalPlan(&PVEGuestAction{
		OperationKind: "pve.guest.action", PluginID: testPVEPluginID, PluginDigest: digest,
		Node: "pve1", GuestType: "qemu", VMID: 100, Action: "stop",
	}, "policy-12345678", "capability-12345678")
	if err != nil {
		t.Fatal(err)
	}
	if action.Steps[0].Reversible {
		t.Fatal("PVE lifecycle action was presented as a complete rollback")
	}
}

func TestPVERecoveryParentIsCanonicalPlanBound(t *testing.T) {
	digest := "sha256:" + strings.Repeat("e", 64)
	parent := "pve-change-0123456789abcdef0123456789abcdef"
	operation := &PVESnapshotRollback{
		OperationKind: "pve.snapshot.rollback", PluginID: testPVEPluginID, PluginDigest: digest,
		RecoveryOfChangeID: parent, Node: "pve1", GuestType: "qemu", VMID: 100,
		Snapshot: "known-good", BackupStorage: "local",
	}
	plan, err := BuildApprovalPlan(operation, "policy-12345678", "capability-12345678")
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range plan.Steps {
		found := false
		for _, field := range step.Fields {
			found = found || (field.Name == "recoveryOfChangeId" && field.Value == parent)
		}
		if !found {
			t.Fatalf("recovery parent was not shown in every PVE recovery step: %#v", step)
		}
	}
	withoutParent := *operation
	withoutParent.RecoveryOfChangeID = ""
	ordinary, err := BuildApprovalPlan(&withoutParent, "policy-12345678", "capability-12345678")
	if err != nil {
		t.Fatal(err)
	}
	if ordinary.PlanHash == plan.PlanHash {
		t.Fatal("recovery parent did not change the canonical approval plan hash")
	}
	const recoveryPlanGolden = "sha256:f32dc23be1dde4655eb7dadc4366eac241c33d563428fc5a30617eab207e445f"
	if plan.PlanHash != recoveryPlanGolden {
		t.Fatalf("PVE recovery Go/TypeScript golden plan hash changed: got %s want %s", plan.PlanHash, recoveryPlanGolden)
	}
}
