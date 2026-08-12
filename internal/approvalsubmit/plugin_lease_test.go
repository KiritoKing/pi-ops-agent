package approvalsubmit

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/pluginregistry"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

type approvalPluginVersion struct {
	source     string
	inspection pluginregistry.Inspection
	grant      pluginregistry.Grant
}

type actionHookRemote struct {
	*fakeRemote
	onAction func()
}

type recordedRuntimeLease struct {
	closed bool
}

func (lease *recordedRuntimeLease) Close() error {
	lease.closed = true
	return nil
}

func (remote *actionHookRemote) Action(
	ctx context.Context,
	request Request,
	requestID string,
	deadline time.Time,
	grant protocol.ApprovalGrant,
) (HelperResponse, error) {
	if remote.onAction != nil {
		remote.onAction()
	}
	return remote.fakeRemote.Action(ctx, request, requestID, deadline, grant)
}

func TestSubmitRejectsStaleRuntimePluginBeforeReviewOrTTY(t *testing.T) {
	registry := approvalTestRegistry(t)
	versionA := approvalTestPluginVersion(t, registry, "workload.base", "1.0.0", "export const version = 'A';\n")
	versionB := approvalTestPluginVersion(t, registry, "workload.base", "2.0.0", "export const version = 'B';\n")
	if _, err := registry.Register(versionA.source, versionA.grant); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Register(versionB.source, versionB.grant); err != nil {
		t.Fatal(err)
	}

	request := testRequest(ActionApprove)
	plan := approvalRuntimeServicePlan(t, versionA.inspection.Digest)
	remote := &fakeRemote{plans: []protocol.ApprovalPlan{plan}, scope: request, state: "PENDING_APPROVAL"}
	confirmer := &fakeConfirmer{}
	reviewer := &fakeApprovalReviewer{}
	submitter := testSubmitter(request, remote, confirmer, testPrivateKey(t))
	submitter.Reviewer = reviewer
	submitter.LeaseRuntimePlugin = registryLeaseAcquirer(registry)

	if _, err := submitter.Submit(context.Background(), request); err == nil ||
		!strings.Contains(err.Error(), "current registration changed") {
		t.Fatalf("direct root submitter accepted stale digest A while B was current: %v", err)
	}
	if remote.statusCalls != 1 || reviewer.calls != 0 || confirmer.calls != 0 || remote.actionCalls != 0 {
		t.Fatalf("stale digest crossed root lease barrier: status=%d review=%d TTY=%d action=%d",
			remote.statusCalls, reviewer.calls, confirmer.calls, remote.actionCalls)
	}
}

func TestApprovalRuntimeLeaseRequiresExactWorkloadRegistration(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	plan := approvalRuntimeServicePlan(t, digest)
	tests := map[string]pluginregistry.RuntimeRegistration{
		"adapter kind": {Registration: pluginregistry.Registration{
			PluginID: "workload.base", Kind: pluginregistry.KindAdapter, Digest: digest,
		}},
		"different id": {Registration: pluginregistry.Registration{
			PluginID: "workload.other", Kind: pluginregistry.KindWorkload, Digest: digest,
		}},
		"different digest": {Registration: pluginregistry.Registration{
			PluginID: "workload.base", Kind: pluginregistry.KindWorkload,
			Digest: "sha256:" + strings.Repeat("b", 64),
		}},
	}
	for name, registration := range tests {
		t.Run(name, func(t *testing.T) {
			lease := &recordedRuntimeLease{}
			submitter := Submitter{LeaseRuntimePlugin: func(string, string) (pluginregistry.RuntimeRegistration, RuntimePluginLease, error) {
				return registration, lease, nil
			}}
			if _, err := submitter.acquireApprovalRuntimePluginLease(ChangeStatus{Plan: &plan}); err == nil ||
				!strings.Contains(err.Error(), "does not match") {
				t.Fatalf("non-exact workload registration was accepted: %v", err)
			}
			if !lease.closed {
				t.Fatal("mismatched registration did not release its shared lease")
			}
		})
	}
}

func TestRootSubmitterLeaseSurvivesClientLeaseLossAndBlocksUpdatesThroughAction(t *testing.T) {
	registry := approvalTestRegistry(t)
	versionA := approvalTestPluginVersion(t, registry, "workload.base", "1.0.0", "export const version = 'A';\n")
	versionB := approvalTestPluginVersion(t, registry, "workload.base", "2.0.0", "export const version = 'B';\n")
	if _, err := registry.Register(versionA.source, versionA.grant); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Register(versionB.source, versionB.grant); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Activate("workload.base", versionA.inspection.Digest, versionA.grant); err != nil {
		t.Fatal(err)
	}
	_, clientLease, err := registry.LeaseRuntimeCurrent("workload.base", versionA.inspection.Digest)
	if err != nil {
		t.Fatal(err)
	}
	clientLeaseClosed := false
	t.Cleanup(func() {
		if !clientLeaseClosed {
			_ = clientLease.Close()
		}
	})
	mutationRegistry, err := pluginregistry.Open(approvalRegistryRoot(registry, versionA))
	if err != nil {
		t.Fatal(err)
	}

	request := testRequest(ActionApprove)
	plan := approvalRuntimeServicePlan(t, versionA.inspection.Digest)
	baseRemote := &fakeRemote{plans: []protocol.ApprovalPlan{plan, plan}, scope: request, state: "PENDING_APPROVAL"}
	var registerErr, activateErr error
	remote := &actionHookRemote{fakeRemote: baseRemote, onAction: func() {
		if closeErr := clientLease.Close(); closeErr != nil {
			t.Errorf("close simulated Client/broker lease: %v", closeErr)
		}
		clientLeaseClosed = true
		_, registerErr = mutationRegistry.Register(versionB.source, versionB.grant)
		_, activateErr = mutationRegistry.Activate("workload.base", versionB.inspection.Digest, versionB.grant)
	}}
	submitter := testSubmitter(request, baseRemote, &fakeConfirmer{}, testPrivateKey(t))
	submitter.NewRemote = func(LoadedServer) (Remote, error) { return remote, nil }
	submitter.LeaseRuntimePlugin = registryLeaseAcquirer(registry)

	result, err := submitter.Submit(context.Background(), request)
	if err != nil || !result.OK || result.State != "COMMITTED" {
		t.Fatalf("approval under root-held lease failed: result=%#v err=%v", result, err)
	}
	for name, updateErr := range map[string]error{"register": registerErr, "activate": activateErr} {
		if updateErr == nil || !strings.Contains(updateErr.Error(), "active source-plugin runtime") {
			t.Fatalf("%s crossed root-held lease after Client/broker lease loss: %v", name, updateErr)
		}
	}
	if _, err := mutationRegistry.Activate("workload.base", versionB.inspection.Digest, versionB.grant); err != nil {
		t.Fatalf("digest B activation remained blocked after final action and root lease release: %v", err)
	}
}

func TestSubmitDoesNotLeaseCandidateOrNonRuntimePlans(t *testing.T) {
	digest := "sha256:" + strings.Repeat("d", 64)
	operations := []protocol.Operation{
		&protocol.PackageInstall{OperationKind: "package.install", Package: "jq"},
		&protocol.PluginRegister{
			OperationKind: "plugin.register", PluginID: "workload.example", PluginKind: "workload",
			Version: "1.0.0", Publisher: "example/plugin", Digest: digest,
			Capabilities: []string{"demo.echo"}, RequestedScopes: []string{"filesystem.read.system"},
		},
		&protocol.PluginInstall{
			OperationKind: "plugin.install", PluginID: "example-plugin", Version: "1.0.0",
			Publisher: "example/plugin", Digest: digest, ArtifactRef: "builtin:" + digest,
		},
		&protocol.WorkloadDeploy{
			OperationKind: "workload.deploy", PluginID: "example-workload", Version: "1.0.0",
			Publisher: "example/plugin", Digest: digest, ArtifactRef: "builtin:" + digest,
		},
	}
	for _, operation := range operations {
		t.Run(operation.Kind(), func(t *testing.T) {
			plan, err := protocol.BuildApprovalPlan(operation, "policy-12345678", "capability-12345678")
			if err != nil {
				t.Fatal(err)
			}
			request := testRequest(ActionApprove)
			remote := &fakeRemote{plans: []protocol.ApprovalPlan{plan, plan}, scope: request, state: "PENDING_APPROVAL"}
			submitter := testSubmitter(request, remote, &fakeConfirmer{}, testPrivateKey(t))
			leaseCalls := 0
			submitter.LeaseRuntimePlugin = func(string, string) (pluginregistry.RuntimeRegistration, RuntimePluginLease, error) {
				leaseCalls++
				return pluginregistry.RuntimeRegistration{}, nil, errors.New("candidate digest must not be resolved as current")
			}
			result, err := submitter.Submit(context.Background(), request)
			if err != nil || !result.OK || leaseCalls != 0 {
				t.Fatalf("%s incorrectly required a runtime current lease: result=%#v calls=%d err=%v",
					operation.Kind(), result, leaseCalls, err)
			}
		})
	}
}

func TestRuntimePluginRollbackDoesNotDependOnCurrentDigest(t *testing.T) {
	request := testRequest(ActionRollback)
	digest := "sha256:" + strings.Repeat("a", 64)
	plan := approvalRuntimeServicePlan(t, digest)
	remote := &fakeRemote{plans: []protocol.ApprovalPlan{plan, plan}, scope: request, state: "COMMITTED", rollback: true}
	submitter := testSubmitter(request, remote, &fakeConfirmer{}, testPrivateKey(t))
	leaseCalls := 0
	submitter.LeaseRuntimePlugin = func(string, string) (pluginregistry.RuntimeRegistration, RuntimePluginLease, error) {
		leaseCalls++
		return pluginregistry.RuntimeRegistration{}, nil, errors.New("rollback must preserve recovery after plugin update")
	}
	result, err := submitter.Submit(context.Background(), request)
	if err != nil || !result.OK || result.State != "ROLLED_BACK" || leaseCalls != 0 {
		t.Fatalf("rollback was incorrectly coupled to runtime current: result=%#v calls=%d err=%v", result, leaseCalls, err)
	}
}

func TestRuntimePluginBindingRejectsMixedMissingOrConflictingProvenance(t *testing.T) {
	digestA := "sha256:" + strings.Repeat("a", 64)
	digestB := "sha256:" + strings.Repeat("b", 64)
	valid := approvalRuntimeServicePlan(t, digestA)
	pve, err := protocol.BuildApprovalPlan(&protocol.PVESnapshotDelete{
		OperationKind: "pve.snapshot.delete", PluginID: "workload.pve", PluginDigest: digestA,
		Node: "pve1", GuestType: "qemu", VMID: 100, Snapshot: "before-update", BackupStorage: "local",
	}, "policy-pve-12345678", "capability-12345678")
	if err != nil {
		t.Fatal(err)
	}
	if binding, required, err := approvalRuntimePluginBinding(pve); err != nil || !required ||
		binding.pluginID != "workload.pve" || binding.digest != digestA {
		t.Fatalf("valid two-step PVE provenance was rejected: binding=%#v required=%t err=%v", binding, required, err)
	}

	tests := map[string]protocol.ApprovalPlan{
		"mixed runtime and non-runtime": cloneApprovalPlan(valid),
		"missing digest":                cloneApprovalPlan(valid),
		"conflicting digest":            cloneApprovalPlan(valid),
		"inconsistent plugin identity":  cloneApprovalPlan(pve),
		"top-level digest mismatch":     cloneApprovalPlan(valid),
	}
	mixed := tests["mixed runtime and non-runtime"]
	mixed.Steps = append(mixed.Steps, protocol.ApprovalPlanStep{
		ID: "step-2", Operation: "package.install", Reversible: false,
		Fields: []protocol.ApprovalPlanField{{Name: "package", Value: "jq"}},
	})
	tests["mixed runtime and non-runtime"] = mixed
	missing := tests["missing digest"]
	missing.Steps[0].Fields = removeApprovalField(missing.Steps[0].Fields, "pluginDigest")
	tests["missing digest"] = missing
	conflicting := tests["conflicting digest"]
	conflicting.Steps[0].Fields = append(conflicting.Steps[0].Fields,
		protocol.ApprovalPlanField{Name: "sourceDigest", Value: digestB})
	tests["conflicting digest"] = conflicting
	inconsistent := tests["inconsistent plugin identity"]
	for index := range inconsistent.Steps[1].Fields {
		if inconsistent.Steps[1].Fields[index].Name == "pluginId" {
			inconsistent.Steps[1].Fields[index].Value = "workload.other"
		}
	}
	tests["inconsistent plugin identity"] = inconsistent
	topLevel := tests["top-level digest mismatch"]
	topLevel.PluginDigest = digestB
	tests["top-level digest mismatch"] = topLevel

	for name, plan := range tests {
		t.Run(name, func(t *testing.T) {
			if _, required, err := approvalRuntimePluginBinding(plan); err == nil || required {
				t.Fatalf("invalid runtime provenance was accepted: required=%t err=%v", required, err)
			}
		})
	}
}

func approvalTestRegistry(t *testing.T) *pluginregistry.Registry {
	t.Helper()
	root := t.TempDir()
	// Registered snapshots are intentionally read-only. Restore directory
	// write/search bits before testing.TempDir's later RemoveAll cleanup.
	t.Cleanup(func() {
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err == nil && entry.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	registry, err := pluginregistry.Open(filepath.Join(root, "registry"))
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func approvalTestPluginVersion(
	t *testing.T,
	registry *pluginregistry.Registry,
	pluginID, version, sourceText string,
) approvalPluginVersion {
	t.Helper()
	source := filepath.Join(t.TempDir(), "source")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := pluginregistry.Manifest{
		APIVersion: pluginregistry.ManifestAPIVersion, SchemaVersion: pluginregistry.ManifestSchema,
		ID: pluginID, Kind: pluginregistry.KindWorkload, Version: version,
		Publisher: "example/plugin", Description: "Approval submitter lease fixture",
		Entrypoint: "index.mjs", Capabilities: []string{"service.manage"},
		RequestedScopes: []string{"service.action"},
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "manifest.json"), append(payload, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "index.mjs"), []byte(sourceText), 0o644); err != nil {
		t.Fatal(err)
	}
	inspection, err := registry.InspectSource(source)
	if err != nil {
		t.Fatal(err)
	}
	grant := pluginregistry.Grant{
		PluginID: pluginID, Kind: pluginregistry.KindWorkload, Digest: inspection.Digest,
		RequestedScopes: append([]string(nil), inspection.Manifest.RequestedScopes...),
		ApprovedBy:      "local-admin:1000", ApprovedAt: testNow,
	}
	return approvalPluginVersion{source: source, inspection: inspection, grant: grant}
}

func registryLeaseAcquirer(registry *pluginregistry.Registry) RuntimePluginLeaseAcquirer {
	return func(pluginID, digest string) (pluginregistry.RuntimeRegistration, RuntimePluginLease, error) {
		registration, lease, err := registry.LeaseRuntimeCurrent(pluginID, digest)
		return registration, lease, err
	}
}

// Inspection.Path is the source path, so derive the sibling registry root
// from the immutable snapshot path returned by a live registration instead.
func approvalRegistryRoot(registry *pluginregistry.Registry, version approvalPluginVersion) string {
	registration, err := registry.Current(version.inspection.Manifest.ID)
	if err != nil {
		panic(err)
	}
	return filepath.Clean(filepath.Join(registration.SnapshotPath, "..", "..", ".."))
}

func approvalRuntimeServicePlan(t *testing.T, digest string) protocol.ApprovalPlan {
	t.Helper()
	plan, err := protocol.BuildApprovalPlan(&protocol.ServiceAction{
		OperationKind: "service.action", PluginID: "workload.base", PluginDigest: digest,
		Unit: "nginx.service", Action: "restart",
	}, "policy-12345678", "capability-12345678")
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func cloneApprovalPlan(plan protocol.ApprovalPlan) protocol.ApprovalPlan {
	clone := plan
	clone.Steps = make([]protocol.ApprovalPlanStep, len(plan.Steps))
	for index, step := range plan.Steps {
		clone.Steps[index] = step
		clone.Steps[index].Fields = append([]protocol.ApprovalPlanField(nil), step.Fields...)
	}
	return clone
}

func removeApprovalField(fields []protocol.ApprovalPlanField, name string) []protocol.ApprovalPlanField {
	result := make([]protocol.ApprovalPlanField, 0, len(fields))
	for _, field := range fields {
		if field.Name != name {
			result = append(result, field)
		}
	}
	return result
}
