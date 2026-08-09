package roothelper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/peercred"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

func TestStoreTTLQuotaAndSafeChangeEviction(t *testing.T) {
	now := time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)
	limits := testStoreLimits(&now)
	limits.MaxChanges = 3
	limits.MaxPendingChanges = 2
	store, err := OpenStoreWithLimits(t.TempDir(), limits)
	if err != nil {
		t.Fatal(err)
	}

	for index := 1; index <= 3; index++ {
		change := testStoredChange(fmt.Sprintf("change-pending-%d", index), StatePendingApproval, now.Add(time.Duration(index)*time.Minute))
		if err := store.PutChange(change); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := store.Change("change-pending-1"); ok {
		t.Fatal("oldest pending change was not safely evicted at the pending quota")
	}

	for index := 1; index <= 3; index++ {
		change := testStoredChange(fmt.Sprintf("change-recovery-%d", index), StateRecoveryRequired, now.Add(time.Duration(index+10)*time.Minute))
		if err := store.PutChange(change); err != nil {
			t.Fatalf("store recovery change %d: %v", index, err)
		}
	}
	if len(store.state.Changes) != 3 {
		t.Fatalf("change quota not enforced: %d", len(store.state.Changes))
	}
	protected := testStoredChange("change-recovery-4", StateRecoveryRequired, now.Add(20*time.Minute))
	if err := store.PutChange(protected); err == nil || !strings.Contains(err.Error(), "quota") {
		t.Fatalf("protected recovery records were evicted or quota was not enforced: %v", err)
	}
	if _, ok := store.state.Changes[protected.ID]; ok {
		t.Fatal("failed quota write mutated in-memory state")
	}

	separate, err := OpenStoreWithLimits(t.TempDir(), testStoreLimits(&now))
	if err != nil {
		t.Fatal(err)
	}
	pending := testStoredChange("change-expiring-pending", StatePendingApproval, now)
	terminal := testStoredChange("change-expiring-terminal", StateRejected, now)
	recovery := testStoredChange("change-retained-recovery", StateRecoveryRequired, now)
	for _, change := range []*Change{pending, terminal, recovery} {
		if err := separate.PutChange(change); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(2 * time.Hour)
	if _, ok := separate.Change(pending.ID); ok {
		t.Fatal("expired pending change remained visible")
	}
	if _, ok := separate.Change(terminal.ID); ok {
		t.Fatal("expired terminal change remained visible")
	}
	if _, ok := separate.Change(recovery.ID); !ok {
		t.Fatal("recovery-required change was TTL-evicted")
	}
	if err := separate.PutChange(recovery); err != nil {
		t.Fatal(err)
	}
	if len(separate.state.Changes) != 1 {
		t.Fatalf("expired changes were not compacted on the next mutation: %#v", separate.state.Changes)
	}
}

func TestStoreChangeSnapshotDoesNotShareApprovedUIDPointer(t *testing.T) {
	now := time.Date(2026, 8, 10, 3, 30, 0, 0, time.UTC)
	store, err := OpenStoreWithLimits(t.TempDir(), testStoreLimits(&now))
	if err != nil {
		t.Fatal(err)
	}
	approvedByUID := uint32(1001)
	change := testStoredChange("change-independent-snapshot", StateCommitted, now)
	change.ApprovedByUID = &approvedByUID
	if err := store.PutChange(change); err != nil {
		t.Fatal(err)
	}

	approvedByUID = 2002
	snapshot, ok := store.Change(change.ID)
	if !ok || snapshot.ApprovedByUID == nil || *snapshot.ApprovedByUID != 1001 {
		t.Fatalf("stored change shared the caller's approval UID pointer: %#v", snapshot)
	}
	*snapshot.ApprovedByUID = 3003
	fresh, ok := store.Change(change.ID)
	if !ok || fresh.ApprovedByUID == nil || *fresh.ApprovedByUID != 1001 {
		t.Fatalf("Store.Change returned a snapshot sharing durable pointer state: %#v", fresh)
	}
}

func TestStoreReplayRecordTTLNonceQuotaAndPersistenceFailure(t *testing.T) {
	now := time.Date(2026, 8, 8, 9, 0, 0, 0, time.UTC)
	limits := testStoreLimits(&now)
	limits.MaxRequests = 2
	limits.MaxApprovalNonces = 1
	store, err := OpenStoreWithLimits(t.TempDir(), limits)
	if err != nil {
		t.Fatal(err)
	}
	response := protocol.Response{Version: protocol.Version, RequestID: "mutation-request-1", OK: true, ChangeID: "change-example-1"}
	if err := store.ReserveRequest(response.RequestID); err != nil {
		t.Fatal(err)
	}
	if err := store.Cache(response.RequestID, 1001, "fingerprint-a", response, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if replayed, ok, err := store.Cached(response.RequestID, 1001, "fingerprint-a"); err != nil || !ok || replayed.ChangeID != response.ChangeID {
		t.Fatalf("durable replay cache lookup failed: response=%#v ok=%v err=%v", replayed, ok, err)
	}
	if _, _, err := store.Cached(response.RequestID, 1002, "fingerprint-a"); err == nil {
		t.Fatal("request replay by another peer was accepted")
	}

	if err := store.UseApprovalNonce("nonce-store-test-00000001", "change-example-1", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.UseApprovalNonce("nonce-store-test-00000001", "change-example-1", now.Add(time.Minute)); err == nil {
		t.Fatal("approval nonce replay was accepted")
	}
	if err := store.UseApprovalNonce("nonce-store-test-00000002", "change-example-2", now.Add(time.Minute)); err == nil || !strings.Contains(err.Error(), "quota") {
		t.Fatalf("nonce quota was not enforced: %v", err)
	}

	now = now.Add(2 * time.Minute)
	if _, ok, err := store.Cached(response.RequestID, 1001, "fingerprint-a"); err != nil || ok {
		t.Fatalf("expired request cache remained usable: ok=%v err=%v", ok, err)
	}
	if err := store.UseApprovalNonce("nonce-store-test-00000001", "change-example-3", now.Add(time.Minute)); err != nil {
		t.Fatalf("expired nonce did not release quota: %v", err)
	}

	failureStore, err := OpenStoreWithLimits(t.TempDir(), testStoreLimits(&now))
	if err != nil {
		t.Fatal(err)
	}
	if err := failureStore.ReserveRequest("mutation-cache-failure"); err != nil {
		t.Fatal(err)
	}
	failureStore.dir = filepath.Join(failureStore.dir, "missing", "directory")
	failureResponse := protocol.Response{Version: protocol.Version, RequestID: "mutation-cache-failure", OK: true}
	if err := failureStore.Cache("mutation-cache-failure", 1001, "fingerprint-failure", failureResponse, now.Add(time.Minute)); err == nil {
		t.Fatal("cache persistence failure was not reported")
	}
	if len(failureStore.reservations) != 0 {
		t.Fatalf("cache persistence failure leaked reservations: %#v", failureStore.reservations)
	}
	if replayed, ok, err := failureStore.Cached("mutation-cache-failure", 1001, "fingerprint-failure"); err != nil || !ok || !replayed.OK {
		t.Fatalf("bounded volatile replay guard was not retained: response=%#v ok=%v err=%v", replayed, ok, err)
	}
}

func TestStateFileByteQuotaIsTransactional(t *testing.T) {
	now := time.Date(2026, 8, 8, 9, 30, 0, 0, time.UTC)
	limits := testStoreLimits(&now)
	limits.MaxStateBytes = protocol.MaxFrameBytes
	store, err := OpenStoreWithLimits(t.TempDir(), limits)
	if err != nil {
		t.Fatal(err)
	}
	operation, err := json.Marshal(&protocol.FileWrite{
		OperationKind: "file.write", Path: "/tmp/bounded-state", Content: strings.Repeat("x", 128*1024),
	})
	if err != nil {
		t.Fatal(err)
	}
	change := testStoredChange("change-large-state-1", StatePendingApproval, now)
	change.Kind, change.Operation = "file.write", operation
	if err := store.PutChange(change); err != nil {
		t.Fatalf("first bounded change did not fit: %v", err)
	}
	second := cloneChange(change)
	second.ID = "change-large-state-2"
	if err := store.PutChange(second); err == nil || !strings.Contains(err.Error(), "byte quota") {
		t.Fatalf("oversized state was persisted: %v", err)
	}
	if _, exists := store.state.Changes[second.ID]; exists {
		t.Fatal("byte-quota failure mutated the live state")
	}
}

type largeInspector struct{ payload string }

func (i largeInspector) Inspect(context.Context, protocol.Request, []string) (interface{}, error) {
	return map[string]string{"output": i.payload}, nil
}

func TestReadResponsesAreNeverPersisted(t *testing.T) {
	now := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	service := testService(t, now, &fakeExecutor{})
	service.Inspector = largeInspector{payload: strings.Repeat("x", 128*1024)}
	agent := peercred.Credential{UID: service.AgentUID}
	inspect := service.Handle(context.Background(), agent, parseRequest(t, now, "inspect-not-persisted", `"method":"host.snapshot"`))
	if !inspect.OK {
		t.Fatalf("large inspect failed: %#v", inspect)
	}
	if len(service.Store.state.Requests) != 0 {
		t.Fatal("inspect response was persisted in the replay state")
	}
	prepared := service.Handle(context.Background(), agent, parseRequest(t, now, "prepare-for-status", `"method":"change.prepare","operation":{"kind":"package.install","package":"nginx"}`))
	if !prepared.OK {
		t.Fatal(prepared.Error)
	}
	requestCount := len(service.Store.state.Requests)
	status := service.Handle(context.Background(), agent, parseRequest(t, now, "status-not-persisted", fmt.Sprintf(`"method":"change.status","changeId":%q`, prepared.ChangeID)))
	if !status.OK || len(service.Store.state.Requests) != requestCount {
		t.Fatalf("status response changed persistent replay state: status=%#v requests=%d", status, len(service.Store.state.Requests))
	}
}

func TestStoreMigratesPVEVMIDLocksAndRejectsLegacyGuestTypeCollision(t *testing.T) {
	now := time.Date(2026, 8, 8, 10, 30, 0, 0, time.UTC)
	safeDir := t.TempDir()
	qemu := testPVEStoredChange(t, "pve-change-qemu-parent-0001", StateRecoveryRequired, now, "qemu", 100, "")
	qemu.ResourceKey = "pve/qemu/100"
	safeState := emptyPersistedState()
	safeState.Changes[qemu.ID] = qemu
	safeState.ResourceLocks[qemu.ResourceKey] = qemu.ID
	writeTestState(t, safeDir, safeState)
	migrated, err := OpenStoreWithLimits(safeDir, testStoreLimits(&now))
	if err != nil {
		t.Fatalf("safe legacy PVE lock migration failed: %v", err)
	}
	if migrated.state.Changes[qemu.ID].ResourceKey != "pve/vmid/100" ||
		migrated.state.ResourceLocks["pve/vmid/100"] != qemu.ID || len(migrated.state.ResourceLocks) != 1 {
		t.Fatalf("legacy PVE lock was not normalized cluster-globally: %#v", migrated.state)
	}

	conflictDir := t.TempDir()
	lxc := testPVEStoredChange(t, "pve-change-lxc-parent-00001", StateRecoveryRequired, now, "lxc", 100, "")
	lxc.ResourceKey = "pve/lxc/100"
	conflict := emptyPersistedState()
	conflict.Changes[qemu.ID], conflict.Changes[lxc.ID] = qemu, lxc
	conflict.ResourceLocks[qemu.ResourceKey], conflict.ResourceLocks[lxc.ResourceKey] = qemu.ID, lxc.ID
	writeTestState(t, conflictDir, conflict)
	if _, err := OpenStoreWithLimits(conflictDir, testStoreLimits(&now)); err == nil || !strings.Contains(err.Error(), "cluster-global") {
		t.Fatalf("ambiguous qemu/lxc legacy VMID locks did not fail closed: %v", err)
	}
}

func TestPVERecoveryTransferIsAtomicDurableAndKeepsFailedChildLock(t *testing.T) {
	now := time.Date(2026, 8, 8, 11, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	store, err := OpenStoreWithLimits(dir, testStoreLimits(&now))
	if err != nil {
		t.Fatal(err)
	}
	parent := testPVEStoredChange(t, "pve-change-parent-0123456789", StateRecoveryRequired, now, "qemu", 100, "")
	if err := store.PutChangeWithResourceLock(parent); err != nil {
		t.Fatal(err)
	}
	child := testPVEStoredChange(t, "pve-change-child-01234567890", StatePendingApproval, now.Add(time.Minute), "lxc", 100, parent.ID)
	if err := store.ValidateRecoveryCandidate(child); err != nil {
		t.Fatalf("valid cross-guest-type VMID recovery was rejected: %v", err)
	}
	if err := store.PutChange(child); err != nil {
		t.Fatal(err)
	}
	child.State = StatePreparing
	child.AuthorizationBasis = "local-uid:0"
	child.AuthorizedAt = timestamp(now.Add(time.Minute))
	if err := store.PutRecoveryChangeAndTransferResource(child, PVERecoveryReadiness{
		MutationDisposition: protocol.PVEMutationDispositionNotStarted,
	}); err != nil {
		t.Fatalf("atomic recovery transfer failed: %v", err)
	}
	resolved, _ := store.Change(parent.ID)
	if resolved.State != StateSuperseded || resolved.Resolution == nil ||
		resolved.Resolution.ChildChangeID != child.ID || resolved.Resolution.ChildPlanHash != child.PlanHash ||
		resolved.Resolution.ParentTaskEvidence == nil ||
		store.state.ResourceLocks[child.ResourceKey] != child.ID {
		t.Fatalf("parent resolution or child lock is incomplete: parent=%#v locks=%#v", resolved, store.state.ResourceLocks)
	}
	child.State = StateRecoveryRequired
	child.LastError = "typed recovery failed"
	child.UpdatedAt = timestamp(now.Add(2 * time.Minute))
	if err := store.PutChange(child); err != nil {
		t.Fatal(err)
	}
	legacyNullEvidence := clonePersistedState(store.state)
	legacyNullEvidence.Changes[parent.ID].Resolution.ParentTaskEvidence = nil
	writeTestState(t, dir, legacyNullEvidence)
	reopened, err := OpenStoreWithLimits(dir, testStoreLimits(&now))
	if err != nil {
		t.Fatalf("durable recovery chain did not reopen: %v", err)
	}
	if reopened.state.ResourceLocks["pve/vmid/100"] != child.ID || reopened.state.Changes[parent.ID].State != StateSuperseded ||
		reopened.state.Changes[parent.ID].Resolution.ParentTaskEvidence == nil {
		t.Fatalf("restart revived the parent lock: %#v", reopened.state)
	}
	canonicalState, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(canonicalState), `"parentTaskEvidence":[]`) {
		t.Fatalf("reopen did not rewrite legacy null task evidence canonically: %s", canonicalState)
	}

	ordinary := testPVEStoredChange(t, "pve-change-ordinary-01234567", StatePreparing, now.Add(3*time.Minute), "qemu", 100, "")
	if err := reopened.PutChangeWithResourceLock(ordinary); err == nil || !strings.Contains(err.Error(), child.ID) {
		t.Fatalf("ordinary change bypassed failed recovery child lock: %v", err)
	}

	child.State = StateCommitted
	child.UpdatedAt = timestamp(now.Add(4 * time.Minute))
	if err := reopened.PutChangeAndReleaseResource(child); err != nil {
		t.Fatal(err)
	}
	reopenedAgain, err := OpenStoreWithLimits(dir, testStoreLimits(&now))
	if err != nil {
		t.Fatal(err)
	}
	if len(reopenedAgain.state.ResourceLocks) != 0 || reopenedAgain.state.Changes[parent.ID].Resolution == nil {
		t.Fatalf("committed child did not release only its lock or lost parent evidence: %#v", reopenedAgain.state)
	}
}

func TestPVEUnknownClearanceStoreFailureLeavesParentChildAndLockAtomic(t *testing.T) {
	now := time.Date(2026, 8, 8, 11, 30, 0, 0, time.UTC)
	dir := t.TempDir()
	store, err := OpenStoreWithLimits(dir, testStoreLimits(&now))
	if err != nil {
		t.Fatal(err)
	}
	parent := testPVEStoredChange(t, "pve-change-parent-clear-fault", StateRecoveryRequired, now, "qemu", 100, "")
	parent.PVEMutationVersion = 1
	parent.MutationDisposition = protocol.PVEMutationDispositionUnknown
	child := testPVEStoredChange(t, "pve-change-child-clear-fault1", StatePendingApproval, now, "qemu", 100, parent.ID)
	child.PVEMutationVersion = 1
	if err := store.PutChangeWithResourceLock(parent); err != nil {
		t.Fatal(err)
	}
	if err := store.PutChange(child); err != nil {
		t.Fatal(err)
	}
	observation, err := protocol.NewPVERecoveryClearanceObservation(
		"qemu", 100,
		[]protocol.PVERecoveryActiveTaskProbe{{Node: "pve1", VMID: 100, ActiveCount: 0}},
		[]protocol.PVERecoveryGuestState{{Node: "pve1", GuestType: "qemu", VMID: 100, Status: "stopped"}},
		[]protocol.PVERecoveryClusterState{{Type: "node", Name: "pve1", Node: "pve1", NodeID: 0, Local: 1, Online: 1}},
	)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := protocol.FinalizePVERecoveryClearanceChallenge(protocol.PVERecoveryClearanceChallenge{
		Kind: "pve.recovery-clearance-challenge/v1", ClearanceID: "pve-clearance-0123456789abcdef0123456789abcdef",
		ParentChangeID: parent.ID, ChildChangeID: child.ID, ChildPlanHash: child.PlanHash,
		ResourceKey: child.ResourceKey, Observation: observation,
		IssuedAt: timestamp(now), ExpiresAt: timestamp(now.Add(time.Minute)),
	})
	if err != nil {
		t.Fatal(err)
	}
	child.State = StatePreparing
	child.AuthorizationBasis = "approval-key:approver-test-v1"
	child.AuthorizedAt = timestamp(now)
	for _, stage := range []string{"write", "file-sync", "rename"} {
		store.persistFault = func(actual string) error {
			if actual == stage {
				return fmt.Errorf("injected %s failure", stage)
			}
			return nil
		}
		if err := store.PutRecoveryChangeAndTransferResourceWithClearance(child, challenge); err == nil || !strings.Contains(err.Error(), stage) {
			t.Fatalf("injected %s failure was ignored: %v", stage, err)
		}
		storedParent, _ := store.Change(parent.ID)
		storedChild, _ := store.Change(child.ID)
		if storedParent.State != StateRecoveryRequired || storedParent.Resolution != nil || storedChild.State != StatePendingApproval ||
			store.state.ResourceLocks[parent.ResourceKey] != parent.ID {
			t.Fatalf("%s failure partially transferred recovery chain: parent=%#v child=%#v locks=%#v", stage, storedParent, storedChild, store.state.ResourceLocks)
		}
	}
	store.persistFault = nil
	originalDir := store.dir
	store.dir = filepath.Join(originalDir, "missing", "broker-state")
	if err := store.PutRecoveryChangeAndTransferResourceWithClearance(child, challenge); err == nil {
		t.Fatal("injected PVE clearance state persistence failure was ignored")
	}
	storedParent, _ := store.Change(parent.ID)
	storedChild, _ := store.Change(child.ID)
	if storedParent.State != StateRecoveryRequired || storedParent.Resolution != nil || storedChild.State != StatePendingApproval ||
		store.state.ResourceLocks[parent.ResourceKey] != parent.ID {
		t.Fatalf("failed state write partially transferred recovery chain: parent=%#v child=%#v locks=%#v", storedParent, storedChild, store.state.ResourceLocks)
	}
	store.dir = originalDir
	if err := store.PutRecoveryChangeAndTransferResourceWithClearance(child, challenge); err != nil {
		t.Fatalf("valid retry after persistence fault failed: %v", err)
	}
	reopened, err := OpenStoreWithLimits(dir, testStoreLimits(&now))
	if err != nil {
		t.Fatal(err)
	}
	if reopened.state.Changes[parent.ID].State != StateSuperseded ||
		reopened.state.Changes[parent.ID].Resolution == nil ||
		reopened.state.Changes[parent.ID].Resolution.Basis != "local-unknown-clearance" ||
		reopened.state.Changes[parent.ID].Resolution.ParentTaskEvidence == nil ||
		reopened.state.ResourceLocks[parent.ResourceKey] != child.ID {
		t.Fatalf("successful retry was not one durable atomic transfer: %#v", reopened.state)
	}
}

func TestPVEUnknownClearancePostRenameFailureCommitsCandidateAndFailsStop(t *testing.T) {
	for _, stage := range []string{"directory-open", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			now := time.Date(2026, 8, 8, 11, 45, 0, 0, time.UTC)
			dir := t.TempDir()
			store, err := OpenStoreWithLimits(dir, testStoreLimits(&now))
			if err != nil {
				t.Fatal(err)
			}
			parent := testPVEStoredChange(t, "pve-change-parent-post-rename", StateRecoveryRequired, now, "qemu", 100, "")
			parent.PVEMutationVersion = 1
			parent.MutationDisposition = protocol.PVEMutationDispositionUnknown
			child := testPVEStoredChange(t, "pve-change-child-post-rename1", StatePendingApproval, now, "qemu", 100, parent.ID)
			child.PVEMutationVersion = 1
			if err := store.PutChangeWithResourceLock(parent); err != nil {
				t.Fatal(err)
			}
			if err := store.PutChange(child); err != nil {
				t.Fatal(err)
			}
			observation, err := protocol.NewPVERecoveryClearanceObservation(
				"qemu", 100,
				[]protocol.PVERecoveryActiveTaskProbe{{Node: "pve1", VMID: 100, ActiveCount: 0}},
				[]protocol.PVERecoveryGuestState{{Node: "pve1", GuestType: "qemu", VMID: 100, Status: "stopped"}},
				[]protocol.PVERecoveryClusterState{{Type: "node", Name: "pve1", Node: "pve1", NodeID: 0, Local: 1, Online: 1}},
			)
			if err != nil {
				t.Fatal(err)
			}
			challenge, err := protocol.FinalizePVERecoveryClearanceChallenge(protocol.PVERecoveryClearanceChallenge{
				Kind: "pve.recovery-clearance-challenge/v1", ClearanceID: "pve-clearance-fedcba9876543210fedcba9876543210",
				ParentChangeID: parent.ID, ChildChangeID: child.ID, ChildPlanHash: child.PlanHash,
				ResourceKey: child.ResourceKey, Observation: observation,
				IssuedAt: timestamp(now), ExpiresAt: timestamp(now.Add(time.Minute)),
			})
			if err != nil {
				t.Fatal(err)
			}
			child.State = StatePreparing
			child.AuthorizationBasis = "approval-key:approver-test-v1"
			child.AuthorizedAt = timestamp(now)
			store.persistFault = func(actual string) error {
				if actual == stage {
					return fmt.Errorf("injected %s failure", stage)
				}
				return nil
			}

			err = store.PutRecoveryChangeAndTransferResourceWithClearance(child, challenge)
			if err == nil || !strings.Contains(err.Error(), stage) || !strings.Contains(err.Error(), "restart and reopen") {
				t.Fatalf("post-rename %s failure did not enter fail-stop mode: %v", stage, err)
			}
			if err := store.DurabilityError(); err == nil || !strings.Contains(err.Error(), "restart and reopen") {
				t.Fatalf("post-rename %s failure did not remain fail-stop: %v", stage, err)
			}
			storedParent, _ := store.Change(parent.ID)
			storedChild, _ := store.Change(child.ID)
			if storedParent.State != StateSuperseded || storedParent.Resolution == nil ||
				storedParent.Resolution.Basis != "local-unknown-clearance" || storedChild.State != StatePreparing ||
				store.state.ResourceLocks[parent.ResourceKey] != child.ID {
				t.Fatalf("post-rename %s failure kept the predecessor in memory: parent=%#v child=%#v locks=%#v", stage, storedParent, storedChild, store.state.ResourceLocks)
			}
			beforeRejectedWrite, err := os.ReadFile(store.path)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.PutChange(parent); err == nil || !strings.Contains(err.Error(), "restart and reopen") {
				t.Fatalf("post-rename %s store accepted a predecessor rewrite: %v", stage, err)
			}
			afterRejectedWrite, err := os.ReadFile(store.path)
			if err != nil {
				t.Fatal(err)
			}
			if string(beforeRejectedWrite) != string(afterRejectedWrite) {
				t.Fatalf("post-rename %s fail-stop rewrote durable state", stage)
			}

			service := testService(t, now, &fakeExecutor{})
			service.Store = store
			blocked := service.Handle(context.Background(), peercred.Credential{UID: 1001}, protocol.Request{
				Version: protocol.Version, RequestID: "post-rename-fail-stop-request", Method: protocol.MethodHostSnapshot,
				Deadline: now.Add(time.Minute),
			})
			if blocked.Error == "" || !strings.Contains(blocked.Error, "restart and reopen") {
				t.Fatalf("broker served a request after post-rename %s failure: %#v", stage, blocked)
			}

			reopened, err := OpenStoreWithLimits(dir, testStoreLimits(&now))
			if err != nil {
				t.Fatalf("reopen after post-rename %s failure did not validate candidate: %v", stage, err)
			}
			if err := reopened.DurabilityError(); err != nil {
				t.Fatalf("validated reopened store remained fail-stop: %v", err)
			}
			if reopened.state.Changes[parent.ID].State != StateSuperseded ||
				reopened.state.Changes[parent.ID].Resolution == nil ||
				reopened.state.ResourceLocks[parent.ResourceKey] != child.ID {
				t.Fatalf("reopened post-rename %s candidate was incomplete: %#v", stage, reopened.state)
			}
		})
	}
}

func TestClosedPVERecoveryChainSurvivesTTLAndQuotaPruning(t *testing.T) {
	now := time.Date(2026, 8, 8, 11, 30, 0, 0, time.UTC)
	limits := testStoreLimits(&now)
	limits.MaxChanges, limits.MaxPendingChanges = 2, 2
	dir := t.TempDir()
	store, err := OpenStoreWithLimits(dir, limits)
	if err != nil {
		t.Fatal(err)
	}
	parent := testPVEStoredChange(t, "pve-change-prune-parent-0001", StateRecoveryRequired, now, "qemu", 100, "")
	parent.MutationDisposition = protocol.PVEMutationDispositionNotStarted
	parent.PVEMutationVersion = 1
	if err := store.PutChangeWithResourceLock(parent); err != nil {
		t.Fatal(err)
	}
	child := testPVEStoredChange(t, "pve-change-prune-child-00001", StatePreparing, now.Add(time.Minute), "lxc", 100, parent.ID)
	child.PVEMutationVersion = 1
	child.AuthorizationBasis = "local-uid:0"
	child.AuthorizedAt = timestamp(now.Add(time.Minute))
	if err := store.PutRecoveryChangeAndTransferResource(child, PVERecoveryReadiness{
		MutationDisposition: protocol.PVEMutationDispositionNotStarted,
	}); err != nil {
		t.Fatal(err)
	}
	child.State = StateCommitted
	child.UpdatedAt = timestamp(now.Add(2 * time.Minute))
	if err := store.PutChangeAndReleaseResource(child); err != nil {
		t.Fatal(err)
	}

	now = now.Add(2 * time.Hour)
	unrelated := testStoredChange("change-quota-trigger", StateRejected, now)
	if err := store.PutChange(unrelated); err == nil || !strings.Contains(err.Error(), "quota") {
		t.Fatalf("quota pruning split or displaced a closed recovery chain: %v", err)
	}
	if _, ok := store.Change(parent.ID); !ok {
		t.Fatal("TTL hid the retained recovery parent")
	}
	if _, ok := store.Change(child.ID); !ok {
		t.Fatal("TTL hid the selected recovery child")
	}
	reopened, err := OpenStoreWithLimits(dir, limits)
	if err != nil {
		t.Fatalf("reopen after TTL/quota pruning found a dangling chain: %v", err)
	}
	if len(reopened.state.Changes) != 2 || reopened.state.Changes[parent.ID].Resolution == nil ||
		reopened.state.Changes[parent.ID].Resolution.ChildChangeID != child.ID {
		t.Fatalf("closed recovery chain was not retained atomically: %#v", reopened.state.Changes)
	}
}

func testPVEStoredChange(t *testing.T, id, state string, updatedAt time.Time, guestType string, vmid int, recoveryOf string) *Change {
	t.Helper()
	operation := &protocol.PVEGuestAction{
		OperationKind: "pve.guest.action", PluginID: testPVEPluginID,
		PluginDigest: "sha256:" + strings.Repeat("d", 64), RecoveryOfChangeID: recoveryOf,
		Node: "pve1", GuestType: guestType, VMID: vmid, Action: "start",
	}
	fields := []protocol.ApprovalPlanField{{Name: "currentStatus", Value: "stopped"}, {Name: "currentLock", Value: "unlocked"}}
	preconditionDigest, err := protocol.ApprovalPreconditionDigest(fields)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := protocol.BuildApprovalPlanWithPreconditions(operation, "policy-pve-12345678", protocol.CapabilityRevision, preconditionDigest, fields)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := protocol.MarshalOperation(operation)
	if err != nil {
		t.Fatal(err)
	}
	return &Change{
		ID: id, ServerID: "server-pve-12345678", MachineID: "machine-pve-12345678", TargetID: "target-pve-root",
		PolicyRevision: "policy-pve-12345678", CapabilityRevision: protocol.CapabilityRevision,
		PreconditionDigest: preconditionDigest, PreconditionFields: fields,
		ResourceKey: fmt.Sprintf("pve/vmid/%d", vmid), RecoveryOfChangeID: recoveryOf,
		PlanHash: plan.PlanHash, Kind: operation.Kind(), Summary: operation.Summary(), Operation: payload,
		State: state, PreparedAt: timestamp(updatedAt), UpdatedAt: timestamp(updatedAt),
	}
}

func writeTestState(t *testing.T, dir string, state persistedState) {
	t.Helper()
	payload, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
}

func testStoreLimits(now *time.Time) StoreLimits {
	return StoreLimits{
		MaxChanges: 16, MaxPendingChanges: 8, MaxRequests: 8, MaxApprovalNonces: 8,
		MaxStateBytes: 512 * 1024, PendingChangeTTL: time.Hour, TerminalChangeTTL: time.Hour,
		RequestTTL: 10 * time.Minute, ApprovalNonceTTL: 5 * time.Minute,
		Now: func() time.Time { return *now },
	}
}

func testStoredChange(id, state string, updatedAt time.Time) *Change {
	operation, _ := json.Marshal(&protocol.PackageInstall{OperationKind: "package.install", Package: "example"})
	return &Change{
		ID: id, PlanHash: "sha256:" + strings.Repeat("a", 64), Kind: "package.install", Summary: "install package example",
		Operation: operation, State: state, PreparedAt: timestamp(updatedAt), UpdatedAt: timestamp(updatedAt),
	}
}
