package roothelper

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/peercred"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

func TestRootBrokerSignsStatusAndActionAfterDurableAudit(t *testing.T) {
	now := time.Date(2026, 8, 8, 11, 0, 0, 0, time.UTC)
	receiptPublic, receiptPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	approvalPublic, approvalPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service := testService(t, now, &fakeExecutor{})
	service.Policy = testTargetPolicy(t, t.TempDir(), "policy-12345678")
	service.Approval = &ApprovalVerifier{KeyID: "approver-test-v1", PublicKey: approvalPublic}
	service.ReceiptSigner, err = NewBrokerReceiptSigner("core-receipt-v1", DomainCore, receiptPrivate)
	if err != nil {
		t.Fatal(err)
	}
	serverPeer := peercred.Credential{UID: 1001}
	prepared := service.Handle(context.Background(), serverPeer, parseRemoteRequest(t, now, "prepare-receipt-0001", "agent", `"method":"change.prepare","operation":{"kind":"package.install","package":"example"}`))
	if !prepared.OK || prepared.ChangeID == "" {
		t.Fatalf("prepare failed: %#v", prepared)
	}
	change, ok := service.Store.Change(prepared.ChangeID)
	if !ok {
		t.Fatal("prepared change was not persisted")
	}

	statusRequest := parseRemoteRequest(t, now, "status-receipt-0001", "approver", fmt.Sprintf(`"method":"change.status","changeId":%q`, change.ID))
	status := service.Handle(context.Background(), serverPeer, statusRequest)
	statusClaims := protocol.BrokerReceiptClaims{
		KeyID: "core-receipt-v1", Domain: DomainCore, RequestID: statusRequest.RequestID,
		Method: protocol.MethodChangeStatus, ServerID: change.ServerID, MachineID: change.MachineID,
		TargetID: change.TargetID, ChangeID: change.ID, PlanHash: change.PlanHash,
	}
	if status.Receipt == nil || status.AuditID == "" || status.State != StatePendingApproval {
		t.Fatalf("status was not signed after state and audit: %#v", status)
	}
	if err := protocol.VerifyBrokerResponse(status, statusClaims, now, receiptPublic); err != nil {
		t.Fatalf("status receipt did not verify: %v", err)
	}

	grant := signedGrant(t, approvalPrivate, now, "approve", change)
	grantJSON, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	actionRequest := parseRemoteRequest(t, now, "approve-receipt-001", "approver", fmt.Sprintf(`"method":"change.approve","changeId":%q,"approval":%s`, change.ID, grantJSON))
	action := service.Handle(context.Background(), serverPeer, actionRequest)
	actionClaims := statusClaims
	actionClaims.RequestID = actionRequest.RequestID
	actionClaims.Method = protocol.MethodChangeApprove
	if !action.OK || action.State != StateCommitted || action.Receipt == nil || action.AuditID == "" {
		t.Fatalf("action was not signed after commit and audit: %#v", action)
	}
	if err := protocol.VerifyBrokerResponse(action, actionClaims, now, receiptPublic); err != nil {
		t.Fatalf("action receipt did not verify: %v", err)
	}

	tampered := action
	tampered.State = StateRolledBack
	if err := protocol.VerifyBrokerResponse(tampered, actionClaims, now, receiptPublic); err == nil {
		t.Fatal("server-fabricated terminal state was accepted")
	}
	// A persistent action retry returns the exact already-signed result, rather
	// than asking the mutable server to reconstruct a terminal response.
	replayed := service.Handle(context.Background(), serverPeer, actionRequest)
	if replayed.Receipt == nil || replayed.Receipt.Signature != action.Receipt.Signature {
		t.Fatalf("idempotent action did not replay its signed result: %#v", replayed)
	}
}

func TestSignedStatusUsesImmutableSnapshotAcrossConcurrentCommit(t *testing.T) {
	now := time.Date(2026, 8, 10, 3, 0, 0, 0, time.UTC)
	receiptPublic, receiptPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service := testService(t, now, &fakePVEExecutor{})
	service.Domain = DomainPVE
	service.ReceiptSigner, err = NewBrokerReceiptSigner("pve-receipt-v1", DomainPVE, receiptPrivate)
	if err != nil {
		t.Fatal(err)
	}
	change := testPVEStoredChange(
		t, "pve-change-status-sign-race-0001", StateExecuting, now, "qemu", 100, "",
	)
	change.PVEMutationVersion = 1
	if err := service.Store.PutChange(change); err != nil {
		t.Fatalf("persist EXECUTING race fixture: %v", err)
	}
	request := protocol.Request{
		Version: protocol.Version, RequestID: "status-sign-race-executing", Deadline: now.Add(time.Minute),
		Method: protocol.MethodChangeStatus, ServerID: change.ServerID, MachineID: change.MachineID,
		TargetID: change.TargetID, PolicyRevision: change.PolicyRevision,
		CapabilityRevision: change.CapabilityRevision, ChangeID: change.ID,
		Raw: []byte("status-sign-race-executing"),
	}

	// Pause exactly after status() has built and audited the EXECUTING Store
	// snapshot, when Handle evaluates the signing timestamp. A simulated fast
	// worker commits before receipt signing resumes.
	signingReached := make(chan struct{})
	releaseSigning := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseSigning) }) }
	defer release()
	var nowCalls atomic.Int32
	service.Now = func() time.Time {
		if nowCalls.Add(1) == 2 {
			close(signingReached)
			<-releaseSigning
		}
		return now
	}
	responses := make(chan protocol.Response, 1)
	go func() {
		responses <- service.Handle(
			context.Background(), peercred.Credential{UID: service.AgentUID}, request,
		)
	}()
	select {
	case <-signingReached:
	case <-time.After(time.Second):
		t.Fatal("status did not reach the deterministic receipt-signing barrier")
	}

	commitResult := make(chan error, 1)
	go func() {
		unlock := service.lockChange(change.ID)
		defer unlock()
		current, ok := service.Store.Change(change.ID)
		if !ok {
			commitResult <- fmt.Errorf("race fixture change disappeared")
			return
		}
		current.State = StateCommitted
		current.Verification = "fast fake-PVE task committed"
		current.UpdatedAt = timestamp(now.Add(time.Second))
		commitResult <- service.Store.PutChange(current)
	}()
	select {
	case err := <-commitResult:
		if err != nil {
			release()
			t.Fatalf("simulated fast worker could not commit: %v", err)
		}
	case <-time.After(time.Second):
		release()
		t.Fatal("status snapshot blocked the simulated fast worker")
	}
	durable, ok := service.Store.Change(change.ID)
	if !ok || durable.State != StateCommitted {
		release()
		t.Fatalf("simulated worker did not durably commit before receipt signing: %#v", durable)
	}

	release()
	var response protocol.Response
	select {
	case response = <-responses:
	case <-time.After(time.Second):
		t.Fatal("status did not finish after releasing the receipt-signing barrier")
	}
	claims := protocol.BrokerReceiptClaims{
		KeyID: "pve-receipt-v1", Domain: DomainPVE, RequestID: request.RequestID,
		Method: protocol.MethodChangeStatus, ServerID: change.ServerID, MachineID: change.MachineID,
		TargetID: change.TargetID, ChangeID: change.ID, PlanHash: change.PlanHash,
	}
	if !response.OK || response.State != StateExecuting || response.Receipt == nil {
		t.Fatalf("status lost its signed EXECUTING snapshot during fast commit: %#v", response)
	}
	if err := protocol.VerifyBrokerResponse(response, claims, now, receiptPublic); err != nil {
		t.Fatalf("EXECUTING status receipt did not verify: %v", err)
	}

	fresh := request
	fresh.RequestID = "status-sign-race-committed"
	fresh.Raw = []byte(fresh.RequestID)
	committed := service.Handle(
		context.Background(), peercred.Credential{UID: service.AgentUID}, fresh,
	)
	claims.RequestID = fresh.RequestID
	if !committed.OK || committed.State != StateCommitted || committed.Receipt == nil {
		t.Fatalf("fresh status did not observe signed COMMITTED state: %#v", committed)
	}
	if err := protocol.VerifyBrokerResponse(committed, claims, now, receiptPublic); err != nil {
		t.Fatalf("COMMITTED status receipt did not verify: %v", err)
	}
}

func TestConfiguredReceiptSignerFailsClosedOnDomainMismatch(t *testing.T) {
	now := time.Date(2026, 8, 8, 11, 30, 0, 0, time.UTC)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service := testService(t, now, &fakeExecutor{})
	service.ReceiptSigner, err = NewBrokerReceiptSigner("pve-receipt-v1", DomainPVE, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	response := service.Handle(context.Background(), peercred.Credential{UID: 1001}, parseRequest(t, now, "prepare-domain-sign-1", `"method":"change.prepare","operation":{"kind":"package.install","package":"example"}`))
	if response.OK || !strings.Contains(response.Error, "does not match") {
		t.Fatalf("mismatched configured receipt signer did not fail closed: %#v", response)
	}
}

func TestLoadBrokerReceiptSignerRequiresOwnerOnlyEd25519PKCS8(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "receipt.key")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBrokerReceiptSigner("core-receipt-v1", DomainCore, path, false); err != nil {
		t.Fatalf("valid owner-only key was rejected: %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBrokerReceiptSigner("core-receipt-v1", DomainCore, path, false); err == nil {
		t.Fatal("group-readable broker receipt private key was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(filepath.Dir(path), "receipt-link.key")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBrokerReceiptSigner("core-receipt-v1", DomainCore, symlink, false); err == nil {
		t.Fatal("symlinked broker receipt private key was accepted")
	}
}
