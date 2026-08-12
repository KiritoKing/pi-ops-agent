package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBrokerReceiptBindsRequestScopeAndCompleteResult(t *testing.T) {
	now := time.Date(2026, 8, 8, 10, 0, 0, 123456000, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	planHash := "sha256:" + strings.Repeat("a", 64)
	response := Response{
		Version: Version, RequestID: "status-request-0001", OK: true,
		AuditID:  "audit-0123456789abcdef0123456789abcdef",
		ChangeID: "change-0123456789abcdef0123456789abcdef", State: "COMMITTED",
		Summary: "change committed",
		Data: map[string]interface{}{
			"plan":              map[string]interface{}{"version": 1, "steps": []interface{}{"one", "two"}},
			"rollbackAvailable": true,
		},
	}
	claims := BrokerReceiptClaims{
		KeyID: "core-receipt-v1", Domain: "core", RequestID: response.RequestID,
		Method: MethodChangeStatus, ServerID: "server-12345678", MachineID: "machine-12345678",
		TargetID: "target-12345678", ChangeID: response.ChangeID, PlanHash: planHash,
	}
	signed, err := SignBrokerResponse(response, claims, now, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Receipt == nil || signed.Receipt.Action != "status" || signed.Receipt.ResultDigest == "" {
		t.Fatalf("signed response omitted claims: %#v", signed.Receipt)
	}
	if signed.Receipt.ResultDigest != "sha256:592c0d9bc3006a0d3c2238c1e5d3a7689a94404f47a36ccdc4a0ab42603a61e7" {
		t.Fatalf("cross-language broker result digest drifted: %s", signed.Receipt.ResultDigest)
	}
	if err := VerifyBrokerResponse(signed, claims, now, publicKey); err != nil {
		t.Fatalf("valid signed response was rejected: %v", err)
	}

	otherPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongKeyID := claims
	wrongKeyID.KeyID = "other-receipt-v1"
	wrongDomain := claims
	wrongDomain.Domain = "pve"
	wrongRequest := claims
	wrongRequest.RequestID = "status-request-0002"
	wrongMethod := claims
	wrongMethod.Method = MethodChangeReject
	wrongChange := claims
	wrongChange.ChangeID = "change-fedcba9876543210fedcba9876543210"
	wrongPlan := claims
	wrongPlan.PlanHash = "sha256:" + strings.Repeat("b", 64)

	checks := []struct {
		name     string
		response Response
		claims   BrokerReceiptClaims
		key      ed25519.PublicKey
	}{
		{name: "wrong key", response: signed, claims: claims, key: otherPublicKey},
		{name: "wrong key id", response: signed, claims: wrongKeyID, key: publicKey},
		{name: "wrong domain", response: signed, claims: wrongDomain, key: publicKey},
		{name: "wrong request", response: signed, claims: wrongRequest, key: publicKey},
		{name: "wrong method", response: signed, claims: wrongMethod, key: publicKey},
		{name: "wrong change", response: signed, claims: wrongChange, key: publicKey},
		{name: "wrong plan", response: signed, claims: wrongPlan, key: publicKey},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := VerifyBrokerResponse(check.response, check.claims, now, check.key); err == nil {
				t.Fatal("mismatched broker receipt was accepted")
			}
		})
	}

	tamperedResult := signed
	tamperedResult.Summary = "fabricated committed result"
	if err := VerifyBrokerResponse(tamperedResult, claims, now, publicKey); err == nil {
		t.Fatal("tampered broker result was accepted")
	}
	tamperedAction := cloneResponseReceipt(signed)
	tamperedAction.Receipt.Action = "approve"
	if err := VerifyBrokerResponse(tamperedAction, claims, now, publicKey); err == nil {
		t.Fatal("tampered broker action was accepted")
	}
	tamperedState := cloneResponseReceipt(signed)
	tamperedState.Receipt.State = "ROLLED_BACK"
	if err := VerifyBrokerResponse(tamperedState, claims, now, publicKey); err == nil {
		t.Fatal("tampered broker state was accepted")
	}
	tamperedSignature := cloneResponseReceipt(signed)
	tamperedSignature.Receipt.Signature = strings.Repeat("A", len(tamperedSignature.Receipt.Signature))
	if err := VerifyBrokerResponse(tamperedSignature, claims, now, publicKey); err == nil {
		t.Fatal("tampered broker signature was accepted")
	}
}

func TestBrokerReceiptPVEKeyAndChangeDomainAreSeparate(t *testing.T) {
	now := time.Date(2026, 8, 8, 10, 30, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	response := Response{
		Version: Version, RequestID: "approve-pve-request-1", OK: true,
		AuditID:  "audit-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ChangeID: "pve-change-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", State: "COMMITTED",
		Summary: "PVE change committed",
	}
	claims := BrokerReceiptClaims{
		KeyID: "pve-receipt-v1", Domain: "pve", RequestID: response.RequestID,
		Method: MethodChangeApprove, ServerID: "server-pve-0001", MachineID: "machine-pve-0001",
		TargetID: "target-pve-0001", ChangeID: response.ChangeID,
		PlanHash: "sha256:" + strings.Repeat("c", 64),
	}
	signed, err := SignBrokerResponse(response, claims, now, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Receipt.Action != "approve" {
		t.Fatalf("unexpected PVE action %q", signed.Receipt.Action)
	}
	if err := VerifyBrokerResponse(signed, claims, now, publicKey); err != nil {
		t.Fatal(err)
	}

	coreClaims := claims
	coreClaims.Domain = "core"
	if _, err := SignBrokerResponse(response, coreClaims, now, privateKey); err == nil {
		t.Fatal("core receipt signed a PVE change ID")
	}
}

func TestBrokerReceiptBindsWorkloadCommandProfileAndResult(t *testing.T) {
	now := time.Date(2026, 8, 8, 10, 20, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	response := Response{
		Version: Version, RequestID: "command-inspect-0001", OK: true,
		AuditID: "audit-0123456789abcdef0123456789abcdef",
		Data: map[string]interface{}{
			"kind": "workload.command.inspect-result/v1", "pluginId": "workload.example-command",
			"pluginDigest": digest, "profileKey": "example.status", "output": "ok\n",
		},
	}
	claims := BrokerReceiptClaims{
		KeyID: "core-receipt-v1", Domain: "core", RequestID: response.RequestID,
		Method: MethodWorkloadCommandInspect, ServerID: "server-12345678",
		MachineID: "machine-12345678", TargetID: "target-12345678",
		PluginID: "workload.example-command", PluginDigest: digest, ProfileKey: "example.status",
	}
	signed, err := SignBrokerResponse(response, claims, now, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Receipt == nil || signed.Receipt.Action != "inspect" || signed.Receipt.ChangeID != "" || signed.Receipt.State != "" {
		t.Fatalf("unexpected command receipt: %#v", signed.Receipt)
	}
	if err := VerifyBrokerResponse(signed, claims, now, publicKey); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*BrokerReceiptClaims){
		func(value *BrokerReceiptClaims) { value.PluginID = "workload.other" },
		func(value *BrokerReceiptClaims) { value.PluginDigest = "sha256:" + strings.Repeat("b", 64) },
		func(value *BrokerReceiptClaims) { value.ProfileKey = "example.other" },
	} {
		other := claims
		mutate(&other)
		if err := VerifyBrokerResponse(signed, other, now, publicKey); err == nil {
			t.Fatal("command receipt accepted a different workload profile scope")
		}
	}
	tampered := signed
	tampered.Data = map[string]interface{}{"output": "fabricated"}
	if err := VerifyBrokerResponse(tampered, claims, now, publicKey); err == nil {
		t.Fatal("command receipt accepted a tampered result")
	}
	wrongDomain := claims
	wrongDomain.Domain = "pve"
	if _, err := SignBrokerResponse(response, wrongDomain, now, privateKey); err == nil {
		t.Fatal("PVE key domain signed a core workload command")
	}
}

func TestBrokerReceiptActionVocabularyIsClosed(t *testing.T) {
	now := time.Date(2026, 8, 8, 10, 45, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for index, test := range []struct {
		method Method
		action string
		state  string
	}{
		{method: MethodChangeStatus, action: "status", state: "PENDING_APPROVAL"},
		{method: MethodChangeStatus, action: "status", state: "SUPERSEDED"},
		{method: MethodChangeApprove, action: "approve", state: "COMMITTED"},
		{method: MethodChangeReject, action: "reject", state: "REJECTED"},
		{method: MethodChangeRollback, action: "rollback", state: "ROLLED_BACK"},
	} {
		requestID := "receipt-action-request-" + strconv.Itoa(index)
		response := Response{
			Version: Version, RequestID: requestID, OK: true,
			AuditID:  "audit-dddddddddddddddddddddddddddddddd",
			ChangeID: "change-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", State: test.state,
		}
		claims := BrokerReceiptClaims{
			KeyID: "core-receipt-v1", Domain: "core", RequestID: requestID, Method: test.method,
			ServerID: "server-12345678", MachineID: "machine-12345678", TargetID: "target-12345678",
			ChangeID: response.ChangeID, PlanHash: "sha256:" + strings.Repeat("f", 64),
		}
		signed, err := SignBrokerResponse(response, claims, now, privateKey)
		if err != nil || signed.Receipt.Action != test.action {
			t.Fatalf("sign %s: receipt=%#v err=%v", test.method, signed.Receipt, err)
		}
		if err := VerifyBrokerResponse(signed, claims, now, publicKey); err != nil {
			t.Fatalf("verify %s: %v", test.method, err)
		}
	}
}

func TestCanonicalBrokerResultRejectsLossyNumbers(t *testing.T) {
	response := Response{
		Version: Version, RequestID: "status-number-0001",
		Data: map[string]interface{}{"fraction": 1.5},
	}
	if _, err := CanonicalBrokerResultDigest(response); err == nil {
		t.Fatal("fractional response data was accepted into the cross-language receipt digest")
	}
	response.Data = map[string]interface{}{"tooLarge": float64(1 << 54)}
	if _, err := CanonicalBrokerResultDigest(response); err == nil {
		t.Fatal("lossy integer response data was accepted into the receipt digest")
	}
}

func cloneResponseReceipt(response Response) Response {
	clone := response
	if response.Receipt != nil {
		receipt := *response.Receipt
		clone.Receipt = &receipt
	}
	return clone
}
