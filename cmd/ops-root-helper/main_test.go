package main

import (
	"strings"
	"testing"
)

func TestValidateRemoteSecurityConfig(t *testing.T) {
	tests := []struct {
		name               string
		targetPolicyFile   string
		approvalKeyID      string
		approvalPublicKey  string
		receiptKeyID       string
		receiptPrivateKey  string
		wantErrorSubstring string
	}{
		{name: "local mode may omit remote trust material"},
		{
			name: "receipt pair is atomic", receiptKeyID: "receipt-v1",
			wantErrorSubstring: "configured together",
		},
		{
			name: "remote mode requires approval public key", targetPolicyFile: "/etc/ops-agent/targets.json",
			approvalKeyID: "approver-v1", receiptKeyID: "receipt-v1", receiptPrivateKey: "/etc/ops-agent/receipt.key",
			wantErrorSubstring: "approval key ID and public key",
		},
		{
			name: "remote mode requires approval key ID", targetPolicyFile: "/etc/ops-agent/targets.json",
			approvalPublicKey: "/etc/ops-agent/approval.pub.pem", receiptKeyID: "receipt-v1", receiptPrivateKey: "/etc/ops-agent/receipt.key",
			wantErrorSubstring: "approval key ID and public key",
		},
		{
			name: "remote mode requires receipt signer", targetPolicyFile: "/etc/ops-agent/targets.json",
			approvalKeyID: "approver-v1", approvalPublicKey: "/etc/ops-agent/approval.pub.pem",
			wantErrorSubstring: "receipt signing key",
		},
		{
			name: "remote mode accepts complete trust material", targetPolicyFile: "/etc/ops-agent/targets.json",
			approvalKeyID: "approver-v1", approvalPublicKey: "/etc/ops-agent/approval.pub.pem",
			receiptKeyID: "receipt-v1", receiptPrivateKey: "/etc/ops-agent/receipt.key",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateRemoteSecurityConfig(test.targetPolicyFile, test.approvalKeyID,
				test.approvalPublicKey, test.receiptKeyID, test.receiptPrivateKey)
			if test.wantErrorSubstring == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErrorSubstring) {
				t.Fatalf("expected error containing %q, got %v", test.wantErrorSubstring, err)
			}
		})
	}
}
