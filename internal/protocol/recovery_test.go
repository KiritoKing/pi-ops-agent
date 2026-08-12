package protocol

import "testing"

func TestLegacyPlanHashV02MatchesPersistedAlgorithmVector(t *testing.T) {
	operation := []byte(`{"kind":"service.action","unit":"demo.service","action":"restart"}`)
	got := LegacyPlanHashV02(
		"server-12345678", "machine-12345678", "target-12345678",
		"policy-v2", "capability-v2", operation,
	)
	const want = "sha256:e729bd8ba0454b58c15fab8f2b1d3069ee0986c06a6de01c933e455f76b5b9af"
	if got != want {
		t.Fatalf("legacy plan hash=%q, want %q", got, want)
	}
}

func TestRecoveryDescriptorRejectsUnboundCompatibleBackup(t *testing.T) {
	descriptor := RecoveryDescriptor{
		Version: Version, CompatibilityVersion: LegacyPlanCompatibilityV02,
		OriginalKind: "file.write", OriginalTarget: "/etc/demo.conf", OriginalAction: "file.write",
		CompensationTarget: "/etc/demo.conf", CompensationAction: "file.restore",
		RollbackDataDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		BackupObjects:      []RecoveryBackupObject{{Reference: "/var/lib/ops-agent/state/changes/change-1234/file.backup"}},
		RollbackCompatible: true,
	}
	if err := descriptor.Validate(); err == nil {
		t.Fatal("compatible recovery descriptor accepted an undigested backup object")
	}
}
