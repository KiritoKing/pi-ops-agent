package targetpolicy

import (
	"fmt"
	"strings"
	"testing"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

const testPVEPluginID = "workload.pve"

func TestPVEPolicyBindsDigestResourcesAndOperations(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	policy := parsePVEPolicyForTest(t, digest)

	read := protocol.Request{
		Method: protocol.MethodPVEGuestStatus, TargetID: "target-pve-root",
		PolicyRevision: policy.Revision,
		PVE: protocol.PVEInspection{
			PluginID: "workload.example-pve", PluginDigest: digest,
			Node: "pve1", GuestType: "qemu", VMID: 100,
		},
	}
	if err := policy.Authorize(read); err != nil {
		t.Fatalf("approved PVE guest read was denied: %v", err)
	}
	read.PVE.VMID = 999
	if err := policy.Authorize(read); err == nil {
		t.Fatal("unlisted PVE guest read was authorized")
	}
	read.PVE.VMID = 100
	read.PVE.PluginID = testPVEPluginID
	if err := policy.Authorize(read); err == nil {
		t.Fatal("PVE inspection with a different workload identity was authorized")
	}
	read.PVE.PluginID = "workload.example-pve"
	read.PVE.PluginDigest = "sha256:" + strings.Repeat("b", 64)
	if err := policy.Authorize(read); err == nil {
		t.Fatal("PVE inspection with a different source digest was authorized")
	}

	operation := &protocol.PVEGuestMigrate{
		OperationKind: "pve.guest.migrate", PluginID: "workload.example-pve",
		PluginDigest: digest, Node: "pve1", GuestType: "qemu", VMID: 100,
		TargetNode: "pve2", Online: true, WithLocalDisks: true,
	}
	if err := policy.AuthorizeOperation("target-pve-root", operation); err != nil {
		t.Fatalf("approved PVE migration was denied: %v", err)
	}
	operation.PluginID = testPVEPluginID
	if err := policy.AuthorizeOperation("target-pve-root", operation); err == nil {
		t.Fatal("PVE operation with a different workload identity was authorized")
	}
	operation.PluginID = "workload.example-pve"
	operation.PluginDigest = "sha256:" + strings.Repeat("b", 64)
	if err := policy.AuthorizeOperation("target-pve-root", operation); err == nil {
		t.Fatal("PVE operation with a different source digest was authorized")
	}
	operation.PluginDigest, operation.TargetNode = digest, "pve3"
	if err := policy.AuthorizeOperation("target-pve-root", operation); err == nil {
		t.Fatal("PVE operation with an unlisted migration target was authorized")
	}
}

func TestPVEPolicyRejectsUnknownOrOverbroadShape(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	valid := pvePolicyPayload(digest)
	for _, invalid := range []string{
		strings.Replace(valid, `"account":"root"`, `"account":"operator"`, 1),
		strings.Replace(valid, `"workload.example-pve"`, `"adapter.example-pve"`, 1),
		strings.Replace(valid, `"workload.example-pve"`, `"workload.Example-pve"`, 1),
		strings.Replace(valid, `"pluginDigest":`, `"command":"pvesh get /nodes","pluginDigest":`, 1),
		strings.Replace(valid, `"migrationTargets":["pve2"]`, `"migrationTargets":["pve3"]`, 1),
		strings.Replace(valid, `"operations":[`, `"operations":["pve.raw.exec",`, 1),
	} {
		if _, err := Parse([]byte(invalid)); err == nil {
			t.Fatalf("unsafe PVE policy was accepted: %s", invalid)
		}
	}
}

func parsePVEPolicyForTest(t *testing.T, digest string) *Policy {
	t.Helper()
	policy, err := Parse([]byte(pvePolicyPayload(digest)))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func pvePolicyPayload(digest string) string {
	return fmt.Sprintf(`{"version":1,"revision":"policy-pve-12345678","targets":[{"id":"target-pve-root","account":"root","displayName":"PVE root","inspect":{"hostSnapshot":true,"processList":true,"units":[],"readPaths":[]},"changes":{"writePaths":[],"units":[],"packages":[],"plugins":[]},"pve":{"pluginId":"workload.example-pve","pluginDigest":%q,"nodes":["pve1","pve2"],"storages":["local","local-lvm"],"guests":[{"guestType":"qemu","vmid":100},{"guestType":"lxc","vmid":101}],"migrationTargets":["pve2"],"operations":["pve.guest.backup","pve.guest.migrate","pve.guest.restore","pve.guest.shutdown","pve.guest.start","pve.snapshot.create","pve.snapshot.delete","pve.snapshot.rollback"]}}]}`, digest)
}
