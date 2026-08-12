package agentserver

import (
	"context"
	"strings"
	"testing"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

const testPVEPluginID = "workload.pve"

func TestRoutingBackendSeparatesCoreAndPVERequests(t *testing.T) {
	core := &fakeBackend{}
	pve := &fakeBackend{}
	router := RoutingBackend{Core: core, PVE: pve}
	digest := "sha256:" + strings.Repeat("a", 64)
	tests := []protocol.Request{
		{Method: protocol.MethodHostSnapshot},
		{Method: protocol.MethodPVEClusterStatus},
		{Method: protocol.MethodChangePrepare, Operation: &protocol.PVEGuestAction{
			OperationKind: "pve.guest.action", PluginID: testPVEPluginID,
			PluginDigest: digest, Node: "pve1", GuestType: "qemu", VMID: 100, Action: "start",
		}},
		{Method: protocol.MethodChangeStatus, ChangeID: "pve-change-12345678"},
		{Method: protocol.MethodChangeStatus, ChangeID: "change-12345678"},
	}
	for _, request := range tests {
		if _, err := router.Do(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	if len(core.requests) != 2 || len(pve.requests) != 3 {
		t.Fatalf("request domains were mixed: core=%#v pve=%#v", core.requests, pve.requests)
	}
}

func TestRoutingBackendFailsClosedWhenPVEHelperIsUnavailable(t *testing.T) {
	router := RoutingBackend{Core: &fakeBackend{}}
	_, err := router.Do(context.Background(), protocol.Request{Method: protocol.MethodPVEClusterStatus})
	if err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("missing PVE broker was not rejected: %v", err)
	}
}
