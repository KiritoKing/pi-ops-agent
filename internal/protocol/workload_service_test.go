package protocol

import (
	"strings"
	"testing"
	"time"
)

const testWorkloadDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestWorkloadServiceIdentityAndUnitValidationAreGenericButBounded(t *testing.T) {
	for _, pluginID := range []string{
		"workload.example-service", "workload.example-hermes", "workload.example-botmux",
	} {
		if !ValidWorkloadPluginID(pluginID) {
			t.Fatalf("valid source workload identity %q was rejected", pluginID)
		}
	}
	for _, pluginID := range []string{
		"adapter.example-service", "workload.Example", "workload.example-", "workload.",
	} {
		if ValidWorkloadPluginID(pluginID) {
			t.Fatalf("invalid source workload identity %q was accepted", pluginID)
		}
	}
	for _, unit := range []string{
		"example.service", "example-daemon@blue.service", "hermes-gateway.service", "botmux.service",
	} {
		if !ValidWorkloadServiceUnit(unit) {
			t.Fatalf("valid systemd service unit %q was rejected", unit)
		}
	}
	for _, unit := range []string{"example", "../example.service", "example.socket", "example service.service"} {
		if ValidWorkloadServiceUnit(unit) {
			t.Fatalf("invalid systemd service unit %q was accepted", unit)
		}
	}
}

func TestWorkloadServiceActionStrictShapeAndPlan(t *testing.T) {
	now := time.Now().UTC()
	payload := `{"version":1,"requestId":"workload-service-0001","deadline":"` + now.Add(time.Minute).Format(time.RFC3339Nano) + `","method":"change.prepare","operation":{"kind":"workload.service.action","pluginId":"workload.example-service","pluginDigest":"` + testWorkloadDigest + `","account":"alice","manager":"user","unit":"example-daemon@blue.service","action":"restart"}}`
	request, err := ParseRequest([]byte(payload), now)
	if err != nil {
		t.Fatal(err)
	}
	operation, ok := request.Operation.(*WorkloadServiceAction)
	if !ok || operation.Account != "alice" || operation.Manager != "user" || operation.Action != "restart" {
		t.Fatalf("unexpected operation: %#v", request.Operation)
	}
	plan, err := BuildApprovalPlan(operation, "policy-12345678", CapabilityRevision)
	if err != nil {
		t.Fatal(err)
	}
	if plan.PluginDigest != testWorkloadDigest || len(plan.Steps) != 1 || plan.Steps[0].Reversible {
		t.Fatalf("workload service plan omitted digest or claimed rollback: %#v", plan)
	}
	encoded := string(mustMarshalOperation(t, operation))
	for _, expected := range []string{`"pluginId":"workload.example-service"`, `"account":"alice"`, `"manager":"user"`, `"unit":"example-daemon@blue.service"`, `"action":"restart"`} {
		if !strings.Contains(encoded, expected) {
			t.Fatalf("marshaled operation omitted %s: %s", expected, encoded)
		}
	}
	other := *operation
	other.PluginID = "workload.other-service"
	otherPlan, err := BuildApprovalPlan(&other, "policy-12345678", CapabilityRevision)
	if err != nil {
		t.Fatal(err)
	}
	if otherPlan.PlanHash == plan.PlanHash {
		t.Fatal("custom workload identity was not bound into the canonical approval plan")
	}
}

func TestWorkloadServiceActionRejectsUnboundedVariants(t *testing.T) {
	base := WorkloadServiceAction{
		OperationKind: "workload.service.action", PluginID: "workload.example-service",
		PluginDigest: testWorkloadDigest, Account: "alice", Manager: "user",
		Unit: "example.service", Action: "restart",
	}
	tests := []struct {
		name   string
		mutate func(*WorkloadServiceAction)
	}{
		{"raw action", func(value *WorkloadServiceAction) { value.Action = "daemon-reload" }},
		{"adapter plugin", func(value *WorkloadServiceAction) { value.PluginID = "adapter.example-service" }},
		{"malformed workload plugin", func(value *WorkloadServiceAction) { value.PluginID = "workload.Example" }},
		{"raw unit", func(value *WorkloadServiceAction) { value.Unit = "../../ssh.service" }},
		{"root account", func(value *WorkloadServiceAction) { value.Account = "Root" }},
		{"unknown manager", func(value *WorkloadServiceAction) { value.Manager = "session" }},
		{"bad digest", func(value *WorkloadServiceAction) { value.PluginDigest = "sha256:bad" }},
	}
	for _, action := range []string{"reload", "reset-failed", "restart", "start", "stop"} {
		value := base
		value.Action = action
		if err := value.Validate(); err != nil {
			t.Fatalf("bounded workload service action %q was rejected: %v", action, err)
		}
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := base
			test.mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatalf("invalid workload service action was accepted: %#v", value)
			}
		})
	}
}

func mustMarshalOperation(t *testing.T, operation Operation) []byte {
	t.Helper()
	payload, err := MarshalOperation(operation)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
