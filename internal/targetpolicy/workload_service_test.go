package targetpolicy

import (
	"strings"
	"testing"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

const servicePolicyDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func TestWorkloadServicePolicyBindsDigestAccountManagerUnitAndAction(t *testing.T) {
	policy := parseWorkloadServicePolicy(t, "alice", "alice")
	base := &protocol.WorkloadServiceAction{
		OperationKind: "workload.service.action", PluginID: "workload.example-service",
		PluginDigest: servicePolicyDigest, Account: "alice", Manager: "user",
		Unit: "example.service", Action: "restart",
	}
	if err := policy.AuthorizeOperation("target-alice", base); err != nil {
		t.Fatalf("exact workload service action was denied: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*protocol.WorkloadServiceAction)
	}{
		{"plugin ID", func(value *protocol.WorkloadServiceAction) { value.PluginID = "workload.other-service" }},
		{"digest", func(value *protocol.WorkloadServiceAction) {
			value.PluginDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		}},
		{"account", func(value *protocol.WorkloadServiceAction) { value.Account = "bob" }},
		{"manager", func(value *protocol.WorkloadServiceAction) { value.Manager = "system" }},
		{"unit", func(value *protocol.WorkloadServiceAction) { value.Unit = "other.service" }},
		{"action", func(value *protocol.WorkloadServiceAction) { value.Action = "start" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := *base
			test.mutate(&value)
			if err := policy.AuthorizeOperation("target-alice", &value); err == nil {
				t.Fatalf("policy accepted drifted workload service action: %#v", value)
			}
		})
	}
}

func TestWorkloadServicePolicyRejectsNonWorkloadOrMalformedIdentity(t *testing.T) {
	valid := workloadServicePolicyJSON("alice", "alice")
	for _, invalidID := range []string{"adapter.example-service", "workload.Example-service", "workload.example-service-"} {
		invalid := strings.Replace(valid, "workload.example-service", invalidID, 1)
		if _, err := Parse([]byte(invalid)); err == nil {
			t.Fatalf("invalid service workload identity %q was accepted", invalidID)
		}
	}
}

func TestWorkloadServicePolicyRequiresTargetAccount(t *testing.T) {
	payload := workloadServicePolicyJSON("alice", "bob")
	if _, err := Parse([]byte(payload)); err == nil || !strings.Contains(err.Error(), "target account") {
		t.Fatalf("cross-account service policy was not rejected: %v", err)
	}
}

func parseWorkloadServicePolicy(t *testing.T, targetAccount, serviceAccount string) *Policy {
	t.Helper()
	policy, err := Parse([]byte(workloadServicePolicyJSON(targetAccount, serviceAccount)))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func workloadServicePolicyJSON(targetAccount, serviceAccount string) string {
	return `{"version":1,"revision":"policy-service-v1","targets":[{"id":"target-alice","account":"` + targetAccount + `","displayName":"Alice services","inspect":{"hostSnapshot":false,"processList":false,"units":[],"readPaths":[]},"changes":{"writePaths":[],"units":[],"packages":[],"plugins":[]},"serviceWorkloads":[{"pluginId":"workload.example-service","pluginDigest":"` + servicePolicyDigest + `","account":"` + serviceAccount + `","manager":"user","units":["example.service"],"operations":["restart"]}]}]}`
}
