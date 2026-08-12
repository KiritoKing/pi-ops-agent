package targetpolicy

import (
	"strings"
	"testing"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

const jsonConfigPolicyDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

func jsonConfigPolicyJSON() string {
	return `{"version":1,"revision":"policy-json-config-v1","targets":[{"id":"target-alice-botmux","account":"alice","displayName":"Alice BotMux","inspect":{"hostSnapshot":false,"processList":false,"units":[],"readPaths":[]},"changes":{"writePaths":[],"units":[],"packages":[],"plugins":[]},"authorization":{"standingScopes":[]},"jsonConfigWorkloads":[{"pluginId":"workload.botmux-ops","pluginDigest":"` + jsonConfigPolicyDigest + `","targetAccount":"alice","profileKey":"botmux.bots","runAsUid":1000,"runAsHome":"/home/alice","relativeConfig":".botmux/bots.json","selectorKey":"name","allowedSelectors":["primary"],"fields":[{"fieldKey":"model","jsonField":"model","valueType":"string","allowClear":true,"stringConstraint":"model-id/v1"},{"fieldKey":"backendType","jsonField":"backendType","valueType":"string","allowClear":true,"stringConstraint":"enum/v1","enumValues":["pty","tmux"]},{"fieldKey":"defaultWorkingDir","jsonField":"defaultWorkingDir","valueType":"string","allowClear":true,"stringConstraint":"absolute-path/v1","pathRoots":["/home/alice","/srv/alice-projects"]},{"fieldKey":"showInTeam","jsonField":"showInTeam","valueType":"boolean","allowClear":true}]}]}]}`
}

func TestJSONConfigWorkloadPolicyResolvesOnlyExactSemanticGrant(t *testing.T) {
	policy, err := Parse([]byte(jsonConfigPolicyJSON()))
	if err != nil {
		t.Fatal(err)
	}
	model := "openai/gpt-5"
	edit := protocol.WorkloadJSONConfigEdit{
		OperationKind: "workload.json-config.edit", PluginID: "workload.botmux-ops",
		SourceDigest: jsonConfigPolicyDigest, ProfileKey: "botmux.bots", SelectorValue: "primary",
		FieldKey: "model", Value: protocol.WorkloadJSONConfigValue{Kind: "string", StringValue: &model},
	}
	profile, field, ok := policy.JSONConfigWorkload("target-alice-botmux", edit)
	if !ok || profile.RunAsUID != 1000 || profile.RunAsHome != "/home/alice" ||
		profile.RelativeConfig != ".botmux/bots.json" || profile.SelectorKey != "name" || field.JSONField != "model" {
		t.Fatalf("exact JSON config profile was not resolved: %#v %#v ok=%t", profile, field, ok)
	}
	if err := policy.AuthorizeOperation("target-alice-botmux", &edit); err != nil {
		t.Fatalf("exact edit was denied: %v", err)
	}
	if _, _, ok := policy.JSONConfigWorkload("target-alice-botmux", protocol.WorkloadJSONConfigEdit{
		OperationKind: edit.OperationKind, PluginID: edit.PluginID, SourceDigest: edit.SourceDigest,
		ProfileKey: edit.ProfileKey, SelectorValue: edit.SelectorValue, FieldKey: "larkAppSecret", Value: edit.Value,
	}); ok {
		t.Fatal("unmapped secret field was resolved")
	}
	if _, _, ok := policy.JSONConfigWorkload("target-alice-botmux", edit); !ok {
		t.Fatal("mutating returned policy copy changed the active lookup")
	}
	profile.AllowedSelectors[0] = "mutated"
	profile.Fields[0].FieldKey = "mutated"
	field.PathRoots = append(field.PathRoots, "/")
	if _, _, ok := policy.JSONConfigWorkload("target-alice-botmux", edit); !ok {
		t.Fatal("returned JSON config profile exposed mutable active policy state")
	}
}

func TestJSONConfigWorkloadPolicyEnforcesClosedConstraints(t *testing.T) {
	policy, err := Parse([]byte(jsonConfigPolicyJSON()))
	if err != nil {
		t.Fatal(err)
	}
	stringValue := func(value string) protocol.WorkloadJSONConfigValue {
		return protocol.WorkloadJSONConfigValue{Kind: "string", StringValue: &value}
	}
	boolean := true
	tests := []struct {
		field string
		value protocol.WorkloadJSONConfigValue
		allow bool
	}{
		{"model", stringValue("anthropic/claude-opus-4"), true},
		{"model", stringValue("bad model"), false},
		{"backendType", stringValue("tmux"), true},
		{"backendType", stringValue("shell"), false},
		{"defaultWorkingDir", stringValue("/srv/alice-projects/repo"), true},
		{"defaultWorkingDir", stringValue("/etc"), false},
		{"defaultWorkingDir", stringValue("/home/alice/../root"), false},
		{"showInTeam", protocol.WorkloadJSONConfigValue{Kind: "boolean", BooleanValue: &boolean}, true},
		{"showInTeam", stringValue("true"), false},
		{"showInTeam", protocol.WorkloadJSONConfigValue{Kind: "clear"}, true},
	}
	for _, test := range tests {
		edit := protocol.WorkloadJSONConfigEdit{
			OperationKind: "workload.json-config.edit", PluginID: "workload.botmux-ops",
			SourceDigest: jsonConfigPolicyDigest, ProfileKey: "botmux.bots", SelectorValue: "primary",
			FieldKey: test.field, Value: test.value,
		}
		_, _, ok := policy.JSONConfigWorkload("target-alice-botmux", edit)
		if ok != test.allow {
			t.Fatalf("constraint result for %s/%s was %t, want %t", test.field, test.value.SafeText(), ok, test.allow)
		}
	}
}

func TestJSONConfigWorkloadNeverReceivesStandingAuthorization(t *testing.T) {
	policy, err := Parse([]byte(jsonConfigPolicyJSON()))
	if err != nil {
		t.Fatal(err)
	}
	model := "openai/gpt-5"
	edit := &protocol.WorkloadJSONConfigEdit{
		OperationKind: "workload.json-config.edit", PluginID: "workload.botmux-ops", SourceDigest: jsonConfigPolicyDigest,
		ProfileKey: "botmux.bots", SelectorValue: "primary", FieldKey: "model",
		Value: protocol.WorkloadJSONConfigValue{Kind: "string", StringValue: &model},
	}
	if basis, scope, ok := policy.StandingApproval("target-alice-botmux", edit); ok || basis != "" || scope != "" {
		t.Fatalf("JSON config edit received standing authorization: %q %q", basis, scope)
	}
}

func TestJSONConfigWorkloadPolicyRejectsAmbiguousOrUnsafeMappings(t *testing.T) {
	valid := jsonConfigPolicyJSON()
	invalid := []string{
		strings.Replace(valid, `"targetAccount":"alice"`, `"targetAccount":"root"`, 1),
		strings.Replace(valid, `"runAsUid":1000`, `"runAsUid":0`, 1),
		strings.Replace(valid, `"relativeConfig":".botmux/bots.json"`, `"relativeConfig":"../bots.json"`, 1),
		strings.Replace(valid, `"selectorKey":"name"`, `"selectorKey":"../name"`, 1),
		strings.Replace(valid, `"jsonField":"model"`, `"jsonField":"name"`, 1),
		strings.Replace(valid, `"stringConstraint":"enum/v1","enumValues":["pty","tmux"]`, `"stringConstraint":"enum/v1","enumValues":null`, 1),
		strings.Replace(valid, `"stringConstraint":"absolute-path/v1","pathRoots":["/home/alice","/srv/alice-projects"]`, `"stringConstraint":"absolute-path/v1","pathRoots":["/"]`, 1),
		strings.Replace(valid, `"fields":[`, `"fields":[{"fieldKey":"model","jsonField":"otherModel","valueType":"string","allowClear":true,"stringConstraint":"model-id/v1"},`, 1),
		strings.Replace(valid, `"jsonConfigWorkloads":[`, `"jsonConfigWorkloads":[{"pluginId":"workload.botmux-ops","pluginDigest":"`+jsonConfigPolicyDigest+`","targetAccount":"alice","profileKey":"botmux.other","runAsUid":1000,"runAsHome":"/home/alice","relativeConfig":".botmux/bots.json","selectorKey":"name","allowedSelectors":["primary"],"fields":[{"fieldKey":"model","jsonField":"model","valueType":"string","allowClear":true,"stringConstraint":"model-id/v1"}]},`, 1),
	}
	for index, payload := range invalid {
		if _, err := Parse([]byte(payload)); err == nil {
			t.Fatalf("invalid JSON config policy %d was accepted", index)
		}
	}
}
