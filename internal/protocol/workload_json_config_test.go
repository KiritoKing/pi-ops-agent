package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

const jsonConfigTestDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestWorkloadJSONConfigEditStrictTaggedValue(t *testing.T) {
	valid := `{"kind":"workload.json-config.edit","pluginId":"workload.botmux-ops","sourceDigest":"` + jsonConfigTestDigest + `","profileKey":"botmux.bots","selectorValue":"primary","fieldKey":"model","value":{"kind":"string","stringValue":"openai/gpt-5"}}`
	operation, err := parseOperation([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	edit, ok := operation.(*WorkloadJSONConfigEdit)
	if !ok || edit.Value.StringValue == nil || *edit.Value.StringValue != "openai/gpt-5" {
		t.Fatalf("unexpected operation: %#v", operation)
	}

	invalid := []string{
		strings.Replace(valid, `"stringValue":"openai/gpt-5"`, `"stringValue":"openai/gpt-5","booleanValue":true`, 1),
		strings.Replace(valid, `"kind":"string","stringValue":"openai/gpt-5"`, `"kind":"clear","stringValue":"openai/gpt-5"`, 1),
		strings.Replace(valid, `"stringValue":"openai/gpt-5"`, `"stringValue":"bad\nmodel"`, 1),
		strings.Replace(valid, `"fieldKey":"model"`, `"fieldKey":"../model"`, 1),
		strings.Replace(valid, `"value":{`, `"account":"root","value":{`, 1),
		strings.Replace(valid, `"stringValue":"openai/gpt-5"`, `"stringValue":"openai/gpt-5","argv":["sh"]`, 1),
		strings.Replace(valid, `"fieldKey":"model"`, `"fieldKey":"model","fieldKey":"backendType"`, 1),
	}
	for index, payload := range invalid {
		if _, err := parseOperation([]byte(payload)); err == nil {
			t.Fatalf("invalid json config operation %d was accepted", index)
		}
	}
}

func TestWorkloadJSONConfigEditBooleanAndClearRoundTrip(t *testing.T) {
	boolean := true
	for _, value := range []WorkloadJSONConfigValue{
		{Kind: "boolean", BooleanValue: &boolean},
		{Kind: "clear"},
	} {
		operation := &WorkloadJSONConfigEdit{
			OperationKind: "workload.json-config.edit", PluginID: "workload.botmux-ops",
			SourceDigest: jsonConfigTestDigest, ProfileKey: "botmux.bots", SelectorValue: "primary",
			FieldKey: "showInTeam", Value: value,
		}
		payload, err := MarshalOperation(operation)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(payload), "booleanValue\":null") || strings.Contains(string(payload), "stringValue") {
			t.Fatalf("tagged value leaked an inactive member: %s", payload)
		}
		parsed, err := ParseStoredOperation(payload)
		if err != nil || parsed.Kind() != operation.Kind() {
			t.Fatalf("round trip failed: %#v %v", parsed, err)
		}
	}
}

func TestWorkloadJSONConfigApprovalPlanBindsOnlySemanticRequestAndPreconditions(t *testing.T) {
	value := "openai/gpt-5"
	operation := &WorkloadJSONConfigEdit{
		OperationKind: "workload.json-config.edit", PluginID: "workload.botmux-ops",
		SourceDigest: jsonConfigTestDigest, ProfileKey: "botmux.bots", SelectorValue: "primary",
		FieldKey: "model", Value: WorkloadJSONConfigValue{Kind: "string", StringValue: &value},
	}
	preconditions := []ApprovalPlanField{
		{Name: "configDigest", Value: "sha256:" + strings.Repeat("b", 64)},
		{Name: "before", Value: "openai/gpt-4.1"},
		{Name: "after", Value: value},
		{Name: "documentRewrite", Value: "whole-document-semantic-rewrite"},
	}
	digest, err := ApprovalPreconditionDigest(preconditions)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildApprovalPlanWithPreconditions(operation, "policy-test-v1", CapabilityRevision, digest, preconditions)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, expected := range []string{"sourceDigest", "profileKey", "selectorValue", "requestedValue", "precondition.configDigest", "whole-document-semantic-rewrite"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("approval plan omitted %q: %s", expected, text)
		}
	}
	for _, forbidden := range []string{"runAsUid", "runAsHome", "relativeConfig", "selectorKey", "helper", "argv"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("caller-controlled execution detail %q entered the plan: %s", forbidden, text)
		}
	}
}

func TestWorkloadJSONConfigApprovalPlanMatchesTypeScriptGolden(t *testing.T) {
	requested := "openai/gpt-5"
	operation := &WorkloadJSONConfigEdit{
		OperationKind: "workload.json-config.edit",
		PluginID:      "workload.botmux-ops",
		SourceDigest:  jsonConfigTestDigest,
		ProfileKey:    "botmux.bots",
		SelectorValue: "ops-agent",
		FieldKey:      "model",
		Value:         WorkloadJSONConfigValue{Kind: "string", StringValue: &requested},
	}
	preconditions := []ApprovalPlanField{
		{Name: "targetAccount", Value: "botmux"},
		{Name: "accountUid", Value: "1000"},
		{Name: "configPath", Value: "/home/botmux/.botmux/bots.json"},
		{Name: "profileKey", Value: "botmux.bots"},
		{Name: "selectorKey", Value: "name"},
		{Name: "selectorValue", Value: "ops-agent"},
		{Name: "fieldKey", Value: "model"},
		{Name: "jsonField", Value: "model"},
		{Name: "beforeKind", Value: "string"},
		{Name: "before", Value: "openai/gpt-4.1"},
		{Name: "afterKind", Value: "string"},
		{Name: "after", Value: requested},
		{Name: "configDigest", Value: "sha256:" + strings.Repeat("b", 64)},
		{Name: "configIdentity", Value: "dev=1;ino=2;mode=0600;bytes=128"},
		{Name: "documentRewrite", Value: "whole-document-semantic-rewrite"},
		{Name: "sameUidRaceBoundary", Value: "digest-cas-detects-but-cannot-prevent-later-same-uid-replacement"},
	}
	preconditionDigest, err := ApprovalPreconditionDigest(preconditions)
	if err != nil {
		t.Fatal(err)
	}
	const goldenPreconditionDigest = "sha256:3bdcbaa2cd90ff432fc91468a7b54b2f6a93ca94778189f4c31c1e6cf3c3b7c4"
	if preconditionDigest != goldenPreconditionDigest {
		t.Fatalf("JSON config Go/TypeScript precondition digest changed: got %s want %s", preconditionDigest, goldenPreconditionDigest)
	}
	plan, err := BuildApprovalPlanWithPreconditions(
		operation,
		"policy-json-config-v1",
		CapabilityRevision,
		preconditionDigest,
		preconditions,
	)
	if err != nil {
		t.Fatal(err)
	}
	const goldenPlanHash = "sha256:ea6fc7e091c926e7ec9bb42a5a4a327a6bc7b53817199f40afd9623531570e40"
	if plan.PlanHash != goldenPlanHash {
		t.Fatalf("JSON config Go/TypeScript plan hash changed: got %s want %s", plan.PlanHash, goldenPlanHash)
	}
	if plan.PluginDigest != jsonConfigTestDigest || plan.PreconditionDigest != goldenPreconditionDigest {
		t.Fatalf("JSON config plan lost source or authoritative precondition digest: %#v", plan)
	}
}
