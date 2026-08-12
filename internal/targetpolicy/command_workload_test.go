package targetpolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

func commandWorkloadPolicyJSON(digest string) string {
	return fmt.Sprintf(`{"version":1,"revision":"policy-command-1234","targets":[{"id":"target-alice-1234","account":"alice","displayName":"Alice","inspect":{"hostSnapshot":false,"processList":false,"units":[],"readPaths":[]},"changes":{"writePaths":[],"units":[],"packages":[],"plugins":[]},"commandWorkloads":[{"pluginId":"workload.example-command","pluginDigest":%q,"targetAccount":"alice","profileKey":"example.status","runAsAccount":"alice","runAsHome":"/home/alice","executable":"/usr/local/bin/example","argv":["status","--plain"],"timeoutSeconds":15,"maxOutputBytes":4096}]}]}`, digest)
}

func TestStandardBotMuxProfilesUseCurrentUpstreamFixedArgv(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join(
		"..", "..", "plugins", "workload-botmux-ops", "target-policy.example.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := Parse(payload)
	if err != nil {
		t.Fatalf("standard BotMux target policy fixture is invalid: %v", err)
	}
	digest := "sha256:" + strings.Repeat("0", 64)
	checks := []struct {
		profileKey string
		argv       []string
	}{
		{profileKey: "botmux.sessions.list", argv: []string{"list", "--plain"}},
		{profileKey: "botmux.setup.summary", argv: []string{"setup", "list", "--json"}},
		{profileKey: "botmux.status", argv: []string{"status"}},
	}
	for _, check := range checks {
		profile, ok := policy.CommandWorkload("target-alice-botmux", protocol.WorkloadCommandInspection{
			PluginID: "workload.botmux-ops", PluginDigest: digest, ProfileKey: check.profileKey,
		})
		if !ok || !slices.Equal(profile.Argv, check.argv) {
			t.Fatalf("BotMux profile %s argv drifted: %#v", check.profileKey, profile.Argv)
		}
		if len(profile.Argv) > 0 && profile.Argv[0] == "sessions" {
			t.Fatalf("BotMux profile %s regressed to unsupported sessions list argv", check.profileKey)
		}
	}
}

func TestCommandWorkloadPolicyBindsExactDigestAndSemanticProfile(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	policy, err := Parse([]byte(commandWorkloadPolicyJSON(digest)))
	if err != nil {
		t.Fatal(err)
	}
	inspection := protocol.WorkloadCommandInspection{
		PluginID: "workload.example-command", PluginDigest: digest, ProfileKey: "example.status",
	}
	profile, ok := policy.CommandWorkload("target-alice-1234", inspection)
	if !ok || profile.Executable != "/usr/local/bin/example" || len(profile.Argv) != 2 {
		t.Fatalf("exact command profile was not resolved: %#v ok=%t", profile, ok)
	}
	profile.Argv[0] = "mutated"
	second, ok := policy.CommandWorkload("target-alice-1234", inspection)
	if !ok || second.Argv[0] != "status" {
		t.Fatal("command profile lookup exposed mutable policy argv")
	}
	request := protocol.Request{
		Method: protocol.MethodWorkloadCommandInspect, TargetID: "target-alice-1234",
		PolicyRevision: policy.Revision, WorkloadCommand: inspection,
	}
	if err := policy.Authorize(request); err != nil {
		t.Fatalf("exact command profile was denied: %v", err)
	}
	for _, drift := range []protocol.WorkloadCommandInspection{
		{PluginID: "workload.other", PluginDigest: digest, ProfileKey: "example.status"},
		{PluginID: inspection.PluginID, PluginDigest: "sha256:" + strings.Repeat("b", 64), ProfileKey: "example.status"},
		{PluginID: inspection.PluginID, PluginDigest: digest, ProfileKey: "example.other"},
	} {
		request.WorkloadCommand = drift
		if err := policy.Authorize(request); err == nil {
			t.Fatalf("drifted command profile was authorized: %#v", drift)
		}
	}
}

func TestCommandWorkloadPolicyRejectsInvocationControlledOrAmbiguousRecipes(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	valid := commandWorkloadPolicyJSON(digest)
	invalid := []string{
		strings.Replace(valid, `"pluginId":"workload.example-command"`, `"pluginId":"workload.base"`, 1),
		strings.Replace(valid, `"targetAccount":"alice"`, `"targetAccount":"bob"`, 1),
		strings.Replace(valid, `"runAsAccount":"alice"`, `"runAsAccount":"root"`, 1),
		strings.Replace(valid, `"profileKey":"example.status"`, `"profileKey":"../status"`, 1),
		strings.Replace(valid, `"argv":["status","--plain"]`, `"argv":null`, 1),
		strings.Replace(valid, `"timeoutSeconds":15`, `"timeoutSeconds":121`, 1),
		strings.Replace(valid, `"maxOutputBytes":4096`, `"maxOutputBytes":65537`, 1),
		strings.Replace(valid, `"commandWorkloads":[`, `"commandWorkloads":[{"pluginId":"workload.example-command","pluginDigest":"`+digest+`","targetAccount":"alice","profileKey":"example.status","runAsAccount":"alice","runAsHome":"/home/alice","executable":"/usr/local/bin/example","argv":["status","--plain"],"timeoutSeconds":15,"maxOutputBytes":4096},`, 1),
	}
	for index, payload := range invalid {
		if _, err := Parse([]byte(payload)); err == nil {
			t.Fatalf("invalid command workload policy %d was accepted", index)
		}
	}
}
