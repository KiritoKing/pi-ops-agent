package roothelper

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/peercred"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
	"github.com/KiritoKing/pi-ops-agent/internal/targetpolicy"
)

type workloadCommandRunner struct {
	name   string
	args   []string
	output string
	err    error
}

func (r *workloadCommandRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.name = name
	r.args = append([]string{}, args...)
	return r.output, r.err
}

func testCommandProfile(executable string) targetpolicy.CommandWorkloadPolicy {
	return targetpolicy.CommandWorkloadPolicy{
		PluginID: "workload.example-command", PluginDigest: "sha256:" + strings.Repeat("a", 64),
		TargetAccount: "alice", ProfileKey: "example.status", RunAsAccount: "alice",
		RunAsHome: "/home/alice", Executable: executable, Argv: []string{"status", "--plain"},
		TimeoutSeconds: 15, MaxOutputBytes: 64,
	}
}

func TestWorkloadCommandUsesHardenedNonRootTransientService(t *testing.T) {
	profile := testCommandProfile("/bin/echo")
	runner := &workloadCommandRunner{output: "ok\x00\n" + strings.Repeat("x", 80)}
	inspector := OSInspector{
		Runner: runner,
		LookupWorkloadAccount: func(account string) (int, string, error) {
			if account != "alice" {
				t.Fatalf("unexpected account %q", account)
			}
			return 1000, "/home/alice", nil
		},
	}
	result, err := inspector.InspectWorkloadCommand(context.Background(), protocol.WorkloadCommandInspection{
		PluginID: profile.PluginID, PluginDigest: profile.PluginDigest, ProfileKey: profile.ProfileKey,
	}, profile)
	if err != nil {
		t.Fatal(err)
	}
	if runner.name != "/usr/bin/systemd-run" {
		t.Fatalf("command bypassed transient systemd execution: %q", runner.name)
	}
	joined := strings.Join(runner.args, "\n")
	for _, required := range []string{
		"--wait", "--pipe", "--collect", "--uid=alice", "--working-directory=/home/alice",
		"--property=ProtectSystem=strict", "--property=ProtectHome=read-only",
		"--property=PrivateNetwork=yes", "--property=NoNewPrivileges=yes",
		"--property=RuntimeMaxSec=15s", "/usr/bin/env", "-i", "PYTHONNOUSERSITE=1",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("transient command omitted %q: %#v", required, runner.args)
		}
	}
	if len(runner.args) < 2 || runner.args[len(runner.args)-2] != "status" || runner.args[len(runner.args)-1] != "--plain" {
		t.Fatalf("fixed argv was not preserved exactly: %#v", runner.args)
	}
	if result.ExecutableTrust != "root-owned-nonwritable-path" || !result.Truncated || strings.ContainsRune(result.Output, '\x00') {
		t.Fatalf("unexpected bounded command result: %#v", result)
	}
}

func TestWorkloadCommandRejectsWritableOrIdentityDriftedExecutable(t *testing.T) {
	executable := t.TempDir() + "/command"
	if err := writeExecutableTestFile(executable); err != nil {
		t.Fatal(err)
	}
	profile := testCommandProfile(executable)
	inspector := OSInspector{
		Runner:                &workloadCommandRunner{},
		LookupWorkloadAccount: func(string) (int, string, error) { return 1000, "/home/alice", nil },
	}
	inspection := protocol.WorkloadCommandInspection{
		PluginID: profile.PluginID, PluginDigest: profile.PluginDigest, ProfileKey: profile.ProfileKey,
	}
	if _, err := inspector.InspectWorkloadCommand(context.Background(), inspection, profile); err == nil ||
		(!strings.Contains(err.Error(), "root-owned") && !strings.Contains(err.Error(), "writable")) {
		t.Fatalf("writable or non-root executable path was accepted: %v", err)
	}
	inspection.PluginDigest = "sha256:" + strings.Repeat("b", 64)
	if _, err := inspector.InspectWorkloadCommand(context.Background(), inspection, testCommandProfile("/bin/echo")); err == nil {
		t.Fatal("digest drift was accepted before command execution")
	}
}

func TestWorkloadCommandServiceReturnsProfileBoundSignedReceiptWithoutAuditingOutput(t *testing.T) {
	now := time.Date(2026, 8, 8, 15, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	payload := fmt.Sprintf(`{"version":1,"revision":"policy-command-service","targets":[{"id":"target-service","account":"alice","displayName":"Alice","inspect":{"hostSnapshot":false,"processList":false,"units":[],"readPaths":[]},"changes":{"writePaths":[],"units":[],"packages":[],"plugins":[]},"commandWorkloads":[{"pluginId":"workload.example-command","pluginDigest":%q,"targetAccount":"alice","profileKey":"example.status","runAsAccount":"alice","runAsHome":"/home/alice","executable":"/bin/echo","argv":["status"],"timeoutSeconds":15,"maxOutputBytes":4096}]}]}`, digest)
	policy, err := targetpolicy.Parse([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	service, auditPath := testServiceWithAuditPath(t, now, &fakeExecutor{})
	service.Policy = policy
	service.Inspector = OSInspector{
		Runner:                &workloadCommandRunner{output: "never-audit-this-secret\n"},
		LookupWorkloadAccount: func(string) (int, string, error) { return 1000, "/home/alice", nil },
	}
	service.ReceiptSigner, err = NewBrokerReceiptSigner("core-receipt-v1", DomainCore, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	request := parseRemoteRequestWithPolicy(
		t, now, "command-service-0001", "agent", policy.Revision,
		fmt.Sprintf(`"method":"workload.command.inspect","pluginId":"workload.example-command","pluginDigest":%q,"profileKey":"example.status"`, digest),
	)
	response := service.Handle(context.Background(), peercred.Credential{UID: service.AgentUID}, request)
	if !response.OK || response.Receipt == nil || response.ChangeID != "" || response.State != "" {
		t.Fatalf("command inspection was not signed: %#v", response)
	}
	claims := protocol.BrokerReceiptClaims{
		KeyID: "core-receipt-v1", Domain: DomainCore, RequestID: request.RequestID,
		Method: protocol.MethodWorkloadCommandInspect, ServerID: request.ServerID,
		MachineID: request.MachineID, TargetID: request.TargetID,
		PluginID: "workload.example-command", PluginDigest: digest, ProfileKey: "example.status",
	}
	if err := protocol.VerifyBrokerResponse(response, claims, now, publicKey); err != nil {
		t.Fatal(err)
	}
	auditPayload, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(auditPayload), "never-audit-this-secret") {
		t.Fatal("root audit persisted raw workload command output")
	}
	roleDrift := parseRemoteRequestWithPolicy(
		t, now, "command-service-role", "approver", policy.Revision,
		fmt.Sprintf(`"method":"workload.command.inspect","pluginId":"workload.example-command","pluginDigest":%q,"profileKey":"example.status"`, digest),
	)
	denied := service.Handle(context.Background(), peercred.Credential{UID: service.AgentUID}, roleDrift)
	if denied.OK || !strings.Contains(denied.Error, "non-privileged agent") {
		t.Fatalf("non-agent caller role reached command profile: %#v", denied)
	}
}

func writeExecutableTestFile(path string) error {
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		return err
	}
	return os.Chmod(path, 0o777)
}
