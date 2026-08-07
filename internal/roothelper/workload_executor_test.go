package roothelper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/KiritoKing/pi-ops-agent/internal/pluginpkg"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

type workloadRollbackRunner struct {
	containerName string
	labels        map[string]string
}

func (r workloadRollbackRunner) Run(_ context.Context, _ string, args ...string) (string, error) {
	if len(args) == 0 {
		return "", errors.New("missing Docker arguments")
	}
	switch args[0] {
	case "container":
		return r.containerName + "\n", nil
	case "inspect":
		payload, err := json.Marshal([]dockerInspectResult{{Config: struct {
			Image       string            `json:"Image"`
			Cmd         []string          `json:"Cmd"`
			Entrypoint  []string          `json:"Entrypoint"`
			Env         []string          `json:"Env"`
			Labels      map[string]string `json:"Labels"`
			User        string            `json:"User"`
			StopTimeout *int              `json:"StopTimeout"`
		}{Labels: r.labels}}})
		return string(payload), err
	case "rm":
		return "", nil
	default:
		return "", fmt.Errorf("unexpected Docker operation %q", args[0])
	}
}

func TestManagedWorkloadSpecIsGenericAndRejectsPrivilegeDrift(t *testing.T) {
	stopTimeout := 30
	workload := testManagedWorkload()
	rollback := workloadRollback{
		Version: 2, ChangeID: "change-workload-12345678", PluginID: "workload.example",
		ArtifactDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ImageDigest:    workload.ImageDigest, ContainerName: workload.ContainerName,
	}
	value := dockerInspectResult{}
	value.State.Running = true
	value.Config.Image = workload.ImageRepository + "@" + workload.ImageDigest
	value.Config.Cmd = append([]string(nil), workload.ContainerCommand...)
	value.Config.Entrypoint = append([]string(nil), workload.ExpectedEntrypoint...)
	value.Config.User = workload.ExpectedUser
	value.Config.StopTimeout = &stopTimeout
	value.Config.Labels = map[string]string{
		"io.pi-ops-agent.managed": "true", "io.pi-ops-agent.change": rollback.ChangeID,
		"io.pi-ops-agent.workload": rollback.PluginID, "io.pi-ops-agent.artifact-digest": rollback.ArtifactDigest,
		"io.pi-ops-agent.image-digest": rollback.ImageDigest,
	}
	value.Config.Env = []string{"MODE=managed", "EXAMPLE_API_KEY=secret-value"}
	value.HostConfig.NetworkMode = "bridge"
	value.HostConfig.IpcMode = "private"
	value.HostConfig.Memory = workload.Resources.MemoryBytes
	value.HostConfig.NanoCPUs = workload.Resources.NanoCPUs
	value.HostConfig.PidsLimit = workload.Resources.PidsLimit
	value.HostConfig.ShmSize = workload.Resources.ShmBytes
	value.HostConfig.CapDrop = []string{"ALL"}
	value.HostConfig.SecurityOpt = []string{"no-new-privileges:true"}
	value.HostConfig.RestartPolicy.Name = "unless-stopped"
	value.HostConfig.LogConfig.Type = "json-file"
	value.HostConfig.LogConfig.Config = map[string]string{"max-size": "10m", "max-file": "3"}
	value.HostConfig.PortBindings = map[string][]struct {
		HostIP   string `json:"HostIp"`
		HostPort string `json:"HostPort"`
	}{"8080/tcp": {{HostIP: "127.0.0.1", HostPort: "18080"}}}
	executor := &OSExecutor{StateDir: "/var/lib/ops-agent/root-helper"}
	value.Mounts = []struct {
		Type        string `json:"Type"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	}{{Type: "bind", Source: executor.workloadDataRoot(rollback.PluginID), Destination: workload.DataMountTarget, RW: true}}
	if err := executor.validateWorkloadContainerSpec(value, rollback, workload, map[string]string{"apiKey": "secret-value"}); err != nil {
		t.Fatalf("fixed managed workload spec was rejected: %v", err)
	}
	value.HostConfig.Privileged = true
	if err := executor.validateWorkloadContainerSpec(value, rollback, workload, map[string]string{"apiKey": "secret-value"}); err == nil {
		t.Fatal("privileged managed workload drift was accepted")
	}
}

func TestManagedWorkloadProcessPolicySupportsBoundedRootInitialization(t *testing.T) {
	policy := pluginpkg.WorkloadProcessPolicy{
		RuntimeUser:             "10000:10000",
		AllowedRuntimeCommands:  []string{"example", "logger"},
		RequiredRuntimeCommands: []string{"example"},
		AllowedRootCommands:     []string{"s6-svscan", "s6-supervise"},
	}
	valid := "UID GID PID COMMAND\n0 0 1 s6-svscan\n0 0 12 s6-supervise\n10000 10000 21 example\n10000 10000 22 logger\n"
	if err := validateWorkloadProcessTable(valid, policy); err != nil {
		t.Fatalf("bounded init/runtime process table was rejected: %v", err)
	}
	for name, table := range map[string]string{
		"undeclared root":   "UID GID PID COMMAND\n0 0 1 sh\n10000 10000 21 example\n",
		"wrong runtime uid": "UID GID PID COMMAND\n0 0 1 s6-svscan\n10001 10000 21 example\n",
		"missing required":  "UID GID PID COMMAND\n0 0 1 s6-svscan\n10000 10000 22 logger\n",
		"mixed root":        "UID GID PID COMMAND\n0 10000 1 s6-svscan\n10000 10000 21 example\n",
		"missing pid":       "UID GID PID COMMAND\n0 0 0 s6-svscan\n10000 10000 21 example\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateWorkloadProcessTable(table, policy); err == nil {
				t.Fatal("unsafe process table was accepted")
			}
		})
	}
}

func TestManagedWorkloadRollbackUsesPersistedMetadataAfterPolicyOrCatalogChange(t *testing.T) {
	stateDir := t.TempDir()
	operation := &protocol.WorkloadDeploy{
		OperationKind: "workload.deploy", PluginID: "workload.example", Version: "0.2.0",
		Publisher:   "example/publisher",
		Digest:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ArtifactRef: "builtin:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	rollback := workloadRollback{
		Version: 2, ChangeID: "change-workload-12345678", PluginID: operation.PluginID,
		ArtifactDigest: operation.Digest,
		ImageDigest:    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ContainerName:  "ops-agent-example",
	}
	rollbackData, err := json.Marshal(rollback)
	if err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{
		"io.pi-ops-agent.managed": "true", "io.pi-ops-agent.change": rollback.ChangeID,
		"io.pi-ops-agent.workload": rollback.PluginID, "io.pi-ops-agent.artifact-digest": rollback.ArtifactDigest,
		"io.pi-ops-agent.image-digest": rollback.ImageDigest,
	}
	executor := &OSExecutor{
		StateDir: stateDir, PluginCatalog: filepath.Join(stateDir, "missing-catalog"),
		Runner: workloadRollbackRunner{containerName: rollback.ContainerName, labels: labels},
	}
	root := executor.workloadRoot(operation.PluginID)
	if err := os.MkdirAll(filepath.Join(root, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	marker, err := json.Marshal(workloadMarker{
		Version: 1, ChangeID: rollback.ChangeID, PluginID: rollback.PluginID,
		ArtifactDigest: rollback.ArtifactDigest, ImageDigest: rollback.ImageDigest,
		CredentialBundleDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "managed.json"), append(marker, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	scope := ExecutionScope{ChangeID: rollback.ChangeID, TargetID: "target-local-system", PolicyRevision: "policy-new-revision"}
	if err := executor.Rollback(context.Background(), scope, operation, ExecutionResult{RollbackData: rollbackData, RollbackAvailable: true}); err != nil {
		t.Fatalf("rollback depended on current policy/catalog/plugin pointer: %v", err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("managed root survived rollback: %v", err)
	}
	recovery := filepath.Join(stateDir, "changes", rollback.ChangeID, "workload-recovery", safeUnitFragment(operation.PluginID))
	if _, err := os.Stat(recovery); err != nil {
		t.Fatalf("rollback recovery evidence is missing: %v", err)
	}
}

func TestCredentialBundleRequiresExactDeclaredSlots(t *testing.T) {
	workload := testManagedWorkload()
	valid := []byte(`{"version":1,"pluginId":"workload.example","values":[{"name":"apiKey","value":"secret-value"}]}`)
	values, err := parseCredentialBundle(valid, "workload.example", workload)
	if err != nil || values["apiKey"] != "secret-value" {
		t.Fatalf("valid credential bundle was rejected: %v", err)
	}
	for name, payload := range map[string][]byte{
		"unknown field": []byte(`{"version":1,"pluginId":"workload.example","values":[{"name":"apiKey","value":"secret-value","extra":true}]}`),
		"extra slot":    []byte(`{"version":1,"pluginId":"workload.example","values":[{"name":"other","value":"secret-value"}]}`),
		"newline":       []byte("{\"version\":1,\"pluginId\":\"workload.example\",\"values\":[{\"name\":\"apiKey\",\"value\":\"secret\\nvalue\"}]}"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCredentialBundle(payload, "workload.example", workload); err == nil {
				t.Fatal("invalid credential bundle was accepted")
			}
		})
	}
}

func testManagedWorkload() *pluginpkg.ManagedWorkload {
	return &pluginpkg.ManagedWorkload{
		Runtime: "docker", ImageRepository: "example/workload",
		ImageDigest:   "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ContainerName: "ops-agent-example", ContainerCommand: []string{"serve"},
		ExpectedEntrypoint: []string{"/usr/local/bin/entrypoint"}, ExpectedUser: "10000:10000",
		ProcessPolicy: pluginpkg.WorkloadProcessPolicy{
			RuntimeUser: "10000:10000", AllowedRuntimeCommands: []string{"example"},
			RequiredRuntimeCommands: []string{"example"}, AllowedRootCommands: []string{},
		},
		ContainerPort: 8080, HostPort: 18080, DataMountTarget: "/srv/data", UID: 10000, GID: 10000,
		Resources: pluginpkg.WorkloadResources{MemoryBytes: 256 * 1024 * 1024, NanoCPUs: 500_000_000, PidsLimit: 64, ShmBytes: 64 * 1024 * 1024},
		CapAdd:    []string{}, LiteralEnvironment: map[string]string{"MODE": "managed"},
		CredentialEnvironment: map[string]string{"apiKey": "EXAMPLE_API_KEY"},
		Directories:           []pluginpkg.WorkloadDirectory{}, Files: []pluginpkg.WorkloadFile{},
		ContainerExecChecks: []pluginpkg.ContainerExecCheck{{Argv: []string{"/usr/local/bin/healthcheck"}, OutputContains: "ready"}},
	}
}
