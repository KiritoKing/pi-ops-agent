package roothelper

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/pluginregistry"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

func writeSourcePlugin(t *testing.T, root, version, body string) string {
	t.Helper()
	source := filepath.Join(root, "workload.example")
	if err := os.MkdirAll(source, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{
		"apiVersion": "agentd.plugin/v1", "schemaVersion": 1,
		"id": "workload.example", "kind": "workload", "version": version,
		"publisher": "example/ops", "description": "Example source workload",
		"entrypoint":      "workload.mjs",
		"capabilities":    []string{"target.inspect"},
		"requestedScopes": []string{"control.target.inspect", "control.target.prepare"},
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "manifest.json"), append(payload, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "workload.mjs"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return source
}

func writableRegistryTestRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Cleanup(func() {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				return os.Chmod(path, 0o700)
			}
			return os.Chmod(path, 0o600)
		})
	})
	return root
}

func sourcePluginOperation(t *testing.T, executor *OSExecutor) *protocol.PluginRegister {
	t.Helper()
	registry, err := executor.sourcePluginRegistry()
	if err != nil {
		t.Fatal(err)
	}
	inspection, err := registry.InspectSource(executor.sourcePluginDirectory("workload.example"))
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.PluginRegister{
		OperationKind: "plugin.register", PluginID: "workload.example", PluginKind: "workload",
		Version: inspection.Manifest.Version, Publisher: inspection.Manifest.Publisher, Digest: inspection.Digest,
		Capabilities:    inspection.Manifest.Capabilities,
		RequestedScopes: []string{"control.target.inspect", "control.target.prepare"},
	}
}

func TestSourcePluginRegistrationRehashesAtExecutionAndRollsBack(t *testing.T) {
	sourceRoot, registryRoot := t.TempDir(), writableRegistryTestRoot(t)
	source := writeSourcePlugin(t, sourceRoot, "1.0.0", "export const version = 1;\n")
	executor := &OSExecutor{SourcePluginRoot: sourceRoot, SourcePluginRegistry: registryRoot}
	operation := sourcePluginOperation(t, executor)
	scope := ExecutionScope{
		ChangeID: "change-source-plugin-0001", TargetID: "target-local-system",
		ApprovedBy: "local-uid:1000", ApprovedAt: time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC),
	}
	result, err := executor.Prepare(context.Background(), scope, operation)
	if err != nil || !result.RollbackAvailable {
		t.Fatalf("prepare source plugin: result=%#v err=%v", result, err)
	}
	if err := os.WriteFile(filepath.Join(source, "workload.mjs"), []byte("export const version = 999;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := executor.Execute(context.Background(), scope, operation, result); err == nil || !strings.Contains(err.Error(), "no longer matches") {
		t.Fatalf("source mutation after approval was accepted: %v", err)
	}
	registry, err := pluginregistry.Open(registryRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Current(operation.PluginID); !os.IsNotExist(err) {
		t.Fatalf("failed registration changed current: %v", err)
	}
	if err := os.WriteFile(filepath.Join(source, "workload.mjs"), []byte("export const version = 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := executor.Execute(context.Background(), scope, operation, result); err != nil {
		t.Fatal(err)
	}
	if verification, err := executor.Verify(context.Background(), scope, operation, result); err != nil || !strings.Contains(verification, operation.Digest) {
		t.Fatalf("verify registration: %q %v", verification, err)
	}
	if err := executor.Rollback(context.Background(), scope, operation, result); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Current(operation.PluginID); !os.IsNotExist(err) {
		t.Fatalf("rollback did not deactivate a newly registered plugin: %v", err)
	}
}

func TestSourcePluginRegistrationBindsDisplayedManifestMetadata(t *testing.T) {
	sourceRoot, registryRoot := t.TempDir(), writableRegistryTestRoot(t)
	writeSourcePlugin(t, sourceRoot, "1.0.0", "export const version = 1;\n")
	executor := &OSExecutor{SourcePluginRoot: sourceRoot, SourcePluginRegistry: registryRoot}
	operation := sourcePluginOperation(t, executor)
	scope := ExecutionScope{
		ChangeID: "change-source-metadata-0001", TargetID: "target-local-system",
		ApprovedBy: "local-uid:1000", ApprovedAt: time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC),
	}
	for name, mutate := range map[string]func(*protocol.PluginRegister){
		"version":      func(value *protocol.PluginRegister) { value.Version = "2.0.0" },
		"publisher":    func(value *protocol.PluginRegister) { value.Publisher = "attacker/example" },
		"capabilities": func(value *protocol.PluginRegister) { value.Capabilities = []string{"other.capability"} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := *operation
			changed.Capabilities = append([]string(nil), operation.Capabilities...)
			changed.RequestedScopes = append([]string(nil), operation.RequestedScopes...)
			mutate(&changed)
			if _, err := executor.Prepare(context.Background(), scope, &changed); err == nil || !strings.Contains(err.Error(), "no longer matches") {
				t.Fatalf("registration accepted mismatched displayed %s: %v", name, err)
			}
		})
	}
}

func TestSourcePluginUpdateRollbackRestoresPreviousDigest(t *testing.T) {
	sourceRoot, registryRoot := t.TempDir(), writableRegistryTestRoot(t)
	writeSourcePlugin(t, sourceRoot, "1.0.0", "export const version = 1;\n")
	executor := &OSExecutor{SourcePluginRoot: sourceRoot, SourcePluginRegistry: registryRoot}
	first := sourcePluginOperation(t, executor)
	firstScope := ExecutionScope{ChangeID: "change-source-plugin-0002", ApprovedBy: "local-uid:1000", ApprovedAt: time.Now().UTC()}
	firstResult, err := executor.Prepare(context.Background(), firstScope, first)
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.Execute(context.Background(), firstScope, first, firstResult); err != nil {
		t.Fatal(err)
	}

	writeSourcePlugin(t, sourceRoot, "2.0.0", "export const version = 2;\n")
	second := sourcePluginOperation(t, executor)
	if second.Digest == first.Digest {
		t.Fatal("source update did not change the content digest")
	}
	secondScope := ExecutionScope{ChangeID: "change-source-plugin-0003", ApprovedBy: "approval-key:test-v1", ApprovedAt: time.Now().UTC()}
	secondResult, err := executor.Prepare(context.Background(), secondScope, second)
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.Execute(context.Background(), secondScope, second, secondResult); err != nil {
		t.Fatal(err)
	}
	if err := executor.Rollback(context.Background(), secondScope, second, secondResult); err != nil {
		t.Fatal(err)
	}
	registry, _ := pluginregistry.Open(registryRoot)
	current, err := registry.Current(first.PluginID)
	if err != nil || current.Digest != first.Digest {
		t.Fatalf("rollback did not restore the previous digest: %#v %v", current, err)
	}
}

func TestSourcePluginUpdateFailsClosedWhileOldDigestInvocationIsLeased(t *testing.T) {
	sourceRoot, registryRoot := t.TempDir(), writableRegistryTestRoot(t)
	writeSourcePlugin(t, sourceRoot, "1.0.0", "export const version = 1;\n")
	executor := &OSExecutor{SourcePluginRoot: sourceRoot, SourcePluginRegistry: registryRoot}
	first := sourcePluginOperation(t, executor)
	firstScope := ExecutionScope{ChangeID: "change-source-plugin-lease-0001", ApprovedBy: "local-uid:1000", ApprovedAt: time.Now().UTC()}
	firstResult, err := executor.Prepare(context.Background(), firstScope, first)
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.Execute(context.Background(), firstScope, first, firstResult); err != nil {
		t.Fatal(err)
	}

	registry, err := pluginregistry.Open(registryRoot)
	if err != nil {
		t.Fatal(err)
	}
	_, invocationLease, err := registry.LeaseRuntimeCurrent(first.PluginID, first.Digest)
	if err != nil {
		t.Fatal(err)
	}
	defer invocationLease.Close()

	writeSourcePlugin(t, sourceRoot, "2.0.0", "export const version = 2;\n")
	second := sourcePluginOperation(t, executor)
	secondScope := ExecutionScope{ChangeID: "change-source-plugin-lease-0002", ApprovedBy: "local-uid:1000", ApprovedAt: time.Now().UTC()}
	secondResult, err := executor.Prepare(context.Background(), secondScope, second)
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.Execute(context.Background(), secondScope, second, secondResult); err == nil ||
		!strings.Contains(err.Error(), "active source-plugin runtime") {
		t.Fatalf("source update crossed an active invocation lease: %v", err)
	}
	if err := executor.Rollback(context.Background(), secondScope, second, secondResult); err != nil {
		t.Fatalf("pre-activation failure did not roll back idempotently: %v", err)
	}
	current, err := registry.Current(first.PluginID)
	if err != nil || current.Digest != first.Digest {
		t.Fatalf("blocked update changed current: %#v %v", current, err)
	}
}
