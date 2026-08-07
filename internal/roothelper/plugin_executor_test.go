package roothelper

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

func TestPluginInstallCommitVerifyAndRollback(t *testing.T) {
	root := t.TempDir()
	catalog := filepath.Join(root, "catalog")
	pluginRoot := filepath.Join(root, "plugins")
	binRoot := filepath.Join(root, "bin")
	stateRoot := filepath.Join(root, "state")
	if err := os.MkdirAll(catalog, 0o755); err != nil {
		t.Fatal(err)
	}
	packagePath := filepath.Join(catalog, "adapter-botmux.opspkg")
	payload := writeExecutorPluginPackage(t, packagePath)
	digest := sha256.Sum256(payload)
	operation := &protocol.PluginInstall{
		OperationKind: "plugin.install",
		PluginID:      "adapter.botmux",
		Version:       "0.2.0",
		Publisher:     "KiritoKing/pi-ops-agent",
		Digest:        "sha256:" + hex.EncodeToString(digest[:]),
		ArtifactRef:   "builtin:sha256:" + hex.EncodeToString(digest[:]),
	}
	executor := &OSExecutor{
		StateDir: stateRoot, PluginRoot: pluginRoot,
		PluginCatalog: catalog, PluginBinRoot: binRoot,
	}
	scope := ExecutionScope{ChangeID: "change-plugin-0001", TargetID: "target-local-system"}
	prepared, err := executor.Prepare(context.Background(), scope, operation)
	if err != nil {
		t.Fatal(err)
	}
	if !prepared.RollbackAvailable {
		t.Fatal("plugin installation must be rollback-capable")
	}
	if err := executor.Execute(context.Background(), scope, operation, prepared); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Verify(context.Background(), scope, operation, prepared); err != nil {
		t.Fatal(err)
	}
	current, err := os.Readlink(filepath.Join(pluginRoot, "adapter.botmux", "current"))
	if err != nil || current != "0.2.0" {
		t.Fatalf("unexpected current plugin pointer %q: %v", current, err)
	}
	if _, err := os.Stat(filepath.Join(binRoot, "ops-agent-botmux")); err != nil {
		t.Fatal(err)
	}
	if err := executor.Rollback(context.Background(), scope, operation, prepared); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(pluginRoot, "adapter.botmux", "0.2.0")); !os.IsNotExist(err) {
		t.Fatalf("plugin version survived rollback: %v", err)
	}
	if _, err := os.Stat(filepath.Join(binRoot, "ops-agent-botmux")); !os.IsNotExist(err) {
		t.Fatalf("plugin launcher survived rollback: %v", err)
	}
}

func writeExecutorPluginPackage(t *testing.T, output string) []byte {
	t.Helper()
	file, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	archive := tar.NewWriter(gzipWriter)
	files := map[string]string{
		"manifest.json": `{"schemaVersion":1,"id":"adapter.botmux","kind":"im-adapter","version":"0.2.0","publisher":"KiritoKing/pi-ops-agent","coreProtocol":1,"entrypoint":"adapter.mjs","description":"BotMux adapter","capabilities":{"inboundText":true,"verifiedSender":true,"privateConversation":true,"proactiveDelivery":true,"approvalIntent":true,"streaming":false},"secrets":[],"setupOperations":[]}`,
		"adapter.mjs":   "export const ready = true;\n",
	}
	for name, payload := range files {
		if err := archive.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(payload)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
