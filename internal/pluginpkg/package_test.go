package pluginpkg

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestInspectAndExtractPackage(t *testing.T) {
	catalog := t.TempDir()
	packagePath := filepath.Join(catalog, "adapter-botmux.opspkg")
	writeTestPackage(t, packagePath, map[string]string{
		"manifest.json": validManifest,
		"adapter.mjs":   "export const ready = true;\n",
	})

	packageInfo, err := Inspect(packagePath, catalog)
	if err != nil {
		t.Fatal(err)
	}
	if packageInfo.Manifest.ID != "adapter.botmux" || packageInfo.Manifest.Version != "0.1.0" {
		t.Fatalf("unexpected manifest: %#v", packageInfo.Manifest)
	}
	if !strings.HasPrefix(packageInfo.Digest, "sha256:") {
		t.Fatalf("unexpected digest: %q", packageInfo.Digest)
	}
	destination := filepath.Join(t.TempDir(), "plugin")
	previousUmask := syscall.Umask(0o077)
	defer syscall.Umask(previousUmask)
	if err := packageInfo.Extract(destination); err != nil {
		t.Fatal(err)
	}
	directoryInfo, err := os.Stat(destination)
	if err != nil || directoryInfo.Mode().Perm() != 0o755 {
		t.Fatalf("unexpected extraction directory mode: %v, %v", directoryInfo, err)
	}
	payload, err := os.ReadFile(filepath.Join(destination, "adapter.mjs"))
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "export const ready = true;\n" {
		t.Fatalf("unexpected entrypoint payload: %q", payload)
	}
	entrypointInfo, err := os.Stat(filepath.Join(destination, "adapter.mjs"))
	if err != nil || entrypointInfo.Mode().Perm() != 0o644 {
		t.Fatalf("unexpected extracted file mode: %v, %v", entrypointInfo, err)
	}
}

func TestInspectRejectsArchiveTraversal(t *testing.T) {
	catalog := t.TempDir()
	packagePath := filepath.Join(catalog, "unsafe.opspkg")
	writeTestPackage(t, packagePath, map[string]string{
		"manifest.json": validManifest,
		"../escape":     "nope",
	})
	if _, err := Inspect(packagePath, catalog); err == nil || !strings.Contains(err.Error(), "unsafe plugin archive path") {
		t.Fatalf("expected traversal rejection, got %v", err)
	}
}

func TestInspectRejectsUnknownManifestFields(t *testing.T) {
	catalog := t.TempDir()
	packagePath := filepath.Join(catalog, "unknown.opspkg")
	manifest := strings.Replace(validManifest, `"description":"BotMux adapter"`, `"description":"BotMux adapter","installCommand":"sudo sh"`, 1)
	writeTestPackage(t, packagePath, map[string]string{"manifest.json": manifest})
	if _, err := Inspect(packagePath, catalog); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected strict manifest rejection, got %v", err)
	}
}

func writeTestPackage(t *testing.T, output string, files map[string]string) {
	t.Helper()
	file, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	archive := tar.NewWriter(gzipWriter)
	for name, payload := range files {
		if err := archive.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(payload)), Typeflag: tar.TypeReg}); err != nil {
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
}

const validManifest = `{"schemaVersion":1,"id":"adapter.botmux","kind":"im-adapter","version":"0.1.0","publisher":"KiritoKing/pi-ops-agent","coreProtocol":1,"entrypoint":"adapter.mjs","description":"BotMux adapter","capabilities":{"inboundText":true,"verifiedSender":true,"privateConversation":true,"proactiveDelivery":true,"approvalIntent":true,"streaming":false},"secrets":["larkAppSecret"],"setupOperations":["credential.install","config.write","service.start"]}`
