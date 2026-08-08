package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/pluginregistry"
)

type failingLeaseWriter struct{}

func (failingLeaseWriter) Write([]byte) (int, error) {
	return 0, errors.New("synthetic lease handshake failure")
}

func writeLeaseTestPlugin(t *testing.T, root, version, body string) string {
	t.Helper()
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{
		"apiVersion": "agentd.plugin/v1", "schemaVersion": 1,
		"id": "workload.example", "kind": "workload", "version": version,
		"publisher": "example/pluginctl", "description": "Pluginctl lease test workload",
		"entrypoint": "workload.mjs", "capabilities": []string{"target.inspect"},
		"requestedScopes": []string{"control.target.inspect"},
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), append(payload, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "workload.mjs"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func leaseTestGrant(inspection pluginregistry.Inspection) pluginregistry.Grant {
	return pluginregistry.Grant{
		PluginID: inspection.Manifest.ID, Kind: inspection.Manifest.Kind, Digest: inspection.Digest,
		RequestedScopes: inspection.Manifest.RequestedScopes,
		ApprovedBy:      "test:pluginctl", ApprovedAt: time.Now().UTC(),
	}
}

func TestLeaseCommandOFDLifetimeAndHandshakeCleanup(t *testing.T) {
	registryParent := t.TempDir()
	registryRoot := filepath.Join(registryParent, "registry")
	t.Cleanup(func() {
		_ = filepath.Walk(registryRoot, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				return os.Chmod(path, 0o700)
			}
			return os.Chmod(path, 0o600)
		})
	})
	registry, err := pluginregistry.Open(registryRoot)
	if err != nil {
		t.Fatal(err)
	}
	firstSource := writeLeaseTestPlugin(t, filepath.Join(t.TempDir(), "first"), "1.0.0", "export const value = 1;\n")
	first, err := registry.InspectSource(firstSource)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Register(firstSource, leaseTestGrant(first)); err != nil {
		t.Fatal(err)
	}

	leasePath := filepath.Join(registryRoot, "invocation-leases", "workload.example.lock")
	parentLease, err := os.Open(leasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer parentLease.Close()
	childFD, err := syscall.Dup(int(parentLease.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	childLease := os.NewFile(uintptr(childFD), "test-inherited-lease")
	if childLease == nil {
		_ = syscall.Close(childFD)
		t.Fatal("failed to duplicate inherited lease descriptor")
	}
	var output bytes.Buffer
	if err := writeInheritedLeaseRecord(
		registry,
		"workload.example",
		first.Digest,
		childLease,
		&output,
	); err != nil {
		t.Fatal(err)
	}
	if err := childLease.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), first.Digest) {
		t.Fatalf("lease command did not emit the pinned runtime registration: %q", output.String())
	}

	secondSource := writeLeaseTestPlugin(t, filepath.Join(t.TempDir(), "second"), "2.0.0", "export const value = 2;\n")
	second, err := registry.InspectSource(secondSource)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Register(secondSource, leaseTestGrant(second)); err == nil ||
		!strings.Contains(err.Error(), "active source-plugin runtime") {
		t.Fatalf("lease command released its shared lock when the validator exited: %v", err)
	}

	if err := parentLease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Register(secondSource, leaseTestGrant(second)); err != nil {
		t.Fatalf("exclusive update remained blocked after the parent descriptor closed: %v", err)
	}

	failedParent, err := os.Open(leasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer failedParent.Close()
	failedChildFD, err := syscall.Dup(int(failedParent.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	failedChild := os.NewFile(uintptr(failedChildFD), "test-failed-inherited-lease")
	if failedChild == nil {
		_ = syscall.Close(failedChildFD)
		t.Fatal("failed to duplicate failed-handshake lease descriptor")
	}
	if err := writeInheritedLeaseRecord(
		registry,
		"workload.example",
		second.Digest,
		failedChild,
		failingLeaseWriter{},
	); err == nil || !strings.Contains(err.Error(), "synthetic lease handshake failure") {
		t.Fatalf("failed lease handshake did not surface its output error: %v", err)
	}
	if err := failedChild.Close(); err != nil {
		t.Fatal(err)
	}

	thirdSource := writeLeaseTestPlugin(t, filepath.Join(t.TempDir(), "third"), "3.0.0", "export const value = 3;\n")
	third, err := registry.InspectSource(thirdSource)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Register(thirdSource, leaseTestGrant(third)); err != nil {
		t.Fatalf("failed handshake left the parent's shared OFD lock active: %v", err)
	}
}
