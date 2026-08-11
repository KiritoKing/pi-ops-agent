package pluginregistry

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestSourceDigestIsDeterministicAndContentAddressed(t *testing.T) {
	registry := testRegistry(t)
	first := writePlugin(t, t.TempDir(), manifestOptions{}, map[string]string{
		"index.mjs":       "export const value = 1;\n",
		"lib/feature.mjs": "export const feature = true;\n",
	})
	second := t.TempDir()
	writeFile(t, filepath.Join(second, "lib", "feature.mjs"), "export const feature = true;\n", 0o644)
	writeFile(t, filepath.Join(second, "index.mjs"), "export const value = 1;\n", 0o644)
	writeManifest(t, second, manifestOptions{})

	firstInspection, err := registry.InspectSource(first)
	if err != nil {
		t.Fatal(err)
	}
	secondInspection, err := registry.InspectSource(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstInspection.Digest != secondInspection.Digest {
		t.Fatalf("same source tree produced different digests: %s != %s", firstInspection.Digest, secondInspection.Digest)
	}

	grant := grantFor(firstInspection)
	registration, err := registry.Register(first, grant)
	if err != nil {
		t.Fatal(err)
	}
	expectedPath := filepath.Join(registry.root, "snapshots", "sha256", strings.TrimPrefix(firstInspection.Digest, "sha256:"))
	if registration.SnapshotPath != expectedPath {
		t.Fatalf("snapshot path is not content addressed: %q", registration.SnapshotPath)
	}
	if payload, err := os.ReadFile(filepath.Join(expectedPath, "lib", "feature.mjs")); err != nil || string(payload) != "export const feature = true;\n" {
		t.Fatalf("snapshot payload mismatch: %q, %v", payload, err)
	}
	current, err := registry.Current("workload.example")
	if err != nil || current.Digest != firstInspection.Digest {
		t.Fatalf("unexpected current registration: %#v, %v", current, err)
	}
}

func TestRegisteredRuntimeTreeRemainsReadableByRegistryGroup(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("setgid inheritance is a Linux deployment invariant")
	}
	registry := testRegistry(t)
	source := writePlugin(t, t.TempDir(), manifestOptions{}, map[string]string{
		"index.mjs":       "export const value = 1;\n",
		"lib/feature.mjs": "export const feature = true;\n",
	})
	inspection := mustInspect(t, registry, source)
	registration, err := registry.Register(source, grantFor(inspection))
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{
		filepath.Join(registry.root, "snapshots"),
		filepath.Join(registry.root, "snapshots", "sha256"),
		filepath.Join(registry.root, "plugins"),
		filepath.Join(registry.root, "plugins", registration.PluginID),
		filepath.Join(registry.root, "plugins", registration.PluginID, "registrations"),
	} {
		info, err := os.Lstat(directory)
		if err != nil {
			t.Fatal(err)
		}
		_, gid, err := numericOwner(info)
		if err != nil || gid != registry.groupGID || info.Mode().Perm() != 0o750 ||
			info.Mode()&os.ModeSetgid == 0 {
			t.Fatalf("registry directory lost its reader group or setgid mode: %s mode=%v gid=%d err=%v", directory, info.Mode(), gid, err)
		}
	}
	err = filepath.Walk(registration.SnapshotPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		_, gid, ownerErr := numericOwner(info)
		if ownerErr != nil {
			return ownerErr
		}
		if gid != registry.groupGID {
			return fmt.Errorf("snapshot entry %s has gid %d, want %d", path, gid, registry.groupGID)
		}
		if info.IsDir() && info.Mode().Perm()&0o050 != 0o050 {
			return fmt.Errorf("snapshot directory %s is not group-readable/traversable", path)
		}
		if info.Mode().IsRegular() && info.Mode().Perm()&0o040 == 0 {
			return fmt.Errorf("snapshot file %s is not group-readable", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSourceUpdateInvalidatesOldGrantAndTamperIsDetected(t *testing.T) {
	registry := testRegistry(t)
	source := writePlugin(t, t.TempDir(), manifestOptions{}, map[string]string{
		"index.mjs": "export const value = 1;\n",
	})
	first, err := registry.InspectSource(source)
	if err != nil {
		t.Fatal(err)
	}
	oldGrant := grantFor(first)
	if _, err := registry.Register(source, oldGrant); err != nil {
		t.Fatal(err)
	}

	writeFileReplacing(t, filepath.Join(source, "index.mjs"), "export const value = 2;\n", 0o644)
	second, err := registry.InspectSource(source)
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest == second.Digest {
		t.Fatal("source byte change did not change the digest")
	}
	if _, err := registry.Register(source, oldGrant); err == nil || !strings.Contains(err.Error(), "does not exactly match") {
		t.Fatalf("stale grant activated changed source: %v", err)
	}
	if _, err := registry.Activate("workload.example", second.Digest, oldGrant); err == nil {
		t.Fatal("stale grant activated the new digest")
	}
	current, err := registry.Current("workload.example")
	if err != nil || current.Digest != first.Digest {
		t.Fatalf("failed update changed current pointer: %#v, %v", current, err)
	}

	newGrant := grantFor(second)
	updated, err := registry.Register(source, newGrant)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Digest != second.Digest {
		t.Fatalf("unexpected updated digest: %q", updated.Digest)
	}
	if _, err := registry.Activate("workload.example", second.Digest, oldGrant); err == nil {
		t.Fatal("old grant activated an already installed new snapshot")
	}
	entrypoint := filepath.Join(updated.SnapshotPath, "index.mjs")
	if err := os.Chmod(entrypoint, 0o640); err != nil {
		t.Fatal(err)
	}
	writeFileReplacing(t, entrypoint, "export const value = 3;\n", 0o440)
	if _, err := registry.Current("workload.example"); err == nil || !strings.Contains(err.Error(), "no longer matches") {
		t.Fatalf("tampered current snapshot was accepted: %v", err)
	}
}

func TestInvocationLeaseSerializesCurrentDigestMutation(t *testing.T) {
	registry := testRegistry(t)
	firstSource := writePlugin(t, t.TempDir(), manifestOptions{Version: "1.0.0"}, map[string]string{
		"index.mjs": "export const value = 1;\n",
	})
	secondSource := writePlugin(t, t.TempDir(), manifestOptions{Version: "2.0.0"}, map[string]string{
		"index.mjs": "export const value = 2;\n",
	})
	first := mustInspect(t, registry, firstSource)
	second := mustInspect(t, registry, secondSource)
	if _, err := registry.Register(firstSource, grantFor(first)); err != nil {
		t.Fatal(err)
	}

	view, invocationLease, err := registry.LeaseRuntimeCurrent("workload.example", first.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if view.Digest != first.Digest {
		t.Fatalf("invocation lease pinned unexpected digest %q", view.Digest)
	}
	_, independentClientLease, err := registry.LeaseRuntimeCurrent("workload.example", first.Digest)
	if err != nil {
		t.Fatal(err)
	}
	secondRegistry, err := Open(registry.root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secondRegistry.Register(secondSource, grantFor(second)); err == nil ||
		!strings.Contains(err.Error(), "active source-plugin runtime") {
		t.Fatalf("current mutation crossed an active shared invocation lease: %v", err)
	}
	current, err := registry.Current("workload.example")
	if err != nil || current.Digest != first.Digest {
		t.Fatalf("blocked update changed current: %#v, %v", current, err)
	}

	if err := invocationLease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := secondRegistry.Register(secondSource, grantFor(second)); err == nil ||
		!strings.Contains(err.Error(), "active source-plugin runtime") {
		t.Fatalf("closing the outer runner lease released an independent client lease: %v", err)
	}
	if err := independentClientLease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := secondRegistry.Register(secondSource, grantFor(second)); err != nil {
		t.Fatalf("update did not proceed after every invocation lease drained: %v", err)
	}
	if _, staleLease, err := registry.LeaseRuntimeCurrent("workload.example", first.Digest); err == nil {
		_ = staleLease.Close()
		t.Fatal("old digest acquired an invocation lease after current changed")
	}
}

func TestTUISelfUpdateRemainsBlockedByAnotherTUIRuntimeLease(t *testing.T) {
	registry := testRegistry(t)
	options := manifestOptions{
		ID:         "adapter.tui",
		Kind:       KindAdapter,
		Entrypoint: "profile.json",
		Capabilities: []string{
			"adapter.inbound.text", "adapter.outbound.display", "adapter.session.bind", "approval.local",
		},
		RequestedScopes: []string{
			"adapter.inbound.text.local", "adapter.outbound.display.local",
			"adapter.session.bind.local", "approval.submit.local",
		},
	}
	firstSource := writePlugin(t, t.TempDir(), options, map[string]string{
		"profile.json": `{"schemaVersion":1,"profile":"first"}` + "\n",
	})
	options.Version = "2.0.0"
	secondSource := writePlugin(t, t.TempDir(), options, map[string]string{
		"profile.json": `{"schemaVersion":1,"profile":"second"}` + "\n",
	})
	first := mustInspect(t, registry, firstSource)
	second := mustInspect(t, registry, secondSource)
	if _, err := registry.Register(firstSource, grantFor(first)); err != nil {
		t.Fatal(err)
	}
	_, runnerLease, err := registry.LeaseRuntimeCurrent("adapter.tui", first.Digest)
	if err != nil {
		t.Fatal(err)
	}
	_, otherTUILease, err := registry.LeaseRuntimeCurrent("adapter.tui", first.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := runnerLease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Register(secondSource, grantFor(second)); err == nil ||
		!strings.Contains(err.Error(), "active source-plugin runtime") {
		t.Fatalf("self-update handoff released another TUI's independent lease: %v", err)
	}
	if err := otherTUILease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Register(secondSource, grantFor(second)); err != nil {
		t.Fatalf("TUI update remained blocked after every runtime lease drained: %v", err)
	}
}

func TestInvocationLeaseFileMustRemainOwnerControlled(t *testing.T) {
	registry := testRegistry(t)
	source := writePlugin(t, t.TempDir(), manifestOptions{}, map[string]string{
		"index.mjs": "export {};\n",
	})
	inspection := mustInspect(t, registry, source)
	if _, err := registry.Register(source, grantFor(inspection)); err != nil {
		t.Fatal(err)
	}
	leasePath, err := registry.invocationLeasePath("workload.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(leasePath, 0o660); err != nil {
		t.Fatal(err)
	}
	if _, lease, err := registry.LeaseRuntimeCurrent("workload.example", inspection.Digest); err == nil {
		_ = lease.Close()
		t.Fatal("group-writable invocation lease file was accepted")
	}
}

func TestInspectRejectsSymlinksAndSpecialFiles(t *testing.T) {
	registry := testRegistry(t)
	source := writePlugin(t, t.TempDir(), manifestOptions{}, map[string]string{
		"index.mjs": "export {};\n",
	})
	if err := os.Symlink("index.mjs", filepath.Join(source, "alias.mjs")); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.InspectSource(source); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("source symlink was accepted: %v", err)
	}
	if err := os.Remove(filepath.Join(source, "alias.mjs")); err != nil {
		t.Fatal(err)
	}

	pipePath := filepath.Join(source, "plugin.pipe")
	if err := syscall.Mkfifo(pipePath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.InspectSource(source); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("source named pipe was accepted: %v", err)
	}

	shortSource, err := os.MkdirTemp("/tmp", "pluginregistry-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shortSource) })
	writePlugin(t, shortSource, manifestOptions{}, map[string]string{"index.mjs": "export {};\n"})
	socketPath := filepath.Join(shortSource, "plugin.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Log("sandbox does not permit creating a Unix socket; special-file rejection was covered by the named pipe")
			return
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if _, err := registry.InspectSource(shortSource); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("source socket was accepted: %v", err)
	}
}

func TestInspectRejectsUnknownManifestFieldAndPathTraversal(t *testing.T) {
	registry := testRegistry(t)
	source := writePlugin(t, t.TempDir(), manifestOptions{}, map[string]string{
		"index.mjs": "export {};\n",
	})
	payload, err := os.ReadFile(filepath.Join(source, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(payload, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest["trusted"] = true
	writeJSON(t, filepath.Join(source, "manifest.json"), manifest)
	if _, err := registry.InspectSource(source); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown manifest field was accepted: %v", err)
	}

	writeManifest(t, source, manifestOptions{Entrypoint: "../outside.mjs"})
	if _, err := registry.InspectSource(source); err == nil || !strings.Contains(err.Error(), "entrypoint") {
		t.Fatalf("manifest path traversal was accepted: %v", err)
	}
}

func TestGrantMustBindExactRequestedScopes(t *testing.T) {
	registry := testRegistry(t)
	source := writePlugin(t, t.TempDir(), manifestOptions{}, map[string]string{
		"index.mjs": "export {};\n",
	})
	inspection, err := registry.InspectSource(source)
	if err != nil {
		t.Fatal(err)
	}
	grant := grantFor(inspection)
	grant.RequestedScopes = []string{"filesystem.read.system"}
	if _, err := registry.Register(source, grant); err == nil {
		t.Fatal("grant with a subset of requested scopes was accepted")
	}
	grant = grantFor(inspection)
	grant.RequestedScopes = append(grant.RequestedScopes, "system.root")
	if _, err := registry.Register(source, grant); err == nil {
		t.Fatal("grant with an extra requested scope was accepted")
	}
}

func TestCurrentPointerReplacementIsAtomic(t *testing.T) {
	registry := testRegistry(t)
	firstSource := writePlugin(t, t.TempDir(), manifestOptions{Version: "1.0.0"}, map[string]string{
		"index.mjs": "export const value = 1;\n",
	})
	secondSource := writePlugin(t, t.TempDir(), manifestOptions{Version: "2.0.0"}, map[string]string{
		"index.mjs": "export const value = 2;\n",
	})
	first := mustInspect(t, registry, firstSource)
	second := mustInspect(t, registry, secondSource)
	firstGrant := grantFor(first)
	secondGrant := grantFor(second)
	if _, err := registry.Register(firstSource, firstGrant); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Register(secondSource, secondGrant); err != nil {
		t.Fatal(err)
	}

	allowed := map[string]struct{}{first.Digest: {}, second.Digest: {}}

	var wait sync.WaitGroup
	stop := make(chan struct{})
	errorsSeen := make(chan error, 1)
	wait.Add(1)
	go func() {
		defer wait.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			current, err := registry.Current("workload.example")
			if err != nil {
				select {
				case errorsSeen <- fmt.Errorf("current pointer became unreadable during replacement: %w", err):
				default:
				}
				return
			}
			if _, ok := allowed[current.Digest]; !ok {
				select {
				case errorsSeen <- fmt.Errorf("current pointer exposed unexpected digest %q", current.Digest):
				default:
				}
				return
			}
		}
	}()
	for index := 0; index < 40; index++ {
		if _, err := registry.Activate("workload.example", first.Digest, firstGrant); err != nil {
			t.Fatal(err)
		}
		if _, err := registry.Activate("workload.example", second.Digest, secondGrant); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wait.Wait()
	select {
	case err := <-errorsSeen:
		t.Fatal(err)
	default:
	}
}

func TestDeactivateRequiresExactCurrentDigestAndKeepsSnapshot(t *testing.T) {
	registry := testRegistry(t)
	source := writePlugin(t, t.TempDir(), manifestOptions{}, map[string]string{
		"index.mjs": "export {};\n",
	})
	inspection := mustInspect(t, registry, source)
	registration, err := registry.Register(source, grantFor(inspection))
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Deactivate("workload.example", "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("deactivate accepted a digest other than current")
	}
	if err := registry.Deactivate("workload.example", inspection.Digest); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Current("workload.example"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deactivated plugin still has a current pointer: %v", err)
	}
	if _, err := os.Stat(registration.SnapshotPath); err != nil {
		t.Fatalf("deactivate removed recovery snapshot: %v", err)
	}
}

func TestRuntimeDiscoveryReturnsRevalidatedSortedWorkloads(t *testing.T) {
	registry := testRegistry(t)
	firstSource := writePlugin(t, t.TempDir(), manifestOptions{Version: "1.0.0"}, map[string]string{
		"index.mjs": "export const workload = {};\n",
	})
	first := mustInspect(t, registry, firstSource)
	if _, err := registry.Register(firstSource, grantFor(first)); err != nil {
		t.Fatal(err)
	}

	view, err := registry.RuntimeCurrent("workload.example")
	if err != nil {
		t.Fatal(err)
	}
	if view.Entrypoint != "index.mjs" || view.SnapshotPath == "" || view.Digest != first.Digest {
		t.Fatalf("unexpected runtime view: %#v", view)
	}
	listed, err := registry.ListRuntime(KindWorkload)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].PluginID != "workload.example" || listed[0].Digest != first.Digest {
		t.Fatalf("unexpected runtime list: %#v", listed)
	}
	adapters, err := registry.ListRuntime(KindAdapter)
	if err != nil {
		t.Fatal(err)
	}
	if len(adapters) != 0 {
		t.Fatalf("workload appeared in adapter discovery: %#v", adapters)
	}

	if err := os.Chmod(view.SnapshotPath, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(view.SnapshotPath, "index.mjs"), 0o640); err != nil {
		t.Fatal(err)
	}
	writeFileReplacing(t, filepath.Join(view.SnapshotPath, "index.mjs"), "export const workload = {tampered:true};\n", 0o440)
	if err := os.Chmod(view.SnapshotPath, 0o550); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.ListRuntime(KindWorkload); err == nil || !strings.Contains(err.Error(), "no longer matches") {
		t.Fatalf("runtime discovery accepted a tampered active snapshot: %v", err)
	}
}

func TestInspectEnforcesHardSizeLimits(t *testing.T) {
	root := testTempDir(t)
	limits := defaultLimits
	limits.MaxFileBytes = 1024
	limits.MaxTotalBytes = 2048
	limits.MaxManifestBytes = 1024
	registry, err := openWithLimits(filepath.Join(root, "registry"), limits)
	if err != nil {
		t.Fatal(err)
	}
	source := writePlugin(t, filepath.Join(root, "source"), manifestOptions{}, map[string]string{
		"index.mjs": strings.Repeat("x", 1025),
	})
	if _, err := registry.InspectSource(source); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversized source file was accepted: %v", err)
	}
}

func TestRepositorySourcePluginManifests(t *testing.T) {
	_, sourceFile, _, ok := runtimeCaller()
	if !ok {
		t.Fatal("cannot resolve test source path")
	}
	repositoryRoot := filepath.Join(filepath.Dir(sourceFile), "..", "..")
	registry := testRegistry(t)
	for _, test := range []struct {
		path           string
		id             string
		kind           Kind
		expectedDigest string
	}{
		{
			path: "adapter-tui", id: "adapter.tui", kind: KindAdapter,
			expectedDigest: "sha256:230fbaad8b45fda68ea715ecd16db9be419258a5fde4408d21a8bd46767da32a",
		},
		{
			path: "workload-base", id: "workload.base", kind: KindWorkload,
			expectedDigest: "sha256:534be6a85ffd44457e3c6c941b25c40ae241492626d28f5fd1c04d7dad5211e2",
		},
		{path: "workload-example", id: "workload.example", kind: KindWorkload},
		{path: "workload-hermes-ops", id: "workload.hermes-ops", kind: KindWorkload},
		{path: "workload-botmux-ops", id: "workload.botmux-ops", kind: KindWorkload},
		{path: "workload-pve", id: "workload.pve", kind: KindWorkload},
	} {
		inspection, err := registry.InspectSource(filepath.Join(repositoryRoot, "plugins", test.path))
		if err != nil {
			t.Fatalf("inspect repository plugin %s: %v", test.path, err)
		}
		if inspection.Manifest.ID != test.id || inspection.Manifest.Kind != test.kind {
			t.Fatalf("unexpected repository plugin manifest: %#v", inspection.Manifest)
		}
		if test.expectedDigest != "" && inspection.Digest != test.expectedDigest {
			t.Fatalf("repository plugin %s digest changed: got %s, want %s", test.id, inspection.Digest, test.expectedDigest)
		}
	}
}

type manifestOptions struct {
	ID              string
	Kind            Kind
	Entrypoint      string
	Version         string
	Capabilities    []string
	RequestedScopes []string
}

func testRegistry(t *testing.T) *Registry {
	t.Helper()
	root := testTempDir(t)
	registry, err := Open(filepath.Join(root, "registry"))
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func testTempDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Cleanup(func() {
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err == nil && entry.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	return root
}

func writePlugin(t *testing.T, root string, options manifestOptions, files map[string]string) string {
	t.Helper()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	writeManifest(t, root, options)
	for name, payload := range files {
		writeFile(t, filepath.Join(root, filepath.FromSlash(name)), payload, 0o644)
	}
	return root
}

func writeManifest(t *testing.T, root string, options manifestOptions) {
	t.Helper()
	entrypoint := options.Entrypoint
	if entrypoint == "" {
		entrypoint = "index.mjs"
	}
	version := options.Version
	if version == "" {
		version = "1.0.0"
	}
	id := options.ID
	if id == "" {
		id = "workload.example"
	}
	kind := options.Kind
	if kind == "" {
		kind = KindWorkload
	}
	capabilities := options.Capabilities
	if capabilities == nil {
		capabilities = []string{"command.exec", "filesystem.read"}
	}
	requestedScopes := options.RequestedScopes
	if requestedScopes == nil {
		requestedScopes = []string{
			"command.exec.sandbox", "filesystem.read.system", "filesystem.write.workspace",
		}
	}
	manifest := Manifest{
		APIVersion: ManifestAPIVersion, SchemaVersion: ManifestSchema,
		ID: id, Kind: kind, Version: version,
		Publisher: "example/plugin", Description: "Test source plugin",
		Entrypoint:      entrypoint,
		Capabilities:    capabilities,
		RequestedScopes: requestedScopes,
	}
	writeJSON(t, filepath.Join(root, "manifest.json"), manifest)
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload, '\n')
	writeFileReplacing(t, path, string(payload), 0o644)
}

func writeFile(t *testing.T, path, payload string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(payload); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeFileReplacing(t *testing.T, path, payload string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(payload), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func mustInspect(t *testing.T, registry *Registry, source string) Inspection {
	t.Helper()
	inspection, err := registry.InspectSource(source)
	if err != nil {
		t.Fatal(err)
	}
	return inspection
}

func grantFor(inspection Inspection) Grant {
	return Grant{
		PluginID: inspection.Manifest.ID, Kind: inspection.Manifest.Kind, Digest: inspection.Digest,
		RequestedScopes: slices.Clone(inspection.Manifest.RequestedScopes), ApprovedBy: "local-admin:1000",
		ApprovedAt: time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC),
	}
}

// Kept behind a variable so the repository-path test is easy to exercise from
// external build systems without relying on the process working directory.
var runtimeCaller = func() (uintptr, string, int, bool) {
	return runtime.Caller(0)
}
