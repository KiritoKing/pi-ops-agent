package pluginlease

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/peercred"
	"github.com/KiritoKing/pi-ops-agent/internal/pluginregistry"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

func testAuthorizer(maxDuration time.Duration) Authorizer {
	return Authorizer{
		AdministratorUID:    1000,
		AgentUID:            1001,
		BotMuxUID:           1002,
		WorkloadMaxDuration: maxDuration,
		LookupUsername: func(uid uint32) (string, error) {
			return map[uint32]string{
				2001: "ops-adapter-example",
				2002: "ops-adapter-second",
				2999: "ops-agent-server",
			}[uid], nil
		},
	}
}

func TestAuthorizerBindsEveryPeerToItsExactLeaseClass(t *testing.T) {
	authorizer := testAuthorizer(time.Minute)
	allowed := []struct {
		uid      uint32
		pluginID string
	}{
		{1000, "adapter.tui"},
		{1000, "workload.base"},
		{1001, "workload.example"},
		{1002, "adapter.botmux"},
		{2001, "adapter.example"},
	}
	for _, test := range allowed {
		if _, err := authorizer.Authorize(test.uid, test.pluginID); err != nil {
			t.Fatalf("expected uid=%d plugin=%s to be authorized: %v", test.uid, test.pluginID, err)
		}
	}
	denied := []struct {
		uid      uint32
		pluginID string
	}{
		{0, "workload.base"},
		{1000, "adapter.example"},
		{1001, "adapter.tui"},
		{1002, "workload.base"},
		{2001, "adapter.second"},
		{2001, "adapter.tui"},
		{2001, "workload.example"},
		{2999, "workload.example"},
		{2999, "adapter.example"},
	}
	for _, test := range denied {
		if _, err := authorizer.Authorize(test.uid, test.pluginID); err == nil {
			t.Fatalf("identity confusion authorized uid=%d plugin=%s", test.uid, test.pluginID)
		}
	}
}

func TestLeaseConnectionPinsExactDigestUntilAcknowledgedRelease(t *testing.T) {
	registry, firstSource, first := leaseTestRegistry(t, "1.0.0", "export const value = 1;\n")
	if _, err := registry.Register(firstSource, leaseGrant(first)); err != nil {
		t.Fatal(err)
	}
	secondSource := writeLeasePlugin(t, filepath.Join(t.TempDir(), "second"), "2.0.0", "export const value = 2;\n")
	second, err := registry.InspectSource(secondSource)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Registry: registry, Authorizer: testAuthorizer(time.Minute)}
	client, handler := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.ServeConnection(context.Background(), handler, peercred.Credential{UID: 1001})
		_ = handler.Close()
	}()
	defer client.Close()
	writeLeaseFrame(t, client, Request{Version: Version, PluginID: "workload.example", Digest: first.Digest})
	response := readLeaseResponse(t, client)
	if !response.OK || response.State != "LEASED" || response.Registration == nil || response.Registration.Digest != first.Digest {
		t.Fatalf("unexpected lease response: %#v", response)
	}
	if _, err := registry.Register(secondSource, leaseGrant(second)); err == nil ||
		!strings.Contains(err.Error(), "active source-plugin runtime") {
		t.Fatalf("digest update crossed a broker-held lease: %v", err)
	}
	writeLeaseFrame(t, client, releaseRequest{Version: Version, Action: "release"})
	released := readLeaseResponse(t, client)
	if !released.OK || released.State != "RELEASED" {
		t.Fatalf("unexpected release acknowledgement: %#v", released)
	}
	<-done
	if _, err := registry.Register(secondSource, leaseGrant(second)); err != nil {
		t.Fatalf("update remained blocked after acknowledged release: %v", err)
	}
}

func TestDisconnectRestartAndHardDeadlineReleaseLocks(t *testing.T) {
	for _, test := range []struct {
		name     string
		duration time.Duration
		restart  bool
	}{
		{name: "broker restart", duration: time.Minute, restart: true},
		{name: "workload hard deadline", duration: 40 * time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			registry, source, first := leaseTestRegistry(t, "1.0.0", "export {};\n")
			if _, err := registry.Register(source, leaseGrant(first)); err != nil {
				t.Fatal(err)
			}
			updatedSource := writeLeasePlugin(t, filepath.Join(t.TempDir(), "updated"), "2.0.0", "export const updated = true;\n")
			updated, err := registry.InspectSource(updatedSource)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			server := &Server{Registry: registry, Authorizer: testAuthorizer(test.duration)}
			client, handler := net.Pipe()
			done := make(chan struct{})
			go func() {
				defer close(done)
				server.ServeConnection(ctx, handler, peercred.Credential{UID: 1001})
				_ = handler.Close()
			}()
			writeLeaseFrame(t, client, Request{Version: Version, PluginID: "workload.example", Digest: first.Digest})
			if response := readLeaseResponse(t, client); !response.OK || response.State != "LEASED" {
				t.Fatalf("unexpected lease response: %#v", response)
			}
			if test.restart {
				cancel()
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("lease remained held after broker restart or hard deadline")
			}
			_ = client.Close()
			cancel()
			if _, err := registry.Register(updatedSource, leaseGrant(updated)); err != nil {
				t.Fatalf("lock survived broker termination: %v", err)
			}
		})
	}
}

func TestUnauthorizedAndStaleDigestRequestsNeverAcquireLease(t *testing.T) {
	registry, source, inspection := leaseTestRegistry(t, "1.0.0", "export {};\n")
	if _, err := registry.Register(source, leaseGrant(inspection)); err != nil {
		t.Fatal(err)
	}
	server := &Server{Registry: registry, Authorizer: testAuthorizer(time.Minute)}
	for _, test := range []struct {
		name   string
		uid    uint32
		digest string
	}{
		{name: "unauthorized server uid", uid: 2999, digest: inspection.Digest},
		{name: "stale digest", uid: 1001, digest: "sha256:" + strings.Repeat("f", 64)},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, handler := net.Pipe()
			done := make(chan struct{})
			go func() {
				defer close(done)
				server.ServeConnection(context.Background(), handler, peercred.Credential{UID: test.uid})
				_ = handler.Close()
			}()
			writeLeaseFrame(t, client, Request{Version: Version, PluginID: "workload.example", Digest: test.digest})
			response := readLeaseResponse(t, client)
			if response.OK || response.Error == "" {
				t.Fatalf("unsafe lease request succeeded: %#v", response)
			}
			_ = client.Close()
			<-done
		})
	}
}

func TestAdmissionBoundsTotalUIDAndPluginFloods(t *testing.T) {
	limits, err := newAdmission(2, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	releaseUID1, ok := limits.acquireUID(1001)
	if !ok {
		t.Fatal("first UID slot was rejected")
	}
	releasePlugin, ok := limits.acquirePlugin(1001, "workload.base")
	if !ok {
		t.Fatal("first UID/plugin slot was rejected")
	}
	if _, ok := limits.acquirePlugin(1001, "workload.base"); ok {
		t.Fatal("same UID/plugin exceeded its concurrent limit")
	}
	releaseUID2, ok := limits.acquireUID(1001)
	if !ok {
		t.Fatal("second UID slot was rejected")
	}
	if _, ok := limits.acquireUID(2001); ok {
		t.Fatal("global connection flood exceeded its limit")
	}
	releasePlugin()
	releaseUID2()
	releaseUID1()
	if release, ok := limits.acquireUID(2001); !ok {
		t.Fatal("released admission slots were not reusable")
	} else {
		release()
	}
}

func TestLeaseFramesRejectUnknownFieldsTrailingDataAndInvalidRelease(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload string
	}{
		{name: "unknown request field", payload: `{"version":1,"pluginId":"workload.example","digest":"sha256:` + strings.Repeat("a", 64) + `","root":"/tmp/attacker"}`},
		{name: "trailing JSON", payload: `{"version":1,"pluginId":"workload.example","digest":"sha256:` + strings.Repeat("a", 64) + `"}{}`},
		{name: "invalid version", payload: `{"version":2,"pluginId":"workload.example","digest":"sha256:` + strings.Repeat("a", 64) + `"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseRequest([]byte(test.payload)); err == nil {
				t.Fatal("unsafe plugin lease request was accepted")
			}
		})
	}
	for _, payload := range []string{
		`{"version":1,"action":"release","digest":"sha256:` + strings.Repeat("a", 64) + `"}`,
		`{"version":1,"action":"keepalive"}`,
		`{"version":2,"action":"release"}`,
	} {
		if err := parseRelease([]byte(payload)); err == nil {
			t.Fatalf("unsafe plugin lease release was accepted: %s", payload)
		}
	}
}

func leaseTestRegistry(t *testing.T, version, body string) (*pluginregistry.Registry, string, pluginregistry.Inspection) {
	t.Helper()
	registryRoot := filepath.Join(t.TempDir(), "registry")
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
	source := writeLeasePlugin(t, filepath.Join(t.TempDir(), "source"), version, body)
	inspection, err := registry.InspectSource(source)
	if err != nil {
		t.Fatal(err)
	}
	return registry, source, inspection
}

func writeLeasePlugin(t *testing.T, root, version, body string) string {
	t.Helper()
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{
		"apiVersion": "agentd.plugin/v1", "schemaVersion": 1,
		"id": "workload.example", "kind": "workload", "version": version,
		"publisher": "example/plugin-lease", "description": "Lease broker test workload",
		"entrypoint": "workload.mjs", "capabilities": []string{"demo.echo"},
		"requestedScopes": []string{},
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

func leaseGrant(inspection pluginregistry.Inspection) pluginregistry.Grant {
	return pluginregistry.Grant{
		PluginID: inspection.Manifest.ID, Kind: inspection.Manifest.Kind, Digest: inspection.Digest,
		RequestedScopes: inspection.Manifest.RequestedScopes,
		ApprovedBy:      "test:plugin-lease", ApprovedAt: time.Now().UTC(),
	}
}

func writeLeaseFrame(t *testing.T, connection net.Conn, value any) {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.WriteFrame(connection, payload); err != nil {
		t.Fatal(err)
	}
}

func readLeaseResponse(t *testing.T, connection net.Conn) Response {
	t.Helper()
	payload, err := protocol.ReadFrame(connection)
	if err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.Unmarshal(payload, &response); err != nil {
		t.Fatal(err)
	}
	return response
}
