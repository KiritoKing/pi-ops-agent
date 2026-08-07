package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestFrameRoundTripAndLimits(t *testing.T) {
	payload := []byte(`{"version":1}`)
	var framed bytes.Buffer
	if err := WriteFrame(&framed, payload); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadFrame(&framed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("decoded %q, want %q", decoded, payload)
	}
	var invalid bytes.Buffer
	binary.Write(&invalid, binary.BigEndian, uint32(MaxFrameBytes+1))
	if _, err := ReadFrame(&invalid); err == nil {
		t.Fatal("oversized frame was accepted")
	}
}

func TestParseRequestStrictTaggedUnion(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	deadline := now.Add(time.Minute).Format(time.RFC3339Nano)
	valid := fmt.Sprintf(`{"version":1,"requestId":"request-12345678","deadline":%q,"method":"change.prepare","operation":{"kind":"package.install","package":"nginx","version":"1.2.3"}}`, deadline)
	request, err := ParseRequest([]byte(valid), now)
	if err != nil {
		t.Fatal(err)
	}
	operation, ok := request.Operation.(*PackageInstall)
	if !ok || operation.Package != "nginx" {
		t.Fatalf("unexpected operation %#v", request.Operation)
	}

	unknownTop := strings.Replace(valid, `"method":`, `"unexpected":true,"method":`, 1)
	if _, err := ParseRequest([]byte(unknownTop), now); err == nil {
		t.Fatal("unknown top-level field was accepted")
	}
	unknownOperation := strings.Replace(valid, `"package":"nginx"`, `"package":"nginx","command":"rm"`, 1)
	if _, err := ParseRequest([]byte(unknownOperation), now); err == nil {
		t.Fatal("unknown operation field was accepted")
	}
	wrongTag := strings.Replace(valid, `"package.install"`, `"raw.command"`, 1)
	if _, err := ParseRequest([]byte(wrongTag), now); err == nil {
		t.Fatal("unsupported operation tag was accepted")
	}
}

func TestWorkloadDeployOnlyAcceptsAPinnedBuiltinArtifact(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	deadline := now.Add(time.Minute).Format(time.RFC3339Nano)
	digest := "sha256:" + strings.Repeat("a", 64)
	valid := fmt.Sprintf(`{"version":1,"requestId":"request-workload-1234","deadline":%q,"method":"change.prepare","operation":{"kind":"workload.deploy","pluginId":"workload.assistant","version":"1.0.0","publisher":"example/ops","digest":%q,"artifactRef":%q}}`, deadline, digest, "builtin:"+digest)
	request, err := ParseRequest([]byte(valid), now)
	if err != nil {
		t.Fatal(err)
	}
	operation, ok := request.Operation.(*WorkloadDeploy)
	if !ok || operation.Digest != digest || operation.ArtifactRef != "builtin:"+digest {
		t.Fatalf("unexpected workload operation %#v", request.Operation)
	}
	for _, injected := range []string{
		strings.Replace(valid, `"pluginId":`, `"hostPath":"/root","pluginId":`, 1),
		strings.Replace(valid, `"artifactRef":"builtin:sha256:`, `"artifactRef":"https://example.com/`, 1),
		strings.Replace(valid, `"artifactRef":"builtin:sha256:`+strings.Repeat("a", 64)+`"`, `"artifactRef":"builtin:sha256:`+strings.Repeat("b", 64)+`"`, 1),
	} {
		if _, err := ParseRequest([]byte(injected), now); err == nil {
			t.Fatal("unsafe workload artifact input was accepted")
		}
	}
}

func TestParseRequestRejectsExpiredAndDistantDeadline(t *testing.T) {
	now := time.Now().UTC()
	for _, deadline := range []time.Time{now.Add(-time.Second), now.Add(11 * time.Minute)} {
		payload := fmt.Sprintf(`{"version":1,"requestId":"request-12345678","deadline":%q,"method":"heartbeat"}`, deadline.Format(time.RFC3339Nano))
		if _, err := ParseRequest([]byte(payload), now); err == nil {
			t.Fatalf("accepted deadline %s", deadline)
		}
	}
}

func TestRemoteRequestScopeAndPluginOperationsAreStrict(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	digest := "sha256:" + strings.Repeat("a", 64)
	base := fmt.Sprintf(`{"version":1,"requestId":"request-remote-0001","deadline":%q,"method":"change.prepare","serverId":"server-12345678","machineId":"machine-12345678","targetId":"service","sessionId":"session-12345678","turnId":"turn-12345678","policyRevision":"policy-12345678","callerRole":"agent","operation":{"kind":"plugin.install","pluginId":"adapter.botmux","version":"1.0.0","publisher":"example/ops","digest":%q,"artifactRef":%q}}`, now.Add(time.Minute).Format(time.RFC3339Nano), digest, "builtin:"+digest)
	request, err := ParseRequest([]byte(base), now)
	if err != nil {
		t.Fatal(err)
	}
	operation, ok := request.Operation.(*PluginInstall)
	if !ok || operation.PluginID != "adapter.botmux" || request.TargetID != "service" {
		t.Fatalf("unexpected remote operation %#v", request)
	}
	missingRole := strings.Replace(base, `,"callerRole":"agent"`, "", 1)
	if _, err := ParseRequest([]byte(missingRole), now); err == nil {
		t.Fatal("remote request without caller role was accepted")
	}
	remoteURL := strings.Replace(base, `"artifactRef":"builtin:`, `"artifactRef":"https://example.com/`, 1)
	if _, err := ParseRequest([]byte(remoteURL), now); err == nil {
		t.Fatal("remote plugin URL was accepted as a builtin artifact reference")
	}
}

func TestV01PluginOperationsAreStoredOnlyAndStrict(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	deadline := now.Add(time.Minute).Format(time.RFC3339Nano)
	digest := "sha256:" + strings.Repeat("a", 64)
	legacyInstall := fmt.Sprintf(`{"kind":"plugin.install","pluginId":"adapter.botmux","version":"0.1.0","digest":%q,"catalogPath":"/opt/pi-ops-agent/current/catalog/adapter.botmux.json"}`, digest)
	legacyConfigure := fmt.Sprintf(`{"kind":"plugin.configure","pluginId":"adapter.botmux","version":"0.1.0","digest":%q,"settings":[{"name":"TOKEN_FILE","value":"/run/credentials/token"}]}`, digest)
	legacyRemove := fmt.Sprintf(`{"kind":"plugin.remove","pluginId":"adapter.botmux","version":"0.1.0","digest":%q}`, digest)

	for index, legacy := range []string{legacyInstall, legacyConfigure, legacyRemove} {
		request := fmt.Sprintf(`{"version":1,"requestId":"legacy-prepare-%04d","deadline":%q,"method":"change.prepare","operation":%s}`, index, deadline, legacy)
		if _, err := ParseRequest([]byte(request), now); err == nil {
			t.Fatalf("legacy operation %d was accepted as a new prepare", index)
		}
		operation, err := ParseStoredOperation([]byte(legacy))
		if err != nil {
			t.Fatalf("read legacy operation %d: %v", index, err)
		}
		if !IsStoredOnlyOperation(operation) {
			t.Fatalf("legacy operation %d was not marked stored-only", index)
		}
		if _, err := MarshalOperation(operation); err == nil {
			t.Fatalf("legacy operation %d was marshaled into a new change", index)
		}
		wantRollback := index == 0
		if StoredRollbackSupported(operation) != wantRollback {
			t.Fatalf("legacy operation %d rollback support=%v, want %v", index, StoredRollbackSupported(operation), wantRollback)
		}
	}

	operation, err := ParseStoredOperation([]byte(legacyInstall))
	if err != nil {
		t.Fatal(err)
	}
	install, ok := operation.(*PluginInstall)
	if !ok || install.Publisher != "legacy/v0.1" || install.ArtifactRef != "builtin:"+digest {
		t.Fatalf("legacy install was not safely normalized: %#v", operation)
	}

	invalidStored := []string{
		strings.Replace(legacyInstall, `"catalogPath":`, `"command":"sh","catalogPath":`, 1),
		strings.Replace(legacyInstall, `/opt/pi-ops-agent/current/catalog/adapter.botmux.json`, `/opt/pi-ops-agent/current/../secret`, 1),
		strings.Replace(legacyConfigure, `"settings":[`, `"settings":[{"name":"TOKEN_FILE","value":"duplicate"},`, 1),
		strings.Replace(legacyRemove, `}`, `,"settings":[]}`, 1),
	}
	for index, invalid := range invalidStored {
		if _, err := ParseStoredOperation([]byte(invalid)); err == nil {
			t.Fatalf("invalid legacy stored operation %d was accepted", index)
		}
	}
}
