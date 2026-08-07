package agentserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
	"github.com/KiritoKing/pi-ops-agent/internal/targetpolicy"
)

type fakeBackend struct {
	requests  []protocol.Request
	responses []protocol.Response
}

func (f *fakeBackend) Do(_ context.Context, request protocol.Request) (protocol.Response, error) {
	f.requests = append(f.requests, request)
	if len(f.responses) == 0 {
		return protocol.Response{Version: protocol.Version, RequestID: request.RequestID, OK: true}, nil
	}
	response := f.responses[0]
	f.responses = f.responses[1:]
	response.RequestID = request.RequestID
	return response, nil
}

func TestAgentRoleCanInspectButCannotApprove(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	server, backend := testServer(t, now)
	handler, err := server.Handler()
	if err != nil {
		t.Fatal(err)
	}
	body := requestBody(now, `"method":"host.snapshot"`)
	request := httptest.NewRequest(http.MethodPost, "/v1/inspect", strings.NewReader(body))
	request.TLS = tlsState(t, RoleAgent)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || len(backend.requests) != 1 || backend.requests[0].CallerRole != "agent" || backend.requests[0].Method != protocol.MethodHostSnapshot {
		t.Fatalf("inspect code=%d body=%s requests=%#v", recorder.Code, recorder.Body.String(), backend.requests)
	}

	approve := httptest.NewRequest(http.MethodPost, "/v1/changes/change-12345678/approve", strings.NewReader(requestBody(now, "")))
	approve.TLS = tlsState(t, RoleAgent)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, approve)
	if recorder.Code != http.StatusForbidden || len(backend.requests) != 1 {
		t.Fatal("agent role reached approval backend")
	}
}

func TestAgentRoleForwardsEveryInspectionTaggedUnion(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		extra    string
		method   protocol.Method
		path     string
		maxBytes int
	}{
		{name: "process", extra: `"method":"process.list"`, method: protocol.MethodProcessList},
		{name: "metadata", extra: `"method":"file.metadata","path":"/etc/os-release"`, method: protocol.MethodFileMetadata, path: "/etc/os-release"},
		{name: "read", extra: `"method":"file.read","path":"/etc/os-release","maxBytes":4096`, method: protocol.MethodFileRead, path: "/etc/os-release", maxBytes: 4096},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, backend := testServer(t, now)
			handler, err := server.Handler()
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/v1/inspect", strings.NewReader(requestBody(now, test.extra)))
			request.TLS = tlsState(t, RoleAgent)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK || len(backend.requests) != 1 {
				t.Fatalf("inspect code=%d body=%s requests=%#v", recorder.Code, recorder.Body.String(), backend.requests)
			}
			forwarded := backend.requests[0]
			if forwarded.Method != test.method || forwarded.Path != test.path || forwarded.MaxBytes != test.maxBytes {
				t.Fatalf("unexpected forwarded inspection: %#v", forwarded)
			}
		})
	}
}

func TestInspectRejectsFieldsOutsideTheSelectedTag(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	for _, extra := range []string{
		`"method":"systemd.unit","unit":"example.service","lines":10`,
		`"method":"file.metadata","path":"/etc/os-release","maxBytes":1024`,
	} {
		server, backend := testServer(t, now)
		handler, err := server.Handler()
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/v1/inspect", strings.NewReader(requestBody(now, extra)))
		request.TLS = tlsState(t, RoleAgent)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusBadRequest || len(backend.requests) != 0 {
			t.Fatalf("invalid inspection reached backend: code=%d body=%s", recorder.Code, recorder.Body.String())
		}
	}
}

func TestApproverRoleForwardsScopedAction(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	server, backend := testServer(t, now)
	backend.responses = []protocol.Response{{Version: 1, OK: true, ChangeID: "change-12345678", State: "COMMITTED"}}
	handler, _ := server.Handler()
	request := httptest.NewRequest(http.MethodPost, "/v1/changes/change-12345678/approve", strings.NewReader(actionBody(now)))
	request.TLS = tlsState(t, RoleApprover)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || len(backend.requests) != 1 {
		t.Fatalf("approve code=%d body=%s", recorder.Code, recorder.Body.String())
	}
	forwarded := backend.requests[0]
	if forwarded.Method != protocol.MethodChangeApprove || forwarded.CallerRole != "approver" || forwarded.TargetID != "target-service" || forwarded.PolicyRevision != "policy-12345678" {
		t.Fatalf("unexpected forwarded request %#v", forwarded)
	}
	var response publicResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || response.ChangeID != "change-12345678" {
		t.Fatalf("unexpected public response %s", recorder.Body.String())
	}
}

func actionBody(now time.Time) string {
	grant := `"approval":{"version":1,"keyId":"approver-test-v1","action":"approve","serverId":"server-12345678","machineId":"machine-12345678","targetId":"target-service","changeId":"change-12345678","planHash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policyRevision":"policy-12345678","issuedAt":"2026-08-06T12:00:00Z","expiresAt":"2026-08-06T12:01:00Z","nonce":"nonce-agentserver-test-12345678","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`
	return requestBody(now, grant)
}

func TestStrictJSONScopeAndCertificateRole(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	server, backend := testServer(t, now)
	handler, _ := server.Handler()
	request := httptest.NewRequest(http.MethodPost, "/v1/inspect", strings.NewReader(requestBody(now, `"method":"host.snapshot","command":"id"`)))
	request.TLS = tlsState(t, RoleAgent)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || len(backend.requests) != 0 {
		t.Fatal("unknown JSON field reached backend")
	}

	request = httptest.NewRequest(http.MethodGet, "/v1/identity", nil)
	request.TLS = tlsState(t, RoleAgent, RoleApprover)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatal("certificate with multiple roles was accepted")
	}
}

func TestCapabilitiesPublishOnlyImplementedArtifactOperations(t *testing.T) {
	server, _ := testServer(t, time.Now())
	handler, _ := server.Handler()
	request := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	request.TLS = tlsState(t, RoleAgent)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK || !strings.Contains(body, `"revision":"capability-remote-mvp-v3"`) || strings.Contains(body, "breakglass") || !strings.Contains(body, "process.list") || !strings.Contains(body, "file.metadata") || !strings.Contains(body, "file.read") || !strings.Contains(body, "plugin.install") || !strings.Contains(body, "workload.deploy") || strings.Contains(body, "plugin.configure") || strings.Contains(body, "plugin.remove") {
		t.Fatalf("unsafe capability was published: %s", body)
	}
}

func TestArtifactCatalogIsTargetScopedAndHidesHostDetails(t *testing.T) {
	server, _ := testServer(t, time.Now())
	handler, _ := server.Handler()
	request := httptest.NewRequest(http.MethodGet, "/v1/artifacts?targetId=target-managed", nil)
	request.TLS = tlsState(t, RoleAgent)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK || !strings.Contains(body, `"kind":"managed-workload"`) || !strings.Contains(body, `"publisher":"example/ops"`) || !strings.Contains(body, `"artifactRef":"builtin:sha256:`) {
		t.Fatalf("unexpected artifact catalog: %s", body)
	}
	if strings.Contains(body, "credentialBundleDigest") || strings.Contains(body, "catalogPath") {
		t.Fatalf("artifact catalog leaked host-only details: %s", body)
	}

	request = httptest.NewRequest(http.MethodGet, "/v1/artifacts", nil)
	request.TLS = tlsState(t, RoleAgent)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("artifact catalog accepted missing targetId: %s", recorder.Body.String())
	}
}

func testServer(t *testing.T, now time.Time) (*Server, *fakeBackend) {
	t.Helper()
	directory := t.TempDir()
	digest := "sha256:" + strings.Repeat("a", 64)
	credentialDigest := "sha256:" + strings.Repeat("b", 64)
	policyPayload := fmt.Sprintf(`{"version":1,"revision":"policy-12345678","targets":[{"id":"target-service","account":"service_agent","displayName":"Service","inspect":{"hostSnapshot":true,"processList":true,"units":["example.service"],"readPaths":[%q]},"changes":{"writePaths":[%q],"units":["example.service"],"packages":["example"],"plugins":[{"id":"adapter.web","kind":"im-adapter","version":"1.0.0","publisher":"example/ops","digest":%q}]}},{"id":"target-managed","account":"managed_agent","displayName":"Managed workload","inspect":{"hostSnapshot":true,"processList":true,"units":[],"readPaths":[%q]},"changes":{"writePaths":[],"units":[],"packages":[],"plugins":[{"id":"workload.assistant","kind":"managed-workload","version":"1.0.0","publisher":"example/ops","digest":%q,"credentialBundleDigest":%q}]}}]}`, directory, directory, digest, directory, digest, credentialDigest)
	policy, err := targetpolicy.Parse([]byte(policyPayload))
	if err != nil {
		t.Fatal(err)
	}
	backend := &fakeBackend{}
	return &Server{
		Identity: Identity{Version: 1, ServerID: "server-12345678", MachineID: "machine-12345678", MachineName: "Managed host", Account: "ops-agent-server"},
		Policy:   policy, Backend: backend, Now: func() time.Time { return now },
	}, backend
}

func requestBody(now time.Time, extra string) string {
	if extra != "" {
		extra = "," + extra
	}
	return fmt.Sprintf(`{"version":1,"requestId":"request-12345678","deadline":%q,"machineId":"machine-12345678","targetId":"target-service"%s}`, now.Add(time.Minute).Format(time.RFC3339Nano), extra)
}

func tlsState(t *testing.T, roles ...Role) *tls.ConnectionState {
	t.Helper()
	certificate := &x509.Certificate{Raw: []byte("client-certificate")}
	for _, role := range roles {
		parsed, err := url.Parse("spiffe://ops-agent/role/" + string(role))
		if err != nil {
			t.Fatal(err)
		}
		certificate.URIs = append(certificate.URIs, parsed)
	}
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate}}}
}
