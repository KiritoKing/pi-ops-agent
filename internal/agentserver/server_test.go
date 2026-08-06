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
	if forwarded.Method != protocol.MethodChangeApprove || forwarded.CallerRole != "approver" || forwarded.TargetID != "target-hermes" || forwarded.PolicyRevision != "policy-12345678" {
		t.Fatalf("unexpected forwarded request %#v", forwarded)
	}
	var response publicResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || response.ChangeID != "change-12345678" {
		t.Fatalf("unexpected public response %s", recorder.Body.String())
	}
}

func actionBody(now time.Time) string {
	grant := `"approval":{"version":1,"keyId":"approver-test-v1","action":"approve","serverId":"server-12345678","machineId":"machine-12345678","targetId":"target-hermes","changeId":"change-12345678","planHash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policyRevision":"policy-12345678","issuedAt":"2026-08-06T12:00:00Z","expiresAt":"2026-08-06T12:01:00Z","nonce":"nonce-agentserver-test-12345678","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`
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

func TestCapabilitiesPublishOnlyImplementedPluginInstall(t *testing.T) {
	server, _ := testServer(t, time.Now())
	handler, _ := server.Handler()
	request := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	request.TLS = tlsState(t, RoleAgent)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK || strings.Contains(body, "breakglass") || !strings.Contains(body, "plugin.install") || strings.Contains(body, "plugin.configure") || strings.Contains(body, "plugin.remove") {
		t.Fatalf("unsafe capability was published: %s", body)
	}
}

func testServer(t *testing.T, now time.Time) (*Server, *fakeBackend) {
	t.Helper()
	directory := t.TempDir()
	policyPayload := fmt.Sprintf(`{"version":1,"revision":"policy-12345678","targets":[{"id":"target-hermes","account":"hermes-agent","displayName":"Hermes","inspect":{"hostSnapshot":true,"processList":true,"units":["hermes.service"],"readPaths":[%q]},"changes":{"writePaths":[%q],"units":["hermes.service"],"packages":["hermes"],"plugins":["adapter.botmux"]}}]}`, directory, directory)
	policy, err := targetpolicy.Parse([]byte(policyPayload))
	if err != nil {
		t.Fatal(err)
	}
	backend := &fakeBackend{}
	return &Server{
		Identity: Identity{Version: 1, ServerID: "server-12345678", MachineID: "machine-12345678", MachineName: "Hermes host", Account: "ops-agent-server"},
		Policy:   policy, Backend: backend, Now: func() time.Time { return now },
	}, backend
}

func requestBody(now time.Time, extra string) string {
	if extra != "" {
		extra = "," + extra
	}
	return fmt.Sprintf(`{"version":1,"requestId":"request-12345678","deadline":%q,"machineId":"machine-12345678","targetId":"target-hermes"%s}`, now.Add(time.Minute).Format(time.RFC3339Nano), extra)
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
