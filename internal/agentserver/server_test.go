package agentserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/admission"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
	"github.com/KiritoKing/pi-ops-agent/internal/targetpolicy"
)

type fakeBackend struct {
	requests  []protocol.Request
	responses []protocol.Response
}

type blockingBackend struct {
	started chan struct{}
	release <-chan struct{}
	calls   atomic.Int32
}

func (b *blockingBackend) Do(ctx context.Context, request protocol.Request) (protocol.Response, error) {
	b.calls.Add(1)
	select {
	case b.started <- struct{}{}:
	default:
	}
	select {
	case <-b.release:
		return protocol.Response{Version: protocol.Version, RequestID: request.RequestID, OK: true}, nil
	case <-ctx.Done():
		return protocol.Response{}, ctx.Err()
	}
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

func TestWorkloadCommandInspectionIsAgentOnlyAndForwardsNoRecipeFields(t *testing.T) {
	now := time.Date(2026, 8, 8, 14, 30, 0, 0, time.UTC)
	digest := "sha256:" + strings.Repeat("a", 64)
	server, backend := testServer(t, now)
	handler, err := server.Handler()
	if err != nil {
		t.Fatal(err)
	}
	body := requestBody(now, `"method":"workload.command.inspect","pluginId":"workload.example-command","pluginDigest":"`+digest+`","profileKey":"example.status"`)
	request := httptest.NewRequest(http.MethodPost, "/v1/workload-command-inspections", strings.NewReader(body))
	request.TLS = tlsState(t, RoleAgent)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || len(backend.requests) != 1 {
		t.Fatalf("agent command inspection was not forwarded: %d %s %#v", recorder.Code, recorder.Body.String(), backend.requests)
	}
	forwarded := backend.requests[0]
	if forwarded.Method != protocol.MethodWorkloadCommandInspect || forwarded.CallerRole != "agent" ||
		forwarded.WorkloadCommand.PluginID != "workload.example-command" ||
		forwarded.WorkloadCommand.PluginDigest != digest || forwarded.WorkloadCommand.ProfileKey != "example.status" {
		t.Fatalf("command profile identity changed at HTTPS boundary: %#v", forwarded)
	}

	for _, test := range []struct {
		role Role
		body string
	}{
		{role: RoleAdmin, body: body},
		{role: RoleObserver, body: body},
		{role: RoleAgent, body: requestBody(now, `"method":"workload.command.inspect","pluginId":"workload.example-command","pluginDigest":"`+digest+`","profileKey":"example.status","executable":"/bin/sh"`)},
		{role: RoleAgent, body: requestBody(now, `"method":"workload.command.inspect","pluginId":"workload.example-command","pluginDigest":"`+digest+`","profileKey":"../status"`)},
	} {
		request = httptest.NewRequest(http.MethodPost, "/v1/workload-command-inspections", strings.NewReader(test.body))
		request.TLS = tlsState(t, test.role)
		recorder = httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code == http.StatusOK {
			t.Fatalf("unsafe command inspection reached backend: role=%s body=%s", test.role, test.body)
		}
	}
	if len(backend.requests) != 1 {
		t.Fatalf("rejected command inspection reached backend: %#v", backend.requests)
	}
}

func TestObserverRoleCanReadMetadataAndChangeStatusOnly(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	server, backend := testServer(t, now)
	handler, err := server.Handler()
	if err != nil {
		t.Fatal(err)
	}
	metadataRequests := []*http.Request{
		httptest.NewRequest(http.MethodGet, "/v1/health", nil),
		httptest.NewRequest(http.MethodGet, "/v1/identity", nil),
		httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil),
		httptest.NewRequest(http.MethodGet, "/v1/targets", nil),
		httptest.NewRequest(http.MethodGet, "/v1/artifacts?targetId=target-managed", nil),
	}
	for _, request := range metadataRequests {
		request.TLS = tlsState(t, RoleObserver)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("observer metadata request %s failed: %d %s", request.URL.Path, recorder.Code, recorder.Body.String())
		}
	}

	statusURL := fmt.Sprintf(
		"/v1/changes/change-12345678?requestId=request-observer-status&deadline=%s&machineId=machine-12345678&targetId=target-service",
		url.QueryEscape(now.Add(time.Minute).Format(time.RFC3339Nano)),
	)
	status := httptest.NewRequest(http.MethodGet, statusURL, nil)
	status.TLS = tlsState(t, RoleObserver)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, status)
	if recorder.Code != http.StatusOK || len(backend.requests) != 1 || backend.requests[0].CallerRole != "observer" || backend.requests[0].Method != protocol.MethodChangeStatus {
		t.Fatalf("observer status was not narrowly forwarded: code=%d body=%s requests=%#v", recorder.Code, recorder.Body.String(), backend.requests)
	}

	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "/v1/inspect", strings.NewReader(requestBody(now, `"method":"host.snapshot"`))),
		httptest.NewRequest(http.MethodPost, "/v1/changes", strings.NewReader(requestBody(now, `"method":"change.prepare","operation":{"kind":"package.install","package":"example"},"policyRevision":"policy-12345678","capabilityRevision":"capability-remote-v0.3-v8"`))),
		httptest.NewRequest(http.MethodPost, "/v1/changes/change-12345678/approve", strings.NewReader(requestBody(now, ""))),
	} {
		request.TLS = tlsState(t, RoleObserver)
		recorder = httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("observer reached privileged endpoint %s: %d %s", request.URL.Path, recorder.Code, recorder.Body.String())
		}
	}
	if len(backend.requests) != 1 {
		t.Fatalf("observer privileged request reached backend: %#v", backend.requests)
	}
}

func TestHTTPSAdmissionLimitsRateAndConcurrentRequestsPerCertificate(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	server, backend := testServer(t, now)
	server.AdmissionLimits = admission.Limits{
		MaxConcurrent: 2, MaxConcurrentPerKey: 1,
		MaxRequestsPerWindow: 1, MaxGlobalPerWindow: 2,
		MaxKeys: 4, Window: time.Second, IdleTTL: time.Minute,
	}
	handler, err := server.Handler()
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	request.TLS = tlsState(t, RoleAgent)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("first HTTPS request rejected: %d %s", recorder.Code, recorder.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	request.TLS = tlsState(t, RoleAgent)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusTooManyRequests || recorder.Header().Get("Retry-After") != "1" {
		t.Fatalf("HTTPS rate limit did not reject the second request: %d %s", recorder.Code, recorder.Body.String())
	}
	if len(backend.requests) != 0 {
		t.Fatal("health requests unexpectedly reached the root backend")
	}

	server, _ = testServer(t, now)
	release := make(chan struct{})
	blocking := &blockingBackend{started: make(chan struct{}, 1), release: release}
	server.Backend = blocking
	server.AdmissionLimits = admission.Limits{
		MaxConcurrent: 2, MaxConcurrentPerKey: 1,
		MaxRequestsPerWindow: 10, MaxGlobalPerWindow: 20,
		MaxKeys: 4, Window: time.Second, IdleTTL: time.Minute,
	}
	handler, err = server.Handler()
	if err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		request := httptest.NewRequest(http.MethodPost, "/v1/inspect", strings.NewReader(requestBody(now, `"method":"host.snapshot"`)))
		request.TLS = tlsState(t, RoleAgent)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		firstDone <- recorder
	}()
	select {
	case <-blocking.started:
	case <-time.After(time.Second):
		t.Fatal("first HTTPS request did not reach the backend")
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/inspect", strings.NewReader(requestBody(now, `"method":"host.snapshot"`)))
	request.TLS = tlsState(t, RoleAgent)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusTooManyRequests || blocking.calls.Load() != 1 {
		t.Fatalf("concurrent HTTPS request was not rejected: code=%d calls=%d", recorder.Code, blocking.calls.Load())
	}
	close(release)
	if first := <-firstDone; first.Code != http.StatusOK {
		t.Fatalf("admitted HTTPS request failed: %d %s", first.Code, first.Body.String())
	}
}

func TestHTTPSDispatchDeadlineUsesBoundedInjectedClock(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 30, 0, 0, time.UTC)
	for _, test := range []struct {
		name        string
		dispatchNow time.Time
		errorText   string
	}{
		{
			name:        "deadline expires after validation",
			dispatchNow: now.Add(2 * time.Minute),
			errorText:   "deadline expired before backend dispatch",
		},
		{
			name:        "clock retreat cannot extend execution window",
			dispatchNow: now.Add(-10 * time.Minute),
			errorText:   "deadline exceeds the bounded backend dispatch window",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, backend := testServer(t, now)
			var clockCalls atomic.Int32
			server.Now = func() time.Time {
				if clockCalls.Add(1) <= 2 {
					return now
				}
				return test.dispatchNow
			}
			handler, err := server.Handler()
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/v1/inspect",
				strings.NewReader(requestBody(now, `"method":"host.snapshot"`)))
			request.TLS = tlsState(t, RoleAgent)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusRequestTimeout ||
				!strings.Contains(recorder.Body.String(), test.errorText) || len(backend.requests) != 0 {
				t.Fatalf("invalid dispatch deadline reached backend: code=%d body=%s requests=%#v",
					recorder.Code, recorder.Body.String(), backend.requests)
			}
		})
	}
}

func TestAgentRoleForwardsEveryInspectionTaggedUnion(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	digest := "sha256:" + strings.Repeat("a", 64)
	pvePrefix := `"pluginId":"workload.example-pve","pluginDigest":"` + digest + `",`
	pveIdentity := protocol.PVEInspection{PluginID: "workload.example-pve", PluginDigest: digest}
	tests := []struct {
		name     string
		extra    string
		method   protocol.Method
		path     string
		maxBytes int
		pve      protocol.PVEInspection
	}{
		{name: "process", extra: `"method":"process.list"`, method: protocol.MethodProcessList},
		{name: "metadata", extra: `"method":"file.metadata","path":"/etc/os-release"`, method: protocol.MethodFileMetadata, path: "/etc/os-release"},
		{name: "read", extra: `"method":"file.read","path":"/etc/os-release","maxBytes":4096`, method: protocol.MethodFileRead, path: "/etc/os-release", maxBytes: 4096},
		{name: "pve cluster", extra: `"method":"pve.cluster.status",` + pvePrefix[:len(pvePrefix)-1], method: protocol.MethodPVEClusterStatus, pve: pveIdentity},
		{name: "pve node", extra: `"method":"pve.node.status",` + pvePrefix + `"node":"pve1"`, method: protocol.MethodPVENodeStatus, pve: protocol.PVEInspection{PluginID: pveIdentity.PluginID, PluginDigest: digest, Node: "pve1"}},
		{name: "pve storage", extra: `"method":"pve.storage.status",` + pvePrefix + `"node":"pve1","storage":"local"`, method: protocol.MethodPVEStorageStatus, pve: protocol.PVEInspection{PluginID: pveIdentity.PluginID, PluginDigest: digest, Node: "pve1", Storage: "local"}},
		{name: "pve task", extra: `"method":"pve.task.status",` + pvePrefix + `"node":"pve1","upid":"UPID:pve1:00000001:00000002:00000003:vzdump:100:root@pam:"`, method: protocol.MethodPVETaskStatus, pve: protocol.PVEInspection{PluginID: pveIdentity.PluginID, PluginDigest: digest, Node: "pve1", UPID: "UPID:pve1:00000001:00000002:00000003:vzdump:100:root@pam:"}},
		{name: "pve guest", extra: `"method":"pve.guest.status",` + pvePrefix + `"node":"pve1","guestType":"qemu","vmid":100`, method: protocol.MethodPVEGuestStatus, pve: protocol.PVEInspection{PluginID: pveIdentity.PluginID, PluginDigest: digest, Node: "pve1", GuestType: "qemu", VMID: 100}},
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
			if forwarded.Method != test.method || forwarded.Path != test.path || forwarded.MaxBytes != test.maxBytes || forwarded.PVE != test.pve {
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
		`"method":"pve.cluster.status","node":"pve1"`,
		`"method":"pve.guest.status","node":"pve1","guestType":"qemu","vmid":100,"command":"qm stop 100"`,
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
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := protocol.BrokerReceiptClaims{
		KeyID: "core-receipt-v1", Domain: "core", RequestID: "request-12345678",
		Method: protocol.MethodChangeApprove, ServerID: "server-12345678", MachineID: "machine-12345678",
		TargetID: "target-service", ChangeID: "change-12345678",
		PlanHash: "sha256:" + strings.Repeat("a", 64),
	}
	signed, err := protocol.SignBrokerResponse(protocol.Response{
		Version: 1, RequestID: claims.RequestID, OK: true,
		AuditID:  "audit-0123456789abcdef0123456789abcdef",
		ChangeID: claims.ChangeID, State: "COMMITTED",
	}, claims, now, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	backend.responses = []protocol.Response{signed}
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
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || response.ChangeID != "change-12345678" ||
		response.Receipt == nil || response.Receipt.Signature != signed.Receipt.Signature || response.Receipt.ResultDigest != signed.Receipt.ResultDigest {
		t.Fatalf("unexpected public response %s", recorder.Body.String())
	}
	relayed := protocol.Response{
		Version: response.Version, RequestID: response.RequestID, OK: response.OK, AuditID: response.AuditID,
		ChangeID: response.ChangeID, State: response.State, Summary: response.Summary,
		Data: response.Data, Error: response.Error, Receipt: response.Receipt,
	}
	if err := protocol.VerifyBrokerResponse(relayed, claims, now, publicKey); err != nil {
		t.Fatalf("server did not relay a verifiable broker receipt: %v", err)
	}
	relayed.State = "ROLLED_BACK"
	if err := protocol.VerifyBrokerResponse(relayed, claims, now, publicKey); err == nil {
		t.Fatal("relayed terminal state substitution was not detected")
	}
}

func TestPVERecoveryClearanceEndpointsAreApproverOnlyAndStrict(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 30, 0, 0, time.UTC)
	server, backend := testServer(t, now)
	handler, err := server.Handler()
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/changes/pve-change-child-12345678/pve-recovery-clearance-prepare"
	for _, role := range []Role{RoleAgent, RoleObserver, RoleAdmin} {
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(requestBody(now, "")))
		request.TLS = tlsState(t, role)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden || len(backend.requests) != 0 {
			t.Fatalf("role %s reached PVE recovery clearance backend: code=%d requests=%#v", role, recorder.Code, backend.requests)
		}
	}
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(requestBody(now, "")))
	request.TLS = tlsState(t, RoleApprover)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || len(backend.requests) != 1 ||
		backend.requests[0].Method != protocol.MethodPVERecoveryClearancePrepare ||
		backend.requests[0].CallerRole != "approver" || backend.requests[0].ChangeID != "pve-change-child-12345678" {
		t.Fatalf("approver clearance prepare was not narrowly forwarded: code=%d body=%s requests=%#v", recorder.Code, recorder.Body.String(), backend.requests)
	}

	unknown := httptest.NewRequest(http.MethodPost, path, strings.NewReader(requestBody(now, `"command":"pvesh get /nodes/pve1/tasks"`)))
	unknown.TLS = tlsState(t, RoleApprover)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, unknown)
	if recorder.Code != http.StatusBadRequest || len(backend.requests) != 1 {
		t.Fatalf("unknown clearance field reached backend: code=%d requests=%#v", recorder.Code, backend.requests)
	}

	approval := fmt.Sprintf(`"clearanceApproval":{"version":1,"keyId":"approver-test-v1","action":"local-unknown-clearance","serverId":"server-12345678","machineId":"machine-12345678","targetId":"target-service","clearanceId":"pve-clearance-0123456789abcdef0123456789abcdef","parentChangeId":"pve-change-parent-1234567","childChangeId":"pve-change-child-12345678","childPlanHash":"sha256:%s","resourceKey":"pve/vmid/100","challengeDigest":"sha256:%s","policyRevision":"policy-12345678","capabilityRevision":%q,"issuedAt":%q,"expiresAt":%q,"nonce":"clearance-agentserver-nonce-1234","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`,
		strings.Repeat("a", 64), strings.Repeat("b", 64), protocol.CapabilityRevision,
		now.Format(time.RFC3339Nano), now.Add(time.Minute).Format(time.RFC3339Nano))
	confirm := httptest.NewRequest(http.MethodPost,
		"/v1/changes/pve-change-child-12345678/pve-recovery-clearance-confirm",
		strings.NewReader(requestBody(now, approval)))
	confirm.TLS = tlsState(t, RoleApprover)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, confirm)
	if recorder.Code != http.StatusOK || len(backend.requests) != 2 ||
		backend.requests[1].Method != protocol.MethodPVERecoveryClearanceConfirm ||
		backend.requests[1].ClearanceApproval == nil ||
		backend.requests[1].ClearanceApproval.ChallengeDigest != "sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("approver clearance confirmation was not exactly forwarded: code=%d body=%s requests=%#v", recorder.Code, recorder.Body.String(), backend.requests)
	}

	token := "pve-clearance-abcdef0123456789abcdef0123456789"
	actionWithToken := strings.Replace(actionBody(now), `"approval":`, `"clearanceToken":"`+token+`","approval":`, 1)
	actionWithToken = strings.Replace(actionWithToken, `"changeId":"change-12345678"`, `"changeId":"pve-change-child-12345678"`, 1)
	adminAction := httptest.NewRequest(http.MethodPost,
		"/v1/changes/pve-change-child-12345678/approve", strings.NewReader(actionWithToken))
	adminAction.TLS = tlsState(t, RoleAdmin)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, adminAction)
	if recorder.Code != http.StatusForbidden || len(backend.requests) != 2 {
		t.Fatalf("admin role relayed a PVE clearance grant: code=%d requests=%#v", recorder.Code, backend.requests)
	}
	approverAction := httptest.NewRequest(http.MethodPost,
		"/v1/changes/pve-change-child-12345678/approve", strings.NewReader(actionWithToken))
	approverAction.TLS = tlsState(t, RoleApprover)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, approverAction)
	if recorder.Code != http.StatusOK || len(backend.requests) != 3 ||
		backend.requests[2].CallerRole != "approver" || backend.requests[2].ClearanceToken != token {
		t.Fatalf("approver clearance grant was not exactly forwarded: code=%d requests=%#v", recorder.Code, backend.requests)
	}
}

func TestChangePrepareRequiresServerAuthoritativeCapabilityRevision(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	server, backend := testServer(t, now)
	handler, _ := server.Handler()
	body := func(revision string) string {
		return requestBody(now, fmt.Sprintf(
			`"method":"change.prepare","operation":{"kind":"package.install","package":"example"},"policyRevision":"policy-12345678","capabilityRevision":%q`,
			revision,
		))
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/changes", strings.NewReader(body("capability-attacker-12345678")))
	request.TLS = tlsState(t, RoleAgent)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusConflict || len(backend.requests) != 0 {
		t.Fatalf("client-selected capability revision reached broker: code=%d body=%s", recorder.Code, recorder.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/changes", strings.NewReader(body(protocol.CapabilityRevision)))
	request.TLS = tlsState(t, RoleAgent)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || len(backend.requests) != 1 || backend.requests[0].CapabilityRevision != protocol.CapabilityRevision {
		t.Fatalf("server did not bind its compiled revision: code=%d body=%s requests=%#v", recorder.Code, recorder.Body.String(), backend.requests)
	}
}

func actionBody(now time.Time) string {
	grant := `"approval":{"version":1,"keyId":"approver-test-v1","action":"approve","serverId":"server-12345678","machineId":"machine-12345678","targetId":"target-service","changeId":"change-12345678","planHash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","policyRevision":"policy-12345678","capabilityRevision":"capability-12345678","issuedAt":"2026-08-06T12:00:00Z","expiresAt":"2026-08-06T12:01:00Z","nonce":"nonce-agentserver-test-12345678","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`
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

	duplicate := strings.Replace(requestBody(now, `"method":"host.snapshot"`), `"version":1`, `"version":1,"version":1`, 1)
	request = httptest.NewRequest(http.MethodPost, "/v1/inspect", strings.NewReader(duplicate))
	request.TLS = tlsState(t, RoleAgent)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || len(backend.requests) != 0 || !strings.Contains(recorder.Body.String(), "duplicate JSON field") {
		t.Fatal("duplicate JSON field reached backend")
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
	if recorder.Code != http.StatusOK || !strings.Contains(body, `"revision":"capability-remote-v0.3-v8"`) || strings.Contains(body, "breakglass") || !strings.Contains(body, "process.list") || !strings.Contains(body, "file.metadata") || !strings.Contains(body, "file.read") || !strings.Contains(body, "workload.command.inspect") || !strings.Contains(body, "pve.cluster.status") || !strings.Contains(body, "pve.guest.status") || !strings.Contains(body, "plugin.install") || !strings.Contains(body, "workload.deploy") || strings.Contains(body, "plugin.configure") || strings.Contains(body, "plugin.remove") {
		t.Fatalf("unsafe capability was published: %s", body)
	}

	breakglassPolicy, err := targetpolicy.Parse([]byte(`{"version":1,"revision":"policy-breakglass-1234","targets":[{"id":"target-root-admin","account":"root","displayName":"Root administrator","inspect":{"hostSnapshot":true,"processList":true,"units":[],"readPaths":[]},"changes":{"writePaths":[],"units":[],"packages":[],"plugins":[]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	server.Policy = breakglassPolicy
	handler, err = server.Handler()
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	request.TLS = tlsState(t, RoleAgent)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"breakglass.prepare"`) {
		t.Fatalf("root target did not advertise the manual approval fallback: %s", recorder.Body.String())
	}
}

func TestNonPVEHostDoesNotAdvertiseOrRoutePVECapabilities(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	server, backend := testServer(t, now)
	server.PVEEnabled = false
	handler, err := server.Handler()
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	request.TLS = tlsState(t, RoleAgent)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), `"pve.`) {
		t.Fatalf("non-PVE server advertised PVE: %d %s", recorder.Code, recorder.Body.String())
	}

	digest := "sha256:" + strings.Repeat("a", 64)
	request = httptest.NewRequest(http.MethodPost, "/v1/inspect", strings.NewReader(requestBody(now,
		`"method":"pve.cluster.status","pluginId":"workload.pve","pluginDigest":"`+digest+`"`)))
	request.TLS = tlsState(t, RoleAgent)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusConflict || len(backend.requests) != 0 {
		t.Fatalf("non-PVE server routed PVE request: %d %s requests=%#v", recorder.Code, recorder.Body.String(), backend.requests)
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
		Policy:   policy, Backend: backend, PVEEnabled: true, Now: func() time.Time { return now },
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
