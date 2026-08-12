package agentserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/admission"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
	"github.com/KiritoKing/pi-ops-agent/internal/targetpolicy"
)

const (
	maxBodyBytes              = protocol.MaxFrameBytes
	maxRequestDispatchTimeout = 10 * time.Minute
)

type Server struct {
	Identity        Identity
	Policy          *targetpolicy.Policy
	Backend         Backend
	Now             func() time.Time
	CatalogDir      string
	PVEEnabled      bool
	AdmissionLimits admission.Limits
}

type requestEnvelope struct {
	Version   int    `json:"version"`
	RequestID string `json:"requestId"`
	Deadline  string `json:"deadline"`
	MachineID string `json:"machineId"`
	TargetID  string `json:"targetId"`
}

type inspectRequest struct {
	requestEnvelope
	Method       string `json:"method"`
	PluginID     string `json:"pluginId,omitempty"`
	PluginDigest string `json:"pluginDigest,omitempty"`
	Unit         string `json:"unit,omitempty"`
	Lines        int    `json:"lines,omitempty"`
	Path         string `json:"path,omitempty"`
	MaxBytes     int    `json:"maxBytes,omitempty"`
	Node         string `json:"node,omitempty"`
	Storage      string `json:"storage,omitempty"`
	GuestType    string `json:"guestType,omitempty"`
	VMID         int    `json:"vmid,omitempty"`
	UPID         string `json:"upid,omitempty"`
}

type workloadCommandInspectRequest struct {
	requestEnvelope
	Method       string `json:"method"`
	PluginID     string `json:"pluginId"`
	PluginDigest string `json:"pluginDigest"`
	ProfileKey   string `json:"profileKey"`
}

type changeRequest struct {
	requestEnvelope
	Method             string          `json:"method"`
	Operation          json.RawMessage `json:"operation"`
	PolicyRevision     string          `json:"policyRevision"`
	CapabilityRevision string          `json:"capabilityRevision"`
}

type actionRequest struct {
	requestEnvelope
	Approval       protocol.ApprovalGrant `json:"approval"`
	ClearanceToken string                 `json:"clearanceToken,omitempty"`
}

type clearancePrepareRequest struct {
	requestEnvelope
}

type clearanceConfirmRequest struct {
	requestEnvelope
	ClearanceApproval protocol.PVERecoveryClearanceApproval `json:"clearanceApproval"`
}

type rootWire struct {
	Version            int                                    `json:"version"`
	RequestID          string                                 `json:"requestId"`
	Deadline           string                                 `json:"deadline"`
	Method             protocol.Method                        `json:"method"`
	ServerID           string                                 `json:"serverId"`
	MachineID          string                                 `json:"machineId"`
	TargetID           string                                 `json:"targetId"`
	SessionID          string                                 `json:"sessionId,omitempty"`
	TurnID             string                                 `json:"turnId,omitempty"`
	PolicyRevision     string                                 `json:"policyRevision"`
	CapabilityRevision string                                 `json:"capabilityRevision,omitempty"`
	CallerRole         string                                 `json:"callerRole"`
	ChangeID           string                                 `json:"changeId,omitempty"`
	Unit               string                                 `json:"unit,omitempty"`
	Lines              int                                    `json:"lines,omitempty"`
	Path               string                                 `json:"path,omitempty"`
	MaxBytes           int                                    `json:"maxBytes,omitempty"`
	Node               string                                 `json:"node,omitempty"`
	Storage            string                                 `json:"storage,omitempty"`
	GuestType          string                                 `json:"guestType,omitempty"`
	VMID               int                                    `json:"vmid,omitempty"`
	UPID               string                                 `json:"upid,omitempty"`
	PluginID           string                                 `json:"pluginId,omitempty"`
	PluginDigest       string                                 `json:"pluginDigest,omitempty"`
	ProfileKey         string                                 `json:"profileKey,omitempty"`
	Operation          json.RawMessage                        `json:"operation,omitempty"`
	Approval           *protocol.ApprovalGrant                `json:"approval,omitempty"`
	ClearanceApproval  *protocol.PVERecoveryClearanceApproval `json:"clearanceApproval,omitempty"`
	ClearanceToken     string                                 `json:"clearanceToken,omitempty"`
}

type publicResponse struct {
	Version   int                     `json:"version"`
	RequestID string                  `json:"requestId,omitempty"`
	OK        bool                    `json:"ok"`
	AuditID   string                  `json:"auditId,omitempty"`
	ChangeID  string                  `json:"changeId,omitempty"`
	State     string                  `json:"state,omitempty"`
	Summary   string                  `json:"summary,omitempty"`
	Data      interface{}             `json:"data,omitempty"`
	Error     string                  `json:"error,omitempty"`
	Receipt   *protocol.BrokerReceipt `json:"brokerReceipt,omitempty"`
}

func (s *Server) Handler() (http.Handler, error) {
	if s.Policy == nil || s.Backend == nil {
		return nil, errors.New("policy and root backend are required")
	}
	if _, err := ParseIdentity(mustJSON(s.Identity)); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.handleHealth)
	mux.HandleFunc("GET /v1/identity", s.handleIdentity)
	mux.HandleFunc("GET /v1/capabilities", s.handleCapabilities)
	mux.HandleFunc("GET /v1/targets", s.handleTargets)
	mux.HandleFunc("GET /v1/artifacts", s.handleArtifacts)
	mux.HandleFunc("POST /v1/inspect", s.handleInspect)
	mux.HandleFunc("POST /v1/workload-command-inspections", s.handleWorkloadCommandInspect)
	mux.HandleFunc("POST /v1/changes", s.handleChangePrepare)
	mux.HandleFunc("GET /v1/changes/{changeRef}", s.handleChangeStatus)
	mux.HandleFunc("POST /v1/changes/{changeRef}/{action}", s.handleChangeAction)
	limits := s.AdmissionLimits
	if limits.MaxConcurrent == 0 {
		limits = admission.Limits{
			MaxConcurrent: 64, MaxConcurrentPerKey: 16,
			MaxRequestsPerWindow: 128, MaxGlobalPerWindow: 512,
			MaxKeys: 1024, Window: time.Second, IdleTTL: 5 * time.Minute,
		}
	}
	limiter, err := admission.New(limits, s.Now)
	if err != nil {
		return nil, fmt.Errorf("configure HTTPS admission: %w", err)
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		key := "unauthenticated"
		if principal, authErr := authenticate(request.TLS); authErr == nil {
			key = principal.Fingerprint
		}
		release, rejected := limiter.Acquire(key)
		if rejected != "" {
			writer.Header().Set("Retry-After", "1")
			writeError(writer, http.StatusTooManyRequests, string(rejected))
			return
		}
		defer release()
		mux.ServeHTTP(writer, request)
	}), nil
}

func (s *Server) handleHealth(writer http.ResponseWriter, request *http.Request) {
	if _, ok := s.requireRole(writer, request, RoleAgent, RoleObserver, RoleApprover, RoleAdmin); !ok {
		return
	}
	writeJSON(writer, http.StatusOK, map[string]interface{}{
		"version": protocol.Version, "ok": true, "status": "healthy", "serverId": s.Identity.ServerID,
		"machineId": s.Identity.MachineID, "policyRevision": s.Policy.Revision,
	})
}

func (s *Server) handleIdentity(writer http.ResponseWriter, request *http.Request) {
	if _, ok := s.requireRole(writer, request, RoleAgent, RoleObserver, RoleApprover, RoleAdmin); !ok {
		return
	}
	writeJSON(writer, http.StatusOK, map[string]interface{}{
		"serverId": s.Identity.ServerID, "machineId": s.Identity.MachineID, "machineName": s.Identity.MachineName,
		"account": s.Identity.Account, "protocolVersion": protocol.Version,
	})
}

func (s *Server) handleCapabilities(writer http.ResponseWriter, request *http.Request) {
	if _, ok := s.requireRole(writer, request, RoleAgent, RoleObserver, RoleApprover, RoleAdmin); !ok {
		return
	}
	operations := []string{"host.snapshot", "process.list", "systemd.unit", "journal.tail", "file.metadata", "file.read", "workload.command.inspect", "change.prepare", "change.status", "plugin.install", "plugin.register", "workload.deploy"}
	if s.PVEEnabled {
		operations = append(operations, "pve.cluster.status", "pve.node.status", "pve.storage.status", "pve.task.status", "pve.guest.status")
	}
	if policyHasRootTarget(s.Policy) {
		operations = append(operations, "breakglass.prepare")
	}
	writeJSON(writer, http.StatusOK, map[string]interface{}{
		"revision": protocol.CapabilityRevision, "policyRevision": s.Policy.Revision,
		"operations": operations,
	})
}

func policyHasRootTarget(policy *targetpolicy.Policy) bool {
	if policy == nil {
		return false
	}
	for _, target := range policy.PublicTargets() {
		if target.Account == "root" {
			return true
		}
	}
	return false
}

func (s *Server) handleTargets(writer http.ResponseWriter, request *http.Request) {
	if _, ok := s.requireRole(writer, request, RoleAgent, RoleObserver, RoleApprover, RoleAdmin); !ok {
		return
	}
	targets := s.Policy.PublicTargets()
	type publicTarget struct {
		TargetID    string           `json:"targetId"`
		Account     string           `json:"account"`
		DisplayName string           `json:"displayName"`
		Artifacts   []publicArtifact `json:"artifacts"`
	}
	public := make([]publicTarget, 0, len(targets))
	for _, target := range targets {
		public = append(public, publicTarget{
			TargetID: target.ID, Account: target.Account, DisplayName: target.DisplayName,
			Artifacts: publicArtifacts(target.Changes.Plugins),
		})
	}
	writeJSON(writer, http.StatusOK, public)
}

func (s *Server) handleInspect(writer http.ResponseWriter, request *http.Request) {
	principal, ok := s.requireRole(writer, request, RoleAgent, RoleAdmin)
	if !ok {
		return
	}
	var input inspectRequest
	if err := decodeStrictBody(writer, request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	method, err := inspectMethod(input.Method)
	if err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	wire := rootWireFromEnvelope(input.requestEnvelope, principal, method)
	wire.Unit, wire.Lines, wire.Path, wire.MaxBytes = input.Unit, input.Lines, input.Path, input.MaxBytes
	wire.Node, wire.Storage, wire.GuestType, wire.VMID, wire.UPID = input.Node, input.Storage, input.GuestType, input.VMID, input.UPID
	wire.PluginID, wire.PluginDigest = input.PluginID, input.PluginDigest
	s.forward(writer, request.Context(), wire)
}

func (s *Server) handleWorkloadCommandInspect(writer http.ResponseWriter, request *http.Request) {
	principal, ok := s.requireRole(writer, request, RoleAgent)
	if !ok {
		return
	}
	var input workloadCommandInspectRequest
	if err := decodeStrictBody(writer, request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	if input.Method != string(protocol.MethodWorkloadCommandInspect) {
		writeError(writer, http.StatusBadRequest, "method must be workload.command.inspect")
		return
	}
	wire := rootWireFromEnvelope(input.requestEnvelope, principal, protocol.MethodWorkloadCommandInspect)
	wire.PluginID, wire.PluginDigest, wire.ProfileKey = input.PluginID, input.PluginDigest, input.ProfileKey
	s.forward(writer, request.Context(), wire)
}

func (s *Server) handleChangePrepare(writer http.ResponseWriter, request *http.Request) {
	principal, ok := s.requireRole(writer, request, RoleAgent, RoleAdmin)
	if !ok {
		return
	}
	var input changeRequest
	if err := decodeStrictBody(writer, request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	if len(input.Operation) == 0 {
		writeError(writer, http.StatusBadRequest, "operation is required")
		return
	}
	if input.Method != "change.prepare" {
		writeError(writer, http.StatusBadRequest, "method must be change.prepare")
		return
	}
	if input.CapabilityRevision != protocol.CapabilityRevision {
		writeError(writer, http.StatusConflict, "capabilityRevision does not match the active compiled contract")
		return
	}
	wire := rootWireFromEnvelope(input.requestEnvelope, principal, protocol.MethodChangePrepare)
	wire.PolicyRevision = input.PolicyRevision
	wire.Operation = input.Operation
	s.forward(writer, request.Context(), wire)
}

func (s *Server) handleChangeStatus(writer http.ResponseWriter, request *http.Request) {
	principal, ok := s.requireRole(writer, request, RoleAgent, RoleObserver, RoleApprover, RoleAdmin)
	if !ok {
		return
	}
	envelope, err := envelopeFromQuery(request.URL.Query())
	if err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	wire := rootWireFromEnvelope(envelope, principal, protocol.MethodChangeStatus)
	wire.ChangeID = request.PathValue("changeRef")
	s.forward(writer, request.Context(), wire)
}

func (s *Server) handleChangeAction(writer http.ResponseWriter, request *http.Request) {
	principal, ok := s.requireRole(writer, request, RoleApprover, RoleAdmin)
	if !ok {
		return
	}
	action := request.PathValue("action")
	if action == "pve-recovery-clearance-prepare" || action == "pve-recovery-clearance-confirm" {
		if principal.Role != RoleApprover {
			writeError(writer, http.StatusForbidden, "PVE recovery clearance requires the approver certificate role")
			return
		}
		if action == "pve-recovery-clearance-prepare" {
			var input clearancePrepareRequest
			if err := decodeStrictBody(writer, request, &input); err != nil {
				writeError(writer, http.StatusBadRequest, err.Error())
				return
			}
			wire := rootWireFromEnvelope(input.requestEnvelope, principal, protocol.MethodPVERecoveryClearancePrepare)
			wire.ChangeID = request.PathValue("changeRef")
			s.forward(writer, request.Context(), wire)
			return
		}
		var input clearanceConfirmRequest
		if err := decodeStrictBody(writer, request, &input); err != nil {
			writeError(writer, http.StatusBadRequest, err.Error())
			return
		}
		wire := rootWireFromEnvelope(input.requestEnvelope, principal, protocol.MethodPVERecoveryClearanceConfirm)
		wire.ChangeID = request.PathValue("changeRef")
		wire.ClearanceApproval = &input.ClearanceApproval
		s.forward(writer, request.Context(), wire)
		return
	}
	var input actionRequest
	if err := decodeStrictBody(writer, request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	methods := map[string]protocol.Method{
		"approve": protocol.MethodChangeApprove, "reject": protocol.MethodChangeReject, "rollback": protocol.MethodChangeRollback,
	}
	method, exists := methods[action]
	if !exists {
		writeError(writer, http.StatusNotFound, "unsupported change action")
		return
	}
	if input.ClearanceToken != "" && (principal.Role != RoleApprover || method != protocol.MethodChangeApprove) {
		writeError(writer, http.StatusForbidden, "PVE recovery clearance may only accompany an approver-role approve action")
		return
	}
	wire := rootWireFromEnvelope(input.requestEnvelope, principal, method)
	wire.ChangeID = request.PathValue("changeRef")
	wire.Approval = &input.Approval
	wire.ClearanceToken = input.ClearanceToken
	s.forward(writer, request.Context(), wire)
}

func (s *Server) forward(writer http.ResponseWriter, ctx context.Context, wire rootWire) {
	wire.ServerID = s.Identity.ServerID
	wire.CapabilityRevision = protocol.CapabilityRevision
	if wire.PolicyRevision == "" {
		wire.PolicyRevision = s.Policy.Revision
	}
	if err := s.validateEnvelope(wire); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	payload, err := json.Marshal(wire)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "encode root request")
		return
	}
	request, err := protocol.ParseRequest(payload, s.now())
	if err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	if protocol.IsPVERequest(request) && !s.PVEEnabled {
		writeError(writer, http.StatusConflict, "PVE capability is not enabled on this server")
		return
	}
	deadlineCtx, cancel, err := boundedRequestContext(ctx, request.Deadline, s.now())
	if err != nil {
		writeError(writer, http.StatusRequestTimeout, err.Error())
		return
	}
	defer cancel()
	response, err := s.Backend.Do(deadlineCtx, request)
	if err != nil {
		writeError(writer, http.StatusBadGateway, "root broker unavailable")
		return
	}
	public := publicResponse{
		Version: response.Version, RequestID: response.RequestID, OK: response.OK, AuditID: response.AuditID,
		ChangeID: response.ChangeID, State: response.State, Summary: response.Summary, Data: response.Data, Error: response.Error,
		Receipt: response.Receipt,
	}
	status := http.StatusOK
	writeJSON(writer, status, public)
}

func boundedRequestContext(parent context.Context, deadline, now time.Time) (context.Context, context.CancelFunc, error) {
	remaining := deadline.Sub(now)
	if remaining <= 0 {
		return nil, nil, errors.New("request deadline expired before backend dispatch")
	}
	if remaining > maxRequestDispatchTimeout {
		return nil, nil, errors.New("request deadline exceeds the bounded backend dispatch window")
	}
	ctx, cancel := context.WithTimeout(parent, remaining)
	return ctx, cancel, nil
}

func (s *Server) validateEnvelope(wire rootWire) error {
	if wire.MachineID != s.Identity.MachineID {
		return errors.New("machineId does not match this server")
	}
	if wire.PolicyRevision != s.Policy.Revision {
		return errors.New("policyRevision does not match the active policy")
	}
	if wire.CapabilityRevision != protocol.CapabilityRevision {
		return errors.New("capabilityRevision does not match the active compiled contract")
	}
	if _, ok := s.Policy.Target(wire.TargetID); !ok {
		return errors.New("unknown targetId")
	}
	return nil
}

func (s *Server) requireRole(writer http.ResponseWriter, request *http.Request, allowed ...Role) (Principal, bool) {
	principal, err := authenticate(request.TLS)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, err.Error())
		return Principal{}, false
	}
	for _, role := range allowed {
		if principal.Role == role {
			return principal, true
		}
	}
	writeError(writer, http.StatusForbidden, "client certificate role is not authorized for this endpoint")
	return Principal{}, false
}

func rootWireFromEnvelope(input requestEnvelope, principal Principal, method protocol.Method) rootWire {
	return rootWire{
		Version: input.Version, RequestID: input.RequestID, Deadline: input.Deadline, Method: method,
		MachineID: input.MachineID, TargetID: input.TargetID, CallerRole: string(principal.Role),
	}
}

func inspectMethod(kind string) (protocol.Method, error) {
	methods := map[string]protocol.Method{
		"host.snapshot": protocol.MethodHostSnapshot, "process.list": protocol.MethodProcessList,
		"systemd.unit": protocol.MethodSystemdUnit, "journal.tail": protocol.MethodJournalTail,
		"file.metadata": protocol.MethodFileMetadata, "file.read": protocol.MethodFileRead,
		"pve.cluster.status": protocol.MethodPVEClusterStatus, "pve.node.status": protocol.MethodPVENodeStatus,
		"pve.storage.status": protocol.MethodPVEStorageStatus, "pve.task.status": protocol.MethodPVETaskStatus,
		"pve.guest.status": protocol.MethodPVEGuestStatus,
	}
	method, ok := methods[kind]
	if !ok {
		return "", errors.New("unsupported inspection kind")
	}
	return method, nil
}

func envelopeFromQuery(query url.Values) (requestEnvelope, error) {
	allowed := map[string]struct{}{
		"requestId": {}, "deadline": {}, "machineId": {}, "targetId": {},
	}
	for key, values := range query {
		if _, ok := allowed[key]; !ok || len(values) != 1 {
			return requestEnvelope{}, fmt.Errorf("unknown or repeated query parameter %q", key)
		}
	}
	return requestEnvelope{
		Version: protocol.Version, RequestID: query.Get("requestId"), Deadline: query.Get("deadline"),
		MachineID: query.Get("machineId"), TargetID: query.Get("targetId"),
	}, nil
}

func decodeStrictBody(writer http.ResponseWriter, request *http.Request, target interface{}) error {
	request.Body = http.MaxBytesReader(writer, request.Body, maxBodyBytes)
	payload, err := io.ReadAll(request.Body)
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	if len(payload) == 0 {
		return errors.New("decode request: empty body")
	}
	if err := rejectDuplicateJSONKeys(payload); err != nil {
		return fmt.Errorf("decode request: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode request: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("decode request: trailing value")
		}
		return fmt.Errorf("decode request: %w", err)
	}
	return nil
}

func rejectDuplicateJSONKeys(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON object key is not a string")
				}
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf("duplicate JSON field %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return errors.New("unterminated JSON object")
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return errors.New("unterminated JSON array")
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return fmt.Errorf("unexpected trailing JSON token %v", token)
	}
	return nil
}

func writeError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, publicResponse{Version: protocol.Version, OK: false, Error: message})
}

func writeJSON(writer http.ResponseWriter, status int, value interface{}) {
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func mustJSON(value interface{}) []byte {
	payload, _ := json.Marshal(value)
	return payload
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}
