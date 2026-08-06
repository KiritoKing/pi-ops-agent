package agentserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
	"github.com/KiritoKing/pi-ops-agent/internal/targetpolicy"
)

const maxBodyBytes = protocol.MaxFrameBytes

type Server struct {
	Identity   Identity
	Policy     *targetpolicy.Policy
	Backend    Backend
	Now        func() time.Time
	CatalogDir string
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
	Method   string `json:"method"`
	Unit     string `json:"unit,omitempty"`
	Lines    int    `json:"lines,omitempty"`
	Path     string `json:"path,omitempty"`
	MaxBytes int    `json:"maxBytes,omitempty"`
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
	Approval protocol.ApprovalGrant `json:"approval"`
}

type rootWire struct {
	Version            int                     `json:"version"`
	RequestID          string                  `json:"requestId"`
	Deadline           string                  `json:"deadline"`
	Method             protocol.Method         `json:"method"`
	ServerID           string                  `json:"serverId"`
	MachineID          string                  `json:"machineId"`
	TargetID           string                  `json:"targetId"`
	SessionID          string                  `json:"sessionId,omitempty"`
	TurnID             string                  `json:"turnId,omitempty"`
	PolicyRevision     string                  `json:"policyRevision"`
	CapabilityRevision string                  `json:"capabilityRevision,omitempty"`
	CallerRole         string                  `json:"callerRole"`
	ChangeID           string                  `json:"changeId,omitempty"`
	Unit               string                  `json:"unit,omitempty"`
	Lines              int                     `json:"lines,omitempty"`
	Path               string                  `json:"path,omitempty"`
	MaxBytes           int                     `json:"maxBytes,omitempty"`
	Operation          json.RawMessage         `json:"operation,omitempty"`
	Approval           *protocol.ApprovalGrant `json:"approval,omitempty"`
}

type publicResponse struct {
	Version   int         `json:"version"`
	RequestID string      `json:"requestId,omitempty"`
	OK        bool        `json:"ok"`
	AuditID   string      `json:"auditId,omitempty"`
	ChangeID  string      `json:"changeId,omitempty"`
	State     string      `json:"state,omitempty"`
	Summary   string      `json:"summary,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
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
	mux.HandleFunc("GET /v1/plugins", s.handlePlugins)
	mux.HandleFunc("POST /v1/inspect", s.handleInspect)
	mux.HandleFunc("POST /v1/changes", s.handleChangePrepare)
	mux.HandleFunc("GET /v1/changes/{changeRef}", s.handleChangeStatus)
	mux.HandleFunc("POST /v1/changes/{changeRef}/{action}", s.handleChangeAction)
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(writer, request)
	}), nil
}

func (s *Server) handleHealth(writer http.ResponseWriter, request *http.Request) {
	if _, ok := s.requireRole(writer, request, RoleAgent, RoleApprover, RoleAdmin); !ok {
		return
	}
	writeJSON(writer, http.StatusOK, map[string]interface{}{
		"version": protocol.Version, "ok": true, "status": "healthy", "serverId": s.Identity.ServerID,
		"machineId": s.Identity.MachineID, "policyRevision": s.Policy.Revision,
	})
}

func (s *Server) handleIdentity(writer http.ResponseWriter, request *http.Request) {
	if _, ok := s.requireRole(writer, request, RoleAgent, RoleApprover, RoleAdmin); !ok {
		return
	}
	writeJSON(writer, http.StatusOK, map[string]interface{}{
		"serverId": s.Identity.ServerID, "machineId": s.Identity.MachineID, "machineName": s.Identity.MachineName,
		"account": s.Identity.Account, "protocolVersion": protocol.Version,
	})
}

func (s *Server) handleCapabilities(writer http.ResponseWriter, request *http.Request) {
	if _, ok := s.requireRole(writer, request, RoleAgent, RoleApprover, RoleAdmin); !ok {
		return
	}
	writeJSON(writer, http.StatusOK, map[string]interface{}{
		"revision": "capability-remote-mvp-v1", "policyRevision": s.Policy.Revision,
		"operations": []string{"host.snapshot", "systemd.unit", "journal.tail", "change.prepare", "change.status", "plugin.install"},
	})
}

func (s *Server) handleTargets(writer http.ResponseWriter, request *http.Request) {
	if _, ok := s.requireRole(writer, request, RoleAgent, RoleApprover, RoleAdmin); !ok {
		return
	}
	targets := s.Policy.PublicTargets()
	public := make([]map[string]string, 0, len(targets))
	for _, target := range targets {
		public = append(public, map[string]string{"targetId": target.ID, "account": target.Account, "displayName": target.DisplayName})
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
	wire := rootWireFromEnvelope(input.requestEnvelope, principal, protocol.MethodChangePrepare)
	wire.PolicyRevision, wire.CapabilityRevision = input.PolicyRevision, input.CapabilityRevision
	wire.Operation = input.Operation
	s.forward(writer, request.Context(), wire)
}

func (s *Server) handleChangeStatus(writer http.ResponseWriter, request *http.Request) {
	principal, ok := s.requireRole(writer, request, RoleAgent, RoleApprover, RoleAdmin)
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
	var input actionRequest
	if err := decodeStrictBody(writer, request, &input); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	methods := map[string]protocol.Method{
		"approve": protocol.MethodChangeApprove, "reject": protocol.MethodChangeReject, "rollback": protocol.MethodChangeRollback,
	}
	method, exists := methods[request.PathValue("action")]
	if !exists {
		writeError(writer, http.StatusNotFound, "unsupported change action")
		return
	}
	wire := rootWireFromEnvelope(input.requestEnvelope, principal, method)
	wire.ChangeID = request.PathValue("changeRef")
	wire.Approval = &input.Approval
	s.forward(writer, request.Context(), wire)
}

func (s *Server) forward(writer http.ResponseWriter, ctx context.Context, wire rootWire) {
	wire.ServerID = s.Identity.ServerID
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
	deadlineCtx, cancel := context.WithDeadline(ctx, request.Deadline)
	defer cancel()
	response, err := s.Backend.Do(deadlineCtx, request)
	if err != nil {
		writeError(writer, http.StatusBadGateway, "root broker unavailable")
		return
	}
	public := publicResponse{
		Version: response.Version, RequestID: response.RequestID, OK: response.OK, AuditID: response.AuditID,
		ChangeID: response.ChangeID, State: response.State, Summary: response.Summary, Data: response.Data, Error: response.Error,
	}
	status := http.StatusOK
	writeJSON(writer, status, public)
}

func (s *Server) validateEnvelope(wire rootWire) error {
	if wire.MachineID != s.Identity.MachineID {
		return errors.New("machineId does not match this server")
	}
	if wire.PolicyRevision != s.Policy.Revision {
		return errors.New("policyRevision does not match the active policy")
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
	decoder := json.NewDecoder(request.Body)
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
