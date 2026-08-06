package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const Version = 1

var (
	requestIDPattern     = regexp.MustCompile(`^[a-zA-Z0-9._:-]{8,160}$`)
	changeIDPattern      = regexp.MustCompile(`^[a-zA-Z0-9._-]{8,160}$`)
	packagePattern       = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9+._-]{0,127}$`)
	versionPattern       = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9+.:~_-]{0,127}$`)
	unitPattern          = regexp.MustCompile(`^[a-zA-Z0-9@_.:-]{1,192}\.service$`)
	modePattern          = regexp.MustCompile(`^0?[0-7]{3,4}$`)
	identityPattern      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,159}$`)
	pluginIDPattern      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	digestPattern        = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	settingPattern       = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9._-]{0,127}$`)
	approvalKeyIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{7,159}$`)
	noncePattern         = regexp.MustCompile(`^[a-zA-Z0-9_-]{20,160}$`)
)

func ValidUnit(value string) bool    { return unitPattern.MatchString(value) }
func ValidPackage(value string) bool { return packagePattern.MatchString(value) }

type Method string

const (
	MethodChangePrepare  Method = "change.prepare"
	MethodChangeStatus   Method = "change.status"
	MethodChangeApprove  Method = "change.approve"
	MethodChangeReject   Method = "change.reject"
	MethodChangeRollback Method = "change.rollback"
	MethodHostSnapshot   Method = "host.snapshot"
	MethodSystemdUnit    Method = "systemd.unit"
	MethodJournalTail    Method = "journal.tail"
	MethodProcessList    Method = "process.list"
	MethodFileMetadata   Method = "file.metadata"
	MethodFileRead       Method = "file.read"
	MethodHeartbeat      Method = "heartbeat"
)

type Request struct {
	Version            int
	RequestID          string
	Deadline           time.Time
	Method             Method
	ServerID           string
	MachineID          string
	TargetID           string
	SessionID          string
	TurnID             string
	PolicyRevision     string
	CapabilityRevision string
	CallerRole         string
	ChangeID           string
	Unit               string
	Lines              int
	Path               string
	MaxBytes           int
	Operation          Operation
	Approval           *ApprovalGrant
	Raw                json.RawMessage
}

// ApprovalGrant is signed by the model-external client and verified again by
// the root broker. The network-facing server may relay it but cannot mint one.
type ApprovalGrant struct {
	Version        int    `json:"version"`
	KeyID          string `json:"keyId"`
	Action         string `json:"action"`
	ServerID       string `json:"serverId"`
	MachineID      string `json:"machineId"`
	TargetID       string `json:"targetId"`
	ChangeID       string `json:"changeId"`
	PlanHash       string `json:"planHash"`
	PolicyRevision string `json:"policyRevision"`
	IssuedAt       string `json:"issuedAt"`
	ExpiresAt      string `json:"expiresAt"`
	Nonce          string `json:"nonce"`
	Signature      string `json:"signature"`
}

// ApprovalPayload returns the stable bytes signed by clients. Keep this field
// order synchronized with src/shared/approval.ts.
func (g ApprovalGrant) ApprovalPayload() ([]byte, error) {
	unsigned := struct {
		Version        int    `json:"version"`
		KeyID          string `json:"keyId"`
		Action         string `json:"action"`
		ServerID       string `json:"serverId"`
		MachineID      string `json:"machineId"`
		TargetID       string `json:"targetId"`
		ChangeID       string `json:"changeId"`
		PlanHash       string `json:"planHash"`
		PolicyRevision string `json:"policyRevision"`
		IssuedAt       string `json:"issuedAt"`
		ExpiresAt      string `json:"expiresAt"`
		Nonce          string `json:"nonce"`
	}{g.Version, g.KeyID, g.Action, g.ServerID, g.MachineID, g.TargetID, g.ChangeID, g.PlanHash, g.PolicyRevision, g.IssuedAt, g.ExpiresAt, g.Nonce}
	return json.Marshal(unsigned)
}

func (g ApprovalGrant) ValidateShape() error {
	if g.Version != Version || !approvalKeyIDPattern.MatchString(g.KeyID) || !noncePattern.MatchString(g.Nonce) {
		return errors.New("approval grant has an invalid version, keyId, or nonce")
	}
	if g.Action != "approve" && g.Action != "reject" && g.Action != "rollback" {
		return errors.New("approval grant has an invalid action")
	}
	if !identityPattern.MatchString(g.ServerID) || !identityPattern.MatchString(g.MachineID) || !identityPattern.MatchString(g.TargetID) || !changeIDPattern.MatchString(g.ChangeID) || !digestPattern.MatchString(g.PlanHash) || !identityPattern.MatchString(g.PolicyRevision) {
		return errors.New("approval grant has an invalid scope or plan hash")
	}
	issuedAt, issuedErr := time.Parse(time.RFC3339Nano, g.IssuedAt)
	expiresAt, expiresErr := time.Parse(time.RFC3339Nano, g.ExpiresAt)
	if issuedErr != nil || expiresErr != nil || !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > 5*time.Minute {
		return errors.New("approval grant has an invalid validity window")
	}
	if len(g.Signature) < 80 || len(g.Signature) > 160 {
		return errors.New("approval grant has an invalid signature encoding")
	}
	return nil
}

type Response struct {
	Version   int         `json:"version"`
	RequestID string      `json:"requestId"`
	OK        bool        `json:"ok"`
	AuditID   string      `json:"auditId,omitempty"`
	ChangeID  string      `json:"changeId,omitempty"`
	State     string      `json:"state,omitempty"`
	Summary   string      `json:"summary,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	Error     string      `json:"error,omitempty"`
}

type Operation interface {
	Kind() string
	Summary() string
	Validate() error
}

type PackageInstall struct {
	OperationKind string `json:"kind"`
	Package       string `json:"package"`
	Version       string `json:"version,omitempty"`
}

func (o PackageInstall) Kind() string { return "package.install" }
func (o PackageInstall) Summary() string {
	if o.Version == "" {
		return "install package " + o.Package
	}
	return "install package " + o.Package + " version " + o.Version
}
func (o PackageInstall) Validate() error {
	if o.OperationKind != o.Kind() || !packagePattern.MatchString(o.Package) {
		return errors.New("invalid package.install operation")
	}
	if o.Version != "" && !versionPattern.MatchString(o.Version) {
		return errors.New("invalid package version")
	}
	return nil
}

type ServiceAction struct {
	OperationKind string `json:"kind"`
	Unit          string `json:"unit"`
	Action        string `json:"action"`
}

func (o ServiceAction) Kind() string    { return "service.action" }
func (o ServiceAction) Summary() string { return o.Action + " service " + o.Unit }
func (o ServiceAction) Validate() error {
	if o.OperationKind != o.Kind() || !unitPattern.MatchString(o.Unit) {
		return errors.New("invalid service.action operation")
	}
	switch o.Action {
	case "restart", "reload", "start", "stop":
		return nil
	default:
		return errors.New("invalid service action")
	}
}

type FileWrite struct {
	OperationKind string `json:"kind"`
	Path          string `json:"path"`
	Content       string `json:"content"`
	Mode          string `json:"mode,omitempty"`
}

type PluginInstall struct {
	OperationKind string `json:"kind"`
	PluginID      string `json:"pluginId"`
	Version       string `json:"version"`
	Digest        string `json:"digest"`
	CatalogPath   string `json:"catalogPath"`
}

func (o PluginInstall) Kind() string { return "plugin.install" }
func (o PluginInstall) Summary() string {
	return "install catalog plugin " + o.PluginID + " version " + o.Version
}
func (o PluginInstall) Validate() error {
	if o.OperationKind != o.Kind() || !pluginIDPattern.MatchString(o.PluginID) || !versionPattern.MatchString(o.Version) || !digestPattern.MatchString(o.Digest) {
		return errors.New("invalid plugin.install operation")
	}
	if !validCatalogPath(o.CatalogPath) {
		return errors.New("plugin.install must bind a local catalog path")
	}
	return nil
}

type PluginSetting struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type PluginConfigure struct {
	OperationKind string          `json:"kind"`
	PluginID      string          `json:"pluginId"`
	Version       string          `json:"version"`
	Digest        string          `json:"digest"`
	Settings      []PluginSetting `json:"settings,omitempty"`
}

func (o PluginConfigure) Kind() string { return "plugin.configure" }
func (o PluginConfigure) Summary() string {
	return "configure plugin " + o.PluginID + " version " + o.Version
}
func (o PluginConfigure) Validate() error {
	if o.OperationKind != o.Kind() || !pluginIDPattern.MatchString(o.PluginID) || !versionPattern.MatchString(o.Version) || !digestPattern.MatchString(o.Digest) || len(o.Settings) > 128 {
		return errors.New("invalid plugin.configure operation")
	}
	seen := make(map[string]struct{}, len(o.Settings))
	for _, setting := range o.Settings {
		if !settingPattern.MatchString(setting.Name) || len(setting.Value) > 4096 || strings.ContainsRune(setting.Value, '\x00') {
			return errors.New("invalid plugin setting")
		}
		if _, ok := seen[setting.Name]; ok {
			return errors.New("duplicate plugin setting")
		}
		seen[setting.Name] = struct{}{}
	}
	return nil
}

type PluginRemove struct {
	OperationKind string `json:"kind"`
	PluginID      string `json:"pluginId"`
	Version       string `json:"version"`
	Digest        string `json:"digest"`
}

func (o PluginRemove) Kind() string { return "plugin.remove" }
func (o PluginRemove) Summary() string {
	return "remove plugin " + o.PluginID + " version " + o.Version
}
func (o PluginRemove) Validate() error {
	if o.OperationKind != o.Kind() || !pluginIDPattern.MatchString(o.PluginID) || !versionPattern.MatchString(o.Version) || !digestPattern.MatchString(o.Digest) {
		return errors.New("invalid plugin.remove operation")
	}
	return nil
}

func validCatalogPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && len(path) <= 4096 && !strings.ContainsAny(path, "\x00\n\r")
}

func (o FileWrite) Kind() string { return "file.write" }
func (o FileWrite) Summary() string {
	return fmt.Sprintf("write %d bytes to %s", len(o.Content), o.Path)
}
func (o FileWrite) Validate() error {
	if o.OperationKind != o.Kind() || !filepath.IsAbs(o.Path) || filepath.Clean(o.Path) != o.Path {
		return errors.New("file.write path must be a clean absolute path")
	}
	if len(o.Path) > 4096 || strings.ContainsAny(o.Path, "\x00\n\r") || len(o.Content) > 128*1024 {
		return errors.New("file.write exceeds a protocol limit")
	}
	if o.Mode != "" && !modePattern.MatchString(o.Mode) {
		return errors.New("invalid file mode")
	}
	return nil
}

type BreakglassScript struct {
	OperationKind string   `json:"kind"`
	Script        string   `json:"script"`
	BackupPaths   []string `json:"backupPaths"`
	VerifyScript  string   `json:"verifyScript,omitempty"`
	Network       bool     `json:"network"`
}

func (o BreakglassScript) Kind() string { return "breakglass.script" }
func (o BreakglassScript) Summary() string {
	return fmt.Sprintf("run digest-bound break-glass script (%d bytes, %d backup paths)", len(o.Script), len(o.BackupPaths))
}
func (o BreakglassScript) Validate() error {
	if o.OperationKind != o.Kind() || len(o.Script) == 0 || len(o.Script) > 128*1024 {
		return errors.New("invalid breakglass.script operation")
	}
	if len(o.VerifyScript) > 32*1024 || len(o.BackupPaths) == 0 || len(o.BackupPaths) > 32 {
		return errors.New("break-glass requires a bounded backup and verification plan")
	}
	for _, path := range o.BackupPaths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || path == "/" || strings.ContainsAny(path, "\x00\n\r") {
			return errors.New("break-glass backup paths must be clean absolute paths below root")
		}
	}
	return nil
}

type wireBase struct {
	Version            int    `json:"version"`
	RequestID          string `json:"requestId"`
	Deadline           string `json:"deadline"`
	Method             Method `json:"method"`
	ServerID           string `json:"serverId,omitempty"`
	MachineID          string `json:"machineId,omitempty"`
	TargetID           string `json:"targetId,omitempty"`
	SessionID          string `json:"sessionId,omitempty"`
	TurnID             string `json:"turnId,omitempty"`
	PolicyRevision     string `json:"policyRevision,omitempty"`
	CapabilityRevision string `json:"capabilityRevision,omitempty"`
	CallerRole         string `json:"callerRole,omitempty"`
}

func ParseRequest(payload []byte, now time.Time) (Request, error) {
	var header wireBase
	if err := json.Unmarshal(payload, &header); err != nil {
		return Request{}, fmt.Errorf("decode request header: %w", err)
	}
	if header.Version != Version || !requestIDPattern.MatchString(header.RequestID) {
		return Request{}, errors.New("unsupported version or invalid requestId")
	}
	deadline, err := time.Parse(time.RFC3339Nano, header.Deadline)
	if err != nil || !deadline.After(now) || deadline.After(now.Add(10*time.Minute)) {
		return Request{}, errors.New("deadline must be within the next ten minutes")
	}
	if err := validateWireIdentity(header); err != nil {
		return Request{}, err
	}
	request := Request{
		Version: Version, RequestID: header.RequestID, Deadline: deadline, Method: header.Method,
		ServerID: header.ServerID, MachineID: header.MachineID, TargetID: header.TargetID,
		SessionID: header.SessionID, TurnID: header.TurnID, PolicyRevision: header.PolicyRevision,
		CapabilityRevision: header.CapabilityRevision, CallerRole: header.CallerRole, Raw: append(json.RawMessage(nil), payload...),
	}

	switch header.Method {
	case MethodChangePrepare:
		var wire struct {
			wireBase
			Operation json.RawMessage `json:"operation"`
		}
		if err := strictDecode(payload, &wire); err != nil {
			return Request{}, err
		}
		request.Operation, err = parseOperation(wire.Operation)
		if err != nil {
			return Request{}, err
		}
	case MethodChangeStatus:
		var wire struct {
			wireBase
			ChangeID string `json:"changeId"`
		}
		if err := strictDecode(payload, &wire); err != nil {
			return Request{}, err
		}
		if !changeIDPattern.MatchString(wire.ChangeID) {
			return Request{}, errors.New("invalid changeId")
		}
		request.ChangeID = wire.ChangeID
	case MethodChangeApprove, MethodChangeReject, MethodChangeRollback:
		var wire struct {
			wireBase
			ChangeID string         `json:"changeId"`
			Approval *ApprovalGrant `json:"approval,omitempty"`
		}
		if err := strictDecode(payload, &wire); err != nil {
			return Request{}, err
		}
		if !changeIDPattern.MatchString(wire.ChangeID) {
			return Request{}, errors.New("invalid changeId")
		}
		if wire.Approval != nil {
			if wire.Approval.ChangeID != wire.ChangeID {
				return Request{}, errors.New("approval grant changeId does not match request")
			}
			if err := wire.Approval.ValidateShape(); err != nil {
				return Request{}, err
			}
		}
		request.ChangeID, request.Approval = wire.ChangeID, wire.Approval
	case MethodSystemdUnit, MethodJournalTail:
		var wire struct {
			wireBase
			Unit  string `json:"unit"`
			Lines int    `json:"lines,omitempty"`
		}
		if err := strictDecode(payload, &wire); err != nil {
			return Request{}, err
		}
		if !unitPattern.MatchString(wire.Unit) {
			return Request{}, errors.New("invalid systemd unit")
		}
		if header.Method == MethodJournalTail {
			if wire.Lines == 0 {
				wire.Lines = 100
			}
			if wire.Lines < 1 || wire.Lines > 200 {
				return Request{}, errors.New("journal lines must be between 1 and 200")
			}
		} else if wire.Lines != 0 {
			return Request{}, errors.New("lines is not valid for systemd.unit")
		}
		request.Unit, request.Lines = wire.Unit, wire.Lines
	case MethodFileMetadata, MethodFileRead:
		var wire struct {
			wireBase
			Path     string `json:"path"`
			MaxBytes int    `json:"maxBytes,omitempty"`
		}
		if err := strictDecode(payload, &wire); err != nil {
			return Request{}, err
		}
		if !filepath.IsAbs(wire.Path) || filepath.Clean(wire.Path) != wire.Path || wire.Path == "/" || len(wire.Path) > 4096 || strings.ContainsAny(wire.Path, "\x00\n\r") {
			return Request{}, errors.New("file inspection path must be a clean absolute path below root")
		}
		if header.Method == MethodFileRead {
			if wire.MaxBytes == 0 {
				wire.MaxBytes = 64 * 1024
			}
			if wire.MaxBytes < 1 || wire.MaxBytes > 128*1024 {
				return Request{}, errors.New("file read maxBytes must be between 1 and 131072")
			}
		} else if wire.MaxBytes != 0 {
			return Request{}, errors.New("maxBytes is not valid for file.metadata")
		}
		request.Path, request.MaxBytes = wire.Path, wire.MaxBytes
	case MethodHostSnapshot, MethodProcessList, MethodHeartbeat:
		var wire struct {
			wireBase
		}
		if err := strictDecode(payload, &wire); err != nil {
			return Request{}, err
		}
	default:
		return Request{}, fmt.Errorf("unsupported method %q", header.Method)
	}
	return request, nil
}

func validateWireIdentity(header wireBase) error {
	values := []string{header.ServerID, header.MachineID, header.TargetID, header.PolicyRevision, header.CapabilityRevision, header.CallerRole}
	remote := false
	for _, value := range values {
		remote = remote || value != ""
	}
	if !remote {
		return nil
	}
	if !identityPattern.MatchString(header.ServerID) || !identityPattern.MatchString(header.MachineID) || !identityPattern.MatchString(header.TargetID) || !identityPattern.MatchString(header.PolicyRevision) {
		return errors.New("remote request has invalid server, machine, target, or policy identity")
	}
	if header.CapabilityRevision != "" && !identityPattern.MatchString(header.CapabilityRevision) {
		return errors.New("remote request has invalid capabilityRevision")
	}
	if header.SessionID != "" && !identityPattern.MatchString(header.SessionID) {
		return errors.New("remote request has invalid sessionId")
	}
	if header.TurnID != "" && !identityPattern.MatchString(header.TurnID) {
		return errors.New("remote request has invalid turnId")
	}
	switch header.CallerRole {
	case "agent", "approver", "admin":
		return nil
	default:
		return errors.New("remote request has invalid callerRole")
	}
}

func ParseStoredOperation(payload []byte) (Operation, error) {
	return parseOperation(payload)
}

func MarshalOperation(operation Operation) ([]byte, error) {
	if operation == nil {
		return nil, errors.New("operation is required")
	}
	if err := operation.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(operation)
}

func parseOperation(payload []byte) (Operation, error) {
	var header struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(payload, &header); err != nil {
		return nil, fmt.Errorf("decode operation header: %w", err)
	}
	var operation Operation
	switch header.Kind {
	case "package.install":
		operation = &PackageInstall{}
	case "service.action":
		operation = &ServiceAction{}
	case "file.write":
		operation = &FileWrite{}
	case "plugin.install":
		operation = &PluginInstall{}
	case "plugin.configure":
		operation = &PluginConfigure{}
	case "plugin.remove":
		operation = &PluginRemove{}
	case "breakglass.script":
		operation = &BreakglassScript{}
	default:
		return nil, fmt.Errorf("unsupported operation kind %q", header.Kind)
	}
	if err := strictDecode(payload, operation); err != nil {
		return nil, err
	}
	if err := operation.Validate(); err != nil {
		return nil, err
	}
	return operation, nil
}

func strictDecode(payload []byte, target interface{}) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("strict JSON decode: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("strict JSON decode: trailing value")
		}
		return fmt.Errorf("strict JSON decode: %w", err)
	}
	return nil
}
