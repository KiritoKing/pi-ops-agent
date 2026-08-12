package approvalsubmit

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

const RegistryPath = "/etc/ops-agent/servers.json"

const MaxUserIntentBytes = 4096

var (
	stableIDPattern  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{7,159}$`)
	targetIDPattern  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,159}$`)
	changeIDPattern  = regexp.MustCompile(`^[a-zA-Z0-9._-]{8,160}$`)
	fieldNamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9._:-]{0,127}$`)
	operationPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$`)
	digestPattern    = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

type Action string

const (
	ActionApprove  Action = "approve"
	ActionReject   Action = "reject"
	ActionRollback Action = "rollback"
)

type Request struct {
	Action     Action
	ServerID   string
	MachineID  string
	TargetID   string
	ChangeID   string
	UserIntent string
}

func (r Request) Validate() error {
	if r.Action != ActionApprove && r.Action != ActionReject && r.Action != ActionRollback {
		return errors.New("action must be approve, reject, or rollback")
	}
	if !stableIDPattern.MatchString(r.ServerID) || !stableIDPattern.MatchString(r.MachineID) ||
		!targetIDPattern.MatchString(r.TargetID) || !changeIDPattern.MatchString(r.ChangeID) {
		return errors.New("serverId, machineId, targetId, or changeId is invalid")
	}
	if _, err := brokerDomainForChangeID(r.ChangeID); err != nil {
		return err
	}
	if len(r.UserIntent) < 1 || len(r.UserIntent) > MaxUserIntentBytes ||
		!utf8.ValidString(r.UserIntent) || strings.TrimSpace(r.UserIntent) == "" {
		return fmt.Errorf("user intent must be valid UTF-8 with 1 to %d bounded bytes", MaxUserIntentBytes)
	}
	return nil
}

// ParseArgs deliberately accepts only the five fixed selectors plus one
// bounded base64url user-intent value. In particular,
// no URL, credential path, command, or non-interactive confirmation flag can be
// supplied by a caller.
func ParseArgs(args []string) (Request, error) {
	if len(args) != 12 {
		return Request{}, errors.New("exactly six --name value arguments are required")
	}
	values := make(map[string]string, 6)
	allowed := map[string]struct{}{
		"--action": {}, "--server-id": {}, "--machine-id": {}, "--target-id": {}, "--change-id": {},
		"--user-intent-b64": {},
	}
	for index := 0; index < len(args); index += 2 {
		name, value := args[index], args[index+1]
		if _, ok := allowed[name]; !ok {
			return Request{}, fmt.Errorf("unsupported argument %q", name)
		}
		if _, exists := values[name]; exists {
			return Request{}, fmt.Errorf("argument %q was repeated", name)
		}
		if value == "" || strings.HasPrefix(value, "--") {
			return Request{}, fmt.Errorf("argument %q requires a value", name)
		}
		values[name] = value
	}
	for name := range allowed {
		if _, ok := values[name]; !ok {
			return Request{}, fmt.Errorf("argument %q is required", name)
		}
	}
	encodedIntent := values["--user-intent-b64"]
	intent, err := base64.RawURLEncoding.DecodeString(encodedIntent)
	if err != nil || base64.RawURLEncoding.EncodeToString(intent) != encodedIntent {
		return Request{}, errors.New("user intent must use canonical unpadded base64url")
	}
	request := Request{
		Action: Action(values["--action"]), ServerID: values["--server-id"],
		MachineID: values["--machine-id"], TargetID: values["--target-id"], ChangeID: values["--change-id"],
		UserIntent: string(intent),
	}
	if err := request.Validate(); err != nil {
		return Request{}, err
	}
	return request, nil
}

type HelperResponse struct {
	Version   int                     `json:"version"`
	RequestID string                  `json:"requestId,omitempty"`
	OK        bool                    `json:"ok"`
	AuditID   string                  `json:"auditId,omitempty"`
	ChangeID  string                  `json:"changeId,omitempty"`
	State     string                  `json:"state,omitempty"`
	Summary   string                  `json:"summary,omitempty"`
	Data      json.RawMessage         `json:"data,omitempty"`
	Error     string                  `json:"error,omitempty"`
	Receipt   *protocol.BrokerReceipt `json:"brokerReceipt,omitempty"`
}

type ChangeStatus struct {
	Summary                   string
	ServerID                  string
	MachineID                 string
	TargetID                  string
	PolicyRevision            string
	CapabilityRevision        string
	PlanHash                  string
	Kind                      string
	BackupRefs                []string
	Verification              string
	RollbackAvailable         bool
	RollbackUnavailableReason string
	AuthorizationBasis        string
	AuthorizationScope        string
	AuthorizedAt              string
	LastError                 string
	RecoveryOfChangeID        string
	Resolution                *protocol.PVERecoveryResolution
	PVEMutationVersion        int
	MutationDisposition       string
	RecoveryOnly              bool
	RecoveryDescriptor        *protocol.RecoveryDescriptor
	Plan                      *protocol.ApprovalPlan
	State                     string
}

type statusWire struct {
	ServerID                  string                          `json:"serverId"`
	MachineID                 string                          `json:"machineId"`
	TargetID                  string                          `json:"targetId"`
	PolicyRevision            string                          `json:"policyRevision"`
	CapabilityRevision        string                          `json:"capabilityRevision"`
	PlanHash                  string                          `json:"planHash"`
	Kind                      string                          `json:"kind"`
	BackupRefs                []string                        `json:"backupRefs"`
	Verification              string                          `json:"verification"`
	RollbackAvailable         *bool                           `json:"rollbackAvailable"`
	RollbackUnavailableReason string                          `json:"rollbackUnavailableReason,omitempty"`
	AuthorizationBasis        string                          `json:"authorizationBasis,omitempty"`
	AuthorizationScope        string                          `json:"authorizationScope,omitempty"`
	AuthorizedAt              string                          `json:"authorizedAt,omitempty"`
	LastError                 string                          `json:"lastError,omitempty"`
	RecoveryOfChangeID        string                          `json:"recoveryOfChangeId,omitempty"`
	Resolution                *protocol.PVERecoveryResolution `json:"resolution,omitempty"`
	PVEMutationVersion        int                             `json:"pveMutationVersion,omitempty"`
	MutationDisposition       string                          `json:"mutationDisposition,omitempty"`
	RecoveryOnly              *bool                           `json:"recoveryOnly"`
	RecoveryDescriptor        *protocol.RecoveryDescriptor    `json:"recoveryDescriptor,omitempty"`
	Plan                      json.RawMessage                 `json:"plan,omitempty"`
}

type approvalPlanWire struct {
	Version            int                    `json:"version"`
	PlanHash           string                 `json:"planHash"`
	PolicyRevision     string                 `json:"policyRevision"`
	CapabilityRevision string                 `json:"capabilityRevision"`
	PreconditionDigest string                 `json:"preconditionDigest,omitempty"`
	PluginDigest       string                 `json:"pluginDigest,omitempty"`
	Steps              []approvalPlanStepWire `json:"steps"`
}

type approvalPlanStepWire struct {
	ID         string                  `json:"id"`
	Operation  string                  `json:"operation"`
	Fields     []approvalPlanFieldWire `json:"fields"`
	Reversible *bool                   `json:"reversible"`
}

type approvalPlanFieldWire struct {
	Name  string  `json:"name"`
	Value *string `json:"value"`
}

func parseStatus(response HelperResponse, expected Request) (ChangeStatus, error) {
	if !response.OK {
		return ChangeStatus{}, errors.New("cannot parse an unsuccessful status response")
	}
	if response.ChangeID != expected.ChangeID {
		return ChangeStatus{}, errors.New("status response changeId does not match the requested change")
	}
	var wire statusWire
	if err := strictDecode(response.Data, &wire); err != nil {
		return ChangeStatus{}, fmt.Errorf("decode authoritative change status: %w", err)
	}
	if wire.ServerID != expected.ServerID || wire.MachineID != expected.MachineID || wire.TargetID != expected.TargetID {
		return ChangeStatus{}, errors.New("authoritative change scope does not match the requested scope")
	}
	if !stableIDPattern.MatchString(wire.ServerID) || !stableIDPattern.MatchString(wire.MachineID) ||
		!targetIDPattern.MatchString(wire.TargetID) || !targetIDPattern.MatchString(wire.PolicyRevision) ||
		!targetIDPattern.MatchString(wire.CapabilityRevision) || !digestPattern.MatchString(wire.PlanHash) ||
		!operationPattern.MatchString(wire.Kind) {
		return ChangeStatus{}, errors.New("authoritative change metadata contains an invalid identity, revision, kind, or planHash")
	}
	if wire.RollbackAvailable == nil || wire.RecoveryOnly == nil {
		return ChangeStatus{}, errors.New("authoritative change is missing rollback or recovery-only metadata")
	}
	if wire.RecoveryOfChangeID != "" &&
		(!strings.HasPrefix(wire.RecoveryOfChangeID, "pve-change-") || !changeIDPattern.MatchString(wire.RecoveryOfChangeID)) {
		return ChangeStatus{}, errors.New("authoritative PVE recovery parent is invalid")
	}
	if wire.Resolution != nil {
		if response.State != "SUPERSEDED" || wire.Resolution.Validate() != nil {
			return ChangeStatus{}, errors.New("authoritative PVE recovery resolution is invalid")
		}
	} else if response.State == "SUPERSEDED" {
		return ChangeStatus{}, errors.New("superseded authoritative PVE change has no resolution evidence")
	}
	pveKind := strings.HasPrefix(wire.Kind, "pve.")
	if wire.PVEMutationVersion < 0 || wire.PVEMutationVersion > 1 {
		return ChangeStatus{}, errors.New("authoritative PVE mutation protocol version is invalid")
	}
	switch wire.MutationDisposition {
	case "", protocol.PVEMutationDispositionNotStarted, protocol.PVEMutationDispositionTasksTerminal,
		protocol.PVEMutationDispositionUnknown:
	default:
		return ChangeStatus{}, errors.New("authoritative PVE mutation disposition is invalid")
	}
	if !pveKind && (wire.PVEMutationVersion != 0 || wire.MutationDisposition != "") {
		return ChangeStatus{}, errors.New("non-PVE authoritative change has PVE mutation metadata")
	}
	if pveKind && (response.State == "RECOVERY_REQUIRED" || response.State == "SUPERSEDED") && wire.MutationDisposition == "" {
		return ChangeStatus{}, errors.New("unresolved authoritative PVE change has no mutation disposition")
	}
	if wire.Resolution != nil && wire.Resolution.ParentMutationDisposition != wire.MutationDisposition {
		return ChangeStatus{}, errors.New("authoritative PVE resolution does not bind the parent mutation disposition")
	}
	if wire.Resolution != nil {
		for _, evidence := range wire.Resolution.ParentTaskEvidence {
			found := false
			for _, reference := range wire.BackupRefs {
				if reference == "pve:task:"+evidence.UPID {
					found = true
					break
				}
			}
			if !found {
				return ChangeStatus{}, errors.New("authoritative PVE resolution task evidence is absent from backup references")
			}
		}
	}
	if *wire.RecoveryOnly {
		if len(wire.Plan) != 0 {
			return ChangeStatus{}, errors.New("recovery-only authoritative change unexpectedly contains a live ApprovalPlan")
		}
		if expected.Action == ActionApprove {
			return ChangeStatus{}, errors.New("recovery-only authoritative change cannot be approved or executed")
		}
		if wire.RecoveryDescriptor == nil {
			return ChangeStatus{}, errors.New("recovery-only authoritative change has no signed recovery descriptor")
		}
		if err := wire.RecoveryDescriptor.Validate(); err != nil {
			return ChangeStatus{}, fmt.Errorf("validate authoritative recovery descriptor: %w", err)
		}
		if wire.RecoveryDescriptor.OriginalKind != wire.Kind ||
			wire.RecoveryDescriptor.RollbackCompatible != *wire.RollbackAvailable ||
			wire.RecoveryDescriptor.UnavailableReason != wire.RollbackUnavailableReason {
			return ChangeStatus{}, errors.New("authoritative recovery descriptor is inconsistent with change status")
		}
	} else if len(wire.Plan) == 0 {
		return ChangeStatus{}, errors.New("authoritative change has no bounded live ApprovalPlan")
	} else if wire.RecoveryDescriptor != nil || wire.RollbackUnavailableReason != "" {
		return ChangeStatus{}, errors.New("live authoritative change unexpectedly contains legacy recovery metadata")
	}
	if len(wire.BackupRefs) > 64 || len(wire.Verification) > 8192 || len(wire.LastError) > 8192 ||
		len(wire.RollbackUnavailableReason) > 2048 || len(response.Summary) > 8192 ||
		len(wire.AuthorizationBasis) > 256 || len(wire.AuthorizationScope) > 128 || len(wire.AuthorizedAt) > 64 ||
		containsUnsafeControl(response.Summary) || containsUnsafeControl(wire.RollbackUnavailableReason) {
		return ChangeStatus{}, errors.New("authoritative change metadata exceeds its bounds")
	}
	if wire.AuthorizationBasis == "" {
		if wire.AuthorizationScope != "" || wire.AuthorizedAt != "" {
			return ChangeStatus{}, errors.New("authoritative change has incomplete authorization metadata")
		}
	} else {
		if containsUnsafeControl(wire.AuthorizationBasis) ||
			(wire.AuthorizationScope != "" && !operationPattern.MatchString(wire.AuthorizationScope)) {
			return ChangeStatus{}, errors.New("authoritative change has invalid authorization metadata")
		}
		if _, err := time.Parse(time.RFC3339Nano, wire.AuthorizedAt); err != nil {
			return ChangeStatus{}, errors.New("authoritative change has invalid authorization time")
		}
	}
	for _, reference := range wire.BackupRefs {
		if reference == "" || len(reference) > 4096 || containsUnsafeControl(reference) {
			return ChangeStatus{}, errors.New("authoritative backup reference is invalid")
		}
	}
	if wire.RecoveryDescriptor != nil {
		if len(wire.RecoveryDescriptor.BackupObjects) != len(wire.BackupRefs) {
			return ChangeStatus{}, errors.New("recovery descriptor backup objects do not match authoritative backup references")
		}
		for index, object := range wire.RecoveryDescriptor.BackupObjects {
			if object.Reference != wire.BackupRefs[index] {
				return ChangeStatus{}, errors.New("recovery descriptor backup object order does not match authoritative backup references")
			}
		}
	}
	var plan *protocol.ApprovalPlan
	if !*wire.RecoveryOnly {
		parsed, err := parseApprovalPlan(wire.Plan)
		if err != nil {
			return ChangeStatus{}, err
		}
		if err := validatePlan(parsed, wire); err != nil {
			return ChangeStatus{}, err
		}
		plan = &parsed
		if approvalPlanFieldValue(parsed, "recoveryOfChangeId") != wire.RecoveryOfChangeID {
			return ChangeStatus{}, errors.New("authoritative PVE recovery parent does not match the canonical ApprovalPlan")
		}
	}
	return ChangeStatus{
		Summary:  response.Summary,
		ServerID: wire.ServerID, MachineID: wire.MachineID, TargetID: wire.TargetID,
		PolicyRevision: wire.PolicyRevision, CapabilityRevision: wire.CapabilityRevision,
		PlanHash: wire.PlanHash, Kind: wire.Kind, BackupRefs: append([]string(nil), wire.BackupRefs...),
		Verification: wire.Verification, RollbackAvailable: *wire.RollbackAvailable,
		RollbackUnavailableReason: wire.RollbackUnavailableReason,
		AuthorizationBasis:        wire.AuthorizationBasis, AuthorizationScope: wire.AuthorizationScope,
		AuthorizedAt: wire.AuthorizedAt,
		LastError:    wire.LastError, RecoveryOfChangeID: wire.RecoveryOfChangeID,
		Resolution: wire.Resolution, PVEMutationVersion: wire.PVEMutationVersion,
		MutationDisposition: wire.MutationDisposition, RecoveryOnly: *wire.RecoveryOnly,
		RecoveryDescriptor: wire.RecoveryDescriptor, Plan: plan,
		State: response.State,
	}, nil
}

func approvalPlanFieldValue(plan protocol.ApprovalPlan, name string) string {
	value := ""
	for _, step := range plan.Steps {
		for _, field := range step.Fields {
			if field.Name == name {
				if value != "" && value != field.Value {
					return "<conflict>"
				}
				value = field.Value
			}
		}
	}
	return value
}

func parseApprovalPlan(payload []byte) (protocol.ApprovalPlan, error) {
	var wire approvalPlanWire
	if err := strictDecode(payload, &wire); err != nil {
		return protocol.ApprovalPlan{}, fmt.Errorf("decode authoritative ApprovalPlan: %w", err)
	}
	plan := protocol.ApprovalPlan{
		Version: wire.Version, PlanHash: wire.PlanHash, PolicyRevision: wire.PolicyRevision,
		CapabilityRevision: wire.CapabilityRevision, PreconditionDigest: wire.PreconditionDigest,
		PluginDigest: wire.PluginDigest, Steps: make([]protocol.ApprovalPlanStep, 0, len(wire.Steps)),
	}
	for _, stepWire := range wire.Steps {
		if stepWire.Reversible == nil {
			return protocol.ApprovalPlan{}, errors.New("ApprovalPlan step is missing reversible")
		}
		step := protocol.ApprovalPlanStep{
			ID: stepWire.ID, Operation: stepWire.Operation, Reversible: *stepWire.Reversible,
			Fields: make([]protocol.ApprovalPlanField, 0, len(stepWire.Fields)),
		}
		for _, fieldWire := range stepWire.Fields {
			if fieldWire.Value == nil {
				return protocol.ApprovalPlan{}, errors.New("ApprovalPlan field is missing value")
			}
			step.Fields = append(step.Fields, protocol.ApprovalPlanField{Name: fieldWire.Name, Value: *fieldWire.Value})
		}
		plan.Steps = append(plan.Steps, step)
	}
	return plan, nil
}

func validatePlan(plan protocol.ApprovalPlan, status statusWire) error {
	if plan.Version != protocol.Version || plan.PlanHash != status.PlanHash ||
		plan.PolicyRevision != status.PolicyRevision || plan.CapabilityRevision != status.CapabilityRevision {
		return errors.New("ApprovalPlan is not bound to the authoritative plan and revisions")
	}
	if plan.PreconditionDigest != "" && !digestPattern.MatchString(plan.PreconditionDigest) {
		return errors.New("ApprovalPlan has an invalid precondition digest")
	}
	if plan.PluginDigest != "" && !digestPattern.MatchString(plan.PluginDigest) {
		return errors.New("ApprovalPlan has an invalid plugin digest")
	}
	if len(plan.Steps) < 1 || len(plan.Steps) > 32 {
		return errors.New("ApprovalPlan must contain between 1 and 32 bounded steps")
	}
	stepIDs := make(map[string]struct{}, len(plan.Steps))
	totalValueBytes := 0
	for _, step := range plan.Steps {
		if !targetIDPattern.MatchString(step.ID) || !operationPattern.MatchString(step.Operation) {
			return errors.New("ApprovalPlan step has an invalid ID or operation")
		}
		if _, duplicate := stepIDs[step.ID]; duplicate {
			return errors.New("ApprovalPlan contains a duplicate step ID")
		}
		stepIDs[step.ID] = struct{}{}
		if len(step.Fields) < 1 || len(step.Fields) > 128 {
			return errors.New("ApprovalPlan step has an invalid field count")
		}
		fieldNames := make(map[string]struct{}, len(step.Fields))
		for _, field := range step.Fields {
			if !fieldNamePattern.MatchString(field.Name) || len(field.Value) > 128*1024 || !utf8.ValidString(field.Value) {
				return errors.New("ApprovalPlan field is invalid or exceeds its bound")
			}
			if _, duplicate := fieldNames[field.Name]; duplicate {
				return errors.New("ApprovalPlan step contains a duplicate field")
			}
			fieldNames[field.Name] = struct{}{}
			totalValueBytes += len(field.Value)
			if totalValueBytes > protocol.MaxFrameBytes-4096 {
				return errors.New("ApprovalPlan field values exceed the total bound")
			}
		}
	}
	canonical, err := protocol.CanonicalApprovalPlanHash(plan)
	if err != nil {
		return fmt.Errorf("recompute canonical ApprovalPlan hash: %w", err)
	}
	if canonical != plan.PlanHash {
		return errors.New("ApprovalPlan displayed fields do not match the authoritative planHash")
	}
	return nil
}

func validateHelperResponse(response HelperResponse, requestID string) error {
	if response.Version != protocol.Version || response.RequestID != requestID || !stableIDPattern.MatchString(response.RequestID) {
		return errors.New("server response has an invalid version or requestId")
	}
	if len(response.AuditID) > 160 || len(response.ChangeID) > 160 || len(response.State) > 64 ||
		len(response.Summary) > 16*1024 || len(response.Error) > 8192 || len(response.Data) > protocol.MaxFrameBytes {
		return errors.New("server response exceeds a field bound")
	}
	if response.ChangeID != "" && !changeIDPattern.MatchString(response.ChangeID) {
		return errors.New("server response has an invalid changeId")
	}
	if response.OK && response.Error != "" {
		return errors.New("successful server response contains an error")
	}
	if !response.OK && response.Error == "" {
		return errors.New("unsuccessful server response has no bounded error")
	}
	if len(response.Data) > 0 && !json.Valid(response.Data) {
		return errors.New("server response data is not valid JSON")
	}
	if response.Receipt != nil {
		if err := response.Receipt.ValidateShape(); err != nil {
			return fmt.Errorf("server response has an invalid broker receipt: %w", err)
		}
	}
	return nil
}

func brokerDomainForChangeID(changeID string) (string, error) {
	switch {
	case strings.HasPrefix(changeID, "pve-change-"):
		return "pve", nil
	case strings.HasPrefix(changeID, "change-"):
		return "core", nil
	default:
		return "", errors.New("changeId does not select a supported root broker domain")
	}
}

func strictDecode(payload []byte, target interface{}) error {
	if len(payload) == 0 || len(payload) > protocol.MaxFrameBytes {
		return errors.New("JSON payload is empty or exceeds the protocol bound")
	}
	if err := rejectDuplicateJSONKeys(payload); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON payload has a trailing value")
		}
		return err
	}
	return nil
}

func rejectDuplicateJSONKeys(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("decode JSON token: %w", err)
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
					return fmt.Errorf("decode JSON object key: %w", err)
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

func containsUnsafeControl(value string) bool {
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return true
		}
	}
	return false
}
