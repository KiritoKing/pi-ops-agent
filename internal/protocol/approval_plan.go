package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var approvalFieldNamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9._-]{0,63}$`)

// ApprovalPlan is the bounded canonical view consumed by the model-external
// reviewer and human approval UI. Ordinary file writes include their exact,
// bounded text as well as a digest: an opaque hash is not meaningful human
// approval. Secret material must use a dedicated typed flow and must never be
// submitted through file.write. A break-glass script likewise includes the
// exact action text in addition to the authoritative digest.
type ApprovalPlan struct {
	Version            int                `json:"version"`
	PlanHash           string             `json:"planHash"`
	PolicyRevision     string             `json:"policyRevision"`
	CapabilityRevision string             `json:"capabilityRevision"`
	PreconditionDigest string             `json:"preconditionDigest,omitempty"`
	PluginDigest       string             `json:"pluginDigest,omitempty"`
	Steps              []ApprovalPlanStep `json:"steps"`
}

type ApprovalPlanStep struct {
	ID         string              `json:"id"`
	Operation  string              `json:"operation"`
	Fields     []ApprovalPlanField `json:"fields"`
	Reversible bool                `json:"reversible"`
}

type ApprovalPlanField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func approvalContentDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func adapterRuntimeIdentity(pluginID string) string {
	if pluginID == "adapter.tui" {
		return "enrolled-local-administrator"
	}
	if pluginID == "adapter.botmux" {
		return "ops-agent-botmux"
	}
	suffix := strings.ReplaceAll(strings.TrimPrefix(pluginID, "adapter."), ".", "-")
	if len(suffix) <= 20 {
		return "ops-adapter-" + suffix
	}
	digest := sha256.Sum256([]byte(pluginID))
	return "ops-adapter-" + hex.EncodeToString(digest[:8])
}

func adapterAuthorityPlanFields(pluginID string) []ApprovalPlanField {
	tui := pluginID == "adapter.tui"
	execution := "source-process"
	directAuthority := "full-runtime-uid-authority;not-os-action-sandboxed"
	if tui {
		execution = "compiled-client"
		directAuthority = "plugin-source-forbidden;fixed-compiled-client-profile"
	}
	return []ApprovalPlanField{
		{Name: "adapterRuntimeIdentity", Value: adapterRuntimeIdentity(pluginID)},
		{Name: "adapterExecution", Value: execution},
		{Name: "adapterFilesystemAuthority", Value: "host-as-runtime-uid"},
		{Name: "adapterNetworkAuthority", Value: "host"},
		{Name: "adapterCredentialAuthority", Value: "runtime-uid-readable"},
		{Name: "adapterActionScopeEnforcement", Value: "digest-review-and-typed-ipc-contract"},
		{Name: "adapterDirectPlatformAuthority", Value: directAuthority},
	}
}

func BuildApprovalPlan(operation Operation, policyRevision, capabilityRevision string) (ApprovalPlan, error) {
	return BuildApprovalPlanWithPreconditions(operation, policyRevision, capabilityRevision, "", nil)
}

// CanonicalApprovalPlanHash binds exactly the bounded fields shown to the
// human approver. The framing is deliberately language-neutral rather than
// JSON-text based, so Go and TypeScript do not disagree about escaping. A
// relaying server may hide or replace a plan, but any replacement will fail
// the submitter's recomputation or the broker's signed-grant comparison.
func CanonicalApprovalPlanHash(plan ApprovalPlan) (string, error) {
	if plan.Version != Version || (plan.PolicyRevision != "" && !identityPattern.MatchString(plan.PolicyRevision)) ||
		!identityPattern.MatchString(plan.CapabilityRevision) ||
		(plan.PreconditionDigest != "" && !digestPattern.MatchString(plan.PreconditionDigest)) ||
		(plan.PluginDigest != "" && !digestPattern.MatchString(plan.PluginDigest)) ||
		len(plan.Steps) < 1 || len(plan.Steps) > 32 {
		return "", fmt.Errorf("approval plan has invalid canonical fields")
	}
	hasher := sha256.New()
	_, _ = io.WriteString(hasher, "agentd-approval-plan-v1\x00")
	writeApprovalPlanHashFrame(hasher, strconv.Itoa(plan.Version))
	writeApprovalPlanHashFrame(hasher, plan.PolicyRevision)
	writeApprovalPlanHashFrame(hasher, plan.CapabilityRevision)
	writeApprovalPlanHashFrame(hasher, plan.PreconditionDigest)
	writeApprovalPlanHashFrame(hasher, plan.PluginDigest)
	writeApprovalPlanHashFrame(hasher, strconv.Itoa(len(plan.Steps)))
	stepIDs := make(map[string]struct{}, len(plan.Steps))
	for _, step := range plan.Steps {
		if !identityPattern.MatchString(step.ID) || !sourceScopePattern.MatchString(step.Operation) ||
			len(step.Fields) < 1 || len(step.Fields) > 128 {
			return "", fmt.Errorf("approval plan step has invalid canonical fields")
		}
		if _, duplicate := stepIDs[step.ID]; duplicate {
			return "", fmt.Errorf("approval plan contains duplicate step id")
		}
		stepIDs[step.ID] = struct{}{}
		writeApprovalPlanHashFrame(hasher, step.ID)
		writeApprovalPlanHashFrame(hasher, step.Operation)
		writeApprovalPlanHashFrame(hasher, strconv.FormatBool(step.Reversible))
		writeApprovalPlanHashFrame(hasher, strconv.Itoa(len(step.Fields)))
		fieldNames := make(map[string]struct{}, len(step.Fields))
		for _, field := range step.Fields {
			if !approvalFieldNamePattern.MatchString(field.Name) || !utf8.ValidString(field.Value) ||
				len([]byte(field.Value)) > 128*1024 {
				return "", fmt.Errorf("approval plan field is invalid or exceeds its bound")
			}
			if _, duplicate := fieldNames[field.Name]; duplicate {
				return "", fmt.Errorf("approval plan step contains duplicate field")
			}
			fieldNames[field.Name] = struct{}{}
			writeApprovalPlanHashFrame(hasher, field.Name)
			writeApprovalPlanHashFrame(hasher, field.Value)
		}
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}

func writeApprovalPlanHashFrame(hasher hash.Hash, value string) {
	payload := []byte(value)
	_, _ = io.WriteString(hasher, strconv.Itoa(len(payload)))
	_, _ = io.WriteString(hasher, ":")
	_, _ = hasher.Write(payload)
}

// ApprovalPreconditionDigest returns the canonical digest used to bind a
// bounded, root-observed precondition into the human approval. Callers must
// preserve field order because it is part of the canonical observation.
func ApprovalPreconditionDigest(fields []ApprovalPlanField) (string, error) {
	if len(fields) == 0 || len(fields) > 64 {
		return "", fmt.Errorf("approval precondition must contain between 1 and 64 fields")
	}
	seen := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		if !approvalFieldNamePattern.MatchString(field.Name) || len(field.Value) > 128*1024 {
			return "", fmt.Errorf("approval precondition contains an invalid field")
		}
		if _, exists := seen[field.Name]; exists {
			return "", fmt.Errorf("approval precondition contains duplicate field %q", field.Name)
		}
		seen[field.Name] = struct{}{}
	}
	payload, err := json.Marshal(fields)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// BuildApprovalPlanWithPreconditions adds broker-observed current state to the
// canonical plan. The digest is independently recomputed so persisted fields
// cannot be shown under another approved precondition identity.
func BuildApprovalPlanWithPreconditions(operation Operation, policyRevision, capabilityRevision, preconditionDigest string, preconditionFields []ApprovalPlanField) (ApprovalPlan, error) {
	if operation == nil {
		return ApprovalPlan{}, fmt.Errorf("approval plan requires an operation")
	}
	if len(preconditionFields) > 0 {
		actual, err := ApprovalPreconditionDigest(preconditionFields)
		if err != nil {
			return ApprovalPlan{}, err
		}
		if actual != preconditionDigest {
			return ApprovalPlan{}, fmt.Errorf("approval precondition digest does not match its fields")
		}
	} else if preconditionDigest != "" && !digestPattern.MatchString(preconditionDigest) {
		return ApprovalPlan{}, fmt.Errorf("approval precondition digest is invalid")
	}
	plan := ApprovalPlan{
		Version: Version, PolicyRevision: policyRevision,
		CapabilityRevision: capabilityRevision, PreconditionDigest: preconditionDigest,
	}
	step := ApprovalPlanStep{ID: "step-1", Operation: operation.Kind()}
	var prefixSteps []ApprovalPlanStep
	switch value := operation.(type) {
	case *PackageInstall:
		step.Fields = []ApprovalPlanField{{Name: "package", Value: value.Package}}
		if value.Version != "" {
			step.Fields = append(step.Fields, ApprovalPlanField{Name: "version", Value: value.Version})
		}
	case *ServiceAction:
		step.Fields = []ApprovalPlanField{
			{Name: "pluginId", Value: value.PluginID},
			{Name: "pluginDigest", Value: value.PluginDigest},
			{Name: "unit", Value: value.Unit},
			{Name: "action", Value: value.Action},
		}
		step.Reversible = value.Action != "stop"
		plan.PluginDigest = value.PluginDigest
	case *WorkloadServiceAction:
		step.Fields = []ApprovalPlanField{
			{Name: "pluginId", Value: value.PluginID},
			{Name: "pluginDigest", Value: value.PluginDigest},
			{Name: "account", Value: value.Account},
			{Name: "manager", Value: value.Manager},
			{Name: "unit", Value: value.Unit},
			{Name: "action", Value: value.Action},
		}
		// Restarting or stopping a daemon can discard in-memory work and an
		// inverse systemd verb cannot restore that state. Compensation therefore
		// requires a new typed change rather than automatic rollback.
		step.Reversible = false
		plan.PluginDigest = value.PluginDigest
	case *WorkloadJSONConfigEdit:
		step.Fields = []ApprovalPlanField{
			{Name: "pluginId", Value: value.PluginID},
			{Name: "sourceDigest", Value: value.SourceDigest},
			{Name: "profileKey", Value: value.ProfileKey},
			{Name: "selectorValue", Value: value.SelectorValue},
			{Name: "fieldKey", Value: value.FieldKey},
			{Name: "valueKind", Value: value.Value.Kind},
			{Name: "requestedValue", Value: value.Value.SafeText()},
		}
		step.Reversible = true
		plan.PluginDigest = value.SourceDigest
	case *FileWrite:
		step.Fields = []ApprovalPlanField{
			{Name: "pluginId", Value: value.PluginID},
			{Name: "pluginDigest", Value: value.PluginDigest},
			{Name: "path", Value: value.Path},
			{Name: "contentDigest", Value: approvalContentDigest(value.Content)},
			{Name: "contentBytes", Value: strconv.Itoa(len([]byte(value.Content)))},
			{Name: "contentText", Value: value.Content},
		}
		if value.Mode != "" {
			step.Fields = append(step.Fields, ApprovalPlanField{Name: "mode", Value: value.Mode})
		}
		step.Reversible = true
		plan.PluginDigest = value.PluginDigest
	case *PluginInstall:
		step.Fields = artifactPlanFields(value.PluginID, value.Version, value.Publisher, value.Digest, value.ArtifactRef)
		step.Reversible = true
		plan.PluginDigest = value.Digest
	case *PluginRegister:
		step.Fields = []ApprovalPlanField{
			{Name: "pluginId", Value: value.PluginID},
			{Name: "pluginKind", Value: value.PluginKind},
			{Name: "version", Value: value.Version},
			{Name: "publisher", Value: value.Publisher},
			{Name: "digest", Value: value.Digest},
			{Name: "capabilities", Value: strings.Join(value.Capabilities, "\n")},
			{Name: "requestedScopes", Value: strings.Join(value.RequestedScopes, "\n")},
		}
		if value.PluginKind == "adapter" {
			step.Fields = append(step.Fields, adapterAuthorityPlanFields(value.PluginID)...)
		}
		step.Reversible = true
		plan.PluginDigest = value.Digest
	case *WorkloadDeploy:
		step.Fields = artifactPlanFields(value.PluginID, value.Version, value.Publisher, value.Digest, value.ArtifactRef)
		step.Reversible = true
		plan.PluginDigest = value.Digest
	case *BreakglassScript:
		verifyDigest := "none"
		if value.VerifyScript != "" {
			verifyDigest = approvalContentDigest(value.VerifyScript)
		}
		step.Fields = []ApprovalPlanField{
			{Name: "scriptDigest", Value: approvalContentDigest(value.Script)},
			{Name: "scriptBytes", Value: strconv.Itoa(len([]byte(value.Script)))},
			{Name: "scriptText", Value: value.Script},
			{Name: "backupPaths", Value: strings.Join(value.BackupPaths, "\n")},
			{Name: "verifyDigest", Value: verifyDigest},
			{Name: "verifyText", Value: value.VerifyScript},
			{Name: "network", Value: strconv.FormatBool(value.Network)},
		}
		// File archives cannot restore arbitrary service, disk, network or other
		// side effects performed by a privileged script.
		step.Reversible = false
	case *PVEGuestAction:
		step.Fields = append(pveGuestPlanFields(value.PluginID, value.PluginDigest, value.RecoveryOfChangeID, value.Node, value.GuestType, value.VMID),
			ApprovalPlanField{Name: "action", Value: value.Action})
		// An inverse lifecycle action cannot restore memory, in-flight I/O or
		// connections, so it must never be presented as a complete rollback.
		step.Reversible = false
		plan.PluginDigest = value.PluginDigest
	case *PVESnapshotCreate:
		step.Fields = append(pveGuestPlanFields(value.PluginID, value.PluginDigest, value.RecoveryOfChangeID, value.Node, value.GuestType, value.VMID),
			ApprovalPlanField{Name: "snapshot", Value: value.Snapshot})
		if value.Description != "" {
			step.Fields = append(step.Fields, ApprovalPlanField{Name: "description", Value: value.Description})
		}
		// Removal is a separate destructive PVE operation that requires its own
		// safety backup and approval; never imply an automatic inverse here.
		step.Reversible = false
		plan.PluginDigest = value.PluginDigest
	case *PVESnapshotDelete:
		step.Fields = append(pveGuestPlanFields(value.PluginID, value.PluginDigest, value.RecoveryOfChangeID, value.Node, value.GuestType, value.VMID),
			ApprovalPlanField{Name: "snapshot", Value: value.Snapshot}, ApprovalPlanField{Name: "backupStorage", Value: value.BackupStorage})
		prefixSteps = append(prefixSteps, pveSafetyBackupPlanStep(value.PluginID, value.PluginDigest, value.RecoveryOfChangeID, value.Node, value.GuestType, value.VMID, value.BackupStorage))
		plan.PluginDigest = value.PluginDigest
	case *PVESnapshotRollback:
		step.Fields = append(pveGuestPlanFields(value.PluginID, value.PluginDigest, value.RecoveryOfChangeID, value.Node, value.GuestType, value.VMID),
			ApprovalPlanField{Name: "snapshot", Value: value.Snapshot}, ApprovalPlanField{Name: "backupStorage", Value: value.BackupStorage})
		prefixSteps = append(prefixSteps, pveSafetyBackupPlanStep(value.PluginID, value.PluginDigest, value.RecoveryOfChangeID, value.Node, value.GuestType, value.VMID, value.BackupStorage))
		plan.PluginDigest = value.PluginDigest
	case *PVEGuestBackup:
		step.Fields = append(pveGuestPlanFields(value.PluginID, value.PluginDigest, value.RecoveryOfChangeID, value.Node, value.GuestType, value.VMID),
			ApprovalPlanField{Name: "storage", Value: value.Storage})
		plan.PluginDigest = value.PluginDigest
	case *PVEGuestRestore:
		step.Fields = append(pveGuestPlanFields(value.PluginID, value.PluginDigest, value.RecoveryOfChangeID, value.Node, value.GuestType, value.VMID),
			ApprovalPlanField{Name: "backupVolume", Value: value.BackupVolume}, ApprovalPlanField{Name: "storage", Value: value.Storage})
		plan.PluginDigest = value.PluginDigest
	case *PVEGuestMigrate:
		step.Fields = append(pveGuestPlanFields(value.PluginID, value.PluginDigest, value.RecoveryOfChangeID, value.Node, value.GuestType, value.VMID),
			ApprovalPlanField{Name: "targetNode", Value: value.TargetNode},
			ApprovalPlanField{Name: "online", Value: strconv.FormatBool(value.Online)},
			ApprovalPlanField{Name: "restart", Value: strconv.FormatBool(value.Restart)},
			ApprovalPlanField{Name: "withLocalDisks", Value: strconv.FormatBool(value.WithLocalDisks)})
		plan.PluginDigest = value.PluginDigest
	default:
		return ApprovalPlan{}, fmt.Errorf("operation %q has no live approval plan representation", operation.Kind())
	}
	if len(prefixSteps) > 0 {
		step.ID = "step-2"
	}
	for _, field := range preconditionFields {
		step.Fields = append(step.Fields, ApprovalPlanField{Name: "precondition." + field.Name, Value: field.Value})
	}
	plan.Steps = append(prefixSteps, step)
	planHash, err := CanonicalApprovalPlanHash(plan)
	if err != nil {
		return ApprovalPlan{}, err
	}
	plan.PlanHash = planHash
	return plan, nil
}

func pveSafetyBackupPlanStep(pluginID, pluginDigest, recoveryOfChangeID, node, guestType string, vmid int, storage string) ApprovalPlanStep {
	fields := append(pveGuestPlanFields(pluginID, pluginDigest, recoveryOfChangeID, node, guestType, vmid),
		ApprovalPlanField{Name: "storage", Value: storage},
		ApprovalPlanField{Name: "purpose", Value: "safety-backup-before-destructive-snapshot-action"})
	return ApprovalPlanStep{ID: "step-1", Operation: "pve.guest.backup", Fields: fields, Reversible: false}
}

func pveGuestPlanFields(pluginID, pluginDigest, recoveryOfChangeID, node, guestType string, vmid int) []ApprovalPlanField {
	fields := []ApprovalPlanField{
		{Name: "pluginId", Value: pluginID},
		{Name: "pluginDigest", Value: pluginDigest},
	}
	if recoveryOfChangeID != "" {
		fields = append(fields, ApprovalPlanField{Name: "recoveryOfChangeId", Value: recoveryOfChangeID})
	}
	return append(fields,
		ApprovalPlanField{Name: "node", Value: node},
		ApprovalPlanField{Name: "guestType", Value: guestType},
		ApprovalPlanField{Name: "vmid", Value: strconv.Itoa(vmid)})
}

func artifactPlanFields(id, version, publisher, digest, artifactRef string) []ApprovalPlanField {
	return []ApprovalPlanField{
		{Name: "pluginId", Value: id},
		{Name: "version", Value: version},
		{Name: "publisher", Value: publisher},
		{Name: "digest", Value: digest},
		{Name: "artifactRef", Value: artifactRef},
	}
}
