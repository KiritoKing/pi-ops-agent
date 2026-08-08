package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	Version = 1
	// CapabilityRevision names the compiled server/root-broker contract. It is
	// implementation-authoritative: callers may echo it but cannot choose it.
	CapabilityRevision = "capability-remote-v0.3-v8"
)

var (
	requestIDPattern       = regexp.MustCompile(`^[a-zA-Z0-9._:-]{8,160}$`)
	changeIDPattern        = regexp.MustCompile(`^[a-zA-Z0-9._-]{8,160}$`)
	packagePattern         = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9+._-]{0,127}$`)
	versionPattern         = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9+.:~_-]{0,127}$`)
	unitPattern            = regexp.MustCompile(`^[a-zA-Z0-9@_.:-]{1,192}\.service$`)
	workloadAccountPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	workloadProfilePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+){0,7}$`)
	jsonConfigKeyPattern   = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,63}$`)
	modePattern            = regexp.MustCompile(`^0?[0246]{3}$`)
	identityPattern        = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,159}$`)
	pluginIDPattern        = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	sourcePluginIDPattern  = regexp.MustCompile(`^(adapter|workload)\.[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$`)
	sourceScopePattern     = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$`)
	digestPattern          = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	publisherPattern       = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/@:-]{0,159}$`)
	artifactRefPattern     = regexp.MustCompile(`^builtin:sha256:[a-f0-9]{64}$`)
	legacySettingPattern   = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9._-]{0,127}$`)
	approvalKeyIDPattern   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{7,159}$`)
	noncePattern           = regexp.MustCompile(`^[a-zA-Z0-9_-]{20,160}$`)
)

const (
	BaseWorkloadPluginID = "workload.base"
)

func ValidUnit(value string) bool            { return unitPattern.MatchString(value) }
func ValidWorkloadAccount(value string) bool { return workloadAccountPattern.MatchString(value) }
func ValidWorkloadPluginID(value string) bool {
	return strings.HasPrefix(value, "workload.") && sourcePluginIDPattern.MatchString(value)
}
func ValidWorkloadServiceUnit(value string) bool { return unitPattern.MatchString(value) }
func ValidWorkloadProfileKey(value string) bool {
	return len(value) <= 96 && workloadProfilePattern.MatchString(value)
}
func ValidJSONConfigKey(value string) bool   { return jsonConfigKeyPattern.MatchString(value) }
func ValidPackage(value string) bool         { return packagePattern.MatchString(value) }
func ValidDigest(value string) bool          { return digestPattern.MatchString(value) }
func ValidArtifactID(value string) bool      { return pluginIDPattern.MatchString(value) }
func ValidArtifactVersion(value string) bool { return versionPattern.MatchString(value) }
func ValidPublisher(value string) bool       { return publisherPattern.MatchString(value) }
func ValidArtifactRef(value string) bool     { return artifactRefPattern.MatchString(value) }

type Method string

const (
	MethodChangePrepare          Method = "change.prepare"
	MethodChangeStatus           Method = "change.status"
	MethodChangeApprove          Method = "change.approve"
	MethodChangeReject           Method = "change.reject"
	MethodChangeRollback         Method = "change.rollback"
	MethodHostSnapshot           Method = "host.snapshot"
	MethodSystemdUnit            Method = "systemd.unit"
	MethodJournalTail            Method = "journal.tail"
	MethodProcessList            Method = "process.list"
	MethodFileMetadata           Method = "file.metadata"
	MethodFileRead               Method = "file.read"
	MethodWorkloadCommandInspect Method = "workload.command.inspect"
	MethodHeartbeat              Method = "heartbeat"
)

// WorkloadCommandInspection is the only caller-controlled portion of a
// command recipe request. The root-owned Target policy supplies the account,
// executable, argv, environment, timeout and output bounds.
type WorkloadCommandInspection struct {
	PluginID     string `json:"pluginId"`
	PluginDigest string `json:"pluginDigest"`
	ProfileKey   string `json:"profileKey"`
}

func (i WorkloadCommandInspection) Validate() error {
	if !ValidWorkloadPluginID(i.PluginID) || i.PluginID == BaseWorkloadPluginID ||
		!ValidDigest(i.PluginDigest) || !ValidWorkloadProfileKey(i.ProfileKey) {
		return errors.New("invalid workload command inspection identity")
	}
	return nil
}

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
	WorkloadCommand    WorkloadCommandInspection
	PVE                PVEInspection
	Operation          Operation
	Approval           *ApprovalGrant
	ClearanceApproval  *PVERecoveryClearanceApproval
	ClearanceToken     string
	Raw                json.RawMessage
}

// ApprovalGrant is signed by the model-external client and verified again by
// the root broker. The network-facing server may relay it but cannot mint one.
type ApprovalGrant struct {
	Version            int    `json:"version"`
	KeyID              string `json:"keyId"`
	Action             string `json:"action"`
	ServerID           string `json:"serverId"`
	MachineID          string `json:"machineId"`
	TargetID           string `json:"targetId"`
	ChangeID           string `json:"changeId"`
	PlanHash           string `json:"planHash"`
	PolicyRevision     string `json:"policyRevision"`
	CapabilityRevision string `json:"capabilityRevision"`
	IssuedAt           string `json:"issuedAt"`
	ExpiresAt          string `json:"expiresAt"`
	Nonce              string `json:"nonce"`
	Signature          string `json:"signature"`
}

// ApprovalPayload returns the stable bytes signed by clients. Keep this field
// order synchronized with src/shared/approval.ts.
func (g ApprovalGrant) ApprovalPayload() ([]byte, error) {
	unsigned := struct {
		Version            int    `json:"version"`
		KeyID              string `json:"keyId"`
		Action             string `json:"action"`
		ServerID           string `json:"serverId"`
		MachineID          string `json:"machineId"`
		TargetID           string `json:"targetId"`
		ChangeID           string `json:"changeId"`
		PlanHash           string `json:"planHash"`
		PolicyRevision     string `json:"policyRevision"`
		CapabilityRevision string `json:"capabilityRevision"`
		IssuedAt           string `json:"issuedAt"`
		ExpiresAt          string `json:"expiresAt"`
		Nonce              string `json:"nonce"`
	}{g.Version, g.KeyID, g.Action, g.ServerID, g.MachineID, g.TargetID, g.ChangeID, g.PlanHash, g.PolicyRevision, g.CapabilityRevision, g.IssuedAt, g.ExpiresAt, g.Nonce}
	return json.Marshal(unsigned)
}

func (g ApprovalGrant) ValidateShape() error {
	if g.Version != Version || !approvalKeyIDPattern.MatchString(g.KeyID) || !noncePattern.MatchString(g.Nonce) {
		return errors.New("approval grant has an invalid version, keyId, or nonce")
	}
	if g.Action != "approve" && g.Action != "reject" && g.Action != "rollback" {
		return errors.New("approval grant has an invalid action")
	}
	if !identityPattern.MatchString(g.ServerID) || !identityPattern.MatchString(g.MachineID) || !identityPattern.MatchString(g.TargetID) || !changeIDPattern.MatchString(g.ChangeID) || !digestPattern.MatchString(g.PlanHash) || !identityPattern.MatchString(g.PolicyRevision) || !identityPattern.MatchString(g.CapabilityRevision) {
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
	Version   int            `json:"version"`
	RequestID string         `json:"requestId"`
	OK        bool           `json:"ok"`
	AuditID   string         `json:"auditId,omitempty"`
	ChangeID  string         `json:"changeId,omitempty"`
	State     string         `json:"state,omitempty"`
	Summary   string         `json:"summary,omitempty"`
	Data      interface{}    `json:"data,omitempty"`
	Error     string         `json:"error,omitempty"`
	Receipt   *BrokerReceipt `json:"brokerReceipt,omitempty"`
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
	PluginID      string `json:"pluginId"`
	PluginDigest  string `json:"pluginDigest"`
	Unit          string `json:"unit"`
	Action        string `json:"action"`
	storedLegacy  bool
}

// WorkloadServiceAction is the digest-bound host-service mutation available to
// any syntactically valid source workload. It is deliberately narrower than
// service.action: the plugin identity, source digest, service account, systemd
// manager, unit and action all cross the broker boundary as typed data and are
// pinned exactly by the root-owned Target policy.
type WorkloadServiceAction struct {
	OperationKind string `json:"kind"`
	PluginID      string `json:"pluginId"`
	PluginDigest  string `json:"pluginDigest"`
	Account       string `json:"account"`
	Manager       string `json:"manager"`
	Unit          string `json:"unit"`
	Action        string `json:"action"`
}

// WorkloadJSONConfigValue is deliberately a strict tagged union. The source
// workload may request one safe scalar or a clear; the root-owned Target
// policy decides whether that value kind is valid for the named semantic
// field and maps it to the real JSON key. It can never carry an object, array,
// executable, path to the config, argv, account, or helper choice.
type WorkloadJSONConfigValue struct {
	Kind         string  `json:"kind"`
	StringValue  *string `json:"stringValue,omitempty"`
	BooleanValue *bool   `json:"booleanValue,omitempty"`
}

func (v WorkloadJSONConfigValue) Validate() error {
	switch v.Kind {
	case "string":
		if v.StringValue == nil || v.BooleanValue != nil || !validBoundedControlFreeText(*v.StringValue, 512) {
			return errors.New("json config string value must be one bounded control-free string")
		}
	case "boolean":
		if v.StringValue != nil || v.BooleanValue == nil {
			return errors.New("json config boolean value must be one boolean")
		}
	case "clear":
		if v.StringValue != nil || v.BooleanValue != nil {
			return errors.New("json config clear value must not carry a scalar")
		}
	default:
		return errors.New("json config value has an unsupported kind")
	}
	return nil
}

func (v WorkloadJSONConfigValue) SafeText() string {
	switch v.Kind {
	case "string":
		if v.StringValue != nil {
			return *v.StringValue
		}
	case "boolean":
		if v.BooleanValue != nil {
			return strconv.FormatBool(*v.BooleanValue)
		}
	case "clear":
		return "<absent>"
	}
	return "<invalid>"
}

// WorkloadJSONConfigEdit is the only caller-controlled part of a JSON config
// mutation. All OS identity, path, selector-key, actual JSON field, helper and
// systemd-run details are resolved from the root-owned Target policy.
type WorkloadJSONConfigEdit struct {
	OperationKind string                  `json:"kind"`
	PluginID      string                  `json:"pluginId"`
	SourceDigest  string                  `json:"sourceDigest"`
	ProfileKey    string                  `json:"profileKey"`
	SelectorValue string                  `json:"selectorValue"`
	FieldKey      string                  `json:"fieldKey"`
	Value         WorkloadJSONConfigValue `json:"value"`
}

func (o WorkloadJSONConfigEdit) Kind() string { return "workload.json-config.edit" }
func (o WorkloadJSONConfigEdit) Summary() string {
	return fmt.Sprintf("edit %s field %s for selector %s", o.ProfileKey, o.FieldKey, o.SelectorValue)
}
func (o WorkloadJSONConfigEdit) Validate() error {
	if o.OperationKind != o.Kind() || !ValidWorkloadPluginID(o.PluginID) || o.PluginID == BaseWorkloadPluginID ||
		!ValidDigest(o.SourceDigest) || !ValidWorkloadProfileKey(o.ProfileKey) ||
		!validBoundedControlFreeText(o.SelectorValue, 256) || !ValidJSONConfigKey(o.FieldKey) {
		return errors.New("invalid workload.json-config.edit operation")
	}
	return o.Value.Validate()
}

func validBoundedControlFreeText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) {
			return false
		}
	}
	return true
}

func (o WorkloadServiceAction) Kind() string { return "workload.service.action" }
func (o WorkloadServiceAction) Summary() string {
	return fmt.Sprintf("%s %s service %s for account %s via %s manager", o.Action, o.PluginID, o.Unit, o.Account, o.Manager)
}
func (o WorkloadServiceAction) Validate() error {
	if o.OperationKind != o.Kind() || !ValidWorkloadPluginID(o.PluginID) ||
		!ValidDigest(o.PluginDigest) || !ValidWorkloadAccount(o.Account) ||
		!ValidWorkloadServiceUnit(o.Unit) {
		return errors.New("invalid workload.service.action operation")
	}
	if o.Manager != "system" && o.Manager != "user" {
		return errors.New("invalid workload service manager")
	}
	switch o.Action {
	case "reload", "reset-failed", "restart", "start", "stop":
		return nil
	default:
		return errors.New("invalid workload service action")
	}
}

func (o ServiceAction) Kind() string    { return "service.action" }
func (o ServiceAction) Summary() string { return o.Action + " service " + o.Unit }
func (o ServiceAction) Validate() error {
	if o.OperationKind != o.Kind() || (!o.storedLegacy &&
		(o.PluginID != BaseWorkloadPluginID || !ValidDigest(o.PluginDigest))) ||
		!unitPattern.MatchString(o.Unit) {
		return errors.New("invalid service.action operation")
	}
	switch o.Action {
	case "restart", "reload", "start", "stop":
		return nil
	default:
		return errors.New("invalid service action")
	}
}

func (o ServiceAction) storedOnly() bool              { return o.storedLegacy }
func (o ServiceAction) storedRollbackSupported() bool { return o.storedLegacy }

type FileWrite struct {
	OperationKind string `json:"kind"`
	PluginID      string `json:"pluginId"`
	PluginDigest  string `json:"pluginDigest"`
	Path          string `json:"path"`
	Content       string `json:"content"`
	Mode          string `json:"mode,omitempty"`
	storedLegacy  bool
}

type PluginInstall struct {
	OperationKind string `json:"kind"`
	PluginID      string `json:"pluginId"`
	Version       string `json:"version"`
	Publisher     string `json:"publisher"`
	Digest        string `json:"digest"`
	ArtifactRef   string `json:"artifactRef"`
	storedLegacy  bool
}

// PluginRegister activates an exact content-addressed source plugin. The
// source path is deliberately derived by the broker from PluginID; no path,
// command, entrypoint, or lifecycle hook crosses this privileged boundary.
type PluginRegister struct {
	OperationKind   string   `json:"kind"`
	PluginID        string   `json:"pluginId"`
	PluginKind      string   `json:"pluginKind"`
	Version         string   `json:"version"`
	Publisher       string   `json:"publisher"`
	Digest          string   `json:"digest"`
	Capabilities    []string `json:"capabilities"`
	RequestedScopes []string `json:"requestedScopes"`
}

func (o PluginRegister) Kind() string { return "plugin.register" }
func (o PluginRegister) Summary() string {
	return fmt.Sprintf("register source %s %s at %s with %d requested scopes", o.PluginKind, o.PluginID, o.Digest, len(o.RequestedScopes))
}
func (o PluginRegister) Validate() error {
	if o.OperationKind != o.Kind() || !sourcePluginIDPattern.MatchString(o.PluginID) ||
		(o.PluginKind != "adapter" && o.PluginKind != "workload") ||
		!strings.HasPrefix(o.PluginID, o.PluginKind+".") || !versionPattern.MatchString(o.Version) ||
		!publisherPattern.MatchString(o.Publisher) || !digestPattern.MatchString(o.Digest) ||
		o.Capabilities == nil || len(o.Capabilities) > 64 ||
		o.RequestedScopes == nil || len(o.RequestedScopes) > 64 {
		return errors.New("invalid plugin.register operation")
	}
	for index, capability := range o.Capabilities {
		if len(capability) > 128 || !sourceScopePattern.MatchString(capability) || (index > 0 && o.Capabilities[index-1] >= capability) {
			return errors.New("plugin.register capabilities must be sorted, unique, and valid")
		}
	}
	for index, scope := range o.RequestedScopes {
		if len(scope) > 128 || !sourceScopePattern.MatchString(scope) || (index > 0 && o.RequestedScopes[index-1] >= scope) {
			return errors.New("plugin.register requestedScopes must be sorted, unique, and valid")
		}
	}
	return nil
}

// legacyPluginConfigure and legacyPluginRemove are read-only representations
// of operations persisted by v0.1. They deliberately remain outside the live
// request tagged union and cannot be marshaled into a new change.
type legacyPluginSetting struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type legacyPluginConfigure struct {
	OperationKind string                `json:"kind"`
	PluginID      string                `json:"pluginId"`
	Version       string                `json:"version"`
	Digest        string                `json:"digest"`
	Settings      []legacyPluginSetting `json:"settings,omitempty"`
}

func (o legacyPluginConfigure) Kind() string { return "plugin.configure" }
func (o legacyPluginConfigure) Summary() string {
	return "configure legacy plugin " + o.PluginID + " version " + o.Version
}
func (o legacyPluginConfigure) Validate() error {
	if o.OperationKind != o.Kind() || !pluginIDPattern.MatchString(o.PluginID) || !versionPattern.MatchString(o.Version) || !digestPattern.MatchString(o.Digest) || len(o.Settings) > 128 {
		return errors.New("invalid legacy plugin.configure operation")
	}
	seen := make(map[string]struct{}, len(o.Settings))
	for _, setting := range o.Settings {
		if !legacySettingPattern.MatchString(setting.Name) || len(setting.Value) > 4096 || strings.ContainsRune(setting.Value, '\x00') {
			return errors.New("invalid legacy plugin setting")
		}
		if _, ok := seen[setting.Name]; ok {
			return errors.New("duplicate legacy plugin setting")
		}
		seen[setting.Name] = struct{}{}
	}
	return nil
}
func (legacyPluginConfigure) storedOnly() bool              { return true }
func (legacyPluginConfigure) storedRollbackSupported() bool { return false }

type legacyPluginRemove struct {
	OperationKind string `json:"kind"`
	PluginID      string `json:"pluginId"`
	Version       string `json:"version"`
	Digest        string `json:"digest"`
}

func (o legacyPluginRemove) Kind() string { return "plugin.remove" }
func (o legacyPluginRemove) Summary() string {
	return "remove legacy plugin " + o.PluginID + " version " + o.Version
}
func (o legacyPluginRemove) Validate() error {
	if o.OperationKind != o.Kind() || !pluginIDPattern.MatchString(o.PluginID) || !versionPattern.MatchString(o.Version) || !digestPattern.MatchString(o.Digest) {
		return errors.New("invalid legacy plugin.remove operation")
	}
	return nil
}
func (legacyPluginRemove) storedOnly() bool              { return true }
func (legacyPluginRemove) storedRollbackSupported() bool { return false }

type WorkloadDeploy struct {
	OperationKind string `json:"kind"`
	PluginID      string `json:"pluginId"`
	Version       string `json:"version"`
	Publisher     string `json:"publisher"`
	Digest        string `json:"digest"`
	ArtifactRef   string `json:"artifactRef"`
}

func (o WorkloadDeploy) Kind() string { return "workload.deploy" }
func (o WorkloadDeploy) Summary() string {
	return "deploy managed workload " + o.PluginID + " version " + o.Version
}
func (o WorkloadDeploy) Validate() error {
	if o.OperationKind != o.Kind() || !validArtifactIdentity(o.PluginID, o.Version, o.Publisher, o.Digest, o.ArtifactRef) {
		return errors.New("invalid workload.deploy operation")
	}
	return nil
}

func (o PluginInstall) Kind() string { return "plugin.install" }
func (o PluginInstall) Summary() string {
	return "install artifact " + o.PluginID + " version " + o.Version
}
func (o PluginInstall) Validate() error {
	if o.OperationKind != o.Kind() || !validArtifactIdentity(o.PluginID, o.Version, o.Publisher, o.Digest, o.ArtifactRef) {
		return errors.New("invalid plugin.install operation")
	}
	return nil
}

func (o PluginInstall) storedOnly() bool              { return o.storedLegacy }
func (o PluginInstall) storedRollbackSupported() bool { return false }

func validArtifactIdentity(id, version, publisher, digest, artifactRef string) bool {
	return pluginIDPattern.MatchString(id) &&
		versionPattern.MatchString(version) &&
		publisherPattern.MatchString(publisher) &&
		digestPattern.MatchString(digest) &&
		artifactRefPattern.MatchString(artifactRef) &&
		artifactRef == "builtin:"+digest
}

func (o FileWrite) Kind() string { return "file.write" }
func (o FileWrite) Summary() string {
	return fmt.Sprintf("write %d bytes to %s", len(o.Content), o.Path)
}
func (o FileWrite) Validate() error {
	if o.OperationKind != o.Kind() || (!o.storedLegacy &&
		(o.PluginID != BaseWorkloadPluginID || !ValidDigest(o.PluginDigest))) ||
		!filepath.IsAbs(o.Path) || filepath.Clean(o.Path) != o.Path {
		return errors.New("file.write path must be a clean absolute path")
	}
	if len(o.Path) > 4096 || strings.ContainsAny(o.Path, "\x00\n\r") || len(o.Content) > 128*1024 {
		return errors.New("file.write exceeds a protocol limit")
	}
	if o.Mode != "" {
		if !modePattern.MatchString(o.Mode) {
			return errors.New("file.write mode must be a non-executable 3-digit octal mode")
		}
		mode, err := strconv.ParseUint(o.Mode, 8, 12)
		if err != nil || mode&0o111 != 0 {
			return errors.New("file.write cannot create executable payload")
		}
	}
	return nil
}

func (o FileWrite) storedOnly() bool              { return o.storedLegacy }
func (o FileWrite) storedRollbackSupported() bool { return o.storedLegacy }

// IsProtectedHostControlPath identifies host control-plane locations that an
// ordinary file.write must never mutate.  These paths contain this agent's
// policy, identities, receipt keys, executable payload, privileged launchers,
// or service definitions.  A root-owned target allowlist cannot turn this
// denylist off; changes here require a dedicated typed operation (or the
// separately gated local break-glass workflow).
func IsProtectedHostControlPath(path string) bool {
	clean := filepath.Clean(path)
	protected := []string{
		"/etc/ops-agent", "/var/lib/ops-agent", "/var/log/ops-agent", "/run/ops-agent",
		"/opt/pi-ops-agent", "/usr/libexec/pi-ops-agent",
		"/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system",
	}
	for _, root := range protected {
		if clean == root || strings.HasPrefix(clean, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
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
	return fmt.Sprintf("run manually approved root script (%d bytes, %d backup paths)", len(o.Script), len(o.BackupPaths))
}
func (o BreakglassScript) Validate() error {
	if o.OperationKind != o.Kind() || len(o.Script) == 0 || len(o.Script) > 128*1024 {
		return errors.New("invalid breakglass.script operation")
	}
	if len(o.VerifyScript) > 32*1024 || len(o.BackupPaths) > 32 {
		return errors.New("manual root capsule backup and verification plans exceed their bounds")
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
			ChangeID       string         `json:"changeId"`
			Approval       *ApprovalGrant `json:"approval,omitempty"`
			ClearanceToken string         `json:"clearanceToken,omitempty"`
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
		if wire.ClearanceToken != "" {
			if header.Method != MethodChangeApprove || !ValidPVERecoveryClearanceToken(wire.ClearanceToken) || !strings.HasPrefix(wire.ChangeID, "pve-change-") {
				return Request{}, errors.New("PVE recovery clearance token is invalid for this action")
			}
		}
		request.ChangeID, request.Approval, request.ClearanceToken = wire.ChangeID, wire.Approval, wire.ClearanceToken
	case MethodPVERecoveryClearancePrepare:
		var wire struct {
			wireBase
			ChangeID string `json:"changeId"`
		}
		if err := strictDecode(payload, &wire); err != nil {
			return Request{}, err
		}
		if !strings.HasPrefix(wire.ChangeID, "pve-change-") || !changeIDPattern.MatchString(wire.ChangeID) {
			return Request{}, errors.New("invalid PVE recovery child changeId")
		}
		request.ChangeID = wire.ChangeID
	case MethodPVERecoveryClearanceConfirm:
		var wire struct {
			wireBase
			ChangeID          string                        `json:"changeId"`
			ClearanceApproval *PVERecoveryClearanceApproval `json:"clearanceApproval"`
		}
		if err := strictDecode(payload, &wire); err != nil {
			return Request{}, err
		}
		if !strings.HasPrefix(wire.ChangeID, "pve-change-") || !changeIDPattern.MatchString(wire.ChangeID) || wire.ClearanceApproval == nil {
			return Request{}, errors.New("invalid PVE recovery clearance confirmation")
		}
		if err := wire.ClearanceApproval.ValidateShape(); err != nil {
			return Request{}, err
		}
		if wire.ClearanceApproval.ChildChangeID != wire.ChangeID {
			return Request{}, errors.New("PVE recovery clearance approval child does not match request")
		}
		request.ChangeID, request.ClearanceApproval = wire.ChangeID, wire.ClearanceApproval
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
	case MethodWorkloadCommandInspect:
		var wire struct {
			wireBase
			PluginID     string `json:"pluginId"`
			PluginDigest string `json:"pluginDigest"`
			ProfileKey   string `json:"profileKey"`
		}
		if err := strictDecode(payload, &wire); err != nil {
			return Request{}, err
		}
		request.WorkloadCommand = WorkloadCommandInspection{
			PluginID: wire.PluginID, PluginDigest: wire.PluginDigest, ProfileKey: wire.ProfileKey,
		}
		if err := request.WorkloadCommand.Validate(); err != nil {
			return Request{}, err
		}
	case MethodPVEClusterStatus, MethodPVENodeStatus, MethodPVEStorageStatus, MethodPVETaskStatus, MethodPVEGuestStatus:
		request.PVE, err = parsePVEInspection(payload, header.Method)
		if err != nil {
			return Request{}, err
		}
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
	if request.CallerRole == "observer" && request.Method != MethodChangeStatus {
		return Request{}, errors.New("observer role may only request change.status from the root broker")
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
	case "agent", "observer", "approver", "admin":
		return nil
	default:
		return errors.New("remote request has invalid callerRole")
	}
}

func ParseStoredOperation(payload []byte) (Operation, error) {
	operation, currentErr := parseOperation(payload)
	if currentErr == nil {
		return operation, nil
	}
	var header struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(payload, &header); err != nil {
		return nil, fmt.Errorf("decode stored operation header: %w", err)
	}
	switch header.Kind {
	case "service.action":
		var legacy struct {
			OperationKind string `json:"kind"`
			Unit          string `json:"unit"`
			Action        string `json:"action"`
		}
		if err := strictDecode(payload, &legacy); err != nil {
			return nil, fmt.Errorf("decode legacy stored service.action: %w", err)
		}
		operation := &ServiceAction{
			OperationKind: legacy.OperationKind,
			Unit:          legacy.Unit,
			Action:        legacy.Action,
			storedLegacy:  true,
		}
		if err := operation.Validate(); err != nil {
			return nil, err
		}
		return operation, nil
	case "file.write":
		var legacy struct {
			OperationKind string `json:"kind"`
			Path          string `json:"path"`
			Content       string `json:"content"`
			Mode          string `json:"mode,omitempty"`
		}
		if err := strictDecode(payload, &legacy); err != nil {
			return nil, fmt.Errorf("decode legacy stored file.write: %w", err)
		}
		operation := &FileWrite{
			OperationKind: legacy.OperationKind,
			Path:          legacy.Path,
			Content:       legacy.Content,
			Mode:          legacy.Mode,
			storedLegacy:  true,
		}
		if err := operation.Validate(); err != nil {
			return nil, err
		}
		return operation, nil
	case "plugin.install":
		var legacy struct {
			OperationKind string `json:"kind"`
			PluginID      string `json:"pluginId"`
			Version       string `json:"version"`
			Digest        string `json:"digest"`
			CatalogPath   string `json:"catalogPath"`
		}
		if err := strictDecode(payload, &legacy); err != nil {
			return nil, fmt.Errorf("decode legacy stored plugin.install: %w", err)
		}
		if legacy.OperationKind != "plugin.install" || !pluginIDPattern.MatchString(legacy.PluginID) || !versionPattern.MatchString(legacy.Version) || !digestPattern.MatchString(legacy.Digest) || !validLegacyCatalogPath(legacy.CatalogPath) {
			return nil, errors.New("invalid legacy stored plugin.install operation")
		}
		return &PluginInstall{
			OperationKind: legacy.OperationKind,
			PluginID:      legacy.PluginID,
			Version:       legacy.Version,
			Publisher:     "legacy/v0.1",
			Digest:        legacy.Digest,
			ArtifactRef:   "builtin:" + legacy.Digest,
			storedLegacy:  true,
		}, nil
	case "plugin.configure":
		operation = &legacyPluginConfigure{}
	case "plugin.remove":
		operation = &legacyPluginRemove{}
	default:
		return nil, currentErr
	}
	if err := strictDecode(payload, operation); err != nil {
		return nil, fmt.Errorf("decode legacy stored %s: %w", header.Kind, err)
	}
	if err := operation.Validate(); err != nil {
		return nil, err
	}
	return operation, nil
}

func MarshalOperation(operation Operation) ([]byte, error) {
	if operation == nil {
		return nil, errors.New("operation is required")
	}
	if IsStoredOnlyOperation(operation) {
		return nil, errors.New("legacy stored operation cannot be prepared as a new change")
	}
	if err := operation.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(operation)
}

type storedOperationCompatibility interface {
	storedOnly() bool
	storedRollbackSupported() bool
}

// IsStoredOnlyOperation identifies operations accepted solely for reading a
// v0.1 persisted state. Such operations must never cross the new-prepare or
// approval execution path.
func IsStoredOnlyOperation(operation Operation) bool {
	compatibility, ok := operation.(storedOperationCompatibility)
	return ok && compatibility.storedOnly()
}

// StoredRollbackSupported is a schema-level lower bound for legacy recovery.
// A true result still requires an exact legacy plan hash and executor-specific
// durable commit evidence. Legacy plugin mutation is deliberately unsupported.
func StoredRollbackSupported(operation Operation) bool {
	compatibility, ok := operation.(storedOperationCompatibility)
	return !ok || !compatibility.storedOnly() || compatibility.storedRollbackSupported()
}

func validLegacyCatalogPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && len(path) <= 4096 && !strings.ContainsAny(path, "\x00\n\r")
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
	case "workload.service.action":
		operation = &WorkloadServiceAction{}
	case "workload.json-config.edit":
		operation = &WorkloadJSONConfigEdit{}
	case "file.write":
		operation = &FileWrite{}
	case "plugin.install":
		operation = &PluginInstall{}
	case "plugin.register":
		operation = &PluginRegister{}
	case "workload.deploy":
		operation = &WorkloadDeploy{}
	case "breakglass.script":
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(payload, &fields); err != nil {
			return nil, fmt.Errorf("decode breakglass fields: %w", err)
		}
		backupPaths, ok := fields["backupPaths"]
		if !ok || bytes.Equal(bytes.TrimSpace(backupPaths), []byte("null")) {
			return nil, errors.New("breakglass.script requires an explicit backup path list")
		}
		network, ok := fields["network"]
		if !ok || bytes.Equal(bytes.TrimSpace(network), []byte("null")) {
			return nil, errors.New("breakglass.script requires an explicit network declaration")
		}
		if verify, ok := fields["verifyScript"]; ok && bytes.Equal(bytes.TrimSpace(verify), []byte("null")) {
			return nil, errors.New("breakglass.script verifyScript must be a string when present")
		}
		operation = &BreakglassScript{}
	case "pve.guest.action":
		operation = &PVEGuestAction{}
	case "pve.snapshot.create":
		operation = &PVESnapshotCreate{}
	case "pve.snapshot.delete":
		operation = &PVESnapshotDelete{}
	case "pve.snapshot.rollback":
		operation = &PVESnapshotRollback{}
	case "pve.guest.backup":
		operation = &PVEGuestBackup{}
	case "pve.guest.restore":
		operation = &PVEGuestRestore{}
	case "pve.guest.migrate":
		operation = &PVEGuestMigrate{}
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
	if err := rejectDuplicateJSONKeys(payload); err != nil {
		return fmt.Errorf("strict JSON decode: %w", err)
	}
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
