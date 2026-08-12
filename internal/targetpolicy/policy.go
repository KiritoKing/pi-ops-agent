package targetpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

const Version = 1

var (
	idPattern          = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	revisionPattern    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{7,159}$`)
	accountPattern     = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	modelIDPattern     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:@/+~-]{0,255}$`)
	systemdPathPattern = regexp.MustCompile(`^/[a-zA-Z0-9._/-]+$`)
)

type Policy struct {
	Version  int      `json:"version"`
	Revision string   `json:"revision"`
	Targets  []Target `json:"targets"`

	byID map[string]Target
}

type ArtifactPolicy struct {
	ID                     string `json:"id"`
	Kind                   string `json:"kind"`
	Version                string `json:"version"`
	Publisher              string `json:"publisher"`
	Digest                 string `json:"digest"`
	CredentialBundleDigest string `json:"credentialBundleDigest,omitempty"`
}

type Target struct {
	ID                  string                     `json:"id"`
	Account             string                     `json:"account"`
	DisplayName         string                     `json:"displayName"`
	Inspect             InspectionPolicy           `json:"inspect"`
	Changes             ChangePolicy               `json:"changes"`
	Authorization       *AuthorizationPolicy       `json:"authorization,omitempty"`
	ServiceWorkloads    []ServiceWorkloadPolicy    `json:"serviceWorkloads,omitempty"`
	CommandWorkloads    []CommandWorkloadPolicy    `json:"commandWorkloads,omitempty"`
	JSONConfigWorkloads []JSONConfigWorkloadPolicy `json:"jsonConfigWorkloads,omitempty"`
	Breakglass          *BreakglassPolicy          `json:"breakglass,omitempty"`
	PVE                 *PVEPolicy                 `json:"pve,omitempty"`
}

type InspectionPolicy struct {
	HostSnapshot bool     `json:"hostSnapshot"`
	ProcessList  bool     `json:"processList"`
	Units        []string `json:"units"`
	ReadPaths    []string `json:"readPaths"`
}

type ChangePolicy struct {
	WritePaths []string         `json:"writePaths"`
	Units      []string         `json:"units"`
	Packages   []string         `json:"packages"`
	Plugins    []ArtifactPolicy `json:"plugins"`
}

// AuthorizationPolicy is deliberately separate from the mutation allowlists.
// An allowlist makes an operation eligible to be prepared; only an exact scope
// in StandingScopes permits the agent path to consume that prior authorization
// without a new human approval. Missing and empty policies therefore preserve
// the legacy, per-change approval behavior.
type AuthorizationPolicy struct {
	StandingScopes     []string `json:"standingScopes"`
	BaseWorkloadDigest string   `json:"baseWorkloadDigest,omitempty"`
}

var allowedStandingScopes = map[string]struct{}{
	"file.write":              {},
	"service.action":          {},
	"workload.service.action": {},
	"pve.guest.start":         {},
	"pve.guest.shutdown":      {},
	"pve.snapshot.create":     {},
	"pve.guest.backup":        {},
}

// ServiceWorkloadPolicy binds one source workload identity and digest to one
// service account and an exact systemd mutation surface. Multiple accounts are
// represented as separate targets, preserving the existing Target identity and
// approval binding while still supporting many instances per managed host.
type ServiceWorkloadPolicy struct {
	PluginID     string   `json:"pluginId"`
	PluginDigest string   `json:"pluginDigest"`
	Account      string   `json:"account"`
	Manager      string   `json:"manager"`
	Units        []string `json:"units"`
	Operations   []string `json:"operations"`
}

// CommandWorkloadPolicy is a root-owned, digest-bound read recipe. Source
// workloads select only ProfileKey; every execution detail remains here and is
// therefore outside model/plugin control at invocation time.
type CommandWorkloadPolicy struct {
	PluginID       string   `json:"pluginId"`
	PluginDigest   string   `json:"pluginDigest"`
	TargetAccount  string   `json:"targetAccount"`
	ProfileKey     string   `json:"profileKey"`
	RunAsAccount   string   `json:"runAsAccount"`
	RunAsHome      string   `json:"runAsHome"`
	Executable     string   `json:"executable"`
	Argv           []string `json:"argv"`
	TimeoutSeconds int      `json:"timeoutSeconds"`
	MaxOutputBytes int      `json:"maxOutputBytes"`
}

// JSONConfigWorkloadPolicy maps a source-visible semantic profile onto one
// non-root user's exact config document. Source workloads never receive or
// supply these execution details. RunAsUID and RunAsHome are both pinned so a
// changed passwd mapping fails closed when the executor revalidates it.
type JSONConfigWorkloadPolicy struct {
	PluginID         string                  `json:"pluginId"`
	PluginDigest     string                  `json:"pluginDigest"`
	TargetAccount    string                  `json:"targetAccount"`
	ProfileKey       string                  `json:"profileKey"`
	RunAsUID         uint32                  `json:"runAsUid"`
	RunAsHome        string                  `json:"runAsHome"`
	RelativeConfig   string                  `json:"relativeConfig"`
	SelectorKey      string                  `json:"selectorKey"`
	AllowedSelectors []string                `json:"allowedSelectors"`
	Fields           []JSONConfigFieldPolicy `json:"fields"`
}

// JSONConfigFieldPolicy maps one source-visible field name onto an actual JSON
// key and one fixed constraint family. Constraint names are closed enums rather
// than caller-provided regular expressions.
type JSONConfigFieldPolicy struct {
	FieldKey         string   `json:"fieldKey"`
	JSONField        string   `json:"jsonField"`
	ValueType        string   `json:"valueType"`
	AllowClear       bool     `json:"allowClear"`
	StringConstraint string   `json:"stringConstraint,omitempty"`
	EnumValues       []string `json:"enumValues,omitempty"`
	PathRoots        []string `json:"pathRoots,omitempty"`
}

// BreakglassPolicy is retained only so v0.2 target-policy files continue to
// parse during an upgrade. In v0.3 it grants no authority: every root target
// may prepare a manual capsule, and every capsule still requires a separate
// local TTY approval. It is never eligible for standing authorization.
type BreakglassPolicy struct {
	Mode         string `json:"mode"`
	AllowNetwork bool   `json:"allowNetwork"`
}

// PVEPolicy is a digest-bound persistent grant for the source workload. It
// names every node, guest, storage and mutation family the workload may reach;
// there is no generic pvesh path or argv allowlist.
type PVEPolicy struct {
	PluginID         string           `json:"pluginId"`
	PluginDigest     string           `json:"pluginDigest"`
	Nodes            []string         `json:"nodes"`
	Storages         []string         `json:"storages"`
	Guests           []PVEGuestPolicy `json:"guests"`
	MigrationTargets []string         `json:"migrationTargets"`
	Operations       []string         `json:"operations"`
}

type PVEGuestPolicy struct {
	GuestType string `json:"guestType"`
	VMID      int    `json:"vmid"`
}

func Load(path string, requireRootOwner bool) (*Policy, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("target policy must be a regular file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("target policy must not be group or world writable")
	}
	if requireRootOwner {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return nil, errors.New("target policy must be owned by root")
		}
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(payload)
}

func Parse(payload []byte) (*Policy, error) {
	if err := rejectDuplicateJSONKeys(payload); err != nil {
		return nil, fmt.Errorf("decode target policy: %w", err)
	}
	var policy Policy
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return nil, fmt.Errorf("decode target policy: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("decode target policy: trailing value")
		}
		return nil, fmt.Errorf("decode target policy: %w", err)
	}
	if err := policy.validate(); err != nil {
		return nil, err
	}
	return &policy, nil
}

func rejectDuplicateJSONKeys(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return fmt.Errorf("unexpected trailing token %v", token)
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
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
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
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

func (p *Policy) validate() error {
	if p.Version != Version || !revisionPattern.MatchString(p.Revision) {
		return errors.New("target policy has an unsupported version or invalid revision")
	}
	if len(p.Targets) == 0 || len(p.Targets) > 128 {
		return errors.New("target policy must contain between 1 and 128 targets")
	}
	p.byID = make(map[string]Target, len(p.Targets))
	for index := range p.Targets {
		target := &p.Targets[index]
		if !idPattern.MatchString(target.ID) || len(target.ID) < 8 || !accountPattern.MatchString(target.Account) || target.DisplayName == "" || len(target.DisplayName) > 256 {
			return fmt.Errorf("target %d has an invalid id or account", index)
		}
		if _, exists := p.byID[target.ID]; exists {
			return fmt.Errorf("duplicate target %q", target.ID)
		}
		if err := validatePaths(target.Inspect.ReadPaths, "readPaths"); err != nil {
			return fmt.Errorf("target %q: %w", target.ID, err)
		}
		if err := validatePaths(target.Changes.WritePaths, "writePaths"); err != nil {
			return fmt.Errorf("target %q: %w", target.ID, err)
		}
		if err := validateValues(target.Inspect.Units, protocol.ValidUnit, "inspection unit"); err != nil {
			return fmt.Errorf("target %q: %w", target.ID, err)
		}
		if err := validateValues(target.Changes.Units, protocol.ValidUnit, "change unit"); err != nil {
			return fmt.Errorf("target %q: %w", target.ID, err)
		}
		if err := validateValues(target.Changes.Packages, protocol.ValidPackage, "package"); err != nil {
			return fmt.Errorf("target %q: %w", target.ID, err)
		}
		if err := validateArtifacts(target.Changes.Plugins); err != nil {
			return fmt.Errorf("target %q: %w", target.ID, err)
		}
		if err := validateAuthorizationPolicy(target.Authorization); err != nil {
			return fmt.Errorf("target %q: %w", target.ID, err)
		}
		if err := validateServiceWorkloads(target); err != nil {
			return fmt.Errorf("target %q: %w", target.ID, err)
		}
		if err := validateCommandWorkloads(target); err != nil {
			return fmt.Errorf("target %q: %w", target.ID, err)
		}
		if err := validateJSONConfigWorkloads(target); err != nil {
			return fmt.Errorf("target %q: %w", target.ID, err)
		}
		if err := validateBreakglassPolicy(target); err != nil {
			return fmt.Errorf("target %q: %w", target.ID, err)
		}
		if target.PVE != nil && target.Account != "root" {
			return fmt.Errorf("target %q: PVE policy requires account root", target.ID)
		}
		if err := validatePVEPolicy(target.PVE); err != nil {
			return fmt.Errorf("target %q: %w", target.ID, err)
		}
		sort.Strings(target.Inspect.Units)
		sort.Strings(target.Inspect.ReadPaths)
		sort.Strings(target.Changes.Units)
		sort.Strings(target.Changes.WritePaths)
		sort.Strings(target.Changes.Packages)
		if target.Authorization != nil {
			sort.Strings(target.Authorization.StandingScopes)
		}
		sort.Slice(target.Changes.Plugins, func(i, j int) bool {
			return artifactKey(target.Changes.Plugins[i]) < artifactKey(target.Changes.Plugins[j])
		})
		sort.Slice(target.ServiceWorkloads, func(i, j int) bool {
			return serviceWorkloadKey(target.ServiceWorkloads[i]) < serviceWorkloadKey(target.ServiceWorkloads[j])
		})
		sort.Slice(target.CommandWorkloads, func(i, j int) bool {
			return commandWorkloadKey(target.CommandWorkloads[i]) < commandWorkloadKey(target.CommandWorkloads[j])
		})
		sort.Slice(target.JSONConfigWorkloads, func(i, j int) bool {
			return jsonConfigWorkloadKey(target.JSONConfigWorkloads[i]) < jsonConfigWorkloadKey(target.JSONConfigWorkloads[j])
		})
		p.byID[target.ID] = *target
	}
	return nil
}

func validateAuthorizationPolicy(policy *AuthorizationPolicy) error {
	if policy == nil {
		return nil
	}
	if policy.StandingScopes == nil || len(policy.StandingScopes) > len(allowedStandingScopes) {
		return errors.New("authorization standingScopes must be a non-null bounded array")
	}
	if err := validateValues(policy.StandingScopes, func(value string) bool {
		_, ok := allowedStandingScopes[value]
		return ok
	}, "standing authorization scope"); err != nil {
		return err
	}
	needsBaseDigest := contains(policy.StandingScopes, "file.write") ||
		contains(policy.StandingScopes, "service.action")
	if policy.BaseWorkloadDigest != "" && !protocol.ValidDigest(policy.BaseWorkloadDigest) {
		return errors.New("authorization baseWorkloadDigest must be a canonical source digest")
	}
	if needsBaseDigest && !protocol.ValidDigest(policy.BaseWorkloadDigest) {
		return errors.New("standing file.write or service.action requires baseWorkloadDigest")
	}
	return nil
}

func validateServiceWorkloads(target *Target) error {
	if len(target.ServiceWorkloads) > 16 {
		return errors.New("service workload allowlist is too large")
	}
	seen := make(map[string]struct{}, len(target.ServiceWorkloads))
	for index := range target.ServiceWorkloads {
		workload := &target.ServiceWorkloads[index]
		if !protocol.ValidWorkloadPluginID(workload.PluginID) || !protocol.ValidDigest(workload.PluginDigest) ||
			!protocol.ValidWorkloadAccount(workload.Account) ||
			workload.Account != target.Account || (workload.Manager != "system" && workload.Manager != "user") {
			return errors.New("service workload must bind a source workload identity, exact digest, target account, and manager")
		}
		if len(workload.Units) == 0 || len(workload.Units) > 64 {
			return errors.New("service workload must contain between 1 and 64 units")
		}
		if err := validateValues(workload.Units, protocol.ValidWorkloadServiceUnit, "service workload unit"); err != nil {
			return err
		}
		if len(workload.Operations) == 0 || len(workload.Operations) > 5 {
			return errors.New("service workload must contain between 1 and 5 operations")
		}
		if err := validateValues(workload.Operations, func(value string) bool {
			return value == "start" || value == "stop" || value == "restart" ||
				value == "reload" || value == "reset-failed"
		}, "service workload operation"); err != nil {
			return err
		}
		sort.Strings(workload.Units)
		sort.Strings(workload.Operations)
		key := serviceWorkloadKey(*workload)
		if _, duplicate := seen[key]; duplicate {
			return errors.New("duplicate service workload policy")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func serviceWorkloadKey(workload ServiceWorkloadPolicy) string {
	return strings.Join([]string{workload.PluginID, workload.PluginDigest, workload.Account, workload.Manager}, "\x00")
}

func validateCommandWorkloads(target *Target) error {
	if len(target.CommandWorkloads) > 64 {
		return errors.New("command workload profile allowlist is too large")
	}
	seen := make(map[string]struct{}, len(target.CommandWorkloads))
	for index := range target.CommandWorkloads {
		profile := &target.CommandWorkloads[index]
		if !protocol.ValidWorkloadPluginID(profile.PluginID) || profile.PluginID == protocol.BaseWorkloadPluginID ||
			!protocol.ValidDigest(profile.PluginDigest) || !protocol.ValidWorkloadAccount(profile.TargetAccount) ||
			profile.TargetAccount == "root" || profile.TargetAccount != target.Account || !protocol.ValidWorkloadProfileKey(profile.ProfileKey) ||
			!protocol.ValidWorkloadAccount(profile.RunAsAccount) || profile.RunAsAccount == "root" {
			return errors.New("command workload must bind a business workload, exact digest, target account, profile key, and non-root run-as account")
		}
		if !filepath.IsAbs(profile.RunAsHome) || filepath.Clean(profile.RunAsHome) != profile.RunAsHome ||
			profile.RunAsHome == "/" || len(profile.RunAsHome) > 4096 || strings.ContainsAny(profile.RunAsHome, "\x00\r\n") {
			return errors.New("command workload runAsHome must be a clean absolute path below root")
		}
		if !filepath.IsAbs(profile.Executable) || filepath.Clean(profile.Executable) != profile.Executable ||
			profile.Executable == "/" || len(profile.Executable) > 4096 || strings.ContainsAny(profile.Executable, "\x00\r\n") {
			return errors.New("command workload executable must be a clean absolute path below root")
		}
		if profile.Argv == nil || len(profile.Argv) > 32 {
			return errors.New("command workload argv must be an explicit bounded array")
		}
		totalArgvBytes := 0
		for _, argument := range profile.Argv {
			if argument == "" || len(argument) > 512 || strings.ContainsAny(argument, "\x00\r\n") {
				return errors.New("command workload argv contains an invalid fixed argument")
			}
			totalArgvBytes += len(argument)
		}
		if totalArgvBytes > 8192 || profile.TimeoutSeconds < 1 || profile.TimeoutSeconds > 120 ||
			profile.MaxOutputBytes < 1 || profile.MaxOutputBytes > 64*1024 {
			return errors.New("command workload timeout, argv, or output bound is invalid")
		}
		key := commandWorkloadKey(*profile)
		if _, duplicate := seen[key]; duplicate {
			return errors.New("duplicate command workload profile")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func commandWorkloadKey(profile CommandWorkloadPolicy) string {
	return strings.Join([]string{profile.PluginID, profile.PluginDigest, profile.ProfileKey}, "\x00")
}

func validateJSONConfigWorkloads(target *Target) error {
	if len(target.JSONConfigWorkloads) > 32 {
		return errors.New("JSON config workload profile allowlist is too large")
	}
	seenProfiles := make(map[string]struct{}, len(target.JSONConfigWorkloads))
	seenDocuments := make(map[string]struct{}, len(target.JSONConfigWorkloads))
	for profileIndex := range target.JSONConfigWorkloads {
		profile := &target.JSONConfigWorkloads[profileIndex]
		if !protocol.ValidWorkloadPluginID(profile.PluginID) || profile.PluginID == protocol.BaseWorkloadPluginID ||
			!protocol.ValidDigest(profile.PluginDigest) || !protocol.ValidWorkloadAccount(profile.TargetAccount) ||
			profile.TargetAccount != target.Account || !protocol.ValidWorkloadProfileKey(profile.ProfileKey) ||
			profile.RunAsUID == 0 || profile.RunAsUID > 1<<31-1 {
			return errors.New("JSON config workload must bind a business workload, exact digest, target account, profile, and non-root UID")
		}
		if !cleanAbsolutePolicyPath(profile.RunAsHome) {
			return errors.New("JSON config workload runAsHome must be a clean absolute path below root")
		}
		if !cleanRelativePolicyPath(profile.RelativeConfig) {
			return errors.New("JSON config workload relativeConfig must stay beneath runAsHome")
		}
		if !protocol.ValidJSONConfigKey(profile.SelectorKey) {
			return errors.New("JSON config workload selectorKey is invalid")
		}
		if len(profile.AllowedSelectors) == 0 || len(profile.AllowedSelectors) > 256 {
			return errors.New("JSON config workload allowedSelectors must be a non-empty bounded array")
		}
		if err := validateValues(profile.AllowedSelectors, func(value string) bool {
			return validBoundedPolicyText(value, 256)
		}, "JSON config selector"); err != nil {
			return err
		}
		if len(profile.Fields) == 0 || len(profile.Fields) > 32 {
			return errors.New("JSON config workload fields must be a non-empty bounded array")
		}
		seenFieldKeys := make(map[string]struct{}, len(profile.Fields))
		seenJSONFields := make(map[string]struct{}, len(profile.Fields))
		for fieldIndex := range profile.Fields {
			field := &profile.Fields[fieldIndex]
			if !protocol.ValidJSONConfigKey(field.FieldKey) || !protocol.ValidJSONConfigKey(field.JSONField) ||
				field.JSONField == profile.SelectorKey {
				return errors.New("JSON config field mapping contains an invalid or selector-overlapping key")
			}
			if _, duplicate := seenFieldKeys[field.FieldKey]; duplicate {
				return errors.New("JSON config workload contains a duplicate semantic field")
			}
			seenFieldKeys[field.FieldKey] = struct{}{}
			if _, duplicate := seenJSONFields[field.JSONField]; duplicate {
				return errors.New("JSON config workload contains a duplicate actual JSON field")
			}
			seenJSONFields[field.JSONField] = struct{}{}
			if err := validateJSONConfigField(field); err != nil {
				return fmt.Errorf("JSON config field %q: %w", field.FieldKey, err)
			}
		}
		sort.Strings(profile.AllowedSelectors)
		sort.Slice(profile.Fields, func(i, j int) bool { return profile.Fields[i].FieldKey < profile.Fields[j].FieldKey })
		profileKey := jsonConfigWorkloadKey(*profile)
		if _, duplicate := seenProfiles[profileKey]; duplicate {
			return errors.New("duplicate JSON config workload profile")
		}
		seenProfiles[profileKey] = struct{}{}
		documentKey := fmt.Sprintf("%d\x00%s\x00%s", profile.RunAsUID, profile.RunAsHome, profile.RelativeConfig)
		if _, duplicate := seenDocuments[documentKey]; duplicate {
			return errors.New("one JSON config document cannot be exposed through multiple policy profiles")
		}
		seenDocuments[documentKey] = struct{}{}
	}
	return nil
}

func validateJSONConfigField(field *JSONConfigFieldPolicy) error {
	switch field.ValueType {
	case "boolean":
		if field.StringConstraint != "" || field.EnumValues != nil || field.PathRoots != nil {
			return errors.New("boolean mapping cannot carry string constraints")
		}
		return nil
	case "string":
	default:
		return errors.New("valueType must be string or boolean")
	}
	switch field.StringConstraint {
	case "model-id/v1":
		if field.EnumValues != nil || field.PathRoots != nil {
			return errors.New("model-id constraint cannot carry enum values or path roots")
		}
	case "enum/v1":
		if len(field.EnumValues) == 0 || len(field.EnumValues) > 32 || field.PathRoots != nil {
			return errors.New("enum constraint requires a non-empty bounded enumValues array")
		}
		if err := validateValues(field.EnumValues, func(value string) bool {
			return validBoundedPolicyText(value, 128)
		}, "JSON config enum value"); err != nil {
			return err
		}
		sort.Strings(field.EnumValues)
	case "absolute-path/v1":
		if field.EnumValues != nil || len(field.PathRoots) == 0 || len(field.PathRoots) > 16 {
			return errors.New("absolute-path constraint requires non-empty bounded pathRoots")
		}
		if err := validateValues(field.PathRoots, cleanAbsolutePolicyPath, "JSON config path root"); err != nil {
			return err
		}
		sort.Strings(field.PathRoots)
	default:
		return errors.New("string mapping requires a supported closed constraint")
	}
	return nil
}

func jsonConfigWorkloadKey(profile JSONConfigWorkloadPolicy) string {
	return strings.Join([]string{profile.PluginID, profile.PluginDigest, profile.ProfileKey}, "\x00")
}

func cleanAbsolutePolicyPath(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && value != "/" &&
		len(value) <= 4096 && systemdPathPattern.MatchString(value)
}

func cleanRelativePolicyPath(value string) bool {
	if value == "" || filepath.IsAbs(value) || filepath.Clean(value) != value || value == "." || value == ".." ||
		strings.HasPrefix(value, ".."+string(filepath.Separator)) || len(value) > 4096 ||
		!systemdPathPattern.MatchString("/"+value) {
		return false
	}
	for _, component := range strings.Split(value, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

func validBoundedPolicyText(value string, maximum int) bool {
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

func validateBreakglassPolicy(target *Target) error {
	if target.Breakglass == nil {
		return nil
	}
	if target.Account != "root" {
		return errors.New("break-glass is only valid for an explicit root target")
	}
	if target.Breakglass.Mode != "full-root" {
		return errors.New("break-glass mode must be full-root")
	}
	return nil
}

func validatePVEPolicy(policy *PVEPolicy) error {
	if policy == nil {
		return nil
	}
	if !protocol.ValidWorkloadPluginID(policy.PluginID) || !protocol.ValidDigest(policy.PluginDigest) {
		return errors.New("PVE policy must bind a source workload identity and exact digest")
	}
	if len(policy.Nodes) == 0 || len(policy.Nodes) > 64 {
		return errors.New("PVE policy must contain between 1 and 64 nodes")
	}
	if err := validateValues(policy.Nodes, protocol.ValidPVENode, "PVE node"); err != nil {
		return err
	}
	if policy.Storages == nil || len(policy.Storages) > 128 {
		return errors.New("PVE storage allowlist must be a non-null array with at most 128 entries")
	}
	if err := validateValues(policy.Storages, protocol.ValidPVEStorage, "PVE storage"); err != nil {
		return err
	}
	if len(policy.Guests) == 0 || len(policy.Guests) > 512 {
		return errors.New("PVE policy must contain between 1 and 512 guests")
	}
	guestKeys := make(map[string]struct{}, len(policy.Guests))
	for _, guest := range policy.Guests {
		if !protocol.ValidPVEGuestType(guest.GuestType) || !protocol.ValidPVEVMID(guest.VMID) {
			return errors.New("PVE policy contains an invalid guest")
		}
		key := fmt.Sprintf("%s/%d", guest.GuestType, guest.VMID)
		if _, exists := guestKeys[key]; exists {
			return errors.New("PVE policy contains a duplicate guest")
		}
		guestKeys[key] = struct{}{}
	}
	if policy.MigrationTargets == nil || len(policy.MigrationTargets) > 64 {
		return errors.New("PVE migrationTargets must be a non-null array with at most 64 entries")
	}
	if err := validateValues(policy.MigrationTargets, protocol.ValidPVENode, "PVE migration target"); err != nil {
		return err
	}
	for _, node := range policy.MigrationTargets {
		if !contains(policy.Nodes, node) {
			return errors.New("PVE migration target is not in the node allowlist")
		}
	}
	allowedOperations := map[string]struct{}{
		"pve.guest.start": {}, "pve.guest.shutdown": {}, "pve.guest.stop": {}, "pve.guest.reboot": {},
		"pve.snapshot.create": {}, "pve.snapshot.delete": {}, "pve.snapshot.rollback": {},
		"pve.guest.backup": {}, "pve.guest.restore": {}, "pve.guest.migrate": {},
	}
	if policy.Operations == nil || len(policy.Operations) > len(allowedOperations) {
		return errors.New("PVE operations must be a non-null bounded array")
	}
	if err := validateValues(policy.Operations, func(value string) bool {
		_, ok := allowedOperations[value]
		return ok
	}, "PVE operation"); err != nil {
		return err
	}
	sort.Strings(policy.Nodes)
	sort.Strings(policy.Storages)
	sort.Strings(policy.MigrationTargets)
	sort.Strings(policy.Operations)
	sort.Slice(policy.Guests, func(left, right int) bool {
		if policy.Guests[left].GuestType != policy.Guests[right].GuestType {
			return policy.Guests[left].GuestType < policy.Guests[right].GuestType
		}
		return policy.Guests[left].VMID < policy.Guests[right].VMID
	})
	return nil
}

func validateArtifacts(artifacts []ArtifactPolicy) error {
	if len(artifacts) > 128 {
		return errors.New("artifact allowlist is too large")
	}
	seen := make(map[string]struct{}, len(artifacts))
	for _, artifact := range artifacts {
		if !protocol.ValidArtifactID(artifact.ID) ||
			!protocol.ValidArtifactVersion(artifact.Version) ||
			!protocol.ValidPublisher(artifact.Publisher) ||
			!protocol.ValidDigest(artifact.Digest) {
			return fmt.Errorf("invalid artifact policy %q", artifact.ID)
		}
		switch artifact.Kind {
		case "im-adapter":
			if artifact.CredentialBundleDigest != "" {
				return fmt.Errorf("im-adapter artifact %q must omit credentialBundleDigest", artifact.ID)
			}
		case "managed-workload":
			if !protocol.ValidDigest(artifact.CredentialBundleDigest) {
				return fmt.Errorf("managed-workload artifact %q requires a valid credentialBundleDigest", artifact.ID)
			}
		default:
			return fmt.Errorf("artifact %q has unsupported kind %q", artifact.ID, artifact.Kind)
		}
		key := artifactKey(artifact)
		if _, ok := seen[key]; ok {
			return fmt.Errorf("duplicate artifact policy %q", artifact.ID)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func artifactKey(artifact ArtifactPolicy) string {
	return strings.Join([]string{artifact.Kind, artifact.ID, artifact.Version, artifact.Publisher, artifact.Digest}, "\x00")
}

func (p *Policy) Target(id string) (Target, bool) {
	if p == nil {
		return Target{}, false
	}
	target, ok := p.byID[id]
	return target, ok
}

func (p *Policy) Artifact(targetID, kind, id, version, publisher, digest string) (ArtifactPolicy, bool) {
	if p == nil {
		return ArtifactPolicy{}, false
	}
	target, ok := p.Target(targetID)
	if !ok {
		return ArtifactPolicy{}, false
	}
	for _, artifact := range target.Changes.Plugins {
		if artifact.Kind == kind && artifact.ID == id && artifact.Version == version && artifact.Publisher == publisher && artifact.Digest == digest {
			return artifact, true
		}
	}
	return ArtifactPolicy{}, false
}

func (p *Policy) CommandWorkload(targetID string, inspection protocol.WorkloadCommandInspection) (CommandWorkloadPolicy, bool) {
	if p == nil || inspection.Validate() != nil {
		return CommandWorkloadPolicy{}, false
	}
	target, ok := p.Target(targetID)
	if !ok {
		return CommandWorkloadPolicy{}, false
	}
	for _, profile := range target.CommandWorkloads {
		if profile.PluginID == inspection.PluginID && profile.PluginDigest == inspection.PluginDigest &&
			profile.ProfileKey == inspection.ProfileKey {
			profile.Argv = append([]string{}, profile.Argv...)
			return profile, true
		}
	}
	return CommandWorkloadPolicy{}, false
}

// JSONConfigWorkload resolves a semantic edit to its root-owned execution
// profile and actual field mapping. Returned slices are copied so callers
// cannot mutate the active policy.
func (p *Policy) JSONConfigWorkload(targetID string, edit protocol.WorkloadJSONConfigEdit) (JSONConfigWorkloadPolicy, JSONConfigFieldPolicy, bool) {
	if p == nil || edit.Validate() != nil {
		return JSONConfigWorkloadPolicy{}, JSONConfigFieldPolicy{}, false
	}
	target, ok := p.Target(targetID)
	if !ok {
		return JSONConfigWorkloadPolicy{}, JSONConfigFieldPolicy{}, false
	}
	for _, profile := range target.JSONConfigWorkloads {
		if profile.PluginID != edit.PluginID || profile.PluginDigest != edit.SourceDigest || profile.ProfileKey != edit.ProfileKey ||
			!contains(profile.AllowedSelectors, edit.SelectorValue) {
			continue
		}
		for _, field := range profile.Fields {
			if field.FieldKey != edit.FieldKey || !jsonConfigValueAllowed(field, edit.Value) {
				continue
			}
			profile.AllowedSelectors = append([]string{}, profile.AllowedSelectors...)
			profile.Fields = append([]JSONConfigFieldPolicy{}, profile.Fields...)
			field.EnumValues = append([]string{}, field.EnumValues...)
			field.PathRoots = append([]string{}, field.PathRoots...)
			return profile, field, true
		}
	}
	return JSONConfigWorkloadPolicy{}, JSONConfigFieldPolicy{}, false
}

func jsonConfigValueAllowed(field JSONConfigFieldPolicy, value protocol.WorkloadJSONConfigValue) bool {
	if value.Validate() != nil {
		return false
	}
	if value.Kind == "clear" {
		return field.AllowClear
	}
	if value.Kind != field.ValueType {
		return false
	}
	if value.Kind == "boolean" {
		return true
	}
	text := *value.StringValue
	switch field.StringConstraint {
	case "model-id/v1":
		return modelIDPattern.MatchString(text)
	case "enum/v1":
		return contains(field.EnumValues, text)
	case "absolute-path/v1":
		if !cleanAbsolutePolicyPath(text) {
			return false
		}
		for _, root := range field.PathRoots {
			relative, err := filepath.Rel(root, text)
			if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				return true
			}
		}
	}
	return false
}

func (p *Policy) PublicTargets() []Target {
	if p == nil {
		return nil
	}
	result := make([]Target, len(p.Targets))
	copy(result, p.Targets)
	return result
}

// BreakglassEnabled is retained for callers compiled against v0.2. In v0.3 it
// reports whether any root target can prepare a manual capsule; no separate
// breakglass policy grants authority.
func (p *Policy) BreakglassEnabled() bool {
	if p == nil {
		return false
	}
	for _, target := range p.Targets {
		if target.Account == "root" {
			return true
		}
	}
	return false
}

func (p *Policy) Breakglass(targetID string) (BreakglassPolicy, bool) {
	target, ok := p.Target(targetID)
	if !ok || target.Breakglass == nil {
		return BreakglassPolicy{}, false
	}
	return *target.Breakglass, true
}

func (p *Policy) Authorize(request protocol.Request) error {
	if p == nil {
		return nil
	}
	if request.PolicyRevision != p.Revision {
		return errors.New("request policyRevision does not match the active root policy")
	}
	target, ok := p.Target(request.TargetID)
	if !ok {
		return errors.New("unknown targetId")
	}
	switch request.Method {
	case protocol.MethodHostSnapshot:
		if !target.Inspect.HostSnapshot {
			return errors.New("host snapshot is denied for this target")
		}
	case protocol.MethodProcessList:
		if !target.Inspect.ProcessList {
			return errors.New("process listing is denied for this target")
		}
	case protocol.MethodSystemdUnit, protocol.MethodJournalTail:
		if !contains(target.Inspect.Units, request.Unit) {
			return errors.New("systemd unit inspection is outside target policy")
		}
	case protocol.MethodFileMetadata:
		if err := pathWithin(request.Path, target.Inspect.ReadPaths); err != nil {
			return fmt.Errorf("file inspection is outside target policy: %w", err)
		}
	case protocol.MethodFileRead:
		if err := exactPathAllowed(request.Path, target.Inspect.ReadPaths); err != nil {
			return fmt.Errorf("file read is outside target policy: %w", err)
		}
	case protocol.MethodWorkloadCommandInspect:
		if _, ok := p.CommandWorkload(request.TargetID, request.WorkloadCommand); !ok {
			return errors.New("workload command profile is outside the exact digest-bound target policy")
		}
	case protocol.MethodPVEClusterStatus:
		if !pveInspectionPluginAllowed(target.PVE, request.PVE) {
			return errors.New("PVE inspection is not enabled for this target")
		}
	case protocol.MethodPVENodeStatus, protocol.MethodPVETaskStatus:
		if !pveInspectionPluginAllowed(target.PVE, request.PVE) || !contains(target.PVE.Nodes, request.PVE.Node) {
			return errors.New("PVE node inspection is outside target policy")
		}
	case protocol.MethodPVEStorageStatus:
		if !pveInspectionPluginAllowed(target.PVE, request.PVE) || !contains(target.PVE.Nodes, request.PVE.Node) || !contains(target.PVE.Storages, request.PVE.Storage) {
			return errors.New("PVE storage inspection is outside target policy")
		}
	case protocol.MethodPVEGuestStatus:
		if !pveInspectionPluginAllowed(target.PVE, request.PVE) || !contains(target.PVE.Nodes, request.PVE.Node) || !pveGuestAllowed(target.PVE.Guests, request.PVE.GuestType, request.PVE.VMID) {
			return errors.New("PVE guest inspection is outside target policy")
		}
	case protocol.MethodChangePrepare:
		return authorizeOperation(target, request.Operation)
	case protocol.MethodChangeStatus, protocol.MethodChangeApprove, protocol.MethodChangeReject, protocol.MethodChangeRollback,
		protocol.MethodPVERecoveryClearancePrepare, protocol.MethodPVERecoveryClearanceConfirm:
		return nil
	default:
		return errors.New("method is not authorized by target policy")
	}
	return nil
}

func pveInspectionPluginAllowed(policy *PVEPolicy, inspection protocol.PVEInspection) bool {
	return policy != nil && policy.PluginID == inspection.PluginID && policy.PluginDigest == inspection.PluginDigest
}

// AuthorizeOperation reuses the exact root-owned mutation allowlist for an
// executor-side recheck immediately before PVE preconditions and side effects.
func (p *Policy) AuthorizeOperation(targetID string, operation protocol.Operation) error {
	if p == nil {
		return errors.New("target policy is required")
	}
	target, ok := p.Target(targetID)
	if !ok {
		return errors.New("unknown targetId")
	}
	return authorizeOperation(target, operation)
}

// StandingApproval returns the exact persistent authorization that applies to
// an already typed and target-scoped operation. It intentionally reuses the
// mutation allowlist check so a standing scope can never widen the resources
// named by the rest of the Target. Package/artifact installation, source plugin
// registration, workload deployment, and arbitrary break-glass scripts have no
// representable standing scope and always require a fresh human approval.
func (p *Policy) StandingApproval(targetID string, operation protocol.Operation) (basis string, scope string, ok bool) {
	if p == nil || operation == nil {
		return "", "", false
	}
	// A recovery reference consumes an unresolved resource lock. It is a new,
	// separately reviewed change and never inherits a standing grant, even when
	// the typed compensation operation would ordinarily be eligible.
	if protocol.PVERecoveryOfChangeID(operation) != "" {
		return "", "", false
	}
	target, exists := p.Target(targetID)
	if !exists || target.Authorization == nil || authorizeOperation(target, operation) != nil {
		return "", "", false
	}
	scope, eligible := standingScope(operation)
	if !eligible || !contains(target.Authorization.StandingScopes, scope) {
		return "", "", false
	}
	switch value := operation.(type) {
	case *protocol.ServiceAction:
		if value.PluginID != protocol.BaseWorkloadPluginID ||
			value.PluginDigest != target.Authorization.BaseWorkloadDigest {
			return "", "", false
		}
	case *protocol.FileWrite:
		if value.PluginID != protocol.BaseWorkloadPluginID ||
			value.PluginDigest != target.Authorization.BaseWorkloadDigest {
			return "", "", false
		}
	}
	return "standing-policy:" + p.Revision + ":" + scope, scope, true
}

func standingScope(operation protocol.Operation) (string, bool) {
	switch value := operation.(type) {
	case *protocol.PVEGuestAction:
		scope := "pve.guest." + value.Action
		_, ok := allowedStandingScopes[scope]
		return scope, ok
	case *protocol.PackageInstall, *protocol.PluginRegister, *protocol.PluginInstall, *protocol.WorkloadDeploy,
		*protocol.BreakglassScript, *protocol.WorkloadJSONConfigEdit:
		return "", false
	case *protocol.WorkloadServiceAction:
		if value.Action == "reload" || value.Action == "reset-failed" {
			return "", false
		}
		return value.Kind(), true
	default:
		scope := operation.Kind()
		_, ok := allowedStandingScopes[scope]
		return scope, ok
	}
}

func authorizeOperation(target Target, operation protocol.Operation) error {
	switch value := operation.(type) {
	case *protocol.FileWrite:
		if protocol.IsProtectedHostControlPath(value.Path) {
			return errors.New("agent control-plane paths require a dedicated typed operation")
		}
		if err := writablePathWithin(value.Path, target.Changes.WritePaths); err != nil {
			return fmt.Errorf("file write is outside target policy: %w", err)
		}
	case *protocol.ServiceAction:
		if !contains(target.Changes.Units, value.Unit) {
			return errors.New("service change is outside target policy")
		}
	case *protocol.WorkloadServiceAction:
		for _, workload := range target.ServiceWorkloads {
			if workload.PluginID == value.PluginID && workload.PluginDigest == value.PluginDigest &&
				workload.Account == value.Account && workload.Manager == value.Manager &&
				contains(workload.Units, value.Unit) && contains(workload.Operations, value.Action) {
				return nil
			}
		}
		return errors.New("workload service action is outside the digest-bound target policy")
	case *protocol.WorkloadJSONConfigEdit:
		for _, profile := range target.JSONConfigWorkloads {
			if profile.PluginID != value.PluginID || profile.PluginDigest != value.SourceDigest ||
				profile.ProfileKey != value.ProfileKey || !contains(profile.AllowedSelectors, value.SelectorValue) {
				continue
			}
			for _, field := range profile.Fields {
				if field.FieldKey == value.FieldKey && jsonConfigValueAllowed(field, value.Value) {
					return nil
				}
			}
		}
		return errors.New("workload JSON config edit is outside the digest-bound target policy")
	case *protocol.PackageInstall:
		if !contains(target.Changes.Packages, value.Package) {
			return errors.New("package change is outside target policy")
		}
	case *protocol.PluginInstall:
		if !artifactOperationAuthorized(target.Changes.Plugins, "", value.PluginID, value.Version, value.Publisher, value.Digest, value.ArtifactRef) {
			return errors.New("plugin install is outside target policy")
		}
	case *protocol.PluginRegister:
		// Registration is a target-independent administrative mutation whose
		// complete source digest, kind, and requested scopes are bound into the
		// separately signed human approval. The broker still derives the only
		// permitted source path and re-hashes it immediately before activation.
		return nil
	case *protocol.WorkloadDeploy:
		if !artifactOperationAuthorized(target.Changes.Plugins, "managed-workload", value.PluginID, value.Version, value.Publisher, value.Digest, value.ArtifactRef) {
			return errors.New("workload deployment is outside target policy")
		}
	case *protocol.BreakglassScript:
		if target.Account != "root" {
			return errors.New("manual root capsules require a root target")
		}
		return nil
	case *protocol.PVEGuestAction:
		return authorizePVE(target.PVE, value.PluginID, value.PluginDigest, value.Node, value.GuestType, value.VMID, "pve.guest."+value.Action, "", "")
	case *protocol.PVESnapshotCreate:
		return authorizePVE(target.PVE, value.PluginID, value.PluginDigest, value.Node, value.GuestType, value.VMID, value.Kind(), "", "")
	case *protocol.PVESnapshotDelete:
		return authorizePVE(target.PVE, value.PluginID, value.PluginDigest, value.Node, value.GuestType, value.VMID, value.Kind(), value.BackupStorage, "")
	case *protocol.PVESnapshotRollback:
		return authorizePVE(target.PVE, value.PluginID, value.PluginDigest, value.Node, value.GuestType, value.VMID, value.Kind(), value.BackupStorage, "")
	case *protocol.PVEGuestBackup:
		return authorizePVE(target.PVE, value.PluginID, value.PluginDigest, value.Node, value.GuestType, value.VMID, value.Kind(), value.Storage, "")
	case *protocol.PVEGuestRestore:
		backupStorage := strings.SplitN(value.BackupVolume, ":", 2)[0]
		if err := authorizePVE(target.PVE, value.PluginID, value.PluginDigest, value.Node, value.GuestType, value.VMID, value.Kind(), value.Storage, ""); err != nil {
			return err
		}
		if target.PVE == nil || !contains(target.PVE.Storages, backupStorage) {
			return errors.New("PVE restore backup volume is outside target policy")
		}
		return nil
	case *protocol.PVEGuestMigrate:
		return authorizePVE(target.PVE, value.PluginID, value.PluginDigest, value.Node, value.GuestType, value.VMID, value.Kind(), "", value.TargetNode)
	default:
		return errors.New("operation is not authorized by target policy")
	}
	return nil
}

func authorizePVE(policy *PVEPolicy, pluginID, pluginDigest, node, guestType string, vmid int, operation, storage, migrationTarget string) error {
	if policy == nil || policy.PluginID != pluginID || policy.PluginDigest != pluginDigest {
		return errors.New("PVE operation is not bound to the target's approved workload digest")
	}
	if !contains(policy.Nodes, node) || !pveGuestAllowed(policy.Guests, guestType, vmid) || !contains(policy.Operations, operation) {
		return errors.New("PVE operation is outside target policy")
	}
	if storage != "" && !contains(policy.Storages, storage) {
		return errors.New("PVE operation storage is outside target policy")
	}
	if migrationTarget != "" && !contains(policy.MigrationTargets, migrationTarget) {
		return errors.New("PVE migration target is outside target policy")
	}
	return nil
}

func pveGuestAllowed(guests []PVEGuestPolicy, guestType string, vmid int) bool {
	for _, guest := range guests {
		if guest.GuestType == guestType && guest.VMID == vmid {
			return true
		}
	}
	return false
}

func artifactOperationAuthorized(artifacts []ArtifactPolicy, kind, id, version, publisher, digest, artifactRef string) bool {
	if artifactRef != "builtin:"+digest {
		return false
	}
	for _, artifact := range artifacts {
		if (kind == "" || artifact.Kind == kind) && artifact.ID == id && artifact.Version == version && artifact.Publisher == publisher && artifact.Digest == digest {
			return true
		}
	}
	return false
}

func validatePaths(values []string, label string) error {
	return validateValues(values, func(value string) bool {
		return filepath.IsAbs(value) && filepath.Clean(value) == value && value != "/" && len(value) <= 4096 && !strings.ContainsAny(value, "\x00\n\r")
	}, label)
}

func validateValues(values []string, valid func(string) bool, label string) error {
	if len(values) > 256 {
		return fmt.Errorf("%s allowlist is too large", label)
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !valid(value) {
			return fmt.Errorf("invalid %s %q", label, value)
		}
		if _, ok := seen[value]; ok {
			return fmt.Errorf("duplicate %s %q", label, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func pathWithin(path string, roots []string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return errors.New("path must be a clean absolute path below root")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}
	return resolvedWithin(resolved, roots)
}

func exactPathAllowed(path string, allowedPaths []string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return errors.New("path must be a clean absolute path below root")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}
	for _, allowed := range allowedPaths {
		resolvedAllowed, allowedErr := filepath.EvalSymlinks(allowed)
		if allowedErr == nil && resolved == resolvedAllowed {
			return nil
		}
	}
	return errors.New("file reads require an exact allowed path")
}

func resolvedWithin(resolved string, roots []string) error {
	for _, root := range roots {
		resolvedRoot, rootErr := filepath.EvalSymlinks(root)
		if rootErr != nil {
			continue
		}
		relative, relErr := filepath.Rel(resolvedRoot, resolved)
		if relErr == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return nil
		}
	}
	return errors.New("path does not resolve beneath an allowed root")
}

func writablePathWithin(path string, roots []string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return errors.New("path must be a clean absolute path below root")
	}
	probe := path
	for {
		if _, err := os.Lstat(probe); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect path: %w", err)
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return errors.New("path has no existing ancestor")
		}
		probe = parent
	}
	resolved, err := filepath.EvalSymlinks(probe)
	if err != nil {
		return fmt.Errorf("resolve path ancestor: %w", err)
	}
	relativeTail, err := filepath.Rel(probe, path)
	if err != nil {
		return err
	}
	resolvedTarget := filepath.Clean(filepath.Join(resolved, relativeTail))
	if protocol.IsProtectedHostControlPath(resolvedTarget) {
		return errors.New("resolved path enters the agent control plane")
	}
	return resolvedWithin(resolvedTarget, roots)
}

func contains(values []string, value string) bool {
	index := sort.SearchStrings(values, value)
	return index < len(values) && values[index] == value
}
