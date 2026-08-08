package roothelper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
	"github.com/KiritoKing/pi-ops-agent/internal/targetpolicy"
)

const (
	jsonConfigHelperPath = "/usr/lib/ops-agent/agentd-json-config-helper"
	jsonConfigStageMount = "/run/agentd-json-config-stage"
	jsonConfigProofLimit = 32 * 1024
)

var jsonNumberPattern = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$`)
var jsonDirectoryIdentityPattern = regexp.MustCompile(`^dev=[0-9]+;ino=[0-9]+;mode=0[0-7]{3};uid=[0-9]+;gid=[0-9]+$`)

// JSONConfigProofRunner keeps helper stdout separate from systemd-run stderr.
// A failed transient unit may still emit an authoritative CAS proof on stdout;
// mixing stderr into it would make the root broker misclassify a known restore
// as an unknown mutation outcome.
type JSONConfigProofRunner interface {
	RunJSONConfig(context.Context, string, ...string) ([]byte, error)
}

type ExecJSONConfigProofRunner struct{}

func (ExecJSONConfigProofRunner) RunJSONConfig(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C"}
	var stdout, stderr limitedBuffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	if stdout.truncated {
		return append([]byte(nil), stdout.payload...), errors.New("JSON config helper proof exceeded its output limit")
	}
	payload := append([]byte(nil), stdout.payload...)
	if err != nil {
		// Deliberately do not return stderr: it is not an authoritative proof and
		// may contain host paths or unbounded service-manager diagnostics.
		return payload, fmt.Errorf("transient JSON config helper unit failed: %w", err)
	}
	return payload, nil
}

type jsonConfigFileMetadata struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Dev    uint64 `json:"dev"`
	Ino    uint64 `json:"ino"`
	Mode   uint32 `json:"mode"`
}

type jsonConfigSafeValue struct {
	Kind         string  `json:"kind"`
	StringValue  *string `json:"stringValue,omitempty"`
	BooleanValue *bool   `json:"booleanValue,omitempty"`
	NumberValue  *string `json:"numberValue,omitempty"`
}

type jsonConfigInspectProof struct {
	Version   int                    `json:"version"`
	Operation string                 `json:"operation"`
	Source    jsonConfigFileMetadata `json:"source"`
	Selected  jsonConfigSafeValue    `json:"selected"`
}

type jsonConfigSnapshotProof struct {
	Version   int                    `json:"version"`
	Operation string                 `json:"operation"`
	Source    jsonConfigFileMetadata `json:"source"`
	Snapshot  jsonConfigFileMetadata `json:"snapshot"`
	Selected  jsonConfigSafeValue    `json:"selected"`
}

type jsonConfigMutateProof struct {
	Version              int                    `json:"version"`
	Operation            string                 `json:"operation"`
	Source               jsonConfigFileMetadata `json:"source"`
	Output               jsonConfigFileMetadata `json:"output"`
	Before               jsonConfigSafeValue    `json:"before"`
	After                jsonConfigSafeValue    `json:"after"`
	BeforeDigest         string                 `json:"beforeDigest"`
	AfterDigest          string                 `json:"afterDigest"`
	WholeDocumentRewrite bool                   `json:"wholeDocumentRewrite"`
}

type jsonConfigCommitProof struct {
	Version           int                     `json:"version"`
	Operation         string                  `json:"operation"`
	Outcome           string                  `json:"outcome"`
	MutationAttempted bool                    `json:"mutationAttempted"`
	ExchangeRestored  bool                    `json:"exchangeRestored"`
	ResidualState     string                  `json:"residualState"`
	CASMethod         string                  `json:"casMethod"`
	Current           *jsonConfigFileMetadata `json:"current,omitempty"`
}

type jsonConfigDirectoryMetadata struct {
	Dev  uint64 `json:"dev"`
	Ino  uint64 `json:"ino"`
	Mode uint32 `json:"mode"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
}

type jsonConfigDirectoryProof struct {
	Version      int                         `json:"version"`
	Operation    string                      `json:"operation"`
	Root         jsonConfigDirectoryMetadata `json:"root"`
	Directory    jsonConfigDirectoryMetadata `json:"directory"`
	ResidualRisk string                      `json:"residualRisk"`
}

type jsonConfigRollback struct {
	Version               int                 `json:"version"`
	PluginID              string              `json:"pluginId"`
	SourceDigest          string              `json:"sourceDigest"`
	ProfileKey            string              `json:"profileKey"`
	TargetAccount         string              `json:"targetAccount"`
	RunAsUID              uint32              `json:"runAsUid"`
	RunAsHome             string              `json:"runAsHome"`
	RelativeConfig        string              `json:"relativeConfig"`
	SelectorKey           string              `json:"selectorKey"`
	SelectorValue         string              `json:"selectorValue"`
	FieldKey              string              `json:"fieldKey"`
	JSONField             string              `json:"jsonField"`
	SealedRoot            string              `json:"sealedRoot"`
	BeforeDigest          string              `json:"beforeDigest"`
	AfterDigest           string              `json:"afterDigest"`
	Before                jsonConfigSafeValue `json:"before"`
	After                 jsonConfigSafeValue `json:"after"`
	WholeDocumentRewrite  bool                `json:"wholeDocumentRewrite"`
	DirectoryRoot         string              `json:"directoryRoot,omitempty"`
	DirectoryPath         string              `json:"directoryPath,omitempty"`
	DirectoryRootIdentity string              `json:"directoryRootIdentity,omitempty"`
	DirectoryIdentity     string              `json:"directoryIdentity,omitempty"`
	DirectoryResidualRisk string              `json:"directoryResidualRisk,omitempty"`
}

type jsonConfigKnownNoMutationError struct{ err error }

func (e jsonConfigKnownNoMutationError) Error() string           { return e.err.Error() }
func (e jsonConfigKnownNoMutationError) Unwrap() error           { return e.err }
func (e jsonConfigKnownNoMutationError) NoMutationStarted() bool { return true }

type jsonConfigUncertainError struct{ err error }

func (e jsonConfigUncertainError) Error() string                  { return e.err.Error() }
func (e jsonConfigUncertainError) Unwrap() error                  { return e.err }
func (e jsonConfigUncertainError) MutationOutcomeUncertain() bool { return true }

func knownJSONConfigNoMutation(message string) error {
	return jsonConfigKnownNoMutationError{err: errors.New(message)}
}

func uncertainJSONConfig(message string) error {
	return jsonConfigUncertainError{err: errors.New(message)}
}

// jsonConfigExchangeRestoredProof is an internal classification marker. An
// exchanged pathname was put back, but that alone does not prove the restored
// bytes are the approved before state: a concurrent writer may have changed or
// replaced the displaced inode before the exchange. The broker must perform a
// fresh typed inspection before choosing a terminal state.
type jsonConfigExchangeRestoredProof struct{ currentDigest string }

func (e jsonConfigExchangeRestoredProof) Error() string {
	return "JSON config CAS exchange was rejected and restored; final content requires re-inspection"
}

type jsonConfigRestoredNoMutationError struct{ err error }

func (e jsonConfigRestoredNoMutationError) Error() string           { return e.err.Error() }
func (e jsonConfigRestoredNoMutationError) Unwrap() error           { return e.err }
func (e jsonConfigRestoredNoMutationError) NoMutationStarted() bool { return true }
func (e jsonConfigRestoredNoMutationError) MutationAttempted() bool { return true }
func (e jsonConfigRestoredNoMutationError) ExchangeRestored() bool  { return true }

type jsonConfigRestoredUncertainError struct{ err error }

func (e jsonConfigRestoredUncertainError) Error() string                  { return e.err.Error() }
func (e jsonConfigRestoredUncertainError) Unwrap() error                  { return e.err }
func (e jsonConfigRestoredUncertainError) MutationOutcomeUncertain() bool { return true }
func (e jsonConfigRestoredUncertainError) MutationAttempted() bool        { return true }
func (e jsonConfigRestoredUncertainError) ExchangeRestored() bool         { return true }

func restoredJSONConfigNoMutation(message string) error {
	return jsonConfigRestoredNoMutationError{err: errors.New(message)}
}

func restoredJSONConfigUncertain(message string) error {
	return jsonConfigRestoredUncertainError{err: errors.New(message)}
}

func (e *OSExecutor) resolveWorkloadJSONConfig(
	scope ExecutionScope,
	operation *protocol.WorkloadJSONConfigEdit,
) (targetpolicy.JSONConfigWorkloadPolicy, targetpolicy.JSONConfigFieldPolicy, error) {
	if e.Policy == nil || scope.PolicyRevision != e.Policy.Revision {
		return targetpolicy.JSONConfigWorkloadPolicy{}, targetpolicy.JSONConfigFieldPolicy{},
			errors.New("workload JSON config edit requires the active root-owned target policy")
	}
	profile, field, ok := e.Policy.JSONConfigWorkload(scope.TargetID, *operation)
	if !ok {
		return targetpolicy.JSONConfigWorkloadPolicy{}, targetpolicy.JSONConfigFieldPolicy{},
			errors.New("workload JSON config edit is outside the exact digest-bound target policy")
	}
	uid, home, err := e.lookupWorkloadAccount(profile.TargetAccount)
	if err != nil {
		return targetpolicy.JSONConfigWorkloadPolicy{}, targetpolicy.JSONConfigFieldPolicy{}, err
	}
	if uint32(uid) != profile.RunAsUID || home != profile.RunAsHome {
		return targetpolicy.JSONConfigWorkloadPolicy{}, targetpolicy.JSONConfigFieldPolicy{},
			errors.New("workload JSON config account UID or home no longer matches root-owned policy")
	}
	configPath := filepath.Join(profile.RunAsHome, profile.RelativeConfig)
	relative, err := filepath.Rel(profile.RunAsHome, configPath)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return targetpolicy.JSONConfigWorkloadPolicy{}, targetpolicy.JSONConfigFieldPolicy{},
			errors.New("workload JSON config policy path escapes the approved home")
	}
	return profile, field, nil
}

func (e *OSExecutor) runWorkloadJSONConfigHelper(
	ctx context.Context,
	profile targetpolicy.JSONConfigWorkloadPolicy,
	hostStageRoot string,
	configWritable bool,
	stageWritable bool,
	extraReadOnly []string,
	helperArguments ...string,
) ([]byte, error) {
	systemdRun := e.SystemdRunPath
	if systemdRun == "" {
		systemdRun = "/usr/bin/systemd-run"
	}
	if !filepath.IsAbs(systemdRun) || filepath.Clean(systemdRun) != systemdRun {
		return nil, errors.New("systemd-run path must be a clean absolute path")
	}
	configPath := filepath.Join(profile.RunAsHome, profile.RelativeConfig)
	configParent := filepath.Dir(configPath)
	if configParent == "/" || !filepath.IsAbs(configParent) || filepath.Clean(configParent) != configParent {
		return nil, errors.New("JSON config parent is unsafe")
	}
	arguments := []string{
		"--quiet", "--wait", "--pipe", "--collect", "--service-type=exec",
		"--uid=" + strconv.FormatUint(uint64(profile.RunAsUID), 10),
		"--working-directory=/",
		"--property=NoNewPrivileges=yes",
		"--property=PrivateTmp=yes",
		"--property=PrivateDevices=yes",
		"--property=PrivateNetwork=yes",
		"--property=ProtectSystem=strict",
		"--property=ProtectHome=tmpfs",
		"--property=ProtectControlGroups=yes",
		"--property=ProtectKernelTunables=yes",
		"--property=ProtectKernelModules=yes",
		"--property=ProtectKernelLogs=yes",
		"--property=ProtectClock=yes",
		"--property=ProtectHostname=yes",
		"--property=ProtectProc=invisible",
		"--property=ProcSubset=pid",
		"--property=RestrictNamespaces=yes",
		"--property=RestrictRealtime=yes",
		"--property=RestrictSUIDSGID=yes",
		"--property=LockPersonality=yes",
		"--property=MemoryDenyWriteExecute=yes",
		"--property=CapabilityBoundingSet=",
		"--property=AmbientCapabilities=",
		"--property=RestrictAddressFamilies=AF_UNIX",
		"--property=SystemCallArchitectures=native",
		"--property=UMask=0077",
		"--property=RuntimeMaxSec=30s",
		"--property=KillMode=control-group",
		"--property=SendSIGKILL=yes",
		"--property=TimeoutStopSec=5s",
	}
	if configWritable {
		arguments = append(arguments,
			"--property=BindPaths="+configParent,
			"--property=ReadWritePaths="+configParent,
		)
	} else {
		arguments = append(arguments, "--property=BindReadOnlyPaths="+configParent)
	}
	if hostStageRoot != "" {
		if !filepath.IsAbs(hostStageRoot) || filepath.Clean(hostStageRoot) != hostStageRoot ||
			strings.ContainsAny(hostStageRoot, ":\x00\r\n\t ") {
			return nil, errors.New("JSON config transaction stage path is unsafe")
		}
		binding := hostStageRoot + ":" + jsonConfigStageMount
		if stageWritable {
			arguments = append(arguments,
				"--property=BindPaths="+binding,
				"--property=ReadWritePaths="+jsonConfigStageMount,
			)
		} else {
			arguments = append(arguments, "--property=BindReadOnlyPaths="+binding)
		}
	}
	for _, path := range extraReadOnly {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" ||
			strings.ContainsAny(path, ":\x00\r\n\t ") {
			return nil, errors.New("JSON config helper read-only path is unsafe")
		}
		arguments = append(arguments, "--property=BindReadOnlyPaths="+path)
	}
	arguments = append(arguments, "--", jsonConfigHelperPath)
	arguments = append(arguments, helperArguments...)
	runner := e.JSONConfigRunner
	if runner == nil {
		runner = ExecJSONConfigProofRunner{}
	}
	return runner.RunJSONConfig(ctx, systemdRun, arguments...)
}

func jsonConfigSelectionArguments(
	profile targetpolicy.JSONConfigWorkloadPolicy,
	field targetpolicy.JSONConfigFieldPolicy,
	operation *protocol.WorkloadJSONConfigEdit,
) []string {
	return []string{
		"--home", profile.RunAsHome,
		"--relative", profile.RelativeConfig,
		"--selector-key", profile.SelectorKey,
		"--selector-value", operation.SelectorValue,
		"--field", field.JSONField,
	}
}

func jsonConfigMutateValueArguments(value protocol.WorkloadJSONConfigValue) []string {
	arguments := []string{"--value-kind", value.Kind}
	switch value.Kind {
	case "string":
		arguments = append(arguments, "--string-value", *value.StringValue)
	case "boolean":
		arguments = append(arguments, "--boolean-value", strconv.FormatBool(*value.BooleanValue))
	}
	return arguments
}

func (e *OSExecutor) inspectWorkloadJSONConfig(
	ctx context.Context,
	profile targetpolicy.JSONConfigWorkloadPolicy,
	field targetpolicy.JSONConfigFieldPolicy,
	operation *protocol.WorkloadJSONConfigEdit,
) (jsonConfigInspectProof, error) {
	arguments := append([]string{"inspect"}, jsonConfigSelectionArguments(profile, field, operation)...)
	payload, runErr := e.runWorkloadJSONConfigHelper(ctx, profile, "", false, false, nil, arguments...)
	if runErr != nil {
		return jsonConfigInspectProof{}, errors.New("read-only JSON config inspection failed")
	}
	var proof jsonConfigInspectProof
	if err := decodeJSONConfigProof(payload, &proof); err != nil {
		return jsonConfigInspectProof{}, err
	}
	if proof.Version != 1 || proof.Operation != "inspect" || proof.Source.validate() != nil || proof.Selected.validate() != nil {
		return jsonConfigInspectProof{}, errors.New("JSON config inspection returned an invalid proof")
	}
	return proof, nil
}

func (e *OSExecutor) inspectWorkloadJSONConfigDirectory(
	ctx context.Context,
	profile targetpolicy.JSONConfigWorkloadPolicy,
	root string,
	path string,
) (jsonConfigDirectoryProof, error) {
	payload, runErr := e.runWorkloadJSONConfigHelper(
		ctx, profile, "", false, false, []string{root},
		"inspect-directory", "--root", root, "--path", path,
	)
	if runErr != nil {
		return jsonConfigDirectoryProof{}, errors.New("read-only JSON config directory inspection failed")
	}
	var proof jsonConfigDirectoryProof
	if err := decodeJSONConfigProof(payload, &proof); err != nil {
		return jsonConfigDirectoryProof{}, err
	}
	if proof.Version != 1 || proof.Operation != "inspect-directory" ||
		proof.ResidualRisk != "pathname_may_be_replaced_after_verification" ||
		proof.Root.validate() != nil || proof.Directory.validate() != nil {
		return jsonConfigDirectoryProof{}, errors.New("JSON config directory inspection returned an invalid proof")
	}
	return proof, nil
}

func (metadata jsonConfigDirectoryMetadata) validate() error {
	if metadata.Dev == 0 || metadata.Ino == 0 || metadata.Mode > 0o7777 || metadata.Mode&0o7000 != 0 {
		return errors.New("JSON config directory proof contains invalid metadata")
	}
	return nil
}

func (metadata jsonConfigDirectoryMetadata) identity() string {
	return fmt.Sprintf("dev=%d;ino=%d;mode=%04o;uid=%d;gid=%d", metadata.Dev, metadata.Ino, metadata.Mode, metadata.UID, metadata.GID)
}

func jsonConfigDirectoryRoot(field targetpolicy.JSONConfigFieldPolicy, path string) (string, bool) {
	selected := ""
	for _, root := range field.PathRoots {
		relative, err := filepath.Rel(root, path)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && len(root) > len(selected) {
			selected = root
		}
	}
	return selected, selected != ""
}

func (e *OSExecutor) planJSONConfigDirectory(
	ctx context.Context,
	profile targetpolicy.JSONConfigWorkloadPolicy,
	field targetpolicy.JSONConfigFieldPolicy,
	operation *protocol.WorkloadJSONConfigEdit,
) ([]protocol.ApprovalPlanField, error) {
	if field.StringConstraint != "absolute-path/v1" || operation.Value.Kind != "string" {
		return nil, nil
	}
	path := *operation.Value.StringValue
	root, ok := jsonConfigDirectoryRoot(field, path)
	if !ok {
		return nil, errors.New("JSON config working directory is outside root-owned policy roots")
	}
	proof, err := e.inspectWorkloadJSONConfigDirectory(ctx, profile, root, path)
	if err != nil {
		return nil, err
	}
	return []protocol.ApprovalPlanField{
		{Name: "workingDirectoryRoot", Value: root},
		{Name: "workingDirectoryPath", Value: path},
		{Name: "workingDirectoryRootIdentity", Value: proof.Root.identity()},
		{Name: "workingDirectoryIdentity", Value: proof.Directory.identity()},
		{Name: "workingDirectoryResidualRisk", Value: proof.ResidualRisk},
	}, nil
}

func (e *OSExecutor) snapshotWorkloadJSONConfig(
	ctx context.Context,
	profile targetpolicy.JSONConfigWorkloadPolicy,
	field targetpolicy.JSONConfigFieldPolicy,
	operation *protocol.WorkloadJSONConfigEdit,
	hostStageRoot string,
) (jsonConfigSnapshotProof, error) {
	arguments := append([]string{"snapshot"}, jsonConfigSelectionArguments(profile, field, operation)...)
	arguments = append(arguments, "--stage-root", jsonConfigStageMount, "--output", filepath.Join(jsonConfigStageMount, "before.json"))
	payload, runErr := e.runWorkloadJSONConfigHelper(ctx, profile, hostStageRoot, false, true, nil, arguments...)
	if runErr != nil {
		return jsonConfigSnapshotProof{}, errors.New("JSON config snapshot helper failed")
	}
	var proof jsonConfigSnapshotProof
	if err := decodeJSONConfigProof(payload, &proof); err != nil {
		return jsonConfigSnapshotProof{}, err
	}
	if proof.Version != 1 || proof.Operation != "snapshot" || proof.Source.validate() != nil ||
		proof.Snapshot.validate() != nil || proof.Selected.validate() != nil ||
		proof.Source.SHA256 != proof.Snapshot.SHA256 {
		return jsonConfigSnapshotProof{}, errors.New("JSON config snapshot returned an invalid proof")
	}
	return proof, nil
}

func (e *OSExecutor) mutateWorkloadJSONConfig(
	ctx context.Context,
	profile targetpolicy.JSONConfigWorkloadPolicy,
	field targetpolicy.JSONConfigFieldPolicy,
	operation *protocol.WorkloadJSONConfigEdit,
	hostStageRoot string,
) (jsonConfigMutateProof, error) {
	arguments := append([]string{"mutate"}, jsonConfigSelectionArguments(profile, field, operation)...)
	arguments = append(arguments, "--stage-root", jsonConfigStageMount, "--output", filepath.Join(jsonConfigStageMount, "after.json"))
	arguments = append(arguments, jsonConfigMutateValueArguments(operation.Value)...)
	payload, runErr := e.runWorkloadJSONConfigHelper(ctx, profile, hostStageRoot, false, true, nil, arguments...)
	if runErr != nil {
		return jsonConfigMutateProof{}, errors.New("JSON config staged mutation helper failed")
	}
	var proof jsonConfigMutateProof
	if err := decodeJSONConfigProof(payload, &proof); err != nil {
		return jsonConfigMutateProof{}, err
	}
	if proof.Version != 1 || proof.Operation != "mutate" || !proof.WholeDocumentRewrite ||
		proof.Source.validate() != nil || proof.Output.validate() != nil || proof.Before.validate() != nil || proof.After.validate() != nil ||
		proof.BeforeDigest != proof.Source.SHA256 || proof.AfterDigest != proof.Output.SHA256 ||
		proof.BeforeDigest == proof.AfterDigest || !proof.After.matchesRequested(operation.Value) {
		return jsonConfigMutateProof{}, errors.New("JSON config staged mutation returned an invalid proof")
	}
	return proof, nil
}

func (metadata jsonConfigFileMetadata) validate() error {
	if !protocol.ValidDigest(metadata.SHA256) || metadata.Size < 1 || metadata.Size > 1024*1024 ||
		metadata.Dev == 0 || metadata.Ino == 0 || (metadata.Mode != 0o400 && metadata.Mode != 0o600) {
		return errors.New("JSON config proof contains invalid file metadata")
	}
	return nil
}

func (value jsonConfigSafeValue) validate() error {
	switch value.Kind {
	case "absent", "null":
		if value.StringValue != nil || value.BooleanValue != nil || value.NumberValue != nil {
			return errors.New("JSON config proof scalar tag is confused")
		}
	case "string":
		if value.StringValue == nil || value.BooleanValue != nil || value.NumberValue != nil ||
			!validJSONConfigProofText(*value.StringValue, 512) {
			return errors.New("JSON config proof contains an unsafe string")
		}
	case "boolean":
		if value.StringValue != nil || value.BooleanValue == nil || value.NumberValue != nil {
			return errors.New("JSON config proof boolean tag is confused")
		}
	case "number":
		if value.StringValue != nil || value.BooleanValue != nil || value.NumberValue == nil ||
			len(*value.NumberValue) == 0 || len(*value.NumberValue) > 128 || !jsonNumberPattern.MatchString(*value.NumberValue) {
			return errors.New("JSON config proof number tag is confused")
		}
	default:
		return errors.New("JSON config proof contains an unsupported scalar tag")
	}
	return nil
}

func (value jsonConfigSafeValue) display() string {
	switch value.Kind {
	case "absent":
		return "<absent>"
	case "null":
		return "<null>"
	case "string":
		return *value.StringValue
	case "boolean":
		return strconv.FormatBool(*value.BooleanValue)
	case "number":
		return *value.NumberValue
	default:
		return "<invalid>"
	}
}

func (value jsonConfigSafeValue) equal(other jsonConfigSafeValue) bool {
	if value.Kind != other.Kind {
		return false
	}
	switch value.Kind {
	case "absent", "null":
		return true
	case "string":
		return value.StringValue != nil && other.StringValue != nil && *value.StringValue == *other.StringValue
	case "boolean":
		return value.BooleanValue != nil && other.BooleanValue != nil && *value.BooleanValue == *other.BooleanValue
	case "number":
		return value.NumberValue != nil && other.NumberValue != nil && *value.NumberValue == *other.NumberValue
	default:
		return false
	}
}

func (value jsonConfigSafeValue) matchesRequested(requested protocol.WorkloadJSONConfigValue) bool {
	switch requested.Kind {
	case "clear":
		return value.Kind == "absent"
	case "string":
		return value.Kind == "string" && value.StringValue != nil && *value.StringValue == *requested.StringValue
	case "boolean":
		return value.Kind == "boolean" && value.BooleanValue != nil && *value.BooleanValue == *requested.BooleanValue
	default:
		return false
	}
}

func (value jsonConfigSafeValue) isRequestedNoop(requested protocol.WorkloadJSONConfigValue) bool {
	return value.matchesRequested(requested)
}

func validJSONConfigProofText(value string, maximum int) bool {
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

func decodeJSONConfigProof(payload []byte, destination interface{}) error {
	if len(payload) == 0 || len(payload) > jsonConfigProofLimit {
		return errors.New("JSON config helper proof is empty or oversized")
	}
	if err := rejectDuplicateJSONConfigProofKeys(payload); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("decode strict JSON config helper proof")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON config helper proof has trailing data")
	}
	return nil
}

func rejectDuplicateJSONConfigProofKeys(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return errors.New("decode JSON config proof token")
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				key, keyOK := keyToken.(string)
				if keyErr != nil || !keyOK {
					return errors.New("decode JSON config proof object key")
				}
				if _, duplicate := seen[key]; duplicate {
					return errors.New("JSON config helper proof contains a duplicate field")
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			closing, closeErr := decoder.Token()
			if closeErr != nil || closing != json.Delim('}') {
				return errors.New("JSON config helper proof object is not closed")
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			closing, closeErr := decoder.Token()
			if closeErr != nil || closing != json.Delim(']') {
				return errors.New("JSON config helper proof array is not closed")
			}
		default:
			return errors.New("JSON config helper proof has an unexpected delimiter")
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON config helper proof has a trailing token")
	}
	return nil
}

func (e *OSExecutor) planWorkloadJSONConfig(
	ctx context.Context,
	scope ExecutionScope,
	operation *protocol.WorkloadJSONConfigEdit,
) (OperationPrecondition, error) {
	profile, field, err := e.resolveWorkloadJSONConfig(scope, operation)
	if err != nil {
		return OperationPrecondition{}, err
	}
	proof, err := e.inspectWorkloadJSONConfig(ctx, profile, field, operation)
	if err != nil {
		return OperationPrecondition{}, err
	}
	if proof.Selected.isRequestedNoop(operation.Value) {
		return OperationPrecondition{}, errors.New("requested JSON config value is already current")
	}
	afterKind := operation.Value.Kind
	if afterKind == "clear" {
		afterKind = "absent"
	}
	fields := []protocol.ApprovalPlanField{
		{Name: "targetAccount", Value: profile.TargetAccount},
		{Name: "accountUid", Value: strconv.FormatUint(uint64(profile.RunAsUID), 10)},
		{Name: "configPath", Value: filepath.Join(profile.RunAsHome, profile.RelativeConfig)},
		{Name: "profileKey", Value: profile.ProfileKey},
		{Name: "selectorKey", Value: profile.SelectorKey},
		{Name: "selectorValue", Value: operation.SelectorValue},
		{Name: "fieldKey", Value: operation.FieldKey},
		{Name: "jsonField", Value: field.JSONField},
		{Name: "beforeKind", Value: proof.Selected.Kind},
		{Name: "before", Value: proof.Selected.display()},
		{Name: "afterKind", Value: afterKind},
		{Name: "after", Value: operation.Value.SafeText()},
		{Name: "configDigest", Value: proof.Source.SHA256},
		{Name: "configIdentity", Value: fmt.Sprintf("dev=%d;ino=%d;mode=%04o;bytes=%d", proof.Source.Dev, proof.Source.Ino, proof.Source.Mode, proof.Source.Size)},
		{Name: "documentRewrite", Value: "whole-document-semantic-rewrite"},
		{Name: "sameUidRaceBoundary", Value: "digest-cas-detects-but-cannot-prevent-later-same-uid-replacement"},
	}
	directoryFields, err := e.planJSONConfigDirectory(ctx, profile, field, operation)
	if err != nil {
		return OperationPrecondition{}, err
	}
	fields = append(fields, directoryFields...)
	digest, err := protocol.ApprovalPreconditionDigest(fields)
	if err != nil {
		return OperationPrecondition{}, err
	}
	return OperationPrecondition{Digest: digest, Fields: fields}, nil
}

func (e *OSExecutor) prepareWorkloadJSONConfig(
	ctx context.Context,
	scope ExecutionScope,
	operation *protocol.WorkloadJSONConfigEdit,
) (result ExecutionResult, returnErr error) {
	if scope.PreconditionDigest == "" {
		return ExecutionResult{}, errors.New("workload JSON config edit is missing its approved precondition digest")
	}
	profile, field, err := e.resolveWorkloadJSONConfig(scope, operation)
	if err != nil {
		return ExecutionResult{}, err
	}
	planned, err := e.planWorkloadJSONConfig(ctx, scope, operation)
	if err != nil {
		return ExecutionResult{}, err
	}
	if planned.Digest != scope.PreconditionDigest {
		return ExecutionResult{}, errors.New("JSON config preconditions changed after approval")
	}
	approvedDigest := approvalPreconditionValue(planned.Fields, "configDigest")
	scratchRoot, err := e.createJSONConfigTargetStage(scope, profile.RunAsUID, "json-config-preparing", false)
	if err != nil {
		return ExecutionResult{}, err
	}
	sealedRoot, err := e.createJSONConfigSealedRoot(scope)
	if err != nil {
		_ = os.RemoveAll(scratchRoot)
		return ExecutionResult{}, err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(scratchRoot)
			_ = os.RemoveAll(sealedRoot)
		}
	}()
	snapshot, err := e.snapshotWorkloadJSONConfig(ctx, profile, field, operation, scratchRoot)
	if err != nil {
		return ExecutionResult{}, err
	}
	if snapshot.Source.SHA256 != approvedDigest || metadataIdentity(snapshot.Source) != approvalPreconditionValue(planned.Fields, "configIdentity") ||
		!snapshot.Selected.equal(jsonConfigSelectionFromPrecondition(planned.Fields)) {
		return ExecutionResult{}, errors.New("JSON config changed between approved inspection and snapshot")
	}
	mutation, err := e.mutateWorkloadJSONConfig(ctx, profile, field, operation, scratchRoot)
	if err != nil {
		return ExecutionResult{}, err
	}
	if mutation.Source.SHA256 != snapshot.Source.SHA256 || !mutation.Before.equal(snapshot.Selected) {
		return ExecutionResult{}, errors.New("JSON config changed while preparing the staged mutation")
	}
	if err := e.sealJSONConfigDocuments(
		scratchRoot, sealedRoot, profile.RunAsUID, mutation.BeforeDigest, mutation.AfterDigest,
	); err != nil {
		return ExecutionResult{}, err
	}
	if err := os.RemoveAll(scratchRoot); err != nil {
		return ExecutionResult{}, errors.New("remove target-owned JSON config preparation scratch")
	}
	rollback := jsonConfigRollback{
		Version: 1, PluginID: operation.PluginID, SourceDigest: operation.SourceDigest,
		ProfileKey: operation.ProfileKey, TargetAccount: profile.TargetAccount,
		RunAsUID: profile.RunAsUID, RunAsHome: profile.RunAsHome, RelativeConfig: profile.RelativeConfig,
		SelectorKey: profile.SelectorKey, SelectorValue: operation.SelectorValue,
		FieldKey: operation.FieldKey, JSONField: field.JSONField, SealedRoot: sealedRoot,
		BeforeDigest: mutation.BeforeDigest, AfterDigest: mutation.AfterDigest,
		Before: mutation.Before, After: mutation.After, WholeDocumentRewrite: true,
		DirectoryRoot:         approvalPreconditionValue(planned.Fields, "workingDirectoryRoot"),
		DirectoryPath:         approvalPreconditionValue(planned.Fields, "workingDirectoryPath"),
		DirectoryRootIdentity: approvalPreconditionValue(planned.Fields, "workingDirectoryRootIdentity"),
		DirectoryIdentity:     approvalPreconditionValue(planned.Fields, "workingDirectoryIdentity"),
		DirectoryResidualRisk: approvalPreconditionValue(planned.Fields, "workingDirectoryResidualRisk"),
	}
	rollbackData, err := json.Marshal(rollback)
	if err != nil {
		return ExecutionResult{}, errors.New("encode JSON config rollback metadata")
	}
	complete = true
	return ExecutionResult{
		BackupRefs: []string{
			"json-config:before:" + rollback.BeforeDigest,
			"json-config:after:" + rollback.AfterDigest,
		},
		RollbackData: rollbackData, RollbackAvailable: true,
	}, nil
}

func metadataIdentity(metadata jsonConfigFileMetadata) string {
	return fmt.Sprintf("dev=%d;ino=%d;mode=%04o;bytes=%d", metadata.Dev, metadata.Ino, metadata.Mode, metadata.Size)
}

func approvalPreconditionValue(fields []protocol.ApprovalPlanField, name string) string {
	for _, field := range fields {
		if field.Name == name {
			return field.Value
		}
	}
	return ""
}

func jsonConfigSelectionFromPrecondition(fields []protocol.ApprovalPlanField) jsonConfigSafeValue {
	kind := approvalPreconditionValue(fields, "beforeKind")
	value := approvalPreconditionValue(fields, "before")
	result := jsonConfigSafeValue{Kind: kind}
	switch kind {
	case "string":
		result.StringValue = &value
	case "boolean":
		parsed := value == "true"
		result.BooleanValue = &parsed
	case "number":
		result.NumberValue = &value
	}
	return result
}

func (e *OSExecutor) jsonConfigChangeDirectory(scope ExecutionScope) (string, error) {
	if !filepath.IsAbs(e.StateDir) || filepath.Clean(e.StateDir) != e.StateDir || e.StateDir == "/" ||
		strings.ContainsAny(e.StateDir, ":\x00\r\n\t ") {
		return "", errors.New("root broker state directory is unsafe for a JSON config transaction")
	}
	if scope.ChangeID == "" || strings.ContainsAny(scope.ChangeID, "/\\\x00\r\n") {
		return "", errors.New("JSON config transaction has an invalid change identity")
	}
	changeDirectory := filepath.Join(e.StateDir, "changes", scope.ChangeID)
	if err := os.MkdirAll(changeDirectory, 0o700); err != nil {
		return "", errors.New("create JSON config change directory")
	}
	return changeDirectory, nil
}

func (e *OSExecutor) createJSONConfigTargetStage(scope ExecutionScope, uid uint32, name string, unique bool) (string, error) {
	changeDirectory, err := e.jsonConfigChangeDirectory(scope)
	if err != nil {
		return "", err
	}
	var stageRoot string
	if unique {
		stageRoot, err = os.MkdirTemp(changeDirectory, name+"-")
	} else {
		stageRoot = filepath.Join(changeDirectory, name)
		err = os.Mkdir(stageRoot, 0o700)
	}
	if err != nil {
		return "", errors.New("create exclusive JSON config transaction stage")
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(stageRoot)
		}
	}()
	if info, err := os.Lstat(stageRoot); err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return "", errors.New("JSON config transaction stage has an unsafe identity or mode")
	}
	if err := os.Chown(stageRoot, int(uid), -1); err != nil {
		return "", errors.New("assign JSON config transaction stage to the approved UID")
	}
	if err := syncSecureDirectory(stageRoot); err != nil {
		return "", errors.New("persist JSON config transaction stage")
	}
	if err := syncSecureDirectory(changeDirectory); err != nil {
		return "", errors.New("persist JSON config transaction directory")
	}
	cleanup = false
	return stageRoot, nil
}

func (e *OSExecutor) createJSONConfigSealedRoot(scope ExecutionScope) (string, error) {
	changeDirectory, err := e.jsonConfigChangeDirectory(scope)
	if err != nil {
		return "", err
	}
	sealedRoot := filepath.Join(changeDirectory, "json-config-sealed")
	if err := os.Mkdir(sealedRoot, 0o700); err != nil {
		return "", errors.New("create exclusive root-owned JSON config sealed store")
	}
	info, err := os.Lstat(sealedRoot)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		_ = os.Remove(sealedRoot)
		return "", errors.New("JSON config sealed store has an unsafe identity or mode")
	}
	if owner, ok := fileOwner(info); !ok || owner != uint32(os.Geteuid()) {
		_ = os.Remove(sealedRoot)
		return "", errors.New("JSON config sealed store is not owned by the broker identity")
	}
	if err := syncSecureDirectory(sealedRoot); err != nil {
		_ = os.Remove(sealedRoot)
		return "", errors.New("persist JSON config sealed store")
	}
	if err := syncSecureDirectory(changeDirectory); err != nil {
		_ = os.Remove(sealedRoot)
		return "", errors.New("persist JSON config sealed store parent")
	}
	return sealedRoot, nil
}

func (e *OSExecutor) sealJSONConfigDocuments(scratchRoot, sealedRoot string, uid uint32, beforeDigest, afterDigest string) error {
	for _, item := range []struct {
		name   string
		digest string
	}{
		{name: "before.json", digest: beforeDigest},
		{name: "after.json", digest: afterDigest},
	} {
		payload, err := readStableJSONConfigFile(filepath.Join(scratchRoot, item.name), uid, item.digest)
		if err != nil {
			return fmt.Errorf("read target-owned staged %s for sealing: %w", item.name, err)
		}
		if err := writeSealedJSONConfigFile(filepath.Join(sealedRoot, item.name), payload, item.digest); err != nil {
			return fmt.Errorf("seal root-owned %s: %w", item.name, err)
		}
	}
	return syncSecureDirectory(sealedRoot)
}

func readStableJSONConfigFile(path string, expectedOwner uint32, expectedDigest string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0o600 || before.Size() < 1 || before.Size() > 1024*1024 {
		return nil, errors.New("staged JSON config is not a bounded mode-0600 regular file")
	}
	owner, linksOK := fileOwnerAndLinks(before)
	if !linksOK || owner != expectedOwner {
		return nil, errors.New("staged JSON config owner or link count is unsafe")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("open staged JSON config without following links")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("staged JSON config identity changed before read")
	}
	read := func() ([]byte, error) {
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		payload, err := io.ReadAll(io.LimitReader(file, 1024*1024+1))
		if err != nil || len(payload) < 1 || len(payload) > 1024*1024 {
			return nil, errors.New("read bounded staged JSON config")
		}
		return payload, nil
	}
	first, err := read()
	if err != nil {
		return nil, err
	}
	middle, err := file.Stat()
	if err != nil || !os.SameFile(opened, middle) || middle.Size() != int64(len(first)) {
		return nil, errors.New("staged JSON config changed during first read")
	}
	second, err := read()
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(middle, after) || !bytes.Equal(first, second) || after.Size() != int64(len(second)) {
		return nil, errors.New("staged JSON config changed during stable read")
	}
	if jsonConfigPayloadDigest(first) != expectedDigest {
		return nil, errors.New("staged JSON config digest does not match helper proof")
	}
	return first, nil
}

func writeSealedJSONConfigFile(path string, payload []byte, expectedDigest string) error {
	if jsonConfigPayloadDigest(payload) != expectedDigest {
		return errors.New("sealed JSON config payload has an unexpected digest")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(payload); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	owner, linksOK := fileOwnerAndLinks(info)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !linksOK || owner != uint32(os.Geteuid()) {
		return errors.New("sealed JSON config file has an unsafe owner, mode, or link count")
	}
	return nil
}

func fileOwnerAndLinks(info os.FileInfo) (uint32, bool) {
	owner, ok := fileOwner(info)
	if !ok {
		return 0, false
	}
	stat := info.Sys().(*syscall.Stat_t)
	return owner, stat.Nlink == 1
}

func fileOwner(info os.FileInfo) (uint32, bool) {
	if info == nil {
		return 0, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}

func jsonConfigPayloadDigest(payload []byte) string {
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func (e *OSExecutor) materializeJSONConfigInvocationStage(
	scope ExecutionScope,
	rollback jsonConfigRollback,
	sealedName string,
) (string, error) {
	payload, err := readStableJSONConfigFile(
		filepath.Join(rollback.SealedRoot, sealedName), uint32(os.Geteuid()),
		map[string]string{"before.json": rollback.BeforeDigest, "after.json": rollback.AfterDigest}[sealedName],
	)
	if err != nil {
		return "", errors.New("read root-sealed JSON config rollback material")
	}
	stageRoot, err := e.createJSONConfigTargetStage(scope, rollback.RunAsUID, "json-config-invoke", true)
	if err != nil {
		return "", err
	}
	stagedPath := filepath.Join(stageRoot, "staged.json")
	file, err := os.OpenFile(stagedPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = os.RemoveAll(stageRoot)
		return "", errors.New("create ephemeral JSON config invocation copy")
	}
	failed := true
	defer func() {
		_ = file.Close()
		if failed {
			_ = os.RemoveAll(stageRoot)
		}
	}()
	if _, err := file.Write(payload); err != nil {
		return "", errors.New("write ephemeral JSON config invocation copy")
	}
	if err := file.Chown(int(rollback.RunAsUID), -1); err != nil {
		return "", errors.New("assign ephemeral JSON config invocation copy")
	}
	if err := file.Sync(); err != nil {
		return "", errors.New("persist ephemeral JSON config invocation copy")
	}
	if err := file.Close(); err != nil {
		return "", errors.New("close ephemeral JSON config invocation copy")
	}
	if err := syncSecureDirectory(stageRoot); err != nil {
		return "", errors.New("persist ephemeral JSON config invocation stage")
	}
	failed = false
	return stageRoot, nil
}

func (e *OSExecutor) executeWorkloadJSONConfig(
	ctx context.Context,
	scope ExecutionScope,
	operation *protocol.WorkloadJSONConfigEdit,
	result ExecutionResult,
) error {
	profile, field, err := e.resolveWorkloadJSONConfig(scope, operation)
	if err != nil {
		return err
	}
	rollback, err := e.decodeJSONConfigRollback(scope, operation, result)
	if err != nil {
		return err
	}
	if !rollback.matchesPolicy(profile, field) {
		return errors.New("JSON config execution profile changed after the durable mutation barrier")
	}
	planned, err := e.planWorkloadJSONConfig(ctx, scope, operation)
	if err != nil || planned.Digest != scope.PreconditionDigest {
		return knownJSONConfigNoMutation("JSON config or directory preconditions changed after the durable mutation barrier; CAS was not attempted")
	}
	current, err := e.inspectWorkloadJSONConfig(ctx, profile, field, operation)
	if err != nil {
		return uncertainJSONConfig("cannot re-inspect JSON config after the durable mutation barrier")
	}
	if current.Source.SHA256 == rollback.AfterDigest && current.Selected.equal(rollback.After) {
		return nil
	}
	if current.Source.SHA256 != rollback.BeforeDigest || !current.Selected.equal(rollback.Before) {
		return knownJSONConfigNoMutation("JSON config no longer matches the approved before digest; CAS was not attempted")
	}
	proof, runErr := e.commitWorkloadJSONConfig(ctx, scope, profile, rollback, "commit", "after.json", rollback.BeforeDigest, rollback.AfterDigest)
	classificationErr := classifyJSONConfigCommitProof(proof, runErr, rollback.AfterDigest)
	var restored jsonConfigExchangeRestoredProof
	if errors.As(classificationErr, &restored) {
		observed, inspectErr := e.inspectWorkloadJSONConfig(ctx, profile, field, operation)
		if inspectErr != nil {
			return restoredJSONConfigUncertain("JSON config exchange was restored but final content could not be inspected")
		}
		switch {
		case observed.Source.SHA256 == rollback.BeforeDigest && observed.Selected.equal(rollback.Before):
			return restoredJSONConfigNoMutation("JSON config exchange was restored and a fresh inspection proved the exact approved before state")
		case observed.Source.SHA256 == rollback.AfterDigest && observed.Selected.equal(rollback.After):
			// A concurrent writer may have produced the approved after bytes. The
			// normal final verification below still has to observe them exactly.
		default:
			return restoredJSONConfigUncertain("JSON config exchange was restored but final content is neither the exact approved before nor after state")
		}
	} else if classificationErr != nil {
		return classificationErr
	}
	verified, err := e.inspectWorkloadJSONConfig(ctx, profile, field, operation)
	if err != nil || verified.Source.SHA256 != rollback.AfterDigest || !verified.Selected.equal(rollback.After) {
		return uncertainJSONConfig("committed JSON config could not be verified at the approved after digest")
	}
	return nil
}

func (e *OSExecutor) verifyWorkloadJSONConfig(
	ctx context.Context,
	scope ExecutionScope,
	operation *protocol.WorkloadJSONConfigEdit,
	result ExecutionResult,
) (string, error) {
	profile, field, err := e.resolveWorkloadJSONConfig(scope, operation)
	if err != nil {
		return "", err
	}
	rollback, err := e.decodeJSONConfigRollback(scope, operation, result)
	if err != nil {
		return "", err
	}
	proof, err := e.inspectWorkloadJSONConfig(ctx, profile, field, operation)
	if err != nil || proof.Source.SHA256 != rollback.AfterDigest || !proof.Selected.equal(rollback.After) {
		return "", uncertainJSONConfig("JSON config postcondition is not the approved after digest and scalar")
	}
	if err := e.verifyJSONConfigDirectoryEvidence(ctx, profile, rollback); err != nil {
		return "", uncertainJSONConfig("JSON config working-directory postcondition changed after commit")
	}
	return "json-config-after:" + rollback.AfterDigest, nil
}

func (e *OSExecutor) verifyJSONConfigDirectoryEvidence(
	ctx context.Context,
	profile targetpolicy.JSONConfigWorkloadPolicy,
	rollback jsonConfigRollback,
) error {
	if rollback.DirectoryPath == "" {
		if rollback.DirectoryRoot != "" || rollback.DirectoryRootIdentity != "" || rollback.DirectoryIdentity != "" || rollback.DirectoryResidualRisk != "" {
			return errors.New("JSON config rollback has partial directory evidence")
		}
		return nil
	}
	if rollback.DirectoryRoot == "" || rollback.DirectoryRootIdentity == "" || rollback.DirectoryIdentity == "" ||
		rollback.DirectoryResidualRisk != "pathname_may_be_replaced_after_verification" {
		return errors.New("JSON config rollback is missing directory evidence")
	}
	proof, err := e.inspectWorkloadJSONConfigDirectory(ctx, profile, rollback.DirectoryRoot, rollback.DirectoryPath)
	if err != nil || proof.Root.identity() != rollback.DirectoryRootIdentity ||
		proof.Directory.identity() != rollback.DirectoryIdentity || proof.ResidualRisk != rollback.DirectoryResidualRisk {
		return errors.New("JSON config directory identity changed")
	}
	return nil
}

func (e *OSExecutor) rollbackWorkloadJSONConfig(
	ctx context.Context,
	scope ExecutionScope,
	operation *protocol.WorkloadJSONConfigEdit,
	result ExecutionResult,
) error {
	rollback, err := e.decodeJSONConfigRollback(scope, operation, result)
	if err != nil {
		return err
	}
	uid, home, err := e.lookupWorkloadAccount(rollback.TargetAccount)
	if err != nil || uint32(uid) != rollback.RunAsUID || home != rollback.RunAsHome {
		return errors.New("JSON config rollback account no longer matches durable UID/home evidence")
	}
	profile := rollback.policyProfile()
	field := targetpolicy.JSONConfigFieldPolicy{FieldKey: rollback.FieldKey, JSONField: rollback.JSONField}
	current, err := e.inspectWorkloadJSONConfig(ctx, profile, field, operation)
	if err != nil {
		return errors.New("cannot inspect JSON config before rollback")
	}
	if current.Source.SHA256 == rollback.BeforeDigest && current.Selected.equal(rollback.Before) {
		return nil
	}
	if current.Source.SHA256 != rollback.AfterDigest || !current.Selected.equal(rollback.After) {
		return errors.New("JSON config rollback refused because current content is neither the approved after nor before state")
	}
	proof, runErr := e.commitWorkloadJSONConfig(ctx, scope, profile, rollback, "rollback", "before.json", rollback.AfterDigest, rollback.BeforeDigest)
	classificationErr := classifyJSONConfigCommitProof(proof, runErr, rollback.BeforeDigest)
	var restored jsonConfigExchangeRestoredProof
	if errors.As(classificationErr, &restored) {
		observed, inspectErr := e.inspectWorkloadJSONConfig(ctx, profile, field, operation)
		if inspectErr != nil {
			return restoredJSONConfigUncertain("JSON config rollback exchange was restored but final content could not be inspected")
		}
		switch {
		case observed.Source.SHA256 == rollback.BeforeDigest && observed.Selected.equal(rollback.Before):
			return nil
		case observed.Source.SHA256 == rollback.AfterDigest && observed.Selected.equal(rollback.After):
			return restoredJSONConfigUncertain("JSON config rollback exchange was restored to the approved after state instead of completing rollback")
		default:
			return restoredJSONConfigUncertain("JSON config rollback exchange was restored but final content is neither the exact approved before nor after state")
		}
	} else if classificationErr != nil {
		return classificationErr
	}
	verified, err := e.inspectWorkloadJSONConfig(ctx, profile, field, operation)
	if err != nil || verified.Source.SHA256 != rollback.BeforeDigest || !verified.Selected.equal(rollback.Before) {
		return errors.New("rolled-back JSON config failed exact before-state verification")
	}
	return nil
}

func (e *OSExecutor) commitWorkloadJSONConfig(
	ctx context.Context,
	scope ExecutionScope,
	profile targetpolicy.JSONConfigWorkloadPolicy,
	rollback jsonConfigRollback,
	command string,
	stagedName string,
	expectedBefore string,
	expectedAfter string,
) (jsonConfigCommitProof, error) {
	ephemeralRoot, err := e.materializeJSONConfigInvocationStage(scope, rollback, stagedName)
	if err != nil {
		return jsonConfigCommitProof{}, err
	}
	defer os.RemoveAll(ephemeralRoot)
	arguments := []string{
		command,
		"--home", rollback.RunAsHome,
		"--relative", rollback.RelativeConfig,
		"--stage-root", jsonConfigStageMount,
		"--staged", filepath.Join(jsonConfigStageMount, "staged.json"),
		"--expected-before", expectedBefore,
		"--expected-after", expectedAfter,
	}
	payload, runErr := e.runWorkloadJSONConfigHelper(ctx, profile, ephemeralRoot, true, false, nil, arguments...)
	var proof jsonConfigCommitProof
	if err := decodeJSONConfigProof(payload, &proof); err != nil {
		if runErr != nil {
			return jsonConfigCommitProof{}, uncertainJSONConfig("JSON config CAS failed without a valid authoritative proof")
		}
		return jsonConfigCommitProof{}, uncertainJSONConfig("JSON config CAS returned an invalid authoritative proof")
	}
	return proof, runErr
}

func classifyJSONConfigCommitProof(proof jsonConfigCommitProof, runErr error, expectedAfter string) error {
	if proof.Version != 1 || (proof.Operation != "commit" && proof.Operation != "rollback") ||
		proof.CASMethod != "rename_exchange_then_validate" {
		return uncertainJSONConfig("JSON config CAS proof has an invalid identity")
	}
	if proof.Current != nil && proof.Current.validate() != nil {
		return uncertainJSONConfig("JSON config CAS proof has invalid current metadata")
	}
	switch proof.Outcome {
	case "committed":
		if runErr != nil || !proof.MutationAttempted || proof.ExchangeRestored ||
			proof.ResidualState != "same_uid_writers_may_race_after_verification" ||
			proof.Current == nil || proof.Current.SHA256 != expectedAfter {
			return uncertainJSONConfig("JSON config committed proof conflicts with transient unit outcome")
		}
		return nil
	case "already_after":
		if runErr != nil || proof.MutationAttempted || proof.ExchangeRestored ||
			proof.ResidualState != "same_uid_writers_may_race_after_verification" ||
			proof.Current == nil || proof.Current.SHA256 != expectedAfter {
			return uncertainJSONConfig("JSON config idempotent proof conflicts with current content")
		}
		return nil
	case "refused_before_exchange":
		if runErr == nil || proof.MutationAttempted || proof.ExchangeRestored || proof.ResidualState != "no_mutation_observed" {
			return uncertainJSONConfig("JSON config refusal proof is internally inconsistent")
		}
		return knownJSONConfigNoMutation("JSON config CAS refused before exchange")
	case "refused_restored":
		if runErr == nil || !proof.MutationAttempted || !proof.ExchangeRestored ||
			proof.ResidualState != "exchange_restored_at_verification" || proof.Current == nil {
			return uncertainJSONConfig("JSON config restored proof is internally inconsistent")
		}
		return jsonConfigExchangeRestoredProof{currentDigest: proof.Current.SHA256}
	case "outcome_uncertain":
		return uncertainJSONConfig("JSON config CAS outcome is uncertain")
	default:
		return uncertainJSONConfig("JSON config CAS proof has an unsupported outcome")
	}
}

func (e *OSExecutor) decodeJSONConfigRollback(
	scope ExecutionScope,
	operation *protocol.WorkloadJSONConfigEdit,
	result ExecutionResult,
) (jsonConfigRollback, error) {
	if !result.RollbackAvailable || len(result.RollbackData) == 0 || len(result.RollbackData) > 32*1024 {
		return jsonConfigRollback{}, errors.New("JSON config rollback metadata is unavailable or oversized")
	}
	var rollback jsonConfigRollback
	if err := decodeJSONConfigProof(result.RollbackData, &rollback); err != nil {
		return jsonConfigRollback{}, errors.New("decode strict JSON config rollback metadata")
	}
	expectedSealedRoot := filepath.Join(e.StateDir, "changes", scope.ChangeID, "json-config-sealed")
	if rollback.Version != 1 || rollback.PluginID != operation.PluginID || rollback.SourceDigest != operation.SourceDigest ||
		rollback.ProfileKey != operation.ProfileKey || rollback.SelectorValue != operation.SelectorValue ||
		rollback.FieldKey != operation.FieldKey || !protocol.ValidWorkloadAccount(rollback.TargetAccount) ||
		rollback.TargetAccount == "root" || rollback.RunAsUID == 0 || rollback.RunAsUID > 1<<31-1 ||
		!filepath.IsAbs(rollback.RunAsHome) || filepath.Clean(rollback.RunAsHome) != rollback.RunAsHome || rollback.RunAsHome == "/" ||
		rollback.RelativeConfig == "" || filepath.IsAbs(rollback.RelativeConfig) || filepath.Clean(rollback.RelativeConfig) != rollback.RelativeConfig ||
		rollback.SelectorKey == "" || rollback.JSONField == "" || rollback.SealedRoot != expectedSealedRoot ||
		!protocol.ValidDigest(rollback.BeforeDigest) || !protocol.ValidDigest(rollback.AfterDigest) ||
		rollback.BeforeDigest == rollback.AfterDigest || rollback.Before.validate() != nil || rollback.After.validate() != nil ||
		!rollback.After.matchesRequested(operation.Value) || !rollback.WholeDocumentRewrite {
		return jsonConfigRollback{}, errors.New("JSON config rollback metadata does not match the approved operation")
	}
	for _, component := range strings.Split(rollback.RelativeConfig, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return jsonConfigRollback{}, errors.New("JSON config rollback path is unsafe")
		}
	}
	if !protocol.ValidJSONConfigKey(rollback.SelectorKey) || !protocol.ValidJSONConfigKey(rollback.JSONField) ||
		rollback.JSONField == rollback.SelectorKey {
		return jsonConfigRollback{}, errors.New("JSON config rollback field mapping is unsafe")
	}
	directoryEvidence := []string{
		rollback.DirectoryRoot, rollback.DirectoryPath, rollback.DirectoryRootIdentity,
		rollback.DirectoryIdentity, rollback.DirectoryResidualRisk,
	}
	nonEmptyDirectoryFields := 0
	for _, value := range directoryEvidence {
		if value != "" {
			nonEmptyDirectoryFields++
		}
	}
	if nonEmptyDirectoryFields != 0 {
		if nonEmptyDirectoryFields != len(directoryEvidence) || operation.Value.Kind != "string" ||
			rollback.DirectoryPath != *operation.Value.StringValue ||
			!filepath.IsAbs(rollback.DirectoryRoot) || filepath.Clean(rollback.DirectoryRoot) != rollback.DirectoryRoot || rollback.DirectoryRoot == "/" ||
			!filepath.IsAbs(rollback.DirectoryPath) || filepath.Clean(rollback.DirectoryPath) != rollback.DirectoryPath || rollback.DirectoryPath == "/" ||
			!jsonDirectoryIdentityPattern.MatchString(rollback.DirectoryRootIdentity) ||
			!jsonDirectoryIdentityPattern.MatchString(rollback.DirectoryIdentity) ||
			rollback.DirectoryResidualRisk != "pathname_may_be_replaced_after_verification" {
			return jsonConfigRollback{}, errors.New("JSON config rollback directory evidence is invalid")
		}
		relative, err := filepath.Rel(rollback.DirectoryRoot, rollback.DirectoryPath)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return jsonConfigRollback{}, errors.New("JSON config rollback directory escapes its approved root")
		}
	}
	return rollback, nil
}

func (rollback jsonConfigRollback) matchesPolicy(profile targetpolicy.JSONConfigWorkloadPolicy, field targetpolicy.JSONConfigFieldPolicy) bool {
	return rollback.PluginID == profile.PluginID && rollback.SourceDigest == profile.PluginDigest &&
		rollback.ProfileKey == profile.ProfileKey && rollback.TargetAccount == profile.TargetAccount &&
		rollback.RunAsUID == profile.RunAsUID && rollback.RunAsHome == profile.RunAsHome &&
		rollback.RelativeConfig == profile.RelativeConfig && rollback.SelectorKey == profile.SelectorKey &&
		rollback.FieldKey == field.FieldKey && rollback.JSONField == field.JSONField
}

func (rollback jsonConfigRollback) policyProfile() targetpolicy.JSONConfigWorkloadPolicy {
	return targetpolicy.JSONConfigWorkloadPolicy{
		PluginID: rollback.PluginID, PluginDigest: rollback.SourceDigest,
		TargetAccount: rollback.TargetAccount, ProfileKey: rollback.ProfileKey,
		RunAsUID: rollback.RunAsUID, RunAsHome: rollback.RunAsHome,
		RelativeConfig: rollback.RelativeConfig, SelectorKey: rollback.SelectorKey,
	}
}

func (e *OSExecutor) ReconcileInterruptedChange(
	ctx context.Context,
	scope ExecutionScope,
	operation protocol.Operation,
	result ExecutionResult,
) (InterruptedChangeReconciliation, error) {
	edit, ok := operation.(*protocol.WorkloadJSONConfigEdit)
	if !ok {
		return InterruptedChangeReconciliation{}, nil
	}
	rollback, err := e.decodeJSONConfigRollback(scope, edit, result)
	if err != nil {
		return InterruptedChangeReconciliation{}, err
	}
	uid, home, err := e.lookupWorkloadAccount(rollback.TargetAccount)
	if err != nil || uint32(uid) != rollback.RunAsUID || home != rollback.RunAsHome {
		return InterruptedChangeReconciliation{}, errors.New("interrupted JSON config account does not match durable UID/home evidence")
	}
	profile := rollback.policyProfile()
	field := targetpolicy.JSONConfigFieldPolicy{FieldKey: rollback.FieldKey, JSONField: rollback.JSONField}
	proof, err := e.inspectWorkloadJSONConfig(ctx, profile, field, edit)
	if err != nil {
		return InterruptedChangeReconciliation{}, errors.New("interrupted JSON config cannot be inspected safely")
	}
	if proof.Source.SHA256 == rollback.BeforeDigest && proof.Selected.equal(rollback.Before) {
		return InterruptedChangeReconciliation{
			State:        StateRolledBack,
			EvidenceRefs: []string{"json-config:reconciled-before:" + rollback.BeforeDigest},
		}, nil
	}
	if proof.Source.SHA256 == rollback.AfterDigest && proof.Selected.equal(rollback.After) {
		if err := e.verifyJSONConfigDirectoryEvidence(ctx, profile, rollback); err != nil {
			return InterruptedChangeReconciliation{}, errors.New("interrupted JSON config after-state has stale directory evidence")
		}
		return InterruptedChangeReconciliation{
			State: StateCommitted, Verification: "json-config-after:" + rollback.AfterDigest,
			EvidenceRefs: []string{"json-config:reconciled-after:" + rollback.AfterDigest},
		}, nil
	}
	return InterruptedChangeReconciliation{}, errors.New("interrupted JSON config is neither the approved before nor after digest")
}
