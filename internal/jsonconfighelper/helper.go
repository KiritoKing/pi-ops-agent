package jsonconfighelper

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxJSONBytes     = 1024 * 1024
	maxPathBytes     = 4096
	maxKeyBytes      = 64
	maxSelectorBytes = 256
)

type safeValue struct {
	Kind         string  `json:"kind"`
	StringValue  *string `json:"stringValue,omitempty"`
	BooleanValue *bool   `json:"booleanValue,omitempty"`
	NumberValue  *string `json:"numberValue,omitempty"`
}

type fileMetadata struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Dev    uint64 `json:"dev"`
	Ino    uint64 `json:"ino"`
	Mode   uint32 `json:"mode"`
}

type inspectProof struct {
	Version   int          `json:"version"`
	Operation string       `json:"operation"`
	Source    fileMetadata `json:"source"`
	Selected  safeValue    `json:"selected"`
}

// directoryMetadata is intentionally limited to identity and access metadata.
// In particular, inspect-directory proofs never echo a policy path or any
// directory entry names back to the caller.
type directoryMetadata struct {
	Dev  uint64 `json:"dev"`
	Ino  uint64 `json:"ino"`
	Mode uint32 `json:"mode"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
}

type inspectDirectoryProof struct {
	Version      int               `json:"version"`
	Operation    string            `json:"operation"`
	Root         directoryMetadata `json:"root"`
	Directory    directoryMetadata `json:"directory"`
	ResidualRisk string            `json:"residualRisk"`
}

type snapshotProof struct {
	Version   int          `json:"version"`
	Operation string       `json:"operation"`
	Source    fileMetadata `json:"source"`
	Snapshot  fileMetadata `json:"snapshot"`
	Selected  safeValue    `json:"selected"`
}

// mutateProof never includes the source document or any unknown field. The
// helper currently performs a deterministic whole-document JSON rewrite after
// changing one selected scalar; callers must surface that fact during review.
type mutateProof struct {
	Version              int          `json:"version"`
	Operation            string       `json:"operation"`
	Source               fileMetadata `json:"source"`
	Output               fileMetadata `json:"output"`
	Before               safeValue    `json:"before"`
	After                safeValue    `json:"after"`
	BeforeDigest         string       `json:"beforeDigest"`
	AfterDigest          string       `json:"afterDigest"`
	WholeDocumentRewrite bool         `json:"wholeDocumentRewrite"`
}

// CommitProof deliberately describes the exchange-then-validate primitive
// accurately. Linux has no rename primitive that conditionally exchanges a
// pathname based on a content digest. Another process with the same UID can
// therefore race after any observation; callers must serialize cooperative
// writers and treat outcome_uncertain as recovery-required.
type CommitProof struct {
	Version           int           `json:"version"`
	Operation         string        `json:"operation"`
	Outcome           string        `json:"outcome"`
	MutationAttempted bool          `json:"mutationAttempted"`
	ExchangeRestored  bool          `json:"exchangeRestored"`
	ResidualState     string        `json:"residualState"`
	CASMethod         string        `json:"casMethod"`
	Current           *fileMetadata `json:"current,omitempty"`
}

type inspectOptions struct {
	Home          string
	Relative      string
	SelectorKey   string
	SelectorValue string
	Field         string
}

type inspectDirectoryOptions struct {
	Root string
	Path string
}

type snapshotOptions struct {
	inspectOptions
	StageRoot string
	Output    string
}

type mutateValue struct {
	Kind         string
	StringValue  *string
	BooleanValue *bool
}

type mutateOptions struct {
	inspectOptions
	StageRoot string
	Output    string
	Value     mutateValue
}

type commitOptions struct {
	Home           string
	Relative       string
	StageRoot      string
	Staged         string
	ExpectedBefore string
	ExpectedAfter  string
	Operation      string
}

// Run is the complete command implementation used by the small cmd wrapper.
// It rejects root even if invoked outside the intended systemd-run profile.
func Run(arguments []string, output io.Writer) error {
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		return errors.New("refusing to run with a root identity")
	}
	if os.Getuid() != os.Geteuid() {
		return errors.New("real and effective user identities must match")
	}
	if output == nil {
		return errors.New("proof output is unavailable")
	}
	if len(arguments) == 0 {
		return errors.New("expected inspect, inspect-directory, snapshot, mutate, commit, or rollback")
	}

	var proof any
	var operationErr error
	switch arguments[0] {
	case "inspect":
		options, err := parseInspectOptions(arguments[1:])
		if err != nil {
			return err
		}
		proof, operationErr = inspectPlatform(options)
	case "inspect-directory":
		options, err := parseInspectDirectoryOptions(arguments[1:])
		if err != nil {
			return err
		}
		proof, operationErr = inspectDirectoryPlatform(options)
	case "snapshot":
		options, err := parseSnapshotOptions(arguments[1:])
		if err != nil {
			return err
		}
		proof, operationErr = snapshotPlatform(options)
	case "mutate":
		options, err := parseMutateOptions(arguments[1:])
		if err != nil {
			return err
		}
		proof, operationErr = mutatePlatform(options)
	case "commit", "rollback":
		options, err := parseCommitOptions(arguments[0], arguments[1:])
		if err != nil {
			return err
		}
		var commitProof CommitProof
		commitProof, operationErr = commitPlatform(options)
		if commitProof.Version != 0 {
			proof = commitProof
		}
	default:
		return errors.New("expected inspect, inspect-directory, snapshot, mutate, commit, or rollback")
	}

	if proof != nil {
		encoder := json.NewEncoder(output)
		encoder.SetEscapeHTML(true)
		if err := encoder.Encode(proof); err != nil {
			return errors.New("write bounded JSON proof")
		}
	}
	return operationErr
}

func parseInspectDirectoryOptions(arguments []string) (inspectDirectoryOptions, error) {
	values, err := parseStrictOptions(arguments, []string{"root", "path"})
	if err != nil {
		return inspectDirectoryOptions{}, errors.New("inspect-directory arguments are invalid")
	}
	options := inspectDirectoryOptions{Root: values["root"], Path: values["path"]}
	if err := options.validate(); err != nil {
		return inspectDirectoryOptions{}, err
	}
	return options, nil
}

func parseInspectOptions(arguments []string) (inspectOptions, error) {
	values, err := parseStrictOptions(arguments, []string{
		"home", "relative", "selector-key", "selector-value", "field",
	})
	if err != nil {
		return inspectOptions{}, errors.New("inspect arguments are invalid")
	}
	options := inspectOptions{
		Home: values["home"], Relative: values["relative"], SelectorKey: values["selector-key"],
		SelectorValue: values["selector-value"], Field: values["field"],
	}
	if err := options.validate(); err != nil {
		return inspectOptions{}, err
	}
	return options, nil
}

func parseSnapshotOptions(arguments []string) (snapshotOptions, error) {
	values, err := parseStrictOptions(arguments, []string{
		"home", "relative", "selector-key", "selector-value", "field", "stage-root", "output",
	})
	if err != nil {
		return snapshotOptions{}, errors.New("snapshot arguments are invalid")
	}
	options := snapshotOptions{
		inspectOptions: inspectOptions{
			Home: values["home"], Relative: values["relative"], SelectorKey: values["selector-key"],
			SelectorValue: values["selector-value"], Field: values["field"],
		},
		StageRoot: values["stage-root"], Output: values["output"],
	}
	if err := options.inspectOptions.validate(); err != nil {
		return snapshotOptions{}, err
	}
	if err := validateStagePath(options.StageRoot, options.Output, "snapshot output"); err != nil {
		return snapshotOptions{}, err
	}
	return options, nil
}

func parseMutateOptions(arguments []string) (mutateOptions, error) {
	allowed := []string{
		"home", "relative", "selector-key", "selector-value", "field", "stage-root", "output",
		"value-kind", "string-value", "boolean-value",
	}
	required := []string{
		"home", "relative", "selector-key", "selector-value", "field", "stage-root", "output", "value-kind",
	}
	values, err := parseStrictOptionalOptions(arguments, allowed, required)
	if err != nil {
		return mutateOptions{}, errors.New("mutate arguments are invalid")
	}
	options := mutateOptions{
		inspectOptions: inspectOptions{
			Home: values["home"], Relative: values["relative"], SelectorKey: values["selector-key"],
			SelectorValue: values["selector-value"], Field: values["field"],
		},
		StageRoot: values["stage-root"], Output: values["output"],
		Value: mutateValue{Kind: values["value-kind"]},
	}
	if err := options.inspectOptions.validate(); err != nil {
		return mutateOptions{}, err
	}
	if options.SelectorKey == options.Field {
		return mutateOptions{}, errors.New("mutate cannot change the selector field")
	}
	if err := validateStagePath(options.StageRoot, options.Output, "mutate output"); err != nil {
		return mutateOptions{}, err
	}
	switch options.Value.Kind {
	case "string":
		value, ok := values["string-value"]
		if !ok || values["boolean-value"] != "" || !validMutationText(value) {
			return mutateOptions{}, errors.New("string mutation requires one bounded safe string value")
		}
		options.Value.StringValue = &value
	case "boolean":
		value, ok := values["boolean-value"]
		if !ok || values["string-value"] != "" || (value != "true" && value != "false") {
			return mutateOptions{}, errors.New("boolean mutation requires exactly true or false")
		}
		boolean := value == "true"
		options.Value.BooleanValue = &boolean
	case "clear":
		if values["string-value"] != "" || values["boolean-value"] != "" {
			return mutateOptions{}, errors.New("clear mutation does not accept a value")
		}
	default:
		return mutateOptions{}, errors.New("mutation value kind must be string, boolean, or clear")
	}
	return options, nil
}

func parseCommitOptions(operation string, arguments []string) (commitOptions, error) {
	values, err := parseStrictOptions(arguments, []string{
		"home", "relative", "staged", "stage-root", "expected-before", "expected-after",
	})
	if err != nil {
		return commitOptions{}, fmt.Errorf("%s arguments are invalid", operation)
	}
	options := commitOptions{
		Home: values["home"], Relative: values["relative"], Staged: values["staged"],
		StageRoot: values["stage-root"], ExpectedBefore: values["expected-before"],
		ExpectedAfter: values["expected-after"], Operation: operation,
	}
	if err := validateHomeAndRelative(options.Home, options.Relative); err != nil {
		return commitOptions{}, err
	}
	if err := validateStagePath(options.StageRoot, options.Staged, "staged input"); err != nil {
		return commitOptions{}, err
	}
	if !validDigest(options.ExpectedBefore) || !validDigest(options.ExpectedAfter) ||
		options.ExpectedBefore == options.ExpectedAfter {
		return commitOptions{}, errors.New("expected digests must be distinct canonical sha256 values")
	}
	return options, nil
}

func parseStrictOptions(arguments []string, names []string) (map[string]string, error) {
	return parseStrictOptionalOptions(arguments, names, names)
}

func parseStrictOptionalOptions(arguments, allowedNames, requiredNames []string) (map[string]string, error) {
	allowed := make(map[string]struct{}, len(allowedNames))
	for _, name := range allowedNames {
		if name == "" {
			return nil, errors.New("empty allowed option")
		}
		if _, duplicate := allowed[name]; duplicate {
			return nil, errors.New("duplicate allowed option")
		}
		allowed[name] = struct{}{}
	}
	values := make(map[string]string, len(allowedNames))
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if !strings.HasPrefix(argument, "--") || argument == "--" {
			return nil, errors.New("positional argument")
		}
		nameValue := strings.TrimPrefix(argument, "--")
		name, value, hasEquals := strings.Cut(nameValue, "=")
		if _, ok := allowed[name]; !ok || name == "" {
			return nil, errors.New("unknown option")
		}
		if _, duplicate := values[name]; duplicate {
			return nil, errors.New("duplicate option")
		}
		if !hasEquals {
			index++
			if index >= len(arguments) {
				return nil, errors.New("missing option value")
			}
			value = arguments[index]
		}
		if value == "" || len(value) > maxPathBytes {
			return nil, errors.New("empty or oversized option value")
		}
		values[name] = value
	}
	for _, name := range requiredNames {
		if _, ok := allowed[name]; !ok {
			return nil, errors.New("required option is not allowed")
		}
		if values[name] == "" {
			return nil, errors.New("missing required option")
		}
	}
	return values, nil
}

func (options inspectOptions) validate() error {
	if err := validateHomeAndRelative(options.Home, options.Relative); err != nil {
		return err
	}
	if !validObjectKey(options.SelectorKey) || !validObjectKey(options.Field) {
		return errors.New("selector and field keys must be bounded ASCII identifiers")
	}
	if !validBoundedText(options.SelectorValue, maxSelectorBytes) {
		return errors.New("selector value must be bounded control-free UTF-8")
	}
	return nil
}

func (options inspectDirectoryOptions) validate() error {
	if !cleanAbsoluteDirectoryPath(options.Root) || !cleanAbsoluteDirectoryPath(options.Path) {
		return errors.New("directory root and path must be clean absolute paths")
	}
	relative, err := filepath.Rel(options.Root, options.Path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("directory path must stay beneath or equal its root")
	}
	return nil
}

func cleanAbsoluteDirectoryPath(path string) bool {
	return len(path) > 0 && len(path) <= maxPathBytes && filepath.IsAbs(path) && filepath.Clean(path) == path &&
		!strings.ContainsRune(path, '\x00')
}

func validateHomeAndRelative(home, relative string) error {
	if !cleanAbsolutePath(home) || home == string(filepath.Separator) {
		return errors.New("home must be a clean non-root absolute path")
	}
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || relative == "." ||
		relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("relative config path must stay beneath home")
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return errors.New("relative config path contains an unsafe component")
		}
	}
	return nil
}

func validateStagePath(stageRoot, path, label string) error {
	if !cleanAbsolutePath(stageRoot) || stageRoot == string(filepath.Separator) || !cleanAbsolutePath(path) {
		return fmt.Errorf("%s paths must be clean non-root absolute paths", label)
	}
	relative, err := filepath.Rel(stageRoot, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s must stay beneath stage root", label)
	}
	return nil
}

func cleanAbsolutePath(path string) bool {
	return len(path) > 1 && len(path) <= maxPathBytes && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func validObjectKey(value string) bool {
	if len(value) == 0 || len(value) > maxKeyBytes {
		return false
	}
	for index, char := range value {
		if char > unicode.MaxASCII || !(char == '_' || char == '-' || char >= 'a' && char <= 'z' ||
			char >= 'A' && char <= 'Z' || index > 0 && char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}

func validBoundedText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) || unicode.In(char, unicode.Cf, unicode.Zl, unicode.Zp) {
			return false
		}
	}
	return true
}

func validMutationText(value string) bool {
	// validBoundedText also excludes rendering controls so the reviewed value
	// cannot render differently from what the JSON contains.
	return validBoundedText(value, maxSafeTextBytes)
}

func digestPayload(payload []byte) string {
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	encoded := strings.TrimPrefix(value, "sha256:")
	if encoded != strings.ToLower(encoded) {
		return false
	}
	decoded, err := hex.DecodeString(encoded)
	return err == nil && len(decoded) == sha256.Size
}
