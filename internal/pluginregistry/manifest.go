package pluginregistry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"slices"
	"strings"
)

const (
	ManifestAPIVersion = "agentd.plugin/v1"
	ManifestSchema     = 1
)

type Kind string

const (
	KindAdapter  Kind = "adapter"
	KindWorkload Kind = "workload"
)

var (
	pluginIDPattern  = regexp.MustCompile(`^(adapter|workload)\.[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$`)
	versionPattern   = regexp.MustCompile(`^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$`)
	publisherPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,159}$`)
	namePattern      = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$`)
)

// Manifest is deliberately common to first- and third-party source plugins.
// requestedScopes is the exact, reviewable authority set a grant must bind.
type Manifest struct {
	APIVersion      string   `json:"apiVersion"`
	SchemaVersion   int      `json:"schemaVersion"`
	ID              string   `json:"id"`
	Kind            Kind     `json:"kind"`
	Version         string   `json:"version"`
	Publisher       string   `json:"publisher"`
	Description     string   `json:"description"`
	Entrypoint      string   `json:"entrypoint"`
	Capabilities    []string `json:"capabilities"`
	RequestedScopes []string `json:"requestedScopes"`
}

func parseManifest(payload []byte) (Manifest, error) {
	if err := rejectDuplicateJSONKeys(payload); err != nil {
		return Manifest{}, fmt.Errorf("decode source plugin manifest: %w", err)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil || fields == nil {
		return Manifest{}, errors.New("source plugin manifest must be a JSON object")
	}
	required := []string{
		"apiVersion", "schemaVersion", "id", "kind", "version", "publisher",
		"description", "entrypoint", "capabilities", "requestedScopes",
	}
	allowed := slices.Clone(required)
	if len(fields) < len(required) || len(fields) > len(allowed) {
		for key := range fields {
			if !slices.Contains(allowed, key) {
				return Manifest{}, fmt.Errorf("source plugin manifest contains unknown field %q", key)
			}
		}
	}
	for _, key := range required {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return Manifest{}, fmt.Errorf("source plugin manifest is missing required field %q", key)
		}
	}
	for key := range fields {
		if !slices.Contains(allowed, key) {
			return Manifest{}, fmt.Errorf("source plugin manifest contains unknown field %q", key)
		}
	}

	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode source plugin manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Manifest{}, errors.New("decode source plugin manifest: trailing JSON value")
	}
	if err := manifest.validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func (m Manifest) validate() error {
	if m.APIVersion != ManifestAPIVersion || m.SchemaVersion != ManifestSchema {
		return errors.New("source plugin manifest has an unsupported API or schema version")
	}
	if m.Kind != KindAdapter && m.Kind != KindWorkload {
		return errors.New("source plugin manifest kind must be adapter or workload")
	}
	if !pluginIDPattern.MatchString(m.ID) || !strings.HasPrefix(m.ID, string(m.Kind)+".") {
		return errors.New("source plugin manifest id does not match its kind")
	}
	if len(m.Version) > 96 || !versionPattern.MatchString(m.Version) {
		return errors.New("source plugin manifest version must be a bounded semantic version")
	}
	if !publisherPattern.MatchString(m.Publisher) || strings.Contains(m.Publisher, "..") || strings.Contains(m.Publisher, "//") ||
		!boundedText(m.Description, 2048) {
		return errors.New("source plugin manifest publisher or description is invalid")
	}
	if !safeRelativePath(m.Entrypoint) || m.Entrypoint == "manifest.json" {
		return errors.New("source plugin manifest entrypoint must be a normalized package-relative path")
	}
	if err := validateSortedNames("capabilities", m.Capabilities, 64); err != nil {
		return err
	}
	if err := validateSortedNames("requestedScopes", m.RequestedScopes, 64); err != nil {
		return err
	}
	return nil
}

func validateSortedNames(label string, values []string, maximum int) error {
	if values == nil || len(values) > maximum {
		return fmt.Errorf("source plugin manifest %s must be a non-null array with at most %d entries", label, maximum)
	}
	for index, value := range values {
		if len(value) > 128 || !namePattern.MatchString(value) {
			return fmt.Errorf("source plugin manifest %s contains an invalid value", label)
		}
		if index > 0 && values[index-1] >= value {
			return fmt.Errorf("source plugin manifest %s must be sorted with unique entries", label)
		}
	}
	return nil
}

func boundedText(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character == '\x00' || character == '\r' || character == '\n' || character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func safeRelativePath(value string) bool {
	if value == "" || len(value) > 512 || strings.ContainsAny(value, "\\\x00\r\n") || path.IsAbs(value) || path.Clean(value) != value {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
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
