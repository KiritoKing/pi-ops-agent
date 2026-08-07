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

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

const Version = 1

var (
	idPattern       = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	revisionPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{7,159}$`)
	accountPattern  = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
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
	ID          string           `json:"id"`
	Account     string           `json:"account"`
	DisplayName string           `json:"displayName"`
	Inspect     InspectionPolicy `json:"inspect"`
	Changes     ChangePolicy     `json:"changes"`
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
		sort.Strings(target.Inspect.Units)
		sort.Strings(target.Inspect.ReadPaths)
		sort.Strings(target.Changes.Units)
		sort.Strings(target.Changes.WritePaths)
		sort.Strings(target.Changes.Packages)
		sort.Slice(target.Changes.Plugins, func(i, j int) bool {
			return artifactKey(target.Changes.Plugins[i]) < artifactKey(target.Changes.Plugins[j])
		})
		p.byID[target.ID] = *target
	}
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

func (p *Policy) PublicTargets() []Target {
	if p == nil {
		return nil
	}
	result := make([]Target, len(p.Targets))
	copy(result, p.Targets)
	return result
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
	case protocol.MethodFileMetadata, protocol.MethodFileRead:
		if err := pathWithin(request.Path, target.Inspect.ReadPaths); err != nil {
			return fmt.Errorf("file inspection is outside target policy: %w", err)
		}
	case protocol.MethodChangePrepare:
		return authorizeOperation(target, request.Operation)
	case protocol.MethodChangeStatus, protocol.MethodChangeApprove, protocol.MethodChangeReject, protocol.MethodChangeRollback:
		return nil
	default:
		return errors.New("method is not authorized by target policy")
	}
	return nil
}

func authorizeOperation(target Target, operation protocol.Operation) error {
	switch value := operation.(type) {
	case *protocol.FileWrite:
		if err := writablePathWithin(value.Path, target.Changes.WritePaths); err != nil {
			return fmt.Errorf("file write is outside target policy: %w", err)
		}
	case *protocol.ServiceAction:
		if !contains(target.Changes.Units, value.Unit) {
			return errors.New("service change is outside target policy")
		}
	case *protocol.PackageInstall:
		if !contains(target.Changes.Packages, value.Package) {
			return errors.New("package change is outside target policy")
		}
	case *protocol.PluginInstall:
		if !artifactOperationAuthorized(target.Changes.Plugins, "", value.PluginID, value.Version, value.Publisher, value.Digest, value.ArtifactRef) {
			return errors.New("plugin install is outside target policy")
		}
	case *protocol.WorkloadDeploy:
		if !artifactOperationAuthorized(target.Changes.Plugins, "managed-workload", value.PluginID, value.Version, value.Publisher, value.Digest, value.ArtifactRef) {
			return errors.New("workload deployment is outside target policy")
		}
	case *protocol.BreakglassScript:
		return errors.New("breakglass.script is never authorized by remote target policy")
	default:
		return errors.New("operation is not authorized by target policy")
	}
	return nil
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
	return resolvedWithin(filepath.Join(resolved, relativeTail), roots)
}

func contains(values []string, value string) bool {
	index := sort.SearchStrings(values, value)
	return index < len(values) && values[index] == value
}
