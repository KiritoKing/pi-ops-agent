package pluginpkg

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	maxPackageBytes = 16 * 1024 * 1024
	maxFiles        = 256
	maxFileBytes    = 8 * 1024 * 1024
	maxCatalogFiles = 256
)

var (
	adapterIDPattern         = regexp.MustCompile(`^adapter\.[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$`)
	workloadIDPattern        = regexp.MustCompile(`^workload\.[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$`)
	versionPattern           = regexp.MustCompile(`^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$`)
	secretPattern            = regexp.MustCompile(`^[a-z][a-zA-Z0-9]{0,63}$`)
	adapterEntrypointPattern = regexp.MustCompile(`^[A-Za-z0-9._/-]+\.mjs$`)
	imageRepoPattern         = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+$`)
	digestPattern            = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	containerPattern         = regexp.MustCompile(`^ops-agent-[a-z0-9][a-z0-9_.-]{0,53}$`)
	userPattern              = regexp.MustCompile(`^[1-9][0-9]{0,9}:[1-9][0-9]{0,9}$`)
	processCommandPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$`)
	environmentPattern       = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)
	modePattern              = regexp.MustCompile(`^0[0-7]{3}$`)
)

var adapterSetupOperations = map[string]struct{}{
	"serviceAccount.create":  {},
	"systemdUnit.install":    {},
	"credential.install":     {},
	"supplementaryGroup.add": {},
	"config.write":           {},
	"service.start":          {},
}

var safeContainerCapabilities = map[string]struct{}{
	"CHOWN": {}, "DAC_OVERRIDE": {}, "FOWNER": {}, "FSETID": {},
	"KILL": {}, "NET_BIND_SERVICE": {}, "SETGID": {}, "SETUID": {},
}

type Capabilities struct {
	InboundText         bool `json:"inboundText"`
	VerifiedSender      bool `json:"verifiedSender"`
	PrivateConversation bool `json:"privateConversation"`
	ProactiveDelivery   bool `json:"proactiveDelivery"`
	ApprovalIntent      bool `json:"approvalIntent"`
	Streaming           bool `json:"streaming"`
}

type Manifest struct {
	SchemaVersion   int              `json:"schemaVersion"`
	ID              string           `json:"id"`
	Kind            string           `json:"kind"`
	Version         string           `json:"version"`
	Publisher       string           `json:"publisher"`
	CoreProtocol    int              `json:"coreProtocol"`
	Description     string           `json:"description"`
	Entrypoint      string           `json:"entrypoint,omitempty"`
	Capabilities    *Capabilities    `json:"capabilities,omitempty"`
	Secrets         []string         `json:"secrets,omitempty"`
	SetupOperations []string         `json:"setupOperations,omitempty"`
	Workload        *ManagedWorkload `json:"workload,omitempty"`
}

type ManagedWorkload struct {
	Runtime               string                `json:"runtime"`
	ImageRepository       string                `json:"imageRepository"`
	ImageDigest           string                `json:"imageDigest"`
	ContainerName         string                `json:"containerName"`
	ContainerCommand      []string              `json:"containerCommand"`
	ExpectedEntrypoint    []string              `json:"expectedEntrypoint"`
	ExpectedUser          string                `json:"expectedUser"`
	ProcessPolicy         WorkloadProcessPolicy `json:"processPolicy"`
	ContainerPort         int                   `json:"containerPort"`
	HostPort              int                   `json:"hostPort"`
	DataMountTarget       string                `json:"dataMountTarget"`
	UID                   int                   `json:"uid"`
	GID                   int                   `json:"gid"`
	Resources             WorkloadResources     `json:"resources"`
	CapAdd                []string              `json:"capAdd"`
	LiteralEnvironment    map[string]string     `json:"literalEnvironment"`
	CredentialEnvironment map[string]string     `json:"credentialEnvironment"`
	Directories           []WorkloadDirectory   `json:"directories"`
	Files                 []WorkloadFile        `json:"files"`
	ContainerExecChecks   []ContainerExecCheck  `json:"containerExecChecks"`
}

type WorkloadProcessPolicy struct {
	RuntimeUser             string   `json:"runtimeUser"`
	AllowedRuntimeCommands  []string `json:"allowedRuntimeCommands"`
	RequiredRuntimeCommands []string `json:"requiredRuntimeCommands"`
	AllowedRootCommands     []string `json:"allowedRootCommands"`
}

type WorkloadResources struct {
	MemoryBytes int64 `json:"memoryBytes"`
	NanoCPUs    int64 `json:"nanoCpus"`
	PidsLimit   int64 `json:"pidsLimit"`
	ShmBytes    int64 `json:"shmBytes"`
}

type WorkloadDirectory struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

type WorkloadFile struct {
	Source string `json:"source"`
	Path   string `json:"path"`
	Mode   string `json:"mode"`
}

type ContainerExecCheck struct {
	Argv           []string `json:"argv"`
	OutputContains string   `json:"outputContains"`
}

type adapterManifestWire struct {
	SchemaVersion   int          `json:"schemaVersion"`
	ID              string       `json:"id"`
	Kind            string       `json:"kind"`
	Version         string       `json:"version"`
	Publisher       string       `json:"publisher"`
	CoreProtocol    int          `json:"coreProtocol"`
	Entrypoint      string       `json:"entrypoint"`
	Description     string       `json:"description"`
	Capabilities    Capabilities `json:"capabilities"`
	Secrets         []string     `json:"secrets"`
	SetupOperations []string     `json:"setupOperations"`
}

type workloadManifestWire struct {
	SchemaVersion int             `json:"schemaVersion"`
	ID            string          `json:"id"`
	Kind          string          `json:"kind"`
	Version       string          `json:"version"`
	Publisher     string          `json:"publisher"`
	CoreProtocol  int             `json:"coreProtocol"`
	Description   string          `json:"description"`
	Workload      ManagedWorkload `json:"workload"`
}

type archiveInfo struct {
	manifest     []byte
	regularFiles map[string]os.FileMode
}

type Package struct {
	Path     string
	Digest   string
	Manifest Manifest
	payload  []byte
}

func Inspect(packagePath, catalogRoot string) (*Package, error) {
	if !filepath.IsAbs(packagePath) || filepath.Clean(packagePath) != packagePath || !filepath.IsAbs(catalogRoot) {
		return nil, errors.New("plugin package and catalog root must be clean absolute paths")
	}
	info, err := os.Lstat(packagePath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() < 1 || info.Size() > maxPackageBytes {
		return nil, errors.New("plugin package must be a bounded regular file that is not group or world writable")
	}
	resolvedPackage, err := filepath.EvalSymlinks(packagePath)
	if err != nil {
		return nil, err
	}
	resolvedCatalog, err := filepath.EvalSymlinks(catalogRoot)
	if err != nil {
		return nil, err
	}
	relative, err := filepath.Rel(resolvedCatalog, resolvedPackage)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("plugin package is outside the trusted local catalog")
	}
	payload, err := os.ReadFile(resolvedPackage)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	archive, err := inspectArchive(payload)
	if err != nil {
		return nil, err
	}
	manifest, err := parseManifest(archive.manifest)
	if err != nil {
		return nil, err
	}
	if manifest.Workload != nil {
		for _, file := range manifest.Workload.Files {
			if _, ok := archive.regularFiles[file.Source]; !ok {
				return nil, fmt.Errorf("managed workload source %q is missing from the package", file.Source)
			}
		}
	}
	return &Package{
		Path: resolvedPackage, Digest: "sha256:" + hex.EncodeToString(digest[:]),
		Manifest: manifest, payload: payload,
	}, nil
}

func InspectArtifactRef(catalogRoot, reference string) (*Package, error) {
	if !filepath.IsAbs(catalogRoot) || filepath.Clean(catalogRoot) != catalogRoot {
		return nil, errors.New("plugin catalog root must be a clean absolute path")
	}
	if !strings.HasPrefix(reference, "builtin:") || !digestPattern.MatchString(strings.TrimPrefix(reference, "builtin:")) {
		return nil, errors.New("artifact reference must use builtin:sha256:<digest>")
	}
	entries, err := os.ReadDir(catalogRoot)
	if err != nil {
		return nil, err
	}
	var match *Package
	packageCount := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".opspkg") {
			continue
		}
		packageCount++
		if packageCount > maxCatalogFiles {
			return nil, errors.New("trusted plugin catalog contains too many packages")
		}
		packageInfo, inspectErr := Inspect(filepath.Join(catalogRoot, entry.Name()), catalogRoot)
		if inspectErr != nil {
			return nil, fmt.Errorf("inspect trusted catalog package %q: %w", entry.Name(), inspectErr)
		}
		if packageInfo.Reference() != reference {
			continue
		}
		if match != nil {
			return nil, errors.New("artifact reference is ambiguous in the trusted catalog")
		}
		match = packageInfo
	}
	if match == nil {
		return nil, errors.New("artifact reference was not found in the trusted catalog")
	}
	return match, nil
}

func (p *Package) Reference() string {
	if p == nil || !digestPattern.MatchString(p.Digest) {
		return ""
	}
	return "builtin:" + p.Digest
}

func (p *Package) ValidateExpected(id, version, digest string) error {
	if p == nil || p.Manifest.ID != id || p.Manifest.Version != version || p.Digest != digest {
		return errors.New("plugin package identity, version, or digest does not match the prepared operation")
	}
	return nil
}

func (p *Package) Extract(destination string) error {
	if p == nil || !filepath.IsAbs(destination) || filepath.Clean(destination) != destination {
		return errors.New("plugin extraction destination must be a clean absolute path")
	}
	if err := os.MkdirAll(destination, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(destination, 0o755); err != nil {
		return err
	}
	reader, err := gzip.NewReader(bytes.NewReader(p.payload))
	if err != nil {
		return err
	}
	defer reader.Close()
	archive := tar.NewReader(reader)
	for {
		header, nextErr := archive.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return nextErr
		}
		name, nameErr := safeArchiveName(header.Name)
		if nameErr != nil {
			return nameErr
		}
		target := filepath.Join(destination, filepath.FromSlash(name))
		switch header.Typeflag {
		case tar.TypeDir:
			if err := ensurePublicDirectories(destination, target); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || header.Size > maxFileBytes {
				return errors.New("plugin archive contains an oversized file")
			}
			if err := ensurePublicDirectories(destination, filepath.Dir(target)); err != nil {
				return err
			}
			mode := os.FileMode(0o644)
			if header.Mode&0o111 != 0 {
				mode = 0o755
			}
			file, openErr := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
			if openErr != nil {
				return openErr
			}
			_, copyErr := io.CopyN(file, archive, header.Size)
			syncErr := file.Sync()
			closeErr := file.Close()
			if copyErr != nil {
				return copyErr
			}
			if syncErr != nil {
				return syncErr
			}
			if closeErr != nil {
				return closeErr
			}
			if err := os.Chmod(target, mode); err != nil {
				return err
			}
		default:
			return fmt.Errorf("plugin archive entry %q has unsupported type %d", name, header.Typeflag)
		}
	}
	return nil
}

func ensurePublicDirectories(root, target string) error {
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("plugin directory escapes extraction root")
	}
	current := root
	if err := os.Chmod(current, 0o755); err != nil {
		return err
	}
	if relative == "." {
		return nil
	}
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		if err := os.MkdirAll(current, 0o755); err != nil {
			return err
		}
		if err := os.Chmod(current, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func inspectArchive(payload []byte) (archiveInfo, error) {
	reader, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return archiveInfo{}, errors.New("plugin package is not a gzip tar archive")
	}
	defer reader.Close()
	archive := tar.NewReader(reader)
	seen := make(map[string]struct{})
	result := archiveInfo{regularFiles: make(map[string]os.FileMode)}
	var total int64
	for count := 0; ; count++ {
		if count >= maxFiles {
			return archiveInfo{}, errors.New("plugin archive contains too many entries")
		}
		header, nextErr := archive.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return archiveInfo{}, nextErr
		}
		name, nameErr := safeArchiveName(header.Name)
		if nameErr != nil {
			return archiveInfo{}, nameErr
		}
		if _, exists := seen[name]; exists {
			return archiveInfo{}, fmt.Errorf("duplicate plugin archive entry %q", name)
		}
		seen[name] = struct{}{}
		if header.Typeflag != tar.TypeDir && header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return archiveInfo{}, fmt.Errorf("plugin archive entry %q has an unsupported type", name)
		}
		if header.Size < 0 || header.Size > maxFileBytes {
			return archiveInfo{}, errors.New("plugin archive contains an oversized file")
		}
		total += header.Size
		if total > maxPackageBytes {
			return archiveInfo{}, errors.New("plugin archive expands beyond its size limit")
		}
		if header.Typeflag == tar.TypeReg || header.Typeflag == tar.TypeRegA {
			result.regularFiles[name] = os.FileMode(header.Mode).Perm()
		}
		if name == "manifest.json" {
			if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
				return archiveInfo{}, errors.New("plugin manifest must be a regular file")
			}
			result.manifest, err = io.ReadAll(io.LimitReader(archive, 128*1024+1))
			if err != nil || len(result.manifest) > 128*1024 {
				return archiveInfo{}, errors.New("plugin manifest exceeds its size limit")
			}
		}
	}
	if len(result.manifest) == 0 {
		return archiveInfo{}, errors.New("plugin archive has no root manifest.json")
	}
	return result, nil
}

func safeArchiveName(value string) (string, error) {
	value = strings.TrimPrefix(value, "./")
	clean := path.Clean(value)
	if clean == "." || clean == "" || path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") || strings.ContainsRune(clean, '\\') {
		return "", fmt.Errorf("unsafe plugin archive path %q", value)
	}
	return clean, nil
}

func parseManifest(payload []byte) (Manifest, error) {
	var header struct {
		SchemaVersion int `json:"schemaVersion"`
	}
	if err := json.Unmarshal(payload, &header); err != nil {
		return Manifest{}, fmt.Errorf("decode plugin manifest header: %w", err)
	}
	switch header.SchemaVersion {
	case 1:
		return parseAdapterManifest(payload)
	case 2:
		return parseManagedWorkloadManifest(payload)
	default:
		return Manifest{}, errors.New("plugin manifest has an unsupported schema version")
	}
}

func parseAdapterManifest(payload []byte) (Manifest, error) {
	fields, err := requireExactJSONFields(payload, "plugin manifest", []string{
		"schemaVersion", "id", "kind", "version", "publisher", "coreProtocol", "entrypoint",
		"description", "capabilities", "secrets", "setupOperations",
	})
	if err != nil {
		return Manifest{}, err
	}
	if _, err := requireExactJSONFields(fields["capabilities"], "plugin capabilities", []string{
		"inboundText", "verifiedSender", "privateConversation", "proactiveDelivery", "approvalIntent", "streaming",
	}); err != nil {
		return Manifest{}, err
	}
	var wire adapterManifestWire
	if err := strictDecodeManifest(payload, &wire); err != nil {
		return Manifest{}, err
	}
	if wire.SchemaVersion != 1 || wire.Kind != "im-adapter" || wire.CoreProtocol != 1 ||
		!adapterIDPattern.MatchString(wire.ID) || len(wire.Version) > 96 || !versionPattern.MatchString(wire.Version) ||
		wire.Publisher == "" || len(wire.Publisher) > 160 || wire.Description == "" || len(wire.Description) > 2048 {
		return Manifest{}, errors.New("plugin manifest has unsupported identity or protocol fields")
	}
	entrypoint, entrypointErr := safeArchiveName(wire.Entrypoint)
	if entrypointErr != nil || entrypoint != wire.Entrypoint || len(wire.Entrypoint) > 512 ||
		!adapterEntrypointPattern.MatchString(wire.Entrypoint) || hasUnsafePathSegment(wire.Entrypoint) {
		return Manifest{}, errors.New("plugin manifest entrypoint must be a normalized package-relative path")
	}
	if wire.Secrets == nil || len(wire.Secrets) > 16 {
		return Manifest{}, errors.New("plugin manifest secrets must contain at most 16 entries")
	}
	seenSecrets := make(map[string]struct{}, len(wire.Secrets))
	for _, secret := range wire.Secrets {
		if !secretPattern.MatchString(secret) {
			return Manifest{}, errors.New("plugin manifest contains an invalid secret name")
		}
		if _, exists := seenSecrets[secret]; exists {
			return Manifest{}, errors.New("plugin manifest contains duplicate secret names")
		}
		seenSecrets[secret] = struct{}{}
	}
	if wire.SetupOperations == nil || len(wire.SetupOperations) > len(adapterSetupOperations) {
		return Manifest{}, errors.New("plugin manifest setupOperations exceeds its limit")
	}
	seenOperations := make(map[string]struct{}, len(wire.SetupOperations))
	for _, operation := range wire.SetupOperations {
		if _, ok := adapterSetupOperations[operation]; !ok {
			return Manifest{}, errors.New("plugin manifest contains an unsupported setup operation")
		}
		if _, exists := seenOperations[operation]; exists {
			return Manifest{}, errors.New("plugin manifest contains duplicate setup operations")
		}
		seenOperations[operation] = struct{}{}
	}
	if len(wire.Secrets) > 0 {
		if _, ok := seenOperations["credential.install"]; !ok {
			return Manifest{}, errors.New("plugins declaring secrets must request credential.install")
		}
	}
	capabilities := wire.Capabilities
	return Manifest{
		SchemaVersion: wire.SchemaVersion, ID: wire.ID, Kind: wire.Kind, Version: wire.Version,
		Publisher: wire.Publisher, CoreProtocol: wire.CoreProtocol, Description: wire.Description,
		Entrypoint: wire.Entrypoint, Capabilities: &capabilities, Secrets: wire.Secrets,
		SetupOperations: wire.SetupOperations,
	}, nil
}

func parseManagedWorkloadManifest(payload []byte) (Manifest, error) {
	fields, err := requireExactJSONFields(payload, "plugin manifest", []string{
		"schemaVersion", "id", "kind", "version", "publisher", "coreProtocol", "description", "workload",
	})
	if err != nil {
		return Manifest{}, err
	}
	workloadFields, err := requireExactJSONFields(fields["workload"], "managed workload", []string{
		"runtime", "imageRepository", "imageDigest", "containerName", "containerCommand", "expectedEntrypoint",
		"expectedUser", "processPolicy", "containerPort", "hostPort", "dataMountTarget", "uid", "gid", "resources", "capAdd",
		"literalEnvironment", "credentialEnvironment", "directories", "files", "containerExecChecks",
	})
	if err != nil {
		return Manifest{}, err
	}
	if _, err := requireExactJSONFields(workloadFields["resources"], "managed workload resources", []string{
		"memoryBytes", "nanoCpus", "pidsLimit", "shmBytes",
	}); err != nil {
		return Manifest{}, err
	}
	if _, err := requireExactJSONFields(workloadFields["processPolicy"], "managed workload process policy", []string{
		"runtimeUser", "allowedRuntimeCommands", "requiredRuntimeCommands", "allowedRootCommands",
	}); err != nil {
		return Manifest{}, err
	}
	var wire workloadManifestWire
	if err := strictDecodeManifest(payload, &wire); err != nil {
		return Manifest{}, err
	}
	if wire.SchemaVersion != 2 || wire.Kind != "managed-workload" || wire.CoreProtocol != 1 ||
		!workloadIDPattern.MatchString(wire.ID) || len(wire.Version) > 96 || !versionPattern.MatchString(wire.Version) ||
		wire.Publisher == "" || len(wire.Publisher) > 160 || wire.Description == "" || len(wire.Description) > 2048 {
		return Manifest{}, errors.New("managed workload manifest has unsupported identity or protocol fields")
	}
	if err := validateManagedWorkload(wire.Workload); err != nil {
		return Manifest{}, err
	}
	workload := wire.Workload
	return Manifest{
		SchemaVersion: wire.SchemaVersion, ID: wire.ID, Kind: wire.Kind, Version: wire.Version,
		Publisher: wire.Publisher, CoreProtocol: wire.CoreProtocol, Description: wire.Description,
		Workload: &workload,
	}, nil
}

func validateManagedWorkload(workload ManagedWorkload) error {
	if workload.Runtime != "docker" || !imageRepoPattern.MatchString(workload.ImageRepository) || len(workload.ImageRepository) > 255 ||
		!digestPattern.MatchString(workload.ImageDigest) || !containerPattern.MatchString(workload.ContainerName) ||
		(workload.ExpectedUser != "root" && !userPattern.MatchString(workload.ExpectedUser)) {
		return errors.New("managed workload has an invalid runtime or container identity")
	}
	if err := validateArgv(workload.ContainerCommand, "containerCommand", 32); err != nil {
		return err
	}
	if err := validateArgv(workload.ExpectedEntrypoint, "expectedEntrypoint", 16); err != nil {
		return err
	}
	if !cleanContainerPath(workload.ExpectedEntrypoint[0]) {
		return errors.New("managed workload expectedEntrypoint must start with a clean absolute container path")
	}
	if workload.ContainerPort < 1 || workload.ContainerPort > 65535 || workload.HostPort < 1 || workload.HostPort > 65535 {
		return errors.New("managed workload ports must be between 1 and 65535")
	}
	if !cleanContainerPath(workload.DataMountTarget) || workload.DataMountTarget == "/" {
		return errors.New("managed workload dataMountTarget must be a clean absolute container path")
	}
	if workload.UID < 1 || workload.UID > 65535 || workload.GID < 1 || workload.GID > 65535 {
		return errors.New("managed workload uid and gid must be between 1 and 65535")
	}
	runtimeUser := fmt.Sprintf("%d:%d", workload.UID, workload.GID)
	if workload.ExpectedUser != "root" && workload.ExpectedUser != runtimeUser {
		return errors.New("managed workload expectedUser must be root or match uid:gid")
	}
	if workload.ProcessPolicy.RuntimeUser != runtimeUser {
		return errors.New("managed workload processPolicy.runtimeUser must match uid:gid")
	}
	if err := validateWorkloadProcessPolicy(workload.ExpectedUser, workload.ProcessPolicy); err != nil {
		return err
	}
	resources := workload.Resources
	if resources.MemoryBytes < 64*1024*1024 || resources.MemoryBytes > 128*1024*1024*1024 ||
		resources.NanoCPUs < 100_000_000 || resources.NanoCPUs > 64_000_000_000 ||
		resources.PidsLimit < 16 || resources.PidsLimit > 65536 ||
		resources.ShmBytes < 1024*1024 || resources.ShmBytes > 16*1024*1024*1024 || resources.ShmBytes > resources.MemoryBytes {
		return errors.New("managed workload resource limits are outside the supported bounds")
	}
	if workload.CapAdd == nil || len(workload.CapAdd) > len(safeContainerCapabilities) {
		return errors.New("managed workload capAdd exceeds its limit")
	}
	seenCaps := make(map[string]struct{}, len(workload.CapAdd))
	for _, capability := range workload.CapAdd {
		if _, ok := safeContainerCapabilities[capability]; !ok {
			return fmt.Errorf("managed workload capability %q is not in the safe subset", capability)
		}
		if _, exists := seenCaps[capability]; exists {
			return errors.New("managed workload capAdd contains duplicates")
		}
		seenCaps[capability] = struct{}{}
	}
	if err := validateWorkloadEnvironment(workload.LiteralEnvironment, workload.CredentialEnvironment); err != nil {
		return err
	}
	if workload.Directories == nil || len(workload.Directories) > 64 || workload.Files == nil || len(workload.Files) > 64 {
		return errors.New("managed workload static filesystem declarations exceed their limits")
	}
	seenTargets := make(map[string]struct{}, len(workload.Directories)+len(workload.Files))
	for _, directory := range workload.Directories {
		if !pathWithinMount(directory.Path, workload.DataMountTarget) || !safeMode(directory.Mode, true) {
			return errors.New("managed workload contains an invalid static directory")
		}
		if _, exists := seenTargets[directory.Path]; exists {
			return errors.New("managed workload contains duplicate static paths")
		}
		seenTargets[directory.Path] = struct{}{}
	}
	for _, file := range workload.Files {
		source, sourceErr := safeArchiveName(file.Source)
		if sourceErr != nil || source != file.Source || file.Source == "manifest.json" || len(file.Source) > 512 ||
			!pathWithinMount(file.Path, workload.DataMountTarget) || !safeMode(file.Mode, false) {
			return errors.New("managed workload contains an invalid static file")
		}
		if _, exists := seenTargets[file.Path]; exists {
			return errors.New("managed workload contains duplicate static paths")
		}
		seenTargets[file.Path] = struct{}{}
	}
	if len(workload.ContainerExecChecks) == 0 || len(workload.ContainerExecChecks) > 16 {
		return errors.New("managed workload must contain between 1 and 16 container exec checks")
	}
	for _, check := range workload.ContainerExecChecks {
		if err := validateArgv(check.Argv, "containerExecChecks.argv", 32); err != nil {
			return err
		}
		base := path.Base(check.Argv[0])
		if base == "sh" || base == "bash" || base == "dash" || base == "zsh" || base == "env" {
			return errors.New("managed workload checks cannot invoke a shell or env launcher")
		}
		if check.OutputContains == "" || len(check.OutputContains) > 1024 || strings.ContainsAny(check.OutputContains, "\x00\r\n") {
			return errors.New("managed workload check outputContains is invalid")
		}
	}
	return nil
}

func validateWorkloadProcessPolicy(expectedUser string, policy WorkloadProcessPolicy) error {
	if len(policy.AllowedRuntimeCommands) == 0 || len(policy.AllowedRuntimeCommands) > 32 ||
		len(policy.RequiredRuntimeCommands) == 0 || len(policy.RequiredRuntimeCommands) > 16 ||
		len(policy.AllowedRootCommands) > 32 {
		return errors.New("managed workload process policy exceeds its limits")
	}
	allowedRuntime := make(map[string]struct{}, len(policy.AllowedRuntimeCommands))
	for _, command := range policy.AllowedRuntimeCommands {
		if !processCommandPattern.MatchString(command) {
			return errors.New("managed workload process policy contains an invalid runtime command")
		}
		if _, duplicate := allowedRuntime[command]; duplicate {
			return errors.New("managed workload process policy contains duplicate runtime commands")
		}
		allowedRuntime[command] = struct{}{}
	}
	seenRequired := make(map[string]struct{}, len(policy.RequiredRuntimeCommands))
	for _, command := range policy.RequiredRuntimeCommands {
		if _, ok := allowedRuntime[command]; !ok {
			return errors.New("managed workload required runtime commands must be allowed")
		}
		if _, duplicate := seenRequired[command]; duplicate {
			return errors.New("managed workload process policy contains duplicate required commands")
		}
		seenRequired[command] = struct{}{}
	}
	seenRoot := make(map[string]struct{}, len(policy.AllowedRootCommands))
	for _, command := range policy.AllowedRootCommands {
		if !processCommandPattern.MatchString(command) {
			return errors.New("managed workload process policy contains an invalid root command")
		}
		if _, duplicate := seenRoot[command]; duplicate {
			return errors.New("managed workload process policy contains duplicate root commands")
		}
		seenRoot[command] = struct{}{}
	}
	if expectedUser == "root" && len(policy.AllowedRootCommands) == 0 {
		return errors.New("root-initialized managed workloads must explicitly allow bounded root supervisor commands")
	}
	if expectedUser != "root" && len(policy.AllowedRootCommands) != 0 {
		return errors.New("non-root managed workloads cannot allow root processes")
	}
	return nil
}

func validateWorkloadEnvironment(literal, credentials map[string]string) error {
	if literal == nil || len(literal) > 32 || credentials == nil || len(credentials) > 16 {
		return errors.New("managed workload environment declarations exceed their limits")
	}
	usedEnvironment := make(map[string]struct{}, len(literal)+len(credentials))
	for name, value := range literal {
		if !environmentPattern.MatchString(name) || len(value) > 512 || strings.ContainsAny(value, "\x00\r\n") || looksSensitiveEnvironment(name) {
			return errors.New("managed workload contains an invalid or secret-like literal environment value")
		}
		usedEnvironment[name] = struct{}{}
	}
	for slot, name := range credentials {
		if !secretPattern.MatchString(slot) || !environmentPattern.MatchString(name) {
			return errors.New("managed workload credentialEnvironment contains an invalid slot or environment name")
		}
		if _, exists := usedEnvironment[name]; exists {
			return errors.New("managed workload environment targets must be unique")
		}
		usedEnvironment[name] = struct{}{}
	}
	return nil
}

func validateArgv(values []string, label string, maximum int) error {
	if len(values) == 0 || len(values) > maximum {
		return fmt.Errorf("managed workload %s must contain between 1 and %d arguments", label, maximum)
	}
	total := 0
	for _, value := range values {
		total += len(value)
		if value == "" || len(value) > 512 || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("managed workload %s contains an invalid argument", label)
		}
	}
	if total > 4096 {
		return fmt.Errorf("managed workload %s exceeds its total size limit", label)
	}
	return nil
}

func cleanContainerPath(value string) bool {
	return len(value) >= 2 && len(value) <= 512 && path.IsAbs(value) && path.Clean(value) == value &&
		!strings.ContainsAny(value, "\\\x00\r\n")
}

func pathWithinMount(value, mount string) bool {
	return cleanContainerPath(value) && cleanContainerPath(mount) && value != mount && strings.HasPrefix(value, mount+"/")
}

func safeMode(value string, directory bool) bool {
	if !modePattern.MatchString(value) {
		return false
	}
	parsed, err := strconv.ParseUint(value, 8, 32)
	if err != nil || parsed&0o022 != 0 {
		return false
	}
	if directory {
		return parsed&0o500 == 0o500
	}
	return parsed&0o400 == 0o400
}

func looksSensitiveEnvironment(name string) bool {
	for _, marker := range []string{"KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

func hasUnsafePathSegment(value string) bool {
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func requireExactJSONFields(payload []byte, label string, allowed []string) (map[string]json.RawMessage, error) {
	var values map[string]json.RawMessage
	if err := json.Unmarshal(payload, &values); err != nil || values == nil {
		return nil, fmt.Errorf("%s must be a JSON object", label)
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = struct{}{}
		value, ok := values[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, fmt.Errorf("%s is missing required field %q", label, key)
		}
	}
	for key := range values {
		if _, ok := allowedSet[key]; !ok {
			return nil, fmt.Errorf("%s contains unknown field %q", label, key)
		}
	}
	return values, nil
}

func strictDecodeManifest(payload []byte, target interface{}) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode plugin manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("decode plugin manifest: trailing value")
	}
	return nil
}
