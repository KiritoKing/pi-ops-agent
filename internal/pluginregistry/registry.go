package pluginregistry

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	RegistrationAPIVersion = "agentd.plugin-registration/v1"
	stateSchemaVersion     = 1
	invocationLeaseMode    = 0o640
)

func sharedDirectoryMode() os.FileMode {
	if runtime.GOOS == "linux" {
		return os.FileMode(0o750) | os.ModeSetgid
	}
	return 0o750
}

func stagingDirectoryMode() os.FileMode {
	if runtime.GOOS == "linux" {
		return os.FileMode(0o700) | os.ModeSetgid
	}
	return 0o700
}

var digestPattern = regexpDigest()

type Limits struct {
	MaxEntries       int
	MaxDepth         int
	MaxFileBytes     int64
	MaxTotalBytes    int64
	MaxManifestBytes int64
}

var defaultLimits = Limits{
	MaxEntries:       512,
	MaxDepth:         24,
	MaxFileBytes:     8 * 1024 * 1024,
	MaxTotalBytes:    32 * 1024 * 1024,
	MaxManifestBytes: 64 * 1024,
}

type Grant struct {
	PluginID        string
	Kind            Kind
	Digest          string
	RequestedScopes []string
	ApprovedBy      string
	ApprovedAt      time.Time
}

type Inspection struct {
	Digest   string   `json:"digest"`
	Manifest Manifest `json:"manifest"`
	Files    int      `json:"files"`
	Bytes    int64    `json:"bytes"`
	Path     string   `json:"path"`
}

type Registration struct {
	APIVersion      string    `json:"apiVersion"`
	SchemaVersion   int       `json:"schemaVersion"`
	PluginID        string    `json:"pluginId"`
	Kind            Kind      `json:"kind"`
	Version         string    `json:"version"`
	Publisher       string    `json:"publisher"`
	Digest          string    `json:"digest"`
	Capabilities    []string  `json:"capabilities"`
	RequestedScopes []string  `json:"requestedScopes"`
	ApprovedBy      string    `json:"approvedBy"`
	ApprovedAt      time.Time `json:"approvedAt"`
	SnapshotPath    string    `json:"-"`
}

// RuntimeRegistration is the revalidated, read-only view consumed by an
// isolated plugin host. SnapshotPath and Entrypoint are deliberately omitted
// from the durable grant record: they are derived again from the immutable
// snapshot every time this view is requested.
type RuntimeRegistration struct {
	Registration
	Entrypoint   string `json:"entrypoint"`
	SnapshotPath string `json:"snapshotPath"`
}

type Registry struct {
	root     string
	limits   Limits
	ownerUID int
	groupGID int
	leaseGID int
	mu       sync.RWMutex
}

// InvocationLease pins one active plugin registration across an isolated
// workload invocation. Registry mutations take the corresponding exclusive
// filesystem lock, so a current-pointer transition cannot cross a privileged
// provider call made under the old digest.
type InvocationLease struct {
	file     *os.File
	once     sync.Once
	closeErr error
}

func (lease *InvocationLease) Close() error {
	if lease == nil {
		return nil
	}
	lease.once.Do(func() {
		if lease.file == nil {
			return
		}
		unlockErr := syscall.Flock(int(lease.file.Fd()), syscall.LOCK_UN)
		closeErr := lease.file.Close()
		if unlockErr != nil {
			lease.closeErr = unlockErr
		} else {
			lease.closeErr = closeErr
		}
	})
	return lease.closeErr
}

func Open(root string) (*Registry, error) {
	return openWithLimits(root, defaultLimits)
}

func openWithLimits(root string, limits Limits) (*Registry, error) {
	if !cleanAbsolute(root) {
		return nil, errors.New("plugin registry root must be a clean absolute path")
	}
	if err := validateLimits(limits); err != nil {
		return nil, err
	}
	if err := ensureDirectory(root, sharedDirectoryMode()); err != nil {
		return nil, err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	ownerUID, groupGID, err := numericOwner(rootInfo)
	if err != nil || (runtime.GOOS == "linux" && rootInfo.Mode()&os.ModeSetgid == 0) {
		return nil, errors.New("plugin registry root must be a setgid directory with a stable owner and reader group")
	}
	registry := &Registry{
		root: root, limits: limits, ownerUID: ownerUID, groupGID: groupGID,
	}
	for _, directory := range []string{
		filepath.Join(root, "snapshots"),
		filepath.Join(root, "snapshots", "sha256"),
		filepath.Join(root, "plugins"),
	} {
		if err := registry.ensureSharedDirectory(directory); err != nil {
			return nil, err
		}
	}
	if err := registry.ensurePrivateInvocationLeaseDirectory(); err != nil {
		return nil, err
	}
	// Release upgrades may encounter registrations created before invocation
	// leases existed. Only the registry owner may materialize those root-owned
	// lock files; non-owner runtime readers fail closed if installation did not
	// perform this migration first.
	if os.Geteuid() == ownerUID {
		if err := registry.ensureExistingInvocationLeaseFiles(); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

func (r *Registry) InspectSource(source string) (Inspection, error) {
	if r == nil {
		return Inspection{}, errors.New("plugin registry is nil")
	}
	if err := r.validateSourcePath(source); err != nil {
		return Inspection{}, err
	}
	result, err := scanTree(source, "", r.limits)
	if err != nil {
		return Inspection{}, err
	}
	result.Path = source
	return result, nil
}

// Register snapshots source and activates it only when grant exactly matches
// the observed digest and requested scopes. A source mutation after review is
// therefore fail-closed and leaves the previous current pointer untouched.
func (r *Registry) Register(source string, grant Grant) (Registration, error) {
	if r == nil {
		return Registration{}, errors.New("plugin registry is nil")
	}
	if err := r.validateSourcePath(source); err != nil {
		return Registration{}, err
	}
	if err := validatePluginID(grant.PluginID); err != nil {
		return Registration{}, err
	}
	lease, err := r.acquireInvocationLease(grant.PluginID, true, true)
	if err != nil {
		return Registration{}, err
	}
	defer lease.Close()
	r.mu.Lock()
	defer r.mu.Unlock()

	staging, err := os.MkdirTemp(filepath.Join(r.root, "snapshots", "sha256"), ".incoming-")
	if err != nil {
		return Registration{}, err
	}
	defer removeStagingTree(staging)
	// Keep the staging tree owner-only while retaining setgid inheritance. Its
	// files become group-readable only after the complete digest has been
	// verified and the tree is made immutable.
	if err := os.Chmod(staging, stagingDirectoryMode()); err != nil {
		return Registration{}, err
	}
	inspection, err := scanTree(source, staging, r.limits)
	if err != nil {
		return Registration{}, err
	}
	if err := validateGrant(grant, inspection.Manifest, inspection.Digest); err != nil {
		return Registration{}, err
	}
	if err := makeSnapshotReadOnly(staging); err != nil {
		return Registration{}, err
	}
	destination, err := r.snapshotPath(inspection.Digest)
	if err != nil {
		return Registration{}, err
	}
	if err := r.commitSnapshot(staging, destination, inspection.Digest); err != nil {
		return Registration{}, err
	}
	return r.activateLocked(inspection.Manifest.ID, inspection.Digest, grant)
}

func (r *Registry) Activate(pluginID, digest string, grant Grant) (Registration, error) {
	if r == nil {
		return Registration{}, errors.New("plugin registry is nil")
	}
	if err := validatePluginID(pluginID); err != nil {
		return Registration{}, err
	}
	lease, err := r.acquireInvocationLease(pluginID, true, true)
	if err != nil {
		return Registration{}, err
	}
	defer lease.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.activateLocked(pluginID, digest, grant)
}

// Deactivate removes only the active pointer bound to the exact approved
// digest. Content-addressed snapshots and registrations are retained for
// audit and recovery.
func (r *Registry) Deactivate(pluginID, digest string) error {
	if r == nil {
		return errors.New("plugin registry is nil")
	}
	if err := validatePluginID(pluginID); err != nil {
		return err
	}
	if !digestPattern.MatchString(digest) {
		return errors.New("plugin digest must use sha256:<64 lowercase hex characters>")
	}
	lease, err := r.acquireInvocationLease(pluginID, true, true)
	if err != nil {
		return err
	}
	defer lease.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	pluginDirectory := filepath.Join(r.root, "plugins", pluginID)
	currentPath := filepath.Join(pluginDirectory, "current")
	target, err := os.Readlink(currentPath)
	if err != nil {
		return err
	}
	expectedSnapshot, err := r.snapshotPath(digest)
	if err != nil {
		return err
	}
	expectedTarget, err := filepath.Rel(pluginDirectory, expectedSnapshot)
	if err != nil || target != expectedTarget {
		return errors.New("plugin current pointer no longer matches the rollback digest")
	}
	if err := os.Remove(currentPath); err != nil {
		return err
	}
	return syncDirectory(pluginDirectory)
}

// LeaseRuntimeCurrent takes a non-blocking shared lease and then resolves the
// active immutable runtime view under that lease. The expected digest is
// mandatory: a session opened under A must not silently lease B after an
// update. Callers must keep the returned lease open until every provider call,
// signed status check, and local result handling for the invocation is done.
func (r *Registry) LeaseRuntimeCurrent(pluginID, expectedDigest string) (RuntimeRegistration, *InvocationLease, error) {
	if r == nil {
		return RuntimeRegistration{}, nil, errors.New("plugin registry is nil")
	}
	if err := validatePluginID(pluginID); err != nil {
		return RuntimeRegistration{}, nil, err
	}
	if !digestPattern.MatchString(expectedDigest) {
		return RuntimeRegistration{}, nil, errors.New("plugin digest must use sha256:<64 lowercase hex characters>")
	}
	lease, err := r.acquireInvocationLease(pluginID, false, false)
	if err != nil {
		return RuntimeRegistration{}, nil, err
	}
	registration, err := r.RuntimeCurrent(pluginID)
	if err != nil {
		_ = lease.Close()
		return RuntimeRegistration{}, nil, err
	}
	if registration.Digest != expectedDigest {
		_ = lease.Close()
		return RuntimeRegistration{}, nil, errors.New("plugin current registration changed before the invocation lease was acquired")
	}
	return registration, lease, nil
}

// PinRuntimeCurrentOnInheritedFile applies the shared flock to an already-open
// descriptor inherited from the runtime process. flock is attached to the
// open file description, so the short validator process may close its duplicate
// after emitting the registration while the runtime's original descriptor
// continues to hold the lease. On success this method deliberately does not
// unlock file; the owning runtime releases the lease by closing its descriptor.
func (r *Registry) PinRuntimeCurrentOnInheritedFile(
	pluginID, expectedDigest string,
	file *os.File,
) (RuntimeRegistration, error) {
	if r == nil {
		return RuntimeRegistration{}, errors.New("plugin registry is nil")
	}
	if file == nil {
		return RuntimeRegistration{}, errors.New("plugin invocation lease descriptor is missing")
	}
	if err := validatePluginID(pluginID); err != nil {
		return RuntimeRegistration{}, err
	}
	if !digestPattern.MatchString(expectedDigest) {
		return RuntimeRegistration{}, errors.New("plugin digest must use sha256:<64 lowercase hex characters>")
	}
	path, err := r.invocationLeasePath(pluginID)
	if err != nil {
		return RuntimeRegistration{}, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return RuntimeRegistration{}, err
	}
	if err := r.validateInvocationLeaseFile(path, before); err != nil {
		return RuntimeRegistration{}, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return RuntimeRegistration{}, errors.New("inherited plugin invocation lease does not match the registry lock file")
	}
	if err := r.validateInvocationLeaseFile(path, opened); err != nil {
		return RuntimeRegistration{}, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return RuntimeRegistration{}, errors.New("plugin current mutation is in progress; retry the workload invocation")
		}
		return RuntimeRegistration{}, err
	}
	registration, err := r.RuntimeCurrent(pluginID)
	if err != nil {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		return RuntimeRegistration{}, err
	}
	if registration.Digest != expectedDigest {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		return RuntimeRegistration{}, errors.New("plugin current registration changed before the invocation lease was acquired")
	}
	return registration, nil
}

func (r *Registry) Current(pluginID string) (Registration, error) {
	if r == nil {
		return Registration{}, errors.New("plugin registry is nil")
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if err := validatePluginID(pluginID); err != nil {
		return Registration{}, err
	}
	pluginDirectory := filepath.Join(r.root, "plugins", pluginID)
	currentPath := filepath.Join(pluginDirectory, "current")
	target, err := os.Readlink(currentPath)
	if err != nil {
		return Registration{}, err
	}
	if filepath.IsAbs(target) || filepath.Clean(target) != target {
		return Registration{}, errors.New("plugin current pointer is not a normalized relative link")
	}
	digest := "sha256:" + filepath.Base(target)
	snapshotPath, err := r.snapshotPath(digest)
	if err != nil {
		return Registration{}, errors.New("plugin current pointer has an invalid digest target")
	}
	expectedTarget, err := filepath.Rel(pluginDirectory, snapshotPath)
	if err != nil || target != expectedTarget {
		return Registration{}, errors.New("plugin current pointer escapes the registry snapshot store")
	}
	registration, err := r.readRegistration(pluginID, digest)
	if err != nil {
		return Registration{}, err
	}
	inspection, err := inspectSnapshot(snapshotPath, r.limits)
	if err != nil {
		return Registration{}, fmt.Errorf("verify current plugin snapshot: %w", err)
	}
	if inspection.Digest != digest || !registrationMatchesManifest(registration, inspection.Manifest) {
		return Registration{}, errors.New("plugin current snapshot no longer matches its registration")
	}
	registration.SnapshotPath = snapshotPath
	return registration, nil
}

// RuntimeCurrent performs the same current-pointer and snapshot revalidation
// as Current, then returns the entrypoint observed in that exact immutable
// snapshot. Callers must still revalidate Current before each privileged
// provider call; this view never grants authority by itself.
func (r *Registry) RuntimeCurrent(pluginID string) (RuntimeRegistration, error) {
	registration, err := r.Current(pluginID)
	if err != nil {
		return RuntimeRegistration{}, err
	}
	inspection, err := inspectSnapshot(registration.SnapshotPath, r.limits)
	if err != nil {
		return RuntimeRegistration{}, fmt.Errorf("verify runtime plugin snapshot: %w", err)
	}
	if inspection.Digest != registration.Digest ||
		!registrationMatchesManifest(registration, inspection.Manifest) {
		return RuntimeRegistration{}, errors.New("runtime plugin snapshot no longer matches its registration")
	}
	return RuntimeRegistration{
		Registration: registration,
		Entrypoint:   inspection.Manifest.Entrypoint,
		SnapshotPath: registration.SnapshotPath,
	}, nil
}

// ListRuntime returns a stable, bounded list of active registrations. Every
// item is independently resolved through RuntimeCurrent, so a broken or
// tampered active plugin fails the whole discovery operation closed.
func (r *Registry) ListRuntime(kind Kind) ([]RuntimeRegistration, error) {
	if r == nil {
		return nil, errors.New("plugin registry is nil")
	}
	if kind != KindAdapter && kind != KindWorkload {
		return nil, errors.New("plugin runtime list kind must be adapter or workload")
	}
	pluginsRoot := filepath.Join(r.root, "plugins")
	entries, err := os.ReadDir(pluginsRoot)
	if err != nil {
		return nil, err
	}
	if len(entries) > 128 {
		return nil, errors.New("plugin registry contains too many plugin directories")
	}
	registrations := make([]RuntimeRegistration, 0, len(entries))
	for _, entry := range entries {
		info, infoErr := entry.Info()
		if infoErr != nil {
			return nil, infoErr
		}
		if !entry.IsDir() || info.Mode()&os.ModeSymlink != 0 || validatePluginID(entry.Name()) != nil {
			return nil, fmt.Errorf("plugin registry contains invalid plugin directory %q", entry.Name())
		}
		registration, currentErr := r.RuntimeCurrent(entry.Name())
		if errors.Is(currentErr, os.ErrNotExist) {
			continue
		}
		if currentErr != nil {
			return nil, fmt.Errorf("resolve active plugin %q: %w", entry.Name(), currentErr)
		}
		if registration.Kind == kind {
			registrations = append(registrations, registration)
		}
	}
	slices.SortFunc(registrations, func(left, right RuntimeRegistration) int {
		return strings.Compare(left.PluginID, right.PluginID)
	})
	return registrations, nil
}

func (r *Registry) activateLocked(pluginID, digest string, grant Grant) (Registration, error) {
	if err := validatePluginID(pluginID); err != nil {
		return Registration{}, err
	}
	snapshotPath, err := r.snapshotPath(digest)
	if err != nil {
		return Registration{}, err
	}
	inspection, err := inspectSnapshot(snapshotPath, r.limits)
	if err != nil {
		return Registration{}, fmt.Errorf("verify plugin snapshot: %w", err)
	}
	if inspection.Digest != digest {
		return Registration{}, errors.New("plugin snapshot content does not match its digest path")
	}
	if inspection.Manifest.ID != pluginID {
		return Registration{}, errors.New("plugin snapshot identity does not match activation target")
	}
	if err := validateGrant(grant, inspection.Manifest, digest); err != nil {
		return Registration{}, err
	}

	registration := Registration{
		APIVersion:      RegistrationAPIVersion,
		SchemaVersion:   stateSchemaVersion,
		PluginID:        pluginID,
		Kind:            inspection.Manifest.Kind,
		Version:         inspection.Manifest.Version,
		Publisher:       inspection.Manifest.Publisher,
		Digest:          digest,
		Capabilities:    slices.Clone(inspection.Manifest.Capabilities),
		RequestedScopes: slices.Clone(inspection.Manifest.RequestedScopes),
		ApprovedBy:      grant.ApprovedBy,
		ApprovedAt:      grant.ApprovedAt.UTC(),
		SnapshotPath:    snapshotPath,
	}
	pluginDirectory := filepath.Join(r.root, "plugins", pluginID)
	if err := r.ensureSharedDirectory(pluginDirectory); err != nil {
		return Registration{}, err
	}
	registrationsDirectory := filepath.Join(pluginDirectory, "registrations")
	if err := r.ensureSharedDirectory(registrationsDirectory); err != nil {
		return Registration{}, err
	}
	recordPath := filepath.Join(registrationsDirectory, strings.TrimPrefix(digest, "sha256:")+".json")
	registration, err = r.persistRegistration(recordPath, registration)
	if err != nil {
		return Registration{}, err
	}
	registration.SnapshotPath = snapshotPath
	relativeTarget, err := filepath.Rel(pluginDirectory, snapshotPath)
	if err != nil {
		return Registration{}, err
	}
	if err := atomicSymlink(relativeTarget, filepath.Join(pluginDirectory, "current")); err != nil {
		return Registration{}, err
	}
	return registration, nil
}

func (r *Registry) persistRegistration(path string, registration Registration) (Registration, error) {
	if payload, err := readStateFile(path); err == nil {
		existing, decodeErr := decodeRegistration(payload)
		if decodeErr != nil {
			return Registration{}, fmt.Errorf("existing plugin registration is invalid: %w", decodeErr)
		}
		if existing.PluginID != registration.PluginID || existing.Kind != registration.Kind ||
			existing.Version != registration.Version || existing.Publisher != registration.Publisher ||
			existing.Digest != registration.Digest || !slices.Equal(existing.Capabilities, registration.Capabilities) ||
			!slices.Equal(existing.RequestedScopes, registration.RequestedScopes) {
			return Registration{}, errors.New("existing plugin registration conflicts with the approved snapshot")
		}
		return existing, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return Registration{}, err
	}
	payload, err := json.Marshal(registration)
	if err != nil {
		return Registration{}, err
	}
	payload = append(payload, '\n')
	if err := atomicWrite(path, payload, 0o440); err != nil {
		return Registration{}, err
	}
	return registration, nil
}

func (r *Registry) readRegistration(pluginID, digest string) (Registration, error) {
	path := filepath.Join(r.root, "plugins", pluginID, "registrations", strings.TrimPrefix(digest, "sha256:")+".json")
	payload, err := readStateFile(path)
	if err != nil {
		return Registration{}, err
	}
	registration, err := decodeRegistration(payload)
	if err != nil {
		return Registration{}, err
	}
	if registration.PluginID != pluginID || registration.Digest != digest {
		return Registration{}, errors.New("plugin registration identity does not match its path")
	}
	return registration, nil
}

func readStateFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() < 1 || info.Size() > 64*1024 {
		return nil, errors.New("plugin registry state must be a bounded, non-writable regular file")
	}
	return readStableRegularFile(path, info, 64*1024)
}

func decodeRegistration(payload []byte) (Registration, error) {
	if err := rejectDuplicateJSONKeys(payload); err != nil {
		return Registration{}, err
	}
	var registration Registration
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registration); err != nil {
		return Registration{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Registration{}, errors.New("plugin registration has a trailing JSON value")
	}
	if registration.APIVersion != RegistrationAPIVersion || registration.SchemaVersion != stateSchemaVersion ||
		validatePluginID(registration.PluginID) != nil || (registration.Kind != KindAdapter && registration.Kind != KindWorkload) ||
		!strings.HasPrefix(registration.PluginID, string(registration.Kind)+".") || !versionPattern.MatchString(registration.Version) ||
		!digestPattern.MatchString(registration.Digest) || !publisherPattern.MatchString(registration.Publisher) ||
		strings.Contains(registration.Publisher, "..") || strings.Contains(registration.Publisher, "//") ||
		registration.ApprovedAt.IsZero() || !boundedText(registration.ApprovedBy, 256) ||
		validateSortedNames("capabilities", registration.Capabilities, 64) != nil ||
		validateSortedNames("requestedScopes", registration.RequestedScopes, 64) != nil {
		return Registration{}, errors.New("plugin registration has invalid fields")
	}
	return registration, nil
}

func validateGrant(grant Grant, manifest Manifest, digest string) error {
	if grant.PluginID != manifest.ID || grant.Kind != manifest.Kind || grant.Digest != digest ||
		!slices.Equal(grant.RequestedScopes, manifest.RequestedScopes) {
		return errors.New("plugin grant does not exactly match the source digest and requested scopes")
	}
	if grant.ApprovedAt.IsZero() || !boundedText(grant.ApprovedBy, 256) {
		return errors.New("plugin grant has an invalid approver or approval time")
	}
	return nil
}

func registrationMatchesManifest(registration Registration, manifest Manifest) bool {
	return registration.PluginID == manifest.ID && registration.Kind == manifest.Kind &&
		registration.Version == manifest.Version && registration.Publisher == manifest.Publisher &&
		slices.Equal(registration.Capabilities, manifest.Capabilities) &&
		slices.Equal(registration.RequestedScopes, manifest.RequestedScopes)
}

func (r *Registry) validateSourcePath(source string) error {
	if !cleanAbsolute(source) {
		return errors.New("source plugin root must be a clean absolute path")
	}
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("source plugin root must be a real directory")
	}
	resolvedSource, err := filepath.EvalSymlinks(source)
	if err != nil {
		return err
	}
	resolvedRoot, err := filepath.EvalSymlinks(r.root)
	if err != nil {
		return err
	}
	if pathsOverlap(resolvedSource, resolvedRoot) {
		return errors.New("source plugin root and registry root must not overlap")
	}
	return nil
}

func scanTree(source, destination string, limits Limits) (Inspection, error) {
	info, err := os.Lstat(source)
	if err != nil {
		return Inspection{}, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return Inspection{}, errors.New("plugin tree root must be a real directory")
	}
	hasher := sha256.New()
	_, _ = io.WriteString(hasher, "agentd-source-plugin-snapshot-v1\x00")
	state := &scanState{
		hasher: hasher, limits: limits, regularFiles: make(map[string]struct{}),
		directories: map[string]os.FileInfo{source: info},
	}
	err = filepath.WalkDir(source, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current == source {
			return nil
		}
		relative, err := filepath.Rel(source, current)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("plugin tree entry escapes its source root")
		}
		relative = filepath.ToSlash(relative)
		if !safeRelativePath(relative) {
			return fmt.Errorf("plugin tree contains unsafe path %q", relative)
		}
		if strings.Count(relative, "/")+1 > limits.MaxDepth {
			return errors.New("plugin tree exceeds its maximum depth")
		}
		state.entries++
		if state.entries > limits.MaxEntries {
			return errors.New("plugin tree contains too many entries")
		}
		entryInfo, err := entry.Info()
		if err != nil {
			return err
		}
		mode := entryInfo.Mode()
		if mode&os.ModeSymlink != 0 {
			return fmt.Errorf("plugin tree symlink %q is not allowed", relative)
		}
		switch {
		case mode.IsDir():
			state.directories[current] = entryInfo
			writeHashHeader(state.hasher, 'D', relative, false, 0)
			if destination != "" {
				if err := os.Mkdir(filepath.Join(destination, filepath.FromSlash(relative)), 0o700); err != nil {
					return err
				}
			}
			return nil
		case mode.IsRegular():
		default:
			return fmt.Errorf("plugin tree entry %q is not a regular file or directory", relative)
		}
		if entryInfo.Size() < 0 || entryInfo.Size() > limits.MaxFileBytes {
			return fmt.Errorf("plugin tree file %q exceeds its size limit", relative)
		}
		state.totalBytes += entryInfo.Size()
		if state.totalBytes > limits.MaxTotalBytes {
			return errors.New("plugin tree exceeds its total size limit")
		}
		payload, err := readStableRegularFile(current, entryInfo, limits.MaxFileBytes)
		if err != nil {
			return fmt.Errorf("read plugin tree file %q: %w", relative, err)
		}
		executable := mode.Perm()&0o111 != 0
		writeHashHeader(state.hasher, 'F', relative, executable, int64(len(payload)))
		if _, err := state.hasher.Write(payload); err != nil {
			return err
		}
		state.files++
		state.regularFiles[relative] = struct{}{}
		if relative == "manifest.json" {
			if int64(len(payload)) > limits.MaxManifestBytes {
				return errors.New("source plugin manifest exceeds its size limit")
			}
			state.manifestPayload = slices.Clone(payload)
		}
		if destination != "" {
			mode := os.FileMode(0o400)
			if executable {
				mode = 0o500
			}
			if err := writeNewFile(filepath.Join(destination, filepath.FromSlash(relative)), payload, mode); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return Inspection{}, err
	}
	for directory, before := range state.directories {
		after, err := os.Lstat(directory)
		if err != nil || !after.IsDir() || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, after) ||
			after.Mode() != before.Mode() || after.ModTime() != before.ModTime() {
			return Inspection{}, errors.New("plugin tree directory changed while snapshotting")
		}
	}
	if len(state.manifestPayload) == 0 {
		return Inspection{}, errors.New("source plugin tree has no root manifest.json")
	}
	manifest, err := parseManifest(state.manifestPayload)
	if err != nil {
		return Inspection{}, err
	}
	if _, ok := state.regularFiles[manifest.Entrypoint]; !ok {
		return Inspection{}, errors.New("source plugin entrypoint is not a regular file in the snapshot")
	}
	digest := state.hasher.Sum(nil)
	return Inspection{
		Digest: "sha256:" + hex.EncodeToString(digest), Manifest: manifest,
		Files: state.files, Bytes: state.totalBytes,
	}, nil
}

type scanState struct {
	hasher          hash.Hash
	limits          Limits
	entries         int
	files           int
	totalBytes      int64
	manifestPayload []byte
	regularFiles    map[string]struct{}
	directories     map[string]os.FileInfo
}

func writeHashHeader(writer io.Writer, kind byte, relative string, executable bool, size int64) {
	_, _ = writer.Write([]byte{kind})
	_ = binary.Write(writer, binary.BigEndian, uint32(len(relative)))
	_, _ = io.WriteString(writer, relative)
	if executable {
		_, _ = writer.Write([]byte{1})
	} else {
		_, _ = writer.Write([]byte{0})
	}
	_ = binary.Write(writer, binary.BigEndian, uint64(size))
}

func readStableRegularFile(path string, before os.FileInfo, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, errors.New("file identity changed while snapshotting")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > maximum || int64(len(payload)) != before.Size() {
		return nil, errors.New("file size changed while snapshotting")
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	pathAfter, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !after.Mode().IsRegular() || !pathAfter.Mode().IsRegular() || !os.SameFile(before, after) ||
		!os.SameFile(before, pathAfter) || after.Size() != before.Size() || after.ModTime() != before.ModTime() {
		return nil, errors.New("file changed while snapshotting")
	}
	return payload, nil
}

func inspectSnapshot(root string, limits Limits) (Inspection, error) {
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return errors.New("plugin snapshot contains an unsupported entry")
		}
		if info.Mode().Perm()&0o222 != 0 {
			return errors.New("plugin snapshot contains a writable entry")
		}
		return nil
	}); err != nil {
		return Inspection{}, err
	}
	return scanTree(root, "", limits)
}

func (r *Registry) commitSnapshot(staging, destination, digest string) error {
	if info, err := os.Lstat(destination); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("plugin snapshot digest path is not a real directory")
		}
		existing, inspectErr := inspectSnapshot(destination, r.limits)
		if inspectErr != nil || existing.Digest != digest {
			return errors.New("existing plugin snapshot does not match its digest path")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(staging, destination); err != nil {
		if info, statErr := os.Lstat(destination); statErr == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			existing, inspectErr := inspectSnapshot(destination, r.limits)
			if inspectErr == nil && existing.Digest == digest {
				return nil
			}
		}
		return err
	}
	if err := syncDirectory(filepath.Dir(destination)); err != nil {
		return err
	}
	return nil
}

func (r *Registry) snapshotPath(digest string) (string, error) {
	if !digestPattern.MatchString(digest) {
		return "", errors.New("plugin digest must use sha256:<64 lowercase hex characters>")
	}
	return filepath.Join(r.root, "snapshots", "sha256", strings.TrimPrefix(digest, "sha256:")), nil
}

func makeSnapshotReadOnly(root string) error {
	var directories []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			directories = append(directories, path)
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			if err != nil {
				return err
			}
			return errors.New("snapshot staging tree contains a non-regular entry")
		}
		mode := os.FileMode(0o440)
		if info.Mode().Perm()&0o100 != 0 {
			mode = 0o550
		}
		return os.Chmod(path, mode)
	})
	if err != nil {
		return err
	}
	for index := len(directories) - 1; index >= 0; index-- {
		if err := syncDirectory(directories[index]); err != nil {
			return err
		}
		if err := os.Chmod(directories[index], 0o550); err != nil {
			return err
		}
	}
	return nil
}

func atomicWrite(path string, payload []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".registration-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func atomicSymlink(target, linkPath string) error {
	directory := filepath.Dir(linkPath)
	temporary, err := os.CreateTemp(directory, ".current-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Remove(temporaryPath); err != nil {
		return err
	}
	defer os.Remove(temporaryPath)
	if err := os.Symlink(target, temporaryPath); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, linkPath); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func writeNewFile(path string, payload []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
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
	return file.Close()
}

func removeStagingTree(root string) {
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err == nil && entry.IsDir() {
			_ = os.Chmod(path, 0o700)
		}
		return nil
	})
	_ = os.RemoveAll(root)
}

func ensureDirectory(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s must be a real directory", path)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s must not be group or world writable", path)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	info, err = os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s must be a newly created real directory", path)
	}
	return os.Chmod(path, mode)
}

func numericOwner(info os.FileInfo) (int, int, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("plugin registry filesystem does not expose Unix ownership")
	}
	return int(stat.Uid), int(stat.Gid), nil
}

func (r *Registry) ensureSharedDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, sharedDirectoryMode()); err != nil {
			return err
		}
		created, statErr := os.Lstat(path)
		if statErr != nil {
			return statErr
		}
		createdUID, createdGID, ownerErr := numericOwner(created)
		if ownerErr != nil {
			return ownerErr
		}
		if runtime.GOOS == "linux" && (createdUID != r.ownerUID || createdGID != r.groupGID) {
			if err := os.Chown(path, r.ownerUID, r.groupGID); err != nil {
				return err
			}
		}
		if err := os.Chmod(path, sharedDirectoryMode()); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	uid, gid, ownerErr := numericOwner(info)
	if ownerErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o750 ||
		(runtime.GOOS == "linux" && (info.Mode()&os.ModeSetgid == 0 ||
			uid != r.ownerUID || gid != r.groupGID)) {
		return fmt.Errorf("%s must be an owner-controlled setgid directory in the registry reader group", path)
	}
	return nil
}

func (r *Registry) ensurePrivateInvocationLeaseDirectory() error {
	path := filepath.Join(r.root, "invocation-leases")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if os.Geteuid() != r.ownerUID {
			return errors.New("private plugin invocation lease directory is missing; complete the root-owned registry migration")
		}
		if r.ownerUID == 0 {
			return errors.New("root registry requires an installer-provisioned private lease directory and broker group")
		}
		leaseGID := os.Getegid()
		if err := os.Mkdir(path, 0o750); err != nil {
			return err
		}
		if err := os.Chown(path, r.ownerUID, leaseGID); err != nil {
			return err
		}
		if err := os.Chmod(path, 0o750); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	uid, gid, ownerErr := numericOwner(info)
	if ownerErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o750 || uid != r.ownerUID ||
		(r.ownerUID == 0 && gid == r.groupGID) {
		return errors.New("plugin invocation leases must be in a root-controlled directory outside the registry reader group")
	}
	r.leaseGID = gid
	return nil
}

func (r *Registry) invocationLeasePath(pluginID string) (string, error) {
	if err := validatePluginID(pluginID); err != nil {
		return "", err
	}
	return filepath.Join(r.root, "invocation-leases", pluginID+".lock"), nil
}

func (r *Registry) ensureExistingInvocationLeaseFiles() error {
	pluginsRoot := filepath.Join(r.root, "plugins")
	entries, err := os.ReadDir(pluginsRoot)
	if err != nil {
		return err
	}
	if len(entries) > 128 {
		return errors.New("plugin registry contains too many plugin directories")
	}
	for _, entry := range entries {
		info, infoErr := entry.Info()
		if infoErr != nil {
			return infoErr
		}
		if !entry.IsDir() || info.Mode()&os.ModeSymlink != 0 || validatePluginID(entry.Name()) != nil {
			return fmt.Errorf("plugin registry contains invalid plugin directory %q", entry.Name())
		}
		if err := r.ensureInvocationLeaseFile(entry.Name()); err != nil {
			return err
		}
	}
	return nil
}

func (r *Registry) ensureInvocationLeaseFile(pluginID string) error {
	path, err := r.invocationLeasePath(pluginID)
	if err != nil {
		return err
	}
	for {
		info, statErr := os.Lstat(path)
		if statErr == nil {
			return r.validateInvocationLeaseFile(path, info)
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
		fd, openErr := syscall.Open(
			path,
			syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,
			invocationLeaseMode,
		)
		if errors.Is(openErr, syscall.EEXIST) {
			continue
		}
		if openErr != nil {
			return openErr
		}
		file := os.NewFile(uintptr(fd), path)
		if file == nil {
			_ = syscall.Close(fd)
			return errors.New("failed to materialize plugin invocation lease file")
		}
		created := true
		defer func() {
			_ = file.Close()
			if created {
				_ = os.Remove(path)
			}
		}()
		if err := file.Chmod(invocationLeaseMode); err != nil {
			return err
		}
		if err := file.Chown(r.ownerUID, r.leaseGID); err != nil {
			return err
		}
		if err := file.Sync(); err != nil {
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
		created = false
		if err := syncDirectory(filepath.Dir(path)); err != nil {
			return err
		}
		info, err = os.Lstat(path)
		if err != nil {
			return err
		}
		return r.validateInvocationLeaseFile(path, info)
	}
}

func (r *Registry) validateInvocationLeaseFile(path string, info os.FileInfo) error {
	uid, gid, ownerErr := numericOwner(info)
	if ownerErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != invocationLeaseMode || uid != r.ownerUID || gid != r.leaseGID {
		return fmt.Errorf("%s must be an owner-controlled regular file in the registry reader group", path)
	}
	return nil
}

func (r *Registry) acquireInvocationLease(pluginID string, exclusive, create bool) (*InvocationLease, error) {
	path, err := r.invocationLeasePath(pluginID)
	if err != nil {
		return nil, err
	}
	if create {
		if os.Geteuid() != r.ownerUID {
			return nil, errors.New("only the plugin registry owner may create an invocation lease")
		}
		if err := r.ensureInvocationLeaseFile(pluginID); err != nil {
			return nil, err
		}
	}
	before, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("plugin invocation lease is missing; complete the root-owned registry migration")
		}
		return nil, err
	}
	if err := r.validateInvocationLeaseFile(path, before); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("failed to open plugin invocation lease")
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, errors.New("plugin invocation lease identity changed while opening")
	}
	operation := syscall.LOCK_SH | syscall.LOCK_NB
	busyMessage := "plugin current mutation is in progress; retry the workload invocation"
	if exclusive {
		operation = syscall.LOCK_EX | syscall.LOCK_NB
		busyMessage = "plugin current mutation is blocked by an active source-plugin runtime"
	}
	if err := syscall.Flock(fd, operation); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errors.New(busyMessage)
		}
		return nil, err
	}
	return &InvocationLease{file: file}, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func validateLimits(limits Limits) error {
	if limits.MaxEntries < 2 || limits.MaxEntries > defaultLimits.MaxEntries ||
		limits.MaxDepth < 1 || limits.MaxDepth > defaultLimits.MaxDepth ||
		limits.MaxFileBytes < 1 || limits.MaxFileBytes > defaultLimits.MaxFileBytes ||
		limits.MaxTotalBytes < limits.MaxFileBytes || limits.MaxTotalBytes > defaultLimits.MaxTotalBytes ||
		limits.MaxManifestBytes < 1 || limits.MaxManifestBytes > limits.MaxFileBytes {
		return errors.New("plugin registry limits are invalid or exceed hard maximums")
	}
	return nil
}

func validatePluginID(pluginID string) error {
	if !pluginIDPattern.MatchString(pluginID) {
		return errors.New("plugin id is invalid")
	}
	return nil
}

func cleanAbsolute(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value
}

func pathsOverlap(first, second string) bool {
	relative, err := filepath.Rel(first, second)
	if err == nil && (relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))) {
		return true
	}
	relative, err = filepath.Rel(second, first)
	return err == nil && (relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))))
}

func regexpDigest() *regexp.Regexp {
	return regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
}
