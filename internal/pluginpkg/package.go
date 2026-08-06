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
	"strings"
)

const (
	maxPackageBytes = 16 * 1024 * 1024
	maxFiles        = 256
	maxFileBytes    = 8 * 1024 * 1024
)

var (
	idPattern      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,71}$`)
	versionPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9+.:~_-]{0,95}$`)
	secretPattern  = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9._-]{0,63}$`)
)

type Capabilities struct {
	InboundText         bool `json:"inboundText"`
	VerifiedSender      bool `json:"verifiedSender"`
	PrivateConversation bool `json:"privateConversation"`
	ProactiveDelivery   bool `json:"proactiveDelivery"`
	ApprovalIntent      bool `json:"approvalIntent"`
	Streaming           bool `json:"streaming"`
}

type Manifest struct {
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
	manifestPayload, err := inspectArchive(payload)
	if err != nil {
		return nil, err
	}
	manifest, err := parseManifest(manifestPayload)
	if err != nil {
		return nil, err
	}
	return &Package{
		Path: resolvedPackage, Digest: "sha256:" + hex.EncodeToString(digest[:]),
		Manifest: manifest, payload: payload,
	}, nil
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

func inspectArchive(payload []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(payload))
	if err != nil {
		return nil, errors.New("plugin package is not a gzip tar archive")
	}
	defer reader.Close()
	archive := tar.NewReader(reader)
	seen := make(map[string]struct{})
	var manifest []byte
	var total int64
	for count := 0; ; count++ {
		if count >= maxFiles {
			return nil, errors.New("plugin archive contains too many entries")
		}
		header, nextErr := archive.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return nil, nextErr
		}
		name, nameErr := safeArchiveName(header.Name)
		if nameErr != nil {
			return nil, nameErr
		}
		if _, exists := seen[name]; exists {
			return nil, fmt.Errorf("duplicate plugin archive entry %q", name)
		}
		seen[name] = struct{}{}
		if header.Typeflag != tar.TypeDir && header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return nil, fmt.Errorf("plugin archive entry %q has an unsupported type", name)
		}
		if header.Size < 0 || header.Size > maxFileBytes {
			return nil, errors.New("plugin archive contains an oversized file")
		}
		total += header.Size
		if total > maxPackageBytes {
			return nil, errors.New("plugin archive expands beyond its size limit")
		}
		if name == "manifest.json" {
			if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
				return nil, errors.New("plugin manifest must be a regular file")
			}
			manifest, err = io.ReadAll(io.LimitReader(archive, 128*1024+1))
			if err != nil || len(manifest) > 128*1024 {
				return nil, errors.New("plugin manifest exceeds its size limit")
			}
		}
	}
	if len(manifest) == 0 {
		return nil, errors.New("plugin archive has no root manifest.json")
	}
	return manifest, nil
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
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode plugin manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Manifest{}, errors.New("decode plugin manifest: trailing value")
	}
	if manifest.SchemaVersion != 1 || manifest.CoreProtocol != 1 || manifest.Kind != "im-adapter" || !idPattern.MatchString(manifest.ID) || !versionPattern.MatchString(manifest.Version) || manifest.Publisher == "" || len(manifest.Publisher) > 160 || manifest.Description == "" || len(manifest.Description) > 2048 {
		return Manifest{}, errors.New("plugin manifest has unsupported identity or protocol fields")
	}
	entrypoint, err := safeArchiveName(manifest.Entrypoint)
	if err != nil || entrypoint != manifest.Entrypoint {
		return Manifest{}, errors.New("plugin manifest entrypoint must be a normalized package-relative path")
	}
	seenSecrets := make(map[string]struct{}, len(manifest.Secrets))
	for _, secret := range manifest.Secrets {
		if !secretPattern.MatchString(secret) {
			return Manifest{}, errors.New("plugin manifest contains an invalid secret name")
		}
		if _, exists := seenSecrets[secret]; exists {
			return Manifest{}, errors.New("plugin manifest contains duplicate secret names")
		}
		seenSecrets[secret] = struct{}{}
	}
	return manifest, nil
}
