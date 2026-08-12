package roothelper

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxSecureFileBytes = 128 * 1024

// Production root brokers run as UID 0. Tests replace this package-private
// value with their unprivileged fixture owner; the release binary has no
// configuration surface that can weaken the root-owned-parent requirement.
var secureFileRequiredParentUID uint32

// Legacy v0.2 created new file.write targets and backup objects as root:root.
// Package tests may temporarily replace these package-private values because
// developer workstations do not run the test broker as root; release binaries
// expose no configuration surface for them.
var secureLegacyFileRequiredUID uint32
var secureLegacyFileRequiredGID uint32

// allowedFileSnapshot binds an approved file.write to the directory and file
// objects observed during Prepare.  Linux mutation code compares these values
// again while holding the parent directory fd used by renameat(2), so a path
// cannot be redirected through a symlink or a replaced parent after approval.
type allowedFileSnapshot struct {
	Existed       bool
	Mode          uint32
	UID           int
	GID           int
	ParentDev     uint64
	ParentIno     uint64
	TargetDev     uint64
	TargetIno     uint64
	ContentDigest string
}

type allowedFileCommit struct {
	Version       int    `json:"version"`
	TargetDev     uint64 `json:"targetDev"`
	TargetIno     uint64 `json:"targetIno"`
	Mode          uint32 `json:"mode"`
	UID           int    `json:"uid"`
	GID           int    `json:"gid"`
	ContentDigest string `json:"contentDigest"`
}

func (c allowedFileCommit) validate() error {
	if c.Version != 1 || c.TargetDev == 0 || c.TargetIno == 0 || c.Mode&^uint32(0o777) != 0 || c.Mode&0o111 != 0 ||
		c.UID < 0 || c.GID < 0 || !validSecureFileDigest(c.ContentDigest) {
		return errors.New("file.write committed identity is invalid")
	}
	return nil
}

type fileMutationError struct{ err error }

func (e fileMutationError) Error() string                { return e.err.Error() }
func (e fileMutationError) Unwrap() error                { return e.err }
func (fileMutationError) MutationOutcomeUncertain() bool { return true }
func uncertainFileMutation(message string, err error) error {
	if err == nil {
		err = errors.New(message)
	} else {
		err = errors.New(message + ": " + err.Error())
	}
	return fileMutationError{err: err}
}

func selectAllowedFileRoot(path string, roots []string) (string, string, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean != path {
		return "", "", errors.New("file.write target must be a clean absolute path")
	}
	for _, candidate := range roots {
		root := filepath.Clean(candidate)
		if !filepath.IsAbs(root) {
			continue
		}
		relative, err := filepath.Rel(root, clean)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			continue
		}
		base := filepath.Base(relative)
		if base == "." || base == ".." || base == "" || strings.ContainsRune(base, filepath.Separator) {
			continue
		}
		return root, relative, nil
	}
	return "", "", errors.New("file.write target is not beneath a configured root")
}

func copyOpenFile(source *os.File, destination string) (string, error) {
	if source == nil {
		return "", errors.New("file.write backup source is unavailable")
	}
	if _, err := source.Seek(0, 0); err != nil {
		return "", err
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		_ = output.Close()
		if !ok {
			_ = os.Remove(destination)
		}
	}()
	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(output, hasher), io.LimitReader(source, maxSecureFileBytes+1))
	if err != nil {
		return "", err
	}
	if written > maxSecureFileBytes {
		return "", errors.New("file.write backup exceeds the bounded file size")
	}
	if err := output.Sync(); err != nil {
		return "", err
	}
	if err := output.Close(); err != nil {
		return "", err
	}
	if err := syncSecureDirectory(filepath.Dir(destination)); err != nil {
		return "", err
	}
	ok = true
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}

func digestOpenFile(file *os.File) (string, error) {
	if file == nil {
		return "", errors.New("file.write target is unavailable")
	}
	if _, err := file.Seek(0, 0); err != nil {
		return "", err
	}
	hasher := sha256.New()
	read, err := io.Copy(hasher, io.LimitReader(file, maxSecureFileBytes+1))
	if err != nil {
		return "", err
	}
	if read > maxSecureFileBytes {
		return "", errors.New("file.write target exceeds the bounded file size")
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}

func secureFilePayloadDigest(payload []byte) string {
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validSecureFileDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func syncSecureDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}

func writeAllowedFileCommit(path string, commit allowedFileCommit) error {
	if err := commit.validate(); err != nil {
		return err
	}
	payload, err := json.Marshal(commit)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(payload); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := syncSecureDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	ok = true
	return nil
}

func readAllowedFileCommit(path string) (allowedFileCommit, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return allowedFileCommit{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() < 1 || info.Size() > 4096 {
		return allowedFileCommit{}, errors.New("file.write committed identity record is unsafe")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return allowedFileCommit{}, err
	}
	var commit allowedFileCommit
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&commit); err != nil {
		return allowedFileCommit{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return allowedFileCommit{}, errors.New("file.write committed identity has trailing JSON")
	}
	if err := commit.validate(); err != nil {
		return allowedFileCommit{}, err
	}
	return commit, nil
}
