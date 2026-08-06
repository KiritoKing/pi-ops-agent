package roothelper

import (
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
	"strconv"
	"strings"
	"syscall"

	"github.com/KiritoKing/pi-ops-agent/internal/pluginpkg"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

const maxCommandOutput = 64 * 1024

type ExecutionResult struct {
	BackupRefs        []string
	RollbackData      json.RawMessage
	RollbackAvailable bool
	Verification      string
}

type Executor interface {
	Prepare(context.Context, string, protocol.Operation) (ExecutionResult, error)
	Execute(context.Context, string, protocol.Operation, ExecutionResult) error
	Verify(context.Context, string, protocol.Operation, ExecutionResult) (string, error)
	Rollback(context.Context, string, protocol.Operation, ExecutionResult) error
}

type OperationValidator interface {
	ValidateOperation(protocol.Operation) error
}

type CommandRunner interface {
	Run(context.Context, string, ...string) (string, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive"}
	var output limitedBuffer
	command.Stdout, command.Stderr = &output, &output
	err := command.Run()
	if err != nil {
		return output.String(), fmt.Errorf("%s failed: %w", filepath.Base(name), err)
	}
	return output.String(), nil
}

type OSExecutor struct {
	StateDir        string
	AllowedRoots    []string
	AllowBreakglass bool
	Runner          CommandRunner
	PluginRoot      string
	PluginCatalog   string
	PluginBinRoot   string
}

func (e *OSExecutor) Prepare(ctx context.Context, changeID string, operation protocol.Operation) (ExecutionResult, error) {
	if e.Runner == nil {
		e.Runner = ExecRunner{}
	}
	if err := e.ValidateOperation(operation); err != nil {
		return ExecutionResult{}, err
	}
	switch value := operation.(type) {
	case *protocol.PackageInstall:
		return e.preparePackage(ctx, value)
	case *protocol.ServiceAction:
		return e.prepareService(ctx, value)
	case *protocol.FileWrite:
		return e.prepareFile(changeID, value)
	case *protocol.PluginInstall:
		return e.preparePluginInstall(changeID, value)
	case *protocol.BreakglassScript:
		return e.prepareBreakglass(ctx, changeID, value)
	default:
		return ExecutionResult{}, errors.New("executor received an unsupported operation")
	}
}

func (e *OSExecutor) Execute(ctx context.Context, changeID string, operation protocol.Operation, result ExecutionResult) error {
	if e.Runner == nil {
		e.Runner = ExecRunner{}
	}
	if err := e.ValidateOperation(operation); err != nil {
		return err
	}
	switch value := operation.(type) {
	case *protocol.PackageInstall:
		return e.installSpecificPackage(ctx, value.Package, value.Version)
	case *protocol.ServiceAction:
		_, err := e.systemctl(ctx, value.Action, value.Unit)
		return err
	case *protocol.FileWrite:
		return e.executeFile(value, result)
	case *protocol.PluginInstall:
		return e.executePluginInstall(changeID, value)
	case *protocol.BreakglassScript:
		scriptPath := filepath.Join(e.StateDir, "changes", changeID, "script.sh")
		_, err := e.runCapsule(ctx, changeID, scriptPath, value.BackupPaths)
		return err
	default:
		return errors.New("executor received an unsupported operation")
	}
}

func (e *OSExecutor) ValidateOperation(operation protocol.Operation) error {
	switch value := operation.(type) {
	case *protocol.PackageInstall:
		return nil
	case *protocol.ServiceAction:
		if isCriticalService(value.Unit) {
			return errors.New("R3 service is not remotely mutable")
		}
		return nil
	case *protocol.FileWrite:
		return e.ensureAllowedPath(value.Path)
	case *protocol.PluginInstall:
		if value.PluginID != "adapter.botmux" {
			return errors.New("this release only implements the adapter.botmux installer")
		}
		catalog := e.pluginCatalog()
		if _, err := pluginpkg.Inspect(value.CatalogPath, catalog); err != nil {
			return err
		}
		return nil
	case *protocol.BreakglassScript:
		if !e.AllowBreakglass {
			return errors.New("break-glass execution is disabled")
		}
		if value.Network {
			return errors.New("networked break-glass capsules are not supported")
		}
		for _, path := range value.BackupPaths {
			if err := e.ensureAllowedPath(path); err != nil {
				return err
			}
		}
		return nil
	default:
		return errors.New("unsupported operation")
	}
}

func (e *OSExecutor) Verify(ctx context.Context, _ string, operation protocol.Operation, result ExecutionResult) (string, error) {
	switch value := operation.(type) {
	case *protocol.PackageInstall:
		version, installed, err := e.packageVersion(ctx, value.Package)
		if err != nil || !installed {
			return "", errors.New("package is not installed after change")
		}
		if value.Version != "" && version != value.Version {
			return "", fmt.Errorf("installed version %q does not match %q", version, value.Version)
		}
		return "installed version " + version, nil
	case *protocol.ServiceAction:
		state, err := e.systemctl(ctx, "is-active", value.Unit)
		active := strings.TrimSpace(state) == "active"
		if value.Action == "stop" {
			if active {
				return "", errors.New("service is still active")
			}
			return "service is inactive", nil
		}
		if err != nil || !active {
			return "", errors.New("service is not active after change")
		}
		return "service is active", nil
	case *protocol.FileWrite:
		payload, err := os.ReadFile(value.Path)
		if err != nil {
			return "", err
		}
		expected, actual := sha256.Sum256([]byte(value.Content)), sha256.Sum256(payload)
		if expected != actual {
			return "", errors.New("written file digest mismatch")
		}
		return "sha256:" + hex.EncodeToString(actual[:]), nil
	case *protocol.PluginInstall:
		packageInfo, err := pluginpkg.Inspect(value.CatalogPath, e.pluginCatalog())
		if err != nil {
			return "", err
		}
		if err := packageInfo.ValidateExpected(value.PluginID, value.Version, value.Digest); err != nil {
			return "", err
		}
		destination := filepath.Join(e.pluginRoot(), value.PluginID, value.Version)
		entrypoint := filepath.Join(destination, filepath.FromSlash(packageInfo.Manifest.Entrypoint))
		if info, statErr := os.Stat(entrypoint); statErr != nil || !info.Mode().IsRegular() {
			return "", errors.New("installed plugin entrypoint is missing or not a regular file")
		}
		return "installed " + value.PluginID + " " + value.Version + " " + value.Digest, nil
	case *protocol.BreakglassScript:
		if value.VerifyScript == "" {
			return "script completed; no verification script supplied", nil
		}
		path := filepath.Join(e.StateDir, "changes", resultID(result), "verify.sh")
		if err := writePrivateFile(path, []byte(value.VerifyScript), 0o700); err != nil {
			return "", err
		}
		_, err := e.runCapsule(ctx, resultID(result), path, value.BackupPaths)
		if err != nil {
			return "", err
		}
		return "verification script exited successfully", nil
	default:
		return "", errors.New("unsupported verification operation")
	}
}

func (e *OSExecutor) Rollback(ctx context.Context, _ string, operation protocol.Operation, result ExecutionResult) error {
	if !result.RollbackAvailable {
		return errors.New("rollback is unavailable")
	}
	switch value := operation.(type) {
	case *protocol.PackageInstall:
		var rollback packageRollback
		if err := json.Unmarshal(result.RollbackData, &rollback); err != nil {
			return err
		}
		if rollback.Installed {
			return e.installSpecificPackage(ctx, value.Package, rollback.Version)
		}
		return e.removePackage(ctx, value.Package)
	case *protocol.ServiceAction:
		var rollback serviceRollback
		if err := json.Unmarshal(result.RollbackData, &rollback); err != nil {
			return err
		}
		if rollback.Active {
			_, err := e.systemctl(ctx, "start", value.Unit)
			return err
		}
		_, err := e.systemctl(ctx, "stop", value.Unit)
		return err
	case *protocol.FileWrite:
		var rollback fileRollback
		if err := json.Unmarshal(result.RollbackData, &rollback); err != nil {
			return err
		}
		if !rollback.Existed {
			return os.Remove(value.Path)
		}
		payload, err := os.ReadFile(rollback.BackupPath)
		if err != nil {
			return err
		}
		return atomicReplace(value.Path, payload, os.FileMode(rollback.Mode), rollback.UID, rollback.GID)
	case *protocol.PluginInstall:
		return e.rollbackPluginInstall(value, result)
	case *protocol.BreakglassScript:
		var rollback breakglassRollback
		if err := json.Unmarshal(result.RollbackData, &rollback); err != nil {
			return err
		}
		_, err := e.Runner.Run(ctx, "/bin/tar", "--xattrs", "--acls", "--selinux", "-xpf", rollback.Archive, "-C", "/")
		return err
	default:
		return errors.New("unsupported rollback operation")
	}
}

type packageRollback struct {
	Installed bool   `json:"installed"`
	Version   string `json:"version,omitempty"`
}
type serviceRollback struct {
	Active bool `json:"active"`
}
type fileRollback struct {
	Existed    bool   `json:"existed"`
	BackupPath string `json:"backupPath,omitempty"`
	Mode       uint32 `json:"mode,omitempty"`
	UID        int    `json:"uid,omitempty"`
	GID        int    `json:"gid,omitempty"`
}
type breakglassRollback struct {
	ChangeID string `json:"changeId"`
	Archive  string `json:"archive"`
}

type pluginInstallRollback struct {
	Destination    string `json:"destination"`
	CurrentLink    string `json:"currentLink"`
	PreviousLink   string `json:"previousLink,omitempty"`
	WrapperPath    string `json:"wrapperPath,omitempty"`
	WrapperBackup  string `json:"wrapperBackup,omitempty"`
	WrapperExisted bool   `json:"wrapperExisted"`
}

func (e *OSExecutor) preparePackage(ctx context.Context, operation *protocol.PackageInstall) (ExecutionResult, error) {
	oldVersion, installed, err := e.packageVersion(ctx, operation.Package)
	if err != nil {
		return ExecutionResult{}, err
	}
	rollback, _ := json.Marshal(packageRollback{Installed: installed, Version: oldVersion})
	return ExecutionResult{RollbackData: rollback, RollbackAvailable: true}, nil
}

func (e *OSExecutor) installSpecificPackage(ctx context.Context, packageName, version string) error {
	if path, err := exec.LookPath("apt-get"); err == nil {
		target := packageName
		if version != "" {
			target += "=" + version
		}
		_, err = e.Runner.Run(ctx, path, "install", "-y", "--no-install-recommends", "--", target)
		return err
	}
	for _, manager := range []string{"dnf", "yum", "zypper"} {
		if path, err := exec.LookPath(manager); err == nil {
			target := packageName
			if version != "" {
				target += "-" + version
			}
			args := []string{"install", "-y", "--", target}
			if manager == "zypper" {
				args = []string{"--non-interactive", "install", "--", target}
			}
			_, err = e.Runner.Run(ctx, path, args...)
			return err
		}
	}
	return errors.New("no supported package manager found")
}

func (e *OSExecutor) removePackage(ctx context.Context, packageName string) error {
	if path, err := exec.LookPath("apt-get"); err == nil {
		_, err = e.Runner.Run(ctx, path, "remove", "-y", "--", packageName)
		return err
	}
	for _, manager := range []string{"dnf", "yum", "zypper"} {
		if path, err := exec.LookPath(manager); err == nil {
			args := []string{"remove", "-y", "--", packageName}
			if manager == "zypper" {
				args = []string{"--non-interactive", "remove", "--", packageName}
			}
			_, err = e.Runner.Run(ctx, path, args...)
			return err
		}
	}
	return errors.New("no supported package manager found")
}

func (e *OSExecutor) packageVersion(ctx context.Context, packageName string) (string, bool, error) {
	if path, err := exec.LookPath("dpkg-query"); err == nil {
		output, err := e.Runner.Run(ctx, path, "-W", "-f=${Status}\t${Version}", "--", packageName)
		if err != nil {
			return "", false, nil
		}
		parts := strings.Split(strings.TrimSpace(output), "\t")
		if len(parts) == 2 && parts[0] == "install ok installed" {
			return parts[1], true, nil
		}
		return "", false, nil
	}
	if path, err := exec.LookPath("rpm"); err == nil {
		output, err := e.Runner.Run(ctx, path, "-q", "--qf", "%{VERSION}-%{RELEASE}", "--", packageName)
		if err != nil {
			return "", false, nil
		}
		return strings.TrimSpace(output), true, nil
	}
	return "", false, errors.New("no supported package database found")
}

func (e *OSExecutor) prepareService(ctx context.Context, operation *protocol.ServiceAction) (ExecutionResult, error) {
	state, _ := e.systemctl(ctx, "is-active", operation.Unit)
	rollback, _ := json.Marshal(serviceRollback{Active: strings.TrimSpace(state) == "active"})
	return ExecutionResult{RollbackData: rollback, RollbackAvailable: true}, nil
}

func (e *OSExecutor) systemctl(ctx context.Context, action, unit string) (string, error) {
	path, err := exec.LookPath("systemctl")
	if err != nil {
		return "", err
	}
	return e.Runner.Run(ctx, path, action, "--", unit)
}

func (e *OSExecutor) prepareFile(changeID string, operation *protocol.FileWrite) (ExecutionResult, error) {
	if err := e.ensureAllowedPath(operation.Path); err != nil {
		return ExecutionResult{}, err
	}
	changeDir := filepath.Join(e.StateDir, "changes", changeID)
	if err := os.MkdirAll(changeDir, 0o700); err != nil {
		return ExecutionResult{}, err
	}
	rollback := fileRollback{}
	info, err := os.Lstat(operation.Path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return ExecutionResult{}, errors.New("file.write target must be a regular file")
		}
		rollback.Existed, rollback.Mode = true, uint32(info.Mode().Perm())
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			rollback.UID, rollback.GID = int(stat.Uid), int(stat.Gid)
		}
		rollback.BackupPath = filepath.Join(changeDir, "file.backup")
		if err := copyFile(operation.Path, rollback.BackupPath, 0o600); err != nil {
			return ExecutionResult{}, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return ExecutionResult{}, err
	}
	encoded, _ := json.Marshal(rollback)
	result := ExecutionResult{RollbackData: encoded, RollbackAvailable: true}
	if rollback.BackupPath != "" {
		result.BackupRefs = []string{rollback.BackupPath}
	}
	return result, nil
}

func (e *OSExecutor) executeFile(operation *protocol.FileWrite, result ExecutionResult) error {
	var rollback fileRollback
	if err := json.Unmarshal(result.RollbackData, &rollback); err != nil {
		return fmt.Errorf("decode prepared file metadata: %w", err)
	}
	mode := os.FileMode(0o644)
	uid, gid := -1, -1
	if rollback.Existed {
		mode, uid, gid = os.FileMode(rollback.Mode), rollback.UID, rollback.GID
	}
	if operation.Mode != "" {
		parsed, err := strconv.ParseUint(operation.Mode, 8, 32)
		if err != nil {
			return err
		}
		mode = os.FileMode(parsed)
	}
	return atomicReplace(operation.Path, []byte(operation.Content), mode, uid, gid)
}

func (e *OSExecutor) preparePluginInstall(changeID string, operation *protocol.PluginInstall) (ExecutionResult, error) {
	packageInfo, err := pluginpkg.Inspect(operation.CatalogPath, e.pluginCatalog())
	if err != nil {
		return ExecutionResult{}, err
	}
	if err := packageInfo.ValidateExpected(operation.PluginID, operation.Version, operation.Digest); err != nil {
		return ExecutionResult{}, err
	}
	destination := filepath.Join(e.pluginRoot(), operation.PluginID, operation.Version)
	if _, err := os.Lstat(destination); err == nil {
		return ExecutionResult{}, errors.New("plugin version is already installed")
	} else if !errors.Is(err, os.ErrNotExist) {
		return ExecutionResult{}, err
	}
	changeDir := filepath.Join(e.StateDir, "changes", changeID)
	if err := os.MkdirAll(changeDir, 0o700); err != nil {
		return ExecutionResult{}, err
	}
	rollback := pluginInstallRollback{
		Destination: destination,
		CurrentLink: filepath.Join(e.pluginRoot(), operation.PluginID, "current"),
	}
	if previous, err := os.Readlink(rollback.CurrentLink); err == nil {
		rollback.PreviousLink = previous
	} else if !errors.Is(err, os.ErrNotExist) {
		return ExecutionResult{}, errors.New("plugin current pointer is not a symbolic link")
	}
	if operation.PluginID == "adapter.botmux" {
		rollback.WrapperPath = filepath.Join(e.pluginBinRoot(), "ops-agent-botmux")
		if info, err := os.Lstat(rollback.WrapperPath); err == nil {
			if !info.Mode().IsRegular() {
				return ExecutionResult{}, errors.New("existing BotMux launcher is not a regular file")
			}
			rollback.WrapperExisted = true
			rollback.WrapperBackup = filepath.Join(changeDir, "ops-agent-botmux.backup")
			if err := copyFile(rollback.WrapperPath, rollback.WrapperBackup, 0o600); err != nil {
				return ExecutionResult{}, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return ExecutionResult{}, err
		}
	}
	payload, _ := json.Marshal(rollback)
	refs := []string{}
	if rollback.WrapperBackup != "" {
		refs = append(refs, rollback.WrapperBackup)
	}
	return ExecutionResult{BackupRefs: refs, RollbackData: payload, RollbackAvailable: true}, nil
}

func (e *OSExecutor) executePluginInstall(changeID string, operation *protocol.PluginInstall) error {
	packageInfo, err := pluginpkg.Inspect(operation.CatalogPath, e.pluginCatalog())
	if err != nil {
		return err
	}
	if err := packageInfo.ValidateExpected(operation.PluginID, operation.Version, operation.Digest); err != nil {
		return err
	}
	pluginDirectory := filepath.Join(e.pluginRoot(), operation.PluginID)
	if err := os.MkdirAll(pluginDirectory, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(e.pluginRoot(), 0o755); err != nil {
		return err
	}
	if err := os.Chmod(pluginDirectory, 0o755); err != nil {
		return err
	}
	staging := filepath.Join(pluginDirectory, ".staging-"+safeUnitFragment(changeID))
	if err := os.RemoveAll(staging); err != nil {
		return err
	}
	if err := packageInfo.Extract(staging); err != nil {
		_ = os.RemoveAll(staging)
		return err
	}
	destination := filepath.Join(pluginDirectory, operation.Version)
	if err := os.Rename(staging, destination); err != nil {
		_ = os.RemoveAll(staging)
		return err
	}
	temporaryLink := filepath.Join(pluginDirectory, ".current-"+safeUnitFragment(changeID))
	_ = os.Remove(temporaryLink)
	if err := os.Symlink(operation.Version, temporaryLink); err != nil {
		return err
	}
	if err := os.Rename(temporaryLink, filepath.Join(pluginDirectory, "current")); err != nil {
		return err
	}
	if operation.PluginID == "adapter.botmux" {
		if err := os.MkdirAll(e.pluginBinRoot(), 0o755); err != nil {
			return err
		}
		if err := os.Chmod(e.pluginBinRoot(), 0o755); err != nil {
			return err
		}
		launcher := "#!/bin/sh\nset -eu\nexport OPS_AGENT_CORE_ROOT=/opt/pi-ops-agent/current\nexec /opt/pi-ops-agent/current/runtime/node /opt/pi-ops-agent/plugins/adapter.botmux/current/adapter.mjs \"$@\"\n"
		if err := atomicReplace(filepath.Join(e.pluginBinRoot(), "ops-agent-botmux"), []byte(launcher), 0o755, -1, -1); err != nil {
			return err
		}
	}
	return nil
}

func (e *OSExecutor) rollbackPluginInstall(operation *protocol.PluginInstall, result ExecutionResult) error {
	var rollback pluginInstallRollback
	if err := json.Unmarshal(result.RollbackData, &rollback); err != nil {
		return err
	}
	expectedDestination := filepath.Join(e.pluginRoot(), operation.PluginID, operation.Version)
	if rollback.Destination != expectedDestination || filepath.Clean(rollback.Destination) != rollback.Destination {
		return errors.New("plugin rollback destination does not match the operation")
	}
	if err := os.RemoveAll(rollback.Destination); err != nil {
		return err
	}
	_ = os.Remove(rollback.CurrentLink)
	if rollback.PreviousLink != "" {
		if err := os.Symlink(rollback.PreviousLink, rollback.CurrentLink); err != nil {
			return err
		}
	}
	if rollback.WrapperPath != "" {
		if rollback.WrapperExisted {
			payload, err := os.ReadFile(rollback.WrapperBackup)
			if err != nil {
				return err
			}
			return atomicReplace(rollback.WrapperPath, payload, 0o755, -1, -1)
		}
		if err := os.Remove(rollback.WrapperPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (e *OSExecutor) pluginRoot() string {
	if e.PluginRoot != "" {
		return e.PluginRoot
	}
	return "/opt/pi-ops-agent/plugins"
}

func (e *OSExecutor) pluginCatalog() string {
	if e.PluginCatalog != "" {
		return e.PluginCatalog
	}
	return "/opt/pi-ops-agent/current/catalog"
}

func (e *OSExecutor) pluginBinRoot() string {
	if e.PluginBinRoot != "" {
		return e.PluginBinRoot
	}
	return "/opt/pi-ops-agent/bin"
}

func (e *OSExecutor) prepareBreakglass(ctx context.Context, changeID string, operation *protocol.BreakglassScript) (ExecutionResult, error) {
	changeDir := filepath.Join(e.StateDir, "changes", changeID)
	if err := os.MkdirAll(changeDir, 0o700); err != nil {
		return ExecutionResult{}, err
	}
	archive := filepath.Join(changeDir, "backup.tar")
	args := []string{"--xattrs", "--acls", "--selinux", "-cpf", archive, "--absolute-names", "--"}
	args = append(args, operation.BackupPaths...)
	if _, err := e.Runner.Run(ctx, "/bin/tar", args...); err != nil {
		return ExecutionResult{}, err
	}
	scriptPath := filepath.Join(changeDir, "script.sh")
	if err := writePrivateFile(scriptPath, []byte(operation.Script), 0o700); err != nil {
		return ExecutionResult{}, err
	}
	rollback, _ := json.Marshal(breakglassRollback{ChangeID: changeID, Archive: archive})
	result := ExecutionResult{BackupRefs: []string{archive}, RollbackData: rollback, RollbackAvailable: true}
	return result, nil
}

func (e *OSExecutor) runCapsule(ctx context.Context, changeID, scriptPath string, writePaths []string) (string, error) {
	path, err := exec.LookPath("systemd-run")
	if err != nil {
		return "", errors.New("systemd-run is required for break-glass execution")
	}
	args := []string{"--quiet", "--wait", "--pipe", "--collect", "--service-type=exec", "--unit=ops-agent-change-" + safeUnitFragment(changeID),
		"--property=PrivateTmp=yes", "--property=PrivateDevices=yes", "--property=PrivateNetwork=yes", "--property=ProtectHome=read-only",
		"--property=ProtectSystem=strict", "--property=ProtectKernelTunables=yes", "--property=ProtectKernelModules=yes",
		"--property=ProtectControlGroups=yes", "--property=RestrictSUIDSGID=yes", "--property=NoNewPrivileges=yes",
		"--property=CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_FSETID"}
	for _, allowed := range writePaths {
		args = append(args, "--property=ReadWritePaths="+allowed)
	}
	args = append(args, "/bin/bash", "--noprofile", "--norc", scriptPath)
	return e.Runner.Run(ctx, path, args...)
}

func (e *OSExecutor) ensureAllowedPath(path string) error {
	clean := filepath.Clean(path)
	if isCriticalPath(clean) {
		return errors.New("R3 identity, remote-entry, network, disk, or kernel path is not remotely mutable")
	}
	for _, root := range e.AllowedRoots {
		root = filepath.Clean(root)
		relative, err := filepath.Rel(root, clean)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			parent, err := filepath.EvalSymlinks(filepath.Dir(clean))
			if err != nil {
				return fmt.Errorf("resolve target parent: %w", err)
			}
			resolvedRoot, err := filepath.EvalSymlinks(root)
			if err != nil {
				return fmt.Errorf("resolve allowed root: %w", err)
			}
			resolvedRelative, err := filepath.Rel(resolvedRoot, parent)
			if err == nil && resolvedRelative != ".." && !strings.HasPrefix(resolvedRelative, ".."+string(filepath.Separator)) {
				return nil
			}
			return errors.New("target parent escapes the allowed root through a symlink")
		}
	}
	return errors.New("path is outside configured write roots")
}

func isCriticalPath(path string) bool {
	critical := []string{
		"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
		"/etc/sudoers", "/etc/sudoers.d", "/etc/ssh", "/etc/pam.d",
		"/etc/security", "/etc/fstab", "/etc/crypttab", "/etc/ld.so.preload",
		"/etc/modprobe.d", "/etc/sysctl.d",
	}
	for _, denied := range critical {
		if path == denied || strings.HasPrefix(path, denied+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func isCriticalService(unit string) bool {
	_, denied := map[string]struct{}{
		"ops-root-helper.service": {}, "ops-systemd-helper.service": {}, "ops-agentd.service": {},
		"ssh.service": {}, "sshd.service": {}, "dbus.service": {}, "systemd-logind.service": {},
		"network.service": {}, "networking.service": {}, "networkmanager.service": {}, "systemd-networkd.service": {},
		"firewalld.service": {}, "nftables.service": {}, "iptables.service": {}, "ufw.service": {},
	}[strings.ToLower(unit)]
	return denied
}

func resultID(result ExecutionResult) string {
	var rollback breakglassRollback
	if json.Unmarshal(result.RollbackData, &rollback) == nil {
		return rollback.ChangeID
	}
	return "unknown"
}

func atomicReplace(path string, payload []byte, mode os.FileMode, uid, gid int) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".ops-agent-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if uid >= 0 || gid >= 0 {
		if err := temporary.Chown(uid, gid); err != nil {
			temporary.Close()
			return err
		}
	}
	if _, err := temporary.Write(payload); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func copyFile(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		output.Close()
		return err
	}
	return output.Close()
}

func writePrivateFile(path string, payload []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, payload, mode)
}

func safeUnitFragment(value string) string {
	var builder strings.Builder
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' {
			builder.WriteRune(char)
		}
	}
	if builder.Len() > 48 {
		return builder.String()[:48]
	}
	return builder.String()
}

type limitedBuffer struct {
	payload   []byte
	truncated bool
}

func (b *limitedBuffer) Write(payload []byte) (int, error) {
	remaining := maxCommandOutput - len(b.payload)
	if remaining > 0 {
		if len(payload) < remaining {
			remaining = len(payload)
		}
		b.payload = append(b.payload, payload[:remaining]...)
	}
	if len(payload) > remaining {
		b.truncated = true
	}
	return len(payload), nil
}
func (b *limitedBuffer) String() string {
	if b.truncated {
		return string(b.payload) + "\n[TRUNCATED]"
	}
	return string(b.payload)
}
