package roothelper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/KiritoKing/pi-ops-agent/internal/peercred"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
	"github.com/KiritoKing/pi-ops-agent/internal/targetpolicy"
)

type Inspector interface {
	Inspect(context.Context, protocol.Request, []string) (interface{}, error)
}

type OSInspector struct {
	Runner                CommandRunner
	LookupWorkloadAccount func(string) (int, string, error)
}

type WorkloadCommandInspector interface {
	InspectWorkloadCommand(context.Context, protocol.WorkloadCommandInspection, targetpolicy.CommandWorkloadPolicy) (WorkloadCommandInspectionResult, error)
}

type WorkloadCommandInspectionResult struct {
	Kind            string `json:"kind"`
	PluginID        string `json:"pluginId"`
	PluginDigest    string `json:"pluginDigest"`
	ProfileKey      string `json:"profileKey"`
	TargetAccount   string `json:"targetAccount"`
	RunAsAccount    string `json:"runAsAccount"`
	Output          string `json:"output"`
	Truncated       bool   `json:"truncated"`
	ExecutableTrust string `json:"executableTrust"`
}

func (i OSInspector) Inspect(ctx context.Context, request protocol.Request, readPaths []string) (interface{}, error) {
	runner := i.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	switch request.Method {
	case protocol.MethodHostSnapshot:
		return runSnapshot(ctx, runner), nil
	case protocol.MethodProcessList:
		return runCommand(ctx, runner, "ps", "-eo", "pid=,ppid=,user=,stat=,etimes=,comm=", "--sort=pid")
	case protocol.MethodSystemdUnit:
		return runCommand(ctx, runner, "systemctl", "show", "--no-pager", "--property=Id,LoadState,ActiveState,SubState,UnitFileState", "--", request.Unit)
	case protocol.MethodJournalTail:
		return runCommand(ctx, runner, "journalctl", "--no-pager", "--output=short-iso", "--unit", request.Unit, "--lines", strconv.Itoa(request.Lines))
	case protocol.MethodFileMetadata:
		return inspectMetadata(request.Path, readPaths)
	case protocol.MethodFileRead:
		return inspectFile(request.Path, request.MaxBytes, readPaths)
	case protocol.MethodPVEClusterStatus, protocol.MethodPVENodeStatus, protocol.MethodPVEStorageStatus, protocol.MethodPVETaskStatus, protocol.MethodPVEGuestStatus:
		return inspectPVE(ctx, runner, request)
	default:
		return nil, errors.New("unsupported inspection method")
	}
}

func (i OSInspector) InspectWorkloadCommand(
	ctx context.Context,
	inspection protocol.WorkloadCommandInspection,
	profile targetpolicy.CommandWorkloadPolicy,
) (WorkloadCommandInspectionResult, error) {
	if err := inspection.Validate(); err != nil || profile.PluginID != inspection.PluginID ||
		profile.PluginDigest != inspection.PluginDigest || profile.ProfileKey != inspection.ProfileKey {
		return WorkloadCommandInspectionResult{}, errors.New("workload command profile identity changed before execution")
	}
	uid, home, err := i.lookupCommandAccount(profile.RunAsAccount)
	if err != nil {
		return WorkloadCommandInspectionResult{}, err
	}
	if home != profile.RunAsHome {
		return WorkloadCommandInspectionResult{}, errors.New("workload command run-as home no longer matches target policy")
	}
	trustedExecutable, err := resolveTrustedCommandExecutable(profile.Executable)
	if err != nil {
		return WorkloadCommandInspectionResult{}, fmt.Errorf("validate workload command executable: %w", err)
	}
	runner := i.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	commandCtx, cancel := context.WithTimeout(
		ctx,
		time.Duration(profile.TimeoutSeconds+10)*time.Second,
	)
	defer cancel()
	arguments := []string{
		"--quiet", "--wait", "--pipe", "--collect", "--service-type=exec",
		"--uid=" + profile.RunAsAccount,
		"--working-directory=" + home,
		"--property=ProtectSystem=strict",
		"--property=ProtectHome=read-only",
		"--property=PrivateNetwork=yes",
		"--property=PrivateTmp=yes",
		"--property=PrivateDevices=yes",
		"--property=NoNewPrivileges=yes",
		"--property=CapabilityBoundingSet=",
		"--property=AmbientCapabilities=",
		"--property=RestrictAddressFamilies=AF_UNIX",
		"--property=RestrictNamespaces=yes",
		"--property=ProtectHostname=yes",
		"--property=ProtectClock=yes",
		"--property=ProtectKernelTunables=yes",
		"--property=ProtectKernelModules=yes",
		"--property=ProtectKernelLogs=yes",
		"--property=ProtectControlGroups=yes",
		"--property=RestrictRealtime=yes",
		"--property=RestrictSUIDSGID=yes",
		"--property=SystemCallArchitectures=native",
		"--property=KillMode=control-group",
		"--property=SendSIGKILL=yes",
		"--property=TimeoutStopSec=5s",
		"--property=RuntimeMaxSec=" + strconv.Itoa(profile.TimeoutSeconds) + "s",
		"--property=UMask=0077",
		"--", "/usr/bin/env", "-i",
		"HOME=" + home, "USER=" + profile.RunAsAccount, "LOGNAME=" + profile.RunAsAccount,
		"XDG_RUNTIME_DIR=/run/user/" + strconv.Itoa(uid),
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "PYTHONNOUSERSITE=1",
		trustedExecutable,
	}
	arguments = append(arguments, profile.Argv...)
	output, err := runner.Run(commandCtx, "/usr/bin/systemd-run", arguments...)
	if err != nil {
		if errors.Is(commandCtx.Err(), context.DeadlineExceeded) {
			return WorkloadCommandInspectionResult{}, errors.New("workload command profile exceeded its fixed timeout")
		}
		return WorkloadCommandInspectionResult{}, fmt.Errorf("workload command profile failed: %w", err)
	}
	safeOutput, truncated := boundedControlSafeText(output, profile.MaxOutputBytes)
	return WorkloadCommandInspectionResult{
		Kind: "workload.command.inspect-result/v1", PluginID: inspection.PluginID,
		PluginDigest: inspection.PluginDigest, ProfileKey: inspection.ProfileKey,
		TargetAccount: profile.TargetAccount, RunAsAccount: profile.RunAsAccount,
		Output: safeOutput, Truncated: truncated,
		ExecutableTrust: "root-owned-nonwritable-path",
	}, nil
}

func (i OSInspector) lookupCommandAccount(account string) (int, string, error) {
	if !protocol.ValidWorkloadAccount(account) || account == "root" {
		return 0, "", errors.New("workload command requires a non-root local account")
	}
	if i.LookupWorkloadAccount != nil {
		uid, home, err := i.LookupWorkloadAccount(account)
		return validateWorkloadAccount(uid, home, err)
	}
	entry, err := user.Lookup(account)
	if err != nil {
		return 0, "", fmt.Errorf("lookup workload command account: %w", err)
	}
	uid, err := strconv.Atoi(entry.Uid)
	if err != nil {
		return 0, "", errors.New("workload command account has an invalid UID")
	}
	return validateWorkloadAccount(uid, entry.HomeDir, nil)
}

func resolveTrustedCommandExecutable(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return "", errors.New("executable path must be a clean absolute path")
	}
	if err := validateRootOwnedCommandPath(path, true); err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve executable symlinks: %w", err)
	}
	if !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved || resolved == "/" {
		return "", errors.New("resolved executable path is invalid")
	}
	if err := validateRootOwnedCommandPath(resolved, false); err != nil {
		return "", err
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", fmt.Errorf("inspect resolved executable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", errors.New("resolved executable is not an executable regular file")
	}
	return resolved, nil
}

func validateRootOwnedCommandPath(path string, allowSymlinks bool) error {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	prefixes := make([]string, 0, len(parts)+1)
	prefixes = append(prefixes, "/")
	current := "/"
	for _, part := range parts {
		current = filepath.Join(current, part)
		prefixes = append(prefixes, current)
	}
	for index, prefix := range prefixes {
		info, err := os.Lstat(prefix)
		if err != nil {
			return fmt.Errorf("inspect executable path component %q: %w", prefix, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return fmt.Errorf("executable path component %q is not root-owned", prefix)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if !allowSymlinks {
				return fmt.Errorf("resolved executable path component %q is a symlink", prefix)
			}
			continue
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("executable path component %q is group/world writable", prefix)
		}
		if index < len(prefixes)-1 && !info.IsDir() {
			return fmt.Errorf("executable path component %q is not a directory", prefix)
		}
	}
	return nil
}

func boundedControlSafeText(value string, maximum int) (string, bool) {
	value = strings.ToValidUTF8(value, "�")
	var safe strings.Builder
	for _, character := range value {
		if character == '\n' || character == '\t' || (character >= 0x20 && character != 0x7f) {
			safe.WriteRune(character)
		} else {
			safe.WriteRune('�')
		}
	}
	result := safe.String()
	if len(result) <= maximum {
		return result, false
	}
	cut := maximum
	for cut > 0 && !utf8.RuneStart(result[cut]) {
		cut--
	}
	return result[:cut], true
}

func runSnapshot(ctx context.Context, runner CommandRunner) map[string]string {
	result := make(map[string]string)
	commands := []struct {
		name string
		args []string
	}{{"uptime", nil}, {"df", []string{"-P"}}, {"free", []string{"-b"}}}
	for _, command := range commands {
		path, err := exec.LookPath(command.name)
		if err != nil {
			result[command.name] = "unavailable"
			continue
		}
		output, err := runner.Run(ctx, path, command.args...)
		if err != nil {
			result[command.name] = "error: " + err.Error()
			continue
		}
		result[command.name] = output
	}
	return result
}

func runCommand(ctx context.Context, runner CommandRunner, name string, args ...string) (interface{}, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return nil, err
	}
	output, err := runner.Run(ctx, path, args...)
	if err != nil {
		return nil, err
	}
	return map[string]string{"output": output}, nil
}

func inspectMetadata(path string, readPaths []string) (interface{}, error) {
	file, err := openInspectionPath(path, readPaths, false)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	data := map[string]interface{}{
		"path": path, "size": info.Size(), "mode": info.Mode().String(),
		"modifiedAt": info.ModTime().UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		"regular":    info.Mode().IsRegular(), "symlink": false,
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		data["uid"], data["gid"] = stat.Uid, stat.Gid
	}
	return data, nil
}

func inspectFile(path string, maximum int, readPaths []string) (interface{}, error) {
	file, err := openInspectionPath(path, readPaths, true)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("file.read target must be a regular file")
	}
	buffer, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return nil, err
	}
	count := len(buffer)
	truncated := count > maximum
	if truncated {
		count = maximum
	}
	return map[string]interface{}{"path": path, "content": string(buffer[:count]), "truncated": truncated, "size": info.Size()}, nil
}

func (s *Service) inspect(ctx context.Context, peer peercred.Credential, request protocol.Request) protocol.Response {
	if !s.isAgentOrApprover(peer.UID) {
		return denied(request, "peer may not inspect the host")
	}
	if s.Inspector == nil {
		return denied(request, "root-helper inspection is not configured")
	}
	var readPaths []string
	if s.Policy != nil {
		if target, ok := s.Policy.Target(request.TargetID); ok {
			readPaths = append(readPaths, target.Inspect.ReadPaths...)
		}
	}
	data, err := s.Inspector.Inspect(ctx, request, readPaths)
	if err != nil {
		return failed(request, fmt.Errorf("inspect host: %w", err))
	}
	return protocol.Response{Version: protocol.Version, RequestID: request.RequestID, OK: true, Data: data}
}

func (s *Service) inspectWorkloadCommand(ctx context.Context, peer peercred.Credential, request protocol.Request) protocol.Response {
	if peer.UID != s.AgentUID || request.CallerRole != "agent" {
		return denied(request, "only the non-privileged agent may invoke a source-workload command profile")
	}
	if s.Policy == nil || s.Inspector == nil {
		return denied(request, "workload command inspection is not configured")
	}
	profile, ok := s.Policy.CommandWorkload(request.TargetID, request.WorkloadCommand)
	if !ok {
		return denied(request, "workload command profile is outside the exact digest-bound target policy")
	}
	inspector, ok := s.Inspector.(WorkloadCommandInspector)
	if !ok {
		return denied(request, "workload command inspector is unavailable")
	}
	data, err := inspector.InspectWorkloadCommand(ctx, request.WorkloadCommand, profile)
	if err != nil {
		return failed(request, fmt.Errorf("inspect workload command profile: %w", err))
	}
	outputHash := sha256.Sum256([]byte(data.Output))
	auditID, err := s.appendAudit(peer, request, map[string]interface{}{
		"type": "workload_command_inspected", "pluginId": data.PluginID,
		"pluginDigest": data.PluginDigest, "profileKey": data.ProfileKey,
		"targetAccount": data.TargetAccount, "runAsAccount": data.RunAsAccount,
		"truncated": data.Truncated, "executableTrust": data.ExecutableTrust,
		"outputDigest": "sha256:" + hex.EncodeToString(outputHash[:]), "outputBytes": len([]byte(data.Output)),
	})
	if err != nil {
		return failed(request, fmt.Errorf("audit workload command inspection: %w", err))
	}
	return protocol.Response{
		Version: protocol.Version, RequestID: request.RequestID, OK: true, AuditID: auditID,
		Summary: "workload command profile completed", Data: data,
	}
}
