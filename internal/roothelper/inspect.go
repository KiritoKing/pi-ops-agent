package roothelper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"github.com/KiritoKing/pi-ops-agent/internal/peercred"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

type Inspector interface {
	Inspect(context.Context, protocol.Request) (interface{}, error)
}

type OSInspector struct{ Runner CommandRunner }

func (i OSInspector) Inspect(ctx context.Context, request protocol.Request) (interface{}, error) {
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
		return inspectMetadata(request.Path)
	case protocol.MethodFileRead:
		return inspectFile(request.Path, request.MaxBytes)
	default:
		return nil, errors.New("unsupported inspection method")
	}
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

func inspectMetadata(path string) (interface{}, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	data := map[string]interface{}{
		"path": path, "size": info.Size(), "mode": info.Mode().String(),
		"modifiedAt": info.ModTime().UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		"regular":    info.Mode().IsRegular(), "symlink": info.Mode()&os.ModeSymlink != 0,
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		data["uid"], data["gid"] = stat.Uid, stat.Gid
	}
	return data, nil
}

func inspectFile(path string, maximum int) (interface{}, error) {
	file, err := os.Open(path)
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
	data, err := s.Inspector.Inspect(ctx, request)
	if err != nil {
		return failed(request, fmt.Errorf("inspect host: %w", err))
	}
	return protocol.Response{Version: protocol.Version, RequestID: request.RequestID, OK: true, Data: data}
}
