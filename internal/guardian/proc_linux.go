//go:build linux

package guardian

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const maximumProcIdentityBytes = 256 * 1024

type LinuxProcessAccess struct {
	ProcRoot string
}

func NewLinuxProcessAccess() (ProcessAccess, error) {
	if !platformPidfdSupported() {
		return nil, fmt.Errorf("agentd guardian supports Linux amd64 and arm64 pidfds")
	}
	return LinuxProcessAccess{ProcRoot: "/proc"}, nil
}

func (a LinuxProcessAccess) Inspect(ctx context.Context, pid int) (ProcessIdentity, error) {
	if pid <= 1 {
		return ProcessIdentity{}, fmt.Errorf("invalid process PID %d", pid)
	}
	root := a.ProcRoot
	if root == "" {
		root = "/proc"
	}
	processRoot := filepath.Join(root, strconv.Itoa(pid))
	firstStart, err := readProcStartTime(ctx, filepath.Join(processRoot, "stat"), pid)
	if err != nil {
		return ProcessIdentity{}, err
	}
	status, err := readProcFile(ctx, filepath.Join(processRoot, "status"))
	if err != nil {
		return ProcessIdentity{}, err
	}
	uid, err := parseProcUID(string(status))
	if err != nil {
		return ProcessIdentity{}, err
	}
	if err := ctx.Err(); err != nil {
		return ProcessIdentity{}, err
	}
	executable, err := os.Readlink(filepath.Join(processRoot, "exe"))
	if err != nil {
		return ProcessIdentity{}, fmt.Errorf("read process executable: %w", err)
	}
	if !cleanAbsolutePath(executable) || strings.HasSuffix(executable, " (deleted)") {
		return ProcessIdentity{}, fmt.Errorf("process executable is not a live clean absolute path")
	}
	cgroupPayload, err := readProcFile(ctx, filepath.Join(processRoot, "cgroup"))
	if err != nil {
		return ProcessIdentity{}, err
	}
	cgroup, err := parseProcCgroup(string(cgroupPayload))
	if err != nil {
		return ProcessIdentity{}, err
	}
	secondStart, err := readProcStartTime(ctx, filepath.Join(processRoot, "stat"), pid)
	if err != nil {
		return ProcessIdentity{}, err
	}
	if firstStart != secondStart {
		return ProcessIdentity{}, fmt.Errorf("process identity changed during inspection")
	}
	return ProcessIdentity{PID: pid, UID: uid, Executable: executable, Cgroup: cgroup, StartTimeTicks: firstStart}, nil
}

func (LinuxProcessAccess) Open(ctx context.Context, pid int) (ProcessHandle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := pidfdOpenExact(pid)
	if err != nil {
		return nil, fmt.Errorf("open pidfd for %d: %w", pid, err)
	}
	return &pidfdHandle{fd: fd}, nil
}

func readProcStartTime(ctx context.Context, path string, pid int) (uint64, error) {
	payload, err := readProcFile(ctx, path)
	if err != nil {
		return 0, err
	}
	return parseProcStartTime(string(payload), pid)
}

func readProcFile(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open process identity file: %w", err)
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, maximumProcIdentityBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read process identity file: %w", err)
	}
	if len(payload) > maximumProcIdentityBytes {
		return nil, fmt.Errorf("process identity file is too large")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return payload, nil
}

type pidfdHandle struct {
	fd int
}

func (h *pidfdHandle) Signal(signal syscall.Signal) error {
	if err := pidfdSignalExact(h.fd, signal); err != nil {
		return fmt.Errorf("send signal through pidfd: %w", err)
	}
	return nil
}

func (h *pidfdHandle) Wait(ctx context.Context) (bool, error) {
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		err := pidfdSignalExact(h.fd, 0)
		if errors.Is(err, syscall.ESRCH) {
			return true, nil
		}
		if err != nil {
			return false, fmt.Errorf("probe pidfd: %w", err)
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false, ctx.Err()
		case <-timer.C:
		}
	}
}

func (h *pidfdHandle) Close() error {
	return syscall.Close(h.fd)
}
