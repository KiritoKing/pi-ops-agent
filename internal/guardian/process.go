package guardian

import (
	"context"
	"syscall"
)

type ProcessIdentity struct {
	PID            int
	UID            uint32
	Executable     string
	Cgroup         string
	StartTimeTicks uint64
}

func (i ProcessIdentity) Equal(other ProcessIdentity) bool {
	return i.PID == other.PID && i.UID == other.UID && i.Executable == other.Executable &&
		i.Cgroup == other.Cgroup && i.StartTimeTicks == other.StartTimeTicks
}

type ProcessHandle interface {
	Signal(syscall.Signal) error
	Wait(context.Context) (bool, error)
	Close() error
}

type ProcessAccess interface {
	Inspect(context.Context, int) (ProcessIdentity, error)
	Open(context.Context, int) (ProcessHandle, error)
}
