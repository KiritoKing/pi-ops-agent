//go:build linux

package peercred

import (
	"fmt"
	"net"
	"syscall"
)

func (OSResolver) Resolve(connection *net.UnixConn) (Credential, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return Credential{}, err
	}
	var credential *syscall.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credential, controlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return Credential{}, err
	}
	if controlErr != nil {
		return Credential{}, fmt.Errorf("SO_PEERCRED: %w", controlErr)
	}
	if credential == nil {
		return Credential{}, fmt.Errorf("SO_PEERCRED returned no credential")
	}
	return Credential{PID: int(credential.Pid), UID: credential.Uid, GID: credential.Gid}, nil
}
