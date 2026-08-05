//go:build !linux

package peercred

import (
	"errors"
	"net"
)

func (OSResolver) Resolve(*net.UnixConn) (Credential, error) {
	return Credential{}, errors.New("peer credential enforcement requires Linux SO_PEERCRED")
}
