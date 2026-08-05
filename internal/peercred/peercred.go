package peercred

import "net"

type Credential struct {
	PID int
	UID uint32
	GID uint32
}

type Resolver interface {
	Resolve(*net.UnixConn) (Credential, error)
}

type OSResolver struct{}
