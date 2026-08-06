package agentserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"syscall"
)

var identityPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{7,159}$`)

type Identity struct {
	Version     int    `json:"version"`
	ServerID    string `json:"serverId"`
	MachineID   string `json:"machineId"`
	MachineName string `json:"machineName"`
	Account     string `json:"account"`
}

func LoadIdentity(path string, requireRootOwner bool) (Identity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Identity{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return Identity{}, errors.New("server identity must be a regular file that is not group or world writable")
	}
	if requireRootOwner {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return Identity{}, errors.New("server identity must be owned by root")
		}
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return Identity{}, err
	}
	return ParseIdentity(payload)
}

func ParseIdentity(payload []byte) (Identity, error) {
	var identity Identity
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&identity); err != nil {
		return Identity{}, fmt.Errorf("decode identity: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return Identity{}, errors.New("decode identity: trailing value")
		}
		return Identity{}, fmt.Errorf("decode identity: %w", err)
	}
	if identity.Version != 1 || !identityPattern.MatchString(identity.ServerID) || !identityPattern.MatchString(identity.MachineID) || identity.ServerID == identity.MachineID || identity.MachineName == "" || len(identity.MachineName) > 256 || identity.Account == "" || len(identity.Account) > 128 {
		return Identity{}, errors.New("identity has an unsupported version or invalid stable IDs")
	}
	return identity, nil
}
