//go:build !linux

package guardian

import (
	"fmt"
)

func NewLinuxProcessAccess() (ProcessAccess, error) {
	return nil, fmt.Errorf("agentd guardian requires Linux pidfds and procfs")
}
