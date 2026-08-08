//go:build linux

package guardian

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxProcessAccessReadsOnlyExactProcessIdentity(t *testing.T) {
	const pid = 4321
	processRoot := filepath.Join(t.TempDir(), fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(processRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	fields := make([]string, 20)
	for index := range fields {
		fields[index] = fmt.Sprintf("%d", index+3)
	}
	fields[0] = "S"
	fields[19] = "998877"
	files := map[string]string{
		"stat":   fmt.Sprintf("%d (agentd worker) %s\n", pid, strings.Join(fields, " ")),
		"status": "Name:\tagentd\nUid:\t1001\t1001\t1001\t1001\n",
		"cgroup": "0::/system.slice/ops-agentd.service\n",
	}
	for name, payload := range files {
		if err := os.WriteFile(filepath.Join(processRoot, name), []byte(payload), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/opt/pi-ops-agent/releases/0.2.0/runtime/node", filepath.Join(processRoot, "exe")); err != nil {
		t.Fatal(err)
	}
	identity, err := (LinuxProcessAccess{ProcRoot: filepath.Dir(processRoot)}).Inspect(context.Background(), pid)
	if err != nil {
		t.Fatal(err)
	}
	expected := ProcessIdentity{
		PID: pid, UID: 1001, Executable: "/opt/pi-ops-agent/releases/0.2.0/runtime/node",
		Cgroup: "/system.slice/ops-agentd.service", StartTimeTicks: 998877,
	}
	if !identity.Equal(expected) {
		t.Fatalf("unexpected process identity: %#v", identity)
	}
}
