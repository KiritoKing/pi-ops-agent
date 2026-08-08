package roothelper

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

type pveInspectRunner struct {
	name string
	args []string
}

func (r *pveInspectRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	r.name, r.args = name, append([]string(nil), args...)
	return `{"active":1,"enabled":1}`, nil
}

func TestPVEInspectionUsesOnlyConstructedAPIPath(t *testing.T) {
	runner := &pveInspectRunner{}
	request := protocol.Request{
		Method: protocol.MethodPVEStorageStatus,
		PVE:    protocol.PVEInspection{Node: "pve1", Storage: "local"},
	}
	if _, err := inspectPVE(context.Background(), runner, request); err != nil {
		t.Fatal(err)
	}
	if runner.name != pveshPath || strings.Join(runner.args, " ") != "get /nodes/pve1/storage/local/status --output-format json" {
		t.Fatalf("unexpected PVE inspection command: %s %#v", runner.name, runner.args)
	}
}

type oversizedPVEInspectRunner struct{}

func (oversizedPVEInspectRunner) Run(_ context.Context, _ string, _ ...string) (string, error) {
	return fmt.Sprintf(`{"value":%q}`, strings.Repeat("x", maxCommandOutput)), nil
}

func TestPVEInspectionRejectsOversizedOutput(t *testing.T) {
	request := protocol.Request{Method: protocol.MethodPVEClusterStatus}
	if _, err := inspectPVE(context.Background(), oversizedPVEInspectRunner{}, request); err == nil {
		t.Fatal("oversized PVE inspection output was accepted")
	}
}
