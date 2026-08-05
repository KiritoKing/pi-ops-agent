package systemdhelper

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/audit"
	"github.com/KiritoKing/pi-ops-agent/internal/peercred"
	"github.com/KiritoKing/pi-ops-agent/internal/protocol"
)

type fakeRestarter struct{ calls int }

func (f *fakeRestarter) Restart(context.Context, string) error { f.calls++; return nil }

type fakeInspector struct{ calls int }

func (f *fakeInspector) HostSnapshot(context.Context) (interface{}, error) {
	f.calls++
	return map[string]string{"ok": "true"}, nil
}
func (f *fakeInspector) SystemdUnit(context.Context, string) (interface{}, error) {
	f.calls++
	return "unit", nil
}
func (f *fakeInspector) JournalTail(context.Context, string, int) (interface{}, error) {
	f.calls++
	return "journal", nil
}

func TestMonitorRestartsStaleAgentWithRateLimit(t *testing.T) {
	restarter := &fakeRestarter{}
	monitor := NewMonitor("ops-agentd.service", 10*time.Second, time.Second, time.Second, time.Hour, 1, restarter, nil)
	current := time.Now()
	monitor.Now = func() time.Time { return current }
	monitor.Heartbeat(current)
	current = current.Add(11 * time.Second)
	if !monitor.Check(context.Background()) || restarter.calls != 1 {
		t.Fatal("stale agent was not restarted")
	}
	current = current.Add(11 * time.Second)
	if monitor.Check(context.Background()) || restarter.calls != 1 {
		t.Fatal("restart rate limit did not suppress second restart")
	}
}

func TestServiceAcceptsOnlyAgentPeer(t *testing.T) {
	now := time.Now().UTC()
	log, err := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	monitor := NewMonitor("ops-agentd.service", time.Minute, time.Second, time.Minute, time.Hour, 3, &fakeRestarter{}, log)
	inspector := &fakeInspector{}
	service := &Service{AgentUID: 1001, Audit: log, Inspector: inspector, Monitor: monitor, Now: func() time.Time { return now }}
	request := protocol.Request{Version: 1, RequestID: "snapshot-0001", Deadline: now.Add(time.Minute), Method: protocol.MethodHostSnapshot}
	denied := service.Handle(context.Background(), peercred.Credential{UID: 0}, request)
	if denied.OK {
		t.Fatal("unexpected peer accessed systemd-helper")
	}
	allowed := service.Handle(context.Background(), peercred.Credential{UID: 1001}, request)
	if !allowed.OK || inspector.calls != 1 {
		t.Fatalf("agent inspection failed: %#v", allowed)
	}
}
