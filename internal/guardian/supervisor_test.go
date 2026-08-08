package guardian

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"testing"
	"time"
)

type fakeHeartbeatSource struct {
	records []HeartbeatRecord
	errors  []error
	reads   int
}

type blockingHeartbeatSource struct{}

func (blockingHeartbeatSource) Read(ctx context.Context) (HeartbeatRecord, error) {
	<-ctx.Done()
	return HeartbeatRecord{}, ctx.Err()
}

func (s *fakeHeartbeatSource) Read(context.Context) (HeartbeatRecord, error) {
	index := s.reads
	s.reads++
	if index < len(s.errors) && s.errors[index] != nil {
		return HeartbeatRecord{}, s.errors[index]
	}
	if len(s.records) == 0 {
		return HeartbeatRecord{}, errors.New("no heartbeat")
	}
	if index >= len(s.records) {
		index = len(s.records) - 1
	}
	return s.records[index], nil
}

type fakeProcessAccess struct {
	identities []ProcessIdentity
	inspectErr error
	inspects   int
	handle     *fakeProcessHandle
	opens      int
}

func (a *fakeProcessAccess) Inspect(context.Context, int) (ProcessIdentity, error) {
	if a.inspectErr != nil {
		return ProcessIdentity{}, a.inspectErr
	}
	index := a.inspects
	a.inspects++
	if index >= len(a.identities) {
		index = len(a.identities) - 1
	}
	return a.identities[index], nil
}

func (a *fakeProcessAccess) Open(context.Context, int) (ProcessHandle, error) {
	a.opens++
	return a.handle, nil
}

type fakeProcessHandle struct {
	signals []syscall.Signal
	exited  bool
	waitErr error
}

func (h *fakeProcessHandle) Signal(signal syscall.Signal) error {
	h.signals = append(h.signals, signal)
	return nil
}

func (h *fakeProcessHandle) Wait(context.Context) (bool, error) {
	return h.exited, h.waitErr
}

func (*fakeProcessHandle) Close() error { return nil }

func guardianTestConfig() Config {
	return Config{
		HeartbeatPath: "/run/ops-agent/agentd/guardian-heartbeat.json", ExpectedUID: 1001,
		ExpectedExecutable: "/opt/pi-ops-agent/releases/0.2.0/runtime/node",
		ExpectedCgroup:     "/system.slice/ops-agentd.service", HeartbeatTimeout: 45 * time.Second,
		CheckInterval: time.Second, OperationTimeout: time.Second, StartupGrace: time.Second,
		TermGrace: time.Millisecond, MaxClockSkew: 2 * time.Second,
	}
}

func heartbeatAt(at time.Time) HeartbeatRecord {
	record, err := ParseHeartbeat([]byte(validHeartbeatJSON(at.UTC().Format(time.RFC3339Nano))))
	if err != nil {
		panic(err)
	}
	return record
}

func newTestSupervisor(now time.Time, source *fakeHeartbeatSource, access *fakeProcessAccess) *Supervisor {
	return &Supervisor{Config: guardianTestConfig(), Source: source, Processes: access, Now: func() time.Time { return now }, SelfPID: 9999}
}

func TestSupervisorAcceptsFreshHeartbeatWithoutSignal(t *testing.T) {
	now := time.Date(2026, time.August, 8, 4, 0, 0, 0, time.UTC)
	record := heartbeatAt(now.Add(-time.Second))
	handle := &fakeProcessHandle{}
	access := &fakeProcessAccess{identities: []ProcessIdentity{record.Identity()}, handle: handle}
	result, err := newTestSupervisor(now, &fakeHeartbeatSource{records: []HeartbeatRecord{record}}, access).Check(context.Background())
	if err != nil || result.Outcome != OutcomeHealthy {
		t.Fatalf("unexpected result=%#v err=%v", result, err)
	}
	if access.opens != 0 || len(handle.signals) != 0 {
		t.Fatal("fresh heartbeat opened or signaled the process")
	}
}

func TestSupervisorTerminatesThenKillsSameStaleProcess(t *testing.T) {
	now := time.Date(2026, time.August, 8, 4, 0, 0, 0, time.UTC)
	record := heartbeatAt(now.Add(-time.Minute))
	handle := &fakeProcessHandle{waitErr: context.DeadlineExceeded}
	access := &fakeProcessAccess{identities: []ProcessIdentity{record.Identity(), record.Identity(), record.Identity()}, handle: handle}
	result, err := newTestSupervisor(now, &fakeHeartbeatSource{records: []HeartbeatRecord{record, record}}, access).Check(context.Background())
	if err != nil || result.Outcome != OutcomeKilled {
		t.Fatalf("unexpected result=%#v err=%v", result, err)
	}
	if fmt.Sprint(handle.signals) != fmt.Sprint([]syscall.Signal{syscall.SIGTERM, syscall.SIGKILL}) {
		t.Fatalf("unexpected signal sequence: %v", handle.signals)
	}
}

func TestSupervisorStopsAfterTermWhenProcessExits(t *testing.T) {
	now := time.Now().UTC()
	record := heartbeatAt(now.Add(-time.Minute))
	handle := &fakeProcessHandle{exited: true}
	access := &fakeProcessAccess{identities: []ProcessIdentity{record.Identity(), record.Identity()}, handle: handle}
	result, err := newTestSupervisor(now, &fakeHeartbeatSource{records: []HeartbeatRecord{record}}, access).Check(context.Background())
	if err != nil || result.Outcome != OutcomeTerminated || fmt.Sprint(handle.signals) != fmt.Sprint([]syscall.Signal{syscall.SIGTERM}) {
		t.Fatalf("unexpected result=%#v signals=%v err=%v", result, handle.signals, err)
	}
}

func TestSupervisorRejectsIdentityMismatchesWithoutSignal(t *testing.T) {
	now := time.Now().UTC()
	base := heartbeatAt(now.Add(-time.Minute))
	tests := map[string]struct {
		record   HeartbeatRecord
		identity ProcessIdentity
	}{
		"uid":        {record: withRecordUID(base, 2002), identity: base.Identity()},
		"executable": {record: withRecordExecutable(base, "/usr/bin/node"), identity: base.Identity()},
		"cgroup":     {record: withRecordCgroup(base, "/system.slice/other.service"), identity: base.Identity()},
		"starttime":  {record: base, identity: withStartTime(base.Identity(), base.StartTimeTicks+1)},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			handle := &fakeProcessHandle{}
			access := &fakeProcessAccess{identities: []ProcessIdentity{test.identity}, handle: handle}
			result, err := newTestSupervisor(now, &fakeHeartbeatSource{records: []HeartbeatRecord{test.record}}, access).Check(context.Background())
			if err == nil || result.Outcome != OutcomeRejected || access.opens != 0 || len(handle.signals) != 0 {
				t.Fatalf("mismatch was not fail-closed: result=%#v err=%v opens=%d signals=%v", result, err, access.opens, handle.signals)
			}
		})
	}
}

func TestSupervisorWithholdsKillOnPIDReuse(t *testing.T) {
	now := time.Now().UTC()
	record := heartbeatAt(now.Add(-time.Minute))
	reused := withStartTime(record.Identity(), record.StartTimeTicks+100)
	handle := &fakeProcessHandle{waitErr: context.DeadlineExceeded}
	access := &fakeProcessAccess{identities: []ProcessIdentity{record.Identity(), record.Identity(), reused}, handle: handle}
	result, err := newTestSupervisor(now, &fakeHeartbeatSource{records: []HeartbeatRecord{record, record}}, access).Check(context.Background())
	if err != nil || result.Outcome != OutcomeTermOnly {
		t.Fatalf("unexpected result=%#v err=%v", result, err)
	}
	if fmt.Sprint(handle.signals) != fmt.Sprint([]syscall.Signal{syscall.SIGTERM}) {
		t.Fatalf("guardian signaled reused PID: %v", handle.signals)
	}
}

func TestSupervisorWithholdsKillWhenHeartbeatAdvances(t *testing.T) {
	now := time.Now().UTC()
	stale := heartbeatAt(now.Add(-time.Minute))
	fresh := heartbeatAt(now)
	fresh.Sequence = stale.Sequence + 1
	handle := &fakeProcessHandle{waitErr: context.DeadlineExceeded}
	access := &fakeProcessAccess{identities: []ProcessIdentity{stale.Identity(), stale.Identity()}, handle: handle}
	result, err := newTestSupervisor(now, &fakeHeartbeatSource{records: []HeartbeatRecord{stale, fresh}}, access).Check(context.Background())
	if err != nil || result.Outcome != OutcomeTermOnly || len(handle.signals) != 1 {
		t.Fatalf("advanced heartbeat did not withhold KILL: result=%#v signals=%v err=%v", result, handle.signals, err)
	}
}

func TestSupervisorSuppressesRepeatedSignalsForSameGeneration(t *testing.T) {
	now := time.Now().UTC()
	record := heartbeatAt(now.Add(-time.Minute))
	handle := &fakeProcessHandle{exited: true}
	access := &fakeProcessAccess{identities: []ProcessIdentity{record.Identity(), record.Identity(), record.Identity()}, handle: handle}
	supervisor := newTestSupervisor(now, &fakeHeartbeatSource{records: []HeartbeatRecord{record}}, access)
	if _, err := supervisor.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	result, err := supervisor.Check(context.Background())
	if err != nil || result.Outcome != OutcomeSuppressed || len(handle.signals) != 1 {
		t.Fatalf("repeat action was not suppressed: result=%#v signals=%v err=%v", result, handle.signals, err)
	}
}

func TestSupervisorRejectsMalformedHeartbeatWithoutSignal(t *testing.T) {
	now := time.Now().UTC()
	handle := &fakeProcessHandle{}
	access := &fakeProcessAccess{identities: []ProcessIdentity{{}}, handle: handle}
	result, err := newTestSupervisor(now, &fakeHeartbeatSource{errors: []error{errors.New("malformed heartbeat")}}, access).Check(context.Background())
	if err == nil || result.Outcome != OutcomeRejected || access.inspects != 0 || len(handle.signals) != 0 {
		t.Fatalf("malformed record was not fail-closed: result=%#v err=%v", result, err)
	}
}

func TestSupervisorBoundsHeartbeatReadWithOperationDeadline(t *testing.T) {
	now := time.Now().UTC()
	config := guardianTestConfig()
	config.OperationTimeout = 20 * time.Millisecond
	supervisor := &Supervisor{
		Config: config, Source: blockingHeartbeatSource{},
		Processes: &fakeProcessAccess{}, Now: func() time.Time { return now }, SelfPID: 9999,
	}
	started := time.Now()
	result, err := supervisor.Check(context.Background())
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || result.Outcome != OutcomeRejected {
		t.Fatalf("deadline was not enforced: result=%#v err=%v", result, err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("deadline took too long: %s", elapsed)
	}
}

func withRecordUID(record HeartbeatRecord, uid uint32) HeartbeatRecord {
	record.UID = uid
	return record
}

func withRecordExecutable(record HeartbeatRecord, executable string) HeartbeatRecord {
	record.Executable = executable
	return record
}

func withRecordCgroup(record HeartbeatRecord, cgroup string) HeartbeatRecord {
	record.Cgroup = cgroup
	return record
}

func withStartTime(identity ProcessIdentity, start uint64) ProcessIdentity {
	identity.StartTimeTicks = start
	return identity
}
