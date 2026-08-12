package guardian

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"syscall"
	"time"
)

type Outcome string

const (
	OutcomeHealthy    Outcome = "healthy"
	OutcomeSuppressed Outcome = "suppressed"
	OutcomeTerminated Outcome = "terminated"
	OutcomeKilled     Outcome = "killed"
	OutcomeTermOnly   Outcome = "term_only"
	OutcomeRejected   Outcome = "rejected"
)

type Result struct {
	Outcome Outcome
	PID     int
	Reason  string
}

type Supervisor struct {
	Config    Config
	Source    HeartbeatSource
	Processes ProcessAccess
	Now       func() time.Time
	SelfPID   int

	mu        sync.Mutex
	lastActed ProcessIdentity
	hasActed  bool
}

func (s *Supervisor) Check(ctx context.Context) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Source == nil || s.Processes == nil {
		return Result{Outcome: OutcomeRejected}, fmt.Errorf("guardian dependencies are not configured")
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	record, err := s.readHeartbeat(ctx)
	if err != nil {
		return Result{Outcome: OutcomeRejected}, err
	}
	if err := s.validateRecord(record); err != nil {
		return Result{Outcome: OutcomeRejected, PID: record.PID}, err
	}
	identity, err := s.inspect(ctx, record.PID)
	if err != nil {
		return Result{Outcome: OutcomeRejected, PID: record.PID}, err
	}
	if err := matchIdentity(record.Identity(), identity); err != nil {
		return Result{Outcome: OutcomeRejected, PID: record.PID}, err
	}
	now := s.Now().UTC()
	if record.IsFresh(now, s.Config.HeartbeatTimeout, s.Config.MaxClockSkew) {
		s.hasActed = false
		return Result{Outcome: OutcomeHealthy, PID: record.PID}, nil
	}
	if s.hasActed && s.lastActed.Equal(identity) {
		return Result{Outcome: OutcomeSuppressed, PID: record.PID, Reason: "termination already attempted for this process generation"}, nil
	}
	return s.terminate(ctx, record, identity)
}

func (s *Supervisor) Run(ctx context.Context, report func(Result, error)) {
	startup := time.NewTimer(s.Config.StartupGrace)
	defer startup.Stop()
	select {
	case <-ctx.Done():
		return
	case <-startup.C:
	}
	for {
		result, err := s.Check(ctx)
		if report != nil {
			report(result, err)
		}
		timer := time.NewTimer(s.Config.CheckInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (s *Supervisor) terminate(ctx context.Context, record HeartbeatRecord, identity ProcessIdentity) (Result, error) {
	handle, err := s.open(ctx, record.PID)
	if err != nil {
		return Result{Outcome: OutcomeRejected, PID: record.PID}, err
	}
	defer handle.Close()
	revalidated, err := s.inspect(ctx, record.PID)
	if err != nil {
		return Result{Outcome: OutcomeRejected, PID: record.PID}, err
	}
	if !identity.Equal(revalidated) {
		return Result{Outcome: OutcomeRejected, PID: record.PID}, fmt.Errorf("process identity changed after pidfd open")
	}
	s.lastActed, s.hasActed = identity, true
	if err := handle.Signal(syscall.SIGTERM); err != nil {
		return Result{Outcome: OutcomeTermOnly, PID: record.PID}, err
	}
	graceContext, cancel := context.WithTimeout(ctx, s.Config.TermGrace)
	exited, waitErr := handle.Wait(graceContext)
	cancel()
	if exited {
		return Result{Outcome: OutcomeTerminated, PID: record.PID}, nil
	}
	if waitErr != nil && !errors.Is(waitErr, context.DeadlineExceeded) {
		return Result{Outcome: OutcomeTermOnly, PID: record.PID}, waitErr
	}
	latest, err := s.readHeartbeat(ctx)
	if err != nil {
		return Result{Outcome: OutcomeTermOnly, PID: record.PID, Reason: "heartbeat unavailable after TERM; KILL withheld"}, err
	}
	if err := s.validateRecord(latest); err != nil {
		return Result{Outcome: OutcomeTermOnly, PID: record.PID, Reason: "heartbeat invalid after TERM; KILL withheld"}, err
	}
	if !record.SameGeneration(latest) {
		return Result{Outcome: OutcomeTermOnly, PID: record.PID, Reason: "heartbeat generation changed after TERM; KILL withheld"}, nil
	}
	if latest.IsFresh(s.Now().UTC(), s.Config.HeartbeatTimeout, s.Config.MaxClockSkew) {
		return Result{Outcome: OutcomeTermOnly, PID: record.PID, Reason: "heartbeat recovered after TERM; KILL withheld"}, nil
	}
	finalIdentity, err := s.inspect(ctx, record.PID)
	if err != nil {
		return Result{Outcome: OutcomeTermOnly, PID: record.PID, Reason: "process unavailable after TERM; KILL withheld"}, err
	}
	if !identity.Equal(finalIdentity) {
		return Result{Outcome: OutcomeTermOnly, PID: record.PID, Reason: "process identity changed after TERM; KILL withheld"}, nil
	}
	if err := handle.Signal(syscall.SIGKILL); err != nil {
		return Result{Outcome: OutcomeTermOnly, PID: record.PID}, err
	}
	return Result{Outcome: OutcomeKilled, PID: record.PID}, nil
}

func (s *Supervisor) validateRecord(record HeartbeatRecord) error {
	if record.PID == s.SelfPID {
		return fmt.Errorf("heartbeat targets guardian process itself")
	}
	if record.UID != s.Config.ExpectedUID || record.Executable != s.Config.ExpectedExecutable || record.Cgroup != s.Config.ExpectedCgroup {
		return fmt.Errorf("heartbeat identity does not match fixed guardian configuration")
	}
	if record.observedTime.After(s.Now().UTC().Add(s.Config.MaxClockSkew)) {
		return fmt.Errorf("heartbeat timestamp is too far in the future")
	}
	return nil
}

func matchIdentity(expected, actual ProcessIdentity) error {
	if !expected.Equal(actual) {
		return fmt.Errorf("live process identity does not match heartbeat")
	}
	return nil
}

func (s *Supervisor) readHeartbeat(ctx context.Context) (HeartbeatRecord, error) {
	operation, cancel := context.WithTimeout(ctx, s.Config.OperationTimeout)
	defer cancel()
	return s.Source.Read(operation)
}

func (s *Supervisor) inspect(ctx context.Context, pid int) (ProcessIdentity, error) {
	operation, cancel := context.WithTimeout(ctx, s.Config.OperationTimeout)
	defer cancel()
	return s.Processes.Inspect(operation, pid)
}

func (s *Supervisor) open(ctx context.Context, pid int) (ProcessHandle, error) {
	operation, cancel := context.WithTimeout(ctx, s.Config.OperationTimeout)
	defer cancel()
	return s.Processes.Open(operation, pid)
}
