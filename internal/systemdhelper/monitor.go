package systemdhelper

import (
	"context"
	"sync"
	"time"

	"github.com/KiritoKing/pi-ops-agent/internal/audit"
)

type Restarter interface {
	Restart(context.Context, string) error
}

type Monitor struct {
	mu               sync.Mutex
	Unit             string
	HeartbeatTimeout time.Duration
	CheckInterval    time.Duration
	RestartCooldown  time.Duration
	RestartWindow    time.Duration
	MaxRestarts      int
	Restarter        Restarter
	Audit            *audit.Log
	Now              func() time.Time
	lastHeartbeat    time.Time
	lastRestart      time.Time
	restarts         []time.Time
}

func NewMonitor(unit string, timeout, interval, cooldown, window time.Duration, maximum int, restarter Restarter, log *audit.Log) *Monitor {
	now := time.Now()
	return &Monitor{Unit: unit, HeartbeatTimeout: timeout, CheckInterval: interval, RestartCooldown: cooldown, RestartWindow: window, MaxRestarts: maximum, Restarter: restarter, Audit: log, Now: time.Now, lastHeartbeat: now}
}

func (m *Monitor) Heartbeat(at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if at.After(m.lastHeartbeat) {
		m.lastHeartbeat = at
	}
}

func (m *Monitor) Run(ctx context.Context) {
	interval := m.CheckInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.Check(ctx)
		}
	}
}

func (m *Monitor) Check(ctx context.Context) bool {
	m.mu.Lock()
	now := m.Now()
	if now.Sub(m.lastHeartbeat) <= m.HeartbeatTimeout || (!m.lastRestart.IsZero() && now.Sub(m.lastRestart) < m.RestartCooldown) {
		m.mu.Unlock()
		return false
	}
	cutoff := now.Add(-m.RestartWindow)
	kept := m.restarts[:0]
	for _, attempt := range m.restarts {
		if attempt.After(cutoff) {
			kept = append(kept, attempt)
		}
	}
	m.restarts = kept
	if len(m.restarts) >= m.MaxRestarts {
		m.mu.Unlock()
		if m.Audit != nil {
			_, _ = m.Audit.Append(map[string]interface{}{"type": "restart_suppressed", "unit": m.Unit, "reason": "restart limit reached"})
		}
		return false
	}
	m.lastRestart, m.lastHeartbeat = now, now
	m.restarts = append(m.restarts, now)
	m.mu.Unlock()
	err := m.Restarter.Restart(ctx, m.Unit)
	if m.Audit != nil {
		event := map[string]interface{}{"type": "agent_restart", "unit": m.Unit, "ok": err == nil}
		if err != nil {
			event["error"] = err.Error()
		}
		_, _ = m.Audit.Append(event)
	}
	return true
}
