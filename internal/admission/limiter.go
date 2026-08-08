package admission

import (
	"errors"
	"sync"
	"time"
)

type RejectReason string

const (
	RejectGlobalConcurrency RejectReason = "global concurrency limit reached"
	RejectKeyConcurrency    RejectReason = "caller concurrency limit reached"
	RejectGlobalRate        RejectReason = "global request rate limit reached"
	RejectKeyRate           RejectReason = "caller request rate limit reached"
	RejectKeyCapacity       RejectReason = "caller tracking capacity reached"
)

type Limits struct {
	MaxConcurrent        int
	MaxConcurrentPerKey  int
	MaxRequestsPerWindow int
	MaxGlobalPerWindow   int
	MaxKeys              int
	Window               time.Duration
	IdleTTL              time.Duration
}

type entry struct {
	active      int
	requests    int
	windowStart time.Time
	lastSeen    time.Time
}

// Limiter is a deliberately small, in-memory admission boundary. It bounds
// both active work and the number of caller identities retained by the
// limiter; it is not an authorization mechanism or a distributed quota.
type Limiter struct {
	mu                sync.Mutex
	limits            Limits
	now               func() time.Time
	active            int
	globalRequests    int
	globalWindowStart time.Time
	entries           map[string]*entry
}

func New(limits Limits, now func() time.Time) (*Limiter, error) {
	if limits.MaxConcurrent <= 0 || limits.MaxConcurrentPerKey <= 0 ||
		limits.MaxConcurrentPerKey > limits.MaxConcurrent || limits.MaxRequestsPerWindow <= 0 ||
		limits.MaxGlobalPerWindow < limits.MaxRequestsPerWindow || limits.MaxKeys <= 0 ||
		limits.Window <= 0 || limits.IdleTTL < limits.Window {
		return nil, errors.New("invalid admission limits")
	}
	if now == nil {
		now = time.Now
	}
	return &Limiter{limits: limits, now: now, entries: make(map[string]*entry)}, nil
}

// Acquire reserves one active request. The returned release function is safe
// to call more than once. A non-empty reject reason means no reservation was
// made.
func (l *Limiter) Acquire(key string) (release func(), rejected RejectReason) {
	if key == "" {
		key = "unknown"
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	l.pruneLocked(now)
	if l.globalWindowStart.IsZero() || now.Sub(l.globalWindowStart) >= l.limits.Window || now.Before(l.globalWindowStart) {
		l.globalWindowStart = now
		l.globalRequests = 0
	}
	if l.active >= l.limits.MaxConcurrent {
		return nil, RejectGlobalConcurrency
	}
	if l.globalRequests >= l.limits.MaxGlobalPerWindow {
		return nil, RejectGlobalRate
	}

	caller, exists := l.entries[key]
	if !exists {
		if len(l.entries) >= l.limits.MaxKeys {
			return nil, RejectKeyCapacity
		}
		caller = &entry{windowStart: now, lastSeen: now}
		l.entries[key] = caller
	}
	if now.Sub(caller.windowStart) >= l.limits.Window || now.Before(caller.windowStart) {
		caller.windowStart = now
		caller.requests = 0
	}
	caller.lastSeen = now
	if caller.active >= l.limits.MaxConcurrentPerKey {
		return nil, RejectKeyConcurrency
	}
	if caller.requests >= l.limits.MaxRequestsPerWindow {
		return nil, RejectKeyRate
	}

	l.active++
	l.globalRequests++
	caller.active++
	caller.requests++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.active--
			if current := l.entries[key]; current == caller {
				current.active--
				current.lastSeen = l.now()
			}
		})
	}, ""
}

func (l *Limiter) pruneLocked(now time.Time) {
	for key, caller := range l.entries {
		if caller.active == 0 && (now.Sub(caller.lastSeen) >= l.limits.IdleTTL || now.Before(caller.lastSeen)) {
			delete(l.entries, key)
		}
	}
}
