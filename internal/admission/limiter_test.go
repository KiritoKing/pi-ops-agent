package admission

import (
	"sync"
	"testing"
	"time"
)

func TestLimiterEnforcesConcurrencyRateAndBoundedCallerState(t *testing.T) {
	now := time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)
	limiter, err := New(Limits{
		MaxConcurrent: 2, MaxConcurrentPerKey: 1,
		MaxRequestsPerWindow: 2, MaxGlobalPerWindow: 3,
		MaxKeys: 2, Window: time.Second, IdleTTL: 2 * time.Second,
	}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}

	releaseA, rejected := limiter.Acquire("a")
	if rejected != "" {
		t.Fatal(rejected)
	}
	if _, rejected = limiter.Acquire("a"); rejected != RejectKeyConcurrency {
		t.Fatalf("same caller concurrency rejection=%q", rejected)
	}
	releaseB, rejected := limiter.Acquire("b")
	if rejected != "" {
		t.Fatal(rejected)
	}
	if _, rejected = limiter.Acquire("c"); rejected != RejectGlobalConcurrency {
		t.Fatalf("global concurrency rejection=%q", rejected)
	}
	releaseA()
	releaseA()
	if _, rejected = limiter.Acquire("c"); rejected != RejectKeyCapacity {
		t.Fatalf("bounded caller map rejection=%q", rejected)
	}
	releaseB()

	releaseA, rejected = limiter.Acquire("a")
	if rejected != "" {
		t.Fatalf("second request for a rejected: %q", rejected)
	}
	releaseA()
	if _, rejected = limiter.Acquire("a"); rejected != RejectGlobalRate {
		t.Fatalf("global rate rejection=%q", rejected)
	}

	now = now.Add(3 * time.Second)
	releaseC, rejected := limiter.Acquire("c")
	if rejected != "" {
		t.Fatalf("idle identities were not pruned after window advance: %q", rejected)
	}
	releaseC()
}

func TestLimiterReleaseIsRaceSafe(t *testing.T) {
	limiter, err := New(Limits{
		MaxConcurrent: 32, MaxConcurrentPerKey: 32,
		MaxRequestsPerWindow: 64, MaxGlobalPerWindow: 64,
		MaxKeys: 4, Window: time.Second, IdleTTL: time.Minute,
	}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	releases := make([]func(), 0, 32)
	for index := 0; index < 32; index++ {
		release, rejected := limiter.Acquire("caller")
		if rejected != "" {
			t.Fatal(rejected)
		}
		releases = append(releases, release)
	}
	var wait sync.WaitGroup
	for _, release := range releases {
		wait.Add(2)
		go func(release func()) { defer wait.Done(); release() }(release)
		go func(release func()) { defer wait.Done(); release() }(release)
	}
	wait.Wait()
	if _, rejected := limiter.Acquire("caller"); rejected != "" {
		t.Fatalf("released capacity was not restored: %q", rejected)
	}
}
