package scheduler

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// plant inserts an already-expired entry and returns its deadline.
func plant(s *Scheduler, key string) time.Time {
	d := time.Now().Add(-time.Second)
	s.mu.Lock()
	s.entries[key] = d
	s.mu.Unlock()
	return d
}

func entry(s *Scheduler, key string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.entries[key]
	return t, ok
}

// A redeploy that reschedules while the stop is running must keep its new
// deadline (compare-and-delete), and the callback can observe it.
func TestTick_rescheduledDuringStopKeepsNewDeadline(t *testing.T) {
	var s *Scheduler
	var dueBefore, dueAfter bool
	s = newTestScheduler(t, func(ctx context.Context, ns, env string) error {
		dueBefore = StillDue(ctx)
		if err := s.Schedule(ns, env, time.Hour); err != nil { // concurrent redeploy
			t.Error(err)
		}
		dueAfter = StillDue(ctx)
		return nil
	})
	plant(s, "myapp/staging")

	s.tick(context.Background())

	if !dueBefore || dueAfter {
		t.Errorf("StillDue before/after reschedule = %v/%v, want true/false", dueBefore, dueAfter)
	}
	d, ok := entry(s, "myapp/staging")
	if !ok || time.Until(d) < 50*time.Minute {
		t.Errorf("new deadline must be kept, got %v (present=%v)", d, ok)
	}
}

func TestTick_cancelledDuringStopIsNotRecreated(t *testing.T) {
	var s *Scheduler
	s = newTestScheduler(t, func(ctx context.Context, ns, env string) error {
		return s.Cancel(ns, env)
	})
	plant(s, "myapp/staging")
	s.tick(context.Background())
	if _, ok := entry(s, "myapp/staging"); ok {
		t.Error("cancelled entry must stay absent")
	}
}

func TestTick_supersededErrorKeepsEntry(t *testing.T) {
	var s *Scheduler
	s = newTestScheduler(t, func(ctx context.Context, ns, env string) error {
		_ = s.Schedule(ns, env, time.Hour)
		if StillDue(ctx) {
			t.Error("StillDue must be false after a reschedule")
		}
		return ErrSuperseded
	})
	plant(s, "myapp/staging")
	s.tick(context.Background())
	if _, ok := entry(s, "myapp/staging"); !ok {
		t.Error("rescheduled entry must be kept")
	}
}

// fire re-reads the entry before calling stopFn: an entry rescheduled between
// the expired-list snapshot and the call is not stopped.
func TestFire_skipsWhenDeadlineChanged(t *testing.T) {
	called := false
	s := newTestScheduler(t, func(context.Context, string, string) error {
		called = true
		return nil
	})
	old := plant(s, "myapp/staging")
	if err := s.Schedule("myapp", "staging", time.Hour); err != nil {
		t.Fatal(err)
	}

	s.fire(context.Background(), "myapp/staging", "myapp", "staging", old)

	if called {
		t.Error("stopFn must not run for a superseded deadline")
	}
	if _, ok := entry(s, "myapp/staging"); !ok {
		t.Error("new entry must be kept")
	}
}

func TestStillDue_outsideScheduler(t *testing.T) {
	if !StillDue(context.Background()) {
		t.Error("StillDue must default to true for foreign contexts")
	}
}

func TestTick_stopTimeout(t *testing.T) {
	s := newTestScheduler(t, func(ctx context.Context, _, _ string) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("stop context must carry a deadline")
		}
		<-ctx.Done()
		return ctx.Err()
	})
	s.stopTimeout = 20 * time.Millisecond
	plant(s, "myapp/staging")

	done := make(chan struct{})
	go func() { s.tick(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("tick must return once the stop times out")
	}
	if _, ok := entry(s, "myapp/staging"); !ok {
		t.Error("timed-out stop must keep the entry for a retry")
	}
}

// A blocked stop occupies one worker only: the others proceed, and no more
// than maxConcurrentStops run at once.
func TestTick_boundedParallelism(t *testing.T) {
	release := make(chan struct{})
	var running, peak, finished atomic.Int32
	var mu sync.Mutex
	s := newTestScheduler(t, func(ctx context.Context, ns, _ string) error {
		n := running.Add(1)
		defer running.Add(-1)
		mu.Lock()
		if n > peak.Load() {
			peak.Store(n)
		}
		mu.Unlock()
		if ns == "stuck" {
			select {
			case <-release:
			case <-ctx.Done():
			}
			return errors.New("stuck")
		}
		time.Sleep(5 * time.Millisecond)
		finished.Add(1)
		return nil
	})
	plant(s, "stuck/env")
	for _, k := range []string{"a/env", "b/env", "c/env", "d/env"} {
		plant(s, k)
	}

	done := make(chan struct{})
	go func() { s.tick(context.Background()); close(done) }()

	deadline := time.After(5 * time.Second)
	for finished.Load() < 4 {
		select {
		case <-deadline:
			t.Fatalf("only %d stops finished while one was stuck", finished.Load())
		case <-time.After(5 * time.Millisecond):
		}
	}
	close(release)
	<-done

	if p := peak.Load(); p > maxConcurrentStops {
		t.Errorf("peak concurrency = %d, want ≤ %d", p, maxConcurrentStops)
	}
}

func TestTick_cancelledContextStopsLaunching(t *testing.T) {
	var calls atomic.Int32
	block := make(chan struct{})
	s := newTestScheduler(t, func(ctx context.Context, _, _ string) error {
		calls.Add(1)
		<-block
		return nil
	})
	for _, k := range []string{"a/env", "b/env", "c/env", "d/env"} {
		plant(s, k)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.tick(ctx); close(done) }()
	for calls.Load() < maxConcurrentStops {
		time.Sleep(time.Millisecond)
	}
	cancel()
	close(block)
	<-done
	if c := calls.Load(); c != maxConcurrentStops {
		t.Errorf("calls = %d, want %d (no launch after cancel)", c, maxConcurrentStops)
	}
}
