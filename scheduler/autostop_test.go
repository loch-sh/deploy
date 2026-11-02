package scheduler

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestSchedule_and_Cancel(t *testing.T) {
	s := newTestScheduler(t, nil)

	if err := s.Schedule("myapp", "staging", 24*time.Hour); err != nil {
		t.Fatalf("schedule: %v", err)
	}

	s.mu.Lock()
	if _, ok := s.entries["myapp/staging"]; !ok {
		t.Error("entry not found after Schedule")
	}
	s.mu.Unlock()

	if err := s.Cancel("myapp", "staging"); err != nil {
		t.Fatalf("cancel: %v", err)
	}

	s.mu.Lock()
	if _, ok := s.entries["myapp/staging"]; ok {
		t.Error("entry still present after Cancel")
	}
	s.mu.Unlock()
}

func TestTick_firesExpiredEntries(t *testing.T) {
	var called atomic.Int32
	stopFn := func(_ context.Context, ns, env string) error {
		called.Add(1)
		return nil
	}

	s := newTestScheduler(t, stopFn)
	// Directly plant an already-expired entry (past time) bypassing Schedule's
	// duration≤0 guard, which would delete the entry instead.
	s.mu.Lock()
	s.entries["myapp/staging"] = time.Now().Add(-1 * time.Second)
	s.mu.Unlock()

	ctx := context.Background()
	s.tick(ctx)

	if called.Load() != 1 {
		t.Errorf("stopFn called %d times, want 1", called.Load())
	}

	// After firing, the entry must be removed.
	s.mu.Lock()
	if _, ok := s.entries["myapp/staging"]; ok {
		t.Error("entry still present after tick fired it")
	}
	s.mu.Unlock()
}

func TestTick_doesNotFireFutureEntries(t *testing.T) {
	var called atomic.Int32
	stopFn := func(_ context.Context, _, _ string) error {
		called.Add(1)
		return nil
	}

	s := newTestScheduler(t, stopFn)
	if err := s.Schedule("myapp", "staging", 10*time.Hour); err != nil {
		t.Fatalf("schedule: %v", err)
	}

	s.tick(context.Background())

	if called.Load() != 0 {
		t.Errorf("stopFn called %d times, want 0", called.Load())
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	noop := func(_ context.Context, _, _ string) error { return nil }

	s1, err := Load(dir, noop)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := s1.Schedule("myapp", "staging", 24*time.Hour); err != nil {
		t.Fatalf("schedule: %v", err)
	}

	// Reload from same directory.
	s2, err := Load(dir, noop)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	s2.mu.Lock()
	if _, ok := s2.entries["myapp/staging"]; !ok {
		t.Error("entry not found after reload")
	}
	s2.mu.Unlock()
}

func TestSplitKey(t *testing.T) {
	ns, env, ok := splitKey("myapp/staging")
	if !ok || ns != "myapp" || env != "staging" {
		t.Errorf("splitKey: got (%q, %q, %v)", ns, env, ok)
	}
	if _, _, ok := splitKey("bad-key"); ok {
		t.Error("splitKey should return ok=false for key without '/'")
	}
}

func newTestScheduler(t *testing.T, fn StopFunc) *Scheduler {
	t.Helper()
	if fn == nil {
		fn = func(_ context.Context, _, _ string) error { return nil }
	}
	s, err := Load(t.TempDir(), fn)
	if err != nil {
		t.Fatalf("newTestScheduler: %v", err)
	}
	return s
}
