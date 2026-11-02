package scheduler

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStart_firesExpiredEntriesImmediately(t *testing.T) {
	fired := make(chan string, 1)
	s := newTestScheduler(t, func(_ context.Context, ns, env string) error {
		fired <- ns + "/" + env
		return nil
	})
	s.mu.Lock()
	s.entries["myapp/staging"] = time.Now().Add(-time.Minute)
	s.mu.Unlock()

	s.Start(context.Background())
	defer s.Stop()

	select {
	case got := <-fired:
		if got != "myapp/staging" {
			t.Errorf("fired %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("expired entry not fired on start")
	}
}

func TestStop_withoutStartIsSafe(t *testing.T) {
	newTestScheduler(t, nil).Stop()
}

func TestTick_keepsEntryWhenStopFails(t *testing.T) {
	s := newTestScheduler(t, func(context.Context, string, string) error {
		return errors.New("compose down failed")
	})
	s.mu.Lock()
	s.entries["myapp/staging"] = time.Now().Add(-time.Second)
	s.mu.Unlock()

	s.tick(context.Background())

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries["myapp/staging"]; !ok {
		t.Error("entry must be kept for a retry on the next tick")
	}
}

func TestTick_removesMalformedKey(t *testing.T) {
	called := false
	s := newTestScheduler(t, func(context.Context, string, string) error {
		called = true
		return nil
	})
	s.mu.Lock()
	s.entries["no-separator"] = time.Now().Add(-time.Second)
	s.mu.Unlock()

	s.tick(context.Background())

	if called {
		t.Error("stopFn must not be called for a malformed key")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) != 0 {
		t.Errorf("malformed entry not removed: %v", s.entries)
	}
}

func TestLoad_stateFileErrors(t *testing.T) {
	noop := func(context.Context, string, string) error { return nil }

	t.Run("corrupt JSON", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "autostop.json"), []byte("{"), 0o600)
		if _, err := Load(dir, noop); err == nil {
			t.Error("expected error for corrupt state file")
		}
	})

	t.Run("unreadable path", func(t *testing.T) {
		dir := t.TempDir()
		os.Mkdir(filepath.Join(dir, "autostop.json"), 0o700)
		if _, err := Load(dir, noop); err == nil {
			t.Error("expected error when the state file is a directory")
		}
	})

	t.Run("malformed timestamp is skipped", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "autostop.json"),
			[]byte(`{"a/b":"not-a-time","c/d":"2030-01-01T00:00:00Z"}`), 0o600)
		s, err := Load(dir, noop)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if _, ok := s.entries["a/b"]; ok || len(s.entries) != 1 {
			t.Errorf("entries = %v, want only c/d", s.entries)
		}
	})
}

func TestSchedule_flushFailure(t *testing.T) {
	dir := t.TempDir()
	s, err := Load(filepath.Join(dir, "state"), func(context.Context, string, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	// Make the state directory impossible to create.
	os.WriteFile(filepath.Join(dir, "state"), nil, 0o600)

	if err := s.Schedule("myapp", "staging", time.Hour); err == nil {
		t.Error("expected flush error")
	}
}
