// Package scheduler implements the auto-stop timer for ephemeral environments.
//
// When a deployment requests an auto-stop, the target time is persisted to
// data/autostop.json. A background goroutine polls every 5 minutes and runs
// the stop callback for any entry whose deadline has passed.
//
// The state file is written atomically (temp-file + fsync + rename + directory
// fsync) to avoid corruption on crashes. State is reloaded from disk on startup
// so timers survive restarts.
//
// # Keys
//
// Entries are keyed "{namespace}/{environment}", unlike the registry and the
// on-disk stack directory which use "{namespace}-{environment}". This is
// deliberate: slugs never contain "/", so the key can be split back into the
// (namespace, environment) pair the stop callback needs, whereas the "-" form is
// ambiguous ("foo-bar"+"baz" vs "foo"+"bar-baz"). Aligning on "-" would require
// storing the pair separately and would import the registry's collision class
// into the scheduler for no benefit.
//
// # Races with redeploys
//
// An entry is only stopped (and removed) if its deadline is unchanged: the
// scheduler re-reads the entry right before invoking the stop callback, exposes
// the check to the callback through StillDue(ctx), and removes the entry
// afterwards only if the deadline is still the one that fired (compare-and-
// delete). A redeploy that reschedules or cancels the stop in between is
// therefore never erased. The callback should call StillDue once it holds the
// stack lock and return ErrSuperseded when it reports false; otherwise a
// redeploy that completes between the scheduler's pre-check and the callback
// taking the lock is still stopped (its new deadline is kept).
package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	tickInterval = 5 * time.Minute

	// defaultStopTimeout bounds a single auto-stop so a hung compose command
	// cannot hold a worker forever.
	defaultStopTimeout = 10 * time.Minute

	// maxConcurrentStops bounds how many auto-stops run at once, so one stuck
	// stack does not delay the others while the host is not flooded.
	maxConcurrentStops = 2
)

// StopFunc is called by the scheduler when a stack's auto-stop deadline is reached.
// namespace and environment identify the stack to stop. ctx carries a timeout
// and the StillDue guard; see StillDue and ErrSuperseded.
type StopFunc func(ctx context.Context, namespace, environment string) error

// ErrSuperseded may be returned by a StopFunc that found, after taking the
// stack lock, that StillDue(ctx) is false. The scheduler then skips the stop
// silently and keeps the current entry.
var ErrSuperseded = errors.New("scheduler: auto-stop superseded by a newer schedule")

// stillDueKey is the context key carrying the StillDue guard.
type stillDueKey struct{}

// StillDue reports whether the auto-stop that produced ctx is still wanted:
// the entry still exists with the deadline that fired. A StopFunc should call
// it after acquiring the stack lock (i.e. once no deploy can reschedule
// concurrently) and return ErrSuperseded when it is false. For contexts not
// created by the scheduler (e.g. a manual DELETE /stack) it returns true.
func StillDue(ctx context.Context) bool {
	if f, ok := ctx.Value(stillDueKey{}).(func() bool); ok {
		return f()
	}
	return true
}

// Scheduler manages auto-stop entries and runs them in the background.
type Scheduler struct {
	mu      sync.Mutex
	path    string
	entries map[string]time.Time // "{namespace}/{environment}" → stop_at
	stopFn  StopFunc
	// stopTimeout bounds each stopFn call (defaultStopTimeout; tests lower it).
	stopTimeout time.Duration
	cancelFn    context.CancelFunc
	done        chan struct{} // closed when the background loop has exited
}

// Load reads existing auto-stop entries from dataDir/autostop.json and creates
// a Scheduler ready to be started. stopFn is invoked for each expired entry.
func Load(dataDir string, stopFn StopFunc) (*Scheduler, error) {
	path := filepath.Join(dataDir, "autostop.json")
	s := &Scheduler{
		path:        path,
		entries:     make(map[string]time.Time),
		stopFn:      stopFn,
		stopTimeout: defaultStopTimeout,
	}

	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("scheduler: read %s: %w", path, err)
	}

	// Stored as map[string]string (RFC3339) for human readability.
	var stored map[string]string
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, fmt.Errorf("scheduler: corrupt %s: %w", path, err)
	}
	for key, ts := range stored {
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			slog.Warn("scheduler: skipping malformed entry", "key", key, "error", err)
			continue
		}
		s.entries[key] = t
	}
	return s, nil
}

// Schedule registers or updates an auto-stop for (namespace, environment) to fire
// at now+duration. Passing duration ≤ 0 removes any existing entry.
func (s *Scheduler) Schedule(namespace, environment string, duration time.Duration) error {
	key := makeKey(namespace, environment)

	s.mu.Lock()
	defer s.mu.Unlock()

	if duration <= 0 {
		delete(s.entries, key)
	} else {
		s.entries[key] = time.Now().Add(duration)
	}
	return s.flush()
}

// Cancel removes any scheduled auto-stop for (namespace, environment).
func (s *Scheduler) Cancel(namespace, environment string) error {
	return s.Schedule(namespace, environment, 0)
}

// Start launches the background polling goroutine. Call Stop to shut it down.
func (s *Scheduler) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	s.cancelFn = cancel
	s.done = make(chan struct{})
	go func() {
		defer close(s.done)
		s.loop(ctx)
	}()
}

// Stop shuts down the background goroutine and waits for it to exit, so an
// in-flight auto-stop finishes (and persists its state) before returning.
func (s *Scheduler) Stop() {
	if s.cancelFn == nil {
		return
	}
	s.cancelFn()
	<-s.done
}

// loop is the background goroutine. It ticks every tickInterval and checks
// whether any registered stop deadline has passed.
func (s *Scheduler) loop(ctx context.Context) {
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	// Check immediately on startup so entries that expired while the server was
	// offline are handled without waiting a full tick interval.
	s.tick(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.tick(ctx)
		}
	}
}

// tick fires the stop callback for every expired entry, at most
// maxConcurrentStops at a time, and returns once they have all finished (so
// Stop waits for in-flight auto-stops).
func (s *Scheduler) tick(ctx context.Context) {
	now := time.Now()

	type job struct {
		key      string
		deadline time.Time
	}
	s.mu.Lock()
	var expired []job
	for key, stopAt := range s.entries {
		if !now.Before(stopAt) {
			expired = append(expired, job{key, stopAt})
		}
	}
	s.mu.Unlock()

	sem := make(chan struct{}, maxConcurrentStops)
	var wg sync.WaitGroup
	defer wg.Wait()

	for _, j := range expired {
		ns, env, ok := splitKey(j.key)
		if !ok {
			slog.Warn("scheduler: removing malformed key", "key", j.key)
			s.removeEntryIf(j.key, j.deadline)
			continue
		}

		if ctx.Err() != nil {
			return // shutting down: leave the remaining entries for the next start
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
		wg.Go(func() {
			defer func() { <-sem }()
			s.fire(ctx, j.key, ns, env, j.deadline)
		})
	}
}

// fire runs one auto-stop for key if its deadline is still the one that
// expired, and removes the entry afterwards only if it was not rescheduled
// meanwhile.
func (s *Scheduler) fire(ctx context.Context, key, ns, env string, deadline time.Time) {
	stillDue := func() bool { return s.isDue(key, deadline) }

	// Re-check right before stopping: a deploy may have rescheduled or
	// cancelled the stop since the expired list was built (or while waiting
	// for a worker slot).
	if !stillDue() {
		slog.Info("scheduler: auto-stop superseded before running", "namespace", ns, "environment", env)
		return
	}

	stopCtx, cancel := context.WithTimeout(ctx, s.stopTimeout)
	defer cancel()
	stopCtx = context.WithValue(stopCtx, stillDueKey{}, stillDue)

	slog.Info("scheduler: auto-stopping", "namespace", ns, "environment", env, "deadline", deadline)
	if err := s.stopFn(stopCtx, ns, env); err != nil {
		if errors.Is(err, ErrSuperseded) {
			slog.Info("scheduler: auto-stop superseded by a redeploy", "namespace", ns, "environment", env)
			return
		}
		slog.Error("scheduler: auto-stop failed, will retry", "namespace", ns, "environment", env, "error", err)
		// Do not remove the entry on failure — retry next tick.
		return
	}
	if !s.removeEntryIf(key, deadline) {
		slog.Warn("scheduler: stack was rescheduled while being auto-stopped; keeping the new deadline",
			"namespace", ns, "environment", env)
	}
}

// isDue reports whether key is still scheduled at exactly deadline and that
// deadline has passed.
func (s *Scheduler) isDue(key string, deadline time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.entries[key]
	return ok && cur.Equal(deadline) && !time.Now().Before(cur)
}

// removeEntryIf deletes key only if it is still scheduled at deadline
// (compare-and-delete) and flushes to disk. It reports whether it deleted.
func (s *Scheduler) removeEntryIf(key string, deadline time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.entries[key]
	if !ok || !cur.Equal(deadline) {
		return false
	}
	delete(s.entries, key)
	if err := s.flush(); err != nil {
		slog.Error("scheduler: flush after remove", "error", err)
	}
	return true
}

// flush writes the current entries to disk atomically. Caller must hold s.mu.
func (s *Scheduler) flush() error {
	stored := make(map[string]string, len(s.entries))
	for key, t := range s.entries {
		stored[key] = t.UTC().Format(time.RFC3339)
	}

	raw, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return fmt.Errorf("scheduler: marshal: %w", err)
	}

	if err := writeFileAtomic(s.path, raw); err != nil {
		return fmt.Errorf("scheduler: %w", err)
	}
	return nil
}

// writeFileAtomic replaces path with data durably: it writes a temp file in
// the same directory, fsyncs it, renames it over path and fsyncs the
// directory so the rename itself survives a crash.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename to %s: %w", path, err)
	}
	committed = true

	// The new content is now visible; a failing directory fsync only weakens
	// crash durability, so it is logged rather than reported.
	if d, err := os.Open(dir); err != nil {
		slog.Warn("scheduler: open state dir for fsync", "dir", dir, "error", err)
	} else {
		if err := d.Sync(); err != nil {
			slog.Warn("scheduler: fsync state dir", "dir", dir, "error", err)
		}
		d.Close()
	}
	return nil
}

func makeKey(namespace, environment string) string {
	return namespace + "/" + environment
}

// splitKey is the inverse of makeKey.
func splitKey(key string) (namespace, environment string, ok bool) {
	for i, c := range key {
		if c == '/' {
			return key[:i], key[i+1:], true
		}
	}
	return "", "", false
}
