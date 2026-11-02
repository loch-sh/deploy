package handlers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestKeyedLockSerialisesSameKey(t *testing.T) {
	k := newKeyedLock()

	unlock, err := k.lock(context.Background(), "a")
	if err != nil {
		t.Fatalf("lock: %v", err)
	}

	// A second lock on the same key must wait until the context expires.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := k.lock(ctx, "a"); err == nil {
		t.Fatal("expected second lock on the same key to block")
	}

	// A different key is independent.
	unlockB, err := k.lock(context.Background(), "b")
	if err != nil {
		t.Fatalf("lock b: %v", err)
	}
	unlockB()

	unlock()
	unlock2, err := k.lock(context.Background(), "a")
	if err != nil {
		t.Fatalf("relock after unlock: %v", err)
	}
	unlock2()
}

func TestPruneStackDir(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{composeFileName, "api.env", "old.env", "api.env.tmp"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := pruneStackDir(dir, map[string]bool{composeFileName: true, "api.env": true}); err != nil {
		t.Fatalf("pruneStackDir: %v", err)
	}

	entries, _ := os.ReadDir(dir)
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	want := []string{"api.env", composeFileName, "subdir"}
	if len(got) != len(want) {
		t.Fatalf("remaining = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("remaining = %v, want %v", got, want)
		}
	}
}

// Slots must be freed once nobody holds or waits for them, including after a
// cancelled wait, so the map does not grow without bound.
func TestKeyedLockDoesNotLeakSlots(t *testing.T) {
	k := newKeyedLock()

	for i := range 100 {
		unlock, err := k.lock(context.Background(), fmt.Sprintf("stack-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		unlock()
		unlock() // idempotent
	}
	if n := k.size(); n != 0 {
		t.Fatalf("slots after unlock = %d, want 0", n)
	}

	unlock, _ := k.lock(context.Background(), "a")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := k.lock(ctx, "a"); err == nil {
		t.Fatal("expected timeout")
	}
	if n := k.size(); n != 1 {
		t.Fatalf("slots while held = %d, want 1", n)
	}

	// A waiter queued behind the holder keeps the slot alive across unlock.
	got := make(chan func())
	go func() {
		u, err := k.lock(context.Background(), "a")
		if err != nil {
			t.Error(err)
		}
		got <- u
	}()
	time.Sleep(10 * time.Millisecond)
	unlock()
	u2 := <-got
	if n := k.size(); n != 1 {
		t.Fatalf("slots while re-held = %d, want 1", n)
	}
	u2()
	if n := k.size(); n != 0 {
		t.Fatalf("slots at rest = %d, want 0", n)
	}
}
