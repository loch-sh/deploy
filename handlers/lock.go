package handlers

import (
	"context"
	"sync"
)

// keyedLock serialises operations per stack key so two concurrent requests
// (e.g. overlapping pipelines, or a deploy racing the auto-stop) never write
// the same compose directory or run compose commands on the same stack at once.
// Different stacks never block each other.
//
// Slots are reference-counted and removed once no goroutine holds or waits for
// them, so the map does not grow with every key ever seen.
type keyedLock struct {
	mu    sync.Mutex
	slots map[string]*lockSlot
}

// lockSlot is one key's lock: a 1-buffered channel used as a mutex that can
// be waited on with a context, plus the number of holders and waiters.
type lockSlot struct {
	ch   chan struct{}
	refs int // guarded by keyedLock.mu
}

func newKeyedLock() *keyedLock {
	return &keyedLock{slots: make(map[string]*lockSlot)}
}

// stackLocks is shared by every handler and by the scheduler's stop callback.
var stackLocks = newKeyedLock()

// lock blocks until key is free or ctx is done. On success it returns the
// unlock function (safe to call more than once); on cancellation it returns
// ctx.Err().
func (k *keyedLock) lock(ctx context.Context, key string) (func(), error) {
	k.mu.Lock()
	slot, ok := k.slots[key]
	if !ok {
		slot = &lockSlot{ch: make(chan struct{}, 1)}
		k.slots[key] = slot
	}
	slot.refs++
	k.mu.Unlock()

	select {
	case slot.ch <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() {
				<-slot.ch
				k.release(key, slot)
			})
		}, nil
	case <-ctx.Done():
		k.release(key, slot)
		return nil, ctx.Err()
	}
}

// release drops one reference to slot and forgets it once unused.
func (k *keyedLock) release(key string, slot *lockSlot) {
	k.mu.Lock()
	defer k.mu.Unlock()
	slot.refs--
	if slot.refs == 0 && k.slots[key] == slot {
		delete(k.slots, key)
	}
}

// size returns the number of tracked keys (for tests).
func (k *keyedLock) size() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.slots)
}
