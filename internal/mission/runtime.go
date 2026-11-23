package mission

import (
	"context"
	"errors"
	"sync"
)

var ErrPaused = errors.New("mission paused: in-flight operation interrupted")
var ErrAborted = errors.New("mission aborted")

// Runtime gates dispatch and cancels in-flight operations. Pause keeps the
// mission alive; interrupted tool results must be recorded, never replayed.
type Runtime struct {
	mu         sync.Mutex
	paused     bool
	changed    chan struct{}
	abort      context.Context
	stop       context.CancelCauseFunc
	next       uint64
	operations map[uint64]context.CancelCauseFunc
}

func NewRuntime() *Runtime {
	ctx, cancel := context.WithCancelCause(context.Background())
	return &Runtime{changed: make(chan struct{}), abort: ctx, stop: cancel, operations: map[uint64]context.CancelCauseFunc{}}
}
func (runtime *Runtime) notify() { close(runtime.changed); runtime.changed = make(chan struct{}) }
func (runtime *Runtime) Pause() {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.paused = true
	for _, cancel := range runtime.operations {
		cancel(ErrPaused)
	}
	runtime.notify()
}
func (runtime *Runtime) Resume() {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.paused = false
	runtime.notify()
}
func (runtime *Runtime) Abort(reason error) {
	if reason == nil {
		reason = ErrAborted
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.stop(reason)
	for _, cancel := range runtime.operations {
		cancel(reason)
	}
	runtime.notify()
}
func (runtime *Runtime) Wait(ctx context.Context) error {
	for {
		runtime.mu.Lock()
		paused, changed := runtime.paused, runtime.changed
		runtime.mu.Unlock()
		if err := context.Cause(runtime.abort); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if !paused {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-runtime.abort.Done():
			return context.Cause(runtime.abort)
		case <-changed:
		}
	}
}
func (runtime *Runtime) Begin(parent context.Context) (context.Context, func(), error) {
	for {
		if err := runtime.Wait(parent); err != nil {
			return nil, nil, err
		}
		runtime.mu.Lock()
		if runtime.paused {
			runtime.mu.Unlock()
			continue
		}
		if err := context.Cause(runtime.abort); err != nil {
			runtime.mu.Unlock()
			return nil, nil, err
		}
		ctx, cancel := context.WithCancelCause(parent)
		runtime.next++
		id := runtime.next
		runtime.operations[id] = cancel
		runtime.mu.Unlock()
		return ctx, func() {
			runtime.mu.Lock()
			delete(runtime.operations, id)
			runtime.mu.Unlock()
			cancel(context.Canceled)
		}, nil
	}
}
func (runtime *Runtime) Context(parent context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(parent)
	stop := context.AfterFunc(runtime.abort, func() { cancel(context.Cause(runtime.abort)) })
	return ctx, func() { stop(); cancel(context.Canceled) }
}
