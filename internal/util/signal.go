package util

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// ShutdownFunc is a function that performs cleanup during shutdown.
type ShutdownFunc func() error

// SignalHandler manages OS signals for graceful shutdown and config reload.
type SignalHandler struct {
	shutdownFuncs []ShutdownFunc
	reloadFunc    func()
	sigChan       chan os.Signal
	wg            sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
	mu            sync.RWMutex
}

// NewSignalHandler creates a new SignalHandler.
func NewSignalHandler() *SignalHandler {
	ctx, cancel := context.WithCancel(context.Background())
	return &SignalHandler{
		sigChan: make(chan os.Signal, 1),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// RegisterShutdown registers a function to be called during shutdown.
// Functions are called in reverse order of registration (LIFO).
func (s *SignalHandler) RegisterShutdown(fn ShutdownFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shutdownFuncs = append(s.shutdownFuncs, fn)
}

// OnReload sets the function to be called when SIGHUP is received.
func (s *SignalHandler) OnReload(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reloadFunc = fn
}

// Start begins listening for signals.
// This should be called in a goroutine.
func (s *SignalHandler) Start() {
	s.wg.Add(1)
	go s.listen()
}

// listen is the main signal listening loop.
func (s *SignalHandler) listen() {
	defer s.wg.Done()

	// Register for signals
	signal.Notify(s.sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(s.sigChan)

	Info("Signal handler started")

	for {
		select {
		case <-s.ctx.Done():
			return
		case sig := <-s.sigChan:
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				Infof("Received %s, initiating graceful shutdown...", sig.String())
				s.performShutdown()
				return

			case syscall.SIGHUP:
				Info("Received SIGHUP, reloading configuration...")
				s.performReload()
			}
		}
	}
}

// performShutdown executes all registered shutdown functions.
// Functions are called in reverse order (LIFO).
func (s *SignalHandler) performShutdown() {
	s.mu.RLock()
	funcs := make([]ShutdownFunc, len(s.shutdownFuncs))
	copy(funcs, s.shutdownFuncs)
	s.mu.RUnlock()

	// Call shutdown functions in reverse order
	for i := len(funcs) - 1; i >= 0; i-- {
		fn := funcs[i]
		if fn != nil {
			if err := fn(); err != nil {
				Errorf("Shutdown function error: %v", err)
			}
		}
	}

	// Cancel context
	s.cancel()
}

// performReload calls the reload function if set.
func (s *SignalHandler) performReload() {
	s.mu.RLock()
	fn := s.reloadFunc
	s.mu.RUnlock()

	if fn != nil {
		fn()
	} else {
		Warn("No reload function configured, ignoring SIGHUP")
	}
}

// Stop stops the signal handler and waits for it to finish.
func (s *SignalHandler) Stop() {
	s.cancel()
	s.wg.Wait()
}

// Context returns the signal handler's context.
func (s *SignalHandler) Context() context.Context {
	return s.ctx
}

// Done returns a channel that is closed when shutdown is complete.
func (s *SignalHandler) Done() <-chan struct{} {
	return s.ctx.Done()
}

// GracefulShutdown performs a graceful shutdown with timeout.
// It calls all registered shutdown functions and waits for them to complete.
func (s *SignalHandler) GracefulShutdown(timeout time.Duration) error {
	Infof("Starting graceful shutdown with %v timeout...", timeout)

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Execute shutdown functions
	s.performShutdown()

	// Wait for completion or timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		Info("Graceful shutdown completed")
		return nil
	case <-ctx.Done():
		Warn("Graceful shutdown timed out")
		return ctx.Err()
	}
}

// IsShutdown returns true if shutdown has been initiated.
func (s *SignalHandler) IsShutdown() bool {
	select {
	case <-s.ctx.Done():
		return true
	default:
		return false
	}
}

// Wait blocks until shutdown is initiated.
func (s *SignalHandler) Wait() {
	<-s.ctx.Done()
}

// ShutdownNotifier provides a simple way to notify when shutdown should occur.
type ShutdownNotifier struct {
	ch     chan struct{}
	once   sync.Once
	mu     sync.RWMutex
	reason string
}

// NewShutdownNotifier creates a new ShutdownNotifier.
func NewShutdownNotifier() *ShutdownNotifier {
	return &ShutdownNotifier{
		ch: make(chan struct{}),
	}
}

// Notify initiates shutdown notification.
// Safe to call multiple times; only the first call has effect.
func (n *ShutdownNotifier) Notify(reason string) {
	n.once.Do(func() {
		n.mu.Lock()
		n.reason = reason
		n.mu.Unlock()
		close(n.ch)
	})
}

// Done returns a channel that is closed when shutdown is notified.
func (n *ShutdownNotifier) Done() <-chan struct{} {
	return n.ch
}

// Reason returns the shutdown reason.
func (n *ShutdownNotifier) Reason() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.reason
}

// IsNotified returns true if shutdown has been notified.
func (n *ShutdownNotifier) IsNotified() bool {
	select {
	case <-n.ch:
		return true
	default:
		return false
	}
}
