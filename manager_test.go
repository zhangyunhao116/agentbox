package agentbox

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os/exec"
	"sync"
	"testing"

	"github.com/zhangyunhao116/agentbox/platform"
)

// stubPlatform is a test platform that reports as available but returns
// an error from WrapCommand (matching the old builtinLinuxPlatform behavior).
type stubPlatform struct{}

func (stubPlatform) Name() string                                 { return "test-stub" }
func (stubPlatform) Available() bool                              { return true }
func (stubPlatform) CheckDependencies() *platform.DependencyCheck { return &platform.DependencyCheck{} }
func (stubPlatform) WrapCommand(_ context.Context, _ *exec.Cmd, _ *platform.WrapConfig) error {
	return errors.New("test-stub: WrapCommand not implemented")
}
func (stubPlatform) Cleanup(_ context.Context) error { return nil }
func (stubPlatform) Capabilities() platform.Capabilities {
	return platform.Capabilities{}
}

// useStubPlatform overrides detectPlatformFn to use a stub that reports as
// available, allowing tests to get a real *manager for internal testing.
// It registers a cleanup to restore the original function.
// Safe to call multiple times from the same test (idempotent).
func useStubPlatform(t *testing.T) {
	t.Helper()
	origDetect := detectPlatformFn
	detectPlatformFn = func() platform.Platform { return stubPlatform{} }
	t.Cleanup(func() { detectPlatformFn = origDetect })
}

func newTestConfig(t *testing.T) *Config {
	t.Helper()
	useStubPlatform(t)
	cfg := DefaultConfig()
	return cfg
}

func TestNewManagerValid(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	if mgr == nil {
		t.Fatal("newManager returned nil")
	}
}

func TestNewManagerNilConfig(t *testing.T) {
	_, err := newManager(nil)
	if err == nil {
		t.Fatal("newManager(nil) should return error")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
}

func TestNewManagerInvalidConfig(t *testing.T) {
	cfg := &Config{
		Filesystem: FilesystemConfig{
			WritableRoots: []string{""},
		},
	}
	_, err := newManager(cfg)
	if err == nil {
		t.Fatal("newManager with invalid config should return error")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
}

func TestNewManagerDefaultsFilled(t *testing.T) {
	cfg := newTestConfig(t)
	// Clear defaults to verify they get filled in.
	cfg.Classifier = nil
	cfg.Shell = ""
	cfg.MaxOutputBytes = 0 // 0 means no limit; should be preserved as-is.
	cfg.ResourceLimits = nil

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m, ok := mgr.(*manager)
	if !ok {
		t.Fatal("expected *manager type")
	}

	if m.cfg.Classifier == nil {
		t.Error("Classifier should be set to default")
	}
	if m.cfg.Shell != defaultShell {
		t.Errorf("Shell = %q, want %q", m.cfg.Shell, defaultShell)
	}
	if m.cfg.MaxOutputBytes != 0 {
		t.Errorf("MaxOutputBytes = %d, want 0 (no limit)", m.cfg.MaxOutputBytes)
	}
	if m.cfg.ResourceLimits == nil {
		t.Error("ResourceLimits should be set to default")
	}
}

func TestManagerAvailable(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	// On darwin, the stub platform reports Available() = true.
	if !mgr.Available() {
		t.Error("Available() should return true on darwin")
	}
}

func TestManagerCheckDependencies(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	dc := mgr.CheckDependencies()
	if dc == nil {
		t.Fatal("CheckDependencies() returned nil")
	}
	if !dc.OK() {
		t.Errorf("CheckDependencies() not OK: %v", dc.Errors)
	}
}

func TestManagerCleanupThenWrap(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}

	_ = mgr.Cleanup(context.Background())

	cmd := exec.Command("echo", "hello")
	err = mgr.Wrap(context.Background(), cmd)
	if !errors.Is(err, ErrManagerClosed) {
		t.Errorf("Wrap() after Cleanup: got %v, want ErrManagerClosed", err)
	}
}

func TestManagerCleanupThenExec(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}

	_ = mgr.Cleanup(context.Background())

	_, err = mgr.Exec(context.Background(), "echo hello")
	if !errors.Is(err, ErrManagerClosed) {
		t.Errorf("Exec() after Cleanup: got %v, want ErrManagerClosed", err)
	}
}

func TestManagerCleanupThenExecArgs(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}

	_ = mgr.Cleanup(context.Background())

	_, err = mgr.ExecArgs(context.Background(), "echo", []string{"hello"})
	if !errors.Is(err, ErrManagerClosed) {
		t.Errorf("ExecArgs() after Cleanup: got %v, want ErrManagerClosed", err)
	}
}

func TestManagerConcurrentAccess(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = mgr.Exec(context.Background(), "echo concurrent")
		}()
	}
	wg.Wait()
}

func TestManagerConcurrentCleanup(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}

	var wg sync.WaitGroup
	// Multiple goroutines calling Cleanup concurrently should not panic.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = mgr.Cleanup(context.Background())
		}()
	}
	wg.Wait()
}

func TestManagerCleanupIdempotent(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}

	// First cleanup should succeed.
	err = mgr.Cleanup(context.Background())
	if err != nil {
		t.Fatalf("first Cleanup() error: %v", err)
	}

	// Second cleanup should be a no-op (not error).
	err = mgr.Cleanup(context.Background())
	if err != nil {
		t.Fatalf("second Cleanup() error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Fix 1: RWMutex data race test — concurrent Exec + UpdateConfig
// ---------------------------------------------------------------------------

// TestManagerConcurrentExecAndUpdateConfig verifies that concurrent Exec and
// UpdateConfig calls do not race (requires -race flag to detect).
func TestManagerConcurrentExecAndUpdateConfig(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	var wg sync.WaitGroup

	// Concurrent Exec calls.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = mgr.Exec(context.Background(), "echo race")
		}()
	}

	// Concurrent UpdateConfig calls.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			newCfg := DefaultConfig()
			newCfg.Shell = "/bin/sh"
			_ = mgr.UpdateConfig(newCfg)
		}()
	}

	wg.Wait()
}

// TestManagerCheck verifies the Check method on the real manager.
func TestManagerCheck(t *testing.T) {
	cfg := newTestConfig(t)
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	t.Run("safe command", func(t *testing.T) {
		result, err := mgr.Check(context.Background(), "echo hello")
		if err != nil {
			t.Fatalf("Check() error: %v", err)
		}
		if result.Decision != Allow {
			t.Errorf("Decision: got %v, want Allow", result.Decision)
		}
	})

	t.Run("forbidden command", func(t *testing.T) {
		result, err := mgr.Check(context.Background(), ":(){ :|:& };:")
		if err != nil {
			t.Fatalf("Check() error: %v", err)
		}
		if result.Decision != Forbidden {
			t.Errorf("Decision: got %v, want Forbidden", result.Decision)
		}
	})

	t.Run("after cleanup", func(t *testing.T) {
		mgr2, err := newManager(newTestConfig(t))
		if err != nil {
			t.Fatalf("newManager() error: %v", err)
		}
		_ = mgr2.Cleanup(context.Background())
		_, err = mgr2.Check(context.Background(), "echo hello")
		if err == nil {
			t.Fatal("Check() after Cleanup should return error")
		}
	})
}

// ---------------------------------------------------------------------------
// Logger tests
// ---------------------------------------------------------------------------

// TestManagerCustomLogger verifies that a custom logger is accepted and the
// manager operates normally when one is provided.
func TestManagerCustomLogger(t *testing.T) {
	useStubPlatform(t)
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(handler)

	cfg := DefaultConfig()
	cfg.Logger = logger
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	// Execute a simple command — may fail on stub platforms (fail-closed).
	result, err := mgr.Exec(context.Background(), "echo hello")
	if err != nil {
		// On stub platforms, WrapCommand fails. This is expected with fail-closed.
		return
	}
	if result == nil {
		t.Fatal("result is nil")
	}
}

// TestManagerNilLogger verifies that a nil Logger in Config defaults to
// slog.Default() and the manager works correctly.
func TestManagerNilLogger(t *testing.T) {
	useStubPlatform(t)
	cfg := DefaultConfig()
	// Logger is nil by default.
	if cfg.Logger != nil {
		t.Fatal("DefaultConfig().Logger should be nil")
	}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	mgr.Cleanup(context.Background())
	// Should work fine with nil logger (uses slog.Default).
}

// TestManagerLoggerStoredInStruct verifies the resolved logger is stored on
// the manager struct, falling back to slog.Default() when nil.
func TestManagerLoggerStoredInStruct(t *testing.T) {
	t.Run("custom logger", func(t *testing.T) {
		var buf bytes.Buffer
		handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
		logger := slog.New(handler)

		cfg := newTestConfig(t)
		cfg.Logger = logger
		mgr, err := newManager(cfg)
		if err != nil {
			t.Fatalf("newManager: %v", err)
		}
		defer mgr.Cleanup(context.Background())

		m, ok := mgr.(*manager)
		if !ok {
			t.Fatal("expected *manager type")
		}
		if m.logger != logger {
			t.Error("manager.logger should be the custom logger")
		}
	})

	t.Run("nil logger defaults", func(t *testing.T) {
		cfg := newTestConfig(t)
		cfg.Logger = nil
		mgr, err := newManager(cfg)
		if err != nil {
			t.Fatalf("newManager: %v", err)
		}
		defer mgr.Cleanup(context.Background())

		m, ok := mgr.(*manager)
		if !ok {
			t.Fatal("expected *manager type")
		}
		if m.logger == nil {
			t.Error("manager.logger should not be nil when Config.Logger is nil")
		}
	})
}

// TestManagerLoggerPropagatedToProxy verifies that when using NetworkFiltered
// mode with a custom logger, the proxy starts without error.
func TestManagerLoggerPropagatedToProxy(t *testing.T) {
	useStubPlatform(t)
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(handler)

	cfg := DefaultConfig()
	cfg.Logger = logger
	cfg.Network.Mode = NetworkFiltered
	cfg.Network.AllowedDomains = []string{"example.com"}

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	// The proxy should have started with our logger.
	// At minimum, verify the manager was created successfully.
	m, ok := mgr.(*manager)
	if !ok {
		t.Fatal("expected *manager type")
	}
	if m.proxy == nil {
		t.Error("proxy should be started in NetworkFiltered mode")
	}
}
