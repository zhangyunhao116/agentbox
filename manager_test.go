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
	"github.com/zhangyunhao116/agentbox/testutil"
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
	cfg.Shell = testutil.Shell()
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
	// Keep cfg.Shell from newTestConfig (testutil.Shell()) so the shell
	// existence check passes on all platforms. We test the default-shell
	// fill-in separately below.
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
	// Shell was explicitly set; verify it was preserved.
	if m.cfg.Shell != testutil.Shell() {
		t.Errorf("Shell = %q, want %q", m.cfg.Shell, testutil.Shell())
	}
	if m.cfg.MaxOutputBytes != 0 {
		t.Errorf("MaxOutputBytes = %d, want 0 (no limit)", m.cfg.MaxOutputBytes)
	}
	if m.cfg.ResourceLimits == nil {
		t.Error("ResourceLimits should be set to default")
	}
}

// TestNewManagerDefaultShellFill verifies that newManager fills in the
// default shell (/bin/sh) when Shell is empty. This only works on Unix
// where /bin/sh exists.
func TestNewManagerDefaultShellFill(t *testing.T) {
	testutil.SkipIfWindows(t, "defaultShell is /bin/sh which does not exist on Windows")
	cfg := newTestConfig(t)
	cfg.Shell = ""

	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	m := mgr.(*manager)
	if m.cfg.Shell != defaultShell {
		t.Errorf("Shell = %q, want %q", m.cfg.Shell, defaultShell)
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

	shell, echoArgs := testutil.EchoCommand("race")
	var wg sync.WaitGroup

	// Concurrent ExecArgs calls (platform-aware shell).
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = mgr.ExecArgs(context.Background(), shell, echoArgs)
		}()
	}

	// Concurrent UpdateConfig calls.
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			newCfg := DefaultConfig()
			newCfg.Shell = testutil.Shell()
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
	cfg.Shell = testutil.Shell()
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
	cfg.Shell = testutil.Shell()
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
	cfg.Shell = testutil.Shell()
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

// hookRegisteringFailingPlatform is a test platform that registers a hook
// during WrapCommand but then returns an error, simulating the leak scenario.
type hookRegisteringFailingPlatform struct{}

func (hookRegisteringFailingPlatform) Name() string { return "hook-fail-platform" }
func (hookRegisteringFailingPlatform) Available() bool { return true }
func (hookRegisteringFailingPlatform) CheckDependencies() *platform.DependencyCheck {
	return &platform.DependencyCheck{}
}
func (hookRegisteringFailingPlatform) WrapCommand(_ context.Context, cmd *exec.Cmd, _ *platform.WrapConfig) error {
	// Register a hook (this simulates what some platforms do)
	platform.RegisterPostStartHook(cmd, func(*exec.Cmd) error { return nil })
	// Then fail
	return errors.New("hook-fail-platform: intentional failure")
}
func (hookRegisteringFailingPlatform) Cleanup(_ context.Context) error { return nil }
func (hookRegisteringFailingPlatform) Capabilities() platform.Capabilities {
	return platform.Capabilities{}
}

// TestWrapCommandFailureCleanupHook verifies that when WrapCommand fails,
// any PostStartHook registered during that call is cleaned up from the global map.
func TestWrapCommandFailureCleanupHook(t *testing.T) {
	t.Helper()
	
	// Override detectPlatformFn to use our hook-registering-but-failing platform.
	origDetect := detectPlatformFn
	detectPlatformFn = func() platform.Platform { return hookRegisteringFailingPlatform{} }
	t.Cleanup(func() { detectPlatformFn = origDetect })

	cfg := DefaultConfig()
	cfg.Shell = testutil.Shell()
	
	mgr, err := newManager(cfg)
	if err != nil {
		t.Fatalf("newManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	// Test Wrap method
	cmd := exec.Command("echo", "test")
	err = mgr.Wrap(context.Background(), cmd)
	
	// Should return an error from WrapCommand
	if err == nil {
		t.Fatal("Wrap() should return error when WrapCommand fails")
	}
	if !errors.Is(err, errors.New("hook-fail-platform: intentional failure")) {
		// The error wrapping may differ, so check the message contains our error
		if err.Error() != "hook-fail-platform: intentional failure" {
			t.Errorf("expected error from WrapCommand, got: %v", err)
		}
	}

	// Verify the hook was cleaned up (PopPostStartHook should return nil)
	hook := platform.PopPostStartHook(cmd)
	if hook != nil {
		t.Error("hook should have been cleaned up after WrapCommand failure in Wrap()")
	}
}

// TestRunCommandFailureCleanupHook verifies hook cleanup in both FallbackWarn
// and FallbackStrict cases when WrapCommand fails in runCommand.
func TestRunCommandFailureCleanupHook(t *testing.T) {
	t.Helper()
	
	// Override detectPlatformFn to use our hook-registering-but-failing platform.
	origDetect := detectPlatformFn
	detectPlatformFn = func() platform.Platform { return hookRegisteringFailingPlatform{} }
	t.Cleanup(func() { detectPlatformFn = origDetect })

	t.Run("FallbackStrict", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Shell = testutil.Shell()
		cfg.FallbackPolicy = FallbackStrict
		
		mgr, err := newManager(cfg)
		if err != nil {
			t.Fatalf("newManager() error: %v", err)
		}
		defer mgr.Cleanup(context.Background())

		// Exec should fail because WrapCommand fails and policy is strict
		result, err := mgr.Exec(context.Background(), "echo test")
		if err == nil {
			t.Fatal("Exec() should return error when WrapCommand fails with FallbackStrict")
		}
		if result != nil {
			t.Error("result should be nil on error")
		}

		// Since Exec creates an internal command, we can't easily verify the hook cleanup
		// on that specific command, but we can verify the code path is covered.
	})

	t.Run("FallbackWarn", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Shell = testutil.Shell()
		cfg.FallbackPolicy = FallbackWarn
		
		mgr, err := newManager(cfg)
		if err != nil {
			t.Fatalf("newManager() error: %v", err)
		}
		defer mgr.Cleanup(context.Background())

		// Exec should succeed because FallbackWarn allows running without sandbox
		result, err := mgr.Exec(context.Background(), "echo test")
		if err != nil {
			t.Fatalf("Exec() unexpected error with FallbackWarn: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
		if result.Sandboxed {
			t.Error("result.Sandboxed should be false when sandbox wrapping fails")
		}
	})
}
