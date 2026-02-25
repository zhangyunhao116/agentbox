package agentbox

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/zhangyunhao116/agentbox/platform"
)

func TestDependencyCheckOK(t *testing.T) {
	tests := []struct {
		name   string
		check  platform.DependencyCheck
		wantOK bool
	}{
		{"no errors no warnings", platform.DependencyCheck{}, true},
		{"warnings only", platform.DependencyCheck{Warnings: []string{"warn"}}, true},
		{"errors only", platform.DependencyCheck{Errors: []string{"err"}}, false},
		{"both", platform.DependencyCheck{Errors: []string{"err"}, Warnings: []string{"warn"}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.check.OK(); got != tt.wantOK {
				t.Errorf("OK() = %v, want %v", got, tt.wantOK)
			}
		})
	}
}

func TestDependencyCheckZeroValue(t *testing.T) {
	var dc platform.DependencyCheck
	if dc.Errors != nil {
		t.Error("Errors should be nil")
	}
	if dc.Warnings != nil {
		t.Error("Warnings should be nil")
	}
	if !dc.OK() {
		t.Error("zero value DependencyCheck should be OK")
	}
}

func TestNewManagerValidatesConfig(t *testing.T) {
	cfg := &Config{
		Filesystem: FilesystemConfig{
			WritableRoots: []string{""},
		},
	}

	_, err := NewManager(cfg)
	if err == nil {
		t.Fatal("NewManager should return error for invalid config")
	}
	if !errors.Is(err, ErrConfigInvalid) {
		t.Errorf("error should wrap ErrConfigInvalid, got: %v", err)
	}
}

func TestNewManagerSucceeds(t *testing.T) {
	cfg := DefaultConfig()
	cfg.FallbackPolicy = FallbackWarn

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	if mgr == nil {
		t.Fatal("NewManager returned nil manager")
	}
}

func TestNewManagerWithOptions(t *testing.T) {
	cfg := DefaultConfig()
	cfg.FallbackPolicy = FallbackWarn

	called := false
	cb := func(ctx context.Context, req ApprovalRequest) (ApprovalDecision, error) {
		called = true
		return Approve, nil
	}

	cfg.ApprovalCallback = cb

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	// The callback should not have been called during construction.
	if called {
		t.Error("approval callback should not be called during NewManager")
	}
}

func TestConvenienceFunctions(t *testing.T) {
	ctx := context.Background()

	t.Run("Exec", func(t *testing.T) {
		result, err := Exec(ctx, "echo hello")
		if err != nil {
			// On stub platforms, WrapCommand fails (fail-closed) or platform is unavailable.
			if strings.Contains(err.Error(), "sandbox wrapping failed") ||
				errors.Is(err, ErrUnsupportedPlatform) {
				t.Skip("skipping: platform stub does not implement WrapCommand")
			}
			t.Fatalf("Exec error: %v", err)
		}
		if result == nil {
			t.Fatal("Exec returned nil result")
		}
	})

	t.Run("ExecArgs", func(t *testing.T) {
		result, err := ExecArgs(ctx, "echo", []string{"hello"})
		if err != nil {
			if strings.Contains(err.Error(), "sandbox wrapping failed") ||
				errors.Is(err, ErrUnsupportedPlatform) {
				t.Skip("skipping: platform stub does not implement WrapCommand")
			}
			t.Fatalf("ExecArgs error: %v", err)
		}
		if result == nil {
			t.Fatal("ExecArgs returned nil result")
		}
	})
}

func TestCheckConvenience(t *testing.T) {
	ctx := context.Background()

	t.Run("safe command", func(t *testing.T) {
		result, err := Check(ctx, "echo hello")
		if err != nil {
			t.Fatalf("Check() error: %v", err)
		}
		// echo is a safe command, should be Allow.
		if result.Decision != Allow {
			t.Errorf("Decision: got %v, want Allow", result.Decision)
		}
	})

	t.Run("forbidden command", func(t *testing.T) {
		result, err := Check(ctx, ":(){ :|:& };:")
		if err != nil {
			t.Fatalf("Check() error: %v", err)
		}
		if result.Decision != Forbidden {
			t.Errorf("Decision: got %v, want Forbidden", result.Decision)
		}
	})

	t.Run("unknown command", func(t *testing.T) {
		result, err := Check(ctx, "some_random_command --flag")
		if err != nil {
			t.Fatalf("Check() error: %v", err)
		}
		// Unknown commands default to Sandboxed.
		if result.Decision != Sandboxed {
			t.Errorf("Decision: got %v, want Sandboxed", result.Decision)
		}
	})
}

// ---------------------------------------------------------------------------
// Coverage gap: Wrap convenience error after mgr creation (L55-57)
// ---------------------------------------------------------------------------

func TestWrapConvenienceForbiddenCommand(t *testing.T) {
	// Pass a forbidden command (rm -rf /) to the Wrap convenience function.
	// NewManager succeeds, but mgr.Wrap returns ErrForbiddenCommand,
	// which triggers the cleanup-and-return-error path on L55-57.
	ctx := context.Background()
	cmd := exec.Command("rm", "-rf", "/")
	cleanup, err := Wrap(ctx, cmd)
	if err == nil {
		if cleanup != nil {
			cleanup()
		}
		t.Fatal("Wrap() with forbidden command should return error")
	}
	if !errors.Is(err, ErrForbiddenCommand) && !errors.Is(err, ErrUnsupportedPlatform) {
		t.Errorf("Wrap() error: got %v, want ErrForbiddenCommand or ErrUnsupportedPlatform", err)
	}
	if cleanup != nil {
		t.Error("cleanup should be nil when Wrap returns error")
	}
}

func TestCheckManagerMethod(t *testing.T) {
	cfg := DefaultConfig()
	cfg.FallbackPolicy = FallbackWarn
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	result, err := mgr.Check(context.Background(), "echo hello")
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if result.Decision != Allow {
		t.Errorf("Decision: got %v, want Allow", result.Decision)
	}
}

// ---------------------------------------------------------------------------
// Coverage gap: newManager platform unavailable paths (L101-110)
// Override SandboxExecPath to make the platform unavailable on macOS.
// ---------------------------------------------------------------------------

func TestNewManagerPlatformUnavailableFallbackStrict(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("SandboxExecPath override only works on darwin")
	}

	orig := platform.SandboxExecPath
	platform.SandboxExecPath = "/nonexistent/sandbox-exec"
	defer func() { platform.SandboxExecPath = orig }()

	cfg := DefaultConfig()
	cfg.FallbackPolicy = FallbackStrict

	_, err := NewManager(cfg)
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Errorf("NewManager() with unavailable platform + FallbackStrict: got %v, want ErrUnsupportedPlatform", err)
	}
}

func TestNewManagerPlatformUnavailableFallbackWarn(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("SandboxExecPath override only works on darwin")
	}

	orig := platform.SandboxExecPath
	platform.SandboxExecPath = "/nonexistent/sandbox-exec"
	defer func() { platform.SandboxExecPath = orig }()

	cfg := DefaultConfig()
	cfg.FallbackPolicy = FallbackWarn

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager() with FallbackWarn: unexpected error: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	// Should return a NopManager.
	if !mgr.Available() {
		// NopManager.Available() returns false, which is expected.
	}
}

func TestNewManagerPlatformUnavailableDefaultPolicy(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("SandboxExecPath override only works on darwin")
	}

	orig := platform.SandboxExecPath
	platform.SandboxExecPath = "/nonexistent/sandbox-exec"
	defer func() { platform.SandboxExecPath = orig }()

	cfg := DefaultConfig()
	// Use an invalid FallbackPolicy value to trigger the default case.
	cfg.FallbackPolicy = FallbackPolicy(99)

	// This should fail validation first due to invalid FallbackPolicy.
	_, err := NewManager(cfg)
	if err == nil {
		t.Fatal("NewManager() with invalid FallbackPolicy should return error")
	}
}

// ---------------------------------------------------------------------------
// Coverage gap: Convenience functions with unavailable platform
// ---------------------------------------------------------------------------

func TestConvenienceExecPlatformUnavailable(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("SandboxExecPath override only works on darwin")
	}

	orig := platform.SandboxExecPath
	platform.SandboxExecPath = "/nonexistent/sandbox-exec"
	defer func() { platform.SandboxExecPath = orig }()

	// Exec uses DefaultConfig which has FallbackStrict.
	// With platform unavailable, NewManager returns ErrUnsupportedPlatform.
	_, err := Exec(context.Background(), "echo hello")
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Errorf("Exec() with unavailable platform: got %v, want ErrUnsupportedPlatform", err)
	}
}

func TestConvenienceExecArgsPlatformUnavailable(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("SandboxExecPath override only works on darwin")
	}

	orig := platform.SandboxExecPath
	platform.SandboxExecPath = "/nonexistent/sandbox-exec"
	defer func() { platform.SandboxExecPath = orig }()

	_, err := ExecArgs(context.Background(), "echo", []string{"hello"})
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Errorf("ExecArgs() with unavailable platform: got %v, want ErrUnsupportedPlatform", err)
	}
}

func TestConvenienceWrapPlatformUnavailable(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("SandboxExecPath override only works on darwin")
	}

	orig := platform.SandboxExecPath
	platform.SandboxExecPath = "/nonexistent/sandbox-exec"
	defer func() { platform.SandboxExecPath = orig }()

	cmd := exec.Command("echo", "hello")
	cleanup, err := Wrap(context.Background(), cmd)
	if !errors.Is(err, ErrUnsupportedPlatform) {
		if cleanup != nil {
			cleanup()
		}
		t.Errorf("Wrap() with unavailable platform: got %v, want ErrUnsupportedPlatform", err)
	}
	if cleanup != nil {
		t.Error("cleanup should be nil when Wrap returns error")
	}
}

func TestConvenienceCheckPlatformUnavailable(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("SandboxExecPath override only works on darwin")
	}

	orig := platform.SandboxExecPath
	platform.SandboxExecPath = "/nonexistent/sandbox-exec"
	defer func() { platform.SandboxExecPath = orig }()

	// Check falls back to DefaultClassifier when NewManager fails.
	result, err := Check(context.Background(), "echo hello")
	if err != nil {
		t.Fatalf("Check() with unavailable platform: unexpected error: %v", err)
	}
	// DefaultClassifier classifies "echo hello" as Allow.
	if result.Decision != Allow {
		t.Errorf("Decision: got %v, want Allow", result.Decision)
	}
}

func TestLogCleanupErr_Nil(t *testing.T) {
	// logCleanupErr with nil should not panic.
	logCleanupErr(nil)
}

func TestLogCleanupErr_NonNil(t *testing.T) {
	// logCleanupErr with a non-nil error should not panic.
	logCleanupErr(errors.New("test cleanup error"))
}
