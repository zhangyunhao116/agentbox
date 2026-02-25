package agentbox

import (
	"context"
	"log/slog"
	"os/exec"
)

// Manager provides sandboxed command execution.
// Use NewManager to create an instance with a specific configuration.
//
// Implementations must be safe for concurrent use by multiple goroutines.
type Manager interface {
	// Wrap modifies an *exec.Cmd in-place to execute within the sandbox.
	// The command is classified and sandbox restrictions are applied.
	Wrap(ctx context.Context, cmd *exec.Cmd, opts ...Option) error

	// Exec executes a shell command string within the sandbox and returns the result.
	Exec(ctx context.Context, command string, opts ...Option) (*ExecResult, error)

	// ExecArgs executes a command specified as a program name and argument list
	// within the sandbox and returns the result.
	ExecArgs(ctx context.Context, name string, args []string, opts ...Option) (*ExecResult, error)

	// Available reports whether the sandbox platform is functional on this system.
	Available() bool

	// CheckDependencies inspects the system for required and optional dependencies.
	CheckDependencies() *DependencyCheck

	// Check classifies a command without executing it. This is useful for
	// dry-run scenarios or pre-flight validation.
	Check(ctx context.Context, command string) (ClassifyResult, error)

	// Cleanup releases all resources held by the manager.
	// After Cleanup is called, all subsequent calls return ErrManagerClosed.
	Cleanup(ctx context.Context) error

	// UpdateConfig dynamically updates the manager's configuration.
	// The new config is validated before being applied. Network filter rules
	// and the classifier are hot-reloaded; filesystem changes take effect on
	// the next Wrap/Exec call.
	UpdateConfig(cfg *Config) error
}

// Wrap is a convenience function that creates a temporary manager,
// wraps the command, and returns a cleanup function. The caller must
// invoke cleanup after the command has finished running.
// It uses DefaultConfig.
func Wrap(ctx context.Context, cmd *exec.Cmd, opts ...Option) (cleanup func(), err error) {
	cfg := DefaultConfig()
	mgr, err := NewManager(cfg)
	if err != nil {
		return nil, err
	}
	if err := mgr.Wrap(ctx, cmd, opts...); err != nil {
		_ = mgr.Cleanup(ctx)
		return nil, err
	}
	return func() { _ = mgr.Cleanup(context.WithoutCancel(ctx)) }, nil
}

// Exec is a convenience function that creates a temporary manager,
// executes the command, and cleans up. It uses DefaultConfig.
func Exec(ctx context.Context, command string, opts ...Option) (*ExecResult, error) {
	cfg := DefaultConfig()
	mgr, err := NewManager(cfg)
	if err != nil {
		return nil, err
	}
	defer func() { logCleanupErr(mgr.Cleanup(context.WithoutCancel(ctx))) }()
	return mgr.Exec(ctx, command, opts...)
}

// ExecArgs is a convenience function that creates a temporary manager,
// executes the command with explicit arguments, and cleans up. It uses DefaultConfig.
func ExecArgs(ctx context.Context, name string, args []string, opts ...Option) (*ExecResult, error) {
	cfg := DefaultConfig()
	mgr, err := NewManager(cfg)
	if err != nil {
		return nil, err
	}
	defer func() { logCleanupErr(mgr.Cleanup(context.WithoutCancel(ctx))) }()
	return mgr.ExecArgs(ctx, name, args, opts...)
}

// Check classifies a command without executing it using a temporary manager.
func Check(ctx context.Context, command string) (ClassifyResult, error) {
	cfg := DefaultConfig()
	mgr, err := NewManager(cfg)
	if err != nil {
		// If manager creation fails (e.g., unsupported platform), fall back to
		// the default classifier. Log the error so it is not silently lost.
		slog.Debug("agentbox.Check: manager creation failed, using default classifier", "err", err)
		c := DefaultClassifier()
		return c.Classify(command), nil
	}
	defer func() { logCleanupErr(mgr.Cleanup(context.WithoutCancel(ctx))) }()
	return mgr.Check(ctx, command)
}

// NewManager creates a new sandbox Manager with the given configuration.
// The configuration is validated before the manager is created.
//
// If the platform sandbox is unavailable, behavior depends on FallbackPolicy:
//   - FallbackStrict (default): returns ErrUnsupportedPlatform.
//   - FallbackWarn: returns a NopManager that executes without sandboxing.
func NewManager(cfg *Config) (Manager, error) {
	return newManager(cfg)
}

// logCleanupErr logs cleanup errors using the default logger.
// Convenience functions (Exec, ExecArgs, Check) don't have access to
// the manager's configured logger, so we use slog.Debug as a best-effort.
func logCleanupErr(err error) {
	if err != nil {
		slog.Debug("agentbox: cleanup error", "err", err)
	}
}
