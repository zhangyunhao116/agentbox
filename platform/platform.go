package platform

import (
	"context"
	"os/exec"
)

// Platform defines the interface for OS-specific sandbox implementations.
// Each supported operating system provides a concrete implementation that
// applies appropriate isolation mechanisms (e.g., Seatbelt on macOS,
// namespaces + Landlock on Linux).
type Platform interface {
	// Name returns a human-readable identifier for this platform
	// (e.g., "darwin-seatbelt", "linux-namespace").
	Name() string

	// Available reports whether this platform's sandbox mechanism is
	// functional on the current system.
	Available() bool

	// CheckDependencies inspects the system for required and optional
	// dependencies needed by this platform.
	CheckDependencies() *DependencyCheck

	// WrapCommand modifies an *exec.Cmd in-place to execute within the
	// platform's sandbox, applying the restrictions described by cfg.
	WrapCommand(ctx context.Context, cmd *exec.Cmd, cfg *WrapConfig) error

	// Cleanup releases all platform-specific resources.
	Cleanup(ctx context.Context) error

	// Capabilities returns the set of isolation features this platform supports.
	Capabilities() Capabilities
}

// DependencyCheck holds the result of a dependency check.
type DependencyCheck struct {
	// Errors lists critical missing dependencies that prevent sandboxing.
	Errors []string

	// Warnings lists non-critical issues that may degrade functionality.
	Warnings []string
}

// OK returns true if no critical dependency errors were found.
func (d *DependencyCheck) OK() bool {
	return len(d.Errors) == 0
}

// Capabilities describes what isolation features a platform supports.
type Capabilities struct {
	// FileReadDeny indicates the platform can deny file read access.
	FileReadDeny bool

	// FileWriteAllow indicates the platform can restrict writes to specific paths.
	FileWriteAllow bool

	// NetworkDeny indicates the platform can block all network access.
	NetworkDeny bool

	// NetworkProxy indicates the platform can redirect traffic through a proxy.
	NetworkProxy bool

	// PIDIsolation indicates the platform can isolate process IDs.
	PIDIsolation bool

	// SyscallFilter indicates the platform can filter system calls (e.g., seccomp).
	SyscallFilter bool

	// ProcessHarden indicates the platform can apply process hardening measures.
	ProcessHarden bool
}

// WrapConfig is the configuration passed to Platform.WrapCommand.
// It describes the desired sandbox restrictions for a single command execution.
type WrapConfig struct {
	// WritableRoots lists directories where the sandboxed process may write.
	WritableRoots []string

	// DenyWrite lists paths the sandboxed process must not write to.
	DenyWrite []string

	// DenyRead lists paths the sandboxed process must not read from.
	DenyRead []string

	// AllowGitConfig permits the sandboxed process to read git configuration files.
	AllowGitConfig bool

	// NeedsNetworkRestriction indicates that network access should be restricted.
	NeedsNetworkRestriction bool

	// HTTPProxyPort is the local port of the HTTP/CONNECT proxy, if any.
	HTTPProxyPort int

	// SOCKSProxyPort is the local port of the SOCKS5 proxy, if any.
	SOCKSProxyPort int

	// Shell is the shell binary to use for command execution.
	Shell string

	// AllowLocalBinding permits the sandboxed process to bind to local ports.
	AllowLocalBinding bool

	// AllowAllUnixSockets permits all Unix domain socket connections.
	AllowAllUnixSockets bool

	// AllowUnixSockets lists specific Unix socket paths that are permitted.
	AllowUnixSockets []string

	// ResourceLimits specifies resource constraints for the sandboxed process.
	ResourceLimits *ResourceLimits

	// Warnings collects non-fatal issues detected during config building.
	// For example, a DenyWrite path that does not fully exist on disk.
	Warnings []string
}

// ResourceLimits specifies resource constraints for sandboxed processes.
type ResourceLimits struct {
	// MaxProcesses is the maximum number of processes the sandbox may spawn.
	MaxProcesses int

	// MaxMemoryBytes is the maximum memory in bytes the sandbox may use.
	MaxMemoryBytes int64

	// MaxFileDescriptors is the maximum number of open file descriptors.
	MaxFileDescriptors int

	// MaxCPUSeconds is the maximum CPU time in seconds.
	MaxCPUSeconds int
}

// DefaultResourceLimits returns the default resource limits for sandboxed processes.
func DefaultResourceLimits() *ResourceLimits {
	return &ResourceLimits{
		MaxProcesses:       1024,
		MaxMemoryBytes:     2 * 1024 * 1024 * 1024, // 2 GB
		MaxFileDescriptors: 1024,
		MaxCPUSeconds:      0, // unlimited
	}
}

// WorkerExecResult contains the result of a worker-executed command.
// It mirrors the key fields of ExecResult but is specialized for the
// worker fast path communication protocol.
type WorkerExecResult struct {
	// Stdout is the raw standard output from the command.
	Stdout []byte

	// Stderr is the raw standard error from the command.
	Stderr []byte

	// ExitCode is the command's exit code (0 for success, non-zero for failure).
	ExitCode int

	// Error is a worker-level error message (not a command error).
	// Empty string means no worker error occurred.
	// Command failures (non-zero exit) are indicated via ExitCode, not Error.
	Error string
}

// WorkerExecutor is an optional interface that Platform implementations can
// provide to execute commands via a persistent sandbox worker process.
// This avoids re-exec overhead for each command, significantly reducing latency.
//
// The manager checks for this interface via type assertion and uses the fast
// path when available, falling back to WrapCommand + exec when not.
//
// Implementations must return (nil, nil) if the worker is not available,
// signaling the caller to fall back to the standard WrapCommand path.
type WorkerExecutor interface {
	// ExecViaWorker executes a command through the persistent worker.
	// Returns (nil, nil) if the worker is not available — the caller should
	// fall back to the standard WrapCommand path.
	//
	// Parameters:
	//   ctx: context for cancellation and timeouts
	//   cfg: sandbox configuration (same as WrapCommand)
	//   name: resolved command path (e.g., /usr/bin/ls)
	//   args: command arguments including argv[0]
	//   dir: working directory for the command
	//   env: environment variables (full set, not just overrides)
	//
	// Returns:
	//   result: execution result with stdout/stderr/exit code
	//   error: worker communication error (nil if worker handled it)
	ExecViaWorker(ctx context.Context, cfg *WrapConfig, name string, args []string, dir string, env []string) (*WorkerExecResult, error)
}

// Detect returns the appropriate Platform for the current OS.
// On darwin: returns a platform that uses sandbox-exec (Seatbelt).
// On linux: returns a platform that uses namespaces + Landlock.
// On other OS: returns an unsupported platform stub.
func Detect() Platform {
	return detectPlatform()
}
