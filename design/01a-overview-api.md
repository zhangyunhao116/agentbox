# agentbox Architecture — Project Overview & Core API

> Series: [01a](01a-overview-api.md) | [01b](01b-structure-flow.md) | [01c](01c-config-classifier.md) | [01d](01d-integration.md)

> **Status**: Implemented
> **Date**: 2026-02-16
> **Scope**: agentbox — Process-level sandbox library for Go
> **Split note**: This file covers the project overview and core API design.
>   Package structure and component interaction flows: [01b-structure-flow.md](./01b-structure-flow.md).
>   Configuration system, command classifier, platform abstraction: [01c-config-classifier.md](./01c-config-classifier.md).
>   Integration (network proxy, comparison, security model, examples): [01d-integration.md](./01d-integration.md).

---

## 1. Project Overview

### 1.1 Positioning

agentbox is a standalone Go library providing **process-level sandbox isolation** for AI Agents, CI/CD systems, and any scenario requiring secure execution of untrusted commands. It targets feature parity with Anthropic's [sandbox-runtime](https://github.com/anthropics/sandbox-runtime) (TypeScript) but is redesigned in idiomatic Go, aiming for **single-binary, minimal external dependencies**.

> **Note**: "Single-binary, minimal external dependencies" means no Node.js, bubblewrap, socat, or other external processes.
> macOS still requires the system-provided `sandbox-exec`. Linux helper functionality is achieved via
> **same-binary re-exec** (similar to Docker's reexec pattern):
> the `agentbox` binary checks the `_AGENTBOX_CONFIG` environment variable to determine whether to enter
> helper mode (re-exec), requiring no separate helper binary. See [01c §7.4](./01c-config-classifier.md#74-re-exec-bootstrap-mode).

```
github.com/zhangyunhao116/agentbox
```

### 1.2 Core Value

| Value | Description |
|-------|-------------|
| **Single binary, minimal deps** | Pure Go, no CGO, no Node.js runtime, no external process dependencies (except macOS sandbox-exec); helper via re-exec bootstrap |
| **Go-idiomatic API** | `Wrap(ctx, cmd)` in-place modification + `Exec(ctx, cmd)` execution mode, seamless `os/exec` integration |
| **Cross-platform** | macOS (Seatbelt/SBPL) + Linux (Namespaces + Landlock), unified API |
| **Defense in depth** | Filesystem isolation + network isolation + command classification + proxy filtering, multi-layer security |
| **Embeddable** | Go library (`import`), designed for seamless embedding in any Go application |

### 1.3 Comparison with sandbox-runtime

| Dimension | sandbox-runtime (TypeScript) | agentbox (Go) |
|-----------|------------------------------|---------------|
| **Runtime deps** | Node.js 18+, npm ecosystem | Minimal deps, single binary |
| **API style** | Singleton module + string returns | Multi-instance Manager + in-place `*exec.Cmd` modification |
| **Concurrency** | Single-threaded event loop | goroutine-native concurrency safety |
| **Type safety** | Zod runtime validation | Compile-time type checking + `Validate()` |
| **Linux isolation** | bubblewrap + socat external deps | Go-native namespaces + Landlock, zero external deps |
| **Network proxy** | Depends on socat for Unix socket bridging | Built-in HTTP/SOCKS5 proxy, pure Go |
| **Distribution** | npm package | `go install` or single binary download |
| **Embedding cost** | Requires Node.js process | Direct `import`, zero overhead |

---

## 2. Core API Design

### 2.1 Manager Interface

`Manager` is the core abstraction of agentbox, managing the complete sandbox lifecycle. **Not a singleton** — supports multiple concurrent instances (e.g., different projects using different sandbox configurations).

```go
package agentbox

import (
	"context"
	"os/exec"

	"github.com/zhangyunhao116/agentbox/platform"
)

// Manager provides sandboxed command execution.
// Thread-safe, supports multiple concurrent instances.
type Manager interface {
	// Wrap modifies an *exec.Cmd in-place to execute within the sandbox.
	// Injects SysProcAttr, Env, Path/Args as needed.
	// The caller uses the same cmd after Wrap returns.
	//
	// Even if Classifier returns Allow, the command still runs in the sandbox
	// (only classification is skipped). Only Forbidden prevents execution.
	Wrap(ctx context.Context, cmd *exec.Cmd, opts ...Option) error

	// Exec executes a shell command string within the sandbox and returns the result.
	// ⚠️ Shell injection risk: command is executed via sh -c.
	// For programmatic commands, prefer ExecArgs.
	Exec(ctx context.Context, command string, opts ...Option) (*ExecResult, error)

	// ExecArgs executes a command with explicit program name and argument list.
	// Uses execve directly, no shell involved — no injection risk.
	ExecArgs(ctx context.Context, name string, args []string, opts ...Option) (*ExecResult, error)

	// Cleanup releases all resources (proxy servers, temp files, etc.).
	// Must be called when the Manager is no longer needed. Use with defer.
	// After Cleanup, all subsequent calls return ErrManagerClosed.
	Cleanup(ctx context.Context) error

	// Available reports whether the sandbox platform is functional on this system.
	Available() bool

	// CheckDependencies inspects the system for required and optional dependencies.
	// Returns *platform.DependencyCheck with Errors (fatal) and Warnings (degraded).
	CheckDependencies() *platform.DependencyCheck

	// UpdateConfig dynamically updates the manager's configuration.
	// The new config is validated before being applied. Network filter rules
	// and the classifier are hot-reloaded; filesystem changes take effect on
	// the next Wrap/Exec call.
	UpdateConfig(cfg *Config) error

	// Check classifies a command without executing it.
	// Useful for dry-run scenarios or pre-flight validation.
	Check(ctx context.Context, command string) (ClassifyResult, error)
}
```

### 2.2 Factory Functions & Config Helpers

```go
// NewManager creates a new sandbox Manager with the given configuration.
// The configuration is validated before the manager is created.
// cfg must not be nil.
//
// If the platform sandbox is unavailable, behavior depends on FallbackPolicy:
//   - FallbackStrict (default): returns ErrUnsupportedPlatform.
//   - FallbackWarn: returns a NopManager that executes without sandboxing.
func NewManager(cfg *Config, opts ...ManagerOption) (Manager, error)

// DefaultConfig returns a *Config with secure defaults suitable for most use cases.
// Returns *Config directly (no error).
// Defaults: FallbackStrict, NetworkFiltered, deny-write system dirs, deny-read sensitive dirs.
// If os.UserHomeDir() fails, os.TempDir() is used as fallback for home-relative paths.
func DefaultConfig() *Config

// DevelopmentConfig returns a *Config suitable for local development.
// Based on DefaultConfig() with FallbackWarn + NetworkAllowed.
func DevelopmentConfig() *Config

// CIConfig returns a *Config optimized for CI/CD environments.
// Based on DefaultConfig() with FallbackStrict + NetworkBlocked.
func CIConfig() *Config

// DefaultResourceLimits returns sensible default resource limits.
// Defaults: 1024 processes, 2GB memory, 1024 FDs, unlimited CPU.
func DefaultResourceLimits() *ResourceLimits

// NewNopManager creates a Manager that passes through all commands
// without sandboxing. Useful for testing or when sandbox isolation
// is not required.
func NewNopManager() Manager
```

### 2.3 Package-Level Convenience Functions

For simple scenarios that don't need lifecycle management:

```go
// Wrap creates a temporary manager, wraps the command, and returns a cleanup function.
// The caller must invoke cleanup after the command has finished running.
// Uses DefaultConfig.
//
// ⚠️ Signature difference from Manager.Wrap (by design):
//   - Manager.Wrap returns error — Manager manages resource lifecycle via Cleanup().
//   - Package-level Wrap returns (cleanup func(), err error) — no Manager to manage,
//     caller must release resources via cleanup().
func Wrap(ctx context.Context, cmd *exec.Cmd, opts ...Option) (cleanup func(), err error)

// Exec creates a temporary manager, executes the command, and cleans up.
// Uses DefaultConfig.
func Exec(ctx context.Context, command string, opts ...Option) (*ExecResult, error)

// ExecArgs creates a temporary manager, executes with explicit args, and cleans up.
// Uses DefaultConfig.
func ExecArgs(ctx context.Context, name string, args []string, opts ...Option) (*ExecResult, error)

// Check classifies a command without executing it using a temporary manager.
// If manager creation fails (e.g., unsupported platform), falls back to
// DefaultClassifier directly.
func Check(ctx context.Context, command string, opts ...Option) (ClassifyResult, error)
```

### 2.4 Execution Result

```go
import "time"

// ExecResult holds the outcome of a sandboxed command execution.
type ExecResult struct {
	// ExitCode is the process exit code. 0 typically indicates success.
	ExitCode int

	// Stdout contains the captured standard output.
	Stdout string

	// Stderr contains the captured standard error.
	Stderr string

	// Duration is the wall-clock time the process took to execute.
	Duration time.Duration

	// Sandboxed indicates whether the command was executed inside a sandbox.
	Sandboxed bool

	// Truncated indicates whether output was truncated due to MaxOutputBytes.
	Truncated bool

	// Violations contains sandbox policy violations detected during execution.
	Violations []Violation
}

// ViolationType represents the kind of sandbox policy violation.
type ViolationType string

const (
	ViolationFileRead  ViolationType = "file-read"
	ViolationFileWrite ViolationType = "file-write"
	ViolationNetwork   ViolationType = "network"
	ViolationProcess   ViolationType = "process"
	ViolationOther     ViolationType = "other"
)

// Violation represents a single sandbox policy violation detected during execution.
type Violation struct {
	// Operation is the type of operation that was denied.
	Operation ViolationType

	// Path is the filesystem path involved, if applicable.
	Path string

	// Detail is a human-readable description of the violation.
	Detail string

	// Process is the name of the process that triggered the violation.
	Process string

	// Raw is the raw violation message from the platform sandbox.
	Raw string
}
```

### 2.5 Option Pattern (per-call overrides)

```go
// Option configures a single Exec or Wrap call.
type Option func(*callOptions)

// callOptions holds per-call configuration applied via Option functions.
type callOptions struct {
	writableRoots []string
	network       *NetworkConfig
	env           []string
	shell         string
	classifier    Classifier
	workingDir    string
	timeout       time.Duration
	denyRead      []string
	denyWrite     []string
}

// ManagerOption configures a Manager at creation time.
type ManagerOption func(*managerOptions)

// managerOptions holds configuration applied via ManagerOption functions.
type managerOptions struct {
	approvalCallback ApprovalCallback
}

// ApprovalCallback is invoked when a command is classified as Escalated.
// The callback should prompt the user and return a decision.
// Must be safe for concurrent use by multiple goroutines.
type ApprovalCallback func(ctx context.Context, req ApprovalRequest) (ApprovalDecision, error)

// ApprovalRequest contains information about a command that requires approval.
type ApprovalRequest struct {
	Command  string   // The full command string that requires approval
	Reason   string   // Why the command was escalated
	Decision Decision // The classifier's original decision (Escalated)
}

// ApprovalDecision represents the user's response to an approval request.
type ApprovalDecision int

const (
	Approve        ApprovalDecision = iota // Allow the command to execute this one time
	Deny                                   // Reject the command
	ApproveSession                         // Allow for the remainder of the session
)

// Per-call Option functions:
func WithWritableRoots(roots ...string) Option  // Add writable root directories
func WithNetwork(cfg *NetworkConfig) Option      // Override network configuration
func WithEnv(env ...string) Option               // Append environment variables ("KEY=VALUE")
func WithShell(shell string) Option              // Override shell binary
func WithClassifier(c Classifier) Option         // Override classifier
func WithWorkingDir(dir string) Option           // Set working directory
func WithTimeout(d time.Duration) Option         // Set execution timeout
func WithDenyRead(paths ...string) Option        // Add denied read paths
func WithDenyWrite(paths ...string) Option       // Add denied write paths

// Manager-level ManagerOption functions:
func WithApprovalCallback(cb ApprovalCallback) ManagerOption // Register approval callback
```

### 2.6 Error Types

```go
package agentbox

import "errors"

var (
	// ErrUnsupportedPlatform indicates the current OS/architecture is not supported.
	ErrUnsupportedPlatform = errors.New("agentbox: unsupported platform")

	// ErrDependencyMissing indicates a required system dependency is not available.
	ErrDependencyMissing = errors.New("agentbox: required dependency missing")

	// ErrForbiddenCommand indicates the command was rejected by the classifier.
	ErrForbiddenCommand = errors.New("agentbox: command forbidden by classifier")

	// ErrEscalatedCommand indicates the command requires user approval before execution.
	ErrEscalatedCommand = errors.New("agentbox: command requires user approval")

	// ErrManagerClosed indicates the manager has already been closed via Cleanup.
	ErrManagerClosed = errors.New("agentbox: manager already closed")

	// ErrConfigInvalid indicates the provided configuration failed validation.
	ErrConfigInvalid = errors.New("agentbox: invalid configuration")

	// ErrProxyStartFailed indicates the network proxy server could not be started.
	ErrProxyStartFailed = errors.New("agentbox: proxy server failed to start")
)

// DependencyCheck is defined in the platform package (platform.DependencyCheck).
// The root package uses it directly via the Manager interface:
//   CheckDependencies() *platform.DependencyCheck
//
// type DependencyCheck struct {
//     Errors   []string // Fatal — sandbox cannot run
//     Warnings []string // Non-fatal — degraded functionality
// }
// func (d *DependencyCheck) OK() bool { return len(d.Errors) == 0 }
```

### 2.7 Lifecycle

```
┌─────────────┐     ┌──────────────────┐     ┌──────────────────────────┐     ┌─────────────┐
│ NewManager() │────▶│   Initialize     │────▶│ Wrap / Exec / Check /    │────▶│  Cleanup()  │
│              │     │                  │     │ UpdateConfig             │     │             │
│ • Validate   │     │ • Detect platform│     │ (may be called multiple  │     │ • Stop proxy│
│   config     │     │ • Start proxy    │     │  times concurrently)     │     │ • Platform  │
│ • Create     │     │   (if filtered)  │     │ • Classify command       │     │   cleanup   │
│   instance   │     │ • Init platform  │     │ • Wrap/execute           │     │             │
│              │     │   backend        │     │ • Collect violations     │     │             │
└─────────────┘     └──────────────────┘     └──────────────────────────┘     └─────────────┘
```

**Key constraints**:
- `NewManager()` performs synchronous config validation + resource initialization (proxy startup, etc.)
- `Wrap`/`Exec`/`Check`/`UpdateConfig` can be called concurrently; Manager is thread-safe internally
- `Cleanup()` must be called; otherwise proxy servers and temp files leak
- After `Cleanup()`, all calls to `Wrap`/`Exec`/`Check`/`UpdateConfig` return `ErrManagerClosed`
- `UpdateConfig()` hot-reloads network filter rules and classifier; filesystem changes take effect on next call

---

*Continue reading: [01b-structure-flow.md](./01b-structure-flow.md) — Package structure, component interaction flows*
*See also: [01c-config-classifier.md](./01c-config-classifier.md) — Configuration system, command classifier, platform abstraction*
*See also: [01d-integration.md](./01d-integration.md) — Network proxy architecture, comparison, security model, examples*
