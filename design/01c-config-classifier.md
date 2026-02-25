# agentbox Architecture Design — Configuration & Classifier

> Series: [01a](01a-overview-api.md) | [01b](01b-structure-flow.md) | [01c](01c-config-classifier.md) | [01d](01d-integration.md)

> **Status**: Implemented
> **Date**: 2026-02-16
> **Scope**: agentbox — Process-level sandbox library for the Go ecosystem
> **Split note**: This document covers the configuration system, command classifier, and platform abstraction layer.
>   For project overview and core API design, see [01a-overview-api.md](./01a-overview-api.md).
>   For package structure and component interaction flow, see [01b-structure-flow.md](./01b-structure-flow.md).
>   For integration (network proxy, comparison, security model, examples), see [01d-integration.md](./01d-integration.md).

---

## 5. Configuration System

### 5.1 Config Struct

```go
package agentbox

import (
	"context"

	"github.com/zhangyunhao116/agentbox/platform"
)

// Config holds the complete configuration for a sandbox Manager.
type Config struct {
	// Filesystem defines filesystem access restrictions.
	Filesystem FilesystemConfig

	// Network defines network access restrictions.
	Network NetworkConfig

	// Classifier determines how commands are classified.
	Classifier Classifier

	// Shell is the path to the shell used for command execution.
	// If empty, the system default shell is used ("/bin/sh").
	Shell string

	// MaxOutputBytes limits the size of captured stdout/stderr.
	// 0 means no limit.
	MaxOutputBytes int

	// ResourceLimits defines resource constraints for sandboxed processes.
	// If nil, DefaultResourceLimits() is used.
	ResourceLimits *ResourceLimits

	// FallbackPolicy determines behavior when sandboxing is unavailable.
	FallbackPolicy FallbackPolicy
}
```

**Key design notes:**
- `ApprovalCallback` is NOT a Config field. It is injected via `ManagerOption` (see `WithApprovalCallback`), because it is a runtime behavior injection, not core configuration.
- `ResourceLimits` is a type alias: `type ResourceLimits = platform.ResourceLimits`. The canonical definition lives in the `platform` package; the root package re-exports it to avoid circular dependencies.

### 5.2 FallbackPolicy Enum

```go
type FallbackPolicy int

const (
	// FallbackStrict refuses to execute commands if sandboxing is unavailable (default, zero value).
	FallbackStrict FallbackPolicy = iota // 0

	// FallbackWarn executes commands without sandboxing but logs a warning.
	FallbackWarn // 1
)

func (f FallbackPolicy) String() string // returns "strict" or "warn"
```

### 5.3 NetworkMode Enum

```go
type NetworkMode int

const (
	// NetworkFiltered allows network access only to explicitly allowed domains (default, zero value).
	NetworkFiltered NetworkMode = iota // 0

	// NetworkBlocked denies all network access from within the sandbox.
	NetworkBlocked // 1

	// NetworkAllowed permits unrestricted network access.
	NetworkAllowed // 2
)

func (n NetworkMode) String() string // returns "filtered", "blocked", or "allowed"
```

### 5.4 ResourceLimits

The canonical definition is in the `platform` package. The root package uses a type alias:

```go
// In platform/platform.go:
type ResourceLimits struct {
	MaxProcesses       int   // RLIMIT_NPROC. 0 = use default (1024).
	MaxMemoryBytes     int64 // RLIMIT_AS. 0 = use default (2GB).
	MaxFileDescriptors int   // RLIMIT_NOFILE. 0 = use default (1024).
	MaxCPUSeconds      int   // RLIMIT_CPU. 0 = unlimited.
}

func DefaultResourceLimits() *ResourceLimits {
	return &ResourceLimits{
		MaxProcesses:       1024,
		MaxMemoryBytes:     2 * 1024 * 1024 * 1024, // 2 GB
		MaxFileDescriptors: 1024,
		MaxCPUSeconds:      0, // unlimited
	}
}

// In root package (config.go):
type ResourceLimits = platform.ResourceLimits

func DefaultResourceLimits() *ResourceLimits {
	return platform.DefaultResourceLimits()
}
```

### 5.5 FilesystemConfig

```go
type FilesystemConfig struct {
	// WritableRoots lists directories where write access is permitted.
	WritableRoots []string

	// DenyWrite lists path patterns that must never be writable.
	DenyWrite []string

	// DenyRead lists path patterns that must never be readable.
	DenyRead []string

	// AllowGitConfig permits read access to ~/.gitconfig and related files.
	AllowGitConfig bool
}
```

### 5.6 NetworkConfig

```go
type NetworkConfig struct {
	// Mode determines the overall network access policy.
	Mode NetworkMode

	// AllowedDomains lists domain patterns that are permitted when Mode is NetworkFiltered.
	AllowedDomains []string

	// DeniedDomains lists domain patterns that are always blocked.
	DeniedDomains []string

	// OnRequest is an optional callback invoked for each outgoing connection attempt.
	// Only called when Mode is NetworkFiltered and the domain is not in AllowedDomains or DeniedDomains.
	// Implementations must be safe for concurrent use by multiple goroutines.
	OnRequest func(ctx context.Context, host string, port int) (bool, error)
}
```

### 5.7 Default Configuration

```go
// DefaultConfig returns a Config with secure defaults suitable for most use cases.
// If the user's home directory cannot be determined, os.TempDir() is used as a
// fallback for home-relative deny paths.
//
// IMPORTANT: Returns *Config (no error). The os.TempDir() fallback ensures this
// function always succeeds.
func DefaultConfig() *Config {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir() // fallback
	}

	return &Config{
		Filesystem: FilesystemConfig{
			WritableRoots: []string{},
			DenyWrite: []string{
				home,
				"/etc",
				"/usr",
				"/bin",
				"/sbin",
			},
			DenyRead: []string{
				filepath.Join(home, ".ssh"),
				filepath.Join(home, ".aws"),
				filepath.Join(home, ".gnupg"),
				filepath.Join(home, ".git-credentials"),
				filepath.Join(home, ".npmrc"),
				filepath.Join(home, ".netrc"),
				filepath.Join(home, ".docker"),
				filepath.Join(home, ".pypirc"),
				filepath.Join(home, ".kube"),
				filepath.Join(home, ".config", "gcloud"),
				"/proc/*/mem",
				"/sys",
			},
			AllowGitConfig: false,
		},
		Network: NetworkConfig{
			Mode: NetworkFiltered,
		},
		Shell:          "",  // uses "/bin/sh" default
		MaxOutputBytes: 0,   // uses default (10MB)
		ResourceLimits: DefaultResourceLimits(),
		FallbackPolicy: FallbackStrict,
	}
}
```

**Differences from original design:**
- Returns `*Config` (no error), not `(*Config, error)`.
- Uses `os.TempDir()` fallback instead of returning an error when `os.UserHomeDir()` fails.
- `DenyWrite` includes `home`, `/etc`, `/usr`, `/bin`, `/sbin` (not `home/.ssh`, `home/.gnupg`, `home/.aws`).
- `DenyRead` uses `filepath.Join` and includes `/proc/*/mem`, `/sys`.
- `ResourceLimits` is set to `DefaultResourceLimits()` (not nil).

### 5.8 DevelopmentConfig and CIConfig

```go
// DevelopmentConfig returns a Config suitable for local development.
// Uses FallbackWarn so commands still run when the sandbox platform
// is unavailable, and allows unrestricted network access.
func DevelopmentConfig() *Config {
	cfg := DefaultConfig()
	cfg.FallbackPolicy = FallbackWarn
	cfg.Network.Mode = NetworkAllowed
	return cfg
}

// CIConfig returns a Config optimized for CI/CD environments.
// Blocks all network access and uses strict fallback policy to
// ensure commands always run inside a sandbox.
func CIConfig() *Config {
	cfg := DefaultConfig()
	cfg.FallbackPolicy = FallbackStrict
	cfg.Network.Mode = NetworkBlocked
	return cfg
}
```

### 5.9 Configuration Priority

```
1. Option (per-call)        WithWritableRoots(...)
                            ↓ overrides
2. Config (per-Manager)     NewManager(cfg)
                            ↓ overrides
3. Config file              .agentbox.yaml
                            ↓ overrides
4. Environment variables    AGENTBOX_WRITABLE_ROOTS=...
                            ↓ overrides
5. Defaults                 DefaultConfig()
```

**Note**: When used as a library, typically only layers 1, 2, and 5 apply. Config files and environment variables provide additional configuration flexibility.

### 5.10 Configuration Validation

`Validate()` is a **pure function** — it performs no filesystem I/O (no `os.Stat` calls). Shell path existence checking is deferred to `NewManager()` and `UpdateConfig()`.

```go
// Validate checks the configuration for errors and returns a descriptive error
// if any field is invalid. The returned error wraps ErrConfigInvalid.
//
// IMPORTANT: Validate() is pure — no os.Stat, no filesystem I/O.
// Shell existence check is performed in NewManager() and UpdateConfig().
func (c *Config) Validate() error {
	var errs []string

	errs = c.validateFilesystem(errs)
	errs = c.validateNetwork(errs)

	// Validate shell path format (must be absolute if set).
	if c.Shell != "" {
		if !filepath.IsAbs(c.Shell) {
			errs = append(errs, fmt.Sprintf("Shell: %q must be an absolute path", c.Shell))
		}
	}

	errs = c.validateResourceLimits(errs)

	// Validate MaxOutputBytes.
	if c.MaxOutputBytes < 0 {
		errs = append(errs, "MaxOutputBytes: must be >= 0")
	}

	// Validate enum ranges.
	if c.FallbackPolicy < FallbackStrict || c.FallbackPolicy > FallbackWarn {
		errs = append(errs, "FallbackPolicy: invalid value")
	}
	if c.Network.Mode < NetworkFiltered || c.Network.Mode > NetworkAllowed {
		errs = append(errs, "Network.Mode: invalid value")
	}

	if len(errs) > 0 {
		return fmt.Errorf("%w: %s", ErrConfigInvalid, strings.Join(errs, "; "))
	}
	return nil
}
```

**Validation rules:**
- `validateFilesystem`: WritableRoots entries must not be empty; relative paths must be resolvable via `filepath.Abs`; DenyWrite/DenyRead entries must not be empty.
- `validateNetwork`: AllowedDomains/DeniedDomains validated via `validateDomainPattern`.
- `validateResourceLimits`: All fields must be >= 0 when ResourceLimits is non-nil.
- Shell must be an absolute path if set.
- MaxOutputBytes must be >= 0.
- FallbackPolicy and NetworkMode must be within valid enum range.

**Domain pattern validation (`validateDomainPattern`):**
- Rejects empty patterns.
- Rejects patterns containing `://` (protocol prefix).
- Requires at least one dot.
- Wildcards only in `*.domain.tld` format (at least two labels after `*.`).
- Only one leading wildcard allowed.

---

## 6. Command Classifier

### 6.1 Decision Enum

```go
type Decision int

const (
	// Sandboxed indicates the command should be executed within the sandbox.
	// It is the zero value, so an uninitialized ClassifyResult defaults to
	// the safest decision.
	Sandboxed Decision = iota // 0

	// Allow indicates the command is safe and can be executed (still sandboxed).
	Allow // 1

	// Escalated indicates the command requires user approval before execution.
	Escalated // 2

	// Forbidden indicates the command must not be executed.
	Forbidden // 3
)

func (d Decision) String() string // returns "sandboxed", "allow", "escalated", "forbidden"
```

**Key design note:** `Sandboxed` is the zero value (iota=0), not `Allow`. This ensures that an uninitialized `ClassifyResult` defaults to the safest decision (sandboxed execution).

### 6.2 ClassifyResult

```go
type ClassifyResult struct {
	// Decision is the classification decision.
	Decision Decision

	// Reason is a human-readable explanation of why this decision was made.
	Reason string

	// Rule is the identifier of the rule that matched, if any.
	Rule string
}
```

### 6.3 Classifier Interface

```go
// Classifier determines how a command should be handled by the sandbox.
// Implementations must be safe for concurrent use.
type Classifier interface {
	// Classify inspects a shell command string and returns a classification result.
	Classify(command string) ClassifyResult

	// ClassifyArgs inspects a command specified as a program name and argument list.
	ClassifyArgs(name string, args []string) ClassifyResult
}
```

### 6.4 DefaultClassifier Implementation

```go
// DefaultClassifier returns a Classifier pre-loaded with the built-in rules.
// Rules are evaluated in priority order: forbidden, allow, escalated.
func DefaultClassifier() Classifier {
	return &ruleClassifier{
		rules: defaultRules(),
	}
}
```

The internal `rule` type (unexported) and `ruleClassifier`:

```go
// rule defines a single classification rule (unexported).
type rule struct {
	Name     string
	Match    func(command string) (ClassifyResult, bool)
	MatchArgs func(name string, args []string) (ClassifyResult, bool)
}

type ruleClassifier struct {
	rules []rule
}

// Classify iterates through rules in order and returns the first match.
// If no rule matches, returns Sandboxed.
func (c *ruleClassifier) Classify(command string) ClassifyResult {
	for _, r := range c.rules {
		if r.Match != nil {
			if result, ok := r.Match(command); ok {
				return result
			}
		}
	}
	return ClassifyResult{
		Decision: Sandboxed,
		Reason:   "no rule matched; defaulting to sandboxed execution",
	}
}

// ClassifyArgs iterates through rules using MatchArgs first, then falls back
// to Match with a reconstructed command string. If no rule matches, returns Sandboxed.
func (c *ruleClassifier) ClassifyArgs(name string, args []string) ClassifyResult {
	// Build a command string for rules that only implement Match.
	parts := make([]string, 0, 1+len(args))
	parts = append(parts, name)
	parts = append(parts, args...)
	command := strings.Join(parts, " ")

	for _, r := range c.rules {
		if r.MatchArgs != nil {
			if result, ok := r.MatchArgs(name, args); ok {
				return result
			}
		}
		if r.Match != nil {
			if result, ok := r.Match(command); ok {
				return result
			}
		}
	}
	return ClassifyResult{
		Decision: Sandboxed,
		Reason:   "no rule matched; defaulting to sandboxed execution",
	}
}
```

**Key behavioral difference from original design:** `ClassifyArgs` tries BOTH `MatchArgs` AND `Match` for each rule (falling back to `Match` with a reconstructed command string). The original design skipped rules without `MatchArgs`.

### 6.5 Built-in Rules

Rules are evaluated in priority order. The `defaultRules()` function concatenates:
1. `forbiddenRules()` — highest priority
2. `allowRules()` — safe commands
3. `escalatedRules()` — require approval

#### Forbidden Rules (6 rules)

| Rule Name | Detection Method | Description |
|-----------|-----------------|-------------|
| `fork-bomb` | String matching | Detects `:(){ :|:& };:` and renamed variants (e.g., `bomb(){ bomb|bomb& };bomb`) |
| `recursive-delete-root` | Field parsing + MatchArgs | Detects `rm -rf /`, `rm -rf ~`, `rm -rf $HOME` with various flag orderings |
| `disk-wipe` | Field parsing + MatchArgs | Detects `dd of=/dev/sd*`, `of=/dev/nvme*`, `of=/dev/hd*` |
| `reverse-shell` | String matching | Detects `/dev/tcp/`, `/dev/udp/`, `nc -e`, `ncat -e`, python/perl socket imports |
| `chmod-recursive-root` | Field parsing + MatchArgs | Detects `chmod -R` on `/`, `~`, `$HOME` |
| `curl-pipe-shell` | Pipe analysis | Detects `curl|sh`, `wget|bash`, and similar patterns piping to shells (sh, bash, zsh, dash, ksh, python, python3, perl, ruby, node) |

#### Allow Rules (2 rules)

| Rule Name | Detection Method | Safe Commands |
|-----------|-----------------|---------------|
| `common-safe-commands` | Map lookup + MatchArgs | `ls`, `cat`, `echo`, `pwd`, `whoami`, `date`, `head`, `tail`, `wc`, `sort`, `uniq`, `grep`, `which`, `file`, `basename`, `dirname`, `realpath`, `stat`, `du`, `df`, `env`, `printenv`, `id`, `uname`, `hostname`, `true`, `false` |
| `git-read-commands` | Subcommand check + MatchArgs | `git status`, `git log`, `git diff`, `git show`, `git branch`, `git tag`, `git remote -v` |

#### Escalated Rules (3 rules)

| Rule Name | Detection Method | Triggers |
|-----------|-----------------|----------|
| `global-install` | String/arg matching + MatchArgs | `npm install -g`, `npm i -g`, `yarn global add`, `pip install` (without `--user` or venv) |
| `docker-build` | Subcommand check + MatchArgs | `docker build`, `docker push`, `docker pull` |
| `system-package-install` | Subcommand check + MatchArgs | `brew install`, `apt install`, `apt-get install`, `yum install`, `dnf install` |

**Helper function:** `baseCommand(cmd string) string` extracts the base name from a possibly path-qualified command (e.g., `/usr/bin/ls` → `ls`).

### 6.6 ChainClassifier

```go
// ChainClassifier returns a Classifier that evaluates multiple classifiers in
// order. The first non-Sandboxed result wins. If every classifier returns
// Sandboxed the final Sandboxed result is returned.
func ChainClassifier(classifiers ...Classifier) Classifier {
	return &chainClassifier{classifiers: classifiers}
}
```

**Behavioral contract:**
- Empty chain returns `Sandboxed` with reason "no classifiers in chain; defaulting to sandboxed execution".
- First non-Sandboxed result wins (returns immediately).
- If all classifiers return Sandboxed, the last Sandboxed result is returned.

**Usage example:**
```go
cfg := &agentbox.Config{
	Classifier: agentbox.ChainClassifier(
		myProjectClassifier,       // custom rules first
		agentbox.DefaultClassifier(), // then built-in rules
	),
}
```

### 6.7 Classification Decision Flow

```
Command arrives at Manager.Wrap() / Manager.Exec()
  │
  ▼
Classifier.Classify(command) or Classifier.ClassifyArgs(name, args)
  │
  ├── Forbidden ──▶ return ErrForbiddenCommand (never executed)
  │
  ├── Escalated ──▶ check session approval cache
  │                  │ not cached
  │                  ▼
  │              ApprovalCallback (if registered)
  │                  │ Approve / ApproveSession
  │                  ▼
  │              execute in sandbox ◀── filesystem + network + resource limits
  │
  ├── Allow ──────▶ skip further classification
  │                  │
  │                  ▼
  │              execute in sandbox ◀── filesystem + network + resource limits
  │
  └── Sandboxed ──▶ execute in sandbox ◀── filesystem + network + resource limits
```

> **Key security invariant**: Allow and Sandboxed have identical execution paths —
> both go through all sandbox security layers (filesystem isolation, network isolation,
> process isolation, resource limits). Allow only skips further rule matching.

---

## 7. Platform Abstraction Layer

### 7.1 Platform Interface

```go
package platform

import (
	"context"
	"os/exec"
)

// Platform defines the interface for OS-specific sandbox implementations.
type Platform interface {
	// Name returns a human-readable identifier (e.g., "darwin-seatbelt", "linux-namespace").
	Name() string

	// Available reports whether this platform's sandbox mechanism is functional.
	Available() bool

	// CheckDependencies inspects the system for required and optional dependencies.
	CheckDependencies() *DependencyCheck

	// WrapCommand modifies an *exec.Cmd in-place to execute within the sandbox.
	WrapCommand(ctx context.Context, cmd *exec.Cmd, cfg *WrapConfig) error

	// Cleanup releases all platform-specific resources.
	Cleanup(ctx context.Context) error

	// Capabilities returns the set of isolation features this platform supports.
	Capabilities() Capabilities
}
```

**Note:** `Capabilities()` returns `Capabilities`.

### 7.2 Capabilities

```go
// Capabilities describes what isolation features a platform supports.
type Capabilities struct {
	FileReadDeny   bool // Can deny file read access
	FileWriteAllow bool // Can restrict writes to specific paths
	NetworkDeny    bool // Can block all network access
	NetworkProxy   bool // Can redirect traffic through a proxy
	PIDIsolation   bool // Can isolate process IDs
	SyscallFilter  bool // Can filter system calls (e.g., seccomp)
	ProcessHarden  bool // Can apply process hardening measures
}
```

### 7.3 DependencyCheck

```go
type DependencyCheck struct {
	Errors   []string // Critical missing dependencies (sandbox cannot run)
	Warnings []string // Non-critical issues (degraded functionality)
}

func (d *DependencyCheck) OK() bool { return len(d.Errors) == 0 }
```

**Note:** `DependencyCheck` is defined in the `platform` package. The root package's `Manager.CheckDependencies()` returns `*platform.DependencyCheck` directly (no duplication).

### 7.4 WrapConfig

```go
// WrapConfig is the configuration passed to Platform.WrapCommand.
type WrapConfig struct {
	// Filesystem
	WritableRoots  []string
	DenyWrite      []string
	DenyRead       []string
	AllowGitConfig bool

	// Network
	NeedsNetworkRestriction bool
	HTTPProxyPort           int
	SOCKSProxyPort          int

	// Process
	Shell string

	// Resource limits
	ResourceLimits *ResourceLimits
}
```

### 7.5 Detect

```go
// Detect returns the appropriate Platform for the current OS.
// On darwin: returns a platform that uses sandbox-exec (Seatbelt).
// On linux: returns a platform that uses namespaces + Landlock.
// On other OS: returns an unsupported platform stub.
func Detect() Platform {
	return detectPlatform()
}
```

Platform detection is split into build-tag-separated files:
- `platform/detect_darwin.go` — returns `darwin.New()`
- `platform/detect_linux.go` — returns `linux.New()`

Platform implementations use non-stuttering names:
- `darwin.Platform`
- `linux.Platform`

### 7.6 macOS Seatbelt Implementation

```
sandbox-exec -p <SBPL_PROFILE> -D WRITABLE_ROOT_0=/path/to/workspace -- /path/to/binary arg1 arg2
```

- **SBPL policy generation**: Uses `strings.Builder` to dynamically assemble the profile (no temp files).
- **Default deny**: `(deny default)` base with explicit allow rules.
- **Path parameterization**: Writable directories passed via `-D`, referenced in SBPL as `(param "WRITABLE_ROOT_0")`.
- **Symlink resolution**: macOS `/var` → `/private/var` requires `filepath.EvalSymlinks`.
- **Violation monitoring**: Via `log stream --predicate 'subsystem == "com.apple.sandbox"'`.
- **Resource limits**: Via `setrlimit(2)` system call.
- **Process hardening**: `hardenProcess` is a function variable (for testability) that applies ptrace denial and resource limits.
- **Profile building**: `buildProfile` is a function variable (for testability).

### 7.7 Linux Namespace + Landlock Implementation

```go
cmd.SysProcAttr = &syscall.SysProcAttr{
    Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
}
```

- **CLONE_NEWNET**: Complete network isolation.
- **CLONE_NEWPID**: PID isolation (cannot kill host processes).
- **CLONE_NEWNS**: Mount isolation with bind mounts for file visibility control.
- **Landlock**: Uses `landlock.V5.BestEffort()`, auto-degrades to kernel-supported ABI version.
- **Network bridging**: Via Unix socket (bind mounted into sandbox).
- **No root required**: Landlock and user namespaces are unprivileged.
- **Resource limits**: Via `setrlimit(2)`.
- **`runtime.LockOSThread()`**: Called before seccomp/landlock in sandbox init.

### 7.8 Re-exec Bootstrap (Linux)

Linux uses a re-exec pattern for namespace initialization. `SandboxExecPath` is a `var` (not `const`) for testability.

```go
package agentbox

// MaybeSandboxInit checks if the current process was re-executed as a sandbox helper.
// On Linux, this checks for the _AGENTBOX_CONFIG environment variable.
// On other platforms, this is a no-op that returns false.
//
// Call this at the very beginning of main():
//
//	func main() {
//	    if agentbox.MaybeSandboxInit() {
//	        return
//	    }
//	    // ... rest of main
//	}
func MaybeSandboxInit() bool
```

**Workflow:**
1. Main process `WrapCommand` creates `os.Pipe()`, writes config JSON to write end.
2. Read end passed via `cmd.ExtraFiles`, fd number stored in `_AGENTBOX_CONFIG` env var.
3. Uses `os.Args[0]` (current binary path) as child process `cmd.Path`, with `CLONE_NEWNS` etc.
4. Child process: `MaybeSandboxInit()` detects `_AGENTBOX_CONFIG` env var.
5. Reads config JSON from fd, executes bind mount, network bridging, etc.
6. After initialization, execs the user's actual command.

---

*Continue reading: [01d-integration.md](./01d-integration.md) — Network proxy architecture, comparison with sandbox-runtime, security model, usage examples*
*See also: [01a-overview-api.md](./01a-overview-api.md) — Project overview, core API design*
*See also: [01b-structure-flow.md](./01b-structure-flow.md) — Package structure, component interaction flow*
