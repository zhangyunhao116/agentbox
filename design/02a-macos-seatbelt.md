# macOS Seatbelt Sandbox Implementation

> **Status**: Implemented  
> **Author**: Agent  
> **Date**: 2026-02-15 (updated 2026-02-16)  
> **Scope**: agentbox platform abstraction layer + macOS Seatbelt implementation  
> **Prerequisite docs**: [01a-overview-api.md](./01a-overview-api.md), [01b-structure-flow.md](./01b-structure-flow.md)  
> **Related docs**: [02b-linux-namespace-landlock.md](./02b-linux-namespace-landlock.md)

---

## 1. Platform Abstraction Layer

### 1.1 Platform Interface

> **Source**: `platform/platform.go`

```go
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
```

**Key naming**: The return type is `platform.Capabilities`.

### 1.2 Supporting Types

```go
// DependencyCheck holds the result of a dependency check.
type DependencyCheck struct {
	Errors   []string // Critical missing dependencies that prevent sandboxing.
	Warnings []string // Non-critical issues that may degrade functionality.
}

// OK returns true if no critical dependency errors were found.
func (d *DependencyCheck) OK() bool {
	return len(d.Errors) == 0
}

// Capabilities describes what isolation features a platform supports.
type Capabilities struct {
	FileReadDeny   bool // Platform can deny file read access.
	FileWriteAllow bool // Platform can restrict writes to specific paths.
	NetworkDeny    bool // Platform can block all network access.
	NetworkProxy   bool // Platform can redirect traffic through a proxy.
	PIDIsolation   bool // Platform can isolate process IDs.
	SyscallFilter  bool // Platform can filter system calls (e.g., seccomp).
	ProcessHarden  bool // Platform can apply process hardening measures.
}
```

### 1.3 WrapConfig

```go
// WrapConfig is the configuration passed to Platform.WrapCommand.
// It describes the desired sandbox restrictions for a single command execution.
type WrapConfig struct {
	WritableRoots           []string         // Directories where the sandboxed process may write.
	DenyWrite               []string         // Paths the sandboxed process must not write to.
	DenyRead                []string         // Paths the sandboxed process must not read from.
	AllowGitConfig          bool             // Permits reading git configuration files.
	NeedsNetworkRestriction bool             // Network access should be restricted.
	HTTPProxyPort           int              // Local port of the HTTP/CONNECT proxy, if any.
	SOCKSProxyPort          int              // Local port of the SOCKS5 proxy, if any.
	Shell                   string           // Shell binary to use for command execution.
	ResourceLimits          *ResourceLimits  // Resource constraints for the sandboxed process.
}

// ResourceLimits specifies resource constraints for sandboxed processes.
type ResourceLimits struct {
	MaxProcesses       int   // Maximum number of processes the sandbox may spawn.
	MaxMemoryBytes     int64 // Maximum memory in bytes.
	MaxFileDescriptors int   // Maximum number of open file descriptors.
	MaxCPUSeconds      int   // Maximum CPU time in seconds.
}

// DefaultResourceLimits returns the default resource limits.
func DefaultResourceLimits() *ResourceLimits {
	return &ResourceLimits{
		MaxProcesses:       1024,
		MaxMemoryBytes:     2 * 1024 * 1024 * 1024, // 2 GB
		MaxFileDescriptors: 1024,
		MaxCPUSeconds:      0, // unlimited
	}
}
```

### 1.4 Platform Detection

> **Source**: `platform/detect_darwin.go`, `platform/detect_linux.go`, `platform/detect_other.go`

Platform detection uses build tags, not `runtime.GOOS` switch:

```go
// Detect returns the appropriate Platform for the current OS.
func Detect() Platform {
	return detectPlatform()
}
```

Each OS has its own `detectPlatform()` in a build-tagged file:
- `detect_darwin.go` (`//go:build darwin`): returns `&builtinDarwinPlatform{}`
- `detect_linux.go` (`//go:build linux`): returns `&builtinLinuxPlatform{}`
- `detect_other.go` (`//go:build !darwin && !linux`): returns `&unsupportedPlatform{}`

The built-in platform stubs are lightweight implementations that do **not** implement `WrapCommand`. For full sandbox support, use the sub-packages (`platform/darwin` or `platform/linux`) directly.

**`SandboxExecPath`** is defined in `detect_darwin.go` as a **`var`** (not `const`) for testability:

```go
// SandboxExecPath is the path to the macOS sandbox-exec binary.
// This is a var (not const) so tests can temporarily override it to simulate
// a missing sandbox-exec binary.
var SandboxExecPath = "/usr/bin/sandbox-exec"
```

---

## 2. macOS Seatbelt Implementation

### 2.1 Platform Type

> **Source**: `platform/darwin/seatbelt.go`

```go
package darwin

// Platform implements the platform.Platform interface using macOS sandbox-exec
// (Seatbelt). It generates SBPL profiles from WrapConfig and rewrites
// exec.Cmd to run under sandbox-exec.
type Platform struct{}

// New returns a new Platform instance.
func New() *Platform {
	return &Platform{}
}
```

**Key naming**: The type is `darwin.Platform`. The struct has no fields — it is stateless.

### 2.2 Function Variables for Testability

Two key functions are package-level **variables** (not methods) so tests can override them:

```go
// buildProfile builds an SBPL profile from a WrapConfig.
// It is a package-level variable so tests can override it to simulate errors.
var buildProfile = func(cfg *platform.WrapConfig) (string, error) {
	return newProfileBuilder().Build(cfg)
}
```

```go
// hardenProcess applies macOS-specific process hardening.
// It is a package-level variable so tests can override it to simulate errors.
var hardenProcess = hardenProcessImpl
```

### 2.3 Interface Methods

```go
func (d *Platform) Name() string    { return "darwin-seatbelt" }

func (d *Platform) Available() bool {
	_, err := os.Stat(platform.SandboxExecPath)
	return err == nil
}

func (d *Platform) CheckDependencies() *platform.DependencyCheck {
	check := &platform.DependencyCheck{}
	if _, err := os.Stat(platform.SandboxExecPath); err != nil {
		check.Errors = append(check.Errors,
			fmt.Sprintf("sandbox-exec not found at %s: %v", platform.SandboxExecPath, err))
	}
	return check
}

func (d *Platform) Capabilities() platform.Capabilities {
	return platform.Capabilities{
		FileReadDeny:   true,
		FileWriteAllow: true,
		NetworkDeny:    true,
		NetworkProxy:   true,
		ProcessHarden:  true,
		// PIDIsolation: false (macOS has no PID namespace)
		// SyscallFilter: false (macOS has no seccomp)
	}
}

func (d *Platform) Cleanup(_ context.Context) error {
	return nil // Currently a no-op.
}
```

### 2.4 WrapCommand

```go
func (d *Platform) WrapCommand(_ context.Context, cmd *exec.Cmd, cfg *platform.WrapConfig) error {
	if cfg == nil {
		cfg = &platform.WrapConfig{}
	}

	// 1. Apply process hardening (PT_DENY_ATTACH + disable core dumps).
	//    Best-effort: failures are logged but do not block execution.
	if err := hardenProcess(); err != nil {
		slog.Default().Warn("process hardening failed (non-fatal)", "error", err)
	}

	// 2. Build the SBPL profile.
	profile, err := buildProfile(cfg)
	if err != nil {
		return fmt.Errorf("darwin-seatbelt: failed to build profile: %w", err)
	}

	// 3. Resolve the original command path.
	origPath := cmd.Path
	if origPath == "" {
		return errors.New("darwin-seatbelt: cmd.Path is empty")
	}
	origArgs := make([]string, len(cmd.Args))
	copy(origArgs, cmd.Args)

	// 4. Rewrite the command to run under sandbox-exec.
	ulimitCmds := buildUlimitCommands(cfg.ResourceLimits)
	if ulimitCmds != "" {
		// With resource limits: sandbox-exec -p <profile> -- /bin/sh -c "ulimit ...; exec <cmd>"
		cmd.Path = platform.SandboxExecPath
		shellCmd := buildShellCommand(ulimitCmds, origPath, origArgs)
		cmd.Args = []string{"sandbox-exec", "-p", profile, "--", "/bin/sh", "-c", shellCmd}
	} else {
		// Without resource limits: sandbox-exec -p <profile> -- <original-command> <args...>
		cmd.Path = platform.SandboxExecPath
		newArgs := []string{"sandbox-exec", "-p", profile, "--"}
		if len(origArgs) > 0 {
			newArgs = append(newArgs, origArgs...)
		} else {
			newArgs = append(newArgs, origPath)
		}
		cmd.Args = newArgs
	}

	// 5. Sanitize environment: remove DYLD_* and LD_* variables.
	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	env = sanitizeEnv(env)

	// 6. Add proxy environment variables if proxy ports are configured.
	if cfg.HTTPProxyPort > 0 || cfg.SOCKSProxyPort > 0 {
		env = append(env, proxyEnvVars(cfg.HTTPProxyPort, cfg.SOCKSProxyPort)...)
	}
	cmd.Env = env

	return nil
}
```

**Behavioral notes**:
- Resource limits are applied via `ulimit` commands in a child shell, avoiding the race condition of setting rlimits on the parent process.
- `MaxProcesses` is logged but **skipped** on macOS due to unusual `RLIMIT_NPROC` kernel behavior.
- `cmd.Args[0]` in the rewritten command is `"sandbox-exec"` (the program name), not the full path.

### 2.5 Resource Limit Handling

```go
// buildUlimitCommands generates a string of ulimit shell commands from the
// given ResourceLimits. Returns an empty string if no limits are configured.
func buildUlimitCommands(limits *platform.ResourceLimits) string {
	if limits == nil {
		return ""
	}
	var cmds []string
	if limits.MaxFileDescriptors > 0 {
		cmds = append(cmds, fmt.Sprintf("ulimit -n %d", limits.MaxFileDescriptors))
	}
	if limits.MaxMemoryBytes > 0 {
		kbytes := limits.MaxMemoryBytes / 1024
		if kbytes == 0 { kbytes = 1 }
		cmds = append(cmds, fmt.Sprintf("ulimit -v %d", kbytes))
	}
	if limits.MaxCPUSeconds > 0 {
		cmds = append(cmds, fmt.Sprintf("ulimit -t %d", limits.MaxCPUSeconds))
	}
	// MaxProcesses is logged but skipped on macOS.
	if len(cmds) == 0 {
		return ""
	}
	return strings.Join(cmds, "; ")
}

// buildShellCommand constructs: "ulimit ...; exec 'cmd' 'arg1' 'arg2'"
// Arguments are single-quoted and escaped to prevent shell injection.
func buildShellCommand(ulimitCmds, origPath string, origArgs []string) string { ... }

// shellQuote returns a single-quoted shell-safe representation of s.
// Single quotes within s are escaped as '\'' (end quote, escaped quote, start quote).
func shellQuote(s string) string { ... }
```

---

## 3. SBPL Profile Generation

> **Source**: `platform/darwin/profile.go`

### 3.1 Profile Builder

The builder is **unexported** (`profileBuilder`, not `ProfileBuilder`):

```go
// profileBuilder constructs an SBPL (Sandbox Profile Language) profile
// from a WrapConfig. SBPL uses Scheme-like S-expression syntax.
type profileBuilder struct {
	buf strings.Builder
}

func newProfileBuilder() *profileBuilder {
	return &profileBuilder{}
}

func (b *profileBuilder) Build(cfg *platform.WrapConfig) (string, error) {
	b.buf.Reset()
	b.writeBase()
	b.writeFileRead(cfg)
	b.writeFileWrite(cfg)
	b.writeDangerousFileProtection(cfg)
	b.writeNetwork(cfg)
	b.writePTY()
	return b.buf.String(), nil
}
```

The builder uses a `strings.Builder` (not a `[]string` of sections). Helper methods:
- `line(s string)` — writes a line with newline
- `linef(format, args...)` — writes a formatted line
- `comment(s string)` — writes `; <comment>`
- `blank()` — writes an empty line

### 3.2 Base Policy

```scheme
(version 1)
(deny default)

; Allow basic process operations
(allow process*)
(allow process-exec)
(allow sysctl-read)
(allow mach*)
```

This is a **simplified** base policy compared to the original design. It uses broad `(allow process*)` and `(allow mach*)` rules rather than enumerating individual Mach service names.

### 3.3 File Read Policy (deny-only)

```go
func (b *profileBuilder) writeFileRead(cfg *platform.WrapConfig) {
	b.comment("File read: allow all by default, deny specific paths")
	b.line("(allow file-read*)")
	for _, p := range cfg.DenyRead {
		cp := canonicalizePath(p)
		b.linef("(deny file-read* (subpath \"%s\"))", escapeForSBPL(cp))
	}
	b.blank()
}
```

Generated SBPL:
```scheme
; File read: allow all by default, deny specific paths
(allow file-read*)
(deny file-read* (subpath "/Users/dev/.ssh"))
```

### 3.4 File Write Policy (allow-only)

```go
func (b *profileBuilder) writeFileWrite(cfg *platform.WrapConfig) {
	b.comment("File write: deny all by default, allow specific paths")
	b.line("(deny file-write*)")
	b.blank()

	// Always allow writing to temp directories.
	tmpDirs := getTmpdirParents()
	for _, d := range tmpDirs {
		b.linef("(allow file-write* (subpath \"%s\"))", escapeForSBPL(d))
	}

	// Allow configured writable roots.
	for _, root := range cfg.WritableRoots {
		cp := canonicalizePath(root)
		b.linef("(allow file-write* (subpath \"%s\"))", escapeForSBPL(cp))
	}

	// Deny writes to explicitly denied paths (overrides writable roots).
	for _, p := range cfg.DenyWrite {
		cp := canonicalizePath(p)
		b.linef("(deny file-write* (subpath \"%s\"))", escapeForSBPL(cp))
	}
	b.blank()
}
```

### 3.5 Dangerous File Protection

Denies writes to sensitive dotfiles and directories even within writable roots:

```go
func (b *profileBuilder) writeDangerousFileProtection(cfg *platform.WrapConfig) {
	home, err := os.UserHomeDir()
	if err != nil {
		return // Skip home-relative protections if home dir unknown.
	}
	home = canonicalizePath(home)

	dangerousFiles := []string{
		".bashrc", ".bash_profile", ".zshrc", ".zprofile",
		".profile", ".gitconfig", ".ssh",
	}
	dangerousDirs := []string{".git/hooks"}

	for _, f := range dangerousFiles {
		fp := filepath.Join(home, f)
		b.linef("(deny file-write* (literal \"%s\"))", escapeForSBPL(fp))
	}
	for _, d := range dangerousDirs {
		dp := filepath.Join(home, d)
		b.linef("(deny file-write* (subpath \"%s\"))", escapeForSBPL(dp))
	}

	// Allow git config read if explicitly permitted.
	if cfg.AllowGitConfig {
		gitCfg := filepath.Join(home, ".gitconfig")
		b.linef("(allow file-read* (literal \"%s\"))", escapeForSBPL(gitCfg))
	}
}
```

### 3.6 Network Policy

```go
func (b *profileBuilder) writeNetwork(cfg *platform.WrapConfig) {
	if !cfg.NeedsNetworkRestriction {
		b.comment("Network: no restrictions")
		b.line("(allow network*)")
		b.blank()
		return
	}

	b.comment("Network: deny all, allow localhost for proxy")
	b.line("(deny network*)")
	b.line("(allow network* (local udp \"*:*\"))")
	b.line("(allow network* (remote ip \"localhost:*\"))")
	b.blank()
}
```

When `NeedsNetworkRestriction` is true:
```scheme
; Network: deny all, allow localhost for proxy
(deny network*)
(allow network* (local udp "*:*"))
(allow network* (remote ip "localhost:*"))
```

When false:
```scheme
; Network: no restrictions
(allow network*)
```

### 3.7 PTY Policy

```go
func (b *profileBuilder) writePTY() {
	b.comment("Allow PTY access for interactive commands")
	b.line("(allow file-read* (regex #\"^/dev/(ttys|pty|null|zero|random|urandom|fd)\"))")
	b.line("(allow file-write* (regex #\"^/dev/ttys[0-9]+$\"))")
	b.line("(allow file-write* (regex #\"^/dev/pty[a-z][0-9a-f]$\"))")
	b.line("(allow file-write* (literal \"/dev/null\"))")
	b.line("(allow file-write* (literal \"/dev/zero\"))")
	b.line("(allow file-write* (literal \"/dev/random\"))")
	b.line("(allow file-write* (literal \"/dev/urandom\"))")
	b.line("(allow file-ioctl (regex #\"^/dev/(ttys|pty)\"))")
	b.blank()
}
```

---

## 4. Path Canonicalization

> **Source**: `platform/darwin/profile.go`

```go
// canonicalizePath resolves symlinks and normalizes the path.
// On macOS, /tmp -> /private/tmp and /var -> /private/var.
func canonicalizePath(p string) string {
	// Try to resolve symlinks via EvalSymlinks.
	resolved, err := filepath.EvalSymlinks(p)
	if err == nil {
		return filepath.Clean(resolved)
	}
	// Fallback: manual mapping for well-known macOS symlinks.
	cleaned := filepath.Clean(p)
	if cleaned == "/tmp" || strings.HasPrefix(cleaned, "/tmp/") {
		cleaned = "/private" + cleaned
	}
	if cleaned == "/var" || strings.HasPrefix(cleaned, "/var/") {
		cleaned = "/private" + cleaned
	}
	return cleaned
}
```

**Behavior**: First tries `filepath.EvalSymlinks`. If that fails (e.g., path does not exist), falls back to manual `/tmp` → `/private/tmp` and `/var` → `/private/var` mapping. The fallback checks each prefix independently (not a map iteration).

### 4.1 Temp Directory Resolution

```go
func getTmpdirParents() []string {
	dirs := make(map[string]struct{})

	// Always include the canonical macOS temp locations.
	dirs["/private/tmp"] = struct{}{}
	dirs["/private/var/folders"] = struct{}{}

	// Include TMPDIR if set (e.g., /var/folders/xx/.../T/).
	if tmpdir := os.Getenv("TMPDIR"); tmpdir != "" {
		cp := canonicalizePath(tmpdir)
		dirs[cp] = struct{}{}
	}

	result := make([]string, 0, len(dirs))
	for d := range dirs {
		result = append(result, d)
	}
	sort.Strings(result)
	return result
}
```

Always includes `/private/tmp` and `/private/var/folders`. Adds the canonicalized `TMPDIR` if set. Results are sorted for deterministic profile output.

### 4.2 SBPL String Escaping

```go
func escapeForSBPL(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\t", "\\t")
	return s
}
```

Escapes backslash, double-quote, newline, and tab characters. This is **not** `fmt.Sprintf("%q", s)` — it performs manual character-by-character escaping.

---

## 5. Process Hardening

> **Source**: `platform/darwin/harden.go`

### 5.1 hardenProcess (function variable)

```go
const ptDenyAttach = 31

// hardenProcess is a package-level variable so tests can override it.
var hardenProcess = hardenProcessImpl
```

### 5.2 hardenProcessImpl

```go
func hardenProcessImpl() error {
	// PT_DENY_ATTACH — prevent debugger attachment.
	_, _, errno := syscall.Syscall(syscall.SYS_PTRACE, ptDenyAttach, 0, 0)
	if errno != 0 && errno != syscall.EINVAL {
		// EINVAL means PT_DENY_ATTACH was already applied, which is fine.
		return fmt.Errorf("PT_DENY_ATTACH failed: %w", errno)
	}

	// Disable core dumps (RLIMIT_CORE = 0).
	var rlim syscall.Rlimit
	rlim.Cur = 0
	rlim.Max = 0
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &rlim); err != nil {
		return fmt.Errorf("disable core dumps (RLIMIT_CORE): %w", err)
	}

	return nil
}
```

**Three hardening measures**:
1. **PT_DENY_ATTACH** (ptrace code 31): prevents debugger attachment. EINVAL is silently ignored (means already applied). This is idempotent.
2. **RLIMIT_CORE = 0**: prevents core dump files from being written.
3. **DYLD_\*/LD_\* removal**: done in `sanitizeEnv()` during `WrapCommand`, not in `hardenProcessImpl`.

### 5.3 Environment Sanitization

```go
func sanitizeEnv(env []string) []string {
	env = envutil.RemoveEnvPrefix(env, "DYLD_")
	env = envutil.RemoveEnvPrefix(env, "LD_")
	return env
}
```

Uses `internal/envutil.RemoveEnvPrefix` — removes both `DYLD_*` and `LD_*` prefixes. The `envutil` package extracts the key portion (before `=`) and checks the prefix against it.

---

## 6. Proxy Environment Variables

```go
func proxyEnvVars(httpPort, socksPort int) []string {
	var vars []string
	if httpPort > 0 {
		proxy := fmt.Sprintf("http://127.0.0.1:%d", httpPort)
		vars = append(vars,
			"HTTP_PROXY="+proxy, "http_proxy="+proxy,
			"HTTPS_PROXY="+proxy, "https_proxy="+proxy,
		)
	}
	if socksPort > 0 {
		socks := fmt.Sprintf("socks5://127.0.0.1:%d", socksPort)
		vars = append(vars,
			"ALL_PROXY="+socks, "all_proxy="+socks,
		)
	}
	return vars
}
```

**Note**: Uses `127.0.0.1` (not `localhost`). SOCKS5 scheme is `socks5://` (not `socks5h://`). No `NO_PROXY` variable is set.

---

## 7. Violation Monitoring

> **Source**: `platform/darwin/monitor.go`

Currently a **stub** — only the type is defined:

```go
// violationEvent represents a single sandbox violation detected from
// the macOS system log.
type violationEvent struct {
	Timestamp time.Time
	RawLine   string
}

// Ensure violationEvent is retained for future use.
var _ = violationEvent{}
```

The type is **unexported** (`violationEvent`, not `ViolationEvent`). There is no `ViolationMonitor` struct, no `StartViolationMonitor` function, and no `log stream` integration yet. This is marked as TODO for a future release.

---

## 8. File Structure

```
platform/
├── platform.go              # Platform interface, Capabilities, WrapConfig, ResourceLimits, Detect()
├── detect_darwin.go          # //go:build darwin — SandboxExecPath var, builtinDarwinPlatform
├── detect_linux.go           # //go:build linux — builtinLinuxPlatform
├── detect_other.go           # //go:build !darwin && !linux — unsupportedPlatform
├── unsupported.go            # unsupportedPlatform type + NewUnsupportedPlatform()
├── doc.go                    # Package documentation
├── platform_test.go          # Tests for platform package
├── darwin/
│   ├── seatbelt.go           # Platform struct, New(), WrapCommand, buildUlimitCommands, etc.
│   ├── profile.go            # profileBuilder, SBPL generation, canonicalizePath, sanitizeEnv
│   ├── harden.go             # hardenProcess var, hardenProcessImpl (PT_DENY_ATTACH + RLIMIT_CORE)
│   ├── monitor.go            # violationEvent stub (TODO)
│   ├── seatbelt_test.go      # Tests for seatbelt
│   ├── profile_test.go       # Tests for profile generation
│   └── harden_test.go        # Tests for process hardening
└── linux/
    └── ...                   # See 02b-linux-namespace-landlock.md
```

All darwin files have `//go:build darwin` build tag.

---

## 9. Limitations and Known Issues

| Issue | Description | Mitigation |
|-------|-------------|------------|
| sandbox-exec deprecated | Apple marked deprecated but not removed; macOS 15 still works | Monitor version updates; prepare migration to Endpoint Security |
| No PID isolation | Seatbelt does not provide PID namespace | `(allow process*)` with `same-sandbox` signal restriction |
| Profile size limit | `-p` argument subject to ARG_MAX | Switch to `-f` file mode for large rule sets |
| DYLD/LD bypass | DYLD_INSERT_LIBRARIES / LD_* can inject dynamic libraries | `sanitizeEnv` strips both DYLD_* and LD_* prefixes |
| Symlink TOCTOU | Race between path canonicalization and policy application | `canonicalizePath` with EvalSymlinks + manual fallback |
| Violation monitoring | Not yet implemented | Stub type defined; `log stream` integration planned |
| MaxProcesses on macOS | RLIMIT_NPROC has unusual kernel behavior | Logged but skipped in `buildUlimitCommands` |
