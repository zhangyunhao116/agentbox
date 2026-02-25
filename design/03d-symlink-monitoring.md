# agentbox: Symlink Protection & Violation Monitoring

> **Status**: Implemented  
> **Author**: Agent  
> **Date**: 2026-02-16  
> **Scope**: Symlink protection, path canonicalization, violation monitoring, configuration schema

> Series: [03a](03a-network-architecture.md) | [03b](03b-socks-domain-env.md) | [03c](03c-bridge-fs.md) | [03d](03d-symlink-monitoring.md)

> **This file is part 4 of the 03-network-and-fs series**
> - 📄 [03a-network-architecture.md](03a-network-architecture.md) — Network Isolation Architecture & HTTP Proxy Implementation
> - 📄 [03b-socks-domain-env.md](03b-socks-domain-env.md) — SOCKS5 Proxy, Domain Filtering & Environment Variable Injection
> - 📄 [03c-bridge-fs.md](03c-bridge-fs.md) — Linux Network Bridge & Filesystem Strategy
> - 📄 Current: 03d — Symlink Protection & Violation Monitoring

---

## 11. Symlink Protection

### 11.1 Path Canonicalization Strategy

All paths entering the sandbox policy are canonicalized via `canonicalizePath()` in `darwin/profile.go`:

1. Attempt `filepath.EvalSymlinks(p)` to resolve symlinks
2. On failure, apply manual macOS symlink mapping (`/tmp` → `/private/tmp`, `/var` → `/private/var`)
3. Return `filepath.Clean(result)`

This ensures SBPL rules use real paths, not symlink paths.

### 11.2 macOS /tmp → /private/tmp Handling

macOS has system-level symlinks: `/tmp` → `/private/tmp`, `/var` → `/private/var`. The `canonicalizePath` function handles this:

```go
func canonicalizePath(p string) string {
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

SBPL policies must use the real path:
```scheme
;; Wrong: uses symlink path
(allow file-write* (subpath "/tmp/sandbox"))

;; Correct: uses real path
(allow file-write* (subpath "/private/tmp/sandbox"))
```

### 11.3 Attack Scenarios & Defenses

#### Symlink Replacement Attack

**Attack**: Create a symlink in a writable directory pointing to a sensitive file.

```bash
ln -s /etc/passwd /writable/dir/passwd_link
echo "malicious" > /writable/dir/passwd_link  # Actually writes to /etc/passwd
```

**Defense**:
- macOS: SBPL operates at the kernel level, resolving paths before applying rules
- Linux: Landlock uses file descriptors (`PathFd`), not path strings — immune to path manipulation
- Path canonicalization at policy construction time ensures rules target real paths

#### Directory Move Attack

**Attack**: Create files in a writable directory, then move the directory to a sensitive location.

```bash
mkdir /writable/dir/evil
echo "malicious" > /writable/dir/evil/payload
mv /writable/dir/evil /etc/cron.d/
```

**Defense**:
- macOS SBPL `(deny file-write*)` prevents creating files in non-writable paths
- Linux Landlock `LANDLOCK_ACCESS_FS_REFER` (ABI V2+) blocks cross-boundary rename/link

---

## 12. Violation Monitoring

### 12.1 Current Implementation (darwin/monitor.go)

The violation monitoring is currently a **stub**. The file defines only the `violationEvent` type:

```go
//go:build darwin

package darwin

import "time"

// violationEvent represents a single sandbox violation detected from
// the macOS system log.
type violationEvent struct {
    // Timestamp is when the violation was recorded.
    Timestamp time.Time

    // RawLine is the raw log line from the system log.
    RawLine string
}
```

**Note**: `violationEvent` is **unexported** (lowercase `v`). The full log monitoring implementation (using `log stream`) is planned for a future release.

### 12.2 Violation Types in ExecResult

Violations are reported through the `ExecResult.Violations` field using the `Violation` type:

```go
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
    Operation ViolationType
    Path      string
    Detail    string
}
```

---

## Appendix A: Configuration Schema

### NetworkConfig (config.go)

```go
// NetworkMode determines how network access is handled inside the sandbox.
type NetworkMode int

const (
    // NetworkFiltered allows network access only to explicitly allowed domains.
    NetworkFiltered NetworkMode = iota

    // NetworkBlocked denies all network access from within the sandbox.
    NetworkBlocked

    // NetworkAllowed permits unrestricted network access.
    NetworkAllowed
)

// NetworkConfig defines network access restrictions for the sandbox.
type NetworkConfig struct {
    // Mode determines the overall network access policy.
    Mode NetworkMode

    // AllowedDomains lists domain patterns that are permitted when Mode is NetworkFiltered.
    AllowedDomains []string

    // DeniedDomains lists domain patterns that are always blocked.
    DeniedDomains []string

    // OnRequest is an optional callback invoked for each outgoing connection attempt.
    // Only called when Mode is NetworkFiltered and the domain is not in
    // AllowedDomains or DeniedDomains.
    // Implementations must be safe for concurrent use by multiple goroutines.
    OnRequest func(ctx context.Context, host string, port int) (bool, error)
}
```

### FilesystemConfig (config.go)

```go
// FilesystemConfig defines filesystem access restrictions for the sandbox.
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

### Config (config.go)

```go
// Config holds the complete configuration for a sandbox Manager.
type Config struct {
    Filesystem     FilesystemConfig
    Network        NetworkConfig
    Classifier     Classifier
    Shell          string          // Empty = system default shell
    MaxOutputBytes int             // 0 = no limit
    ResourceLimits *ResourceLimits // nil = DefaultResourceLimits()
    FallbackPolicy FallbackPolicy  // Default: FallbackStrict
}
```

### ResourceLimits

```go
// ResourceLimits is an alias for platform.ResourceLimits.
type ResourceLimits = platform.ResourceLimits

// DefaultResourceLimits returns sensible default resource limits.
func DefaultResourceLimits() *ResourceLimits
```

The canonical definition lives in the `platform` package. The root package uses a type alias.

### Preset Configurations

```go
// DefaultConfig returns a Config with secure defaults.
func DefaultConfig() *Config

// DevelopmentConfig returns a Config suitable for local development.
// Uses FallbackWarn + NetworkAllowed.
func DevelopmentConfig() *Config

// CIConfig returns a Config optimized for CI/CD environments.
// Uses FallbackStrict + NetworkBlocked.
func CIConfig() *Config
```

## Appendix B: Complete Traffic Path Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Sandboxed Process                                │
│                                                                         │
│  curl https://github.com/...                                           │
│    → HTTPS_PROXY=http://127.0.0.1:<port>                               │
│    → CONNECT github.com:443                                            │
│                                                                         │
│  git clone ssh://git@github.com/...                                    │
│    → GIT_SSH_COMMAND="ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:...'" │
│    → SOCKS5 CONNECT github.com:22                                      │
│                                                                         │
│  npm install                                                            │
│    → HTTPS_PROXY=http://127.0.0.1:<port>                               │
│    → CONNECT registry.npmjs.org:443                                    │
│                                                                         │
│  psql -h db.example.com                                                │
│    → ALL_PROXY=socks5h://127.0.0.1:<port>                             │
│    → SOCKS5 CONNECT db.example.com:5432                                │
└────────────────────────┬────────────────────────────────────────────────┘
                         │
          ┌──────────────┴──────────────┐
          │                             │
    ┌─────▼─────┐               ┌──────▼──────┐
    │ HTTP Proxy │               │ SOCKS5 Proxy│
    │ (auto-port)│               │ (auto-port) │
    └─────┬─────┘               └──────┬──────┘
          │                             │
          └──────────────┬──────────────┘
                         │
                  ┌──────▼──────┐
                  │Domain Filter│
                  │             │
                  │ IP blocked? ──▶ REJECT
                  │ denied?     ──▶ REJECT
                  │ allowed?    ──▶ ALLOW
                  │ OnRequest?  ──▶ CALLBACK
                  │ default     ──▶ REJECT
                  └──────┬──────┘
                         │ ALLOW
                  ┌──────▼──────┐
                  │   Internet  │
                  └─────────────┘
```
