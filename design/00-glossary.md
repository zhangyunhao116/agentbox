# agentbox Glossary

> This document defines all core terms used across the agentbox design documents.
> When terminology in other documents conflicts with this table, this table is authoritative.

## Core Types

| Term | Definition | Authoritative Doc |
|------|-----------|-------------------|
| `Manager` | Sandbox manager interface. Provides 8 methods: `Wrap`, `Exec`, `ExecArgs`, `Cleanup`, `Available`, `CheckDependencies`, `UpdateConfig`, `Check` | 01a §2.1 |
| `Config` | Sandbox configuration struct. Fields: `Filesystem`, `Network`, `Classifier`, `Shell`, `MaxOutputBytes`, `ResourceLimits`, `FallbackPolicy` | 01a §2.2 |
| `Platform` | Platform abstraction interface. Provides `Name`, `Available`, `CheckDependencies`, `WrapCommand`, `Cleanup`, `Capabilities` methods. Lives in `platform` package | 01c §7.1 |
| `Classifier` | Command classifier interface. Provides `Classify(command string) ClassifyResult` and `ClassifyArgs(name string, args []string) ClassifyResult` methods | 01c §6.1 |
| `ClassifyResult` | Classification result struct. Fields: `Decision Decision`, `Reason string`, `Rule string` | 01a §2.1 |
| `NetworkConfig` | Network configuration. Fields: `Mode NetworkMode`, `AllowedDomains []string`, `DeniedDomains []string`, `OnRequest func(ctx, host, port) (bool, error)` | 01c §5.1 |
| `FilesystemConfig` | Filesystem configuration. Fields: `WritableRoots []string`, `DenyWrite []string`, `DenyRead []string`, `AllowGitConfig bool` | 01c §5.1 |
| `ExecResult` | Command execution result. Fields: `ExitCode int`, `Stdout string`, `Stderr string`, `Duration time.Duration`, `Sandboxed bool`, `Truncated bool`, `Violations []Violation` | 01a §2.4 |
| `Violation` | Sandbox violation event. Fields: `Operation ViolationType`, `Path string`, `Detail string`, `Process string`, `Raw string` | 01a §2.4 |
| `ViolationType` | String enum for violation kinds: `"file-read"`, `"file-write"`, `"network"`, `"process"`, `"other"`. Constants: `ViolationFileRead`, `ViolationFileWrite`, `ViolationNetwork`, `ViolationProcess`, `ViolationOther` | 01a §2.4 |
| `ResourceLimits` | Resource constraints for sandboxed processes. Canonical definition in `platform` package; root package uses `type ResourceLimits = platform.ResourceLimits` (type alias). Fields: `MaxProcesses int`, `MaxMemoryBytes int64`, `MaxFileDescriptors int`, `MaxCPUSeconds int` | 01c §5.1 |

## Decisions & Policies

| Term | Definition | Authoritative Doc |
|------|-----------|-------------------|
| `Decision` | Classification decision enum (int). Values: `Sandboxed=0` (iota, zero value), `Allow=1`, `Escalated=2`, `Forbidden=3` | 01c §6.2 |
| `Sandboxed` | Zero-value default decision. Command executes in sandbox. Uninitialized `ClassifyResult` defaults to this (safest) | 01c §6.2 |
| `Allow` | Command is safe; skips classification check but **still executes in sandbox** (not a bypass) | 01c §6.2 |
| `Escalated` | Command requires user approval before execution | 01c §6.2 |
| `Forbidden` | Command must not be executed | 01c §6.2 |
| `FallbackPolicy` | Behavior when sandbox is unavailable: `FallbackStrict` (iota=0, default, refuse execution) / `FallbackWarn` (=1, degrade to NopManager + warning) | 01c §5.1 |

## Approval System

| Term | Definition | Authoritative Doc |
|------|-----------|-------------------|
| `ApprovalCallback` | User approval callback type: `func(ctx context.Context, req ApprovalRequest) (ApprovalDecision, error)`. Injected via `ManagerOption`, not a Config field | 01a §2.5 |
| `ApprovalRequest` | Approval request context. Fields: `Command string`, `Reason string`, `Decision Decision` | 01a §2.5 |
| `ApprovalDecision` | Approval result enum (int). Values: `Approve=0` (iota), `Deny=1`, `ApproveSession=2` | 01a §2.5 |
| `ManagerOption` | Manager-level option type: `func(*managerOptions)`. Used in `NewManager(cfg, opts...)` | 01a §2.5 |
| `WithApprovalCallback` | `ManagerOption` that registers an `ApprovalCallback` for escalated commands | 01a §2.5 |

## Network

| Term | Definition | Authoritative Doc |
|------|-----------|-------------------|
| `NetworkMode` | Network mode enum (int): `NetworkFiltered=0` (iota), `NetworkBlocked=1`, `NetworkAllowed=2` | 01c §5.1 |
| `OnRequest` | Network request callback. In root package: `func(ctx context.Context, host string, port int) (bool, error)` field on `NetworkConfig`. In proxy package: `type OnRequest func(ctx context.Context, host string, port int) (bool, error)` type alias | 01c §5.1 |
| `DomainFilter` | Domain filtering engine in `proxy` package. Priority: `denied > allowed > OnRequest > default deny`. Thread-safe, supports `UpdateRules()` for hot-reload | 03b §3 |
| `ValidateDomainPattern` | Exported function in `proxy` package. Validates domain pattern strings (e.g., `"example.com"`, `"*.example.com"`) | proxy/filter.go |

## Options (per-call)

| Term | Definition | Authoritative Doc |
|------|-----------|-------------------|
| `Option` | Per-call option type: `func(*callOptions)`. Used in `Wrap`, `Exec`, `ExecArgs` | 01a §2.5 |
| `WithWritableRoots` | `Option`: adds writable root directories for a single call | 01a §2.5 |
| `WithNetwork` | `Option`: overrides network configuration for a single call | 01a §2.5 |
| `WithEnv` | `Option`: appends environment variables for a single call | 01a §2.5 |
| `WithShell` | `Option`: overrides shell for a single call | 01a §2.5 |
| `WithClassifier` | `Option`: overrides classifier for a single call | 01a §2.5 |
| `WithWorkingDir` | `Option`: sets working directory for a single call | 01a §2.5 |
| `WithTimeout` | `Option`: sets timeout for a single call (convenience wrapper around `context.WithTimeout`) | 01a §2.5 |
| `WithDenyRead` | `Option`: adds paths denied read access for a single call | 01a §2.5 |
| `WithDenyWrite` | `Option`: adds paths denied write access for a single call | 01a §2.5 |

## Config Helpers

| Term | Definition | Authoritative Doc |
|------|-----------|-------------------|
| `DefaultConfig()` | Returns `*Config` (**no error**). Secure defaults: `FallbackStrict`, `NetworkFiltered`, deny-write system dirs, deny-read sensitive dirs | 01a §2.2 |
| `DevelopmentConfig()` | Returns `*Config`. Based on `DefaultConfig()` with `FallbackWarn` + `NetworkAllowed` | 01a §2.2 |
| `CIConfig()` | Returns `*Config`. Based on `DefaultConfig()` with `FallbackStrict` + `NetworkBlocked` | 01a §2.2 |
| `DefaultResourceLimits()` | Returns `*ResourceLimits`. Defaults: 1024 processes, 2GB memory, 1024 FDs, unlimited CPU | 01a §2.2 |

## Error Types

| Term | Definition | Authoritative Doc |
|------|-----------|-------------------|
| `ErrForbiddenCommand` | Command rejected by classifier | 01a §2.6 |
| `ErrEscalatedCommand` | Command requires user approval | 01a §2.6 |
| `ErrUnsupportedPlatform` | Current OS does not support sandboxing | 01a §2.6 |
| `ErrDependencyMissing` | Required system dependency missing (e.g., macOS `sandbox-exec`) | 01a §2.6 |
| `ErrManagerClosed` | Manager already closed via `Cleanup()` | 01a §2.6 |
| `ErrConfigInvalid` | Configuration validation failed | 01a §2.6 |
| `ErrProxyStartFailed` | Network proxy server failed to start | 01a §2.6 |

## Platform Implementations

| Term | Definition | Authoritative Doc |
|------|-----------|-------------------|
| `darwin.Platform` | macOS Seatbelt implementation | 02a |
| `linux.Platform` | Linux Namespace + Landlock implementation | 02b |
| `platform.Capabilities` | Platform capability descriptor. Fields: `FileReadDeny`, `FileWriteAllow`, `NetworkDeny`, `NetworkProxy`, `PIDIsolation`, `SyscallFilter`, `ProcessHarden` | 01c §7.1 |
| `Seatbelt` | macOS sandbox framework (Apple's sandbox mechanism) | 02a |
| `sandbox-exec` | macOS sandbox CLI tool (Seatbelt user-space entry point) | 02a |
| `SandboxExecPath` | `var` (not `const`) in `platform` package. Default: `"/usr/bin/sandbox-exec"`. Mutable for testability | 02a |
| `SBPL` | Sandbox Profile Language, macOS sandbox policy language (Scheme-based) | 02a |
| `Landlock` | Linux kernel security module (5.13+), provides filesystem access control | 02b |
| `seccomp-bpf` | Linux system call filtering mechanism | 02b |
| `DependencyCheck` | Dependency check result. Canonical definition in `platform` package. Fields: `Errors []string`, `Warnings []string`. Method: `OK() bool` | 01a §2.6 |

## Proxy Types

| Term | Definition | Authoritative Doc |
|------|-----------|-------------------|
| `proxy.Server` | Combined HTTP + SOCKS5 proxy server. Implements `Proxy` interface | 01d |
| `proxy.Config` | Proxy server configuration. Fields: `Filter *DomainFilter`, `Logger *slog.Logger` | 01d |
| `proxy.NewServer` | Constructor: `func NewServer(cfg *Config) (*Server, error)` | 01d |
| `proxy.HTTPConfig` | HTTP proxy configuration. Fields: `Filter`, `DialTimeout`, `IdleTimeout`, `MaxRequestBodySize int64`, `Logger` | 01d |
| `proxy.SOCKS5Config` | SOCKS5 proxy configuration. Fields: `Filter`, `Logger`, `Dial` | 01d |
| `proxy.FilterConfig` | Domain filter configuration. Fields: `DeniedDomains`, `AllowedDomains`, `OnRequest` | 01d |
| `proxy.EnvConfig` | Proxy env var generation config. Fields: `HTTPProxyPort`, `SOCKSProxyPort`, `TmpDir` | 01d |
| `proxy.BridgePair` | Manages HTTP + SOCKS5 Unix socket bridges together (Linux). Methods: `Start()`, `Shutdown(timeout)` | 01d |

## Mechanisms

| Term | Definition | Authoritative Doc |
|------|-----------|-------------------|
| `Re-exec` | Linux sandbox bootstrap mechanism. Detected via `_AGENTBOX_CONFIG` environment variable. Entry point: `MaybeSandboxInit()` | 01c §7.4 |
| `WrapConfig` | Configuration passed to `Platform.WrapCommand`. Assembled by Manager from Config + Options. Fields: `WritableRoots`, `DenyWrite`, `DenyRead`, `AllowGitConfig`, `NeedsNetworkRestriction`, `HTTPProxyPort`, `SOCKSProxyPort`, `Shell`, `ResourceLimits` | 01c §7.1 |
| `NopManager` | Pass-through Manager that executes without sandboxing. Created via `NewNopManager()`. Returned by `NewManager` when `FallbackWarn` is set and platform is unavailable | 01a §2.2 |

## Internal Implementation Details

| Term | Definition | Authoritative Doc |
|------|-----------|-------------------|
| `rule` | Unexported classification rule struct (was `Rule` in design). Fields: `Name string`, `Match func`, `MatchArgs func` | classifier_rules.go |
| `hardenProcess` | Unexported function variable in `darwin` package (was `HardenProcess`). Applies ptrace deny + resource limits | darwin/harden.go |
| `profileBuilder` | Unexported SBPL profile builder (was `ProfileBuilder`) | darwin/profile.go |
| `buildProfile` | Unexported function variable in `darwin` package. Builds SBPL profile from WrapConfig. Overridable for testing | darwin/seatbelt.go |

## Implementation Phases

| Term | Definition | Authoritative Doc |
|------|-----------|-------------------|
| Phase 1 | Core framework (Manager/Config/Classifier) | 04a |
| Phase 2 | macOS Seatbelt implementation | 04a |
| Phase 3 | Linux Namespace + Landlock implementation | 04a |
| Phase 4 | Network proxy (HTTP + SOCKS5) | 04a |
| Phase 5 | Polish (documentation, examples) | 04a |
| Phase 6 | Advanced features (approval system, process hardening, etc.) | 04a |
