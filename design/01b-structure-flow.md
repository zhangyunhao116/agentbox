# agentbox Architecture — Package Structure & Component Interaction

> Series: [01a](01a-overview-api.md) | [01b](01b-structure-flow.md) | [01c](01c-config-classifier.md) | [01d](01d-integration.md)

> **Status**: Implemented
> **Date**: 2026-02-16
> **Scope**: agentbox — Process-level sandbox library for Go
> **Split note**: This file covers package structure and component interaction flows.
>   Project overview and core API: [01a-overview-api.md](./01a-overview-api.md).
>   Configuration system, command classifier, platform abstraction: [01c-config-classifier.md](./01c-config-classifier.md).
>   Integration (network proxy, comparison, security model, examples): [01d-integration.md](./01d-integration.md).

---

## 3. Package Structure

```
agentbox/
├── sandbox.go              # Public API entry: Manager interface, Wrap, Exec, ExecArgs, Check, NewManager
├── config.go               # Config struct, DefaultConfig(), DevelopmentConfig(), CIConfig(), Validate()
├── config_test.go          # Config validation tests
├── option.go               # Option, ManagerOption types and all With* functions
├── option_test.go          # Option tests
├── errors.go               # Sentinel error definitions (ErrForbiddenCommand, etc.)
├── errors_test.go          # Error tests
├── result.go               # ExecResult, Violation, ViolationType types
├── result_test.go          # Result type tests
├── classifier.go           # Classifier interface, Decision enum, ClassifyResult type
├── classifier_rules.go     # Built-in classification rules (DefaultClassifier)
├── classifier_test.go      # Classifier tests
├── manager.go              # Core manager struct implementation (all 8 interface methods)
├── manager_test.go         # Manager integration tests
├── nop.go                  # NopManager pass-through implementation
├── nop_test.go             # NopManager tests
├── reexec.go               # MaybeSandboxInit() — re-exec bootstrap entry point
├── reexec_linux.go         # Linux-specific re-exec implementation
├── reexec_other.go         # No-op re-exec for non-Linux platforms
├── reexec_test.go          # Re-exec tests
├── doc.go                  # Package documentation
│
├── proxy/                  # Built-in network proxy (HTTP + SOCKS5)
│   ├── proxy.go            # Proxy interface, Server (combined HTTP+SOCKS5), NewServer, Config
│   ├── proxy_test.go       # Proxy integration tests
│   ├── http.go             # HTTPProxy, HTTPConfig (with MaxRequestBodySize)
│   ├── http_test.go        # HTTP proxy tests
│   ├── socks5.go           # SOCKS5Proxy, SOCKS5Config
│   ├── socks5_test.go      # SOCKS5 proxy tests
│   ├── filter.go           # DomainFilter, FilterConfig, FilterFunc, OnRequest, ValidateDomainPattern
│   ├── filter_test.go      # Domain filter tests
│   ├── bridge.go           # Bridge (Unix socket→TCP), BridgeConfig, BridgePair
│   ├── bridge_test.go      # Bridge tests
│   ├── env.go              # EnvConfig, GenerateProxyEnv()
│   ├── env_test.go         # Proxy env tests
│   ├── doc.go              # Package documentation
│   └── internal/
│       └── socks5/         # Internal SOCKS5 protocol implementation
│           ├── socks5.go       # Server, Config, RuleSet, NameResolver, Request, AddrSpec
│           └── socks5_test.go  # Internal SOCKS5 tests
│
├── platform/               # Platform abstraction layer
│   ├── platform.go         # Platform interface, DependencyCheck, Capabilities, WrapConfig,
│   │                       #   ResourceLimits, DefaultResourceLimits(), Detect()
│   ├── platform_test.go    # Platform detection tests
│   ├── detect_darwin.go    # macOS: builtinDarwinPlatform, SandboxExecPath (var)
│   ├── detect_darwin_test.go
│   ├── detect_linux.go     # Linux: platform detection
│   ├── detect_other.go     # Unsupported platforms stub
│   ├── unsupported.go      # unsupportedPlatform implementation
│   ├── doc.go              # Package documentation
│   │
│   ├── darwin/             # macOS Seatbelt implementation
│   │   ├── seatbelt.go     # darwin.Platform implementation
│   │   ├── profile.go      # SBPL profile generation (profileBuilder, strings.Builder)
│   │   ├── profile_test.go # SBPL profile tests
│   │   ├── harden.go       # hardenProcess function variable (ptrace deny + rlimits)
│   │   ├── harden_test.go  # Process hardening tests
│   │   └── monitor.go      # Sandbox violation log monitoring
│   │
│   └── linux/              # Linux Namespace + Landlock implementation
│       ├── linux.go        # linux.Platform implementation
│       ├── linux_test.go   # Linux platform tests
│       ├── namespace.go    # CLONE_NEWNET/NEWPID/NEWNS configuration
│       ├── landlock.go     # Landlock filesystem restrictions
│       ├── seccomp.go      # Seccomp BPF system call filtering
│       ├── detect.go       # Kernel version detection & capability degradation
│       ├── detect_test.go  # Detection tests
│       ├── harden.go       # Linux process hardening
│       └── reexec.go       # Re-exec mode implementation
│
└── internal/               # Internal utilities (not exported)
    └── envutil/            # Environment variable injection
        ├── envutil.go      # SetEnv, RemoveEnvPrefix, etc.
        └── envutil_test.go # Env util tests
```

> **Note**: `internal/pathutil/` was removed (dead code). Path normalization is handled inline.

### 3.1 Package Responsibility Matrix

| Package | Responsibility | Dependencies | Exported |
|---------|---------------|-------------|----------|
| `agentbox` (root) | Public API, Manager impl, Config, Classifier, re-exec | `proxy`, `platform` | ✅ All |
| `proxy` | HTTP/SOCKS5 proxy, domain filtering, Unix socket bridge | stdlib `net`, `net/http`; `proxy/internal/socks5` | ✅ `Proxy` interface, `Server`, `DomainFilter`, etc. |
| `proxy/internal/socks5` | SOCKS5 protocol implementation | stdlib only | ❌ Internal |
| `platform` | Platform abstraction interface, `Detect()` factory | None | ✅ `Platform` interface, `DependencyCheck`, `Capabilities`, `WrapConfig`, `ResourceLimits` |
| `platform/darwin` | macOS Seatbelt implementation | `platform` | ❌ Via `platform.Detect()` |
| `platform/linux` | Linux Namespace + Landlock | `platform` | ❌ Via `platform.Detect()` |
| `internal/envutil` | Environment variable utilities | stdlib | ❌ |

### 3.2 Key Type Name Conventions (Anti-Stuttering)

The codebase follows Go naming conventions to avoid stuttering when used with package qualifiers:

| Package | Type Name | Usage (with qualifier) |
|---------|-----------|----------------------|
| `platform/darwin` | `Platform` | `darwin.Platform` (not `DarwinPlatform`) |
| `platform/linux` | `Platform` | `linux.Platform` (not `LinuxPlatform`) |
| `platform` | `Capabilities` | `platform.Capabilities` (not `PlatformCapabilities`) |
| `proxy` | `Server` | `proxy.Server` (not `ProxyServer`) |
| `proxy` | `Config` | `proxy.Config` (not `ProxyConfig`) |
| `proxy` | `NewServer` | `proxy.NewServer` (not `NewProxyServer`) |
| `proxy` | `HTTPConfig` | `proxy.HTTPConfig` (not `HTTPProxyConfig`) |
| `proxy` | `SOCKS5Config` | `proxy.SOCKS5Config` (not `SOCKS5ProxyConfig`) |
| `proxy` | `FilterConfig` | `proxy.FilterConfig` (not `DomainFilterConfig`) |
| `proxy` | `EnvConfig` | `proxy.EnvConfig` (not `ProxyEnvConfig`) |

---

## 4. Component Interaction Flows

### 4.1 Initialization Flow

```
Caller                    agentbox.NewManager()              platform.Detect()
  │                            │                                │
  │  NewManager(cfg, opts...)  │                                │
  │───────────────────────────▶│                                │
  │                            │  1. cfg.Validate()             │
  │                            │  2. Deep-copy config slices    │
  │                            │  3. Normalize relative paths   │
  │                            │  4. Fill defaults (Classifier, │
  │                            │     Shell, MaxOutputBytes,     │
  │                            │     ResourceLimits)            │
  │                            │  5. Check shell exists on disk │
  │                            │  6. Apply ManagerOptions       │
  │                            │                                │
  │                            │  7. Detect platform            │
  │                            │───────────────────────────────▶│
  │                            │                                │  runtime.GOOS
  │                            │◀───────────────────────────────│  → Platform instance
  │                            │                                │
  │                            │  8. platform.Available()       │
  │                            │     [unavailable + Strict      │
  │                            │      → return ErrUnsupported]  │
  │                            │     [unavailable + Warn        │
  │                            │      → return NopManager]      │
  │                            │                                │
  │                            │  9. Start proxy (if Filtered)  │
  │                            │     NewDomainFilter(filterCfg) │
  │                            │     proxy.NewServer(proxyCfg)  │
  │                            │     ps.Start(ctx)              │
  │                            │     → httpPort, socksPort      │
  │                            │                                │
  │  ◀── Manager, nil          │                                │
  │      (or error)            │                                │
```

### 4.2 Command Execution Flow (Wrap Mode)

> **Wrap modifies the passed `*exec.Cmd` in-place** (injects `SysProcAttr`, `Env`, `Path`/`Args`, etc.).
> Does not return a new cmd. The caller uses the same cmd after `Wrap` returns.

```
Caller                  Manager.Wrap()           Classifier       ApprovalCB       Platform            Proxy
  │                        │                       │                │                │                  │
  │  Wrap(ctx, cmd, opts)  │                       │                │                │                  │
  │───────────────────────▶│                       │                │                │                  │
  │                        │                       │                │                │                  │
  │                        │  0. Check Manager state                │                │                  │
  │                        │     [closed → return ErrManagerClosed]  │                │                  │
  │                        │                       │                │                │                  │
  │                        │  1. Snapshot config (RLock)             │                │                  │
  │                        │  2. Merge per-call Options              │                │                  │
  │                        │                       │                │                │                  │
  │                        │  3. Classify command   │                │                │                  │
  │                        │──────────────────────▶│                │                │                  │
  │                        │  ◀── ClassifyResult   │                │                │                  │
  │                        │       (Decision +     │                │                │                  │
  │                        │        Reason + Rule) │                │                │                  │
  │                        │                       │                │                │                  │
  │                        │  [Forbidden → return ErrForbiddenCommand]               │                  │
  │                        │                       │                │                │                  │
  │                        │  [Escalated]:          │                │                │                  │
  │                        │    Check session cache │                │                │                  │
  │                        │    [cached → continue] │                │                │                  │
  │                        │    No ApprovalCallback?│                │                │                  │
  │                        │    → return ErrEscalatedCommand         │                │                  │
  │                        │    Has ApprovalCallback:│                │                │                  │
  │                        │──────────────────────────────────────▶│                │                  │
  │                        │    ◀── Approve / Deny / ApproveSession │                │                  │
  │                        │    [Deny → return ErrEscalatedCommand] │                │                  │
  │                        │    [ApproveSession → cache command]    │                │                  │
  │                        │    [Approve → continue]│                │                │                  │
  │                        │                       │                │                │                  │
  │                        │  [Allow → skip classification, still sandbox]           │                  │
  │                        │  [Sandboxed → proceed to sandbox]      │                │                  │
  │                        │                       │                │                │                  │
  │                        │  4. Build WrapConfig from snapshot + options             │                  │
  │                        │                       │                │                │                  │
  │                        │  5. Apply per-call env │                │                │                  │
  │                        │  6. Inject proxy env vars (if proxy active)             │                  │
  │                        │                       │                │                │                  │
  │                        │  7. Platform.WrapCommand(ctx, cmd, wcfg)│                │                  │
  │                        │──────────────────────────────────────────────────────▶│                  │
  │                        │                       │                │                │                  │
  │                        │                       │                │   macOS:       │                  │
  │                        │                       │                │   buildProfile(wcfg)              │
  │                        │                       │                │   → Rewrite cmd:│                  │
  │                        │                       │                │     Path=sandbox-exec             │
  │                        │                       │                │     Args=[-p <profile>            │
  │                        │                       │                │       -- origPath origArgs]       │
  │                        │                       │                │                │                  │
  │                        │                       │                │   Linux:       │                  │
  │                        │                       │                │   cmd.SysProcAttr                 │
  │                        │                       │                │   = &SysProcAttr{                 │
  │                        │                       │                │     Cloneflags:│                  │
  │                        │                       │                │     NEWNET|NEWPID                 │
  │                        │                       │                │   }            │                  │
  │                        │                       │                │   + Landlock rules                │
  │                        │                       │                │                │                  │
  │                        │  ◀── (cmd modified in-place)           │                │                  │
  │                        │                       │                │                │                  │
  │  ◀── nil (or error)    │                       │                │                │                  │
  │                        │                       │                │                │                  │
  │  cmd.Run() / Start()   │                       │                │                │                  │
  │  (caller uses same cmd)│                       │                │                │                  │
```

### 4.3 Command Execution Flow (Exec Mode)

Exec mode wraps the Wrap flow: internally builds `exec.Cmd`, classifies, wraps, executes, and collects results.

```
Exec(ctx, "ls -la")                          // ⚠️ Via sh -c, injection risk
  → Snapshot config (check closed → ErrManagerClosed)
  → Merge per-call Options
  → Apply per-call timeout (if WithTimeout used)
  → Classifier.Classify("ls -la")            // Classifier uses raw command string
  → handleDecision:
      [Forbidden → return ErrForbiddenCommand]
      [Escalated → check cache → ApprovalCallback → approve/deny]
  → exec.CommandContext(ctx, shell, "-c", "ls -la")
  → Apply working dir (if WithWorkingDir used)
  → runCommand:
      → buildWrapConfig(snapshot, callOptions)
      → Apply per-call env
      → Inject proxy env vars
      → platform.WrapCommand(ctx, cmd, wcfg)
      → cmd.Run() + capture stdout/stderr (limited by MaxOutputBytes)
      → Collect violations (macOS)
      → Return *ExecResult (with Truncated flag)

ExecArgs(ctx, "ls", []string{"-la"})         // ✅ No shell, no injection risk
  → Snapshot config (check closed → ErrManagerClosed)
  → Merge per-call Options
  → Apply per-call timeout (if WithTimeout used)
  → Classifier.ClassifyArgs("ls", []string{"-la"})
  → handleDecision (same as above)
  → exec.CommandContext(ctx, "ls", "-la")     // Direct execve, no shell
  → Apply working dir (if WithWorkingDir used)
  → runCommand (same as above)
```

### 4.4 Check Flow (Dry-Run Classification)

```
Manager.Check(ctx, "rm -rf /")
  → Snapshot config (check closed → ErrManagerClosed)
  → Classifier.Classify("rm -rf /")
  → Return ClassifyResult{Decision: Forbidden, Reason: "...", Rule: "..."}
  // No execution, no sandbox wrapping
```

### 4.5 UpdateConfig Flow (Hot-Reload)

```
Manager.UpdateConfig(newCfg)
  → Validate newCfg
  → Acquire write lock
  → Check closed → ErrManagerClosed
  → Deep-copy slices
  → Normalize relative paths
  → Hot-reload proxy filter rules (if domains changed):
      proxyFilter.UpdateRules(denied, allowed)
  → Update classifier (if non-nil)
  → Update filesystem, network, shell (check exists), MaxOutputBytes, ResourceLimits
  → Release write lock
```

### 4.6 Cleanup Flow

```
Caller                  Manager.Cleanup()         Proxy              Platform
  │                        │                       │                   │
  │  Cleanup(ctx)          │                       │                   │
  │───────────────────────▶│                       │                   │
  │                        │  1. Acquire lock       │                   │
  │                        │  2. Mark closed        │                   │
  │                        │     (subsequent calls  │                   │
  │                        │      return            │                   │
  │                        │      ErrManagerClosed) │                   │
  │                        │                       │                   │
  │                        │  3. Stop proxy         │                   │
  │                        │──────────────────────▶│                   │
  │                        │     proxy.Close()     │                   │
  │                        │     (5s timeout)      │                   │
  │                        │  ◀── done             │                   │
  │                        │                       │                   │
  │                        │  4. Platform cleanup   │                   │
  │                        │──────────────────────────────────────────▶│
  │                        │     platform.Cleanup() │                  │
  │                        │  ◀── done             │                   │
  │                        │                       │                   │
  │  ◀── nil (or error)    │                       │                   │
```

---

*Previous: [01a-overview-api.md](./01a-overview-api.md) — Project overview, core API design*
*Continue reading: [01c-config-classifier.md](./01c-config-classifier.md) — Configuration system, command classifier, platform abstraction*
*See also: [01d-integration.md](./01d-integration.md) — Network proxy architecture, comparison, security model, examples*
