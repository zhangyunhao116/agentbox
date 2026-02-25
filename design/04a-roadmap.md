# agentbox Implementation Roadmap

> **Status**: Completed (all 6 phases implemented)  
> **Date**: 2026-02-16  
> **Scope**: agentbox standalone Go sandbox library — phased implementation plan, risk assessment & release strategy  
> **Target**: Single binary, zero external runtime dependencies (except macOS sandbox-exec)  
> **Related**: Testing strategy in [04b-testing.md](./04b-testing.md)

---

## Table of Contents

1. [Implementation Roadmap](#1-implementation-roadmap)
2. [Risk Assessment](#2-risk-assessment)
3. [Dependency Management](#3-dependency-management)
4. [Release Strategy](#4-release-strategy)

---

## 1. Implementation Roadmap

All 6 phases are **complete**. The project has 76 Go files, ~25,000 lines of code, 743 test functions, and coverage ranging from 95.9% (proxy) to 100% (internal packages).

### Phase 1: Core Framework ✅

**Deliverables** (all implemented):

| File/Package | Description |
|-------------|-------------|
| `sandbox.go` | `Manager` interface: `Wrap`, `Exec`, `ExecArgs`, `Cleanup`, `Available`, `CheckDependencies`, `UpdateConfig`, `Check` |
| `config.go` | `Config` struct + `Validate()` + `DefaultConfig()`, `DevelopmentConfig()`, `CIConfig()` |
| `option.go` | `Option` type + `With*` functions, `ManagerOption` + `WithApprovalCallback` |
| `nop.go` | `NopManager` pass-through implementation |
| `classifier.go` | `Classifier` interface + `Decision` enum |
| `classifier_rules.go` | Built-in classification rules |
| `errors.go` | Sentinel errors |
| `result.go` | `ExecResult`, `Violation`, `ViolationType` |
| `manager.go` | Core `Manager` implementation |
| `reexec.go` | Re-exec bootstrap entry (`MaybeSandboxInit`) |
| `platform/` | Platform interface + `Detect()` |

**Key API signatures**:

```go
// Manager interface (sandbox.go)
type Manager interface {
    Wrap(ctx context.Context, cmd *exec.Cmd, opts ...Option) error
    Exec(ctx context.Context, command string, opts ...Option) (*ExecResult, error)
    ExecArgs(ctx context.Context, name string, args []string, opts ...Option) (*ExecResult, error)
    Cleanup(ctx context.Context) error
    Available() bool
    CheckDependencies() *platform.DependencyCheck
    UpdateConfig(cfg *Config) error
    Check(ctx context.Context, command string) (ClassifyResult, error)
}

// Constructor
func NewManager(cfg *Config, opts ...ManagerOption) (Manager, error)

// Convenience functions
func Wrap(ctx context.Context, cmd *exec.Cmd, opts ...Option) (cleanup func(), err error)
func Exec(ctx context.Context, command string, opts ...Option) (*ExecResult, error)
func ExecArgs(ctx context.Context, name string, args []string, opts ...Option) (*ExecResult, error)
func Check(ctx context.Context, command string, opts ...Option) (ClassifyResult, error)

// Decision enum: Sandboxed=0 (iota), Allow=1, Escalated=2, Forbidden=3
// ApprovalDecision enum: Approve=0, Deny=1, ApproveSession=2
// DefaultConfig() returns *Config (no error)
```

**Options**:
- `WithWritableRoots(roots ...string) Option`
- `WithNetwork(cfg *NetworkConfig) Option`
- `WithEnv(env ...string) Option`
- `WithShell(shell string) Option`
- `WithClassifier(c Classifier) Option`
- `WithWorkingDir(dir string) Option`
- `WithTimeout(d time.Duration) Option`
- `WithDenyRead(paths ...string) Option`
- `WithDenyWrite(paths ...string) Option`
- `WithApprovalCallback(cb ApprovalCallback) ManagerOption`

**Error types**: `ErrForbiddenCommand`, `ErrEscalatedCommand`, `ErrUnsupportedPlatform`, `ErrDependencyMissing`, `ErrManagerClosed`, `ErrConfigInvalid`, `ErrProxyStartFailed`

---

### Phase 2: macOS Seatbelt ✅

**Deliverables** (all implemented):

| File/Package | Description |
|-------------|-------------|
| `platform/darwin/seatbelt.go` | `Platform` implementation |
| `platform/darwin/profile.go` | `profileBuilder` (unexported) — SBPL profile generation |
| `platform/darwin/monitor.go` | `violationEvent` (unexported) — stub for future monitoring |
| `platform/darwin/harden.go` | `hardenProcess` (function variable for testability) |

**Key implementation details**:
- `profileBuilder` is unexported (was `ProfileBuilder` in design)
- `hardenProcess` is a function variable (not a method) for testability
- `canonicalizePath` handles `/tmp` → `/private/tmp` and `/var` → `/private/var`
- `sanitizeEnv` removes `DYLD_*` and `LD_*` via `envutil.RemoveEnvPrefix`

---

### Phase 3: Linux Namespace + Landlock ✅

**Deliverables** (all implemented, build-tag gated):

| File/Package | Description |
|-------------|-------------|
| `platform/linux/linux.go` | `Platform` implementation |
| `platform/linux/namespace.go` | Namespace creation |
| `platform/linux/landlock.go` | Landlock rules |
| `platform/linux/seccomp.go` | Seccomp BPF |
| `platform/linux/detect.go` | Kernel version detection |
| `platform/linux/reexec.go` | Re-exec mode |
| `platform/linux/bridge.go` | Network bridge integration |

---

### Phase 4: Network Proxy ✅

**Deliverables** (all implemented):

| File/Package | Description |
|-------------|-------------|
| `proxy/proxy.go` | `Proxy` interface, `Config`, `Server`, `NewServer` |
| `proxy/http.go` | `HTTPConfig`, `HTTPProxy`, `NewHTTPProxy` |
| `proxy/socks5.go` | `SOCKS5Config`, `SOCKS5Proxy`, `NewSOCKS5Proxy` |
| `proxy/filter.go` | `FilterFunc`, `OnRequest`, `FilterConfig`, `DomainFilter`, `ValidateDomainPattern`, `isBlockedIP` |
| `proxy/bridge.go` | `BridgeConfig`, `Bridge`, `BridgePair`, `NewBridgePair` |
| `proxy/env.go` | `EnvConfig`, `GenerateProxyEnv` |
| `proxy/internal/socks5/` | Self-implemented minimal SOCKS5 server |

**Key renames from design**:
- `ProxyServer` → `Server`
- `ProxyConfig` → `Config`
- `NewProxyServer` → `NewServer`
- `HTTPProxyConfig` → `HTTPConfig`
- `SOCKS5ProxyConfig` → `SOCKS5Config`
- `DomainFilterConfig` → `FilterConfig`
- `ProxyEnvConfig` → `EnvConfig`

---

### Phase 5: Polish ✅

**Deliverables** (all implemented):

| File/Package | Description |
|-------------|-------------|
| `README.md` | Project documentation |
| `examples/` | Usage examples |

---

### Phase 6: Advanced Features ✅

All advanced features are implemented:

- **Dynamic config update**: `Manager.UpdateConfig(cfg *Config) error`
- **Approval callback**: `WithApprovalCallback(cb ApprovalCallback) ManagerOption`
- **Process hardening**: `hardenProcess` (function variable) — `PT_DENY_ATTACH`, `RLIMIT_CORE=0`, env sanitization
- **Preset configs**: `DevelopmentConfig()`, `CIConfig()`
- **Check without execute**: `Manager.Check(ctx, command) (ClassifyResult, error)`

---

## 2. Risk Assessment

### 2.1 macOS sandbox-exec Deprecated Risk

| Dimension | Assessment |
|-----------|-----------|
| **Current status** | Apple marked as deprecated but not removed; macOS 15 (Sequoia) still functional |
| **Impact** | All macOS users |
| **Probability** | Medium (2-3 years) |
| **Mitigation** | 1) Monitor macOS releases; 2) Prepare App Sandbox alternative; 3) Degrade to NopManager with `FallbackWarn` |

### 2.2 Linux Kernel Version Fragmentation

| Dimension | Assessment |
|-----------|-----------|
| **Current status** | Landlock requires kernel 5.13+, ABI V1-V4 have different capabilities |
| **Impact** | Older Linux distributions |
| **Probability** | High (enterprise environments) |
| **Mitigation** | 1) `BestEffort` degradation; 2) Namespace + Seccomp without Landlock; 3) Fail-closed by default |

### 2.3 Proxy Environment Variable Bypass

| Dimension | Assessment |
|-----------|-----------|
| **Current status** | Some tools ignore `HTTP_PROXY` |
| **Impact** | Users of non-compliant tools |
| **Probability** | Medium |
| **Mitigation** | 1) Linux: Net Namespace makes proxy the only exit; 2) macOS: SBPL `(deny network*)` blocks direct connections |

---

## 3. Dependency Management

### 3.1 Current Dependencies

The project has **minimal** external dependencies:

```
module github.com/zhangyunhao116/agentbox

go 1.24.0

require golang.org/x/net v0.50.0
```

**Key changes from original design**:
- `golang.org/x/net` — used only in test files (`proxy/proxy_test.go`, `proxy/socks5_test.go`) as a SOCKS5 client for integration testing
- No `go-landlock` or `go-seccomp-bpf` in current go.mod (Linux features use build tags)

### 3.2 Dependency Principles

| Principle | Implementation |
|-----------|---------------|
| Standard library first | HTTP proxy uses `net/http`, not `goproxy` |
| Internal implementation | SOCKS5 is self-implemented in `proxy/internal/socks5/` |
| Zero CGO | All dependencies are pure Go |
| Single binary | No external runtime dependencies (except macOS `sandbox-exec`) |

---

## 4. Release Strategy

### 4.1 Semantic Versioning

```
v0.x.y — Development stage (API may change)
v1.0.0 — First stable release (all phases complete)
```

### 4.2 Current Stats

| Metric | Value |
|--------|-------|
| Go files | 76 |
| Lines of code | ~25,000 |
| Test functions | 743 |
| Root package coverage | 98.6% |
| Platform (darwin) coverage | 99.0% |
| Proxy coverage | 95.9% |
| Internal packages | 100% |

### 4.3 Security Update Process

```
1. Security report → zhangyunhao116@gmail.com (or GitHub Security Advisory)
2. 72-hour acknowledgment and severity assessment
3. Develop fix (private branch)
4. Release security update (patch version)
5. Publish advisory (CVE if applicable)
```

| Severity | Definition | Response Time | Example |
|----------|-----------|--------------|---------|
| Critical | Sandbox escape | 24 hours | Symlink bypass → arbitrary file write |
| High | Partial bypass | 72 hours | Specific command pattern bypasses classifier |
| Medium | Information leak | 1 week | Error message leaks file paths |
| Low | Non-security bug | 2 weeks | Performance regression |
