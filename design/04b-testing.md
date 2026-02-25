# agentbox Testing Strategy

> **Status**: Implemented  
> **Date**: 2026-02-16  
> **Scope**: agentbox testing strategy, coverage analysis, CI configuration  
> **Related**: Implementation roadmap in [04a-roadmap.md](./04a-roadmap.md)

---

## Table of Contents

1. [Testing Strategy](#1-testing-strategy)
2. [Coverage Results](#2-coverage-results)
3. [Test Infrastructure](#3-test-infrastructure)
4. [Linting & Static Analysis](#4-linting--static-analysis)

---

## 1. Testing Strategy

### 1.1 Test Pyramid

```
                    ┌─────────────┐
                    │   E2E Tests  │  10%
                    │  (scenario)  │
                ┌───┴─────────────┴───┐
                │   Integration Tests  │  30%
                │  (sandbox/net/FS)    │
            ┌───┴─────────────────────┴───┐
            │        Unit Tests            │  60%
            │  (config/domain/classify)    │
            └─────────────────────────────┘
```

### 1.2 Test Files

| Package | Test Files | Key Scenarios |
|---------|-----------|---------------|
| Root (`agentbox`) | `config_test.go`, `classifier_test.go`, `manager_test.go`, `sandbox_test.go`, `option_test.go`, `nop_test.go`, `errors_test.go`, `result_test.go`, `reexec_test.go` | Config validation, command classification, manager lifecycle, option application, NopManager pass-through, error types, result types |
| `proxy` | `proxy_test.go`, `http_test.go`, `socks5_test.go`, `filter_test.go`, `env_test.go`, `bridge_test.go` | Server lifecycle, HTTP forwarding/CONNECT, SOCKS5 proxying, domain filtering, env generation, bridge forwarding |
| `proxy/internal/socks5` | `socks5_test.go` | SOCKS5 protocol handling, CONNECT command, auth negotiation |
| `platform` | `platform_test.go`, `detect_darwin_test.go` | Platform detection, capability checks |
| `platform/darwin` | `profile_test.go`, `seatbelt_test.go`, `harden_test.go` | SBPL profile generation, seatbelt wrapping, process hardening |
| `platform/linux` | `linux_test.go`, `detect_test.go` | Linux platform, kernel detection |
| `internal/envutil` | `envutil_test.go` | Environment variable manipulation |

### 1.3 Test Matrix

#### Filesystem Tests

| Scenario | macOS (Seatbelt) | Linux (Landlock) | Method |
|----------|:---:|:---:|--------|
| Read allowed path | ✅ | ✅ | `cat /etc/hostname` succeeds |
| Read denied path | ✅ | ✅ | `cat ~/.ssh/id_rsa` fails (EPERM) |
| Write allowed path | ✅ | ✅ | `echo test > $ALLOWED/file.txt` succeeds |
| Write denied path | ✅ | ✅ | `echo test > /etc/passwd` fails |
| Write dangerous file | ✅ | ✅ | `echo test > $CWD/.bashrc` fails (even if CWD is writable) |
| .git/hooks protection | ✅ | ✅ | `echo evil > .git/hooks/pre-commit` fails |
| Temp directory writable | ✅ | ✅ | `echo test > /tmp/sandbox-test` succeeds |

#### Network Tests

| Scenario | Expected | Method |
|----------|----------|--------|
| Allowed domain HTTP | 200 OK | `curl http://example.com` |
| Allowed domain HTTPS | 200 OK | `curl https://example.com` |
| Denied domain | 403/connection refused | `curl https://evil.com` → blocked |
| Wildcard match | Correct | `*.github.com` matches `api.github.com` |
| Wildcard no bare match | Denied | `*.github.com` does NOT match `github.com` |
| IP address direct | Denied | `curl http://1.2.3.4` → blocked |
| DNS proxy-side | Correct | `socks5h://` ensures proxy resolves |
| Deny > allow priority | Denied | Domain in both lists → denied |
| Dynamic rule update | Immediate | `UpdateRules()` takes effect immediately |
| Blocked IP (loopback) | Denied | Connection to 127.0.0.1 blocked |
| Blocked IP (RFC1918) | Denied | Connection to 10.x.x.x blocked |
| Cloud metadata IP | Denied | Connection to 169.254.169.254 blocked |

#### Security Tests

| Scenario | Expected | Method |
|----------|----------|--------|
| `rm -rf /` | Forbidden | Classifier intercepts |
| `curl \| bash` | Forbidden | Classifier intercepts pipe pattern |
| Reverse shell | Forbidden | `bash -i >& /dev/tcp/...` intercepted |
| Fork bomb | Forbidden | `:(){ :\|:& };:` intercepted |
| Env sanitization | Stripped | `DYLD_*`, `LD_*` removed from env |

---

## 2. Coverage Results

### 2.1 Actual Coverage by Package

| Package | Coverage | Tests |
|---------|----------|-------|
| `agentbox` (root) | **98.6%** | config, classifier, manager, sandbox, option, nop, errors, result, reexec |
| `internal/envutil` | **100.0%** | env var manipulation |
| `platform` | **100.0%** | platform detection |
| `platform/darwin` | **99.0%** | profile generation, seatbelt, hardening |
| `proxy` | **95.9%** | HTTP proxy, SOCKS5 proxy, filter, bridge, env |
| `proxy/internal/socks5` | **100.0%** | SOCKS5 protocol implementation |

**Total test functions**: 743

### 2.2 Coverage Targets vs Actuals

| Package | Target | Actual | Status |
|---------|--------|--------|--------|
| Root | 95%+ | 98.6% | ✅ Exceeded |
| Platform | 95%+ | 99.0-100% | ✅ Exceeded |
| Proxy | 95%+ | 95.9% | ✅ Met |
| Internal | 100% | 100% | ✅ Met |

---

## 3. Test Infrastructure

### 3.1 Test Patterns

**Function variable injection**: Key functions like `hardenProcess` and `buildProfile` are function variables, allowing tests to inject mocks without interfaces.

**`httptest.Server`**: Used extensively in proxy tests to simulate upstream servers.

**`t.TempDir()`**: Used for filesystem tests with automatic cleanup.

**Build tags**: Platform-specific tests use `//go:build darwin` or `//go:build linux` to run only on the appropriate platform.

### 3.2 Mock Strategies

**DNS resolver mock**: `HTTPProxy.resolver` field can be overridden for testing DNS resolution behavior without real DNS queries.

**Dial function mock**: `SOCKS5Config.Dial` accepts a custom dial function, and `HTTPProxy.dialFunc` is a function field — both allow injecting test dialers.

### 3.3 Platform-Conditional Testing

Tests that require specific platform features use skip helpers:

```go
func skipIfNotDarwin(t *testing.T) {
    t.Helper()
    if runtime.GOOS != "darwin" {
        t.Skip("Skipping: requires macOS")
    }
}
```

Platform-specific test files use build tags:
- `platform/darwin/*_test.go` — `//go:build darwin`
- `platform/linux/*_test.go` — `//go:build linux`

---

## 4. Linting & Static Analysis

### 4.1 golangci-lint Configuration

The project uses golangci-lint v2 with **56+ linters** enabled across three categories:

**Bug detection linters**:
- `bodyclose`, `durationcheck`, `errcheck`, `errchkjson`, `errorlint`
- `govet`, `ineffassign`, `makezero`, `nilerr`, `staticcheck`, `unused`

**Style & best practices linters**:
- `copyloopvar`, `dupword`, `goconst`, `gocritic`, `gosec`
- `misspell`, `nakedret`, `perfsprint`, `prealloc`, `revive`
- `unconvert`, `unparam`, `usestdlibvars`, `whitespace`

**Code quality linters**:
- `gocyclo`, `nestif`

### 4.2 CI Quality Gates

| Check | Tool | Threshold |
|-------|------|-----------|
| Unit tests | `go test -race -coverprofile` | All pass |
| Coverage | `go tool cover` | ≥ 95% per package |
| Lint | `golangci-lint run` | Zero warnings |
| Vet | `go vet ./...` | Zero warnings |
| Vulnerability | `govulncheck ./...` | Zero vulnerabilities |

### 4.3 Test Execution

```bash
# Run all tests with race detection and coverage
go test -race -coverprofile=coverage.out ./...

# View coverage summary
go tool cover -func=coverage.out

# Run specific package tests
go test -v ./proxy/...

# Run with timeout (proxy tests may take longer due to network operations)
go test -timeout 60s ./proxy/...
```

---

## Appendix: Reference Implementation Comparison

| sandbox-runtime (TypeScript) | agentbox (Go) | Notes |
|------------------------------|---------------|-------|
| `SandboxManager.initialize()` | `NewManager(cfg *Config, opts ...ManagerOption) (Manager, error)` | Constructor pattern |
| `SandboxManager.wrapWithSandbox()` | `Manager.Wrap()` | Core API |
| `SandboxManager.reset()` | `Manager.Cleanup(ctx)` | Resource cleanup |
| `SandboxRuntimeConfigSchema` (Zod) | `Config` + `Validate()` | Struct + validation |
| `wrapCommandWithSandboxMacOS()` | `darwin.Platform.WrapCommand()` | macOS implementation |
| `wrapCommandWithSandboxLinux()` | `linux.Platform.WrapCommand()` | Linux implementation |
| `macGetMandatoryDenyPatterns()` | `writeDangerousFileProtection()` | Dangerous file list |
| `isSymlinkOutsideBoundary()` | `canonicalizePath()` | Path normalization |
| `SandboxManager.updateConfig()` | `Manager.UpdateConfig()` | Dynamic config update |
| N/A | `Manager.Check()` | Classify without executing |
| N/A | `DevelopmentConfig()`, `CIConfig()` | Preset configurations |
