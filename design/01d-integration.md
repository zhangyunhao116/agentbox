# agentbox Architecture Design — Integration & Security

> Series: [01a](01a-overview-api.md) | [01b](01b-structure-flow.md) | [01c](01c-config-classifier.md) | [01d](01d-integration.md)

> **Status**: Implemented
> **Date**: 2026-02-16
> **Scope**: agentbox — Process-level sandbox library for the Go ecosystem
> **Split note**: This document covers the network proxy architecture, comparison with sandbox-runtime, security model, and usage examples.
>   For project overview and core API design, see [01a-overview-api.md](./01a-overview-api.md).
>   For package structure and component interaction flow, see [01b-structure-flow.md](./01b-structure-flow.md).
>   For configuration system, command classifier, and platform abstraction, see [01c-config-classifier.md](./01c-config-classifier.md).

---

## 8. Network Proxy Architecture

### 8.1 Proxy Types

All proxy types use non-stuttering names.

```go
package proxy

// Proxy is the interface for the combined proxy server.
type Proxy interface {
	Start(ctx context.Context) (httpPort, socksPort int, err error)
	Close() error
}

// Config configures the combined proxy server.
type Config struct {
	Filter *DomainFilter
	Logger *slog.Logger
}

// Server combines HTTP and SOCKS5 proxies into a single unit.
type Server struct { /* ... */ }

// NewServer creates a new Server with the given configuration.
func NewServer(cfg *Config) (*Server, error)

// HTTPConfig configures the HTTP proxy server.
type HTTPConfig struct {
	Filter             FilterFunc
	DialTimeout        time.Duration // default 10s
	IdleTimeout        time.Duration // default 60s
	MaxRequestBodySize int64         // default 10MB
	Logger             *slog.Logger
}

// SOCKS5Config configures the SOCKS5 proxy server.
type SOCKS5Config struct {
	Filter FilterFunc
	Logger *slog.Logger
	Dial   func(ctx context.Context, network, addr string) (net.Conn, error)
}

// FilterConfig configures the domain filter.
type FilterConfig struct {
	DeniedDomains  []string
	AllowedDomains []string
	OnRequest      OnRequest
}

// EnvConfig configures proxy environment variable generation.
type EnvConfig struct {
	HTTPProxyPort  int
	SOCKSProxyPort int
	TmpDir         string
}

// FilterFunc determines whether a connection to the given host:port is allowed.
type FilterFunc func(ctx context.Context, host string, port int) (bool, error)

// OnRequest is a callback for dynamic domain filtering decisions.
type OnRequest func(ctx context.Context, host string, port int) (bool, error)

// DomainFilter implements domain-based filtering with priority:
// denied > allowed > OnRequest > default deny.
type DomainFilter struct { /* ... */ }

func NewDomainFilter(cfg *FilterConfig) (*DomainFilter, error)
func (f *DomainFilter) Filter(ctx context.Context, host string, port int) (bool, error)
func (f *DomainFilter) UpdateRules(denied, allowed []string) error

// ValidateDomainPattern validates a domain pattern string (exported).
func ValidateDomainPattern(pattern string) error

// BridgePair manages HTTP and SOCKS5 bridges together (for Linux network namespace bridging).
type BridgePair struct { /* ... */ }
func NewBridgePair(socketDir string, httpAddr, socksAddr string, logger *slog.Logger) (*BridgePair, error)
func (bp *BridgePair) Start() error
func (bp *BridgePair) Shutdown(timeout time.Duration)
```

**Key implementation details:**
- SOCKS5 is self-implemented in `proxy/internal/socks5/`.
- `Server.Close()` applies a **5-second timeout** on shutdown to prevent indefinite blocking.
- `proxy.OnRequest` is a type alias for the callback function.

### 8.2 Traffic Path

**macOS:**
```
Sandbox process ──HTTP_PROXY=127.0.0.1:PORT──▶ Built-in HTTP proxy ──Filter──▶ Target server
Sandbox process ──ALL_PROXY=socks5h://...──────▶ Built-in SOCKS5 proxy ──Filter──▶ Target server
```

**Linux (network namespace isolation):**
```
Host: HTTP/SOCKS5 proxy ──▶ Unix socket
                              ↓ (bind mount into sandbox)
Sandbox (CLONE_NEWNET): re-exec helper ──▶ TCP:3128/1080 ──▶ User command
```

> **Note**: Linux network bridging is handled by the re-exec helper (see 01c §7.8),
> not by an external socat binary.

### 8.3 Domain Filter Priority

```
Request arrives → Check DeniedDomains → match → DENY
                    ↓ no match
               Check AllowedDomains → match → ALLOW
                    ↓ no match
               Call OnRequest callback → has callback → use return value
                    ↓ no callback
               Default DENY
```

### 8.4 Environment Variable Injection

When network filtering is enabled, the Manager automatically injects proxy environment variables into the sandboxed process:

| Variable | Value | Purpose |
|----------|-------|---------|
| `HTTP_PROXY` / `http_proxy` | `http://127.0.0.1:<port>` | HTTP proxy |
| `HTTPS_PROXY` / `https_proxy` | `http://127.0.0.1:<port>` | HTTPS proxy (CONNECT tunnel) |
| `FTP_PROXY` / `ftp_proxy` | `http://127.0.0.1:<port>` | FTP proxy |
| `ALL_PROXY` / `all_proxy` | `socks5h://127.0.0.1:<port>` | SOCKS5 proxy (proxy-side DNS) |
| `NO_PROXY` / `no_proxy` | `localhost,127.0.0.1,::1,*.local,10.0.0.0/8,...` | Bypass local addresses |
| `GIT_SSH_COMMAND` | `ssh -o ProxyCommand='nc -X 5 -x ...'` (macOS) | Git SSH via SOCKS proxy |
| `SANDBOX_RUNTIME` | `1` | Sandbox runtime marker |

**Platform-specific `GIT_SSH_COMMAND`:**
- macOS: Uses `nc` (netcat) with `-X 5 -x` for SOCKS proxy.
- Linux: Uses `ncat --proxy-type socks5 --proxy` for SOCKS proxy.

---

## 9. Comparison with sandbox-runtime

### 9.1 Architecture Differences

| Dimension | sandbox-runtime | agentbox |
|-----------|----------------|----------|
| **Language** | TypeScript (Node.js) | Go |
| **Manager model** | Singleton module (module-level state) | Multi-instance (`NewManager()` factory) |
| **API return** | `wrapWithSandbox() → string` | `Wrap() → error` (modifies cmd in-place) |
| **Config validation** | Zod Schema (runtime) | `Validate()` (pure) + compile-time types |
| **Linux isolation** | bubblewrap (external binary) | Go native `syscall.SysProcAttr` |
| **Network bridging** | socat (external binary) | Pure Go Unix socket bridging (re-exec helper) |
| **Proxy implementation** | Node.js `http`/`net` modules | Go `net/http` + internal SOCKS5 |
| **Concurrency safety** | Single-threaded (Node.js event loop) | `sync.Mutex` + goroutine safe |
| **Resource cleanup** | `process.on('exit')` | `defer m.Cleanup()` + `context.Context` |
| **Command classification** | No built-in classifier | Built-in `Classifier` + rule chain |
| **Resource limits** | None built-in | `ResourceLimits` (CPU/memory/processes/FD) |
| **Output limits** | None | `MaxOutputBytes` prevents OOM |

### 9.2 API Differences

| sandbox-runtime | agentbox | Notes |
|----------------|----------|-------|
| `SandboxManager.initialize(config)` | `agentbox.NewManager(config)` | Initialization |
| `SandboxManager.wrapWithSandbox(cmd) → string` | `m.Wrap(ctx, cmd) → error` (modifies cmd in-place) | Wrap command |
| `SandboxManager.reset()` | `m.Cleanup(ctx)` | Release resources |
| `SandboxManager.checkDependencies()` | `m.CheckDependencies()` | Dependency check |
| `SandboxManager.isSupportedPlatform()` | `m.Available()` | Platform support |
| `SandboxManager.updateConfig(cfg)` | `m.UpdateConfig(cfg)` | Hot-reload config |
| `SandboxManager.getConfig()` | N/A | No getter (config snapshots are internal) |
| N/A | `m.Exec(ctx, cmd) → *ExecResult` | Direct execution |
| N/A | `m.ExecArgs(ctx, name, args)` | Structured execution (no shell) |
| N/A | `m.Check(ctx, command)` | Classify without executing |
| N/A | `agentbox.Wrap(ctx, cmd, opts...)` | Convenience function |
| N/A | `agentbox.Exec(ctx, cmd, opts...)` | Convenience function |
| N/A | `agentbox.Check(ctx, cmd, opts...)` | Convenience function |
| N/A | `Classifier.Classify(cmd)` | Command classification |
| N/A | `Classifier.ClassifyArgs(name, args)` | Structured classification |

### 9.3 Feature Coverage Comparison

| Feature | sandbox-runtime | agentbox |
|---------|:-:|:-:|
| macOS Seatbelt (SBPL) | ✅ | ✅ |
| Linux bubblewrap | ✅ | ❌ (native namespaces instead) |
| Linux Namespaces | ❌ | ✅ |
| Linux Landlock | ❌ | ✅ |
| Linux seccomp | ✅ | ✅ |
| HTTP proxy | ✅ | ✅ |
| SOCKS5 proxy | ✅ | ✅ |
| Domain filtering | ✅ | ✅ |
| MITM proxy | ✅ | 🔮 v2 |
| Violation monitoring (macOS) | ✅ | ✅ |
| Violation monitoring (Linux) | — | ⚠️ Limited |
| Violation annotation (stderr) | ✅ | ✅ |
| Command classifier | ❌ | ✅ |
| Resource limits (CPU/memory/processes/FD) | ❌ | ✅ |
| Output size limits | ❌ | ✅ |
| Config file | ✅ (Control FD) | ✅ (YAML/JSON) |
| CLI tool | ✅ (`srt`) | ❌ (library-only) |
| WSL support | ✅ | 🔮 v2 |
| Windows support | ❌ | 🔮 v3 |
| Multi-instance Manager | ❌ (singleton) | ✅ |
| per-call Option | ✅ (`customConfig`) | ✅ (`Option` pattern) |
| Dynamic config update | ✅ (`updateConfig`) | ✅ (`UpdateConfig`) |

**Legend**: ✅ Supported | ❌ Not supported | 🔮 Future version

### 9.4 Design Philosophy Differences

| Aspect | sandbox-runtime | agentbox |
|--------|----------------|----------|
| **Mutability** | Mutable config (`updateConfig`) | Hot-reload via `UpdateConfig()` |
| **State management** | Module-level global state | Instance-level state (no global state) |
| **Error handling** | Exceptions + Promise rejection | Explicit `error` return values |
| **Extensibility** | Config-driven | Interface-driven (`Classifier`, `Platform`, `Filter`) |
| **External deps** | bubblewrap, socat, seccomp binary | Minimal external deps (pure Go + re-exec bootstrap) |

---

## 10. Security Model

### 10.1 Defense Layers

```
┌─────────────────────────────────────────────────────────────────┐
│                        Layer 1: Command Classification           │
│  Classifier → Sandboxed / Allow / Escalated / Forbidden          │
│  (Classify before execution: sandbox, allow, approve, forbid)    │
│  ⚠️ Allow and Sandboxed both execute in sandbox                  │
│  ⚠️ Escalated requires user approval, then executes in sandbox   │
├─────────────────────────────────────────────────────────────────┤
│                        Layer 2: Filesystem Isolation             │
│  macOS: SBPL deny default + allow subpath                        │
│  Linux: Landlock + Namespace (CLONE_NEWNS)                       │
│  (Write: allow-only, Read: deny-only)                            │
├─────────────────────────────────────────────────────────────────┤
│                        Layer 3: Network Isolation                │
│  macOS: SBPL deny network + proxy environment variables          │
│  Linux: CLONE_NEWNET + Unix socket bridging (re-exec helper)     │
│  (Domain-level filtering, deny takes priority)                   │
├─────────────────────────────────────────────────────────────────┤
│                        Layer 4: Process Isolation + Resource Limits│
│  Linux: CLONE_NEWPID (PID isolation) + setrlimit(2)              │
│  macOS: SBPL signal restriction (target self) + setrlimit(2)     │
│  (Prevents kill host processes, fork bomb, OOM, FD exhaustion)   │
├─────────────────────────────────────────────────────────────────┤
│                        Layer 5: Output Limits                    │
│  MaxOutputBytes limits stdout/stderr capture                     │
│  (Prevents malicious commands from causing host OOM)             │
└─────────────────────────────────────────────────────────────────┘
```

### 10.2 Security Principles

1. **Default deny**: File writes and network access are denied by default; must be explicitly allowed.
2. **Deny takes priority**: DenyWrite/DeniedDomains always override Allow rules.
3. **Least privilege**: Only grant the minimum permissions needed.
4. **Defense in depth**: Five layers; bypassing one still leaves others protecting.
5. **Graceful degradation**: Unsupported platforms return clear errors; no silent security bypass.
6. **Allow ≠ bypass sandbox**: The classifier's Allow decision only skips classification; all sandbox layers still apply.

### 10.3 Security Invariants

These invariants hold under all configurations:

| Invariant | Description |
|-----------|-------------|
| **All commands go through sandbox** | Whether Classifier returns Allow or Sandboxed, the command executes inside the sandbox |
| **Forbidden is absolute** | Classifier returns Forbidden → command never executes |
| **Escalated requires approval** | Classifier returns Escalated → must be approved before execution; approved commands still run in sandbox; no ApprovalCallback registered → default deny |
| **Deny overrides allow** | DenyWrite overrides WritableRoots; DeniedDomains overrides AllowedDomains |
| **No shell injection** | Platform.WrapCommand uses cmd.Path + cmd.Args directly, no shell string concatenation |
| **Resources are bounded** | ResourceLimits and MaxOutputBytes ensure sandbox processes cannot exhaust host resources |
| **Single-binary bootstrap** | Linux helper uses re-exec (os.Args[0]), no external binaries |

---

## Appendix A: Usage Examples

### A.1 Simplest Usage

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/zhangyunhao116/agentbox"
)

func main() {
	// DefaultConfig() returns *Config (no error).
	result, err := agentbox.Exec(
		context.Background(),
		"ls -la /tmp",
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(result.Stdout)
	if result.Truncated {
		fmt.Println("(output was truncated)")
	}
}
```

### A.2 Manager Lifecycle Management

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/zhangyunhao116/agentbox"
)

func main() {
	cfg := agentbox.DefaultConfig()
	cfg.Filesystem.WritableRoots = []string{"/workspace/myproject", "/tmp"}
	cfg.Network.AllowedDomains = []string{
		"github.com",
		"*.npmjs.org",
		"registry.yarnpkg.com",
	}
	cfg.MaxOutputBytes = 5 * 1024 * 1024 // 5MB
	cfg.ResourceLimits = &agentbox.ResourceLimits{
		MaxProcesses:       512,
		MaxMemoryBytes:     1 * 1024 * 1024 * 1024, // 1GB
		MaxFileDescriptors: 512,
		MaxCPUSeconds:      60,
	}

	mgr, err := agentbox.NewManager(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer mgr.Cleanup(context.Background())

	// Execute multiple commands, reusing the same Manager (proxy starts once).
	for _, cmd := range []string{"npm install", "npm test", "npm run build"} {
		result, err := mgr.Exec(context.Background(), cmd)
		if err != nil {
			log.Printf("command %q failed: %v", cmd, err)
			continue
		}
		fmt.Printf("[%s] exit=%d sandboxed=%v truncated=%v\n",
			cmd, result.ExitCode, result.Sandboxed, result.Truncated)
	}
}
```

### A.3 Wrap Mode (Integration with Existing Code)

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"

	"github.com/zhangyunhao116/agentbox"
)

func main() {
	ctx := context.Background()

	cfg := agentbox.DefaultConfig()
	mgr, err := agentbox.NewManager(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer mgr.Cleanup(ctx)

	// Build the original command, then wrap it for sandboxed execution.
	// Note: Wrap uses cmd.Path and cmd.Args directly, no shell string concatenation.
	cmd := exec.CommandContext(ctx, "python3", "untrusted_script.py")
	cmd.Dir = "/workspace/myproject"

	err = mgr.Wrap(ctx, cmd)
	if err != nil {
		log.Fatal(err)
	}
	output, err := cmd.CombinedOutput() // caller controls I/O
	if err != nil {
		log.Printf("command failed: %v", err)
	}
	fmt.Println(string(output))
}
```

### A.4 Package-Level Wrap Convenience Function

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"

	"github.com/zhangyunhao116/agentbox"
)

func main() {
	ctx := context.Background()

	cmd := exec.CommandContext(ctx, "node", "script.js")
	cmd.Dir = "/workspace"

	// Package-level Wrap uses DefaultConfig() internally.
	cleanup, err := agentbox.Wrap(ctx, cmd,
		agentbox.WithWritableRoots("/workspace", "/tmp"),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer cleanup()

	output, _ := cmd.CombinedOutput()
	fmt.Println(string(output))
}
```

### A.5 UpdateConfig (Hot-Reload)

```go
package main

import (
	"context"
	"log"

	"github.com/zhangyunhao116/agentbox"
)

func main() {
	cfg := agentbox.DefaultConfig()
	mgr, err := agentbox.NewManager(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer mgr.Cleanup(context.Background())

	// Later, update the config without recreating the manager.
	// Network filter rules and classifier are hot-reloaded.
	newCfg := agentbox.DefaultConfig()
	newCfg.Network.AllowedDomains = []string{"*.example.com"}
	if err := mgr.UpdateConfig(newCfg); err != nil {
		log.Fatal(err)
	}
}
```

### A.6 Check (Classify Without Executing)

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/zhangyunhao116/agentbox"
)

func main() {
	// Package-level Check: classify without executing.
	result, err := agentbox.Check(context.Background(), "rm -rf /")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Decision: %s, Reason: %s\n", result.Decision, result.Reason)
	// Output: Decision: forbidden, Reason: recursive deletion of root or home directory
}
```

### A.7 DevelopmentConfig and CIConfig

```go
package main

import (
	"context"
	"log"

	"github.com/zhangyunhao116/agentbox"
)

func main() {
	// Development: FallbackWarn + NetworkAllowed
	devMgr, err := agentbox.NewManager(agentbox.DevelopmentConfig())
	if err != nil {
		log.Fatal(err)
	}
	defer devMgr.Cleanup(context.Background())

	// CI/CD: FallbackStrict + NetworkBlocked
	ciMgr, err := agentbox.NewManager(agentbox.CIConfig())
	if err != nil {
		log.Fatal(err)
	}
	defer ciMgr.Cleanup(context.Background())
}
```

### A.8 Custom Classifier with ApprovalCallback

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/zhangyunhao116/agentbox"
)

func main() {
	cfg := agentbox.DefaultConfig()
	cfg.Classifier = agentbox.ChainClassifier(
		myProjectClassifier(),
		agentbox.DefaultClassifier(),
	)

	mgr, err := agentbox.NewManager(cfg,
		agentbox.WithApprovalCallback(func(ctx context.Context, req agentbox.ApprovalRequest) (agentbox.ApprovalDecision, error) {
			fmt.Printf("Command %q requires approval: %s\n", req.Command, req.Reason)
			// In a real app, prompt the user here.
			return agentbox.Approve, nil
		}),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer mgr.Cleanup(context.Background())

	// Escalated commands will trigger the approval callback.
	result, err := mgr.Exec(context.Background(), "docker build .")
	if err != nil {
		log.Printf("error: %v", err)
		return
	}
	fmt.Println(result.Stdout)
}

func myProjectClassifier() agentbox.Classifier {
	// Return a custom classifier implementation...
	return agentbox.DefaultClassifier()
}
```

---

*See also: [01a-overview-api.md](./01a-overview-api.md) — Project overview, core API design*
*See also: [01b-structure-flow.md](./01b-structure-flow.md) — Package structure, component interaction flow*
*See also: [01c-config-classifier.md](./01c-config-classifier.md) — Configuration system, command classifier, platform abstraction*
