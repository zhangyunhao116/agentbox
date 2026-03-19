# agentbox

Process-level sandbox isolation library for AI agents and CI/CD systems. Zero external runtime dependencies, no CGo, cross-platform (macOS, Linux, Windows via WSL2).

> **⚠️ Beta Notice**
>
> agentbox is currently in **beta**. The API may introduce **breaking changes** between minor versions until v1.0.
>
> | Component | Status |
> |-----------|--------|
> | **macOS (Seatbelt)** | ✅ Tested and stable |
> | **Linux (Namespace + Landlock)** | ✅ Tested (beta) |
> | **Windows (WSL2)** | ✅ Tested (beta) — see [design/06-windows-wsl-sandbox.md](./design/06-windows-wsl-sandbox.md) |
> | **Go API** | ⚠️ Beta — expect breaking changes before v1.0 |
>
> **Windows Support:** Windows support uses WSL2 (Windows Subsystem for Linux 2), providing two isolation tiers: Simple Mode (Hyper-V VM boundary) and Full Mode (Linux namespace sandbox inside WSL2). Requires Windows 10 Build 19041+ with WSL2 ≥ v2.5.10. See the [design document](./design/06-windows-wsl-sandbox.md) for details.

[![Go Reference](https://pkg.go.dev/badge/github.com/zhangyunhao116/agentbox.svg)](https://pkg.go.dev/github.com/zhangyunhao116/agentbox)

## Why agentbox?

AI agents execute commands on behalf of users — often untrusted, LLM-generated commands. Without isolation, a single malicious or hallucinated command can:

- **Exfiltrate data** — `curl` secrets to an external server, read `~/.ssh` or `~/.aws` credentials.
- **Compromise the system** — `rm -rf /`, overwrite system binaries, install rootkits.
- **Escape the workspace** — write outside the project directory, modify global configs.

agentbox wraps every command in a platform-native sandbox that enforces **filesystem isolation**, **network filtering**, and **command classification** — with a fail-closed, default-deny design:

- **Default deny** — writes are blocked everywhere unless explicitly allowed; network access requires an allowlist.
- **Defense in depth** — multiple independent layers (classifier → filesystem → network → process hardening) so no single bypass compromises the system.
- **Minimal trust** — even "safe" commands run inside the sandbox; classification only controls whether to block or prompt, never whether to sandbox.

## Quick Start

### Installation

```bash
go get github.com/zhangyunhao116/agentbox
```

### Exec (one-shot)

```go
result, err := agentbox.Exec(context.Background(), "echo hello")
if err != nil {
    log.Fatal(err)
}
fmt.Println(result.Stdout)
```

### Wrap (modify an existing exec.Cmd)

```go
cmd := exec.CommandContext(ctx, "ls", "-la", "/tmp")
cleanup, err := agentbox.Wrap(ctx, cmd)
if err != nil {
    log.Fatal(err)
}
defer cleanup()
output, _ := cmd.CombinedOutput()
```

### Check (classify without executing)

```go
result, err := agentbox.Check(ctx, "rm -rf /")
fmt.Println(result.Decision) // "forbidden"
```

### Manager (reusable, multi-command)

```go
cfg := agentbox.DefaultConfig()
mgr, err := agentbox.NewManager(cfg)
if err != nil {
    log.Fatal(err)
}
defer mgr.Cleanup(context.Background())

result, _ := mgr.Exec(ctx, "echo hello")
```

## How It Works

### Command Lifecycle

Every command passes through a multi-stage pipeline before execution:

```
Command ─→ Classifier ─┬→ Forbidden ───→ Blocked (ErrForbiddenCommand)
                        ├→ Escalated ───→ Approval Callback ─┬→ Denied → Blocked
                        │                                    └→ Approved ─→ Sandbox → Execute
                        ├→ Allow ───────→ Sandbox → Execute
                        └→ Sandboxed ──→ Sandbox → Execute
```

Note that **all permitted commands run inside the sandbox** — the classifier only decides whether to block or prompt, never whether to skip sandboxing. Even `ls` runs with filesystem and network restrictions applied.

### Command Classification

The built-in classifier evaluates commands against 13 ordered rules and assigns one of four decisions:

**Forbidden** — immediately blocked, never executed:

| Rule | Examples |
|------|----------|
| `fork-bomb` | `:(){ :\|:& };:` |
| `recursive-delete-root` | `rm -rf /`, `rm -rf ~`, `rm -rf $HOME` |
| `disk-wipe` | `dd of=/dev/sda`, `dd of=/dev/nvme0` |
| `reverse-shell` | `/dev/tcp/`, `nc -e /bin/sh`, python/perl socket shells |
| `chmod-recursive-root` | `chmod -R 777 /` |
| `chown-recursive-root` | `chown -R root:root /`, `chown -R user ~` |
| `filesystem-format` | `mkfs.ext4 /dev/sda`, `fdisk /dev/sda`, `parted`, `shred` |
| `curl-pipe-shell` | `curl ... \| sh`, `wget ... \| bash` |

**Allow** — safe to execute without prompting (still sandboxed):

| Rule | Examples |
|------|----------|
| `common-safe-commands` | `ls`, `cat`, `echo`, `pwd`, `grep`, `head`, `tail`, `wc`, `sort`, `stat`, `du`, `df` |
| `git-read-commands` | `git status`, `git log`, `git diff`, `git show`, `git branch` |

**Escalated** — requires user approval via the `ApprovalCallback`:

| Rule | Examples |
|------|----------|
| `global-install` | `npm install -g`, `pip install`, `yarn global add` |
| `docker-build` | `docker build`, `docker push`, `docker pull` |
| `system-package-install` | `brew install`, `apt install`, `yum install` |

**Sandboxed** — the default for any command that matches no rule. Executed inside the sandbox without prompting.

### Filesystem Isolation

The filesystem permission model follows a strict priority chain:

```
DenyRead > DenyWrite > WritableRoots > Default deny
```

**Default behavior**: read is allowed everywhere; write is denied everywhere. Then overrides are applied in priority order:

| Layer | Effect | Example |
|-------|--------|---------|
| **WritableRoots** | Allow writes to specific directories | `[]string{"/tmp", "./build"}` |
| **DenyWrite** | Block writes even if inside a WritableRoot (higher priority) | `$HOME`, `/etc`, `/usr`, `/bin`, `/sbin` |
| **DenyRead** | Block reads entirely — the process cannot see these paths | `~/.ssh`, `~/.aws`, `~/.gnupg`, etc. |

**Default denied paths** (applied by `DefaultConfig()`):

Write denied: `$HOME`, `/etc`, `/usr`, `/bin`, `/sbin`

Read denied: `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.git-credentials`, `~/.npmrc`, `~/.netrc`, `~/.docker`, `~/.pypirc`, `~/.kube`, `~/.config/gcloud`, `/proc/*/mem`, `/sys`

This means an agent can read source code and documentation anywhere on disk, but cannot write outside explicitly allowed directories, and cannot read credentials or secrets at all.

### Network Isolation

Network access is controlled by three modes:

| Mode | Behavior |
|------|----------|
| `NetworkFiltered` | Only allowed domains can be reached (default) |
| `NetworkBlocked` | All network access is denied |
| `NetworkAllowed` | Unrestricted network access |

In **Filtered** mode, a built-in HTTP/SOCKS5 proxy transparently intercepts all traffic. Domain resolution follows this priority chain:

```
Blocked IPs → DeniedDomains → AllowedDomains → OnRequest callback → Default deny
```

1. **Blocked IPs** — connections to private/internal IPs are always denied: loopback (`127.0.0.0/8`), RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`), multicast, CGNAT (`100.64.0.0/10`), and cloud metadata endpoints (`169.254.169.254`).
2. **DeniedDomains** — explicitly blocked domain patterns (e.g., `*.evil.com`).
3. **AllowedDomains** — explicitly permitted domain patterns. Supports wildcards: `*.golang.org` matches `proxy.golang.org`.
4. **OnRequest** — optional callback for dynamic decisions on domains not in either list.
5. **Default deny** — if nothing matches, the connection is refused.

```go
cfg := agentbox.DefaultConfig()
cfg.Network = agentbox.NetworkConfig{
    Mode:           agentbox.NetworkFiltered,
    AllowedDomains: []string{"*.golang.org", "github.com", "*.npmjs.org"},
    DeniedDomains:  []string{"*.evil.com"},
}
```

### Resource Limits

Sandboxed processes are constrained by configurable resource limits:

| Limit | Default | Description |
|-------|---------|-------------|
| `MaxProcesses` | `1024` | Maximum child processes |
| `MaxMemoryBytes` | `2 GB` | Maximum memory usage |
| `MaxFileDescriptors` | `1024` | Maximum open file descriptors |
| `MaxCPUSeconds` | `0` (unlimited) | Maximum CPU time |

### Process Hardening

Platform-specific hardening is applied automatically:

| Technique | macOS | Linux | Windows (WSL2) |
|-----------|-------|-------|----------------|
| Filesystem isolation | Seatbelt/SBPL profiles | User/Mount namespaces + Landlock | Hyper-V VM + Landlock (inside WSL2) |
| Network isolation | SBPL rules + Proxy | `CLONE_NEWNET` + Proxy | `CLONE_NEWNET` + Proxy (inside WSL2) |
| PID isolation | — | `CLONE_NEWPID` namespace | `CLONE_NEWPID` (inside WSL2) |
| Syscall filtering | — | Seccomp BPF | Seccomp BPF (inside WSL2) |
| Privilege escalation prevention | `PT_DENY_ATTACH` | `PR_SET_NO_NEW_PRIVS` | `PR_SET_NO_NEW_PRIVS` (inside WSL2) |
| Environment sanitization | `DYLD_*` variable removal | — | Windows env sanitization + WSL config |
| Core dump prevention | Yes | Yes | Yes |
| VM isolation | — | — | Hyper-V (WSL2) |

### Fallback Behavior

When the sandbox platform is unavailable (e.g., missing kernel features):

| Policy | Behavior |
|--------|----------|
| `FallbackStrict` (default) | Refuse to execute — returns `ErrUnsupportedPlatform`. Fail-closed. |
| `FallbackWarn` | Execute without sandboxing but log a warning. Use only in development. |

### Configuration Profiles

agentbox provides pre-built configuration profiles for common scenarios:

```go
// For local development — permissive: warns on missing sandbox, allows all network
cfg := agentbox.DevelopmentConfig()

// For CI/CD — strict: requires sandbox, blocks all network access
cfg := agentbox.CIConfig()

// Default — balanced: requires sandbox, filtered network
cfg := agentbox.DefaultConfig()
```

## Configuration

### Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Filesystem` | `FilesystemConfig` | Secure defaults | Filesystem access restrictions |
| `Network` | `NetworkConfig` | `NetworkFiltered` | Network access restrictions |
| `Classifier` | `Classifier` | `DefaultClassifier()` | Command classification strategy |
| `Shell` | `string` | System default | Shell path for command execution |
| `MaxOutputBytes` | `int` | `0` (unlimited) | Max captured stdout/stderr size |
| `ResourceLimits` | `*ResourceLimits` | `DefaultResourceLimits()` | Process resource constraints |
| `FallbackPolicy` | `FallbackPolicy` | `FallbackStrict` | Behavior when sandbox is unavailable |
| `Logger` | `*slog.Logger` | `slog.Default()` | Structured logger for operational messages |
| `ApprovalCallback` | `ApprovalCallback` | `nil` | Callback for escalated commands. If nil, escalated commands return `ErrEscalatedCommand`. |

### FilesystemConfig

| Field | Type | Description |
|-------|------|-------------|
| `WritableRoots` | `[]string` | Directories where write access is permitted |
| `DenyWrite` | `[]string` | Path patterns that must never be writable |
| `DenyRead` | `[]string` | Path patterns that must never be readable |
| `AllowGitConfig` | `bool` | Permit read access to `~/.gitconfig` and related files |
| `AutoProtectDangerousFiles` | `bool` | Auto-scan WritableRoots for dangerous files and deny writes |
| `DangerousFileScanDepth` | `int` | Max directory depth when scanning for dangerous files (default: 5) |

### NetworkConfig

| Field | Type | Description |
|-------|------|-------------|
| `Mode` | `NetworkMode` | `NetworkFiltered`, `NetworkBlocked`, or `NetworkAllowed` |
| `AllowedDomains` | `[]string` | Domain patterns permitted in Filtered mode |
| `DeniedDomains` | `[]string` | Domain patterns always blocked |
| `AllowLocalBinding` | `bool` | Permit sandboxed processes to bind to local ports (macOS only) |
| `AllowAllUnixSockets` | `bool` | Permit all Unix domain socket connections (macOS only) |
| `AllowUnixSockets` | `[]string` | Specific Unix socket paths that are permitted (macOS only) |
| `MITMProxy` | `*MITMProxyConfig` | Route specific domains through an upstream MITM proxy |
| `OnRequest` | `func(ctx, host, port) (bool, error)` | Optional callback for dynamic domain decisions |

### Per-Call Options

| Function | Description |
|----------|-------------|
| `WithWritableRoots(roots ...string)` | Add writable directories for a single call |
| `WithNetwork(cfg *NetworkConfig)` | Override network config for a single call |
| `WithEnv(env ...string)` | Add environment variables (`KEY=VALUE` format) |
| `WithShell(shell string)` | Override the shell for a single call |
| `WithClassifier(c Classifier)` | Override the classifier for a single call |
| `WithWorkingDir(dir string)` | Set working directory for a single call |
| `WithTimeout(d time.Duration)` | Set execution timeout for a single call |
| `WithDenyRead(paths ...string)` | Deny read access to paths for a single call |
| `WithDenyWrite(paths ...string)` | Deny write access to paths for a single call |
| `WithMaxOutputBytes(n int)` | Override max captured output size for a single call |

## API Reference

### Convenience Functions

| Function | Description |
|----------|-------------|
| `Exec(ctx, command, opts...)` | Create a temporary manager, execute, and clean up |
| `ExecArgs(ctx, name, args, opts...)` | Like `Exec` but with explicit program + args |
| `Wrap(ctx, cmd, opts...)` | Wrap an existing `*exec.Cmd` with sandbox isolation |
| `Check(ctx, command)` | Classify a command without executing it |

### ViolationType Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `ViolationFileRead` | `"file-read"` | Denied file read access |
| `ViolationFileWrite` | `"file-write"` | Denied file write access |
| `ViolationNetwork` | `"network"` | Denied network access |
| `ViolationProcess` | `"process"` | Denied process operation |
| `ViolationOther` | `"other"` | Other policy violation |

### Approval Callback

Handle commands classified as `Escalated` by setting `ApprovalCallback` on the `Config`:

```go
cfg := agentbox.DefaultConfig()
cfg.FallbackPolicy = agentbox.FallbackWarn
cfg.ApprovalCallback = func(ctx context.Context, req agentbox.ApprovalRequest) (agentbox.ApprovalDecision, error) {
    fmt.Printf("Command requires approval: %s\nReason: %s\n", req.Command, req.Reason)
    // In a real app, prompt the user here
    return agentbox.Approve, nil // or agentbox.Deny
}
mgr, err := agentbox.NewManager(cfg)
```

### Per-Call Overrides

Override settings for individual calls:

```go
result, err := mgr.Exec(ctx, "npm install",
    agentbox.WithWritableRoots("/tmp", "./node_modules"),
    agentbox.WithEnv("NODE_ENV=production"),
)
```

### Dynamic Config Update

Update the manager's configuration at runtime without recreating it:

```go
newCfg := agentbox.DefaultConfig()
newCfg.Network.AllowedDomains = []string{"*.example.com"}
mgr.UpdateConfig(newCfg)
```

### Error Types

| Error | Description |
|-------|-------------|
| `ErrUnsupportedPlatform` | Current OS/architecture is not supported |
| `ErrDependencyMissing` | Required system dependency is not available |
| `ErrForbiddenCommand` | Command was rejected by the classifier |
| `ErrEscalatedCommand` | Command requires user approval |
| `ErrManagerClosed` | Manager has been closed via `Cleanup` |
| `ErrConfigInvalid` | Configuration failed validation |
| `ErrProxyStartFailed` | Network proxy server could not be started |
| `ErrNilCommand` | A nil `*exec.Cmd` was passed to `Wrap` |
| `ForbiddenCommandError` | Returned when a command is rejected. Use `errors.As` to extract `Command` and `Reason` fields. Wraps `ErrForbiddenCommand`. |
| `EscalatedCommandError` | Returned when a command requires approval. Use `errors.As` to extract `Command` and `Reason` fields. Wraps `ErrEscalatedCommand`. |

#### Structured Error Extraction

Use `errors.As` to extract detailed information from structured errors:

```go
_, err := mgr.Exec(ctx, "some-command")
var fce *agentbox.ForbiddenCommandError
if errors.As(err, &fce) {
    log.Printf("Forbidden: command=%s reason=%s", fce.Command, fce.Reason)
}
```

### Dependency Checking

Use `CheckDependencies` to verify that all required system dependencies are available:

```go
check := mgr.CheckDependencies()
if !check.OK() {
    log.Printf("Missing dependencies: %v", check.Errors)
}
```

`DependencyCheck` is a type alias for the platform-specific dependency check result. It exposes an `OK()` method and an `Errors` field listing any missing dependencies.

## Performance

Benchmarks comparing agentbox against other sandbox solutions for executing simple shell commands (`echo hello` and `go version`). All measurements use [hyperfine](https://github.com/sharkdp/hyperfine) for cold-start and hot-start latency, plus native batch execution for sustained throughput.

### Cold-start latency

Comparison of first-run overhead with no warmup (hyperfine `--warmup 0`):

| Platform | agentbox | codex¹ | srt² | bare |
|----------|----------|--------|------|------|
| macOS (Apple M3 Pro) | **16 ms** | 26 ms | 158 ms | 1.3 ms |
| Linux (Xeon Gold 6133) | **30 ms** | 77 ms | 517 ms | 0.9 ms |
| Windows (Xeon Platinum, WSL) | 640 ms | **186 ms** | N/A³ | 43 ms |

### Hot-start latency

Sustained per-call overhead after warmup (hyperfine `--warmup 10`):

| Platform | agentbox | codex | srt |
|----------|----------|-------|-----|
| macOS | **16 ms** | 25 ms | 154 ms |
| Linux | **30 ms** | 77 ms | 497 ms |
| Windows | 631 ms | **187 ms** | N/A |

### Sustained throughput

Batch execution of 100 `echo hello` calls using agentbox `ExecArgs`:

| Platform | Mean | P50 | P95 |
|----------|------|-----|-----|
| macOS | 12.5 ms | 12.1 ms | 13.9 ms |
| Linux | 21.3 ms | 21.0 ms | 23.1 ms |
| Windows | 156 ms | 154 ms | 167 ms |

**Notes:**

1. **codex** = [OpenAI Codex CLI](https://github.com/openai/codex) 0.80–0.115 (Rust). Uses Seatbelt (macOS), bubblewrap+Landlock (Linux), Restricted Token (Windows).
2. **srt** = [Claude Code sandbox-runtime](https://github.com/anthropics/sandbox-runtime) 1.0 (Node.js). Uses sandbox-exec (macOS), bubblewrap (Linux).
3. srt does not support Windows.

Bare execution (no sandbox) is shown for reference. Test commands: `echo hello` (cold/hot), `go version` (verification). macOS tested on Go 1.26.0, Linux on Go 1.23.9 (TencentOS Server, kernel 6.6.47), Windows on Go 1.24.1 (Server 2025, WSL1). Windows performance is constrained by WSL1 overhead; native Windows sandbox implementation is planned for future releases.

## Architecture

```
agentbox/
├── sandbox.go          # Manager interface, convenience functions (Exec, Wrap, ExecArgs)
├── config.go           # Config, NetworkConfig, FilesystemConfig, ResourceLimits
├── option.go           # Per-call Option types
├── classifier.go       # Classifier interface, Decision, ClassifyResult
├── classifier_rules.go # Built-in classification rules (13 rules), DefaultClassifier
├── errors.go           # Sentinel error types
├── result.go           # ExecResult, Violation
├── manager.go          # Core manager implementation (sandbox orchestration)
├── nop.go              # NopManager for FallbackWarn mode (no-op sandbox)
├── reexec.go           # Linux re-exec sandbox helper (namespace setup)
├── platform/           # Platform-specific sandbox backends
│   ├── darwin/         # macOS: Seatbelt/SBPL profile generation + enforcement
│   ├── linux/          # Linux: Namespaces + Landlock + Seccomp BPF
│   └── windows/        # Windows: WSL2 VM isolation + optional Linux sandbox
├── proxy/              # HTTP/SOCKS5 proxy with domain-level filtering
└── internal/           # Internal utilities
```

### Windows WSL2 Sandbox

On Windows, agentbox isolates commands inside a WSL2 virtual machine running a minimal Alpine Linux distribution.

**Simple Mode (Tier 1):** Commands run inside the WSL2 VM with security hardening via `wsl.conf`:
- `interop.enabled=false` — prevents WSL→Windows escape
- `automount.options="metadata,ro"` — Windows drives mounted read-only
- Non-root `sandbox` user
- `appendWindowsPath=false` — Windows PATH not inherited

**Full Mode (Tier 2):** Adds Linux namespace sandbox inside WSL2 using the same mechanisms as the native Linux platform (namespaces, Landlock, seccomp). Requires a pre-built helper binary set via `SetHelperBinary()`.

**Prerequisites:**
- Windows 10 Build 19041+ or Windows 11
- WSL2 ≥ v2.5.10 (enforced for CVE-2025-53788 mitigation)
- `wsl.exe` available in PATH

The sandbox distro (`agentbox-sb`) is automatically provisioned on first use by downloading the Alpine Linux minirootfs (~3.5 MB).

## Linux Re-exec Helper

On Linux, agentbox uses process re-execution for namespace setup. Add this to the very beginning of `main()`:

```go
func main() {
    if agentbox.MaybeSandboxInit() {
        return
    }
    // ... rest of your application
}
```

On macOS and other platforms, `MaybeSandboxInit()` is a no-op that returns `false`.

On Windows, the sandbox helper is a separate Linux binary that runs inside the WSL2 distro. Set it via `SetHelperBinary()` to enable Full Mode.

## Dependencies

agentbox has **zero external runtime dependencies** — the core library uses only the Go standard library. The SOCKS5 proxy implementation is fully internal.

Test dependencies:
- `golang.org/x/net` — used as a SOCKS5 client in proxy integration tests.

## Development

### Prerequisites

- Go 1.24+
- [golangci-lint](https://golangci-lint.run/) v2 (for linting)

### Running Tests

```bash
go test ./... -race
go test ./... -coverprofile=cover.out
go tool cover -html=cover.out
```

### Linting

```bash
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
golangci-lint run ./...
```

### Windows Testing

Windows tests require WSL2 to be installed and enabled. Tests that depend on `/bin/sh` or Unix-specific features are automatically skipped on Windows.

```bash
# On a Windows machine with Go and WSL2:
go test ./...

# Cross-compile the sandbox helper for WSL2 Full Mode:
GOOS=linux GOARCH=amd64 go build -o sandbox-helper ./cmd/sandbox-helper
```

## License

MIT License. See [LICENSE](LICENSE) for details.

---

<sub>agentbox is beta software. APIs are subject to breaking changes. Linux sandbox support has not been fully validated in production environments. Please report issues at the project's issue tracker.</sub>

