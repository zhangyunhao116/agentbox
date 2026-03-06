# Windows Sandbox: WSL2-Based Isolation

> **Status**: Proposed  
> **Author**: Agent  
> **Date**: 2026-03-04  
> **Scope**: agentbox Windows platform — WSL2-based sandbox implementation  
> **Prerequisite docs**: [01a-overview-api.md](./01a-overview-api.md), [01b-structure-flow.md](./01b-structure-flow.md), [02a-macos-seatbelt.md](./02a-macos-seatbelt.md), [02b-linux-namespace-landlock.md](./02b-linux-namespace-landlock.md)

> **Build note**: Files in `platform/windows/` have `//go:build windows` build tags and only compile on Windows. Path translation and config generation utilities are pure Go and testable on all platforms.

---

## 1. Executive Summary

This document describes the design for Windows sandbox support in agentbox, using **WSL2** (Windows Subsystem for Linux 2) as the isolation substrate. The approach leverages the Hyper-V lightweight VM that WSL2 provides, combined with the existing Linux namespace + Landlock + seccomp stack running inside that VM, to deliver defense-in-depth isolation equivalent to native Linux.

**Why WSL2?** Industry leaders have converged on WSL2 as the standard approach for sandbox isolation on Windows:

| Product | Windows Sandbox Strategy | Linux Primitives Inside WSL2 |
|---------|-------------------------|------------------------------|
| **Claude Code** (Anthropic) | WSL2 only; WSL1 not supported | bubblewrap + namespaces + seccomp |
| **OpenAI Codex** | WSL2 with fallback | Landlock v3 + seccomp + user namespaces |
| **Cursor IDE** | WSL2 recommended | Permission-based (no sandbox) |

> **Industry Research (2025-2026):** Claude Code's sandbox runtime is now [open source](https://github.com/anthropic-experimental/sandbox-runtime) and provides a proven reference implementation. Their approach uses WSL2 as the VM boundary, then bubblewrap for filesystem/network isolation inside WSL2. This validates agentbox's two-tier architecture design.
>
> **OWASP Agentic Top 10 (2026):** Sandboxing directly addresses **ASI05: Unexpected Code Execution**, ranked among the top security risks for agentic AI applications. The report emphasizes "least agency" — granting agents only the minimum autonomy required for safe, bounded tasks.
>
> **Security Note:** WSL2 version 2.5.10 or later is required to patch [CVE-2025-53788](https://cvefeed.io/vuln/detail/CVE-2025-53788), a TOCTOU privilege escalation vulnerability. The implementation should check for minimum WSL2 version.

WSL2 provides a real Linux kernel (5.15+) in a lightweight Hyper-V VM with full syscall compatibility — namespaces, cgroups, seccomp, and Landlock all work. This enables maximum code reuse with the existing `platform/linux/` implementation.

### 1.1 Industry Comparison

| Approach | Isolation Level | Dependencies | Startup | Maturity |
|----------|----------------|--------------|---------|----------|
| **WSL2 + Linux sandbox** (this design) | High (Hyper-V + namespaces + Landlock + seccomp) | WSL2 | ~1-2s cold, ~0.1s warm | Production-ready (industry standard) |
| **Windows Job Objects + ACLs** | Medium (process-level, no kernel isolation) | None | Instant | Well-understood, limited isolation |
| **Windows Sandbox (wsb.exe)** | High (dedicated VM) | Win11 24H2+ | ~3-5s | New, limited API |
| **Docker Desktop** | High (container isolation) | Docker Desktop | ~2-3s | Mature, heavy dependency |

**Key Insights from Industry Research:**

1. **Claude Code** (Anthropic) uses WSL2 + bubblewrap — their [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime) is now open source and serves as a reference implementation.

2. **OpenAI Codex** uses Landlock + seccomp directly, but has compatibility issues on some WSL2 configurations (see [openai/codex#1039](https://github.com/openai/codex/issues/1039)).

3. **Cursor IDE** relies on WSL2 for Linux tool compatibility but does not implement OS-level sandboxing — they use permission-based security which has had vulnerabilities (CVE-2025-54135).

**Two-tier architecture:**

1. **Tier 1 — WSL2 VM Boundary** (coarse-grained): Hyper-V isolation, hardened `wsl.conf` (disabled interop, read-only automount, non-root user). Always active.
2. **Tier 2 — Linux Sandbox Inside WSL2** (fine-grained): Reuse of existing `platform/linux/` namespaces + Landlock + seccomp. Same security as native Linux.

---

## 2. Architecture Overview

### 2.1 High-Level Design

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Windows Host (GOOS=windows)                                             │
│                                                                          │
│  ┌──────────────────────────────────────────┐                            │
│  │  agentbox (Windows binary)               │                            │
│  │                                          │                            │
│  │  Manager.Exec("ls -la /workspace")       │                            │
│  │       │                                  │                            │
│  │       ▼                                  │                            │
│  │  platform/windows.WrapCommand()          │                            │
│  │       │                                  │                            │
│  │       │  Rewrites cmd.Path → wsl.exe     │                            │
│  │       │  Translates Windows → WSL paths  │                            │
│  │       ▼                                  │                            │
│  │  exec.Cmd{                               │                            │
│  │    Path: "C:\Windows\system32\wsl.exe"   │                            │
│  │    Args: ["wsl", "-d", "agentbox-sb",    │                            │
│  │           "-e", "/opt/agentbox/helper",  │                            │
│  │           "--config=...",                │                            │
│  │           "--", "/bin/sh", "-c", "..."]  │                            │
│  │  }                                       │                            │
│  └──────────────────────────────────────────┘                            │
│       │  stdin/stdout/stderr via Hyper-V sockets                         │
│       ▼                                                                  │
│  ═══════════════════════════════════════════════════  Hyper-V VM Boundary │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │  WSL2 VM (Linux kernel 5.15+)                                    │    │
│  │                                                                  │    │
│  │  ┌─────────────────────────────────────────────────────────┐    │    │
│  │  │  agentbox-sb distro (Alpine Linux, ~5 MB)               │    │    │
│  │  │                                                         │    │    │
│  │  │  /init (PID 1) → /opt/agentbox/helper                  │    │    │
│  │  │       │                                                 │    │    │
│  │  │       │  Tier 2: Apply Linux sandbox                    │    │    │
│  │  │       │  ├─ CLONE_NEWUSER + CLONE_NEWNS + NEWPID + NET │    │    │
│  │  │       │  ├─ Landlock (file path restrictions)           │    │    │
│  │  │       │  ├─ Seccomp BPF (syscall filtering)             │    │    │
│  │  │       │  └─ prctl hardening                             │    │    │
│  │  │       ▼                                                 │    │    │
│  │  │  /bin/sh -c "ls -la /workspace"                         │    │    │
│  │  │       │                                                 │    │    │
│  │  │       ▼                                                 │    │    │
│  │  │  stdout/stderr → wsl.exe → Go cmd.Stdout/Stderr        │    │    │
│  │  └─────────────────────────────────────────────────────────┘    │    │
│  └──────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────┘
```

**Comparison with existing platforms:**

| Aspect | macOS (Darwin) | Linux | Windows (WSL2) |
|--------|---------------|-------|----------------|
| Wrapper binary | `/usr/bin/sandbox-exec` | Self (reexec) | `wsl.exe` |
| cmd.Path rewrite | → `sandbox-exec` | → `/proc/self/exe` | → `wsl.exe` |
| Isolation mechanism | SBPL profile | Namespaces + Landlock + seccomp | Hyper-V VM + Namespaces + Landlock + seccomp |
| Network isolation | SBPL `deny network*` | `CLONE_NEWNET` | `CLONE_NEWNET` inside WSL2 |
| Filesystem isolation | SBPL subpath rules | Landlock | Landlock inside WSL2 + mount control |
| Cleanup | No-op | No-op | Terminate distro (optional) |

### 2.2 Two-Tier Isolation Architecture

**Tier 1: WSL2 VM Boundary (coarse-grained)** — ALWAYS active.

The WSL2 lightweight VM provides a Hyper-V hardware isolation boundary. Combined with `wsl.conf` hardening, this tier delivers:

- **Process isolation**: Sandboxed commands run inside a dedicated VM, invisible to the Windows host process tree (beyond the `wsl.exe` entry point).
- **Filesystem isolation**: Windows drives automounted read-only; writable access only via explicit namespace bind mounts.
- **Interop isolation**: WSL→Windows interop disabled, preventing escape from WSL to execute arbitrary Windows binaries.
- **User isolation**: Commands run as a non-root `sandbox` user inside the distro.

**Tier 2: Linux Sandbox Inside WSL2 (fine-grained)** — Active in Full Mode.

Inside the WSL2 VM, a helper binary applies the same four-layer isolation stack used by `platform/linux/`:

1. **User Namespace** (`CLONE_NEWUSER`) — unprivileged namespace creation
2. **Mount/PID/Net Namespace** — read-only root, writable bind mounts, PID isolation, network isolation
3. **Landlock** — file path-level restrictions with ABI auto-detection
4. **Seccomp** — system call filtering via raw BPF

This tier reuses the existing `platform/linux/` code compiled as a Linux binary (the sandbox helper).

### 2.3 Component Diagram

```
platform/                              cmd/
├── detect_windows.go ─────┐           └── sandbox-helper/
│   (//go:build windows)   │               └── main.go (GOOS=linux)
│   detectPlatform() ──────┤                   │
│                          ▼                   │  Reuses:
├── windows/               │                   │  ├── platform/linux/namespace.go
│   ├── wsl.go ◄───────────┘                   │  ├── platform/linux/landlock.go
│   │   Platform struct                        │  ├── platform/linux/seccomp.go
│   │   New(), Name(), Available()             │  └── platform/linux/harden.go
│   │   WrapCommand(), Cleanup()               │
│   │   Capabilities()                         │
│   │                                          │
│   ├── detect.go                              │
│   │   WSL2 version detection                 │
│   │   Distro existence check                 │
│   │                                          │
│   ├── distro.go                              │
│   │   Distro provisioning                    │
│   │   wsl.conf generation                    │
│   │   Helper binary installation             │
│   │                                          │
│   ├── paths.go                               │
│   │   Windows ↔ WSL path translation         │
│   │   Drive letter mapping                   │
│   │                                          │
│   └── helper.go                              │
│       Helper binary lifecycle                │
│                                              │
├── platform_windows.go                        │
│   (//go:build windows)                       │
│   import platform/windows                    │
│                                              │
└── detect_other.go                            │
    Update: !darwin && !linux && !windows       │
```

---

## 3. Distro Lifecycle Management

### 3.1 Sandbox Distro Provisioning

The sandbox distro is a minimal **Alpine Linux** root filesystem (~5 MB) imported into WSL2 as a dedicated distribution named `agentbox-sb`. The distro is created once and reused across executions.

**Provisioning steps:**

```
1. Download/embed Alpine Linux minirootfs tarball (~5 MB)
2. Create installation directory: %LOCALAPPDATA%\agentbox\wsl\agentbox-sb\
3. Import distro:
   wsl --import agentbox-sb <install-dir> <alpine-minirootfs.tar.gz>
4. Configure distro:
   - Write /etc/wsl.conf (security hardening)
   - Create sandbox user: adduser -D -s /bin/sh sandbox
   - Install helper binary: copy to /opt/agentbox/helper
5. Restart distro to apply wsl.conf:
   wsl --terminate agentbox-sb
```

**Lazy initialization**: The distro is NOT created at `New()` time. Instead, `New()` only checks WSL2 availability. The distro is created on first `WrapCommand()` invocation if it does not exist. This avoids slow startup for programs that import agentbox but may not use it on Windows.

```go
func (p *Platform) ensureDistro(ctx context.Context) error {
    p.distroOnce.Do(func() {
        p.distroErr = p.provisionDistro(ctx)
    })
    return p.distroErr
}
```

### 3.2 Distro Configuration (wsl.conf)

> **Source**: Written to `/etc/wsl.conf` inside the distro during provisioning.

```ini
[interop]
enabled=false            # CRITICAL: Prevent WSL→Windows escape
appendWindowsPath=false  # Do not leak Windows PATH into WSL

[automount]
enabled=true             # Mount Windows drives at /mnt/c/, /mnt/d/, etc.
options="metadata,ro"    # Read-only by default — write access via bind mounts
mountFsTab=false         # Do not process /etc/fstab

[user]
default=sandbox          # Non-root user for all commands

[network]
hostname=agentbox-sb
generateHosts=false      # Do not auto-generate /etc/hosts
generateResolvConf=true  # Let WSL auto-generate /etc/resolv.conf for DNS

[boot]
systemd=false            # No systemd (Alpine uses OpenRC, but we disable it too)
```

**Security rationale for each setting:**

| Setting | Why |
|---------|-----|
| `interop.enabled=false` | Without this, any process inside WSL can execute `cmd.exe`, `powershell.exe`, or any Windows binary — a trivial sandbox escape. |
| `interop.appendWindowsPath=false` | Prevents `C:\Windows\system32` etc. from appearing in `$PATH` inside WSL. |
| `automount.enabled=true` + `options="metadata,ro"` | Mounts Windows drives as **read-only** by default at `/mnt/c/`, `/mnt/d/`, etc. This provides a read-only base for path translation. Writable access is granted only to specific paths via bind mounts in the mount namespace. |
| `user.default=sandbox` | Commands run as non-root. Combined with Tier 2 namespaces, this prevents privilege escalation. |
| `network.generateResolvConf=true` | Lets WSL auto-generate `/etc/resolv.conf` so DNS works by default. When `NetworkBlocked` is active, the network namespace (`CLONE_NEWNET`) isolates DNS regardless of this setting. |
| `boot.systemd=false` | Minimizes attack surface. No services running in the background. |

#### 3.2.1 Security Hardening Rationale

Based on [Ubuntu's WSL security documentation](https://documentation.ubuntu.com/wsl/stable/explanation/security-overview/) and industry best practices:

1. **Interop is the #1 escape vector**: Without `interop.enabled=false`, any process inside WSL can execute `cmd.exe`, `powershell.exe`, or any Windows binary — a trivial sandbox escape. This is the most critical setting.

2. **Windows PATH leakage**: `appendWindowsPath=false` prevents Windows executables from being callable by name inside WSL2.

3. **Read-only mounts**: Windows drives are mounted read-only at `/mnt/c/`, `/mnt/d/`, etc. Writable access is granted only to specific paths via bind mounts in the mount namespace.

4. **Non-root user**: The `sandbox` user prevents trivial privilege escalation. Combined with `PR_SET_NO_NEW_PRIVS` in Tier 2, the user cannot gain root even via setuid binaries.

### 3.3 Initialization and Cleanup

```go
// New returns a Platform. Detection is performed internally;
// errors are stored for Available()/CheckDependencies() rather
// than returned. This follows the same
// pattern as the Darwin and Linux platform implementations.
func New() *Platform {
    wslPath, _ := findWSLExe()
    ver, _ := detectWSLVersion(wslPath)
    helperOK := false
    distroName := "agentbox-sb"
    if wslPath != "" && ver >= 2 {
        helperOK = distroExists(distroName) && helperInstalled(distroName)
    }
    return &Platform{
        wslPath:         wslPath,
        wslVersion:      ver,
        distroName:      distroName,
        installDir:      filepath.Join(os.Getenv("LOCALAPPDATA"), "agentbox", "wsl", distroName),
        helperAvailable: helperOK,
    }
}

// Available reports whether WSL2 is usable on this system.
func (p *Platform) Available() bool {
    return p.wslPath != "" && p.wslVersion >= 2
}

// Cleanup terminates the sandbox distro. If full cleanup is requested,
// it unregisters (deletes) the distro entirely.
func (p *Platform) Cleanup(ctx context.Context) error {
    // Terminate the distro (stops the WSL2 instance).
    return p.terminateDistro(ctx)
}
```

**Full cleanup** (distro unregistration) is available as a separate method but not called by default `Cleanup()`, since the distro is designed to be reused:

```go
// Unregister removes the sandbox distro entirely, including its VHD.
// This is a destructive operation — the distro must be re-provisioned
// after calling this.
func (p *Platform) Unregister(ctx context.Context) error {
    return exec.CommandContext(ctx, p.wslPath, "--unregister", p.distroName).Run()
}
```

---

## 4. Command Execution Flow

### 4.1 WrapCommand Implementation

> **Source**: `platform/windows/wsl.go`

`WrapCommand` follows the same pattern as `platform/darwin/` — it rewrites `cmd.Path` and `cmd.Args` in-place to wrap the user's command with sandbox infrastructure.

```go
func (p *Platform) WrapCommand(ctx context.Context, cmd *exec.Cmd, cfg *platform.WrapConfig) error {
    if cfg == nil {
        cfg = &platform.WrapConfig{}
    }

    // Ensure the sandbox distro is provisioned.
    if err := p.ensureDistro(ctx); err != nil {
        return fmt.Errorf("provisioning sandbox distro: %w", err)
    }

    // Save original command for reconstruction.
    origPath := cmd.Path
    origArgs := cmd.Args

    // Translate Windows paths in config to WSL paths.
    wslCfg, err := p.translateConfig(cfg)
    if err != nil {
        return fmt.Errorf("translating config paths: %w", err)
    }

    // Build the sandbox helper config JSON.
    helperCfg := p.buildHelperConfig(wslCfg, origPath, origArgs)

    // Rewrite command to invoke wsl.exe.
    cmd.Path = p.wslPath
    cmd.Args = p.buildWSLArgs(helperCfg, cfg)

    // Sanitize environment: remove Windows-specific vars that could
    // interfere, inject proxy settings if needed.
    cmd.Env = p.sanitizeEnv(cmd.Env, cfg)

    return nil
}
```

**Step-by-step flow:**

1. **Ensure distro** — Lazy-provision the sandbox distro if not already created.
2. **Save originals** — Capture `cmd.Path` and `cmd.Args` before rewriting.
3. **Translate paths** — Convert Windows paths in `WritableRoots`, `DenyWrite`, `DenyRead` to WSL paths (see §4.3).
4. **Build helper config** — Serialize sandbox restrictions as JSON for the helper binary.
5. **Rewrite cmd.Path** — Set to `wsl.exe` absolute path.
6. **Rewrite cmd.Args** — Build WSL argument list with distro selection and helper invocation.
7. **Sanitize environment** — Remove Windows-specific variables, inject `HTTP_PROXY`/`SOCKS_PROXY` if configured.

### 4.2 Execution Modes

#### Mode A: Simple Mode (Tier 1 only)

Relies on `wsl.conf` hardening and the Hyper-V VM boundary. No Linux namespace isolation inside WSL2.

```
wsl.exe -d agentbox-sb -e /bin/sh -c "<user_command>"
```

**Use case**: When the sandbox helper binary is not available, or when maximum performance is needed. Provides basic isolation via the VM boundary and `wsl.conf` hardening.

**Security level**: Moderate. Processes inside WSL2 can see each other, access all distro files, and perform arbitrary syscalls (within the VM).

#### Mode B: Full Mode (Tier 1 + Tier 2) — RECOMMENDED

Invokes the sandbox helper binary, which applies Linux namespaces + Landlock + seccomp before exec'ing the user command.

```
wsl.exe -d agentbox-sb -e /opt/agentbox/helper \
    --writable-roots=/workspace,/tmp \
    --deny-read=/etc/shadow,/root \
    --network=blocked \
    --shell=/bin/sh \
    -- -c "ls -la /workspace"
```

The helper binary:
1. Parses configuration from command-line flags
2. Applies `CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET`
3. Sets up mount namespace (read-only root, writable bind mounts)
4. Applies Landlock rules (file path restrictions)
5. Applies seccomp BPF filter
6. Applies process hardening (`PR_SET_NO_NEW_PRIVS`, `PR_SET_DUMPABLE=0`)
7. Calls `syscall.Exec()` to replace itself with the user command

**Security level**: High. Equivalent to native `platform/linux/` — same four-layer isolation.

#### Mode Selection Logic

```go
func (p *Platform) selectMode(cfg *platform.WrapConfig) executionMode {
    if p.helperAvailable {
        return modeFullSandbox // Tier 1 + Tier 2
    }
    return modeSimple // Tier 1 only (log warning)
}
```

### 4.3 Path Translation

> **Source**: `platform/windows/paths.go`

Path translation converts between Windows and WSL path formats. This is implemented in pure Go (no dependency on the `wslpath` binary) so it is testable on all platforms.

```go
// WindowsToWSL translates a Windows path to a WSL path.
//
//   C:\Users\foo\project  → /mnt/c/Users/foo/project
//   D:\data               → /mnt/d/data
//   \\?\C:\long\path      → /mnt/c/long/path
//
// UNC paths (\\server\share) are not supported and return an error.
func WindowsToWSL(winPath string) (string, error) {
    // Normalize path separators.
    p := filepath.ToSlash(winPath)

    // Strip \\?\ prefix (extended-length path).
    p = strings.TrimPrefix(p, "//?/")

    // Check for UNC paths.
    if strings.HasPrefix(p, "//") {
        return "", ErrUNCPathNotSupported
    }

    // Extract drive letter.
    if len(p) >= 2 && p[1] == ':' {
        drive := strings.ToLower(string(p[0]))
        rest := p[2:]
        return "/mnt/" + drive + rest, nil
    }

    // Already a Unix-style path (e.g., /tmp) — pass through.
    return p, nil
}

// WSLToWindows translates a WSL path to a Windows path.
//
//   /mnt/c/Users/foo  → C:\Users\foo
//   /tmp              → (error: no Windows equivalent)
func WSLToWindows(wslPath string) (string, error) {
    if strings.HasPrefix(wslPath, "/mnt/") && len(wslPath) >= 6 {
        drive := strings.ToUpper(string(wslPath[5]))
        rest := wslPath[6:]
        return drive + ":" + filepath.FromSlash(rest), nil
    }
    return "", fmt.Errorf("path %q has no Windows equivalent", wslPath)
}
```

**Limitations:**
- UNC paths (`\\server\share`) are not supported. These cannot be mapped into WSL2 without additional SMB configuration.
- Paths with non-ASCII characters are passed through unchanged; WSL2 handles Unicode natively.
- Relative paths are resolved to absolute before translation using `filepath.Abs()`.

### 4.4 Environment Variable Handling

```go
func (p *Platform) sanitizeEnv(env []string, cfg *platform.WrapConfig) []string {
    filtered := make([]string, 0, len(env))

    for _, e := range env {
        key, _, _ := strings.Cut(e, "=")
        switch {
        // Remove Windows-specific variables that could leak information
        // or cause confusion inside WSL2.
        case strings.EqualFold(key, "SYSTEMROOT"),
             strings.EqualFold(key, "WINDIR"),
             strings.EqualFold(key, "COMSPEC"),
             strings.EqualFold(key, "PATHEXT"),
             strings.EqualFold(key, "OS"),
             strings.EqualFold(key, "PROGRAMFILES"),
             strings.EqualFold(key, "APPDATA"),
             strings.EqualFold(key, "LOCALAPPDATA"):
            continue

        // Translate PATH to Unix format.
        case strings.EqualFold(key, "PATH"):
            // Omit Windows PATH entirely — WSL has its own PATH.
            // (appendWindowsPath=false in wsl.conf prevents leaking anyway.)
            continue

        default:
            filtered = append(filtered, e)
        }
    }

    // Inject proxy environment variables if configured.
    if cfg.HTTPProxyPort > 0 {
        proxyHost := p.proxyHostAddr() // "localhost" for mirrored, host IP for NAT
        filtered = append(filtered,
            fmt.Sprintf("HTTP_PROXY=http://%s:%d", proxyHost, cfg.HTTPProxyPort),
            fmt.Sprintf("HTTPS_PROXY=http://%s:%d", proxyHost, cfg.HTTPProxyPort),
        )
    }
    if cfg.SOCKSProxyPort > 0 {
        proxyHost := p.proxyHostAddr()
        filtered = append(filtered,
            fmt.Sprintf("ALL_PROXY=socks5://%s:%d", proxyHost, cfg.SOCKSProxyPort),
        )
    }

    return filtered
}
```

**Note on `WSLENV`**: WSL2 uses the `WSLENV` environment variable to control which variables are forwarded from Windows to WSL. However, since we disable interop (`interop.enabled=false`), `WSLENV` forwarding is also disabled. Environment variables are passed directly via the `wsl.exe` command's `cmd.Env`.

---

## 5. Filesystem Isolation

Filesystem isolation is applied in three complementary layers.

### 5.1 Layer 1: WSL Config (automount read-only)

With `automount.enabled=true` and `options="metadata,ro"` in `wsl.conf`, Windows drives are automatically mounted at `/mnt/c/`, `/mnt/d/`, etc. in **read-only** mode. This means the sandboxed process can read Windows filesystem content (enabling path translation) but cannot modify any Windows files by default.

### 5.2 Layer 2: Selective Path Sharing via Bind Mounts

The read-only automount provides a base that the helper binary augments with fine-grained write control inside a mount namespace (`CLONE_NEWNS`):

**Approach**: The helper binary runs inside a new mount namespace and bind-mounts specific paths as writable. Since the base `/mnt/c/...` is already available read-only via automount, the helper only needs to remount selected subtrees as read-write — no root/drvfs mounting required.

```
For each WritableRoot:
  1. Translate Windows path → WSL path (e.g., C:\project → /mnt/c/project)
  2. Bind-mount the read-only automount path over itself as read-write
  3. The namespace gives writable access only to these specific subtrees

For each DenyWrite path:
  1. Translate Windows path → WSL path
  2. Already read-only via automount — no additional action needed
  3. Landlock rules provide additional enforcement

For each DenyRead path:
  1. Translated path is hidden via tmpfs overmount in the namespace
  2. Additionally covered by Landlock deny rules
```

### 5.3 Layer 3: Landlock (inside WSL2)

The helper binary applies the same Landlock rules as `platform/linux/`:

```go
// Inside the sandbox helper (Linux binary running in WSL2)
func applyLandlock(cfg *HelperConfig) error {
    abi := detectLandlock()
    if abi < 1 {
        return nil // Graceful degradation
    }

    // Create Landlock ruleset with same logic as platform/linux/landlock.go
    rulesetFd, err := landlockCreateRuleset(handledAccessFS(abi))
    if err != nil {
        return err
    }
    defer syscall.Close(rulesetFd)

    // Add rules for writable roots.
    for _, root := range cfg.WritableRoots {
        landlockAddPathRule(rulesetFd, root, readWriteAccess(abi))
    }

    // Add rules for read-only paths.
    for _, root := range cfg.DenyWrite {
        landlockAddPathRule(rulesetFd, root, readOnlyAccess(abi))
    }

    // Restrict self.
    return landlockRestrictSelf(rulesetFd)
}
```

**ABI version detection**: Performed inside WSL2, since the Landlock ABI version depends on the WSL2 kernel (typically 5.15+, which supports ABI v1). The WSL2 kernel is updated independently of the Windows kernel via `wsl --update`.

**Graceful degradation**: If Landlock is not available (unlikely on modern WSL2 kernels), the helper logs a warning and relies on mount namespace isolation alone.

---

## 6. Network Isolation

### 6.1 Strategy Selection

| `NetworkMode` | Implementation | Details |
|---------------|---------------|---------|
| `NetworkBlocked` | `CLONE_NEWNET` inside WSL2 | Creates empty network namespace — no lo, no eth0. Complete isolation. |
| `NetworkFiltered` | Network namespace + iptables | Creates network namespace with veth pair; iptables rules whitelist only the proxy port. Env vars (`HTTP_PROXY`, `HTTPS_PROXY`) point commands to the proxy. See §6.2. **Degraded fallback**: if iptables/nftables is unavailable, falls back to env-var-only proxy configuration (proxy bypass is possible but detectable). |
| `NetworkAllowed` | No restriction | Commands inherit WSL2's network stack. |

### 6.2 Proxy Architecture

When `NetworkFiltered` is configured, the existing `proxy/` package runs a filtering proxy server on the **Windows host**. The sandboxed command inside WSL2 connects to this proxy:

```
┌─────────────────────────────────────────┐
│  Windows Host                           │
│                                         │
│  agentbox proxy server                  │
│  ├── HTTP proxy on 127.0.0.1:18080     │
│  └── SOCKS5 proxy on 127.0.0.1:18081  │
│       │                                 │
│       │  WSL2 networking mode:          │
│       │  ├── "mirrored": localhost works│
│       │  └── "NAT": use host gateway IP│
│       ▼                                 │
│  ═══════════  VM Boundary  ═══════════  │
│                                         │
│  WSL2 VM                                │
│  ├── HTTP_PROXY=http://host:18080      │
│  ├── SOCKS_PROXY=socks5://host:18081   │
│  └── sandboxed command                  │
│       └── All traffic → proxy → filter  │
└─────────────────────────────────────────┘
```

**WSL2 networking mode considerations:**

> **NetworkFiltered enforcement**: Seccomp alone cannot inspect `connect()` sockaddr arguments to enforce proxy-only networking. Instead, the helper uses a **network namespace + veth pair + iptables** approach:
>
> 1. The helper creates a new network namespace (`CLONE_NEWNET`).
> 2. A veth pair connects the new namespace to the parent namespace.
> 3. `iptables` (or `nftables`) rules inside the new namespace whitelist only outbound connections to the proxy port (e.g., `--dport 18080 -j ACCEPT`) and drop all other outbound traffic.
> 4. The helper needs `CAP_NET_ADMIN` (obtainable inside a user namespace) to configure the veth pair and iptables rules.
>
> **Complexity note**: The veth+iptables approach requires the `iptables` or `nftables` binary inside the distro. If neither is available, the helper falls back to an **env-var-only** strategy: `HTTP_PROXY`/`HTTPS_PROXY` environment variables are set, and a warning is logged that proxy bypass is possible. This degraded mode is acceptable for non-adversarial sandboxing (e.g., preventing accidental network access).

| Mode | Proxy Connectivity | How to Reach Host Proxy |
|------|-------------------|------------------------|
| `mirrored` (Win11 22H2+) | `localhost` works bidirectionally | `HTTP_PROXY=http://localhost:18080` |
| `NAT` (default) | WSL2 has its own IP; cannot use `localhost` | Use host gateway IP from `/proc/net/route` or `ip route show default` |
| `none` | No network at all | Proxy not reachable — use `NetworkBlocked` instead |

```go
// proxyHostAddr returns the address the WSL2 sandbox should use
// to reach the proxy running on the Windows host.
func (p *Platform) proxyHostAddr() string {
    if p.wslNetworkMode == "mirrored" {
        return "localhost"
    }
    // NAT mode: resolve the host gateway IP.
    // This is typically the first IP in the default route inside WSL2.
    return p.resolveHostGateway()
}
```

### 6.3 DNS Resolution

When `NetworkFiltered`:
- Generate `/etc/resolv.conf` with proxy or host DNS server.
- The proxy handles DNS resolution on the Windows side.

When `NetworkBlocked`:
- The network namespace (`CLONE_NEWNET`) has no interfaces, so DNS resolution fails naturally.
- `generateResolvConf=true` in `wsl.conf` is harmless because the empty network namespace has no connectivity regardless.

When `NetworkAllowed`:
- WSL2's auto-generated `resolv.conf` provides DNS resolution out of the box.

---

## 7. Process Management

### 7.1 Process Group on Windows

> **Source**: `procgroup_windows.go`

On Unix, agentbox uses `Setsid` to create a new session for the sandboxed process, enabling clean process group termination. On Windows, the equivalent mechanism is **Job Objects** with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, which guarantees all descendant processes are terminated when the job handle is closed.

> **Note**: `CREATE_NEW_PROCESS_GROUP` alone does **not** guarantee termination of all descendants. Job Objects are the correct Windows primitive for this purpose.

```go
//go:build windows

package agentbox

import (
	"fmt"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

// jobObject wraps a Windows Job Object handle.
type jobObject struct {
	handle windows.Handle
}

// newJobObject creates a Job Object that kills all assigned processes
// when the handle is closed (including on parent process crash).
func newJobObject() (*jobObject, error) {
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateJobObject: %w", err)
	}

	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	_, err = windows.SetInformationJobObject(
		h,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
	if err != nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("SetInformationJobObject: %w", err)
	}
	return &jobObject{handle: h}, nil
}

// assign adds a process to the job object.
func (j *jobObject) assign(proc windows.Handle) error {
	return windows.AssignProcessToJobObject(j.handle, proc)
}

// close terminates all processes in the job and releases the handle.
func (j *jobObject) close() error {
	return windows.CloseHandle(j.handle)
}

// setupProcessGroup configures the command to run in a new Windows Job Object
// so that all child processes (including those inside WSL2) are terminated
// when the parent exits.
func setupProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
}
```

After starting the process, the caller assigns it to the job:

```go
job, err := newJobObject()
if err != nil { /* handle error */ }
defer job.close()

cmd.Start()
job.assign(windows.Handle(cmd.Process.Handle))
```

> **Backup cleanup**: If the Job Object mechanism fails (e.g., handle leak), `wsl --terminate agentbox-sb` during `Cleanup()` ensures the WSL2 distro and all its processes are stopped.

**Process tree on Windows:**

```
agentbox.exe (Go process)
  └── wsl.exe (Windows process, new process group)
        └── /init (WSL2 PID 1)
              └── /opt/agentbox/helper (sandbox helper)
                    └── /bin/sh -c "user command"
```

**Termination**: Killing the `wsl.exe` process on the Windows side causes WSL2 to terminate all processes spawned through that `wsl.exe` invocation. The Go `exec.Cmd` context cancellation mechanism works correctly with `wsl.exe` — when the context is cancelled, `cmd.Process.Kill()` sends `TerminateProcess` to `wsl.exe`, which propagates termination to the WSL2 side.

### 7.2 Timeout and Cancellation

```go
// The standard Go exec.Cmd timeout and cancellation mechanisms work:
ctx, cancel := context.WithTimeout(parentCtx, 30*time.Second)
defer cancel()

cmd := exec.CommandContext(ctx, "wsl.exe", args...)
cmd.WaitDelay = 5 * time.Second // Grace period for cleanup
```

- **Context cancellation** → `TerminateProcess(wsl.exe)` → WSL2 terminates command.
- **WaitDelay** provides a grace period for `wsl.exe` to clean up.
- **Edge case**: If `wsl.exe` becomes orphaned (rare), `wsl --terminate agentbox-sb` during `Cleanup()` ensures the distro is stopped.

---

## 8. Capability Detection and Dependencies

### 8.1 CheckDependencies

> **Source**: `platform/windows/detect.go`

```go
func (p *Platform) CheckDependencies() *platform.DependencyCheck {
    check := &platform.DependencyCheck{}

    // Required: wsl.exe must exist.
    if _, err := exec.LookPath("wsl.exe"); err != nil {
        check.Errors = append(check.Errors,
            "wsl.exe not found in PATH: WSL2 is required for Windows sandbox")
        return check
    }

    // Required: WSL2 (not WSL1).
    ver, err := detectWSLVersion(p.wslPath)
    if err != nil {
        check.Errors = append(check.Errors,
            fmt.Sprintf("cannot detect WSL version: %v", err))
        return check
    }
    if ver < 2 {
        check.Errors = append(check.Errors,
            "WSL1 detected; WSL2 is required (run: wsl --set-default-version 2)")
    }

    // Optional: sandbox distro pre-installed.
    if !p.distroExists() {
        check.Warnings = append(check.Warnings,
            "sandbox distro not provisioned (will be created on first use)")
    }

    // Optional: helper binary installed in distro.
    if p.distroExists() && !p.helperInstalled() {
        check.Warnings = append(check.Warnings,
            "sandbox helper not installed in distro (Simple Mode will be used)")
    }

    return check
}
```

**Version detection** uses `wsl.exe --version` as the primary method, with fallbacks for older (inbox) WSL installations where `--version` is not available:

```go
// detectWSLVersion attempts multiple detection strategies.
func detectWSLVersion(wslPath string) (int, error) {
    // Primary: "wsl.exe --version" (Store-delivered WSL 2.0+).
    // Output includes "WSL version: 2.x.y.z".
    ver, err := detectViaVersion(wslPath)
    if err == nil {
        return ver, nil
    }

    // Fallback 1: "wsl.exe --status" (available on some builds).
    // Output includes "Default Version: 2".
    ver, err = detectViaStatus(wslPath)
    if err == nil {
        return ver, nil
    }

    // Fallback 2: "wsl.exe -l -v" (works on inbox WSL).
    // Lists distros with their WSL version (1 or 2).
    // If any distro runs WSL2, the system supports it.
    ver, err = detectViaListVerbose(wslPath)
    if err == nil {
        return ver, nil
    }

    return 0, fmt.Errorf("cannot detect WSL version: all methods failed")
}
```

Primary output (`wsl.exe --version`):

```
WSL version: 2.0.14.0
Kernel version: 5.15.133.1-1
...
```

Fallback output (`wsl.exe -l -v`):

```
  NAME            STATE           VERSION
* Ubuntu          Running         2
  Alpine          Stopped         1
```

### 8.2 Capabilities

```go
func (p *Platform) Capabilities() platform.Capabilities {
    if p.helperAvailable {
        // Full Mode: helper binary is installed in the distro.
        return platform.Capabilities{
            FileReadDeny:   true,  // Landlock inside WSL2 (ABI v1+)
            FileWriteAllow: true,  // Landlock + mount namespace inside WSL2
            NetworkDeny:    true,  // CLONE_NEWNET inside WSL2
            NetworkProxy:   true,  // Proxy on Windows host + forwarding into WSL2
            PIDIsolation:   true,  // CLONE_NEWPID inside WSL2
            SyscallFilter:  true,  // Seccomp BPF inside WSL2
            ProcessHarden:  true,  // prctl(PR_SET_NO_NEW_PRIVS, ...) inside WSL2
        }
    }

    // Simple Mode: no helper binary — limited to WSL2 defaults.
    return platform.Capabilities{
        FileReadDeny:   false, // No Landlock without helper
        FileWriteAllow: false, // No mount namespace without helper
        NetworkDeny:    false, // No network namespace without helper
        NetworkProxy:   true,  // Proxy env vars still work
        PIDIsolation:   false, // No PID namespace without helper
        SyscallFilter:  false, // No seccomp without helper
        ProcessHarden:  false, // No prctl without helper
    }
}
```

**Note**: Capabilities are reported dynamically based on whether the helper binary is available. In Full Mode, the WSL2 kernel (5.15+) supports all required primitives. In Simple Mode (no helper), only proxy-based filtering is available — the remaining capabilities require the helper to set up Linux namespaces and security primitives.

---

## 9. File Structure

### 9.1 New Files

```
platform/
├── detect_windows.go              # //go:build windows — detectPlatform() returns windows.New()
├── windows/
│   ├── wsl.go                     # Platform struct, New(), Name(), Available()
│   │                              # WrapCommand(), Cleanup(), Capabilities()
│   ├── wsl_test.go                # Platform interface compliance, WrapCommand tests
│   ├── detect.go                  # WSL2 version detection, distro existence check
│   ├── detect_test.go             # Detection tests (mock wsl.exe output)
│   ├── paths.go                   # WindowsToWSL(), WSLToWindows() path translation
│   ├── paths_test.go             # Path translation tests (pure Go, runs on all platforms)
│   ├── distro.go                  # Distro provisioning, wsl.conf generation, rootfs management
│   ├── distro_test.go             # Distro lifecycle tests
│   ├── helper.go                  # Helper binary installation, availability check
│   └── helper_test.go            # Helper binary tests

platform_windows.go                # //go:build windows — platform import registration
procgroup_windows.go               # //go:build windows — Windows Job Object process group

cmd/
└── sandbox-helper/
    ├── main.go                    # Entry point: parse config, apply sandbox, exec command
    ├── config.go                  # Config parsing (flags + JSON)
    └── config_test.go             # Config parsing tests
```

### 9.2 Modified Files

```
platform/detect_other.go           # Build tag: !darwin && !linux → !darwin && !linux && !windows
```

### 9.3 Build Tags

| File | Build Tag | Purpose |
|------|-----------|---------|
| `platform/detect_windows.go` | `//go:build windows` | Platform registration for Windows |
| `platform/windows/*.go` | `//go:build windows` | Windows-specific implementation |
| `platform_windows.go` | `//go:build windows` | Root-level platform import |
| `procgroup_windows.go` | `//go:build windows` | Process group management |
| `platform/detect_other.go` | `//go:build !darwin && !linux && !windows` | Unsupported platform fallback |
| `platform/windows/paths.go` | _(no build tag)_ | Pure Go, testable on all platforms |
| `cmd/sandbox-helper/*.go` | `//go:build linux` | Linux binary for WSL2 execution |

**Note**: `paths.go` and `paths_test.go` intentionally have **no** build tag so that path translation logic can be unit-tested on macOS and Linux CI in addition to Windows. The functions use `filepath.ToSlash()` and string manipulation, not OS-specific syscalls.

---

## 10. Sandbox Helper Binary

### 10.1 Purpose

The sandbox helper is a **Linux binary** that runs inside WSL2. It bridges the gap between the Windows host (which cannot directly invoke Linux syscalls) and the Linux isolation primitives (namespaces, Landlock, seccomp).

The helper:
1. Receives sandbox configuration via command-line flags
2. Applies the four-layer Linux isolation stack
3. Calls `syscall.Exec()` to replace itself with the user command

This is conceptually similar to the `platform/linux/` reexec pattern, but as a standalone binary rather than self-re-execution.

### 10.2 Design

```go
// cmd/sandbox-helper/main.go
//go:build linux

package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "os"
    "syscall"
)

// HelperConfig defines the sandbox restrictions to apply.
type HelperConfig struct {
    WritableRoots []string `json:"writable_roots"`
    DenyWrite     []string `json:"deny_write"`
    DenyRead      []string `json:"deny_read"`
    NetworkMode   string   `json:"network_mode"` // "blocked", "filtered", "allowed"
    Shell         string   `json:"shell"`
    Command       string   `json:"command"`
    Args          []string `json:"args"`
    Env           []string `json:"env"`

    // Resource limits (same as platform/linux ResourceLimits).
    MaxProcs   int `json:"max_procs,omitempty"`
    MaxFiles   int `json:"max_files,omitempty"`
    MaxFileSz  int `json:"max_file_size,omitempty"`
}

func main() {
    configJSON := flag.String("config", "", "JSON sandbox configuration")
    flag.Parse()

    var cfg HelperConfig
    if *configJSON != "" {
        if err := json.Unmarshal([]byte(*configJSON), &cfg); err != nil {
            fatalf("parsing config: %v", err)
        }
    }

    // 1. Apply process hardening.
    applyHardening() // PR_SET_NO_NEW_PRIVS, PR_SET_DUMPABLE=0

    // 2. Apply namespace isolation.
    //    Note: Namespaces are applied via clone flags on the exec,
    //    or by entering new namespaces with unshare(2).
    if err := applyNamespaces(&cfg); err != nil {
        fatalf("applying namespaces: %v", err)
    }

    // 3. Apply Landlock filesystem restrictions.
    if err := applyLandlock(&cfg); err != nil {
        fatalf("applying Landlock: %v", err)
    }

    // 4. Apply seccomp BPF filter.
    if err := applySeccomp(&cfg); err != nil {
        fatalf("applying seccomp: %v", err)
    }

    // 5. Exec the real command (replaces this process).
    execPath, err := exec.LookPath(cfg.Shell)
    if err != nil {
        fatalf("looking up shell %q: %v", cfg.Shell, err)
    }
    if err := syscall.Exec(execPath, cfg.Args, cfg.Env); err != nil {
        fatalf("exec %q: %v", execPath, err)
    }
}

func fatalf(format string, args ...interface{}) {
    fmt.Fprintf(os.Stderr, "sandbox-helper: "+format+"\n", args...)
    os.Exit(1)
}
```

The `applyNamespaces`, `applyLandlock`, `applySeccomp`, and `applyHardening` functions reuse the logic from `platform/linux/` — either by importing the package directly or by extracting shared code into an internal package.

### 10.3 Distribution Strategy

Three options were evaluated:

| Option | Approach | Pros | Cons |
|--------|----------|------|------|
| **A** | Embed Linux binary in Windows binary via `go:embed` | Single binary distribution | Bloats Windows binary; cross-compilation complexity |
| **B** | Build separately, copy into WSL distro during provisioning | Simple build process; clean separation | Requires separate build step; user must have the binary |
| **C** | Compile on-the-fly inside WSL using `go build` | Always up-to-date | Requires Go toolchain inside WSL; slow first run |

**Recommendation: Option B** for simplicity and separation of concerns.

The helper binary is:
1. Built separately as `GOOS=linux GOARCH=amd64 go build -o sandbox-helper ./cmd/sandbox-helper/`
2. Distributed alongside the agentbox release (or downloaded on first use)
3. Copied into the WSL distro at `/opt/agentbox/helper` during provisioning

For development and testing, a `Makefile` target handles cross-compilation:

```makefile
.PHONY: sandbox-helper
sandbox-helper:
	GOOS=linux GOARCH=amd64 go build -o bin/sandbox-helper ./cmd/sandbox-helper/
```

---

## 11. Error Handling

### 11.1 New Error Types

> **Source**: `platform/windows/wsl.go`

```go
var (
    // ErrWSLNotInstalled indicates wsl.exe was not found in PATH.
    ErrWSLNotInstalled = errors.New("WSL is not installed")

    // ErrWSL1NotSupported indicates WSL1 was detected; WSL2 is required.
    ErrWSL1NotSupported = errors.New("WSL1 is not supported; WSL2 is required")

    // ErrDistroNotFound indicates the sandbox distro does not exist
    // and could not be auto-provisioned.
    ErrDistroNotFound = errors.New("sandbox distro not found")

    // ErrDistroProvisionFailed indicates distro creation failed.
    ErrDistroProvisionFailed = errors.New("failed to provision sandbox distro")

    // ErrPathTranslationFailed indicates a Windows path could not be
    // translated to a WSL path.
    ErrPathTranslationFailed = errors.New("path translation failed")

    // ErrUNCPathNotSupported indicates a UNC path (\\server\share) was
    // provided; these cannot be mapped into WSL2.
    ErrUNCPathNotSupported = errors.New("UNC paths are not supported in WSL2")

    // ErrHelperNotFound indicates the sandbox helper binary is not
    // installed in the distro. Simple Mode will be used.
    ErrHelperNotFound = errors.New("sandbox helper binary not found in distro")
)
```

### 11.2 Fallback Behavior

The platform follows the agentbox `FallbackPolicy` contract:

| Condition | `FallbackStrict` | `FallbackWarn` |
|-----------|-------------------|----------------|
| WSL2 not installed | Return `ErrWSLNotInstalled` | Use `NopManager` (no sandbox) |
| WSL1 only | Return `ErrWSL1NotSupported` | Use `NopManager` |
| Distro not provisioned | Auto-provision on first use | Auto-provision on first use |
| Provisioning failed | Return `ErrDistroProvisionFailed` | Log warning, use `NopManager` |
| Helper binary missing | Fall back to Simple Mode (Tier 1) | Fall back to Simple Mode (Tier 1) |
| Path translation failed | Return error | Log warning, skip untranslatable path |

**Note**: Helper binary absence is **not** treated as a fatal error in either mode. The system degrades gracefully to Simple Mode, which still provides Tier 1 isolation.

---

## 12. Testing Strategy

### 12.1 Unit Tests (run on all platforms)

These tests use **no build tags** and can run on macOS, Linux, and Windows CI:

- **Path translation** (`paths_test.go`): Pure string manipulation. Covers drive letters, extended-length paths, UNC paths (error case), edge cases.
- **Config generation** (`distro_test.go`): `wsl.conf` generation is pure Go template rendering. Verifiable without WSL2.
- **WSL argument building** (`wsl_test.go`): Verifies that `buildWSLArgs()` produces correct argument lists for both Simple and Full modes.
- **Environment sanitization**: Verifies Windows-specific variables are removed, proxy vars injected.
- **Helper config serialization** (`config_test.go` in `cmd/sandbox-helper/`): JSON roundtrip tests.

### 12.2 Integration Tests (Windows only)

```go
//go:build windows

func TestWSLExecution(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping WSL integration test in short mode")
    }

    // Check WSL2 is available.
    p, err := windows.New()
    if err != nil {
        t.Skipf("WSL2 not available: %v", err)
    }
    t.Cleanup(func() {
        p.Cleanup(context.Background())
    })

    // Test basic command execution.
    cmd := exec.Command("echo", "hello from sandbox")
    err = p.WrapCommand(context.Background(), cmd, &platform.WrapConfig{})
    require.NoError(t, err)

    out, err := cmd.Output()
    require.NoError(t, err)
    assert.Contains(t, string(out), "hello from sandbox")
}
```

**Integration test categories:**

| Test | What It Verifies |
|------|-----------------|
| `TestWSLDetection` | WSL2 detection, version parsing |
| `TestDistroLifecycle` | Create → verify → terminate → unregister |
| `TestSimpleModeExecution` | Tier 1: basic command runs in distro |
| `TestFullModeExecution` | Tier 2: helper applies sandbox restrictions |
| `TestFilesystemIsolation` | Cannot read/write outside allowed paths |
| `TestNetworkBlocked` | Cannot reach network with `NetworkBlocked` |
| `TestPathTranslation_Live` | Verify translation matches actual `wslpath` output |
| `TestProcessTermination` | Context cancellation kills WSL command |

### 12.3 Cross-Platform CI

```yaml
# .github/workflows/test-windows.yml
jobs:
  test-windows:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: stable

      - name: Enable WSL2
        run: |
          wsl --install --no-distribution
          wsl --set-default-version 2

      - name: Run unit tests (all platforms)
        run: go test ./platform/windows/... -short

      - name: Run integration tests
        run: go test ./platform/windows/... -run Integration -timeout 300s
```

**Note**: GitHub Actions `windows-latest` runners include WSL2 support. The `wsl --install --no-distribution` command enables WSL2 without installing a default distro.

---

## 13. Security Considerations and Vulnerabilities

### 13.1 WSL2 Security Vulnerabilities

#### CVE-2025-53788 - TOCTOU Privilege Escalation

**Published:** August 2025  
**Severity:** High  
**Affected:** WSL2 versions before 2.5.10

A time-of-check time-of-use (TOCTOU) race condition in the WSL2 kernel allows an authorized local attacker to elevate privileges — potentially gaining SYSTEM or higher effective privileges.

**Mitigation:**
- Require WSL2 version 2.5.10 or later
- Add version check in `detectWSLVersion()`
- Warn users if running vulnerable versions

**Reference:** https://cvefeed.io/vuln/detail/CVE-2025-53788

#### CVE-2025-26675 - WSL Vulnerability

Microsoft security update requiring robust update procedures. Ensure WSL2 is kept up to date.

#### Container Escape Vulnerabilities (2025-2026)

**Critical runC Vulnerabilities (November 2025):**
- CVE-2025-31133, CVE-2025-52565, CVE-2025-52881
- Affect Docker, Kubernetes, and other container platforms
- Allow attackers to bypass security protections and gain host file access

**Implication for agentbox:** These vulnerabilities demonstrate that pure container-based sandboxing is insufficient for AI agents. The WSL2 VM boundary provides necessary hardware-level isolation that containers alone cannot guarantee.

### 13.2 Known Limitations

| # | Limitation | Impact | Mitigation |
|---|-----------|--------|------------|
| 1 | Requires WSL2 installation | Not available on all Windows machines (especially locked-down enterprise) | Clear error message; `FallbackWarn` uses `NopManager` |
| 2 | Cold-start overhead (~1-2s) | First command execution is slower than native Linux | Distro kept running between commands; warm start is near-instant |
| 3 | Shared WSL2 kernel | All WSL2 distros share the same Linux kernel; a kernel exploit affects all | Mitigated by Hyper-V isolation from Windows host |
| 4 | No per-distro resource limits | Cannot limit CPU/memory per distro (VM-wide `.wslconfig` only) | Use `rlimit` inside the sandbox (same as native Linux) |
| 5 | UNC paths not supported | Cannot sandbox projects on network shares | Document limitation; recommend local copies |
| 6 | Administrator for initial WSL2 setup | First-time WSL2 installation requires admin rights | One-time requirement; subsequent use is unprivileged |
| 7 | WSL2 not available on Windows Server | Windows Server does not include WSL2 by default | Document as unsupported; may work with manual WSL2 install |
| 8 | **CVE-2025-53788** | Privilege escalation in WSL2 < 2.5.10 | Enforce minimum version check |

### 13.3 Security Considerations

| # | Limitation | Impact | Mitigation |
|---|-----------|--------|------------|
| 1 | Requires WSL2 installation | Not available on all Windows machines (especially locked-down enterprise) | Clear error message; `FallbackWarn` uses `NopManager` |
| 2 | Cold-start overhead (~1-2s) | First command execution is slower than native Linux | Distro kept running between commands; warm start is near-instant |
| 3 | Shared WSL2 kernel | All WSL2 distros share the same Linux kernel; a kernel exploit affects all | Mitigated by Hyper-V isolation from Windows host |
| 4 | No per-distro resource limits | Cannot limit CPU/memory per distro (VM-wide `.wslconfig` only) | Use `rlimit` inside the sandbox (same as native Linux) |
| 5 | UNC paths not supported | Cannot sandbox projects on network shares | Document limitation; recommend local copies |
| 6 | Administrator for initial WSL2 setup | First-time WSL2 installation requires admin rights | One-time requirement; subsequent use is unprivileged |
| 7 | WSL2 not available on Windows Server | Windows Server does not include WSL2 by default | Document as unsupported; may work with manual WSL2 install |

### 13.2 Security Considerations

1. **WSL interop must be disabled** — Without `interop.enabled=false`, any process inside WSL2 can execute `cmd.exe /c <anything>` to escape to Windows. This is the single most critical security setting.

2. **Windows PATH must not leak** — `appendWindowsPath=false` prevents Windows executables from being callable by name inside WSL2.

3. **Windows drives are automounted read-only** — `automount.enabled=true` with `options="metadata,ro"` mounts Windows drives at `/mnt/c/` etc. in read-only mode. Writable access is granted only to specific paths via bind mounts in the mount namespace.

4. **Non-root user** — The `sandbox` user prevents trivial privilege escalation inside the distro. Combined with `PR_SET_NO_NEW_PRIVS`, the user cannot gain root even via setuid binaries.

5. **Shared kernel risk** — All WSL2 distros run on the same VM kernel. If a sandbox process exploits a kernel vulnerability, it could affect other distros. This is mitigated by:
   - The Hyper-V boundary protecting the Windows host
   - Using a dedicated distro with minimal packages installed
   - Seccomp filtering reducing the kernel attack surface

6. **wsl.exe as the trust boundary** — The Windows host trusts `wsl.exe` to correctly isolate commands. A compromised `wsl.exe` or WSL infrastructure would break isolation. This is an acceptable trust assumption (same as trusting `sandbox-exec` on macOS).

### 13.4 Future Enhancements

1. **Native Windows sandbox (Job Objects + ACLs)** — An alternative implementation that uses Windows-native isolation without WSL2. Lower security but zero additional dependencies. Could complement WSL2 as a fallback.

2. **Per-execution ephemeral distros** — Use `wsl --import-in-place` with pre-built VHDs for instant ephemeral distros. Each execution gets a fresh distro that is discarded after use. Higher security, more overhead.

3. **Windows Sandbox (`wsb.exe`) integration** — Windows 11 24H2+ introduces `wsb.exe` CLI for Windows Sandbox (lightweight VMs). Potential alternative for Windows-native isolation. Current limitation: no process I/O capture.

4. **GPU isolation support** — WSL2 supports GPU passthrough via `wslg`. Future work could add GPU access controls for AI/ML workloads.

5. **cgroup-based resource limits** — When WSL2 supports cgroups v2 per-distro (currently VM-wide only), add fine-grained resource limits.

---

## Appendix D: Industry Reference Implementations

### D.1 Anthropic Sandbox Runtime (Claude Code)

The [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime) is an open-source TypeScript implementation that provides:

- **macOS**: `sandbox-exec` with dynamically generated Seatbelt profiles
- **Linux/WSL2**: bubblewrap with network namespace isolation
- **Dual isolation**: Filesystem (deny-read, allow-write patterns) + Network (proxy-based)
- **Unix socket blocking**: seccomp BPF filters on Linux

**Key design decisions to reference:**
1. Mandatory deny paths (auto-protected files like `.bashrc`, `.zshrc`)
2. Two-stage seccomp application (after proxy setup)
3. HTTP/SOCKS5 proxy for network filtering
4. `enableWeakerNestedSandbox` mode for Docker environments

### D.2 OpenAI Codex CLI

Codex CLI uses platform-specific sandboxing:
- **macOS**: Apple Seatbelt with `sandbox-exec`
- **Linux/WSL2**: Landlock v3 + seccomp + user namespaces

**Known issues:**
- Landlock/seccomp compatibility issues on some WSL2 configurations ([openai/codex#1039](https://github.com/openai/codex/issues/1039))
- Requires kernel features that may not be available in all WSL2 setups

**Lesson:** Pure Landlock approach has compatibility challenges; bubblewrap provides better compatibility.

### D.3 Comparison Summary

| Feature | Claude Code | OpenAI Codex | agentbox (proposed) |
|---------|-------------|--------------|---------------------|
| Windows Strategy | WSL2 + bubblewrap | WSL2 + Landlock | WSL2 + Linux sandbox |
| macOS | Seatbelt | Seatbelt | Seatbelt |
| Linux | bubblewrap | Landlock/seccomp | Namespaces + Landlock + seccomp |
| WSL1 Support | ❌ No | ❌ No | ❌ No |
| WSL2 Support | ✅ Full | ⚠️ Partial | ✅ Full |
| Open Source | ✅ Yes | ✅ Yes | ✅ Yes |
| Implementation | TypeScript | Rust | Go |

### D.4 Sandboxing Technology Spectrum

The AI agent sandboxing landscape (2026) offers multiple isolation technologies:

| Technology | Isolation Level | Startup | Best For |
|------------|----------------|---------|----------|
| **Firecracker MicroVMs** | Hardware-level, dedicated kernel | ~125ms | Gold standard (E2B, Vercel) |
| **Kata Containers** | Hardware-level via VMM | ~200ms | Kubernetes integration |
| **gVisor** | Userspace kernel | Fast | Middle ground (Modal) |
| **Bubblewrap** | Namespaces + seccomp | Fast | Lightweight (Claude Code) |
| **Landlock LSM** | Filesystem access control | Fast | Unprivileged sandboxing |
| **Standard Containers** | Shared kernel | Fastest | Development only |

**agentbox's Position:** Uses bubblewrap-style approach (namespaces + Landlock + seccomp), providing strong isolation with fast startup and broad compatibility — ideal for desktop AI agent use cases.

---

## Appendix E: OWASP Top 10 for Agentic Applications (2026)

The [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) identifies the most critical security risks for autonomous AI systems.

### Relevant Risks for agentbox

| ID | Risk | Description | How agentbox Mitigates |
|----|------|-------------|------------------------|
| **ASI01** | Agent Goal Hijack | Prompt injection altering agent objectives | Sandboxing limits blast radius; filesystem/network boundaries |
| **ASI02** | Tool Misuse | Agents using legitimate tools unsafely | Command classifier with forbidden/escalated categories |
| **ASI05** | Unexpected Code Execution | Unsafe code generation/execution | **Core purpose**: Multi-layer sandbox prevents execution escape |
| **ASI10** | Rogue Agents | Compromised agents acting harmfully | Defense-in-depth: classifier → sandbox → monitoring |

### Key Principle: Least Agency

OWASP emphasizes granting agents only the **minimum autonomy** required for safe, bounded tasks. agentbox implements this through:

1. **Default-deny filesystem access** — writes blocked everywhere unless explicitly allowed
2. **Filtered network access** — only approved domains reachable
3. **Resource limits** — CPU, memory, file descriptor constraints
4. **Command classification** — forbidden commands blocked before execution

### Sandboxing as Primary Defense

OWASP recommends sandboxing as the primary defense against ASI05:

> "Rather than analyzing each user input for maliciousness, it's more effective to run anything in a secure environment."

agentbox's two-tier architecture (WSL2 VM + Linux sandbox) provides this secure environment for Windows users.

---

## 14. Implementation Roadmap

### Phase 1: Foundation (platform/windows core)

**Goal**: Basic WSL2 detection and Simple Mode execution.

- [ ] `platform/detect_windows.go` — Platform registration with `//go:build windows`
- [ ] `platform/detect_other.go` — Update build tag to `!darwin && !linux && !windows`
- [ ] `platform_windows.go` — Root-level platform import
- [ ] `procgroup_windows.go` — Windows process group via `CREATE_NEW_PROCESS_GROUP`
- [ ] `platform/windows/detect.go` — WSL2 availability check, version parsing
- [ ] `platform/windows/paths.go` — Windows ↔ WSL path translation (no build tag)
- [ ] `platform/windows/wsl.go` — `Platform` struct, `New()`, `WrapCommand()` (Simple Mode)
- [ ] Unit tests for path translation and detection

### Phase 2: Distro Management

**Goal**: Automated distro provisioning and hardened configuration.

- [ ] `platform/windows/distro.go` — Alpine rootfs download/embed, `wsl --import`, wsl.conf
- [ ] Sandbox user creation (`adduser -D sandbox`)
- [ ] Lazy initialization with `sync.Once`
- [ ] `Cleanup()` and `Unregister()` implementation
- [ ] Integration tests for distro lifecycle

### Phase 3: Full Sandbox (Tier 2)

**Goal**: Sandbox helper binary with full Linux isolation inside WSL2.

- [ ] `cmd/sandbox-helper/main.go` — Entry point
- [ ] Reuse `platform/linux/` namespace, Landlock, seccomp logic
- [ ] Helper binary installation into distro
- [ ] Full Mode `WrapCommand()` implementation
- [ ] Cross-compilation `Makefile` target
- [ ] Integration tests for filesystem and process isolation

### Phase 4: Network & Proxy

**Goal**: Network isolation and proxy-based filtering inside WSL2.

- [ ] `CLONE_NEWNET` for `NetworkBlocked` mode
- [ ] Proxy host address resolution (mirrored vs. NAT mode)
- [ ] `HTTP_PROXY` / `SOCKS_PROXY` injection
- [ ] DNS resolution configuration
- [ ] Integration tests for network isolation and proxy

### Phase 5: Testing & Polish

**Goal**: Comprehensive test coverage and CI integration.

- [ ] Full unit test coverage (all platforms)
- [ ] Windows CI pipeline (GitHub Actions)
- [ ] Edge case testing (long paths, Unicode, concurrent execution)
- [ ] Performance benchmarking (cold start, warm start, throughput)
- [ ] Documentation and CHANGELOG entry

---

## Appendix A: WSL2 Command Reference

| Command | Purpose |
|---------|---------|
| `wsl --version` | Check WSL version and kernel version |
| `wsl --list --quiet` | List installed distros |
| `wsl --list --verbose` | List distros with state and WSL version |
| `wsl --import <name> <path> <rootfs.tar>` | Create a new distro from rootfs tarball |
| `wsl --import-in-place <name> <vhd-path>` | Register existing VHD as distro (fast) |
| `wsl -d <distro> -e <cmd>` | Execute command directly (no shell wrapping) |
| `wsl -d <distro> -- /bin/sh -c "<cmd>"` | Execute command via shell |
| `wsl -d <distro> --cd <path> -- <cmd>` | Set working directory and execute |
| `wsl --terminate <distro>` | Stop a running distro |
| `wsl --shutdown` | Stop all distros and the WSL2 VM |
| `wsl --unregister <distro>` | Delete a distro and its VHD |

## Appendix B: Security Checklist

Before declaring the Windows platform implementation complete, verify:

- [ ] `interop.enabled=false` is set in every provisioned distro's `wsl.conf`
- [ ] `appendWindowsPath=false` is set — no Windows PATH leakage
- [ ] `automount.enabled=true` with `options="metadata,ro"` is set — Windows drives mounted read-only
- [ ] Default user is `sandbox` (non-root)
- [ ] Helper binary applies `PR_SET_NO_NEW_PRIVS` before exec
- [ ] Helper binary applies seccomp BPF filter
- [ ] Helper binary applies Landlock rules (when ABI ≥ 1)
- [ ] `CLONE_NEWNET` is used for `NetworkBlocked` mode
- [ ] Environment sanitization removes all Windows-specific variables
- [ ] Process termination correctly propagates through wsl.exe to WSL2 processes
- [ ] Integration tests verify filesystem isolation (cannot read/write outside allowed paths)
- [ ] Integration tests verify network isolation (cannot reach network when blocked)

## Appendix C: Comparison with Native Windows Sandbox Alternatives

| Approach | Isolation Level | Dependencies | Startup | Maturity |
|----------|----------------|--------------|---------|----------|
| **WSL2 + Linux sandbox** (this design) | High (Hyper-V + namespaces + Landlock + seccomp) | WSL2 | ~1-2s cold, ~0.1s warm | Production-ready (industry standard) |
| **Windows Job Objects + ACLs** | Medium (process-level, no kernel isolation) | None | Instant | Well-understood, limited isolation |
| **Windows Sandbox (wsb.exe)** | High (dedicated VM) | Win11 24H2+ | ~3-5s | New, limited API |
| **Docker Desktop** | High (container isolation) | Docker Desktop | ~2-3s | Mature, heavy dependency |
| **Hyper-V container** | Very High (full VM) | Hyper-V, enterprise | ~5-10s | Enterprise only |

The WSL2 approach provides the best balance of security, performance, and compatibility for the agentbox use case.

### C.1 Why Not Landlock-Only (like Codex)?

OpenAI Codex uses Landlock v3 + seccomp directly on Linux/WSL2. While this approach is elegant, it has compatibility issues:

1. **Kernel feature detection**: Landlock ABI version detection can fail on some WSL2 configurations
2. **Seccomp availability**: Not all WSL2 kernels have seccomp enabled
3. **User namespace requirements**: Some WSL2 setups disable unprivileged user namespaces

**agentbox's approach** (namespaces + Landlock + seccomp) is more robust because:
- bubblewrap handles feature detection gracefully
- Falls back to available primitives if some are missing
- Better compatibility across different WSL2 configurations

**Landlock vs Seccomp: Complementary Roles**

Per the Linux Kernel documentation:

> "A Landlock rule shall be focused on access control on kernel objects instead of syscall filtering (i.e. syscall arguments), which is the purpose of seccomp-bpf."

| Feature | Landlock LSM | Seccomp BPF |
|---------|--------------|-------------|
| **Scope** | Filesystem access control (inode-level) | Syscall filtering |
| **Privilege** | Unprivileged | Requires CAP_SYS_ADMIN or user namespaces |
| **Stackable** | Yes (with other LSMs) | No |
| **Arguments** | Cannot inspect syscall arguments | Can filter by syscall arguments |

**Best Practice:** Use both together for defense-in-depth:
- Landlock for filesystem access control
- Seccomp for syscall filtering
- Namespaces for process/network isolation

### C.2 Why Not Windows Sandbox (wsb.exe)?

Windows 11 24H2+ introduces `wsb.exe` for Windows Sandbox. While promising:

1. **No process I/O capture**: Cannot capture stdout/stderr from sandboxed processes
2. **Limited API**: No programmatic control over the sandbox lifecycle
3. **Windows 11 only**: Not available on Windows 10

WSL2 provides better integration for agentbox's use case.
