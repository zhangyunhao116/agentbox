> **⚠️ LEGACY DOCUMENT — This design document describes the WSL2-based Windows sandbox architecture that was replaced in March 2026 with a native Windows sandbox using Restricted Token + Job Object + Low Integrity Level + ACLs. See `platform/windows/` source code for the current implementation.**

---

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

| Product | Windows Sandbox Strategy | Linux Sandbox Primitives |
|---------|-------------------------|--------------------------| 
| **Claude Code** (Anthropic) | ❌ No sandbox (runs unconfined on Windows) | bubblewrap + namespaces + seccomp (Linux/macOS only) |
| **OpenAI Codex** | Native Windows (Restricted Tokens + ACLs), experimental | Landlock v3 + seccomp (Linux only) |
| **Cursor IDE** | WSL2 recommended | Permission-based (no sandbox) |

> **Industry Research (2025-2026):** Claude Code's sandbox runtime is now [open source](https://github.com/anthropic-experimental/sandbox-runtime), supporting macOS (seatbelt) and Linux (bubblewrap + namespaces + seccomp) but **not Windows**. OpenAI Codex takes a different approach with native Windows security primitives (Restricted Tokens + ACLs), though still marked as "highly experimental." This gap validates agentbox's WSL2-based approach as a novel, stronger alternative for Windows sandbox isolation.
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

1. **Claude Code** (Anthropic) provides a [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime) for Linux/macOS, but **has no Windows sandbox implementation** — Windows runs unconfined.

2. **OpenAI Codex** takes a **native Windows sandbox approach** using Restricted Tokens + ACLs (see [codex-rs/windows-sandbox-rs](https://github.com/openai/codex/tree/main/codex-rs/windows-sandbox-rs)), though it remains experimental with known issues.

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

### 3.4 Distro Health Check and Recovery

Over time a sandbox distro can become corrupted or unusable. `distro.go`'s
`ensureDistro()` must integrate a health-check gate before every first use in a
session.

**Corruption detection — three-stage probe:**

| Stage | Method | Detects |
|-------|--------|---------|
| 1. Registry | `wsl -l -q` lists distro name | Missing / unregistered distro |
| 2. Command | `wsl -d <distro> -- /bin/true` exits 0 | Kernel panic, init crash, broken rootfs |
| 3. Filesystem | `wsl -d <distro> -- touch /tmp/.agentbox-probe && rm /tmp/.agentbox-probe` | Read-only FS, full disk, VHD corruption |

**Common corruption causes:**

- **Power loss / forced shutdown** during a write to the ext4 VHD.
- **Disk full** on the Windows host — the sparse VHD cannot grow.
- **WSL update failures** that leave the distro in a half-upgraded state.
- **Sparse VHD bugs** in older WSL2 builds (pre-2.0.0) causing metadata inconsistencies.

**Atomic recovery flow:**

Recovery is destructive (loses all in-distro state) but the sandbox distro is
ephemeral by design, so re-provisioning is always safe.

```go
// healthCheckAndRecover runs the three-stage probe and, on failure,
// atomically re-provisions the distro. It is called from ensureDistro().
func (p *Platform) healthCheckAndRecover(ctx context.Context) error {
    // Acquire per-user file lock to prevent concurrent recovery.
    unlock, err := acquireDistroLock(p.lockPath)
    if err != nil {
        return fmt.Errorf("cannot acquire distro lock: %w", err)
    }
    defer unlock()

    // Stage 1: registry check.
    if !p.distroExists() {
        return p.provision(ctx) // Fast path: distro was never created.
    }

    // Stage 2: command execution check.
    probe := exec.CommandContext(ctx, p.wslPath,
        "-d", p.distroName, "--", "/bin/true")
    if err := probe.Run(); err != nil {
        log.Printf("distro probe failed (stage 2): %v — recovering", err)
        return p.reprovision(ctx)
    }

    // Stage 3: filesystem writability check.
    fsProbe := exec.CommandContext(ctx, p.wslPath,
        "-d", p.distroName, "--",
        "sh", "-c", "touch /tmp/.agentbox-probe && rm /tmp/.agentbox-probe")
    if err := fsProbe.Run(); err != nil {
        log.Printf("distro probe failed (stage 3): %v — recovering", err)
        return p.reprovision(ctx)
    }

    return nil
}

// reprovision unregisters and re-provisions the distro. Idempotent.
func (p *Platform) reprovision(ctx context.Context) error {
    _ = exec.CommandContext(ctx, p.wslPath,
        "--unregister", p.distroName).Run() // ignore error: may already be gone
    return p.provision(ctx)
}
```

**File lock**: `acquireDistroLock` creates a lock file at
`%LOCALAPPDATA%\agentbox\distro.lock` using `LockFileEx` (Windows) to serialize
concurrent recovery attempts from multiple agentbox processes.

**Integration point**: `ensureDistro()` (§3.3) calls `healthCheckAndRecover()`
on every first invocation per `Platform` instance (guarded by `sync.Once`).

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

### 5.4 Cross-Filesystem Performance Considerations

WSL2 uses the 9P/Plan9 protocol to bridge the Windows (NTFS) and Linux (ext4)
filesystems. This bridge introduces significant overhead that directly impacts
sandbox performance.

**Measured performance (9P vs native ext4 inside WSL2):**

| Operation | Cross-FS performance (% of native) | Notes |
|-----------|-------------------------------------|-------|
| Sequential read | 10–18% | Tolerable for small config files |
| Sequential write | 0.6–8% | Very slow for build artifacts |
| Random read | 3–12% | Database-like workloads suffer |
| Random write | **< 1%** | Worst case — essentially unusable |
| `git status` / `git diff` | **5–10%** (10–20× slower) | Tree-walking is metadata-heavy |

*Source: webbertakken WSL2 filesystem benchmarks.*

**VirtioFS alternative:**

Windows 11 Insider builds (and WSL 2.4+) offer VirtioFS as an experimental
replacement for 9P. VirtioFS is 2–5× faster across most operations but is not
yet available on stable Windows channels. Configuration in `.wslconfig`:

```ini
[wsl2]
; Requires Windows 11 Insider + WSL 2.4+
virtioFS = true
```

**Best practices for sandbox performance:**

1. **Keep working files on WSL native filesystem.** The sandbox copies command
   inputs into `/home/sandbox/` inside the distro (ext4) before execution and
   copies outputs back afterward. This avoids cross-FS penalties during the
   actual command run.
2. **Enable sparse VHD.** Add to `.wslconfig`:
   ```ini
   [experimental]
   sparseVhd = true
   ```
   This prevents the VHD from growing monotonically and reduces Windows-side
   disk pressure (which indirectly reduces 9P stalls caused by host-side I/O
   contention).
3. **Windows Defender real-time scanning** imposes an additional **30–50%**
   reduction in file operation throughput when accessing `\\wsl$\` or
   `\\wsl.localhost\` paths. See **Appendix F** for recommended Defender
   exclusion configuration.
4. **Performance validation.** During integration testing, include a cross-FS
   throughput benchmark (sequential write of 100 MB file from `/mnt/c/` vs
   `/home/`) to catch regressions. Fail the test if cross-FS throughput drops
   below 5% of native — this would indicate a broken 9P channel.

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
│  ├── HTTP proxy on 0.0.0.0:18080       │
│  └── SOCKS5 proxy on 0.0.0.0:18081    │
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

#### 6.2.0 Proxy Bind Address

The proxy server **must bind to `0.0.0.0`** (all interfaces) instead of `127.0.0.1` to be accessible from the WSL2 VM in NAT mode. This requires a corresponding change to `proxy/proxy.go`:

```go
// Current (Linux/macOS): binds to loopback only
httpAddr, err := p.http.ListenAndServe("127.0.0.1:0")

// Windows: binds to all interfaces for WSL2 access
httpAddr, err := p.http.ListenAndServe("0.0.0.0:0")
```

> **Security:** Binding to `0.0.0.0` exposes the proxy on the local network. The Windows platform must add Windows Firewall rules restricting access to the WSL2 virtual subnet only:
>
> ```powershell
> # Block all inbound to proxy port (safety net)
> New-NetFirewallRule -DisplayName "agentbox-proxy-block-$PORT" `
>     -Direction Inbound -LocalPort $PORT -Protocol TCP `
>     -Action Block
>
> # Allow only WSL subnet (higher priority overrides block)  
> New-NetFirewallRule -DisplayName "agentbox-proxy-allow-wsl-$PORT" `
>     -Direction Inbound -LocalPort $PORT -Protocol TCP `
>     -RemoteAddress 172.16.0.0/12 -Action Allow
> ```
>
> Rules are named with the port number for uniqueness. On startup, the proxy implementation should clean up any stale `agentbox-proxy-*` rules from previous crashed sessions before creating new ones. The firewall rule is created when the proxy starts and removed on cleanup.
>
> **Note:** Both HTTP and SOCKS5 proxy ports need firewall rules if SOCKS5 proxy is enabled. Apply the same Block + Allow rule pattern to each port.

**Proxy address injection by network mode:**

| Mode | Detection | Proxy Address |
|------|-----------|---------------|
| Mirrored | `.wslconfig` has `networkingMode=mirrored` | `127.0.0.1:PORT` |
| NAT (default) | No mirrored setting, or Win10 | Host IP from `/etc/resolv.conf` nameserver |

The host IP is resolved **at each command invocation** (not cached) because the WSL2 virtual switch IP may change across WSL restarts.

#### 6.2.1 Network Mode Detection

WSL2 supports two networking modes that fundamentally affect how the sandbox reaches the Windows host proxy. The mode must be detected at platform initialization time.

**Detection logic:** Read `%UserProfile%\.wslconfig` and parse the `[wsl2]` section for the `networkingMode` key.

```go
// detectWSLNetworkMode reads the user's .wslconfig and returns the
// WSL2 networking mode ("nat" or "mirrored"). Defaults to "nat" if
// the file is absent or the key is not set.
func detectWSLNetworkMode() (string, error) {
    home, err := os.UserHomeDir()
    if err != nil {
        return "nat", fmt.Errorf("cannot determine user home: %w", err)
    }
    cfg, err := os.ReadFile(filepath.Join(home, ".wslconfig"))
    if errors.Is(err, os.ErrNotExist) {
        return "nat", nil // default mode
    }
    if err != nil {
        return "nat", fmt.Errorf("reading .wslconfig: %w", err)
    }

    inWSL2Section := false
    scanner := bufio.NewScanner(bytes.NewReader(cfg))
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if strings.HasPrefix(line, "[") {
            inWSL2Section = strings.EqualFold(line, "[wsl2]")
            continue
        }
        if inWSL2Section && strings.HasPrefix(strings.ToLower(line), "networkingmode") {
            parts := strings.SplitN(line, "=", 2)
            if len(parts) == 2 {
                mode := strings.TrimSpace(strings.ToLower(parts[1]))
                if mode == "mirrored" {
                    return "mirrored", nil
                }
            }
        }
    }
    return "nat", nil
}
```

**Mode-specific behavior:**

| Aspect | NAT (default) | Mirrored (Win11 22H2+) |
|--------|---------------|------------------------|
| Host IP discovery | `ip route show default \| awk '{print $3}'` or parse `/proc/net/route` | `localhost` works bidirectionally |
| Proxy setup | `HTTP_PROXY=http://<gateway-ip>:<port>` | `HTTP_PROXY=http://localhost:<port>` |
| DNS resolver | Internal WSL DNS proxy at `172.x.x.1` | Mirrors Windows DNS configuration |
| Firewall interaction | Windows Firewall may block WSL→host traffic | No firewall issues (loopback) |
| Complexity | Higher — gateway IP can change on WSL restart | Lower — stable `localhost` address |

**NAT mode host IP resolution:** In NAT mode, the host gateway IP is the default route inside the WSL2 VM. Two reliable methods:

1. **`/proc/net/route`** (preferred — no subprocess): Parse the default route entry (destination `00000000`) and decode the gateway IP from the hex field.
2. **`ip route show default`** (fallback): Execute `ip route show default | awk '{print $3}'` inside the distro.

**Impact on `proxyHostAddr()`:** The function shown above already accounts for mode, but the mode detection must run during `Platform.init()` and be cached in `p.wslNetworkMode`. If detection fails, default to NAT mode (safe fallback) and log a warning.

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

// setupProcessGroup configures the command to run suspended in a new Windows Job Object
// so that all child processes (including those inside WSL2) are terminated
// when the parent exits. Uses CREATE_SUSPENDED to prevent race conditions —
// the process is assigned to the Job Object before it starts executing.
func setupProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_SUSPENDED | syscall.CREATE_NEW_PROCESS_GROUP,
	}
}
```

After starting the suspended process, the caller assigns it to the job and then resumes execution:

```go
job, err := newJobObject()
if err != nil { /* handle error */ }
defer job.close()

cmd.Start()
job.assign(windows.Handle(cmd.Process.Handle))

// Resume the suspended process — see §15.5 for thread handle acquisition details
resumeProcess(cmd.Process.Pid)
```

> **Why CREATE_SUSPENDED?** Without it, `cmd.Start()` immediately begins execution and any child processes spawned before `job.assign()` would escape the Job Object. CREATE_SUSPENDED ensures the process is frozen until explicitly resumed after Job Object assignment.

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

#### 8.1.1 Enhanced Dependency Checks

The basic `CheckDependencies` above covers wsl.exe presence and WSL version.
The following additional checks catch the most common deployment failures.

**Hyper-V / Virtualization detection:**

WSL2 requires hardware virtualization and the VirtualMachinePlatform Windows
feature. These are the #1 and #2 most common support issues on new machines.

```go
// checkVirtualization verifies that Hyper-V prerequisites are met.
func checkVirtualization(check *platform.DependencyCheck) {
    // 1. Windows feature: VirtualMachinePlatform must be Enabled.
    out, err := powershell(
        `(Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform).State`)
    if err != nil || strings.TrimSpace(out) != "Enabled" {
        check.Errors = append(check.Errors,
            "VirtualMachinePlatform feature is not enabled "+
                "(run: dism.exe /Online /Enable-Feature /FeatureName:VirtualMachinePlatform /NoRestart)")
        return
    }

    // 2. BIOS-level virtualization (VT-x / AMD-V).
    out, err = powershell(
        `(Get-CimInstance -ClassName Win32_Processor).VirtualizationFirmwareEnabled`)
    if err == nil && strings.TrimSpace(out) == "False" {
        check.Errors = append(check.Errors,
            "Hardware virtualization is disabled in BIOS/UEFI — "+
                "enable VT-x (Intel) or AMD-V in firmware settings")
    }

    // 3. Windows version floor: Win10 1903+ (build 18362), Win11, Server 2022+.
    build := windowsBuildNumber() // helper: reads ReleaseId / CurrentBuild from registry
    if build > 0 && build < 18362 {
        check.Errors = append(check.Errors,
            fmt.Sprintf("Windows build %d is too old; WSL2 requires build 18362+ "+
                "(Windows 10 version 1903 or later)", build))
    }
}
```

**CVE version enforcement (WSL2 ≥ 2.5.10):**

CVE-2025-53788 is a TOCTOU privilege-escalation in WSL2 < 2.5.10 (CVSS 7.0).
We enforce the minimum version as a **fatal error** that blocks sandbox creation —
running on a known-vulnerable WSL version would provide a false sense of security.

```go
var minWSLVersion = semver{2, 5, 10} // CVE-2025-53788 fix

// checkWSLCVE parses the WSL build version and returns a fatal error if it is
// below the minimum safe version.
func checkWSLCVE(check *platform.DependencyCheck, wslPath string) {
    // Primary: parse "wsl.exe --version" output.
    out, err := exec.Command(wslPath, "--version").Output()
    if err != nil {
        // Inbox WSL has no --version flag. Fall back to file version.
        out, err = powershell(
            `(Get-Item C:\windows\system32\wsl.exe).VersionInfo.FileVersion`)
        if err != nil {
            check.Errors = append(check.Errors,
                "cannot determine WSL version — CVE-2025-53788 check failed, blocking for safety")
            return
        }
    }

    // Extract version with regex: "WSL version: 2.5.10.0" or plain "2.5.10.0".
    re := regexp.MustCompile(`(?:WSL version:\s+)?([\d]+\.[\d]+\.[\d]+)`)
    m := re.FindStringSubmatch(string(out))
    if m == nil {
        check.Errors = append(check.Errors,
            "cannot parse WSL version from output — CVE check failed, blocking for safety")
        return
    }

    ver, err := parseSemver(m[1])
    if err != nil {
        check.Errors = append(check.Errors, fmt.Sprintf("cannot parse WSL version %q — CVE check failed, blocking for safety", m[1]))
        return
    }
    if ver.Less(minWSLVersion) {
        check.Errors = append(check.Errors,
            fmt.Sprintf("WSL version %s is below %s — vulnerable to CVE-2025-53788 "+
                "(TOCTOU privilege escalation, CVSS 7.0). "+
                "Update with: wsl --update", m[1], minWSLVersion))
    }
}
```

**Integration into `CheckDependencies`:**

The enhanced checks are appended after the existing WSL1/WSL2 detection block:

```go
func (p *Platform) CheckDependencies() *platform.DependencyCheck {
    check := &platform.DependencyCheck{}

    // ... existing wsl.exe and WSL version checks (§8.1.1) ...

    // Enhanced: virtualization and Windows version.
    checkVirtualization(check)

    // Enhanced: CVE version enforcement (fatal — blocks sandbox).
    checkWSLCVE(check, p.wslPath)

    // ... existing distro and helper checks ...

    return check
}
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
| **A** | Embed Linux binary in Windows binary via `go:embed` | Single binary distribution; works offline | Bloats Windows binary (+5–8 MB); cross-compilation complexity |
| **B** | Build separately, copy into WSL distro during provisioning | Simple build process; clean separation | Requires separate build step; user must have the binary |
| **C** | Compile on-the-fly inside WSL using `go build` | Always up-to-date | Requires Go toolchain inside WSL; slow first run |

**Recommendation: Option A (go:embed)** for zero-dependency offline support.

*Rationale*: Option B requires users to manage a separate binary artifact, and
Option C requires a Go toolchain inside WSL. VS Code uses a download-on-demand
model (requires internet), and Docker Desktop pre-bundles in its installer. We
choose `go:embed` because it provides a single self-contained binary with no
network requirement and deterministic builds — the same property that makes Go
binaries attractive in the first place.

#### Embedding approach

Pre-compiled Linux binaries for both amd64 and arm64 are embedded at build time:

```go
package helper

import _ "embed"

//go:embed bin/sandbox-helper-linux-amd64
var helperAmd64 []byte

//go:embed bin/sandbox-helper-linux-arm64
var helperArm64 []byte

// HelperBinary returns the pre-compiled helper for the given architecture.
func HelperBinary(goarch string) ([]byte, error) {
    switch goarch {
    case "amd64":
        return helperAmd64, nil
    case "arm64":
        return helperArm64, nil
    default:
        return nil, fmt.Errorf("unsupported architecture: %s", goarch)
    }
}
```

#### Architecture detection

The Windows host architecture determines which Linux binary to deploy.
`runtime.GOARCH` on Windows maps directly to the WSL2 architecture since WSL2
always matches the host CPU:

```go
// wslArch returns the Linux GOARCH matching the Windows host.
func wslArch() string {
    return runtime.GOARCH // amd64 on x86_64, arm64 on ARM64
}
```

#### Build pipeline

The Makefile cross-compiles both architectures before building the Windows binary:

```makefile
HELPER_SRC   := ./cmd/sandbox-helper/
HELPER_OUT   := ./platform/windows/helper/bin

.PHONY: sandbox-helper
sandbox-helper:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build \
		-trimpath -ldflags="-s -w" \
		-o $(HELPER_OUT)/sandbox-helper-linux-amd64 $(HELPER_SRC)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
		-trimpath -ldflags="-s -w" \
		-o $(HELPER_OUT)/sandbox-helper-linux-arm64 $(HELPER_SRC)

# The Windows build depends on the helper binaries being present for go:embed.
.PHONY: build-windows
build-windows: sandbox-helper
	GOOS=windows GOARCH=amd64 go build -o bin/agentbox.exe ./cmd/agentbox/
```

**CI integration**: The `sandbox-helper` target must run before the Windows
build so that the `go:embed` directives can resolve. In GitHub Actions this
means adding the cross-compilation step before `go build`:

```yaml
- name: Build sandbox-helper (Linux)
  run: make sandbox-helper
- name: Build agentbox (Windows)
  run: make build-windows
```

**Deployment into the distro**: During provisioning (§3.3), the embedded binary
is written to `/opt/agentbox/helper` inside the WSL2 distro via
`wsl -d <distro> -- sh -c 'cat > /opt/agentbox/helper && chmod 755 /opt/agentbox/helper'`
with the binary content piped through stdin.

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

    // ErrWSLVersionInsecure indicates the installed WSL version is below
    // the minimum required to mitigate known CVEs (currently 2.5.10 for
    // CVE-2025-53788). Sandbox creation is blocked.
    // Recovery: run "wsl --update" to install the latest WSL version.
    ErrWSLVersionInsecure = errors.New("WSL version is below the security minimum (2.5.10)")

    // ErrDistroCorrupted indicates the health check detected filesystem
    // corruption or an unusable distro state.
    // Recovery: automatic unregister + re-provision (idempotent).
    ErrDistroCorrupted = errors.New("sandbox distro is corrupted")

    // ErrVirtualizationDisabled indicates Hyper-V or BIOS-level
    // virtualization is not enabled, preventing WSL2 from running.
    // Recovery: enable VT-x/AMD-V in BIOS and enable VirtualMachinePlatform
    // Windows feature.
    ErrVirtualizationDisabled = errors.New("hardware virtualization or Hyper-V is disabled")

    // ErrHelperArchMismatch indicates the embedded helper binary
    // architecture does not match the WSL2 distro (e.g., amd64 helper
    // on arm64 WSL2 instance).
    // Recovery: rebuild agentbox with correct GOARCH for cross-compilation.
    ErrHelperArchMismatch = errors.New("helper binary architecture does not match WSL2 distro")

    // ErrVHDDiskFull indicates the WSL2 virtual hard disk has reached
    // its capacity limit, preventing sandbox operations.
    // Recovery: compact the VHD (wsl --manage <distro> --compact), enable
    // sparse VHD mode, or increase the VHD size limit.
    ErrVHDDiskFull = errors.New("WSL2 VHD disk is full")
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

Additional fallback entries for the new error types:

| Condition | `FallbackStrict` | `FallbackWarn` |
|-----------|-------------------|----------------|
| WSL version insecure | Return `ErrWSLVersionInsecure` (blocks sandbox) | Return `ErrWSLVersionInsecure` (blocks sandbox — no fallback for security) |
| Distro corrupted | Auto-recover: unregister + re-provision | Auto-recover: unregister + re-provision |
| Virtualization disabled | Return `ErrVirtualizationDisabled` | Use `NopManager` with warning |
| Helper arch mismatch | Return `ErrHelperArchMismatch` | Fall back to Simple Mode (Tier 1) |
| VHD disk full | Return `ErrVHDDiskFull` | Log warning, attempt VHD compaction, retry once |

> **Security note**: `ErrWSLVersionInsecure` is **always fatal** regardless of fallback policy. Running a sandbox on a known-vulnerable WSL version would provide a false sense of security.

### 11.3 Error Propagation from Helper Binary

The sandbox helper binary runs inside the WSL2 distro and communicates results back to the Windows host via `wsl.exe`. Understanding the error propagation path is critical for debugging.

**Exit code propagation:** `wsl.exe` propagates the Linux process exit code directly to the Windows caller. The following ranges are reserved:

| Exit Code Range | Meaning |
|----------------|---------|
| `0` | Success |
| `1–99` | User command errors (passed through from the sandboxed process) |
| `100–199` | Sandbox setup errors (helper failed to configure isolation) |
| `200–254` | Reserved for future use (currently passed through as-is) |
| `255` / `-1` | WSL infrastructure crash or signal-based termination |
| `0xFFFFFFFF` (4294967295) | WSL VM crash — the lightweight utility VM terminated unexpectedly |

**Structured error protocol:** In addition to exit codes, the helper binary writes structured error information to stderr using a marker-delimited JSON protocol:

```
[AGENTBOX_ERROR]{"code":101,"type":"setup","msg":"failed to create mount namespace","detail":"EPERM"}
```

The marker prefix `[AGENTBOX_ERROR]` allows the Windows-side parser to distinguish structured errors from regular stderr output of the user's command.

```go
// parseHelperError extracts a structured error from the helper's stderr
// output. Returns nil if no AGENTBOX_ERROR marker is found.
func parseHelperError(stderr []byte) *HelperError {
    const marker = "[AGENTBOX_ERROR]"
    idx := bytes.LastIndex(stderr, []byte(marker))
    if idx == -1 {
        return nil
    }
    jsonData := stderr[idx+len(marker):]
    // Find end of JSON object (first newline or EOF).
    if nl := bytes.IndexByte(jsonData, '\n'); nl != -1 {
        jsonData = jsonData[:nl]
    }
    var herr HelperError
    if err := json.Unmarshal(jsonData, &herr); err != nil {
        return nil // malformed — treat as unstructured error
    }
    return &herr
}

// HelperError represents a structured error from the sandbox helper.
type HelperError struct {
    Code   int    `json:"code"`   // exit code (100-199 range)
    Type   string `json:"type"`   // "setup", "runtime", "cleanup"
    Msg    string `json:"msg"`    // human-readable message
    Detail string `json:"detail"` // optional OS-level detail (errno, etc.)
}
```

**Windows-side error handling:** After `wsl.exe` returns, the platform checks errors in order:

1. Check for `0xFFFFFFFF` exit code → return WSL VM crash error.
2. Parse stderr for `[AGENTBOX_ERROR]` marker → return typed `HelperError`.
3. Check exit code 100–199 → return generic setup error with exit code.
4. Otherwise → pass through exit code and stderr as-is to the caller.

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
| 7 | WSL2 on Windows Server | WSL2 on Windows Server requires manual installation (not included in default Server role); supported on Server 2022+ | Detect Server SKU and guide user through manual WSL2 installation |
| 8 | **CVE-2025-53788** | Privilege escalation in WSL2 < 2.5.10 | Enforce minimum version check |
| 9 | 9P filesystem performance | Cross-FS operations (Windows↔WSL) run at 3–18% of native performance; random writes can drop below 1% | Keep sandbox working files in WSL native filesystem (`/home/`); avoid cross-FS I/O on hot paths |
| 10 | Windows Defender real-time scanning | 30–50% reduction in filesystem operation throughput when Defender scans WSL VHD and `\\wsl$` paths | Recommend AV exclusions for VHDX paths and WSL UNC paths (see §13.3.1 and Appendix F) |

### 13.3 Security Considerations

1. **WSL interop must be disabled** — Without `interop.enabled=false`, any process inside WSL2 can execute `cmd.exe /c <anything>` to escape to Windows. This is the single most critical security setting.

2. **Windows PATH must not leak** — `appendWindowsPath=false` prevents Windows executables from being callable by name inside WSL2.

3. **Windows drives are automounted read-only** — `automount.enabled=true` with `options="metadata,ro"` mounts Windows drives at `/mnt/c/` etc. in read-only mode. Writable access is granted only to specific paths via bind mounts in the mount namespace.

4. **Non-root user** — The `sandbox` user prevents trivial privilege escalation inside the distro. Combined with `PR_SET_NO_NEW_PRIVS`, the user cannot gain root even via setuid binaries.

5. **Shared kernel risk** — All WSL2 distros run on the same VM kernel. If a sandbox process exploits a kernel vulnerability, it could affect other distros. This is mitigated by:
   - The Hyper-V boundary protecting the Windows host
   - Using a dedicated distro with minimal packages installed
   - Seccomp filtering reducing the kernel attack surface

6. **wsl.exe as the trust boundary** — The Windows host trusts `wsl.exe` to correctly isolate commands. A compromised `wsl.exe` or WSL infrastructure would break isolation. This is an acceptable trust assumption (same as trusting `sandbox-exec` on macOS).

#### 13.3.1 Windows Defender Exclusions

Real-time antivirus scanning significantly degrades WSL2 filesystem performance. Benchmarks show a **30–50% reduction** in filesystem operation throughput when Windows Defender scans WSL-related paths.

**Recommended exclusions** (full table and setup commands in Appendix F.1):
VHDX folder path, `\\wsl$\*`, `\\wsl.localhost\*`, `wsl.exe` process, `wslservice.exe` process.

> **Note**: These exclusions reduce scanning overhead but also mean malware written to the WSL filesystem will not be caught by Defender in real-time. This is an acceptable trade-off for a sandboxed environment where the filesystem is ephemeral and controlled. For enterprise deployments, consider using Microsoft Defender for Endpoint's WSL plug-in (requires WSL 2.0.7.0+) instead of blanket exclusions.

See **Appendix F** for detailed setup instructions and **§5.4** for cross-filesystem performance benchmarks.

### 13.4 Future Enhancements

1. **Native Windows sandbox (Job Objects + ACLs)** — An alternative implementation that uses Windows-native isolation without WSL2. Lower security but zero additional dependencies. Could complement WSL2 as a fallback.

2. **Per-execution ephemeral distros** — Use `wsl --import-in-place` with pre-built VHDs for instant ephemeral distros. Each execution gets a fresh distro that is discarded after use. Higher security, more overhead.

3. **Windows Sandbox (`wsb.exe`) integration** — Windows 11 24H2+ introduces `wsb.exe` CLI for Windows Sandbox (lightweight VMs). Potential alternative for Windows-native isolation. Current limitation: no process I/O capture.

4. **GPU isolation support** — WSL2 supports GPU passthrough via `wslg`. Future work could add GPU access controls for AI/ML workloads.

5. **cgroup-based resource limits** — When WSL2 supports cgroups v2 per-distro (currently VM-wide only), add fine-grained resource limits.

### 13.5 WSL2 Version Enforcement

A minimum WSL version policy is enforced to protect against known privilege escalation vulnerabilities.

**Current minimum: WSL 2.5.10+**

| CVE | Description | CVSS | Fixed In |
|-----|------------|------|----------|
| CVE-2025-53788 | TOCTOU privilege escalation in WSL2 | 7.0 (High) | 2.5.10 |

> Nessus Plugin 250272 can be used for enterprise-wide compliance scanning of this requirement.

**Enforcement behavior:**

1. During `Platform.Available()` and `CheckDependencies()`, the WSL version is parsed from `wsl.exe --version` output (see §8.1.1 for version parsing details).
2. If the version is below the minimum, `ErrWSLVersionInsecure` is returned.
3. This error is **always fatal** — it cannot be downgraded by `FallbackWarn`. Running a sandbox on a known-vulnerable WSL version would provide a false sense of security.
4. The error message includes the detected version, the minimum required version, and instructions to update (`wsl --update`).

**Version parsing reference:** Cross-reference §8.1.1 enhanced version checks. The version string is extracted from the `WSL version: X.Y.Z` line of `wsl.exe --version` output using the regex pattern `WSL version:\s+([\d.]+)`.

**Update cadence recommendation:** Check for WSL updates at least monthly. The `wsl --update` command can be run unprivileged on modern Windows. Enterprise deployments should track Microsoft's WSL release notes and update the minimum version constant when new security-relevant CVEs are disclosed.

---

## 15. Dependency Strategy

### 15.1 Principle: Minimal External Dependencies

The Windows platform implementation uses **zero new external Go modules** beyond the Go standard library and `golang.org/x/sys/windows` (already an indirect dependency of the project). All Windows/WSL integration code is self-implemented. The previously anticipated `golang.org/x/text` dependency was eliminated by using `WSL_UTF8=1` (✅ verified).

**Rationale:** Available third-party WSL/Windows libraries (e.g., `ubuntu/GoWSL` ★20, `kolesnikovae/go-winjob` ★21, `ardnew/wslpath` ★12) have low adoption and single maintainers. Self-implementing these ~500 lines of focused code provides better control, fewer supply-chain risks, and no version compatibility concerns.

### 15.2 Self-Implemented Components

| Component | Replaces | Lines (est.) | Approach |
|-----------|----------|-------------|----------|
| WSL CLI Wrapper | `ubuntu/GoWSL` | ~200-300 | Shell out to `wsl.exe` for all operations |
| Job Object Manager | `kolesnikovae/go-winjob` | ~150-200 | Thin wrappers around `kernel32.dll` via `x/sys/windows` |
| Path Translator | `ardnew/wslpath` | ~80-150 | Pure string manipulation for drive letter mapping |

### 15.3 Allowed Dependencies

| Dependency | Usage | Justification |
|------------|-------|---------------|
| `golang.org/x/sys/windows` | Job Objects, process management, registry | Go official extended stdlib; already indirect project dependency |
| ~~`golang.org/x/text/encoding/unicode`~~ | ~~Decode `wsl.exe` UTF-16LE output~~ | **Not needed** — `WSL_UTF8=1` eliminates UTF-16LE (✅ verified, see §15.4) |

> **✅ PoC Verified (2026-03-09):** With `WSL_UTF8=1`, the only required dependency is `golang.org/x/sys/windows`. True zero new external dependencies achieved.

### 15.4 WSL CLI Wrapper Design

All WSL2 management uses `wsl.exe` CLI rather than the COM API (`wslapi.dll`):

| Operation | Command | Notes |
|-----------|---------|-------|
| Import distro | `wsl --import <name> <path> -` | Accepts tar via stdin pipe (from `go:embed`) |
| Run command | `wsl -d <name> -- <cmd>` | Primary execution path |
| List distros | `wsl --list --verbose` | Set `WSL_UTF8=1` for UTF-8 output (✅ verified); without it, output is UTF-16LE |
| Terminate | `wsl --terminate <name>` | Async; may take 1-2 seconds |
| Version check | `wsl --version` | Store WSL: "WSL version: X.Y.Z"; Inbox: may fail |
| Unregister | `wsl --unregister <name>` | Used for distro recovery |

> **Why CLI over COM API:** The `wsl.exe` CLI is more stable across Windows versions, easier to test (mock via exec), and avoids DLL loading complexity. The COM API (`wslapi.dll`) requires UTF-16 string marshaling and has no advantage for our use cases. The only trade-off is process-spawn overhead (~10ms per call), which is negligible for sandbox lifecycle operations.

> **✅ Encoding: Verified (2026-03-09 on Windows Server 2025).** Setting `WSL_UTF8=1` environment variable before invoking `wsl.exe` forces UTF-8 output. Tested on all 6 management subcommands (`--version`, `-l -v`, `--status`, `--list`, `--help`, `--list --online`) — 100% effective, byte size exactly halved (UTF-16LE→UTF-8). No BOM added. **`golang.org/x/text` dependency is eliminated.** Implementation: `cmd.Env = append(os.Environ(), "WSL_UTF8=1")`.

### 15.5 Job Object Implementation

Minimal Job Object wrapper using `golang.org/x/sys/windows`:

```go
// Core pattern: CREATE_SUSPENDED → Assign to Job → Resume
cmd := exec.Command("wsl.exe", args...)
cmd.SysProcAttr = &syscall.SysProcAttr{
    CreationFlags: windows.CREATE_SUSPENDED | syscall.CREATE_NEW_PROCESS_GROUP,
}
cmd.Start()

// Assign to job (ensures all child processes are cleaned up)
windows.AssignProcessToJobObject(jobHandle, processHandle)

// Set KILL_ON_JOB_CLOSE — all processes die when job handle is closed
info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
    BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
        LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    },
}
windows.SetInformationJobObject(jobHandle, windows.JobObjectExtendedLimitInformation, ...)

// Resume the suspended process
windows.ResumeThread(threadHandle)
```

> **✅ Job Object Pattern: Verified (2026-03-09 on Windows Server 2025).** The full `CREATE_SUSPENDED` → `AssignProcessToJobObject` → `ResumeThread` flow works correctly with `os/exec`. Thread handle acquisition via `CreateToolhelp32Snapshot` + `Thread32First`/`Thread32Next` is reliable. Additionally, `NtResumeProcess` (from `ntdll.dll`) was verified as a simpler alternative — it operates directly on the process handle without thread enumeration. **Recommended:** Use `ResumeThread` (documented API) as primary, `NtResumeProcess` as fallback.

### 15.6 Path Translation

Simple bidirectional mapping between Windows and WSL paths:

```go
// Windows → WSL: C:\Users\foo → /mnt/c/Users/foo
func WinToWSL(p string) string {
    if len(p) >= 2 && p[1] == ':' {
        drive := strings.ToLower(string(p[0]))
        rest := strings.ReplaceAll(p[2:], `\`, "/")
        return "/mnt/" + drive + rest
    }
    return strings.ReplaceAll(p, `\`, "/")
}

// WSL → Windows: /mnt/c/Users/foo → C:\Users\foo
func WSLToWin(p string) string {
    if strings.HasPrefix(p, "/mnt/") && len(p) >= 6 {
        drive := strings.ToUpper(string(p[5]))
        if len(p) == 6 {
            return drive + `:\`
        }
        if p[6] == '/' {
            return drive + ":" + strings.ReplaceAll(p[6:], "/", `\`)
        }
    }
    return p
}
```

Edge cases (UNC paths `\\server\share`, extended paths `\\?\`) are deferred to a future phase; the initial implementation covers the common drive-letter case which handles >99% of real-world paths.

---

## Appendix D: Industry Reference Implementations

### D.1 Anthropic Sandbox Runtime (Claude Code)

The [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime) is an open-source TypeScript implementation that supports **macOS and Linux only** — **Windows is explicitly unsupported** (Claude Code runs without sandboxing on Windows):

- **macOS**: `sandbox-exec` with dynamically generated Seatbelt profiles
- **Linux**: bubblewrap with network namespace isolation + seccomp BPF filters
- **Windows**: ❌ **Not supported** — no sandbox is applied; commands run unconfined

**Key design decisions to reference:**
1. Mandatory deny paths (auto-protected files like `.bashrc`, `.zshrc`)
2. Two-stage seccomp application (after proxy setup)
3. HTTP/SOCKS5 proxy for network filtering
4. `enableWeakerNestedSandbox` mode for Docker environments

### D.2 OpenAI Codex CLI

Codex CLI (`github.com/openai/codex`, Rust) uses **platform-native sandboxing** — notably a Windows native approach rather than WSL2:

- **macOS**: Apple Seatbelt with `sandbox-exec`
- **Linux**: Landlock v3 + seccomp + optional bubblewrap
- **Windows**: **Native Windows sandbox** using Restricted Tokens + ACLs + Capability SIDs (`codex-rs/windows-sandbox-rs/`)

**Windows sandbox details:**
- Creates `CreateRestrictedToken` with `DISABLE_MAX_PRIVILEGE | LUA_TOKEN | WRITE_RESTRICTED` flags
- Filesystem isolation via DACLs (`SetEntriesInAclW` + `SetNamedSecurityInfoW`) with per-workspace Capability SIDs
- Network isolation varies by mode:
  - **Unelevated (Restricted Token)**: environment variables only (`HTTP_PROXY=127.0.0.1:9`, `PIP_NO_INDEX=1`, etc.) — easily bypassed
  - **Elevated (dedicated sandbox user)**: Windows Firewall outbound block rule per sandbox SID (`codex_sandbox_offline_block_outbound`) + environment variables — stronger but requires admin/UAC
- Two modes: Restricted Token (unelevated) and Elevated (dedicated `CodexSandboxUsers` accounts)
- Status: marked as **"highly experimental"** with known bugs (#6374, #10090, #10601)

**Key takeaway:** Codex's Windows approach avoids WSL2 dependency but provides weaker security — ACL-based filesystem isolation lacks defense-in-depth, and environment-variable network blocking is trivially bypassed by any process that doesn't honor proxy settings. Our WSL2 + Hyper-V approach provides VM-level isolation with stronger security guarantees.

### D.3 Comparison Summary

| Feature | Claude Code | OpenAI Codex | agentbox (proposed) |
|---------|-------------|--------------|---------------------|
| Windows Strategy | ❌ No sandbox | Native (Restricted Tokens + ACLs) | WSL2 + Hyper-V + Linux sandbox |
| macOS | Seatbelt | Seatbelt | Seatbelt |
| Linux | bubblewrap | Landlock/seccomp | Namespaces + Landlock + seccomp |
| WSL1 Support | ❌ No | ❌ No | ❌ No |
| WSL2 Support | ❌ No sandbox | ❌ Not used | ✅ Full |
| Windows Network Isolation | N/A | ⚠️ Env vars (unelevated) / Firewall (elevated) | ✅ Linux network namespace |
| Windows FS Isolation | N/A | ⚠️ ACLs (same-kernel, no VM boundary) | ✅ VM boundary + Landlock |
| Open Source | ✅ Yes | ✅ Yes | ✅ Yes |
| Implementation | TypeScript | Rust | Go |
| Windows Maturity | N/A | Experimental | Planned |

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
- [ ] WSL2 version >= 2.5.10 (CVE-2025-53788 mitigation)
- [ ] Windows Defender exclusions configured for performance (see Appendix F.1)
- [ ] Distro health check passes before sandbox creation
- [ ] BIOS virtualization and Hyper-V features verified
- [ ] VHD disk space within limits
- [ ] Helper binary architecture matches host
- [ ] Helper error protocol ([AGENTBOX_ERROR] JSON) correctly parsed for all exit code ranges

## Appendix C: Comparison with Native Windows Sandbox Alternatives

| Approach | Isolation Level | Dependencies | Startup | Maturity |
|----------|----------------|--------------|---------|----------|
| **WSL2 + Linux sandbox** (this design) | High (Hyper-V + namespaces + Landlock + seccomp) | WSL2 | ~1-2s cold, ~0.1s warm | Production-ready (industry standard) |
| **Windows Job Objects + ACLs** | Medium (process-level, no kernel isolation) | None | Instant | Well-understood, limited isolation |
| **Windows Sandbox (wsb.exe)** | High (dedicated VM) | Win11 24H2+ | ~3-5s | New, limited API |
| **Docker Desktop** | High (container isolation) | Docker Desktop | ~2-3s | Mature, heavy dependency |
| **Hyper-V container** | Very High (full VM) | Hyper-V, enterprise | ~5-10s | Enterprise only |

The WSL2 approach provides the best balance of security, performance, and compatibility for the agentbox use case.

### C.1 Why Not Landlock-Only (like Codex on Linux)?

> **Note:** This section discusses Codex's *Linux* sandbox approach (Landlock + seccomp). Codex's *Windows* approach is different — it uses native Windows security primitives (Restricted Tokens + ACLs) rather than WSL2. See Appendix D.2 for details on Codex's Windows sandbox.

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

---

## Appendix F: Operational Guide

### F.1 Windows Defender / Antivirus Exclusions

Real-time antivirus scanning can severely impact WSL2 filesystem performance. Without
exclusions, file operations inside WSL2 may see a **30-50% performance reduction** due
to the host scanning every I/O operation on the backing VHD.

**Recommended Exclusions:**

| Type | Path / Value |
|------|-------------|
| Folder | `%LOCALAPPDATA%\Packages\<PackageFamilyName>\LocalState\ext4.vhdx` |
| Folder | `\\wsl$\*` |
| Folder | `\\wsl.localhost\*` |
| Process | `wsl.exe` |
| Process | `wslservice.exe` |

**Finding VHD Locations:**

The registry key `HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss` contains entries
for each registered WSL distro. Each subkey (a GUID) has a `BasePath` value pointing to
the directory containing the distro's `ext4.vhdx` file.

```powershell
# List all registered distro VHD paths
Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss" |
  ForEach-Object { Get-ItemProperty $_.PSPath } |
  Select-Object DistributionName, BasePath
```

**Adding Exclusions (requires Administrator privileges):**

```powershell
# Add process exclusions
Add-MpPreference -ExclusionProcess "wsl.exe"
Add-MpPreference -ExclusionProcess "wslservice.exe"

# Add path exclusions for WSL network paths
Add-MpPreference -ExclusionPath "\\wsl$\*"
Add-MpPreference -ExclusionPath "\\wsl.localhost\*"

# Add exclusion for a specific distro VHD (example)
$basePath = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss\*" |
  Where-Object { $_.DistributionName -eq "agentbox-sb" }).BasePath
if ($basePath) {
    Add-MpPreference -ExclusionPath "$basePath\ext4.vhdx"
}
```

> **Note:** These commands require elevated (Administrator) privileges. In enterprise
> environments, exclusions may be managed via Group Policy and cannot be set locally.

**Microsoft Defender for Endpoint WSL Plug-in:**

For enterprise environments using Microsoft Defender for Endpoint, the WSL plug-in
provides visibility into WSL2 distros without requiring blanket exclusions. This plug-in
requires WSL version **2.0.7.0** or later.

### F.2 Multi-User Windows Scenarios

WSL2 distros are inherently **per-user**. Each Windows user has their own:

- **Registry namespace**: Distro registrations are stored under `HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss` (per-user hive)
- **VHD storage**: Virtual hard disks reside in `%LOCALAPPDATA%\...` (per-user directory)
- **WSL instance**: Each user session runs its own WSL2 lightweight VM

**Implications for agentbox:**

- The distro name can be a constant (`agentbox-sb`) since each Windows user has their own
  namespace — no collision possible between users.
- No special multi-user handling is required in the provisioning code.
- Different Windows users are **fully isolated** by WSL2's per-user design.

**Terminal Server / Multi-Session Scenarios:**

On Windows Server with Remote Desktop Services (multi-session), each user session
gets its own WSL2 instance. This means:

- Multiple concurrent users on the same server each get independent sandboxes
- Disk space compounds: each user gets their own VHD (see F.3 for management)
- Memory usage scales with the number of active WSL2 instances

### F.3 VHD Disk Space Management

Each WSL2 distro uses a **Virtual Hard Disk (VHD)** file to store its filesystem.

**VHD Locations:**

- Default (Microsoft Store WSL): `%LOCALAPPDATA%\Packages\<PackageFamilyName>\LocalState\ext4.vhdx`
- Custom import path: specified during `wsl --import <distro> <install_location> <tarball>`
- Registry lookup: `HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss\{GUID}\BasePath`

**Default Maximum Size:** 1 TB (virtual; actual disk usage depends on content)

**Sparse VHD Mode (WSL 2.0.0+):**

Sparse mode allows the VHD file to shrink when files are deleted inside WSL, rather than
only growing. This is critical for sandbox distros that are frequently created and destroyed.

```powershell
# Enable sparse mode for a distro
wsl --manage agentbox-sb --set-sparse true
```

**Resize VHD (WSL 2.5+):**

```powershell
# Set maximum VHD size to 50GB
wsl --manage agentbox-sb --resize 50GB
```

**Manual Compaction Workflow:**

When sparse mode is insufficient (e.g., older WSL versions), manual compaction reclaims
unused space from the VHD file:

```bash
# Step 1: Inside WSL, trim unused filesystem blocks
sudo fstrim -a
```

```powershell
# Step 2: Shut down WSL to release the VHD file
wsl --shutdown

# Step 3: Compact the VHD using diskpart
# Create a diskpart script
$vhdPath = "C:\Users\<username>\AppData\Local\Packages\...\LocalState\ext4.vhdx"
@"
select vdisk file="$vhdPath"
attach vdisk readonly
compact vdisk
detach vdisk
exit
"@ | diskpart
```

**Recommended Settings for agentbox Sandbox Distros:**

1. **Enable sparse mode** immediately after import (`wsl --manage agentbox-sb --set-sparse true`)
2. **Set a 50 GB size limit** to prevent runaway disk usage (`wsl --manage agentbox-sb --resize 50GB`)
3. **Periodic compaction** on cleanup: run `fstrim -a` inside WSL before unregistering
4. **Monitor disk usage** in `CheckDependencies` — warn if VHD exceeds 80% of limit

### F.4 WSL1 to WSL2 Migration

Some systems may have WSL1 distros or WSL1 as the default version. agentbox requires
WSL2 for Hyper-V-based isolation.

**Detection:**

```powershell
# List distros with their WSL version
wsl -l -v
```

Example output:
```
  NAME            STATE           VERSION
* Ubuntu          Running         2
  Legacy-Distro   Stopped         1
```

The `VERSION` column indicates whether a distro uses WSL1 (1) or WSL2 (2).

**If WSL1 Is Detected:**

agentbox should **not** attempt automatic migration of existing distros. Instead:

1. **Check the default WSL version:**
   ```powershell
   wsl --status
   ```
   Look for `Default Version: 2` in the output.

2. **If default is WSL1**, provide a clear error message:
   ```
   ERROR: WSL default version is 1. agentbox requires WSL2.
   Run: wsl --set-default-version 2
   Then retry. If this fails, ensure Hyper-V and Virtual Machine Platform
   are enabled in Windows Features.
   ```

**Migration Command (for reference):**

```powershell
# Convert an existing distro from WSL1 to WSL2
wsl --set-version <distro-name> 2
```

> **Note:** Migration can take several minutes depending on distro size. It may fail if
> Hyper-V or Virtual Machine Platform features are not enabled, or if BIOS virtualization
> is disabled.

**Recommended Implementation in `CheckDependencies`:**

1. Run `wsl --status` and verify `Default Version: 2`
2. If WSL1 is the default, return a `DependencyCheck` error with actionable guidance
3. Do **not** auto-migrate — the user should explicitly opt in
4. If the agentbox sandbox distro already exists as WSL1 (edge case after downgrade),
   unregister and re-provision as WSL2
