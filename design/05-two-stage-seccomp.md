# Design: Two-Stage Seccomp BPF Filter

**Status**: Informational — documenting for future reference  
**Author**: agentbox team  
**Date**: 2026-02-16

## 1. Problem Statement

The current agentbox Linux sandbox applies a single seccomp BPF filter in one
step during the re-exec child process setup. This filter blocks `AF_UNIX`
sockets, `ptrace`, `mount`, `umount2`, `reboot`, `swapon`, `swapoff`, `mknod`,
and `mknodat`.

If a future feature requires Unix domain sockets for internal communication
(e.g., a socat-style bridge between the sandbox and the host, or a control
channel for runtime configuration updates), the current single-stage approach
would block it. The sandbox-runtime project (TypeScript/Node.js) solves this
with a two-stage seccomp design where a permissive filter is applied first,
internal services are started, and then a restrictive filter is applied before
executing the user command.

## 2. Current Architecture

### Re-exec Model

agentbox uses a re-exec architecture for Linux sandboxing:

```
Parent Process (manager)
  │
  ├── Configures WrapConfig (writable roots, deny paths, network, etc.)
  ├── Sets up cmd.SysProcAttr with namespace flags (CLONE_NEWUSER, CLONE_NEWNS, etc.)
  ├── Starts proxy server (HTTP + SOCKS5) in parent process
  │
  └── Child Process (re-exec)
        ├── Detects re-exec via environment variable
        ├── Applies UID/GID mapping
        ├── Sets up mount namespace (bind mounts, tmpfs, /proc)
        ├── Applies Landlock LSM rules
        ├── Calls hardenProcess() (PR_SET_NO_NEW_PRIVS)
        ├── Calls ApplySeccomp() — single BPF filter
        └── exec() user command
```

### Single-Stage Seccomp

The `ApplySeccomp()` function builds a BPF program that:

1. Validates the architecture (KILL on mismatch)
2. Checks each syscall number against a blocked list (EPERM)
3. For `SYS_SOCKET`, inspects the first argument — blocks `AF_UNIX` only
4. Allows all other syscalls

This is applied via `prctl(PR_SET_SECCOMP, SECCOMP_SET_MODE_FILTER, ...)`.

## 3. Proposed Two-Stage Approach

### Overview

```
Child Process (re-exec)
  │
  ├── hardenProcess() — PR_SET_NO_NEW_PRIVS
  │
  ├── Stage 1: Permissive Seccomp
  │     ├── Block: ptrace, mount, umount2, reboot, swapon, swapoff, mknod, mknodat
  │     ├── Allow: AF_UNIX sockets (needed for internal bridge)
  │     └── Allow: all other syscalls
  │
  ├── Start Internal Bridge
  │     ├── Create AF_UNIX socket pair
  │     ├── Connect to parent's proxy via Unix socket
  │     └── Bridge is ready for forwarding
  │
  ├── Stage 2: Restrictive Seccomp
  │     ├── Block: AF_UNIX socket creation (in addition to Stage 1 blocks)
  │     └── Existing AF_UNIX file descriptors remain usable
  │
  └── exec() user command
```

### Stage 1: Permissive Filter

The first filter blocks dangerous syscalls but allows `AF_UNIX` sockets:

- **Blocked**: `ptrace`, `mount`, `umount2`, `reboot`, `swapon`, `swapoff`,
  `mknod`, `mknodat`
- **Allowed**: `socket(AF_UNIX, ...)`, all other syscalls

This permits the child process to create Unix domain sockets for internal
communication (e.g., connecting to a socat bridge or control channel).

### Stage 2: Restrictive Filter

After the internal bridge is established, a second filter is applied that
additionally blocks `AF_UNIX` socket creation:

- **Blocked**: everything from Stage 1 + `socket(AF_UNIX, ...)`
- **Allowed**: all other syscalls

Seccomp filters are stackable — the kernel evaluates all installed filters
and returns the most restrictive result. This means Stage 2 only needs to
add the `AF_UNIX` restriction; the Stage 1 blocks remain in effect.

### Key Implementation Detail: SECCOMP_FILTER_FLAG_TSYNC

When applying seccomp in a multi-threaded process (Go's runtime uses multiple
OS threads), the filter must be applied to all threads simultaneously. This
requires using the `seccomp()` syscall with `SECCOMP_FILTER_FLAG_TSYNC`:

```go
// Stage 2 application
syscall.Syscall(
    SYS_SECCOMP,
    SECCOMP_SET_MODE_FILTER,  // operation = 1
    SECCOMP_FILTER_FLAG_TSYNC, // flags = 1
    uintptr(unsafe.Pointer(&prog)),
)
```

The current `ApplySeccomp()` uses `prctl(PR_SET_SECCOMP, ...)` which only
applies to the calling thread. For two-stage, both stages should use the
`seccomp()` syscall with `TSYNC` to ensure consistency across all Go runtime
threads.

## 4. Implementation Sketch

```go
// ApplySeccompStage1 applies the permissive filter (allows AF_UNIX).
func ApplySeccompStage1() error {
    sc, err := seccompSyscallsFn()
    if err != nil {
        return fmt.Errorf("seccomp stage1: %w", err)
    }
    // Build filter WITHOUT the AF_UNIX socket check.
    filter := buildSeccompFilterStage1(sc)
    return applyFilterTsync(filter)
}

// ApplySeccompStage2 applies the restrictive filter (blocks AF_UNIX).
func ApplySeccompStage2() error {
    sc, err := seccompSyscallsFn()
    if err != nil {
        return fmt.Errorf("seccomp stage2: %w", err)
    }
    // Build filter that ONLY adds the AF_UNIX block.
    // (Stacked on top of Stage 1.)
    filter := buildSeccompFilterStage2(sc)
    return applyFilterTsync(filter)
}

func applyFilterTsync(filter []sockFilter) error {
    prog := sockFprog{
        len:    uint16(len(filter)),
        filter: unsafe.Pointer(&filter[0]),
    }
    _, _, errno := syscall.Syscall(
        sysSeccompNR(),
        1, // SECCOMP_SET_MODE_FILTER
        1, // SECCOMP_FILTER_FLAG_TSYNC
        uintptr(unsafe.Pointer(&prog)),
    )
    if errno != 0 {
        return errno
    }
    return nil
}
```

## 5. Trade-offs

| Aspect | Single-Stage (Current) | Two-Stage (Proposed) |
|--------|----------------------|---------------------|
| **Complexity** | Simple, one filter | Two filters, ordering matters |
| **Security window** | None — AF_UNIX blocked immediately | Brief window where AF_UNIX is allowed |
| **Internal comms** | Not possible via Unix sockets | Possible between Stage 1 and Stage 2 |
| **Filter stacking** | N/A | Kernel evaluates both filters (most restrictive wins) |
| **Thread safety** | prctl (single thread) | Requires TSYNC for both stages |
| **Debugging** | One filter to inspect | Two filters to reason about |
| **Kernel support** | Linux ≥ 3.5 | Linux ≥ 3.17 (for seccomp() syscall + TSYNC) |

### Security Window Analysis

The window between Stage 1 and Stage 2 is brief (microseconds) and occurs
before `exec()` of the user command. During this window:

- The process is already in an isolated namespace (user, mount, PID, net)
- `PR_SET_NO_NEW_PRIVS` is set (no privilege escalation)
- Landlock rules are applied (filesystem restrictions)
- Only the internal bridge code runs (trusted code path)

The risk is minimal because the user's untrusted code has not started yet.

## 6. Recommendation

**The current single-stage architecture is sufficient for agentbox.**

The key reason is architectural: agentbox's proxy server runs in the **parent
process**, not inside the sandbox. The parent process:

1. Starts the HTTP + SOCKS5 proxy on localhost ports
2. Passes the proxy ports to the child via `WrapConfig`
3. The child connects to the proxy via `AF_INET` (localhost TCP), not `AF_UNIX`

Since the proxy communication uses TCP (which is allowed by the seccomp
filter), there is no need for Unix domain sockets inside the sandbox.

### When Two-Stage Would Be Needed

Two-stage seccomp should be implemented if any of these features are added:

1. **Unix socket bridge**: A socat-style bridge for lower-latency proxy
   communication (replacing TCP localhost with Unix sockets)
2. **Control channel**: A Unix socket-based control channel for runtime
   configuration updates (alternative to the current `UpdateConfig()` API)
3. **Container runtime integration**: If agentbox needs to communicate with
   container runtimes (Docker, containerd) via their Unix socket APIs from
   within the sandbox

Until then, the single-stage approach provides a simpler, more auditable
security boundary with no AF_UNIX exposure window.

This document is preserved for future reference when these features are
considered.
