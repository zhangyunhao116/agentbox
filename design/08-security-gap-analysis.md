# Security Gap Analysis

> **Status**: Active  
> **Author**: Agent  
> **Date**: 2026-03-06  
> **Scope**: Consolidated list of remaining security gaps after cross-referencing the original audit ([07-security-audit.md](./07-security-audit.md)) against the current codebase and the [agent-sandbox-research-2026](../../research/agent-sandbox-research-2026.md) industry research.

---

## 1. Context

The original security audit (2026-03-04) identified 15+ issues. A follow-up code review (2026-03-06) found that **8 of those have already been resolved**:

| Resolved Issue | Evidence |
|---|---|
| Seccomp blocklist expanded (6 → 30+ syscalls) | `platform/linux/seccomp.go` |
| CONNECT tunnel dials before 200 response | `proxy/http.go:330-358` |
| Environment variable sanitization | `internal/envutil/envutil.go`, `platform/linux/reexec.go:129` |
| Landlock default paths granular | `platform/linux/landlock.go:191-206` |
| Config deep-copies all slices | `config.go:457-478` |
| Darwin UDP restricted to port 53/5353 | `platform/darwin/profile.go:303-306` |
| `CLONE_NEWCGROUP` included | `platform/linux/namespace.go:24` |
| `CLONE_NEWIPC` + `CLONE_NEWUTS` included | `platform/linux/namespace.go:22-23` |

This document tracks the **remaining gaps** that require action.

---

## 2. Open Gaps

### 2.1 [P0] `socketpair` Not Blocked by Seccomp

**Category**: Syscall filtering  
**Source**: `platform/linux/seccomp.go`  
**Industry reference**: Claude Code sandbox bypass via `socketpair(AF_UNIX, ...)`

**Problem**: The seccomp filter inspects the first argument of `SYS_SOCKET` and blocks `AF_UNIX` domain. However, `SYS_SOCKETPAIR` creates a pair of connected sockets and is **not** in the blocklist. An attacker can call `socketpair(AF_UNIX, SOCK_STREAM, 0, fds)` to create Unix domain sockets, bypassing the `SYS_SOCKET` check entirely.

**Impact**: AF_UNIX socket creation bypass → potential communication with host-side Unix sockets (e.g., Docker socket, D-Bus, X11).

**Fix**:

Add `sysSocketpair` to `seccompSyscalls` struct and include it in the unconditionally blocked list:

```go
// In seccompSyscalls struct:
sysSocketpair uint32

// In seccompSyscallsFor:
// amd64: sysSocketpair: 53
// arm64: sysSocketpair: 199
```

**Complexity**: Low  
**Risk if not fixed**: High — direct bypass of AF_UNIX isolation

---

### 2.2 [P0] No `PR_SET_PDEATHSIG` — Orphan Process Risk

**Category**: Process lifecycle  
**Source**: `platform/linux/harden.go`, `platform/linux/reexec.go`  
**Industry reference**: bubblewrap `--die-with-parent` (uses `prctl(PR_SET_PDEATHSIG, SIGKILL)`)

**Problem**: If the parent process is killed (SIGKILL, OOM, crash), the re-exec child continues running with all sandbox restrictions active but **no parent to manage it**. The child becomes an orphan process adopted by init. This is especially problematic in long-running agent scenarios.

**Impact**: Sandbox process outlives its manager → resource leak, potential for unmonitored command execution.

**Fix**:

Add `PR_SET_PDEATHSIG` to `hardenProcess()` in `platform/linux/harden.go`:

```go
const prSetPdeathsig = 1

// Ensure child dies when parent exits.
if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetPdeathsig, uintptr(syscall.SIGKILL), 0); errno != 0 {
    return fmt.Errorf("prctl PR_SET_PDEATHSIG: %w", errno)
}
```

**Complexity**: Low  
**Risk if not fixed**: High — orphan processes running indefinitely

---

### 2.3 [P1] Non-existent Deny Path Behavior Not Verified

**Category**: Filesystem isolation  
**Source**: `platform/linux/landlock.go`, `platform/darwin/profile.go`  
**Industry reference**: Claude Code CVE-2026-25725 (CVSS 10.0) — bubblewrap silently skipped non-existent deny paths, allowing attackers to create the file inside the sandbox

**Problem**: The behavior when a deny path does not exist at sandbox setup time has not been tested:

- **Linux/Landlock**: Landlock rules operate on filesystem hierarchy, so parent directory rules should still apply. Risk is likely low.
- **macOS/Seatbelt**: Uses `subpath` rules which should apply to the entire subtree regardless of file existence. But this is **not verified by tests**.

**Impact**: If deny paths are silently skipped, an attacker could create sensitive files (e.g., `~/.bashrc`, `~/.ssh/authorized_keys`) inside the sandbox.

**Fix**:

1. Add integration tests that:
   - Set up a deny path pointing to a non-existent file
   - Attempt to create and write to that path from within the sandbox
   - Verify the operation is blocked
2. Add tests for both Landlock and Seatbelt paths
3. If Seatbelt's `subpath` doesn't protect non-existent children, switch to parent directory rules

**Complexity**: Medium  
**Risk if not fixed**: Medium — depends on Landlock/Seatbelt's actual behavior

---

### 2.4 [P1] Symlink TOCTOU Window

**Category**: Filesystem isolation  
**Source**: `manager.go:293-299`, `platform/darwin/profile.go:387-404`  
**Industry reference**: Claude Code CVE-2025-59829, CVE-2026-25724, CVE-2026-20677

**Problem**: Both platforms resolve symlinks at sandbox setup time (`canonicalizePath`, `filepath.EvalSymlinks`). Between resolution and enforcement, a symlink target can be changed:

```
Time T0: /tmp/safe → /workspace/project (resolved at setup)
Time T1: attacker changes /tmp/safe → /etc/passwd
Time T2: sandbox uses stale resolution, accesses /etc/passwd
```

**Mitigation already in place**: Landlock provides kernel-level path enforcement that is not affected by symlink changes after `landlock_restrict_self`. The TOCTOU window only exists between config resolution and Landlock activation.

**Impact**: Limited by Landlock but still a theoretical window. More concerning on macOS where Seatbelt rules use resolved paths.

**Fix options** (in order of priority):

1. Use `O_NOFOLLOW` when validating paths
2. Implement symlink monitoring for critical deny paths (designed in `design/03d-symlink-monitoring.md`)
3. Re-resolve paths immediately before applying rules (minimize window)

**Complexity**: High  
**Risk if not fixed**: Medium — partially mitigated by Landlock's kernel-level enforcement

---

### 2.5 [P1] Classifier Encoding Bypass

**Category**: Command classification (defense-in-depth)  
**Source**: `classifier_rules.go`  
**Industry reference**: Claude Code CVE-2025-66032 (`$IFS`/short CLI flag parsing bypass)

**Problem**: The classifier uses string matching without decoding common bypass techniques:

| Technique | Example | Detected? |
|-----------|---------|-----------|
| Base64 pipe | `echo "cm0gLXJmIC8=" \| base64 -d \| sh` | ❌ |
| Hex IP | `curl http://0x7f000001:8080/` | ❌ |
| Octal IP | `ping 0177.0.0.1` | ❌ |
| Integer IP | `ping 2130706433` | ❌ |
| `$IFS` splitting | `cat$IFS/etc/passwd` | ❌ |
| Unicode homoglyphs | Cyrillic 'а' vs Latin 'a' | ❌ |

**Impact**: Low — the classifier is defense-in-depth; the sandbox itself is the primary security boundary. An undetected command still runs inside the sandbox with all restrictions active.

**Fix**:

1. Add `base64 -d | sh` and `base64 --decode | sh` pipe detection
2. Add `$IFS` as a known bypass pattern
3. Add IP canonicalization for hex/octal/integer formats
4. Add tests for all bypass techniques listed above

**Complexity**: Medium  
**Risk if not fixed**: Low — defense-in-depth only

---

### 2.6 [P2] Landlock Fallback Strategy Documentation

**Category**: Availability  
**Source**: `platform/linux/landlock.go`, `platform/linux/reexec.go:99-102`

**Problem**: When Landlock is unavailable (kernel < 5.13 or disabled), `applyLandlock` returns an error, and `sandboxInit` exits with code 1 (fail-closed). This means **agentbox is completely unusable on older kernels**.

The design document (`02b-linux-namespace-landlock.md:810`) says "Namespace isolation still provides protection", implying graceful degradation was intended. But the code is fail-closed.

**Current behavior is arguably correct** from a security standpoint — running without filesystem isolation is dangerous. However, it should be explicitly documented.

**Fix**:

1. Document the kernel requirement clearly in README and error messages
2. Consider a `BestEffort` mode that logs a warning and continues with namespace + seccomp only
3. Add `CheckDependencies()` output that explicitly warns about Landlock unavailability

**Complexity**: Low  
**Risk if not fixed**: Low — user-facing clarity, not a security gap

---

### 2.7 [P2] Domain Wildcard Dot-Boundary Matching

**Category**: Network proxy  
**Source**: `proxy/filter.go:176-193`

**Problem**: Need to verify that `*.example.com` does not match `evilexample.com` — the wildcard must require a dot boundary.

**Fix**: Add test case verifying `*.example.com` does NOT match `evilexample.com` and `notexample.com`.

**Complexity**: Low  
**Risk if not fixed**: Medium — potential domain filter bypass

---

## 3. Low Priority / Informational

### 3.1 [P3] `/proc/self/maps` Leaks ASLR

**Source**: `platform/linux/landlock.go:199`

The Landlock default system paths include `/proc/self/maps`, which reveals the memory layout of the sandboxed process. This information can be used to bypass ASLR in exploitation chains.

**Recommendation**: Remove `/proc/self/maps` from default read paths. Programs that need it (e.g., debuggers, profilers) are unlikely to run inside a sandbox.

---

### 3.2 [P3] No cgroup v2 Resource Limits

**Source**: `platform/linux/namespace.go:86-89`

Memory limits use `RLIMIT_AS` (virtual address space), not cgroup v2 physical memory limits. `RLIMIT_AS` can be bypassed with `mmap(PROT_NONE)` reservations that consume address space without physical memory, and doesn't account for shared memory or page cache.

**Recommendation**: For environments where cgroup v2 is available, support `memory.max` and `pids.max` controllers. This requires either root access or systemd-based delegation.

---

### 3.3 [P3] Landlock CVE-2025-68736 (Disconnected Directory Bypass)

**Source**: Upstream kernel CVE

Landlock access rights could be bypassed through disconnected directories on unpatched kernels. This is a host kernel issue, not an agentbox code issue.

**Recommendation**: Document minimum recommended kernel versions. Consider adding a kernel version check that warns when running on kernels known to have Landlock vulnerabilities.

---

### 3.4 [P3] IP Canonicalization in Proxy

**Source**: `proxy/filter.go`

The domain filter does not canonicalize IP address formats. Hex (`0x7f000001`), octal (`0177.0.0.1`), and integer (`2130706433`) representations of IP addresses may bypass domain-based filtering.

**Recommendation**: Parse and canonicalize IP addresses in the proxy filter before domain matching.

---

### 3.5 [P3] Audit Logging for Security Events

**Source**: General architecture

Currently, seccomp violations result in process termination (EPERM or KILL) and Landlock violations return EACCES, but neither produces audit logs visible to the agentbox manager.

**Recommendation**: Consider using seccomp's `SECCOMP_RET_LOG` for development/debugging mode, and monitor `/proc/self/fd` for Landlock violation signals.

---

## 4. Summary

| ID | Priority | Gap | Complexity | Status |
|----|----------|-----|------------|--------|
| 2.1 | 🔴 P0 | `socketpair` not blocked | Low | Open |
| 2.2 | 🔴 P0 | No `PR_SET_PDEATHSIG` | Low | Open |
| 2.3 | 🟡 P1 | Non-existent deny path untested | Medium | Open |
| 2.4 | 🟡 P1 | Symlink TOCTOU window | High | Open |
| 2.5 | 🟡 P1 | Classifier encoding bypass | Medium | Open |
| 2.6 | 🟡 P2 | Landlock fallback docs | Low | Open |
| 2.7 | 🟡 P2 | Domain wildcard dot-boundary | Low | Open |
| 3.1 | 🟢 P3 | `/proc/self/maps` ASLR leak | Low | Open |
| 3.2 | 🟢 P3 | No cgroup v2 limits | High | Open |
| 3.3 | 🟢 P3 | Landlock CVE-2025-68736 | Low | Open |
| 3.4 | 🟢 P3 | IP canonicalization in proxy | Medium | Open |
| 3.5 | 🟢 P3 | Audit logging | Medium | Open |

**Recommended action order**: 2.1 → 2.2 → 2.3 → 2.7 → 2.5 → 2.6 → 3.1 → 2.4 → rest
