# Security Audit: Issues and Optimization Directions

> **Status**: Research & Analysis (updated 2026-03-06 with resolution status)  
> **Author**: Agent  
> **Date**: 2026-03-04 (updated 2026-03-06)  
> **Scope**: Security analysis of existing agentbox implementation based on industry research  
> **Method**: Code review + web research (CVE analysis, industry comparison, OWASP guidelines)

---

## 1. Executive Summary

This document identifies potential security issues and optimization directions for the agentbox library, based on:

1. **Code analysis** of all platform implementations (Linux, Darwin), proxy, classifier, and manager
2. **Industry CVE analysis** — particularly 14 CVEs disclosed against Claude Code's sandbox in Feb 2026
3. **Web research** — OWASP Agentic Top 10, Landlock CVEs, seccomp bypass techniques, DNS rebinding
4. **Comparison** with Claude Code, OpenAI Codex, and other AI agent sandboxing solutions

**Key Finding:** The agentbox implementation is generally well-designed, but several attack patterns discovered in Claude Code's sandbox (CVE-2026-25725, etc.) may also affect agentbox. The most critical issues are around seccomp coverage, symlink TOCTOU, and environment variable sanitization.

> **2026-03-06 Update**: Cross-referenced audit findings against current codebase. Several issues
> have been resolved since the original audit. Each section below now includes a **Resolution** tag:
> ✅ RESOLVED, ⚠️ PARTIALLY RESOLVED, or ❌ OPEN. See [08-security-gap-analysis.md](./08-security-gap-analysis.md)
> for the consolidated list of remaining gaps and action plan.

---

## 2. Critical Issues

### 2.1 Seccomp Blocked Syscall List Too Limited

> **Resolution**: ⚠️ PARTIALLY RESOLVED — Expanded from 6 to 30+ blocked syscalls, but `socketpair` is still missing.

**Source**: `platform/linux/seccomp.go`

**Original state**: Only 6 syscalls were blocked: `ptrace`, `mount`, `umount2`, `reboot`, `swapon`, `swapoff`.

**Current state (2026-03-06)**: The seccomp blocklist has been significantly expanded to 30+ syscalls including: `kexec_load`, `kexec_file_load`, `init_module`, `finit_module`, `delete_module`, `perf_event_open`, `bpf`, `userfaultfd`, `open_by_handle_at`, `setns`, `unshare`, `pivot_root`, `chroot`, `acct`, `kcmp`, `add_key`, `request_key`, `keyctl`, `lookup_dcookie`, `mbind`, `move_pages`, `ioperm`, `iopl`, `clock_settime`, `settimeofday`, `nfsservctl`, `mknod`, `mknodat`.

**Remaining gap**: `socketpair` (SYS_SOCKETPAIR) is **not** blocked. This syscall can create AF_UNIX socket pairs, bypassing the AF_UNIX creation check on `SYS_SOCKET`. See [08-security-gap-analysis.md](./08-security-gap-analysis.md) §2.1.

**Recommendation**: Add `socketpair` to the seccomp blocklist.

### 2.2 Non-existent Deny Path Handling (CVE-2026-25725 Pattern)

> **Resolution**: ❌ OPEN — Behavior not yet verified by tests. See [08-security-gap-analysis.md](./08-security-gap-analysis.md) §2.3.

**Source**: Claude Code CVE-2026-25725 (CVSS 10.0)

**Issue**: Claude Code's bubblewrap sandbox silently skipped deny paths when the file didn't exist at startup. This allowed attackers to create the file inside the sandbox with malicious content.

**agentbox risk assessment**:
- **Landlock** (`platform/linux/landlock.go`): Landlock operates at the kernel level and restricts access based on filesystem hierarchy. If a file doesn't exist, Landlock rules on its parent directory should still apply. **Lower risk** than Claude Code's approach.
- **Seatbelt** (`platform/darwin/profile.go`): Uses `subpath` rules for deny paths, which should apply to the entire subtree regardless of whether specific files exist. **Lower risk** than originally assessed, but needs test verification.

**Recommendation**: 
1. Add tests to verify deny behavior when target files don't exist
2. Document the behavior difference between Landlock and Seatbelt for non-existent paths

### 2.3 CONNECT Tunnel Response Ordering

> **Resolution**: ✅ RESOLVED — Code already dials the target BEFORE sending the 200 response.

**Source**: `proxy/http.go:283-358`

**Original concern**: The HTTP proxy sends `200 Connection Established` response before successfully dialing the target host.

**Verification (2026-03-06)**: The code at `proxy/http.go:330-358` first dials the target (`p.dialFunc(r.Context(), "tcp", targetAddr)`), checks for errors, and only then hijacks the connection and writes `HTTP/1.1 200 Connection Established`. This is the correct order. No fix needed.

---

## 3. High-Severity Issues

### 3.1 Symlink TOCTOU Across Both Platforms

> **Resolution**: ❌ OPEN — Known limitation with partial kernel-level mitigation. See [08-security-gap-analysis.md](./08-security-gap-analysis.md) §2.4.

**Source**: 
- `platform/darwin/profile.go:387-404` — `canonicalizePath()`
- `manager.go:293-299` — writable root resolution

**Issue**: Both platforms resolve symlinks at sandbox setup time. Between resolution and enforcement, symlink targets can change.

**Industry precedent**: 
- Claude Code CVE-2025-59829: Symlink bypass of permission deny rules
- Claude Code CVE-2026-25724: Second symlink bypass variant
- CVE-2026-20677: Apple macOS/iOS symbolic link sandbox bypass

**agentbox mitigation**: The code acknowledges this TOCTOU window (`manager.go:293` comment). Landlock provides kernel-level protection that partially mitigates this. However, the initial resolution still creates a window.

**Recommendation**:
1. Use `O_NOFOLLOW` when validating paths where possible
2. Add symlink monitoring for critical deny paths (already designed in `design/03d-symlink-monitoring.md`)
3. Document the TOCTOU limitation and its kernel-level mitigation

### 3.2 Environment Variable Leaking

> **Resolution**: ✅ RESOLVED — `internal/envutil/envutil.go` implements comprehensive sanitization.

**Source**:
- `internal/envutil/envutil.go:106-128` — sensitive variable definitions
- `internal/envutil/envutil.go:153-212` — `SanitizeEnv` implementation
- `platform/linux/reexec.go:129` — calls `envutil.SanitizeEnv(os.Environ())`

**Original concern**: Sensitive environment variables from the parent process are passed to sandboxed commands without filtering.

**Verification (2026-03-06)**: The `SanitizeEnv` function filters:
- **Exact keys**: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN`, `GITHUB_PAT`, `DOCKER_AUTH_CONFIG`, `NPM_TOKEN`
- **Suffix patterns**: `_SECRET`, `_PASSWORD`, `_API_KEY`, `_PRIVATE_KEY`, `_TOKEN`
- **Preserved**: `_AGENTBOX_CONFIG` is always preserved for re-exec

This is called in `reexec.go:129` before `syscall.Exec`. No additional fix needed.

### 3.3 Classifier Encoding Bypass

> **Resolution**: ❌ OPEN — Defense-in-depth improvement. See [08-security-gap-analysis.md](./08-security-gap-analysis.md) §2.5.

**Source**: `classifier_rules.go`, `classifier_test.go`

**Issue**: The classifier uses string matching without handling encoded forms:

| Bypass Technique | Example | Detected? |
|-----------------|---------|-----------|
| Base64 encoding | `echo "cm0gLXJmIC8=" \| base64 -d \| sh` | ❌ No |
| Hex IP addresses | `curl http://0x7f000001:8080/` | ❌ No |
| Octal IP addresses | `ping 0177.0.0.1` | ❌ No |
| Integer IP | `ping 2130706433` | ❌ No |
| Unicode homoglyphs | Cyrillic 'а' vs Latin 'a' | ❌ No |
| `$IFS` splitting | `cat$IFS/etc/passwd` | ❌ No |

**Industry precedent**: Claude Code CVE-2025-66032 — `$IFS`/short CLI flag parsing led to RCE.

**Note**: The classifier is defense-in-depth; the sandbox itself provides the primary security boundary. However, improving classifier coverage reduces the attack surface.

**Recommendation**:
1. Add tests for common encoding bypass techniques
2. Consider adding base64 pipe detection (`| base64 -d |`)
3. Add `$IFS` detection to common bypass patterns

### 3.4 Landlock Default System Paths Too Permissive

> **Resolution**: ✅ RESOLVED — Paths are now granular.

**Source**: `platform/linux/landlock.go:191-206`

**Original concern**: Default read access includes entire `/etc`, `/proc`, `/dev`.

**Verification (2026-03-06)**: The implementation now uses granular paths:
- `/etc` → only `ld.so.cache`, `ld.so.conf`, `ld.so.conf.d`, `resolv.conf`, `hosts`, `nsswitch.conf`, `ssl`, `ca-certificates`, `pki`, `alternatives`, `localtime`, `timezone`, `passwd`, `group`
- `/proc` → only `/proc/self/status`, `/proc/self/fd`, `/proc/self/exe`, `/proc/self/maps`
- `/dev` → only `/dev/null`, `/dev/zero`, `/dev/urandom`, `/dev/random`, `/dev/stdin`, `/dev/stdout`, `/dev/stderr`, `/dev/fd`, `/dev/pts`, `/dev/shm`

**Remaining concern**: `/proc/self/maps` may leak ASLR information. See [08-security-gap-analysis.md](./08-security-gap-analysis.md) §3.1.

### 3.5 Darwin UDP Rule Too Permissive

> **Resolution**: ✅ RESOLVED — UDP restricted to specific ports.

**Source**: `platform/darwin/profile.go:303-306`

**Original concern**: `(allow network* (local udp "*:*"))` allows all UDP traffic.

**Verification (2026-03-06)**: The actual SBPL rules are:
```scheme
(deny network*)
(allow network* (remote udp "localhost:53"))    ; DNS
(allow network* (remote udp "localhost:5353"))  ; mDNS
```
Only DNS and mDNS on localhost are allowed. The permissive `*:*` rule does not exist in the code. No fix needed.

---

## 4. Medium-Severity Issues

### 4.1 Domain Wildcard Matching

> **Resolution**: ❌ OPEN — See [08-security-gap-analysis.md](./08-security-gap-analysis.md) §2.7.

**Source**: `proxy/filter.go:176-193`

**Issue**: Need to verify that `*.example.com` doesn't match `evilexample.com` (dot-boundary check).

### 4.2 Missing CLONE_NEWCGROUP

> **Resolution**: ✅ RESOLVED — `CLONE_NEWCGROUP` (0x02000000) is included in namespace flags.

**Source**: `platform/linux/namespace.go:24-26`

**Verification (2026-03-06)**: The `configureNamespaces` function includes `cloneNewCgroup = 0x02000000` in the clone flags alongside `CLONE_NEWUSER`, `CLONE_NEWNS`, `CLONE_NEWPID`, `cloneNewIPC`, and `cloneNewUTS`. No fix needed.

### 4.3 Config Snapshot Shallow Copy

> **Resolution**: ✅ RESOLVED — `deepCopyConfig` correctly deep-copies all slice fields.

**Source**: `config.go:457-478`, `manager.go:173-178`

**Verification (2026-03-06)**: The `deepCopyConfig` function deep-copies `WritableRoots`, `DenyWrite`, `DenyRead`, `AllowedDomains`, `DeniedDomains`, `AllowUnixSockets`, and nested structs (`MITMProxy`, `ResourceLimits`). No fix needed.

### 4.4 Default DenyWrite Incomplete

> **Resolution**: ✅ RESOLVED — DenyWrite expanded; home directory deny covers `~/.local`, `~/.config`.

**Source**: `config.go:200-211`

**Verification (2026-03-06)**: Default `DenyWrite` now includes `home`, `/etc`, `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/boot`, `/opt`, `/sys`. Since the entire home directory is denied, paths like `~/.local`, `~/.config`, `~/.local/share` are implicitly covered. No additional fix needed.

### 4.5 Memory Limit Implementation

> **Resolution**: ❌ OPEN — Architectural limitation. See [08-security-gap-analysis.md](./08-security-gap-analysis.md) §3.2.

**Source**: `platform/linux/namespace.go:84-89`

**Issue**: Uses `RLIMIT_AS` (virtual memory) instead of cgroup v2 memory limits (physical RAM).

### 4.6 Landlock CVE-2025-68736

> **Resolution**: ❌ OPEN — Informational; depends on host kernel patching.

**Published**: December 2025

**Issue**: Disconnected directory access rights bypass in Linux Landlock. Files in disconnected directories could bypass Landlock access control.

**Impact**: If agentbox runs on kernels without this fix, Landlock protection may be incomplete.

**Recommendation**: Document minimum kernel version requirement or add kernel version detection.

---

## 5. Lessons from Claude Code Security Batch (14 CVEs, Feb 2026)

The Claude Code sandbox received 14 CVEs in a single disclosure batch. Key patterns relevant to agentbox:

### 5.1 Attack Pattern Categories

| Category | CVEs | agentbox Exposure |
|----------|------|------------------|
| **Deny path bypass** | CVE-2026-25725, CVE-2025-59829, CVE-2026-25724 | Medium — different mechanism (Landlock vs bwrap) |
| **Command parsing bypass** | CVE-2025-58764, CVE-2025-66032, CVE-2026-24887 | Medium — classifier provides defense-in-depth |
| **Env/config exfiltration** | CVE-2026-21852, CVE-2026-24052 | ✅ Low — env vars now sanitized via `envutil.SanitizeEnv` |
| **Working dir escape** | CVE-2026-25722, CVE-2026-25723 | Low — Landlock enforces regardless of cwd |
| **Trust/approval bypass** | CVE-2025-59536, CVE-2025-59041 | Medium — approval callback timing |

### 5.2 Key Architectural Difference

Claude Code's sandbox only covers Bash commands. Read/Write/Edit/Glob/Grep tools execute with full host access (Issue #26616). **agentbox does not have this gap** — all commands go through the sandbox.

### 5.3 Recommendations from Claude Code Lessons

1. **Always handle non-existent deny paths** — never skip them silently
2. **Symlink bypass is a recurring theme** — multiple CVEs, multiple variants
3. **Shell command parsing is fragile** — `$IFS`, `sed`, piped commands all had bypasses
4. **Environment variables are an exfiltration channel** — sanitize before passing to sandbox
5. **Hooks/callbacks running outside sandbox are dangerous** — ensure ApprovalCallback doesn't introduce escape paths

---

## 6. Optimization Roadmap

> **2026-03-06 Update**: Roadmap revised. Completed items marked. Remaining items tracked in
> [08-security-gap-analysis.md](./08-security-gap-analysis.md).

### Phase 1: Security Hardening (Immediate)

| Priority | Task | Impact | Status |
|----------|------|--------|--------|
| 🔴 P0 | Expand seccomp blocked syscall list | Prevent container escape techniques | ✅ Done (30+ syscalls) |
| 🔴 P0 | Fix CONNECT tunnel response ordering | Prevent connection confusion | ✅ Already correct |
| 🔴 P0 | Add environment variable sanitization | Prevent secret exfiltration | ✅ Done (`envutil.SanitizeEnv`) |
| 🟠 P1 | Test non-existent deny path behavior | Prevent CVE-2026-25725 pattern | ❌ Open |
| 🟠 P1 | Restrict Darwin UDP rule | Prevent DNS tunneling | ✅ Already restricted |
| 🟠 P1 | Add socketpair to seccomp blocklist | Close AF_UNIX bypass | ❌ Open |

### Phase 2: Defense-in-Depth (Short-term)

| Priority | Task | Impact | Status |
|----------|------|--------|--------|
| 🟡 P2 | Add classifier encoding bypass tests | Improve detection coverage | ❌ Open |
| 🟡 P2 | Fix domain wildcard dot-boundary | Prevent domain matching bypass | ❌ Open |
| 🟡 P2 | Add CLONE_NEWCGROUP | Improve namespace isolation | ✅ Done |
| 🟡 P2 | Deep-copy config slices | Prevent race conditions | ✅ Done (`deepCopyConfig`) |
| 🟡 P2 | Refine Landlock default paths | Reduce information exposure | ✅ Done (granular paths) |

### Phase 3: Advanced Hardening (Long-term)

| Priority | Task | Impact | Status |
|----------|------|--------|--------|
| 🟢 P3 | cgroup v2 memory limits | Proper memory isolation | ❌ Open |
| 🟢 P3 | Audit logging for seccomp/Landlock | Detect violation attempts | ❌ Open |
| 🟢 P3 | Allowlist-based env filtering | Comprehensive env sanitization | ✅ Done (suffix-based) |
| 🟢 P3 | Symlink change monitoring | Detect TOCTOU attacks | ❌ Open |
| 🟢 P3 | IP canonicalization in proxy | Prevent IP format bypass | ❌ Open |

---

## 7. References

### CVE Sources
- CVE-2026-25725 (Claude Code sandbox escape): https://techowlshield.com/blog-detail.php?slug=claude-code-sandbox-escape-missing-file-rce
- CVE-2025-68736 (Landlock disconnected dir): https://stack.watch/vuln/CVE-2025-68736/
- CVE-2025-53788 (WSL2 TOCTOU): https://cvefeed.io/vuln/detail/CVE-2025-53788

### Industry Research
- OWASP Top 10 for Agentic Applications 2026: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- Claude Code Sandboxing Docs: https://code.claude.com/docs/en/sandboxing
- Anthropic Sandbox Runtime: https://github.com/anthropic-experimental/sandbox-runtime
- AI Agent Sandboxing Landscape 2026: https://zylos.ai/research/2026-01-24-ai-agent-code-execution-sandboxing

### Linux Security
- Landlock LSM Documentation: https://docs.kernel.org/security/landlock.html
- Seccomp BPF Documentation: https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html
- Docker Default Seccomp Profile: https://docs.docker.com/engine/security/seccomp/
