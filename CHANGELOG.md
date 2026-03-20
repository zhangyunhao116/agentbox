# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **windows**: Native sandbox using CreateRestrictedToken + Low Integrity Level for process privilege reduction
- **windows**: Job Object integration for resource limits (memory, CPU, process count) and automatic cleanup
- **windows**: ACL-based filesystem isolation (allow/deny write per path)
- **windows**: PostStartHook mechanism for suspended process → Job Object assignment → resume flow
- **windows**: Tier 2 admin feature — sandbox user management via netapi32 + DPAPI + CreateProcessWithLogonW for stronger isolation using dedicated local user accounts
- **windows**: Tier 2 admin feature — Windows Firewall integration via COM for per-user-SID outbound network blocking
- **windows**: Two-tier architecture — Tier 1 (non-admin: restricted token + job object + low IL) and Tier 2 (admin: Tier 1 PLUS sandbox users + firewall rules for network isolation)
- **windows**: Platform integration of Tier 2 features with graceful fallback to Tier 1 if admin setup fails

- **testutil**: New test utility package providing cross-platform helpers for Windows test compatibility — `Shell()`, `ShellArgs()`, `EchoCommand()`, `ExitCommand()`, `PrintEnvCommand()`, `PwdCommand()`, `StderrCommand()`, `SleepCommand()`, `TempDir()`, `TempPath()`, `HomeDir()`, `SkipIfWindows()`, `SkipIfNotWindows()`, `RequireUnix()`.

- **platform/linux**: Persistent sandbox worker (Zygote mode) — maintains a pre-sandboxed worker process that handles commands via Unix socket IPC, eliminating per-command Go runtime restart. Reduces Linux sandbox overhead from ~140ms to ~20µs protocol round-trip. Falls back to re-exec when worker is unavailable. Note: worker mode uses the broadest Landlock config from Manager initialization; per-command Landlock tightening is planned for a future release.
- **platform/linux**: Worker fast-fail detection — when the worker process exits before connecting (e.g., Landlock not supported on kernel < 5.13), `startWorker` returns error immediately instead of waiting the full 5-second timeout. Reduces cold-start fallback time from ~5.1s to ~125ms on older kernels.
- **cmd/sandbox-bench**: New benchmark CLI tool (`sandbox-bench <cmd>`) for performance testing. Supports `--batch N` flag for hot-path measurement with timing statistics (min/max/mean/P50/P95).
- **platform**: New `WorkerExecutor` optional interface for platforms to provide fast command execution via persistent workers.
- **examples/agentsim**: New multi-step AI coding agent example — writes buggy code, runs tests, detects failure, fixes bug, re-tests until success. Cross-platform (macOS, Linux, Windows).
- **examples/codereview**: New code review agent example — scaffolds project with issues, runs `go vet`/`gofmt`/`go test`, generates structured JSON review report. Cross-platform.
- **examples/healthcheck**: New system health monitor example — inspects Go environment, sandbox capabilities, generates JSON health report. Cross-platform.
- **examples/researchflow**: New research agent example — discovers Go stdlib packages, retrieves docs, generates structured JSON research report. Cross-platform.
- **examples/codemod**: New code modification agent example — scaffolds project with formatting and lint issues, iteratively detects and fixes them using `gofmt`/`go vet`. Cross-platform.
- **examples/projectinit**: New project initialization agent example — bootstraps a Go microservice project, runs full CI pipeline (build, vet, format, test), generates JSON CI report. Cross-platform.
- **internal/pathutil**: Add `ResolveGitWorktree()` to parse `.git` worktree files and resolve the actual git directory path.

### Changed

- **windows**: Replaced WSL2-based sandbox with native Windows security mechanisms (Restricted Token + Job Object + Low Integrity Level + ACL-based filesystem isolation)
- **platform**: Moved PostStartHook registration from root package to `platform` package to resolve circular imports
- **windows**: Simplified process creation by removing `CREATE_SUSPENDED` + `ResumeThread` flow — Job Object is now assigned post-start, with restricted token as primary security boundary during the brief assignment window
- **windows**: ACL filesystem enforcement changed from hard error to best-effort — if ACL setup fails (e.g., insufficient permissions on system directories), sandbox continues with token + job + Low IL isolation
- **windows**: Added `isValidWindowsPath()` defensive filter in ACL module to skip Unix-style paths that may leak from misconfigured `DefaultConfig`
- **ci**: Enhanced Windows CI workflow with cross-compile checks (linux/amd64, darwin/arm64 from Windows; windows/amd64 from Ubuntu), coverage upload, and verbose sandbox test step
- **windows**: Tier 2 admin features (sandbox users + Windows Firewall) validated on Windows Server 2025 — all admin tests pass including NetLocalGroupAdd/Del, NetUserAdd/Del, DPAPI encrypt/decrypt, COM INetFwPolicy2 rule CRUD
- **windows**: Updated Windows benchmark results: P50 16.23ms sandboxed (Restricted Token + Job Object + Low IL)
- **platform/darwin**: Add profile string cache (Tier 1) — repeated `WrapCommand` calls with identical configs skip profile rebuild (~7x speedup)
- **platform/darwin**: Add path canonicalization cache (Tier 2) — `filepath.EvalSymlinks` results cached via `sync.Map` to avoid repeated syscalls
- **tests**: Migrated ~60 Windows `t.Skip` patterns across 20+ test files to use `testutil` helpers, enabling meaningful test execution on Windows CI.
- **ci**: Expanded Windows CI test scope from limited subsets to full `go test ./...`.
- **platform/darwin**: Fix `QF1012` lint warning — use `fmt.Fprintf` instead of `WriteString(fmt.Sprintf(...))` in `profile.go`.
- **all**: Add `//nolint:gosec` annotations to `exec.CommandContext` calls in `manager.go` and `nop.go`.
- **internal/envutil**: Add package-level documentation.
- **config**: Expand default `DenyWrite` paths to include `/lib`, `/lib64`, `/boot`, `/opt`, `/sys`.
- **internal/envutil**: Add `SanitizeEnv()` function for filtering sensitive environment variables.
- **all**: Tests now pass on Windows — Unix-specific tests skip gracefully with `runtime.GOOS == "windows"` checks.
- **internal/pathutil**: Windows-incompatible subtests (symlinks, glob patterns, file permissions) skip on Windows.
- **proxy**: Socket permission check skips on Windows where Unix permission model doesn't apply.
- **all**: Modernize octal permission literals in test files from `0755`/`0644` to `0o755`/`0o644` (Go 1.13+ notation).

> **Note**: The following entries document the WSL2-based implementation that was developed and subsequently replaced with native Windows sandbox before release.

- **platform/windows/distro**: Remove `ro` from WSL automount options — Simple Mode (WSL1) relies on unprivileged sandbox user for write control instead of read-only mount, allowing WritableRoots to work for examples like `codemod` and `projectinit`.
- **platform/windows/wsl**: Add package-level documentation describing the two-tier WSL2 isolation architecture.
- **platform/windows/distro**: Add `TestWslConfHostnameMatchesDistroName` to guard against hostname constant drift.
- **platform/windows**: WSL2-based sandbox for Windows (requires Windows 10 Build 19041+ with WSL2).
- **platform/windows/detect**: WSL2 availability detection and version parsing.
- **platform/windows/paths**: Bidirectional path translation between Windows and WSL (`ToWSL`/`WSLToWindows`).
- **platform/windows/distro**: Alpine Linux rootfs provisioning with security-hardened wsl.conf.
- **platform/windows/helper**: Sandbox helper binary lifecycle management for Full Mode.
- **cmd/sandbox-helper**: Linux entry point for WSL2 Full Mode sandbox (reuses `MaybeSandboxInit`).
- **procgroup_windows**: Windows process group management via `CREATE_NEW_PROCESS_GROUP`.
- **platform/windows**: Full Mode (Tier 2) support — reuses Linux sandbox isolation inside WSL2 via sandbox-helper binary.
- **platform/windows**: `SetHelperBinary()` API for providing pre-built sandbox-helper binary path.
- **platform/windows**: Automatic path translation for WritableRoots, DenyWrite, DenyRead in Full Mode (Windows → WSL).
- **platform/windows/encoding**: UTF-16LE to UTF-8 decoding for WSL command output.
- **platform/windows/wslcmd**: Centralized WSL command construction with `WSL_UTF8=1` environment variable.
- **platform/windows**: Extract `defaultDistroName` constant, wrap `Cleanup` and `Unregister` errors with context, add mutex for thread-safe helper binary access.
- **platform/windows/detect**: Promote `parseWSLStatusOutput` regex to package-level variable for consistency.
- **platform/windows/distro**: Tighten install directory permissions from `0755` to `0700`.
- **platform/windows/distro**: Replace hardcoded `"agentbox-sb"` hostname in `wslConfContent` with `defaultDistroName` constant via function interpolation.
- **platform/windows**: CVE-2025-53788 mitigation — enforces WSL2 ≥ v2.5.10 minimum version.
- **platform/windows/distro**: WSL2 distro hardened with `interop.enabled=false`, metadata-mode automount, non-root sandbox user, `appendWindowsPath=false`.

### Removed

- **windows**: Removed WSL2 sandbox implementation (wsl.go, wslcmd.go, distro.go, helper.go, fullmode.go, detect.go and related tests)
- **windows**: Removed dependency on WSL2/Alpine Linux distro for sandboxing
- **windows**: Removed `process.go` (`resumeProcess` / `CREATE_SUSPENDED` support) — no longer needed after simplifying to post-start Job Object assignment
- **windows**: Removed vestigial WSL2 utility code: `paths.go` (ToWSL/WSLToWindows), `encoding.go` (cleanWSLOutput), and `cmd/sandbox-helper/` (WSL2 helper binary) — all had zero callers after native refactoring

### Fixed

- **manager**: Fixed PostStartHook memory leak when `WrapCommand` fails — hooks are now properly cleaned up in both `Wrap()` and `runCommand()` error paths
- **windows**: Fixed heap corruption (0xC0000374) caused by calling `FreeSid` on Go-managed SIDs returned by `windows.CreateWellKnownSid()` — these SIDs are allocated via Go's `make([]byte, n)` and must not be freed with Windows API's `LocalFree`
- **windows**: Fixed `setLowIntegrityLevel` to use `tml.Size()` instead of `unsafe.Sizeof(tml)` for correct TOKEN_MANDATORY_LABEL size
- **windows**: Fixed missing `TOKEN_ASSIGN_PRIMARY` access right in `OpenProcessToken` — Go's `CreateProcessAsUser` requires this flag when using `SysProcAttr.Token` for sandbox process creation
- **windows**: Fixed `DefaultConfig()` using Unix paths (`/etc`, `/usr`, etc.) on Windows — now uses platform-aware build tags with `config_default_unix.go` and `config_default_windows.go`
- **windows**: Fixed 3 stale Windows tests: removed `CREATE_SUSPENDED` expectations from `TestPlatform_WrapCommand` and `TestPlatform_WrapCommand_MergesCreationFlags`; rewrote `TestSandbox_E2E_LowIntegrityLevel` to use write-deny probe instead of `whoami /groups` output parsing
- **windows**: Fixed native Windows OpenSSH service setup (port 9023) for proper Windows environment testing
- **nop**: `nopManager.Available()` now correctly returns `false` — the fallback manager runs commands without sandboxing, so it should not report as available.
- **examples/gitops**: Refactored from `fmt.Sprintf` shell command construction to `ExecArgs()` with proper argument arrays, eliminating command injection risk.
- **examples/projectscaffold**: Refactored from `fmt.Sprintf` shell commands to native Go file I/O + `ExecArgs()`, eliminating command injection risk.
- **platform/linux**: Wire `MaxOutputBytes` through worker protocol — worker now truncates stdout/stderr before encoding rather than relying solely on post-hoc truncation in manager.

### Performance

- **internal/pathutil**: Optimize `ExpandGlob` for non-recursive patterns — use `filepath.Glob` fast path instead of `filepath.Walk` for patterns without `**`. Eliminates recursive `/proc` traversal on busy Linux servers (1180ms → 30ms on 335-process system, 39× speedup).
- **windows**: Native sandbox replaces WSL2 — reduces Windows sandbox overhead from ~159ms (WSL2 hot-start) / ~727ms (WSL2 cold-start) to ~17ms (echo P50 16.23ms, P95 18.04ms on Windows Server 2025). Benchmark details:
  - macOS (M1, arm64): echo Min 10.68ms, P50 11.29ms, P95 12.17ms, Mean 11.40ms (Seatbelt)
  - Linux (DevCloud): echo Min 12.09ms, P50 19.98ms, P95 29.33ms, Mean 20.41ms (NS+Landlock+Seccomp)
  - Windows (Server 2025): echo Min 15.58ms, P50 16.23ms, P95 18.04ms, Mean 16.94ms (native Restricted Token + Job Object + Low IL)
  - Full report: [benchmarks/windows-server-2025-report.md](benchmarks/windows-server-2025-report.md)

### Security

- **platform/linux**: Block `io_uring` syscalls (`io_uring_setup`, `io_uring_enter`, `io_uring_register`) in seccomp filter to prevent io_uring-based seccomp bypass.
- **platform/linux**: Enforce `DenyWrite` subpath protection via read-only bind mounts within the mount namespace — prevents writes to paths like `.git/hooks` inside writable project directories.
- **platform/linux**: Normalize `DenyWrite` paths with `filepath.Clean` in Landlock for consistent matching.
- **platform/linux**: Resolve symlinks in bind-mount DenyWrite enforcement to prevent symlink-based bypass.
- **platform/linux**: Expand seccomp blocklist from 6 to ~34 dangerous syscalls (kexec, bpf, perf_event_open, namespace manipulation, kernel modules, chroot, keyring, clock modification, etc.), aligning with Docker's default profile.
- **platform/linux**: Add `CLONE_NEWCGROUP` to namespace isolation flags for cgroup isolation.
- **platform/linux**: Add environment variable sanitization in reexec sandbox — filters sensitive vars (`*_SECRET`, `*_PASSWORD`, `*_API_KEY`, `*_PRIVATE_KEY`, `*_TOKEN`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, etc.) before exec.
- **platform/linux**: Restrict Landlock default readable system paths — replace broad `/etc`, `/proc`, `/dev` with granular sub-paths to reduce information exposure.
- **platform/darwin**: Restrict sandbox UDP rule from wildcard `*:*` to DNS (port 53) and mDNS (port 5353) only, preventing DNS tunneling and unauthorized UDP access.
- **classifier**: Add base64 decode pipe-to-shell detection (`base64 -d | sh` variants, including reordered flags).
- **classifier**: Add `$IFS` word-splitting bypass detection with quote-awareness to reduce false positives.
- **manager**: Protect git worktree target directories — resolved `gitdir:` paths are added to `DenyWrite` for both macOS (Seatbelt) and Linux (Landlock + bind mount) enforcement.

### Documentation

- **README**: Update Windows sandbox documentation for native security (Restricted Token + Job Object + Low IL), add cross-platform benchmark comparison, and development instructions.
- **design/06-windows-wsl-sandbox.md**: Add dependency strategy (§15), proxy bind address fix (§6.2.0), and updated industry comparisons (Appendix D).
- **design/07-security-audit.md**: Update resolution status for all issues; mark 8 items as resolved.
- **design/08-security-gap-analysis.md**: New document — consolidated list of 12 remaining security gaps with priority, fix guidance, and recommended action order.
