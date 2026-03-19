# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **testutil**: New test utility package providing cross-platform helpers for Windows test compatibility — `Shell()`, `ShellArgs()`, `EchoCommand()`, `ExitCommand()`, `PrintEnvCommand()`, `PwdCommand()`, `StderrCommand()`, `SleepCommand()`, `TempDir()`, `TempPath()`, `HomeDir()`, `SkipIfWindows()`, `SkipIfNotWindows()`, `RequireUnix()`.

- **platform/linux**: Persistent sandbox worker (Zygote mode) — maintains a pre-sandboxed worker process that handles commands via Unix socket IPC, eliminating per-command Go runtime restart. Reduces Linux sandbox overhead from ~140ms to ~20µs protocol round-trip. Falls back to re-exec when worker is unavailable. Note: worker mode uses the broadest Landlock config from Manager initialization; per-command Landlock tightening is planned for a future release.
- **platform**: New `WorkerExecutor` optional interface for platforms to provide fast command execution via persistent workers.

### Changed

- **platform/darwin**: Add profile string cache (Tier 1) — repeated `WrapCommand` calls with identical configs skip profile rebuild (~7x speedup)
- **platform/darwin**: Add path canonicalization cache (Tier 2) — `filepath.EvalSymlinks` results cached via `sync.Map` to avoid repeated syscalls
- **tests**: Migrated ~60 Windows `t.Skip` patterns across 20+ test files to use `testutil` helpers, enabling meaningful test execution on Windows CI.
- **ci**: Expanded Windows CI test scope from limited subsets to full `go test ./...`.

- **platform/windows/encoding**: UTF-16LE to UTF-8 decoding for WSL command output — fixes `Available()` returning false on systems where `wsl.exe` emits UTF-16LE.
- **platform/windows/wslcmd**: Centralized WSL command construction with `WSL_UTF8=1` environment variable.
- **examples/agentsim**: New multi-step AI coding agent example — writes buggy code, runs tests, detects failure, fixes bug, re-tests until success. Cross-platform (macOS, Linux, Windows).
- **examples/codereview**: New code review agent example — scaffolds project with issues, runs `go vet`/`gofmt`/`go test`, generates structured JSON review report. Cross-platform.
- **examples/healthcheck**: New system health monitor example — inspects Go environment, sandbox capabilities, generates JSON health report. Cross-platform.
- **examples/researchflow**: New research agent example — discovers Go stdlib packages, retrieves docs, generates structured JSON research report. Cross-platform.
- **examples/codemod**: New code modification agent example — scaffolds project with formatting and lint issues, iteratively detects and fixes them using `gofmt`/`go vet`. Cross-platform.
- **examples/projectinit**: New project initialization agent example — bootstraps a Go microservice project, runs full CI pipeline (build, vet, format, test), generates JSON CI report. Cross-platform.
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

### Changed

- **platform/windows/distro**: Remove `ro` from WSL automount options — Simple Mode (WSL1) relies on unprivileged sandbox user for write control instead of read-only mount, allowing WritableRoots to work for examples like `codemod` and `projectinit`.

### Security

- **platform/windows**: CVE-2025-53788 mitigation — enforces WSL2 ≥ v2.5.10 minimum version.
- **platform/windows/distro**: WSL2 distro hardened with `interop.enabled=false`, metadata-mode automount, non-root sandbox user, `appendWindowsPath=false`.
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
- **internal/pathutil**: Add `ResolveGitWorktree()` to parse `.git` worktree files and resolve the actual git directory path.
- **manager**: Protect git worktree target directories — resolved `gitdir:` paths are added to `DenyWrite` for both macOS (Seatbelt) and Linux (Landlock + bind mount) enforcement.

### Documentation

- **README**: Update Windows WSL2 status to "Tested (beta)", add Windows prerequisites, WSL2 sandbox section, and development instructions.
- **design/06-windows-wsl-sandbox.md**: Add dependency strategy (§15), proxy bind address fix (§6.2.0), and updated industry comparisons (Appendix D).
- **design/07-security-audit.md**: Update resolution status for all issues; mark 8 items as resolved.
- **design/08-security-gap-analysis.md**: New document — consolidated list of 12 remaining security gaps with priority, fix guidance, and recommended action order.

### Changed

- **platform/darwin**: Fix `QF1012` lint warning — use `fmt.Fprintf` instead of `WriteString(fmt.Sprintf(...))` in `profile.go`.
- **platform/windows**: Extract `defaultDistroName` constant, wrap `Cleanup` and `Unregister` errors with context, add mutex for thread-safe helper binary access.
- **platform/windows/detect**: Promote `parseWSLStatusOutput` regex to package-level variable for consistency.
- **platform/windows/distro**: Tighten install directory permissions from `0755` to `0700`.
- **all**: Add `//nolint:gosec` annotations to `exec.CommandContext` calls in `manager.go` and `nop.go`.
- **internal/envutil**: Add package-level documentation.
- **config**: Expand default `DenyWrite` paths to include `/lib`, `/lib64`, `/boot`, `/opt`, `/sys`.
- **internal/envutil**: Add `SanitizeEnv()` function for filtering sensitive environment variables.
- **all**: Tests now pass on Windows — Unix-specific tests skip gracefully with `runtime.GOOS == "windows"` checks.
- **internal/pathutil**: Windows-incompatible subtests (symlinks, glob patterns, file permissions) skip on Windows.
- **proxy**: Socket permission check skips on Windows where Unix permission model doesn't apply.
