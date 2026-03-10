# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **platform/linux**: Block `io_uring` syscalls (`io_uring_setup`, `io_uring_enter`, `io_uring_register`) in seccomp filter to prevent io_uring-based seccomp bypass.
- **platform/linux**: Enforce `DenyWrite` subpath protection via read-only bind mounts within the mount namespace — prevents writes to paths like `.git/hooks` inside writable project directories.
- **platform/linux**: Normalize `DenyWrite` paths with `filepath.Clean` in Landlock for consistent matching.
- **platform/linux**: Resolve symlinks in bind-mount DenyWrite enforcement to prevent symlink-based bypass.
- **internal/pathutil**: Add `ResolveGitWorktree()` to parse `.git` worktree files and resolve the actual git directory path.
- **manager**: Protect git worktree target directories — resolved `gitdir:` paths are added to `DenyWrite` for both macOS (Seatbelt) and Linux (Landlock + bind mount) enforcement.

### Documentation

- **design/06-windows-wsl-sandbox.md**: Add dependency strategy (§15), proxy bind address fix (§6.2.0), and updated industry comparisons (Appendix D).

### Changed

- **config**: Expand default `DenyWrite` paths to include `/lib`, `/lib64`, `/boot`, `/opt`, `/sys`.
- **internal/envutil**: Add `SanitizeEnv()` function for filtering sensitive environment variables.
