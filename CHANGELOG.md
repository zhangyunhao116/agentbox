# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **platform/linux**: Expand seccomp blocklist from 6 to ~34 dangerous syscalls (kexec, bpf, perf_event_open, namespace manipulation, kernel modules, chroot, keyring, clock modification, etc.), aligning with Docker's default profile.
- **platform/linux**: Add `CLONE_NEWCGROUP` to namespace isolation flags for cgroup isolation.
- **platform/linux**: Add environment variable sanitization in reexec sandbox — filters sensitive vars (`*_SECRET`, `*_PASSWORD`, `*_API_KEY`, `*_PRIVATE_KEY`, `*_TOKEN`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, etc.) before exec.
- **platform/linux**: Restrict Landlock default readable system paths — replace broad `/etc`, `/proc`, `/dev` with granular sub-paths to reduce information exposure.
- **platform/darwin**: Restrict sandbox UDP rule from wildcard `*:*` to DNS (port 53) and mDNS (port 5353) only, preventing DNS tunneling and unauthorized UDP access.
- **classifier**: Add base64 decode pipe-to-shell detection (`base64 -d | sh` variants, including reordered flags).
- **classifier**: Add `$IFS` word-splitting bypass detection with quote-awareness to reduce false positives.

### Documentation

- **design/07-security-audit.md**: Update resolution status for all issues; mark 8 items as resolved.
- **design/08-security-gap-analysis.md**: New document — consolidated list of 12 remaining security gaps with priority, fix guidance, and recommended action order.

### Changed

- **config**: Expand default `DenyWrite` paths to include `/lib`, `/lib64`, `/boot`, `/opt`, `/sys`.
- **internal/envutil**: Add `SanitizeEnv()` function for filtering sensitive environment variables.
