# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **classifier**: Merged `chmod-recursive-root` + `chown-recursive-root` into a single `recursive-perm-root` rule — both chmod and chown recursive permission changes on dangerous targets are now detected by one rule
- **classifier**: Merged `curl-pipe-shell` + `base64-pipe-shell` into a single `pipe-to-shell` rule — all piping-to-shell patterns (curl/wget and base64-decoded content) are now detected by one rule
- **classifier**: Split `docker-runtime` into three focused rules: `docker-container` (container lifecycle), `docker-compose` (compose commands), and `kubernetes` (kubectl operations)
- **classifier**: Split backup/restore commands out of `database-client` into a new `database-backup` rule — `pg_dump`, `pg_restore`, `mysqldump`, `mongodump`, `mongorestore`, `mongoexport`, `mongoimport`, and `redis-cli SAVE/BGSAVE` are now classified separately from interactive client connections
- **classifier**: Old rule name constants (`RuleChmodRecursiveRoot`, `RuleChownRecursiveRoot`, `RuleCurlPipeShell`, `RuleBase64PipeShell`, `RuleDockerRuntime`) removed — no backward compatibility aliases
- **classifier**: `ssh-command` rule now excludes `ssh -V` (version check) — uppercase `-V` is a version flag, lowercase `-v` (verbose) is still escalated
- **classifier**: `network-scan` rule now excludes `--version`, `--help`, `-V`, `-h` flags with redirect/pipe stripping — `nmap --version 2>&1 | head -3` is no longer escalated
- **classifier**: `firewall-management` rule now handles piped/redirected commands — `iptables -L -n | head -20` and `iptables --help 2>&1 | head -5` are no longer escalated
- **classifier**: `database-client` rule now handles redirected commands — `redis-cli ping 2>&1` health check is no longer escalated
- **classifier**: `crontab-at` rule now handles redirected/piped commands — `crontab -l 2>/dev/null | head -20` is no longer escalated
- **classifier**: `user-management` rule now excludes `passwd -S` (password status check) as read-only
- **classifier**: `output-redirect-system` rule now excludes safe `/dev/` targets (`/dev/null`, `/dev/zero`, `/dev/tty`, `/dev/stdout`, `/dev/stderr`, `/dev/stdin`, `/dev/random`, `/dev/urandom`, `/dev/fd/*`, `/dev/pts/*`) — eliminates massive false positives from `2>/dev/null` patterns
- **classifier**: `output-redirect-system` rule now correctly terminates redirect target extraction at shell metacharacters (`;`, `&`, `|`, `)`, `\n`) — `cmd 2>/dev/null; next` no longer falsely flags `/dev/null;` as a system path
- **classifier**: `filesystem-format` rule now allows `--help`, `-h`, and `--version` flags for all commands (mkfs, shred, fdisk, parted)
- **classifier**: `partition-management` rule now allows `--help`, `-h`, and `--version` flags for gdisk, cfdisk, sfdisk
- **classifier**: `destructive-xargs` rule now correctly identifies the xargs target command by skipping xargs flags — `docker ps | xargs docker rm` is no longer falsely flagged (only actual `xargs rm` is forbidden)
- **classifier**: `shutdown-reboot` rule now excludes `shutdown /a` (Windows abort shutdown) — aborting a shutdown is safe
- **classifier**: `crontab-at` rule now excludes `crontab -l` (list) as a read-only operation
- **classifier**: `service-management` rule now excludes read-only subcommands: `systemctl status/is-active/is-enabled/is-failed/show/list-*`, `launchctl list/print`, `sc query`, `service <name> status`
- **classifier**: `firewall-management` rule now excludes read-only listing: `iptables -L/-S`, `ufw status`, `nft list`, `firewall-cmd --list-all/--state/--get-active-zones`
- **classifier**: `process-kill` rule now excludes `kill -l` (list signals) as a read-only operation
- **classifier**: `user-management` rule now excludes `--help`, `-h`, `--version` flags
- **classifier**: `database-client` rule now excludes `--help`, `--version`, `-V` flags and `redis-cli ping` health check

### Fixed

- **classifier**: `reverse-shell` rule — `nc -zv` connectivity tests no longer false-positive; the `-z` flag (zero-I/O scan mode) now suppresses the match even in combined flags like `-zv`/`-zuv`
- **classifier**: `reverse-shell` rule — flag matching for nc/ncat uses whole-word comparison; `-ErrorAction` no longer matches `-e`, and PowerShell `Get-Command` listing nc/ncat/netcat is excluded
- **classifier**: `reverse-shell` rule — `ncat -C` (CRLF line endings) no longer false-positives as `-c` (execute); ncat flag detection uses original case
- **classifier**: `reverse-shell` rule — `/dev/tcp/` and `/dev/udp/` connectivity tests (`echo > /dev/tcp/host/port`, `timeout < /dev/tcp/host/port`) no longer false-positive; only commands with actual reverse-shell indicators (exec, non-standard fd redirects like `>&3`/`0>&1`, `/bin/sh`, bare `>&`) are flagged
- **classifier**: `reverse-shell` rule — `bash -i >& /dev/tcp/host/port` (bare stdout+stderr redirect) is now correctly detected as a reverse shell
- **classifier**: `reverse-shell` rule — `0<&1` (stdin from stdout) is now detected as a reverse-shell fd redirect pattern
- **classifier**: `reverse-shell` rule — fixed index out-of-bounds panic in `hasNonStdFDRedirect` when input ends with `>&` or `<&`
- **classifier**: `output-redirect-system` rule — `/dev/tcp/`, `/dev/udp/` (bash virtual devices) and `/proc/self/fd/` added as safe redirect targets
- **classifier**: `isFirewallCmdReadOnly` now requires ALL `--` flags to be in the read-only set — mixed flags like `firewall-cmd --list-all --add-service=http` are correctly escalated instead of bypassing
- **classifier**: Flag scanning loops in `recursive-delete-root`, `chmod-recursive-root`, and `chown-recursive-root` rules now stop at command separators (`&&`, `||`, `;`, `|`) — prevents flags from a subsequent command being attributed to the first (e.g., `rm / && echo -rf`)
- **classifier**: Added missing BSD/macOS xargs value flags (`-J`, `-R`, `-S`, `-E`, `-a`, `--arg-file`) to `xargsValFlags` — fixes incorrect target command identification on macOS
- **classifier**: Removed bare `"version"` from `isDBClientInfoOnly` and `versionHelpFlags` — `sqlite3 version` now correctly triggers escalation instead of being misclassified as a version check (it opens a file named "version")

### Added

- **example**: `examples/trustlevel9/` — scans a large command dataset and reports which commands would be blocked at Trust Level 9 (all Escalated allowed, only Forbidden blocked)
- **example**: `examples/ruleanalysis/` — runs all classification rules against a large command dataset and produces a per-rule breakdown report grouped by decision level

- **api**: `ClassifyResult.String()` method — returns human-readable representation (e.g., `"forbidden (reverse-shell: detected pattern)"`)
- **api**: `ExecResult.String()` method — returns execution summary (e.g., `"exit=0 sandboxed=true duration=42ms stdout=5B stderr=0B"`)
- **api**: `FallbackPolicy` and `NetworkMode` now implement `encoding.TextMarshaler`/`TextUnmarshaler` — JSON serialization produces human-readable strings (`"strict"`, `"warn"`, `"filtered"`, `"blocked"`, `"allowed"`) instead of raw integers; consistent with `Decision` and `ApprovalDecision`
- **api**: All four enum `MarshalText` methods (`Decision`, `FallbackPolicy`, `NetworkMode`, `ApprovalDecision`) now return an error for invalid/unknown values instead of silently marshaling `"unknown"`
- **api**: New sentinel error `ErrEmptyArgs` for empty command args — `Wrap()` with empty `cmd.Args` and `ExecArgs()` with empty `name` now return `ErrEmptyArgs` instead of `ErrNilCommand`, allowing callers to distinguish nil-command from empty-args cases via `errors.Is`

- **api**: `ApprovalRequest.Rule` field (`RuleName`, `json:"rule,omitempty"`) — callbacks now receive the name of the classification rule that triggered escalation
- **doc**: Godoc example functions — `ExampleNewManager`, `ExampleDefaultClassifier`, `ExampleWithCustomRules`, `ExampleWithRuleOverrides`, `ExampleBuiltinRuleNames`
- **doc**: Classification evaluation order documented in `doc.go` and `WithRuleOverrides` — custom rules → protected paths → rule overrides → built-in rules
- **doc**: Comprehensive doc comments on all unexported struct types, `Config` copy-safety note, `Close`/`Cleanup` relationship clarified
- **api**: `Decision.MarshalText`/`UnmarshalText` and `ApprovalDecision.MarshalText`/`UnmarshalText` — these types now implement `encoding.TextMarshaler`/`TextUnmarshaler`, so JSON serialization produces human-readable strings (`"allow"`, `"approve_session"`) instead of raw integers
- **api**: `ConfigOption` named type for Config-level functional options (replaces anonymous `func(*Config)`)
- **api**: `Manager.Close()` method implementing `io.Closer` — delegates to `Cleanup(context.Background())`
- **api**: Compile-time interface compliance checks for all `Classifier` implementations (`ruleClassifier`, `chainClassifier`, `customRuleClassifier`, `protectedPathClassifier`, `overrideClassifier`) and `ApprovalCache` implementations (`MemoryApprovalCache`)
- **api**: JSON struct tags on all exported structs — `ClassifyResult`, `ExecResult`, `Violation`, `UserRule`, `RuleOverride`, `ProtectedPath`, `ApprovalRequest`, `Config`, `FilesystemConfig`, `NetworkConfig`, `MITMProxyConfig`, `ForbiddenCommandError`, `EscalatedCommandError`; function/interface fields use `json:"-"`
- **classifier**: `RuleName` typed string and 44 exported constants (`RuleForkBomb`, `RuleSudo`, `RuleDockerRuntime`, etc.) for type-safe, IDE-friendly identification of built-in classification rules
- **classifier**: `BuiltinRuleNames()` function returns all built-in rule names in evaluation order
- **classifier**: `RuleOverride` struct and `WithRuleOverrides` option to change the decision of specific built-in rules by name (e.g., override `RuleDockerRuntime` to `Allow`)
- **approval**: `ApprovalCache` interface and `MemoryApprovalCache` implementation for caching user approval decisions on escalated commands, avoiding repeated prompts for the same command within a session
- **approval**: `WithApprovalCache` config helper for setting the approval cache on a `Config`
- **approval**: Both `manager` and `nopManager` integrate the cache: consult it before invoking `ApprovalCallback` and store the result after
- **classifier**: New `ProtectedPath` type and `WithProtectedPaths`/`WithDefaultProtectedPaths` options — defense-in-depth layer that detects write operations (`rm`, `mv`, `cp`, `chmod`, `chown`, `tee`, `sed -i`, `truncate`, `>` redirect, `>>` redirect, `git checkout --`) targeting sensitive paths (`.git/hooks`, `.agent`, `.claude`, `.vscode`, `.idea`, `.env`); inspired by Claude Code and Codex CLI protected directories
- **classifier**: New `UserRule` type and `WithCustomRules` option — lets users define custom classification rules (glob patterns) that are evaluated before built-in rules, enabling per-command overrides (inspired by Claude Code permission rules and Codex CLI approval policy)
- **classifier**: New escalated rule `sudo` — requires approval for `sudo` and `doas` privilege escalation commands
- **classifier**: New forbidden rule `shutdown-reboot` — blocks `shutdown`, `reboot`, `halt`, `poweroff`, `init 0`, and `init 6`
- **classifier**: New escalated rule `su-privilege` — requires approval for `su` privilege escalation
- **classifier**: New helper `isSimpleCommand()` for quote-aware compound operator detection
- **classifier**: New allow rule `version-check` — allows `X --version`, `X -v`, `X --help`, etc.
- **classifier**: New allow rule `windows-safe-commands` — allows Windows/PowerShell safe read-only commands (dir, where, Get-Command, etc.)
- **classifier**: New allow rule `cd-sleep` — allows directory navigation (cd/pushd/popd) and sleep
- **classifier**: New allow rule `process-list` — allows read-only process inspection (ps, top, htop, pgrep)
- **classifier**: New escalated rule `credential-access` — requires approval for reading sensitive credential/secret files (`.ssh/id_*`, `.aws/credentials`, `.env`, `*.pem`, `*.key`, `*secret*`, `*password*`, etc.)
- **classifier**: New forbidden rule `kernel-module` — blocks kernel module manipulation (`insmod`, `rmmod`, `modprobe`, `depmod`)
- **classifier**: New forbidden rule `partition-management` — blocks disk partition management (`gdisk`, `cfdisk`, `sfdisk`)
- **classifier**: New escalated rule `user-management` — requires approval for user/group management (`useradd`, `userdel`, `usermod`, `groupadd`, `groupdel`, `passwd`, `chpasswd`, `adduser`, `deluser`, etc.)

### Fixed

- **ci**: Set `GOMODCACHE` at job level for `test-windows` — prevents sandbox tests (which create restricted users and modify ACLs) from corrupting the shared Go module cache, fixing "Access is denied" errors on zip hash verification
- **windows**: Platform-specific `defaultShellPath()` and `defaultShellFlag()` — uses `cmd.exe /c` on Windows instead of hardcoded `/bin/sh -c`; falls back to `C:\Windows\System32\cmd.exe` when `SystemRoot` is unset
- **windows**: `NetLocalGroupDel` and `NetUserDel` now treat "not found" errors (2220/2221) as success during cleanup, preventing spurious test failures
- **classifier**: Use `path.Match` instead of `filepath.Match` in custom rule glob matching — fixes incorrect backslash handling on Windows
- **tests**: Use `testutil.EchoCommand()` for cross-platform test commands instead of hardcoded `echo`
- **classifier**: New forbidden rule `history-exec` — blocks history re-execution (`history | sh`, `history | bash`, `fc -s`, `fc -e`)
- **classifier**: New escalated rule `file-permission` — requires approval for `chmod`, `chown`, `chgrp` (non-root-recursive usages; root-recursive remains forbidden)
- **classifier**: New escalated rule `firewall-management` — requires approval for firewall manipulation (`iptables`, `ip6tables`, `ufw`, `nft`, `firewall-cmd`)
- **classifier**: New escalated rule `network-scan` — requires approval for network scanning/capture (`nmap`, `tcpdump`, `tshark`, `wireshark`, `ettercap`, `masscan`)
- **classifier**: New escalated rule `docker-runtime` — requires approval for container runtime operations (`docker run/exec/stop/rm`, `docker-compose up/down`, `kubectl exec/apply/delete/scale`)
- **classifier**: New escalated rule `database-client` — requires approval for database access (`mysql`, `psql`, `sqlite3`, `redis-cli`, `mongo`, `mongosh`, `pg_dump`, `mysqldump`)
- **classifier**: New forbidden rule `destructive-find` — blocks `find` commands with `-delete` or `-exec rm` actions
- **classifier**: New forbidden rule `destructive-xargs` — blocks `xargs rm` patterns that can delete files at scale
- **classifier**: New forbidden rule `output-redirect-system` — blocks commands that redirect output to critical system paths (`/etc/`, `/dev/`, `/boot/`, `/proc/`, `/sys/`)
- **classifier**: New escalated rule `git-stash-drop` — requires approval for `git stash drop` and `git stash clear` which destroy stashed work
- **classifier**: New escalated rule `eval-exec` — requires approval for `eval`, `source`, and `.` (dot-source) shell builtins that execute arbitrary code
- **classifier**: Expanded `credential-access` rule to detect environment credential enumeration via `env | grep -i secret`, `printenv | grep password`, etc.
- **classifier**: Added `test` and `[` to `common-safe-commands` allow list — read-only file test builtins
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

- **classifier**: Split `classifier_rules.go` (3368 lines) into 5 focused files: `classifier_rules.go` (infrastructure, 261 lines), `classifier_rules_forbidden.go` (17 forbidden rules, 1243 lines), `classifier_rules_escalated.go` (22 escalated rules, 1211 lines), `classifier_rules_allow.go` (6 allow rules, 333 lines), `classifier_helpers.go` (shared utilities, 353 lines) — pure refactoring, no behavioral changes
- **classifier**: Split `classifier_test.go` (4838 lines, 173 tests) into 5 focused test files matching source structure: `classifier_test.go` (core, 509 lines), `classifier_rules_forbidden_test.go` (61 tests), `classifier_rules_escalated_test.go` (50 tests), `classifier_rules_allow_test.go` (15 tests), `classifier_helpers_test.go` (16 tests) — pure refactoring
- **manager**: Split `manager.go` (916 lines) into 3 files: `manager.go` (core, 692 lines), `manager_update.go` (dynamic config update, 157 lines), `manager_helpers.go` (utilities, 80 lines) — pure refactoring
- **pathutil**: Split `internal/pathutil/pathutil.go` (389 lines) into 5 focused files by responsibility: `symlink.go`, `glob.go`, `dangerous.go`, `git.go`, `pathutil.go`; also split matching test file (1092 lines) — pure refactoring
- **classifier**: `ClassifyResult.Rule` field type changed from `string` to `RuleName` for type safety
- **api**: `WithApprovalCache` now returns named `ConfigOption` type instead of anonymous `func(*Config)`
- **approval**: `MemoryApprovalCache` is now zero-value usable (no panic without `NewMemoryApprovalCache`)
- **classifier**: Changed `sudo`, `su-privilege`, `credential-access`, and `user-management` rules from Forbidden to Escalated to align with industry best practices; also removed the `su -c` exemption since it performs the same privilege escalation as bare `su`
- **classifier**: Moved several over-classified commands back to Sandboxed to follow the "let the sandbox handle it" principle:
  - `pip install` (non-sudo) — sandbox filesystem/network restrictions are sufficient
  - `git` local operations (`add`, `commit`, `stash`, `checkout`, etc.) — only remote/destructive ops (`push`, `pull`, `clone`, `fetch`, `reset`, `rebase`, `merge`) remain Escalated
  - `mkdir` — sandbox filesystem restrictions are sufficient
  - `lsof` — read-only process info, safe in sandbox
  - All network info commands (`ping`, `netstat`, `ss`, `ifconfig`, `ip`, `dig`, `nslookup`, `traceroute`, etc.) — removed `network-info-read` Allow rule entirely; sandbox network restrictions handle these
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

### Fixed

- **classifier**: `credentialSensitiveGlobs` now uses word-boundary matching (`containsWordToken`) to avoid false positives like "secretariat" being treated as a credential file
- **classifier**: `processKillRule` now matches `stop-process` (lowercase) in addition to `Stop-Process`, consistent with Windows/PowerShell case-insensitivity
- **classifier**: `windowsSafeCommandsRule` now uses `baseCommand()` to strip path prefixes from commands (e.g. `/usr/bin/where` → `where`)
- **classifier**: `gitReadCommandsRule` now uses shared `findGitSubcommand()` to skip git global flags like `-C /path`, so `git -C /some/path status` is correctly allowed
- **classifier**: Compound command parsing fix — Allow rules (`common-safe-commands`, `git-read-commands`) now reject commands containing top-level `&&`, `||`, or `;` operators so that `which python && rm -rf /` is no longer classified as Allow
- **classifier**: Fix `reverse-shell` rule to detect `netcat` (alias for `nc`) with `-e`/`-c`/`--exec` flags — previously only `nc` and `ncat` were caught
- **classifier**: Fix ~242 false positives in command classifier rules
  - `rsNC`/`rsNcat`: Use word-boundary matching so `rsync -e ssh`, `grep -c`, `scutil --nc` no longer trigger the reverse-shell rule; also check `-e`/`-c` flags only in the same compound-command segment as `nc`
  - `curlPipeShellRule`/`containsPipeToShell`: Allow `python`/`python3` with `-c` or `-m` flags (inline code, not stdin eval); bare `python3` still flagged
  - `rsPythonSocket`: Inline `python -c "import socket"` no longer flagged unless reverse-shell indicators (dup2, subprocess.call, subprocess.popen, pty.spawn, os.system, /bin/sh, /bin/bash) are present
  - Pipe splitting now uses `splitTopLevelPipes` that respects `$(...)` subshells, backticks, and quotes, preventing pipes inside `$(echo|shasum)` from being treated as top-level pipes
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

### Removed

- **windows**: Removed WSL2 sandbox implementation (wsl.go, wslcmd.go, distro.go, helper.go, fullmode.go, detect.go and related tests)
- **windows**: Removed dependency on WSL2/Alpine Linux distro for sandboxing
- **windows**: Removed `process.go` (`resumeProcess` / `CREATE_SUSPENDED` support) — no longer needed after simplifying to post-start Job Object assignment
- **windows**: Removed vestigial WSL2 utility code: `paths.go` (ToWSL/WSLToWindows), `encoding.go` (cleanWSLOutput), and `cmd/sandbox-helper/` (WSL2 helper binary) — all had zero callers after native refactoring

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
