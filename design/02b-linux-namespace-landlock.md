# Linux Namespace + Landlock Sandbox Implementation

> **Status**: Implemented  
> **Author**: Agent  
> **Date**: 2026-02-15 (updated 2026-02-16)  
> **Scope**: agentbox Linux Namespace + Landlock + Seccomp implementation  
> **Prerequisite docs**: [01a-overview-api.md](./01a-overview-api.md), [01b-structure-flow.md](./01b-structure-flow.md), [02a-macos-seatbelt.md](./02a-macos-seatbelt.md)

> **Build note**: All files in `platform/linux/` have `//go:build linux` build tags and only compile on Linux.

---

## 1. Four-Layer Isolation Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 1: User Namespace (CLONE_NEWUSER)                        │
│  └── Unprivileged user creates namespaces; UID 0 → host user   │
│                                                                 │
│  Layer 2: Mount/PID/Net Namespace                               │
│  ├── CLONE_NEWNS:  read-only root + writable bind mounts        │
│  ├── CLONE_NEWPID: isolated process tree + isolated /proc       │
│  └── CLONE_NEWNET: complete network isolation (when restricted) │
│                                                                 │
│  Layer 3: Landlock (file path-level restrictions)               │
│  ├── Direct syscall implementation (no external library)        │
│  └── ABI version auto-detection with graceful degradation       │
│                                                                 │
│  Layer 4: Seccomp (system call filtering)                       │
│  ├── Raw BPF filter (no external library)                       │
│  ├── Blocks socket(AF_UNIX, ...) creation                       │
│  └── Architecture validation (amd64/arm64)                      │
└─────────────────────────────────────────────────────────────────┘
```

Each layer works independently — if one layer is bypassed, the others still provide protection.

**Key implementation difference from design**: No external dependencies. Landlock uses direct syscalls (not `go-landlock`). Seccomp uses raw BPF instructions (not `go-seccomp-bpf`). This maintains the "single binary, zero dependencies" design goal.

---

## 2. Platform Type

> **Source**: `platform/linux/linux.go`

```go
package linux

// Platform implements the platform.Platform interface using Linux namespaces,
// Landlock filesystem restrictions, and seccomp BPF filters.
type Platform struct {
	kernelVersion KernelVersion
	landlockABI   int
}

// New creates a new Platform, detecting kernel version and Landlock
// support at construction time.
func New() *Platform {
	kv, _ := DetectKernelVersion()
	ll := DetectLandlock()
	return &Platform{
		kernelVersion: kv,
		landlockABI:   ll.ABIVersion,
	}
}
```

**Key naming**: The type is `linux.Platform`. The struct stores `kernelVersion` and `landlockABI` detected at construction time.

### 2.1 Interface Methods

```go
func (l *Platform) Name() string    { return "linux-namespace" }
func (l *Platform) Available() bool { return true }

func (l *Platform) Capabilities() platform.Capabilities {
	return platform.Capabilities{
		FileReadDeny:   l.landlockABI >= 1,
		FileWriteAllow: l.landlockABI >= 1,
		NetworkDeny:    true, // via CLONE_NEWNET
		NetworkProxy:   true, // via network namespace + proxy bridge
		PIDIsolation:   true, // via CLONE_NEWPID
		SyscallFilter:  true, // via seccomp BPF
		ProcessHarden:  true, // via prctl
	}
}
```

**Note**: `FileReadDeny` and `FileWriteAllow` are conditional on Landlock ABI version ≥ 1. All other capabilities are always true.

### 2.2 CheckDependencies

```go
func (l *Platform) CheckDependencies() *platform.DependencyCheck {
	check := &platform.DependencyCheck{}

	// Require kernel >= 5.13 for Landlock ABI v1.
	if !l.kernelVersion.AtLeast(5, 13) {
		check.Warnings = append(check.Warnings,
			fmt.Sprintf("kernel %s < 5.13: Landlock filesystem restrictions unavailable", l.kernelVersion))
	}

	// Check Landlock support.
	ll := DetectLandlock()
	if !ll.Supported {
		check.Warnings = append(check.Warnings,
			"Landlock not supported: filesystem restrictions will be limited")
	}

	return check
}
```

**Note**: Unlike the original design, there are no `Errors` — only `Warnings`. Missing Landlock or old kernel versions produce warnings, not fatal errors. There is no minimum kernel version check for user namespaces (3.8) or seccomp (4.8).

### 2.3 WrapCommand

```go
func (l *Platform) WrapCommand(_ context.Context, cmd *exec.Cmd, cfg *platform.WrapConfig) error {
	if cfg == nil {
		cfg = &platform.WrapConfig{}
	}

	// Configure namespace isolation (user, mount, PID, and optionally network).
	configureNamespaces(cmd, cfg)

	// NOTE: Resource limits are applied in the re-exec child process
	// (sandboxInit in reexec.go) rather than here, to avoid affecting the
	// parent process. The ResourceLimits are passed via the reExecConfig.

	return nil
}
```

**Key difference from design**: `WrapCommand` only calls `configureNamespaces`. It does **not** set up re-exec, pipe-based config passing, or network bridges. The re-exec pattern is handled separately by the `MaybeSandboxInit` / `sandboxInit` flow. Resource limits are applied in the child process.

### 2.4 Cleanup

```go
func (l *Platform) Cleanup(_ context.Context) error {
	return nil // No-op: namespaces are cleaned up when the process exits.
}
```

---

## 3. Layer 1+2: Namespace Configuration

> **Source**: `platform/linux/namespace.go`

### 3.1 configureNamespaces

```go
func configureNamespaces(cmd *exec.Cmd, cfg *platform.WrapConfig) {
	flags := syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID
	if cfg.NeedsNetworkRestriction {
		flags |= syscall.CLONE_NEWNET
	}

	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Cloneflags = uintptr(flags)

	// Map the current user to root inside the user namespace.
	cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{
		{ContainerID: 0, HostID: os.Getuid(), Size: 1},
	}
	cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{
		{ContainerID: 0, HostID: os.Getgid(), Size: 1},
	}
}
```

**Behavioral notes**:
- Always creates User, Mount, and PID namespaces.
- Network namespace (`CLONE_NEWNET`) is only added when `NeedsNetworkRestriction` is true.
- `GidMappingsEnableSetgroups` is **not** set (defaults to false in Go).
- The `Cloneflags` field is set as `uintptr(flags)`.

### 3.2 Resource Limits (applied in child process)

```go
// Linux rlimit resource constants.
const (
	rlimitCPU    = 0  // RLIMIT_CPU
	rlimitAS     = 9  // RLIMIT_AS (address space / virtual memory)
	rlimitNOFILE = 7  // RLIMIT_NOFILE
	rlimitNPROC  = 6  // RLIMIT_NPROC
)

type rlimitEntry struct {
	resource int
	rlimit   syscall.Rlimit
}

func applyResourceLimits(cmd *exec.Cmd, limits *platform.ResourceLimits) error {
	if limits == nil {
		return nil
	}

	var entries []rlimitEntry
	if limits.MaxProcesses > 0 {
		entries = append(entries, rlimitEntry{
			resource: rlimitNPROC,
			rlimit:   syscall.Rlimit{Cur: uint64(limits.MaxProcesses), Max: uint64(limits.MaxProcesses)},
		})
	}
	if limits.MaxFileDescriptors > 0 {
		entries = append(entries, rlimitEntry{
			resource: rlimitNOFILE,
			rlimit:   syscall.Rlimit{Cur: uint64(limits.MaxFileDescriptors), Max: uint64(limits.MaxFileDescriptors)},
		})
	}
	if limits.MaxMemoryBytes > 0 {
		entries = append(entries, rlimitEntry{
			resource: rlimitAS,
			rlimit:   syscall.Rlimit{Cur: uint64(limits.MaxMemoryBytes), Max: uint64(limits.MaxMemoryBytes)},
		})
	}
	if limits.MaxCPUSeconds > 0 {
		entries = append(entries, rlimitEntry{
			resource: rlimitCPU,
			rlimit:   syscall.Rlimit{Cur: uint64(limits.MaxCPUSeconds), Max: uint64(limits.MaxCPUSeconds)},
		})
	}

	for _, e := range entries {
		if err := syscall.Setrlimit(e.resource, &e.rlimit); err != nil {
			return fmt.Errorf("setrlimit resource %d: %w", e.resource, err)
		}
	}
	return nil
}
```

**Note**: Unlike macOS (which uses `ulimit` in a shell wrapper), Linux applies rlimits directly via `syscall.Setrlimit` in the child process. The `cmd` parameter is retained for API compatibility but is not used. `MaxProcesses` (RLIMIT_NPROC) **is** applied on Linux (unlike macOS where it is skipped).

---

## 4. Re-exec Pattern

> **Source**: `platform/linux/reexec.go`

### 4.1 Design

The re-exec pattern allows the sandbox to apply restrictions (Landlock, seccomp, mount namespace setup) inside the child process without affecting the parent. The process re-executes itself, detects the `_AGENTBOX_CONFIG` environment variable, and enters sandbox-init mode.

### 4.2 reExecConfig

```go
const reExecEnvKey = "_AGENTBOX_CONFIG"

// reExecConfig is the configuration passed to the re-exec child via a pipe.
type reExecConfig struct {
	WritableRoots           []string                 `json:"writable_roots,omitempty"`
	DenyWrite               []string                 `json:"deny_write,omitempty"`
	DenyRead                []string                 `json:"deny_read,omitempty"`
	NeedsNetworkRestriction bool                     `json:"needs_network_restriction,omitempty"`
	ResourceLimits          *platform.ResourceLimits `json:"resource_limits,omitempty"`
}
```

**Note**: This is a separate struct from `platform.WrapConfig` — it only includes the fields needed by the child process. The config is passed via a pipe file descriptor (the env var value is the fd number).

### 4.3 MaybeSandboxInit

```go
func MaybeSandboxInit() bool {
	fdStr := os.Getenv(reExecEnvKey)
	if fdStr == "" {
		return false
	}
	code := sandboxInit(fdStr)
	os.Exit(code)
	return true // unreachable, but satisfies the compiler
}
```

This is also exposed at the root package level (`agentbox.MaybeSandboxInit()`) which checks `runtime.GOOS == "linux"` before delegating.

### 4.4 sandboxInit

```go
func sandboxInit(fdStr string) int {
	// Lock the OS thread because seccomp, landlock_restrict_self, and prctl
	// are per-thread operations.
	runtime.LockOSThread()

	fd, err := strconv.Atoi(fdStr)
	if err != nil { ... return 1 }

	configFile := os.NewFile(uintptr(fd), "config-pipe")
	if configFile == nil { ... return 1 }
	defer configFile.Close()

	var cfg reExecConfig
	if err := json.NewDecoder(configFile).Decode(&cfg); err != nil { ... return 1 }

	// 1. Apply process hardening.
	if err := hardenProcess(); err != nil { ... return 1 }

	// 2. Apply Landlock filesystem restrictions.
	wrapCfg := &platform.WrapConfig{
		WritableRoots:           cfg.WritableRoots,
		DenyWrite:               cfg.DenyWrite,
		DenyRead:                cfg.DenyRead,
		NeedsNetworkRestriction: cfg.NeedsNetworkRestriction,
		ResourceLimits:          cfg.ResourceLimits,
	}
	if err := applyLandlock(wrapCfg); err != nil { ... return 1 }

	// 3. Apply resource limits in the child process context.
	if cfg.ResourceLimits != nil {
		if err := applyResourceLimits(nil, cfg.ResourceLimits); err != nil { ... return 1 }
	}

	// 4. Apply seccomp filter to block AF_UNIX sockets.
	if err := ApplySeccomp(); err != nil { ... return 1 }

	// 5. Exec the real command (remaining args after the re-exec marker).
	args := os.Args[1:]
	if len(args) == 0 { ... return 1 }

	os.Unsetenv(reExecEnvKey)

	if err := syscall.Exec(args[0], args, os.Environ()); err != nil { ... return 1 }
	return 0 // unreachable
}
```

**Key behavioral differences from original design**:
1. **`runtime.LockOSThread()`** is called at the start — seccomp, Landlock, and prctl are per-thread operations.
2. Config is read via `json.NewDecoder` (not `io.ReadAll` + `json.Unmarshal`).
3. **Landlock failure is fatal** (returns 1), not best-effort as in the original design.
4. **Seccomp is always applied** (not conditional on `NeedsNetworkRestriction`).
5. Command args are `os.Args[1:]` directly (no `--` separator search).
6. The order is: hardenProcess → Landlock → resource limits → seccomp → exec.

---

## 5. Layer 3: Landlock

> **Source**: `platform/linux/landlock.go`

### 5.1 Direct Syscall Implementation

Landlock is implemented via **direct syscalls** — no external `go-landlock` library:

```go
const (
	sysLandlockCreateRuleset = 444
	sysLandlockAddRule       = 445
	sysLandlockRestrictSelf  = 446
)
```

### 5.2 Access Flags

```go
const (
	accessFSExecute    = 1 << 0
	accessFSWriteFile  = 1 << 1
	accessFSReadFile   = 1 << 2
	accessFSReadDir    = 1 << 3
	accessFSRemoveDir  = 1 << 4
	accessFSRemoveFile = 1 << 5
	accessFSMakeChar   = 1 << 6
	accessFSMakeDir    = 1 << 7
	accessFSMakeReg    = 1 << 8
	accessFSMakeSock   = 1 << 9
	accessFSMakeFifo   = 1 << 10
	accessFSMakeBlock  = 1 << 11
	accessFSMakeSym    = 1 << 12
	accessFSRefer      = 1 << 13 // ABI v2
	accessFSTruncate   = 1 << 14 // ABI v3
)
```

### 5.3 Kernel Structures

```go
type landlockRulesetAttr struct {
	handledAccessFS uint64
}

type landlockPathBeneathAttr struct {
	allowedAccess uint64
	parentFd      int32
	_             [4]byte // padding
}
```

### 5.4 DetectLandlock

```go
type LandlockInfo struct {
	Supported  bool
	ABIVersion int
	Features   string
}

func DetectLandlock() LandlockInfo {
	// Use landlock_create_ruleset with flag LANDLOCK_CREATE_RULESET_VERSION
	// to query the ABI version without creating a ruleset.
	version, _, errno := syscall.Syscall(
		uintptr(sysLandlockCreateRuleset),
		0, // attr = NULL
		0, // size = 0
		1, // flags = LANDLOCK_CREATE_RULESET_VERSION
	)
	if errno != 0 {
		return LandlockInfo{
			Supported: false,
			Features:  "landlock not available: " + errno.Error(),
		}
	}

	abi := int(version)
	features := fmt.Sprintf("ABI v%d", abi)
	switch {
	case abi >= 3: features += " (fs access, refer, truncate)"
	case abi >= 2: features += " (fs access, refer)"
	case abi >= 1: features += " (fs access)"
	}

	return LandlockInfo{Supported: true, ABIVersion: abi, Features: features}
}
```

### 5.5 applyLandlock

```go
func applyLandlock(cfg *platform.WrapConfig) error {
	info := DetectLandlock()
	if !info.Supported {
		return nil // Landlock not available; skip gracefully.
	}

	// 1. Determine handled access rights based on ABI version.
	var handledAccess uint64
	handledAccess = accessFSExecute | accessFSWriteFile | accessFSReadFile |
		accessFSReadDir | accessFSRemoveDir | accessFSRemoveFile |
		accessFSMakeChar | accessFSMakeDir | accessFSMakeReg |
		accessFSMakeSock | accessFSMakeFifo | accessFSMakeBlock |
		accessFSMakeSym
	if info.ABIVersion >= 2 { handledAccess |= accessFSRefer }
	if info.ABIVersion >= 3 { handledAccess |= accessFSTruncate }

	// 2. Create the ruleset.
	attr := landlockRulesetAttr{handledAccessFS: handledAccess}
	rulesetFd, _, errno := syscall.Syscall(
		uintptr(sysLandlockCreateRuleset),
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
		0,
	)
	if errno != 0 { return fmt.Errorf("landlock_create_ruleset: %w", errno) }
	defer syscall.Close(int(rulesetFd))

	// 3. Define access right sets.
	writeAccess := uint64(accessFSWriteFile | accessFSReadFile | accessFSReadDir |
		accessFSRemoveDir | accessFSRemoveFile | accessFSMakeDir |
		accessFSMakeReg | accessFSMakeSym | accessFSExecute)
	if info.ABIVersion >= 2 { writeAccess |= accessFSRefer }
	if info.ABIVersion >= 3 { writeAccess |= accessFSTruncate }

	readAccess := uint64(accessFSExecute | accessFSReadFile | accessFSReadDir)

	// 4. Add rules for writable roots (skip paths in DenyWrite).
	denyWriteSet := make(map[string]bool, len(cfg.DenyWrite))
	for _, p := range cfg.DenyWrite { denyWriteSet[p] = true }

	for _, path := range cfg.WritableRoots {
		if denyWriteSet[path] {
			// Add as read-only instead of writable.
			landlockAddPathRule(int(rulesetFd), path, readAccess)
			continue
		}
		landlockAddPathRule(int(rulesetFd), path, writeAccess)
	}

	// 5. Allow read access to common system paths (skip DenyRead paths).
	denyReadSet := make(map[string]bool, len(cfg.DenyRead))
	for _, p := range cfg.DenyRead { denyReadSet[p] = true }

	systemReadPaths := []string{"/usr", "/lib", "/lib64", "/etc", "/bin", "/sbin", "/proc", "/dev"}
	for _, path := range systemReadPaths {
		if denyReadSet[path] { continue }
		if _, err := os.Stat(path); err == nil {
			landlockAddPathRule(int(rulesetFd), path, readAccess) // Non-fatal on error.
		}
	}

	// 6. Restrict self.
	_, _, errno = syscall.Syscall(
		uintptr(sysLandlockRestrictSelf), rulesetFd, 0, 0,
	)
	if errno != 0 { return fmt.Errorf("landlock_restrict_self: %w", errno) }

	return nil
}
```

**Key behavioral notes**:
- If Landlock is not supported, returns `nil` (graceful skip, not error).
- DenyWrite paths that appear in WritableRoots are added as **read-only** instead of writable.
- DenyRead paths are excluded from the system read paths list.
- System read paths: `/usr`, `/lib`, `/lib64`, `/etc`, `/bin`, `/sbin`, `/proc`, `/dev`.
- Uses `O_PATH` (0x200000) to open paths for Landlock rules.

### 5.6 ABI Version Compatibility

| ABI Version | Kernel | Features |
|-------------|--------|----------|
| V1 | 5.13+ | Basic filesystem operations |
| V2 | 5.19+ | + REFER (cross-directory rename/link) |
| V3 | 6.2+ | + TRUNCATE |

The implementation handles up to ABI v3. Higher versions are treated as v3 (additional flags are not added).

---

## 6. Layer 4: Seccomp BPF

> **Source**: `platform/linux/seccomp.go`

### 6.1 Raw BPF Implementation

Seccomp is implemented with **raw BPF instructions** — no external library:

```go
// BPF instruction constants.
const (
	bpfLD  = 0x00
	bpfJMP = 0x05
	bpfRET = 0x06
	bpfW   = 0x00
	bpfABS = 0x20
	bpfJEQ = 0x10
	bpfK   = 0x00

	seccompSetModeFilter = 1
	seccompRetAllow      = 0x7fff0000
	seccompRetErrno      = 0x00050000
	seccompRetKill       = 0x00000000

	auditArchX86_64  = 0xc000003e
	auditArchAarch64 = 0xc00000b7

	seccompDataArchOffset = 4
	afUnix                = 1
)

type sockFprog struct {
	len    uint16
	_      [6]byte // padding
	filter unsafe.Pointer
}

type sockFilter struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}
```

### 6.2 Architecture Detection

```go
func seccompArch() (auditArch uint32, sysSocket uint32, err error) {
	switch runtime.GOARCH {
	case "amd64":
		return auditArchX86_64, 41, nil
	case "arm64":
		return auditArchAarch64, 198, nil
	default:
		return 0, 0, fmt.Errorf("unsupported architecture for seccomp: %s", runtime.GOARCH)
	}
}
```

Returns an error for unsupported architectures (only amd64 and arm64 are supported).

### 6.3 ApplySeccomp

```go
func ApplySeccomp() error {
	auditArch, sysSocketNR, err := seccompArch()
	if err != nil {
		return fmt.Errorf("seccomp: %w", err)
	}

	// BPF program:
	// 1. Validate architecture (kill on mismatch for fail-closed)
	// 2. Load syscall number
	// 3. If syscall == SYS_socket, check first argument
	// 4. If first arg == AF_UNIX, return EPERM
	// 5. Otherwise, allow
	filter := []sockFilter{
		// Load arch from seccomp_data.
		{code: bpfLD | bpfW | bpfABS, k: seccompDataArchOffset},
		// If arch matches, continue; otherwise kill.
		{code: bpfJMP | bpfJEQ | bpfK, jt: 0, jf: 6, k: uint32(auditArch)},
		// Load syscall number.
		{code: bpfLD | bpfW | bpfABS, k: 0},
		// If not SYS_socket, allow.
		{code: bpfJMP | bpfJEQ | bpfK, jt: 0, jf: 3, k: sysSocketNR},
		// Load first argument (args[0], lower 32 bits).
		{code: bpfLD | bpfW | bpfABS, k: 16},
		// If AF_UNIX, deny with EPERM.
		{code: bpfJMP | bpfJEQ | bpfK, jt: 0, jf: 1, k: afUnix},
		// Return errno EPERM.
		{code: bpfRET | bpfK, k: seccompRetErrno | 1},
		// Allow.
		{code: bpfRET | bpfK, k: seccompRetAllow},
		// Kill: architecture mismatch.
		{code: bpfRET | bpfK, k: seccompRetKill},
	}

	prog := sockFprog{
		len:    uint16(len(filter)),
		filter: unsafe.Pointer(&filter[0]),
	}

	_, _, errno := syscall.Syscall(
		syscall.SYS_PRCTL,
		syscall.PR_SET_SECCOMP,
		uintptr(seccompSetModeFilter),
		uintptr(unsafe.Pointer(&prog)),
	)
	if errno != 0 {
		return errno
	}
	return nil
}
```

**BPF filter logic**:
1. Validate architecture — **kill** on mismatch (fail-closed).
2. Check if syscall is `SYS_socket` (41 on amd64, 198 on arm64).
3. If socket syscall, check first argument (domain).
4. If domain is `AF_UNIX` (1), return `EPERM`.
5. All other syscalls and socket domains are allowed.

**Note**: `PR_SET_NO_NEW_PRIVS` is **not** set in `ApplySeccomp` — it is set in `hardenProcess()` which is called before seccomp in `sandboxInit`.

---

## 7. Process Hardening

> **Source**: `platform/linux/harden.go`

```go
const (
	prSetNoNewPrivs = 38
	prSetDumpable   = 4
)

func hardenProcess() error {
	// 1. PR_SET_NO_NEW_PRIVS: prevents gaining new privileges.
	//    Required for seccomp and Landlock without CAP_SYS_ADMIN.
	if _, _, errno := syscall.Syscall6(
		syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0,
	); errno != 0 {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", errno)
	}

	// 2. PR_SET_DUMPABLE = 0: prevents core dumps and ptrace attachment.
	if _, _, errno := syscall.Syscall6(
		syscall.SYS_PRCTL, prSetDumpable, 0, 0, 0, 0, 0,
	); errno != 0 {
		return fmt.Errorf("prctl(PR_SET_DUMPABLE): %w", errno)
	}

	// 3. RLIMIT_CORE = 0: ensures no core dump files are written.
	rlimit := syscall.Rlimit{Cur: 0, Max: 0}
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &rlimit); err != nil {
		return fmt.Errorf("setrlimit(RLIMIT_CORE): %w", err)
	}

	return nil
}
```

**Three hardening measures**:
1. **PR_SET_NO_NEW_PRIVS**: prerequisite for seccomp and Landlock without CAP_SYS_ADMIN.
2. **PR_SET_DUMPABLE = 0**: prevents ptrace attachment and core dumps.
3. **RLIMIT_CORE = 0**: double insurance against core dump files.

**Note**: `hardenProcess` is an unexported function (not a function variable like on macOS). Uses `syscall.Syscall6` (not `syscall.RawSyscall`).

---

## 8. Kernel Version Detection

> **Source**: `platform/linux/detect.go`

```go
type KernelVersion struct {
	Major, Minor, Patch int
}

// DetectKernelVersion reads and parses the running kernel version from /proc/version.
func DetectKernelVersion() (KernelVersion, error) {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return KernelVersion{}, fmt.Errorf("read /proc/version: %w", err)
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return KernelVersion{}, fmt.Errorf("unexpected /proc/version format")
	}
	return ParseKernelVersion(fields[2])
}

// ParseKernelVersion parses a kernel version string like "5.15.0-generic".
func ParseKernelVersion(s string) (KernelVersion, error) {
	if idx := strings.IndexAny(s, "- "); idx != -1 {
		s = s[:idx]
	}
	parts := strings.SplitN(s, ".", 3)
	if len(parts) < 2 {
		return KernelVersion{}, fmt.Errorf("invalid kernel version: %q", s)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil { return KernelVersion{}, ... }
	minor, err := strconv.Atoi(parts[1])
	if err != nil { return KernelVersion{}, ... }
	var patch int
	if len(parts) == 3 && parts[2] != "" {
		patch, err = strconv.Atoi(parts[2])
		if err != nil { return KernelVersion{}, ... }
	}
	return KernelVersion{Major: major, Minor: minor, Patch: patch}, nil
}

func (v KernelVersion) AtLeast(major, minor int) bool {
	if v.Major != major {
		return v.Major > major
	}
	return v.Minor >= minor
}

func (v KernelVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}
```

**Key difference from design**: Reads from `/proc/version` (not `syscall.Uname`). Uses `strings.IndexAny(s, "- ")` to strip suffixes (not `strings.SplitN(s, "-", 2)`). Returns proper errors for invalid version components (not silent `strconv.Atoi` ignoring errors).

---

## 9. File Structure

```
platform/linux/
├── linux.go          # Platform struct, New(), WrapCommand, Cleanup, Capabilities
├── namespace.go      # configureNamespaces, applyResourceLimits, rlimit constants
├── reexec.go         # reExecConfig, MaybeSandboxInit, sandboxInit
├── landlock.go       # LandlockInfo, DetectLandlock, applyLandlock, syscall constants
├── seccomp.go        # ApplySeccomp, BPF filter, seccompArch
├── harden.go         # hardenProcess (prctl + rlimit)
├── detect.go         # KernelVersion, DetectKernelVersion, ParseKernelVersion
├── detect_test.go    # Tests for kernel version parsing
└── linux_test.go     # Tests for Linux platform
```

All files have `//go:build linux` build tag.

---

## 10. Degradation Matrix

| Kernel Version | Namespace | Landlock | Seccomp | Security Level |
|---------------|-----------|----------|---------|----------------|
| **6.2+** | ✅ All | ✅ V3 (fs + truncate) | ✅ BPF | 🟢 Full |
| **5.19-6.1** | ✅ All | ✅ V2 (fs + refer) | ✅ BPF | 🟢 Full |
| **5.13-5.18** | ✅ All | ✅ V1 (fs) | ✅ BPF | 🟡 Good |
| **< 5.13** | ✅ All | ❌ (graceful skip) | ✅ BPF | 🟠 Basic |

**Note**: The implementation does not check for minimum kernel versions for user namespaces or seccomp. If these features are unavailable, the process will fail at runtime.

---

## 11. Platform Comparison

| Feature | macOS Seatbelt | Linux NS+Landlock |
|---------|---------------|-------------------|
| File read restriction | ✅ SBPL deny-only | ✅ Landlock (if ABI ≥ 1) |
| File write restriction | ✅ SBPL allow-only | ✅ Landlock + mount NS |
| Network isolation | ✅ SBPL deny default | ✅ CLONE_NEWNET |
| PID isolation | ❌ | ✅ CLONE_NEWPID |
| Syscall filtering | ❌ | ✅ Seccomp BPF |
| Process hardening | ✅ PT_DENY_ATTACH + RLIMIT_CORE | ✅ prctl + RLIMIT_CORE |
| Env sanitization | ✅ DYLD_* + LD_* removal | N/A (namespace isolation) |
| External dependencies | sandbox-exec (system) | None (direct syscalls) |
| Violation monitoring | Stub (planned) | N/A (kernel audit) |

---

## 12. Limitations and Known Issues

| Issue | Description | Mitigation |
|-------|-------------|------------|
| Linux-only build | All files require `//go:build linux` | Cross-compile or CI on Linux |
| No mount namespace setup | `setupMountNamespace` not implemented in current code | Landlock provides filesystem restrictions |
| Seccomp architecture | Only amd64 and arm64 supported | Returns error for other architectures |
| Landlock graceful skip | If Landlock unavailable, no filesystem restrictions | Namespace isolation still provides protection |
| Docker compatibility | May need `--privileged` or `--security-opt` | Document in user guide |
| AF_UNIX only | Seccomp only blocks AF_UNIX socket creation | Does not block inherited FDs or SCM_RIGHTS |
| No network bridge | Network bridge not implemented in current code | CLONE_NEWNET provides full isolation |
