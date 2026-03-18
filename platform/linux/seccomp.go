//go:build linux

package linux

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

// BPF instruction constants for seccomp filter.
const (
	bpfLD  = 0x00
	bpfJMP = 0x05
	bpfRET = 0x06
	bpfW   = 0x00
	bpfABS = 0x20
	bpfJEQ = 0x10
	bpfK   = 0x00

	// seccomp constants.
	seccompSetModeFilter = 2 // SECCOMP_MODE_FILTER (not SECCOMP_MODE_STRICT which is 1)
	seccompRetAllow      = 0x7fff0000
	seccompRetErrno      = 0x00050000 // SECCOMP_RET_ERRNO
	seccompRetKill       = 0x00000000 // SECCOMP_RET_KILL

	// Audit architecture constants.
	auditArchX86_64  = 0xc000003e
	auditArchAarch64 = 0xc00000b7

	// Offset of arch field in seccomp_data struct.
	seccompDataArchOffset = 4

	// Socket families.
	afUnix = 1
)

// sockFprog is the BPF program structure for seccomp.
type sockFprog struct {
	len    uint16
	_      [6]byte // padding
	filter unsafe.Pointer
}

// sockFilter is a single BPF instruction.
type sockFilter struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

// Architecture constants for GOARCH strings.
const (
	archAMD64 = "amd64"
	archARM64 = "arm64"
)

// seccompSyscalls holds architecture-specific syscall numbers used by the
// seccomp BPF filter. A value of 0 means the syscall does not exist on the
// architecture and is skipped when building the filter.
type seccompSyscalls struct {
	auditArch  uint32
	sysSocket  uint32
	sysPtrace  uint32
	sysMount   uint32
	sysUmount2 uint32
	sysReboot  uint32
	sysSwapon  uint32
	sysSwapoff uint32
	sysMknod   uint32
	sysMknodat uint32

	// Kernel loading / module management.
	sysKexecLoad     uint32
	sysKexecFileLoad uint32
	sysInitModule    uint32
	sysFinitModule   uint32
	sysDeleteModule  uint32

	// Side-channel and kernel manipulation.
	sysPerfEventOpen uint32
	sysBpf           uint32
	sysUserfaultfd   uint32

	// io_uring — async I/O that can bypass seccomp filtering.
	sysIoUringSetup    uint32
	sysIoUringEnter    uint32
	sysIoUringRegister uint32

	// Namespace / filesystem escape.
	sysOpenByHandleAt uint32
	sysSetns          uint32
	sysUnshare        uint32
	sysPivotRoot      uint32
	sysChroot         uint32

	// Miscellaneous privileged operations.
	sysAcct          uint32
	sysKcmp          uint32
	sysAddKey        uint32
	sysRequestKey    uint32
	sysKeyctl        uint32
	sysLookupDcookie uint32
	sysMbind         uint32
	sysMovePages     uint32
	sysIoperm        uint32 // x86 only; 0 on arm64
	sysIopl          uint32 // x86 only; 0 on arm64
	sysClockSettime  uint32
	sysSettimeofday  uint32
	sysNfsservctl    uint32
}

// seccompArchFor returns the audit architecture constant and syscall numbers
// for the given GOARCH string. Returns an error for unsupported architectures.
func seccompArchFor(goarch string) (auditArch uint32, sysSocket uint32, err error) {
	sc, err := seccompSyscallsFor(goarch)
	if err != nil {
		return 0, 0, err
	}
	return sc.auditArch, sc.sysSocket, nil
}

// seccompSyscallsFor returns the full set of architecture-specific syscall
// numbers for the given GOARCH string.
func seccompSyscallsFor(goarch string) (seccompSyscalls, error) {
	switch goarch {
	case archAMD64:
		return seccompSyscalls{
			auditArch:  auditArchX86_64,
			sysSocket:  41,
			sysPtrace:  101,
			sysMount:   165,
			sysUmount2: 166,
			sysReboot:  169,
			sysSwapon:  167,
			sysSwapoff: 168,
			sysMknod:   133,
			sysMknodat: 259,

			sysKexecLoad:     246,
			sysKexecFileLoad: 320,
			sysInitModule:    175,
			sysFinitModule:   313,
			sysDeleteModule:  176,

			sysPerfEventOpen: 298,
			sysBpf:           321,
			sysUserfaultfd:   323,

			sysIoUringSetup:    425,
			sysIoUringEnter:    426,
			sysIoUringRegister: 427,

			sysOpenByHandleAt: 304,
			sysSetns:          308,
			sysUnshare:        272,
			sysPivotRoot:      155,
			sysChroot:         161,

			sysAcct:          163,
			sysKcmp:          312,
			sysAddKey:        248,
			sysRequestKey:    249,
			sysKeyctl:        250,
			sysLookupDcookie: 212,
			sysMbind:         237,
			sysMovePages:     279,
			sysIoperm:        173,
			sysIopl:          172,
			sysClockSettime:  227,
			sysSettimeofday:  164,
			sysNfsservctl:    180,
		}, nil
	case archARM64:
		return seccompSyscalls{
			auditArch:  auditArchAarch64,
			sysSocket:  198,
			sysPtrace:  117,
			sysMount:   40,
			sysUmount2: 39,
			sysReboot:  142,
			sysSwapon:  224,
			sysSwapoff: 225,
			sysMknod:   0, // arm64 does not have mknod; only mknodat
			sysMknodat: 33,

			sysKexecLoad:     104,
			sysKexecFileLoad: 294,
			sysInitModule:    105,
			sysFinitModule:   273,
			sysDeleteModule:  106,

			sysPerfEventOpen: 241,
			sysBpf:           280,
			sysUserfaultfd:   282,

			sysIoUringSetup:    425,
			sysIoUringEnter:    426,
			sysIoUringRegister: 427,

			sysOpenByHandleAt: 265,
			sysSetns:          268,
			sysUnshare:        97,
			sysPivotRoot:      41,
			sysChroot:         51,

			sysAcct:          89,
			sysKcmp:          272,
			sysAddKey:        217,
			sysRequestKey:    218,
			sysKeyctl:        219,
			sysLookupDcookie: 18,
			sysMbind:         235,
			sysMovePages:     239,
			sysIoperm:        0, // x86 only; not available on arm64
			sysIopl:          0, // x86 only; not available on arm64
			sysClockSettime:  112,
			sysSettimeofday:  170,
			sysNfsservctl:    42,
		}, nil
	default:
		return seccompSyscalls{}, fmt.Errorf("unsupported architecture for seccomp: %s", goarch)
	}
}

// seccompArch returns the audit architecture constant and SYS_socket number
// for the current GOARCH. Returns an error for unsupported architectures.
func seccompArch() (auditArch uint32, sysSocket uint32, err error) {
	return seccompArchFor(runtime.GOARCH)
}

// seccompSyscallsFn is a function variable for full syscall lookup, allowing
// tests to override it.
var seccompSyscallsFn = func() (seccompSyscalls, error) {
	return seccompSyscallsFor(runtime.GOARCH)
}

// seccompPrctlFn is a function variable for the prctl syscall used to apply
// seccomp filters. Tests can override this to avoid irreversible process changes.
var seccompPrctlFn = syscall.Syscall

// buildSeccompFilter constructs the BPF filter for seccomp. It dynamically
// includes checks for syscalls that exist on the current architecture (e.g.,
// mknod is absent on arm64).
func buildSeccompFilter(sc seccompSyscalls) []sockFilter {
	// Collect the list of unconditionally blocked syscalls.
	blocked := []uint32{
		sc.sysPtrace,
		sc.sysMount,
		sc.sysUmount2,
		sc.sysReboot,
		sc.sysSwapon,
		sc.sysSwapoff,
		sc.sysKexecLoad,
		sc.sysKexecFileLoad,
		sc.sysInitModule,
		sc.sysFinitModule,
		sc.sysDeleteModule,
		sc.sysPerfEventOpen,
		sc.sysBpf,
		sc.sysUserfaultfd,
		sc.sysIoUringSetup,
		sc.sysIoUringEnter,
		sc.sysIoUringRegister,
		sc.sysOpenByHandleAt,
		sc.sysSetns,
		sc.sysUnshare,
		sc.sysPivotRoot,
		sc.sysChroot,
		sc.sysAcct,
		sc.sysKcmp,
		sc.sysAddKey,
		sc.sysRequestKey,
		sc.sysKeyctl,
		sc.sysLookupDcookie,
		sc.sysMbind,
		sc.sysMovePages,
		sc.sysClockSettime,
		sc.sysSettimeofday,
		sc.sysNfsservctl,
	}
	// Conditionally add arch-specific syscalls (0 means absent on this arch).
	archSpecific := []uint32{
		sc.sysMknod,
		sc.sysMknodat,
		sc.sysIoperm,
		sc.sysIopl,
	}
	for _, nr := range archSpecific {
		if nr != 0 {
			blocked = append(blocked, nr)
		}
	}

	n := len(blocked)
	// Total instructions:
	//   [0]       load arch
	//   [1]       check arch → KILL on mismatch
	//   [2]       load syscall nr
	//   [3]       if SYS_SOCKET → socket arg check
	//   [4..4+n-1] blocked syscall checks
	//   [4+n]     ALLOW (fall-through)
	//   [4+n+1]   load args[0]
	//   [4+n+2]   if AF_UNIX → EPERM
	//   [4+n+3]   ALLOW (non-AF_UNIX)
	//   [4+n+4]   EPERM
	//   [4+n+5]   KILL
	total := 4 + n + 6
	epermIdx := 4 + n + 4
	killIdx := 4 + n + 5
	socketArgIdx := 4 + n + 1

	filter := make([]sockFilter, 0, total)

	filter = append(filter,
		// [0] Load architecture.
		sockFilter{code: bpfLD | bpfW | bpfABS, k: seccompDataArchOffset},
		// [1] Check arch → KILL on mismatch. Jump offset = killIdx - currentIdx - 1.
		sockFilter{code: bpfJMP | bpfJEQ | bpfK, jt: 0, jf: uint8(killIdx - 1 - 1), k: sc.auditArch}, //nolint:gosec
		// [2] Load syscall number.
		sockFilter{code: bpfLD | bpfW | bpfABS, k: 0},
		// [3] If SYS_SOCKET → socket arg check. Jump offset = socketArgIdx - currentIdx - 1.
		sockFilter{code: bpfJMP | bpfJEQ | bpfK, jt: uint8(socketArgIdx - 3 - 1), jf: 0, k: sc.sysSocket}, //nolint:gosec
	)
	// [4..4+n-1] Blocked syscall checks → EPERM.
	for i, nr := range blocked {
		idx := 4 + i
		jt := uint8(epermIdx - idx - 1) //nolint:gosec
		filter = append(filter, sockFilter{code: bpfJMP | bpfJEQ | bpfK, jt: jt, jf: 0, k: nr})
	}
	filter = append(filter,
		// [4+n] ALLOW — no dangerous syscall matched.
		sockFilter{code: bpfRET | bpfK, k: seccompRetAllow},
		// [4+n+1] Load first argument (socket domain).
		sockFilter{code: bpfLD | bpfW | bpfABS, k: 16},
		// [4+n+2] If AF_UNIX → EPERM; else ALLOW.
		sockFilter{code: bpfJMP | bpfJEQ | bpfK, jt: 1, jf: 0, k: afUnix},
		// [4+n+3] ALLOW — non-AF_UNIX socket.
		sockFilter{code: bpfRET | bpfK, k: seccompRetAllow},
		// [4+n+4] EPERM.
		sockFilter{code: bpfRET | bpfK, k: seccompRetErrno | 1},
		// [4+n+5] KILL — architecture mismatch.
		sockFilter{code: bpfRET | bpfK, k: seccompRetKill},
	)

	return filter
}

// ApplySeccomp applies a seccomp BPF filter that blocks AF_UNIX socket
// creation and dangerous syscalls including ptrace, mount/umount, reboot,
// swap management, device node creation, kernel module loading, kexec,
// BPF, perf_event_open, io_uring, namespace manipulation, chroot/pivot_root,
// keyring operations, and clock modification. This prevents the sandboxed
// process from escaping its confinement or performing privileged operations.
func ApplySeccomp() error {
	sc, err := seccompSyscallsFn()
	if err != nil {
		return fmt.Errorf("seccomp: %w", err)
	}

	filter := buildSeccompFilter(sc)

	prog := sockFprog{
		len:    uint16(len(filter)), //nolint:gosec // filter length is bounded by seccomp BPF limits
		filter: unsafe.Pointer(&filter[0]),
	}

	_, _, errno := seccompPrctlFn(
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
