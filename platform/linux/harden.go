//go:build linux

package linux

import (
	"fmt"
	"syscall"
)

// prctl constants not available in all Go syscall packages.
const (
	prSetNoNewPrivs = 38
	prSetDumpable   = 4
)

// prctlFunc is a function variable for the prctl syscall, overridden in tests.
var prctlFunc = func(option, arg2, arg3, arg4, arg5, arg6 uintptr) (uintptr, uintptr, syscall.Errno) {
	return syscall.Syscall6(syscall.SYS_PRCTL, option, arg2, arg3, arg4, arg5, arg6)
}

// setrlimitFunc is a function variable for setrlimit, overridden in tests.
var setrlimitFunc = syscall.Setrlimit

// hardenProcess applies process hardening measures to the current process:
//   - PR_SET_NO_NEW_PRIVS: prevents the process from gaining new privileges
//     (required for seccomp and Landlock without CAP_SYS_ADMIN).
//   - PR_SET_DUMPABLE = 0: prevents core dumps and ptrace attachment.
//   - RLIMIT_CORE = 0: ensures no core dump files are written.
func hardenProcess() error {
	// PR_SET_NO_NEW_PRIVS is required before applying seccomp filters
	// and Landlock rules without CAP_SYS_ADMIN.
	if _, _, errno := prctlFunc(prSetNoNewPrivs, 1, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", errno)
	}

	// Disable core dumps via prctl.
	if _, _, errno := prctlFunc(prSetDumpable, 0, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("prctl(PR_SET_DUMPABLE): %w", errno)
	}

	// Set RLIMIT_CORE to 0 to prevent core dump files.
	rlimit := syscall.Rlimit{Cur: 0, Max: 0}
	if err := setrlimitFunc(syscall.RLIMIT_CORE, &rlimit); err != nil {
		return fmt.Errorf("setrlimit(RLIMIT_CORE): %w", err)
	}

	return nil
}
