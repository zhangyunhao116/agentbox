//go:build darwin

package darwin

import (
	"fmt"
	"syscall"
)

// ptDenyAttach is the PT_DENY_ATTACH request code for ptrace on macOS.
// When applied, it prevents debuggers from attaching to the process.
// See: <sys/ptrace.h> in the Darwin kernel headers.
const ptDenyAttach = 31

// hardenProcess applies macOS-specific process hardening.
// It is a package-level variable so tests can override it to simulate errors.
var hardenProcess = hardenProcessImpl

// hardenProcessImpl applies macOS-specific process hardening:
//   - PT_DENY_ATTACH: prevents debugger attachment via ptrace
//   - Disable core dumps: sets RLIMIT_CORE to 0 to avoid leaking
//     sensitive data through crash dumps
//
// This function is idempotent: calling it multiple times is safe.
// If PT_DENY_ATTACH was already applied, the EINVAL error is ignored.
func hardenProcessImpl() error {
	// PT_DENY_ATTACH — prevent debugger attachment.
	// syscall.Syscall maps to the ptrace(2) system call.
	_, _, errno := syscall.Syscall(syscall.SYS_PTRACE, ptDenyAttach, 0, 0)
	if errno != 0 && errno != syscall.EINVAL {
		// EINVAL means PT_DENY_ATTACH was already applied, which is fine.
		return fmt.Errorf("PT_DENY_ATTACH failed: %w", errno)
	}

	// Disable core dumps to prevent sensitive data from being written
	// to disk if the process crashes.
	var rlim syscall.Rlimit
	rlim.Cur = 0
	rlim.Max = 0
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &rlim); err != nil {
		return fmt.Errorf("disable core dumps (RLIMIT_CORE): %w", err)
	}

	return nil
}
