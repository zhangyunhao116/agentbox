//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// TestSeccompArchFor_Amd64 verifies seccompArchFor returns correct values for amd64.
func TestSeccompArchFor_Amd64(t *testing.T) {
	arch, sysSocket, err := seccompArchFor("amd64")
	if err != nil {
		t.Fatalf("seccompArchFor(\"amd64\") error: %v", err)
	}
	if arch != auditArchX86_64 {
		t.Errorf("arch = 0x%x, want 0x%x", arch, auditArchX86_64)
	}
	if sysSocket != 41 {
		t.Errorf("sysSocket = %d, want 41", sysSocket)
	}
}

// TestSeccompArchFor_Arm64 verifies seccompArchFor returns correct values for arm64.
func TestSeccompArchFor_Arm64(t *testing.T) {
	arch, sysSocket, err := seccompArchFor("arm64")
	if err != nil {
		t.Fatalf("seccompArchFor(\"arm64\") error: %v", err)
	}
	if arch != auditArchAarch64 {
		t.Errorf("arch = 0x%x, want 0x%x", arch, auditArchAarch64)
	}
	if sysSocket != 198 {
		t.Errorf("sysSocket = %d, want 198", sysSocket)
	}
}

// TestSeccompArchFor_Unsupported verifies seccompArchFor returns an error for
// unsupported architectures.
func TestSeccompArchFor_Unsupported(t *testing.T) {
	for _, arch := range []string{"386", "mips", "riscv64", ""} {
		_, _, err := seccompArchFor(arch)
		if err == nil {
			t.Errorf("seccompArchFor(%q) expected error, got nil", arch)
		}
		if !strings.Contains(err.Error(), "unsupported architecture") {
			t.Errorf("seccompArchFor(%q) error = %v, want 'unsupported architecture'", arch, err)
		}
	}
}

// TestApplySeccomp_MockSuccess verifies ApplySeccomp succeeds when the prctl
// syscall returns success (errno=0).
func TestApplySeccomp_MockSuccess(t *testing.T) {
	origSyscalls := seccompSyscallsFn
	origPrctl := seccompPrctlFn
	t.Cleanup(func() {
		seccompSyscallsFn = origSyscalls
		seccompPrctlFn = origPrctl
	})

	seccompPrctlFn = func(trap, a1, a2, a3 uintptr) (uintptr, uintptr, syscall.Errno) {
		return 0, 0, 0
	}

	if err := ApplySeccomp(); err != nil {
		t.Fatalf("ApplySeccomp() error: %v", err)
	}
}

// TestApplySeccomp_MockPrctlError verifies ApplySeccomp returns an error when
// the prctl syscall fails.
func TestApplySeccomp_MockPrctlError(t *testing.T) {
	origSyscalls := seccompSyscallsFn
	origPrctl := seccompPrctlFn
	t.Cleanup(func() {
		seccompSyscallsFn = origSyscalls
		seccompPrctlFn = origPrctl
	})

	seccompPrctlFn = func(trap, a1, a2, a3 uintptr) (uintptr, uintptr, syscall.Errno) {
		return 0, 0, syscall.EINVAL
	}

	err := ApplySeccomp()
	if err == nil {
		t.Fatal("ApplySeccomp() expected error, got nil")
	}
	if !errors.Is(err, syscall.EINVAL) {
		t.Errorf("ApplySeccomp() error = %v, want EINVAL", err)
	}
}

// TestApplySeccomp_MockArchError verifies ApplySeccomp returns a wrapped error
// when the architecture lookup fails.
func TestApplySeccomp_MockArchError(t *testing.T) {
	origSyscalls := seccompSyscallsFn
	origPrctl := seccompPrctlFn
	t.Cleanup(func() {
		seccompSyscallsFn = origSyscalls
		seccompPrctlFn = origPrctl
	})

	seccompSyscallsFn = func() (seccompSyscalls, error) {
		return seccompSyscalls{}, errors.New("unsupported architecture for seccomp: mips")
	}

	err := ApplySeccomp()
	if err == nil {
		t.Fatal("ApplySeccomp() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "seccomp:") {
		t.Errorf("ApplySeccomp() error = %v, want wrapped seccomp error", err)
	}
	if !strings.Contains(err.Error(), "unsupported architecture") {
		t.Errorf("ApplySeccomp() error = %v, want 'unsupported architecture'", err)
	}
}

// TestSeccompArch verifies seccompArch returns correct values for the current architecture.
func TestSeccompArch(t *testing.T) {
	arch, sysSocket, err := seccompArch()
	if err != nil {
		t.Fatalf("seccompArch() error: %v", err)
	}

	switch runtime.GOARCH {
	case "amd64":
		if arch != auditArchX86_64 {
			t.Errorf("seccompArch() arch = 0x%x, want 0x%x", arch, auditArchX86_64)
		}
		if sysSocket != 41 {
			t.Errorf("seccompArch() sysSocket = %d, want 41", sysSocket)
		}
	case "arm64":
		if arch != auditArchAarch64 {
			t.Errorf("seccompArch() arch = 0x%x, want 0x%x", arch, auditArchAarch64)
		}
		if sysSocket != 198 {
			t.Errorf("seccompArch() sysSocket = %d, want 198", sysSocket)
		}
	default:
		t.Skipf("unsupported architecture: %s", runtime.GOARCH)
	}
}

// applySeccompTsync applies the same BPF filter as ApplySeccomp but uses the
// seccomp() syscall with SECCOMP_FILTER_FLAG_TSYNC to apply to all threads.
// This is necessary for testing because Go's runtime has multiple OS threads,
// and prctl-based seccomp (used by ApplySeccomp) only applies to the calling
// thread, which causes the Go runtime to hang.
func applySeccompTsync() error {
	sc, err := seccompSyscallsFor(runtime.GOARCH)
	if err != nil {
		return fmt.Errorf("seccomp: %w", err)
	}

	// Use the same BPF program as ApplySeccomp via buildSeccompFilter.
	filter := buildSeccompFilter(sc)

	prog := sockFprog{
		len:    uint16(len(filter)),
		filter: unsafe.Pointer(&filter[0]),
	}

	// sysSeccompNR returns the SYS_SECCOMP syscall number for the current architecture.
	sysSeccompNR := func() uintptr {
		switch runtime.GOARCH {
		case "amd64":
			return 317
		case "arm64":
			return 277
		default:
			return 317 // fallback to amd64
		}
	}
	const seccompFlagTsync = 1
	// SECCOMP_SET_MODE_FILTER is the operation code for the seccomp() syscall.
	// This is distinct from SECCOMP_MODE_FILTER (2) used with prctl(PR_SET_SECCOMP).
	const seccompSetModeFilterOp = 1
	_, _, errno := syscall.Syscall(sysSeccompNR(), seccompSetModeFilterOp,
		seccompFlagTsync, uintptr(unsafe.Pointer(&prog)))
	if errno != 0 {
		return errno
	}
	return nil
}

// seccompSubprocessHelper applies hardenProcess + seccomp in a subprocess,
// then runs the provided test function. Uses TSYNC to apply the filter to all
// Go runtime threads, which is required for the process to function correctly.
func seccompSubprocessHelper(testFn func() string) {
	if err := hardenProcess(); err != nil {
		fmt.Fprintf(os.Stderr, "hardenProcess error: %v\n", err)
		os.Exit(1)
	}
	if err := applySeccompTsync(); err != nil {
		fmt.Fprintf(os.Stderr, "applySeccompTsync error: %v\n", err)
		os.Exit(1)
	}

	result := testFn()
	fmt.Println(result)
	os.Exit(0)
}

// runSeccompSubprocess runs a subprocess test that applies seccomp.
func runSeccompSubprocess(t *testing.T, testName string) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+testName+"$")
	cmd.Env = append(os.Environ(), "TEST_SUBPROCESS=1")
	output, err := cmd.CombinedOutput()
	outStr := string(output)
	if err != nil && !strings.Contains(outStr, "RESULT:") {
		t.Fatalf("subprocess failed: %v\noutput: %s", err, outStr)
	}
	return outStr
}

// TestApplySeccomp runs the seccomp filter in a subprocess and verifies it succeeds.
func TestApplySeccomp(t *testing.T) {
	if os.Getenv("TEST_SUBPROCESS") == "1" {
		seccompSubprocessHelper(func() string {
			return "RESULT:SECCOMP_OK"
		})
		return
	}

	result := runSeccompSubprocess(t, "TestApplySeccomp")
	if !strings.Contains(result, "RESULT:SECCOMP_OK") {
		t.Fatalf("expected RESULT:SECCOMP_OK, got: %q", result)
	}
}

// TestApplySeccomp_BlocksUnixSocket verifies that AF_UNIX socket creation is blocked.
func TestApplySeccomp_BlocksUnixSocket(t *testing.T) {
	if os.Getenv("TEST_SUBPROCESS") == "1" {
		seccompSubprocessHelper(func() string {
			fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
			if err == nil {
				syscall.Close(fd)
				return "RESULT:ERROR AF_UNIX socket should have been blocked"
			}
			if err != syscall.EPERM {
				return fmt.Sprintf("RESULT:ERROR expected EPERM, got: %v", err)
			}
			return "RESULT:UNIX_BLOCKED"
		})
		return
	}

	result := runSeccompSubprocess(t, "TestApplySeccomp_BlocksUnixSocket")
	if strings.Contains(result, "RESULT:ERROR") {
		t.Fatal(result)
	}
	if !strings.Contains(result, "RESULT:UNIX_BLOCKED") {
		t.Fatalf("expected RESULT:UNIX_BLOCKED, got: %q", result)
	}
}

// TestApplySeccomp_AllowsTCPSocket verifies that AF_INET socket creation still works.
func TestApplySeccomp_AllowsTCPSocket(t *testing.T) {
	if os.Getenv("TEST_SUBPROCESS") == "1" {
		seccompSubprocessHelper(func() string {
			fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
			if err != nil {
				return fmt.Sprintf("RESULT:ERROR AF_INET socket failed: %v", err)
			}
			syscall.Close(fd)
			return "RESULT:TCP_ALLOWED"
		})
		return
	}

	result := runSeccompSubprocess(t, "TestApplySeccomp_AllowsTCPSocket")
	if strings.Contains(result, "RESULT:ERROR") {
		t.Fatal(result)
	}
	if !strings.Contains(result, "RESULT:TCP_ALLOWED") {
		t.Fatalf("expected RESULT:TCP_ALLOWED, got: %q", result)
	}
}

// TestApplySeccomp_BlocksPtrace verifies that ptrace is blocked with EPERM.
func TestApplySeccomp_BlocksPtrace(t *testing.T) {
	if os.Getenv("TEST_SUBPROCESS") == "1" {
		seccompSubprocessHelper(func() string {
			sc, _ := seccompSyscallsFor(runtime.GOARCH)
			_, _, errno := syscall.Syscall(uintptr(sc.sysPtrace), 0, 0, 0)
			if errno == 0 {
				return "RESULT:ERROR ptrace should have been blocked"
			}
			if errno != syscall.EPERM {
				return fmt.Sprintf("RESULT:ERROR expected EPERM, got: %v", errno)
			}
			return "RESULT:PTRACE_BLOCKED"
		})
		return
	}

	result := runSeccompSubprocess(t, "TestApplySeccomp_BlocksPtrace")
	if strings.Contains(result, "RESULT:ERROR") {
		t.Fatal(result)
	}
	if !strings.Contains(result, "RESULT:PTRACE_BLOCKED") {
		t.Fatalf("expected RESULT:PTRACE_BLOCKED, got: %q", result)
	}
}

// TestApplySeccomp_BlocksMount verifies that mount is blocked with EPERM.
func TestApplySeccomp_BlocksMount(t *testing.T) {
	if os.Getenv("TEST_SUBPROCESS") == "1" {
		seccompSubprocessHelper(func() string {
			sc, _ := seccompSyscallsFor(runtime.GOARCH)
			_, _, errno := syscall.Syscall6(uintptr(sc.sysMount), 0, 0, 0, 0, 0, 0)
			if errno == 0 {
				return "RESULT:ERROR mount should have been blocked"
			}
			if errno != syscall.EPERM {
				return fmt.Sprintf("RESULT:ERROR expected EPERM, got: %v", errno)
			}
			return "RESULT:MOUNT_BLOCKED"
		})
		return
	}

	result := runSeccompSubprocess(t, "TestApplySeccomp_BlocksMount")
	if strings.Contains(result, "RESULT:ERROR") {
		t.Fatal(result)
	}
	if !strings.Contains(result, "RESULT:MOUNT_BLOCKED") {
		t.Fatalf("expected RESULT:MOUNT_BLOCKED, got: %q", result)
	}
}

// TestApplySeccomp_BlocksReboot verifies that reboot is blocked with EPERM.
func TestApplySeccomp_BlocksReboot(t *testing.T) {
	if os.Getenv("TEST_SUBPROCESS") == "1" {
		seccompSubprocessHelper(func() string {
			sc, _ := seccompSyscallsFor(runtime.GOARCH)
			_, _, errno := syscall.Syscall(uintptr(sc.sysReboot), 0, 0, 0)
			if errno == 0 {
				return "RESULT:ERROR reboot should have been blocked"
			}
			if errno != syscall.EPERM {
				return fmt.Sprintf("RESULT:ERROR expected EPERM, got: %v", errno)
			}
			return "RESULT:REBOOT_BLOCKED"
		})
		return
	}

	result := runSeccompSubprocess(t, "TestApplySeccomp_BlocksReboot")
	if strings.Contains(result, "RESULT:ERROR") {
		t.Fatal(result)
	}
	if !strings.Contains(result, "RESULT:REBOOT_BLOCKED") {
		t.Fatalf("expected RESULT:REBOOT_BLOCKED, got: %q", result)
	}
}

// TestApplySeccomp_BlocksUmount2 verifies that umount2 is blocked with EPERM.
func TestApplySeccomp_BlocksUmount2(t *testing.T) {
	if os.Getenv("TEST_SUBPROCESS") == "1" {
		seccompSubprocessHelper(func() string {
			sc, _ := seccompSyscallsFor(runtime.GOARCH)
			_, _, errno := syscall.Syscall(uintptr(sc.sysUmount2), 0, 0, 0)
			if errno == 0 {
				return "RESULT:ERROR umount2 should have been blocked"
			}
			if errno != syscall.EPERM {
				return fmt.Sprintf("RESULT:ERROR expected EPERM, got: %v", errno)
			}
			return "RESULT:UMOUNT2_BLOCKED"
		})
		return
	}

	result := runSeccompSubprocess(t, "TestApplySeccomp_BlocksUmount2")
	if strings.Contains(result, "RESULT:ERROR") {
		t.Fatal(result)
	}
	if !strings.Contains(result, "RESULT:UMOUNT2_BLOCKED") {
		t.Fatalf("expected RESULT:UMOUNT2_BLOCKED, got: %q", result)
	}
}

// TestApplySeccomp_BlocksSwapon verifies that swapon is blocked with EPERM.
func TestApplySeccomp_BlocksSwapon(t *testing.T) {
	if os.Getenv("TEST_SUBPROCESS") == "1" {
		seccompSubprocessHelper(func() string {
			sc, _ := seccompSyscallsFor(runtime.GOARCH)
			_, _, errno := syscall.Syscall(uintptr(sc.sysSwapon), 0, 0, 0)
			if errno == 0 {
				return "RESULT:ERROR swapon should have been blocked"
			}
			if errno != syscall.EPERM {
				return fmt.Sprintf("RESULT:ERROR expected EPERM, got: %v", errno)
			}
			return "RESULT:SWAPON_BLOCKED"
		})
		return
	}

	result := runSeccompSubprocess(t, "TestApplySeccomp_BlocksSwapon")
	if strings.Contains(result, "RESULT:ERROR") {
		t.Fatal(result)
	}
	if !strings.Contains(result, "RESULT:SWAPON_BLOCKED") {
		t.Fatalf("expected RESULT:SWAPON_BLOCKED, got: %q", result)
	}
}

// TestApplySeccomp_BlocksSwapoff verifies that swapoff is blocked with EPERM.
func TestApplySeccomp_BlocksSwapoff(t *testing.T) {
	if os.Getenv("TEST_SUBPROCESS") == "1" {
		seccompSubprocessHelper(func() string {
			sc, _ := seccompSyscallsFor(runtime.GOARCH)
			_, _, errno := syscall.Syscall(uintptr(sc.sysSwapoff), 0, 0, 0)
			if errno == 0 {
				return "RESULT:ERROR swapoff should have been blocked"
			}
			if errno != syscall.EPERM {
				return fmt.Sprintf("RESULT:ERROR expected EPERM, got: %v", errno)
			}
			return "RESULT:SWAPOFF_BLOCKED"
		})
		return
	}

	result := runSeccompSubprocess(t, "TestApplySeccomp_BlocksSwapoff")
	if strings.Contains(result, "RESULT:ERROR") {
		t.Fatal(result)
	}
	if !strings.Contains(result, "RESULT:SWAPOFF_BLOCKED") {
		t.Fatalf("expected RESULT:SWAPOFF_BLOCKED, got: %q", result)
	}
}

// TestSeccompSyscallsFor_Amd64 verifies all syscall numbers for amd64.
func TestSeccompSyscallsFor_Amd64(t *testing.T) {
	sc, err := seccompSyscallsFor("amd64")
	if err != nil {
		t.Fatalf("seccompSyscallsFor(\"amd64\") error: %v", err)
	}
	checks := []struct {
		name string
		got  uint32
		want uint32
	}{
		{"auditArch", sc.auditArch, auditArchX86_64},
		{"sysSocket", sc.sysSocket, 41},
		{"sysPtrace", sc.sysPtrace, 101},
		{"sysMount", sc.sysMount, 165},
		{"sysUmount2", sc.sysUmount2, 166},
		{"sysReboot", sc.sysReboot, 169},
		{"sysSwapon", sc.sysSwapon, 167},
		{"sysSwapoff", sc.sysSwapoff, 168},
		{"sysMknod", sc.sysMknod, 133},
		{"sysMknodat", sc.sysMknodat, 259},
		{"sysKexecLoad", sc.sysKexecLoad, 246},
		{"sysKexecFileLoad", sc.sysKexecFileLoad, 320},
		{"sysInitModule", sc.sysInitModule, 175},
		{"sysFinitModule", sc.sysFinitModule, 313},
		{"sysDeleteModule", sc.sysDeleteModule, 176},
		{"sysPerfEventOpen", sc.sysPerfEventOpen, 298},
		{"sysBpf", sc.sysBpf, 321},
		{"sysUserfaultfd", sc.sysUserfaultfd, 323},
		{"sysIoUringSetup", sc.sysIoUringSetup, 425},
		{"sysIoUringEnter", sc.sysIoUringEnter, 426},
		{"sysIoUringRegister", sc.sysIoUringRegister, 427},
		{"sysOpenByHandleAt", sc.sysOpenByHandleAt, 304},
		{"sysSetns", sc.sysSetns, 308},
		{"sysUnshare", sc.sysUnshare, 272},
		{"sysPivotRoot", sc.sysPivotRoot, 155},
		{"sysChroot", sc.sysChroot, 161},
		{"sysAcct", sc.sysAcct, 163},
		{"sysKcmp", sc.sysKcmp, 312},
		{"sysAddKey", sc.sysAddKey, 248},
		{"sysRequestKey", sc.sysRequestKey, 249},
		{"sysKeyctl", sc.sysKeyctl, 250},
		{"sysLookupDcookie", sc.sysLookupDcookie, 212},
		{"sysMbind", sc.sysMbind, 237},
		{"sysMovePages", sc.sysMovePages, 279},
		{"sysIoperm", sc.sysIoperm, 173},
		{"sysIopl", sc.sysIopl, 172},
		{"sysClockSettime", sc.sysClockSettime, 227},
		{"sysSettimeofday", sc.sysSettimeofday, 164},
		{"sysNfsservctl", sc.sysNfsservctl, 180},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

// TestSeccompSyscallsFor_Arm64 verifies all syscall numbers for arm64.
func TestSeccompSyscallsFor_Arm64(t *testing.T) {
	sc, err := seccompSyscallsFor("arm64")
	if err != nil {
		t.Fatalf("seccompSyscallsFor(\"arm64\") error: %v", err)
	}
	checks := []struct {
		name string
		got  uint32
		want uint32
	}{
		{"auditArch", sc.auditArch, auditArchAarch64},
		{"sysSocket", sc.sysSocket, 198},
		{"sysPtrace", sc.sysPtrace, 117},
		{"sysMount", sc.sysMount, 40},
		{"sysUmount2", sc.sysUmount2, 39},
		{"sysReboot", sc.sysReboot, 142},
		{"sysSwapon", sc.sysSwapon, 224},
		{"sysSwapoff", sc.sysSwapoff, 225},
		{"sysMknod", sc.sysMknod, 0},
		{"sysMknodat", sc.sysMknodat, 33},
		{"sysKexecLoad", sc.sysKexecLoad, 104},
		{"sysKexecFileLoad", sc.sysKexecFileLoad, 294},
		{"sysInitModule", sc.sysInitModule, 105},
		{"sysFinitModule", sc.sysFinitModule, 273},
		{"sysDeleteModule", sc.sysDeleteModule, 106},
		{"sysPerfEventOpen", sc.sysPerfEventOpen, 241},
		{"sysBpf", sc.sysBpf, 280},
		{"sysUserfaultfd", sc.sysUserfaultfd, 282},
		{"sysIoUringSetup", sc.sysIoUringSetup, 425},
		{"sysIoUringEnter", sc.sysIoUringEnter, 426},
		{"sysIoUringRegister", sc.sysIoUringRegister, 427},
		{"sysOpenByHandleAt", sc.sysOpenByHandleAt, 265},
		{"sysSetns", sc.sysSetns, 268},
		{"sysUnshare", sc.sysUnshare, 97},
		{"sysPivotRoot", sc.sysPivotRoot, 41},
		{"sysChroot", sc.sysChroot, 51},
		{"sysAcct", sc.sysAcct, 89},
		{"sysKcmp", sc.sysKcmp, 272},
		{"sysAddKey", sc.sysAddKey, 217},
		{"sysRequestKey", sc.sysRequestKey, 218},
		{"sysKeyctl", sc.sysKeyctl, 219},
		{"sysLookupDcookie", sc.sysLookupDcookie, 18},
		{"sysMbind", sc.sysMbind, 235},
		{"sysMovePages", sc.sysMovePages, 239},
		{"sysIoperm", sc.sysIoperm, 0},
		{"sysIopl", sc.sysIopl, 0},
		{"sysClockSettime", sc.sysClockSettime, 112},
		{"sysSettimeofday", sc.sysSettimeofday, 170},
		{"sysNfsservctl", sc.sysNfsservctl, 42},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

// TestSeccompSyscallsFor_Unsupported verifies error for unsupported architectures.
func TestSeccompSyscallsFor_Unsupported(t *testing.T) {
	_, err := seccompSyscallsFor("mips")
	if err == nil {
		t.Fatal("seccompSyscallsFor(\"mips\") expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported architecture") {
		t.Errorf("error = %v, want 'unsupported architecture'", err)
	}
}

// TestBuildSeccompFilter_BlockedCount verifies the expanded blocklist contains
// the expected number of syscalls for both architectures.
func TestBuildSeccompFilter_BlockedCount(t *testing.T) {
	tests := []struct {
		arch string
		// Expected minimum blocked syscalls. amd64 has ioperm+iopl,
		// arm64 does not (sysMknod is also 0 on arm64).
		minBlocked int
	}{
		{"amd64", 37}, // 33 unconditional + mknod + mknodat + ioperm + iopl
		{"arm64", 34}, // 33 unconditional + mknodat (mknod=0, ioperm=0, iopl=0)
	}
	for _, tt := range tests {
		t.Run(tt.arch, func(t *testing.T) {
			sc, err := seccompSyscallsFor(tt.arch)
			if err != nil {
				t.Fatal(err)
			}
			filter := buildSeccompFilter(sc)
			// Each blocked syscall produces 1 BPF instruction.
			// Total = 4 (header) + N (blocked) + 6 (footer).
			n := len(filter) - 4 - 6
			if n < tt.minBlocked {
				t.Errorf("arch %s: blocked syscall count = %d, want >= %d", tt.arch, n, tt.minBlocked)
			}
		})
	}
}

// TestApplySeccomp_BlocksIoUring verifies that io_uring_setup is blocked with EPERM.
func TestApplySeccomp_BlocksIoUring(t *testing.T) {
	if os.Getenv("TEST_SUBPROCESS") == "1" {
		seccompSubprocessHelper(func() string {
			sc, err := seccompSyscallsFor(runtime.GOARCH)
			if err != nil {
				return fmt.Sprintf("RESULT:ERROR unsupported arch: %v", err)
			}
			_, _, errno := syscall.Syscall(uintptr(sc.sysIoUringSetup), 0, 0, 0)
			if errno != syscall.EPERM {
				return fmt.Sprintf("RESULT:ERROR expected EPERM, got: %v", errno)
			}
			return "RESULT:IO_URING_BLOCKED"
		})
		return
	}

	result := runSeccompSubprocess(t, "TestApplySeccomp_BlocksIoUring")
	if strings.Contains(result, "RESULT:ERROR") {
		t.Fatal(result)
	}
	if !strings.Contains(result, "RESULT:IO_URING_BLOCKED") {
		t.Fatalf("expected RESULT:IO_URING_BLOCKED, got: %q", result)
	}
}

// TestSeccompSyscallsFor_IoUringNonZero verifies that io_uring syscall numbers
// are non-zero for both amd64 and arm64.
func TestSeccompSyscallsFor_IoUringNonZero(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			sc, err := seccompSyscallsFor(arch)
			if err != nil {
				t.Fatal(err)
			}
			if sc.sysIoUringSetup == 0 {
				t.Errorf("sysIoUringSetup is 0 on %s", arch)
			}
			if sc.sysIoUringEnter == 0 {
				t.Errorf("sysIoUringEnter is 0 on %s", arch)
			}
			if sc.sysIoUringRegister == 0 {
				t.Errorf("sysIoUringRegister is 0 on %s", arch)
			}
		})
	}
}
