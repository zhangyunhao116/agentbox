//go:build linux

package linux

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Seccomp filter structure tests — verify mknod/mknodat are in the blocked list
// ---------------------------------------------------------------------------

// TestSeccompBlocksMknod verifies that the seccomp filter includes SYS_MKNOD
// in the blocked syscall list (on architectures that have it).
func TestSeccompBlocksMknod(t *testing.T) {
	sc, err := seccompSyscallsFor(runtime.GOARCH)
	if err != nil {
		t.Fatalf("seccompSyscallsFor(%q) error: %v", runtime.GOARCH, err)
	}

	filter := buildSeccompFilter(sc)

	// On amd64, sysMknod should be present in the filter.
	if sc.sysMknod == 0 {
		t.Skipf("architecture %s does not have mknod syscall", runtime.GOARCH)
	}

	found := false
	for _, inst := range filter {
		if inst.k == sc.sysMknod && inst.code == (bpfJMP|bpfJEQ|bpfK) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("seccomp filter does not contain SYS_MKNOD (%d) check", sc.sysMknod)
	}
}

// TestSeccompBlocksMknodat verifies that the seccomp filter includes
// SYS_MKNODAT in the blocked syscall list.
func TestSeccompBlocksMknodat(t *testing.T) {
	sc, err := seccompSyscallsFor(runtime.GOARCH)
	if err != nil {
		t.Fatalf("seccompSyscallsFor(%q) error: %v", runtime.GOARCH, err)
	}

	filter := buildSeccompFilter(sc)

	if sc.sysMknodat == 0 {
		t.Skipf("architecture %s does not have mknodat syscall", runtime.GOARCH)
	}

	found := false
	for _, inst := range filter {
		if inst.k == sc.sysMknodat && inst.code == (bpfJMP|bpfJEQ|bpfK) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("seccomp filter does not contain SYS_MKNODAT (%d) check", sc.sysMknodat)
	}
}

// TestSeccompBlocksSpecialFiles verifies that the seccomp filter blocks all
// device-creation syscalls (mknod, mknodat) alongside the other dangerous
// syscalls.
func TestSeccompBlocksSpecialFiles(t *testing.T) {
	sc, err := seccompSyscallsFor(runtime.GOARCH)
	if err != nil {
		t.Fatalf("seccompSyscallsFor(%q) error: %v", runtime.GOARCH, err)
	}

	filter := buildSeccompFilter(sc)

	// Collect all syscall numbers that appear in JEQ checks.
	blockedNrs := make(map[uint32]bool)
	for _, inst := range filter {
		if inst.code == (bpfJMP | bpfJEQ | bpfK) {
			blockedNrs[inst.k] = true
		}
	}

	// Verify all expected dangerous syscalls are present.
	expected := map[string]uint32{
		"ptrace":  sc.sysPtrace,
		"mount":   sc.sysMount,
		"umount2": sc.sysUmount2,
		"reboot":  sc.sysReboot,
		"swapon":  sc.sysSwapon,
		"swapoff": sc.sysSwapoff,
		"socket":  sc.sysSocket,
	}
	if sc.sysMknod != 0 {
		expected["mknod"] = sc.sysMknod
	}
	if sc.sysMknodat != 0 {
		expected["mknodat"] = sc.sysMknodat
	}

	for name, nr := range expected {
		if !blockedNrs[nr] {
			t.Errorf("seccomp filter missing check for %s (syscall %d)", name, nr)
		}
	}
}

// TestBuildSeccompFilterLength verifies the filter has the expected number of
// instructions for each architecture.
func TestBuildSeccompFilterLength(t *testing.T) {
	tests := []struct {
		arch    string
		wantLen int // total BPF instructions: 4 (header) + n (blocked) + 6 (tail)
	}{
		// amd64: 30 unconditional + 4 arch-specific (mknod, mknodat, ioperm, iopl) = 34 blocked → 44 total
		{"amd64", 44},
		// arm64: 30 unconditional + 1 arch-specific (mknodat only) = 31 blocked → 41 total
		{"arm64", 41},
	}

	for _, tt := range tests {
		t.Run(tt.arch, func(t *testing.T) {
			sc, err := seccompSyscallsFor(tt.arch)
			if err != nil {
				t.Fatalf("seccompSyscallsFor(%q) error: %v", tt.arch, err)
			}

			filter := buildSeccompFilter(sc)

			if len(filter) != tt.wantLen {
				t.Errorf("filter length = %d, want %d", len(filter), tt.wantLen)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Subprocess integration tests — verify mknod/mknodat are actually blocked
// ---------------------------------------------------------------------------

// TestApplySeccomp_BlocksMknod verifies that mknod is blocked with EPERM
// under the seccomp filter.
func TestApplySeccomp_BlocksMknod(t *testing.T) {
	if os.Getenv("TEST_SUBPROCESS") == "1" {
		seccompSubprocessHelper(func() string {
			sc, _ := seccompSyscallsFor(runtime.GOARCH)
			if sc.sysMknod == 0 {
				return "RESULT:MKNOD_SKIPPED"
			}
			// Try to call mknod (create a char device /dev/null-like).
			// This should be blocked by seccomp.
			_, _, errno := syscall.Syscall(uintptr(sc.sysMknod), 0, 0, 0)
			if errno == 0 {
				return "RESULT:ERROR mknod should have been blocked"
			}
			if errno != syscall.EPERM {
				return fmt.Sprintf("RESULT:ERROR expected EPERM, got: %v", errno)
			}
			return "RESULT:MKNOD_BLOCKED"
		})
		return
	}

	result := runSeccompSubprocess(t, "TestApplySeccomp_BlocksMknod")
	if strings.Contains(result, "RESULT:ERROR") {
		t.Fatal(result)
	}
	if strings.Contains(result, "RESULT:MKNOD_SKIPPED") {
		t.Skip("mknod syscall not available on this architecture")
	}
	if !strings.Contains(result, "RESULT:MKNOD_BLOCKED") {
		t.Fatalf("expected RESULT:MKNOD_BLOCKED, got: %q", result)
	}
}

// TestApplySeccomp_BlocksMknodat verifies that mknodat is blocked with EPERM
// under the seccomp filter.
func TestApplySeccomp_BlocksMknodat(t *testing.T) {
	if os.Getenv("TEST_SUBPROCESS") == "1" {
		seccompSubprocessHelper(func() string {
			sc, _ := seccompSyscallsFor(runtime.GOARCH)
			if sc.sysMknodat == 0 {
				return "RESULT:MKNODAT_SKIPPED"
			}
			// Try to call mknodat. This should be blocked by seccomp.
			_, _, errno := syscall.Syscall6(uintptr(sc.sysMknodat), 0, 0, 0, 0, 0, 0)
			if errno == 0 {
				return "RESULT:ERROR mknodat should have been blocked"
			}
			if errno != syscall.EPERM {
				return fmt.Sprintf("RESULT:ERROR expected EPERM, got: %v", errno)
			}
			return "RESULT:MKNODAT_BLOCKED"
		})
		return
	}

	result := runSeccompSubprocess(t, "TestApplySeccomp_BlocksMknodat")
	if strings.Contains(result, "RESULT:ERROR") {
		t.Fatal(result)
	}
	if strings.Contains(result, "RESULT:MKNODAT_SKIPPED") {
		t.Skip("mknodat syscall not available on this architecture")
	}
	if !strings.Contains(result, "RESULT:MKNODAT_BLOCKED") {
		t.Fatalf("expected RESULT:MKNODAT_BLOCKED, got: %q", result)
	}
}

// ---------------------------------------------------------------------------
// Namespace / filesystem restriction tests
// ---------------------------------------------------------------------------

// TestNamespaceBlocksFIFO verifies that within a sandboxed namespace,
// FIFO (named pipe) creation in protected paths is blocked by the read-only
// mount namespace.
func TestNamespaceBlocksFIFO(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("namespace tests require root (or user namespace support)")
	}

	// Create a temp dir that will be our "protected" read-only area.
	protectedDir := t.TempDir()

	fifoPath := filepath.Join(protectedDir, "test.fifo")

	// Run mkfifo inside a subprocess with a read-only bind mount.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Use unshare to create a mount namespace and make protectedDir read-only.
	script := fmt.Sprintf(
		"mount --bind %s %s && mount -o remount,ro,bind %s %s && mkfifo %s 2>&1; echo EXIT:$?",
		protectedDir, protectedDir, protectedDir, protectedDir, fifoPath,
	)
	cmd := exec.CommandContext(ctx, "unshare", "--mount", "--", "/bin/sh", "-c", script)
	output, err := cmd.CombinedOutput()
	outStr := string(output)

	// mkfifo should fail because the directory is read-only.
	if err == nil && strings.Contains(outStr, "EXIT:0") {
		t.Fatalf("mkfifo should have failed in read-only namespace, output: %s", outStr)
	}

	// Verify the FIFO was not created.
	if _, statErr := os.Stat(fifoPath); statErr == nil {
		t.Error("FIFO file should not exist after failed mkfifo")
	}
}

// TestHardLinkRestriction verifies that creating hard links to sensitive files
// is restricted by the protected_hardlinks sysctl and/or namespace isolation.
func TestHardLinkRestriction(t *testing.T) {
	// Check if protected_hardlinks is enabled (it is by default on modern kernels).
	data, err := os.ReadFile("/proc/sys/fs/protected_hardlinks")
	if err != nil {
		t.Skip("cannot read protected_hardlinks sysctl")
	}
	if strings.TrimSpace(string(data)) != "1" {
		t.Skip("protected_hardlinks is not enabled")
	}

	// Create a temp dir for the test.
	tmpDir := t.TempDir()

	// Try to create a hard link to /etc/shadow (owned by root).
	// This should fail for non-root users due to protected_hardlinks.
	linkPath := filepath.Join(tmpDir, "shadow-link")
	err = os.Link("/etc/shadow", linkPath)
	if err == nil {
		os.Remove(linkPath)
		// If we're root, the link might succeed — that's expected.
		if os.Getuid() == 0 {
			t.Log("hard link succeeded as root (expected)")
			return
		}
		t.Fatal("hard link to /etc/shadow should have been blocked for non-root")
	}

	// Verify the error is permission-related.
	if !os.IsPermission(err) {
		t.Logf("hard link failed with: %v (expected permission error)", err)
	}
}
