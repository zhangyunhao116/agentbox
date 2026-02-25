//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestHardenProcess runs hardenProcess() in a subprocess and verifies it succeeds.
func TestHardenProcess(t *testing.T) {
	if os.Getenv("TEST_SUBPROCESS") == "1" {
		if err := hardenProcess(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHardenProcess$", "-test.v")
	cmd.Env = append(os.Environ(), "TEST_SUBPROCESS=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v\noutput: %s", err, output)
	}
}

// TestHardenProcess_NoNewPrivsError verifies that hardenProcess returns an error
// when the first prctl call (PR_SET_NO_NEW_PRIVS) fails.
func TestHardenProcess_NoNewPrivsError(t *testing.T) {
	origPrctl := prctlFunc
	t.Cleanup(func() { prctlFunc = origPrctl })

	prctlFunc = func(option, arg2, arg3, arg4, arg5, arg6 uintptr) (uintptr, uintptr, syscall.Errno) {
		return 0, 0, syscall.EPERM
	}

	err := hardenProcess()
	if err == nil {
		t.Fatal("hardenProcess() expected error when PR_SET_NO_NEW_PRIVS fails, got nil")
	}
	if !strings.Contains(err.Error(), "prctl(PR_SET_NO_NEW_PRIVS)") {
		t.Errorf("error should mention PR_SET_NO_NEW_PRIVS, got: %v", err)
	}
}

// TestHardenProcess_DumpableError verifies that hardenProcess returns an error
// when the second prctl call (PR_SET_DUMPABLE) fails.
func TestHardenProcess_DumpableError(t *testing.T) {
	origPrctl := prctlFunc
	t.Cleanup(func() { prctlFunc = origPrctl })

	callCount := 0
	prctlFunc = func(option, arg2, arg3, arg4, arg5, arg6 uintptr) (uintptr, uintptr, syscall.Errno) {
		callCount++
		if callCount == 1 {
			// First call (PR_SET_NO_NEW_PRIVS) succeeds.
			return 0, 0, 0
		}
		// Second call (PR_SET_DUMPABLE) fails.
		return 0, 0, syscall.EINVAL
	}

	err := hardenProcess()
	if err == nil {
		t.Fatal("hardenProcess() expected error when PR_SET_DUMPABLE fails, got nil")
	}
	if !strings.Contains(err.Error(), "prctl(PR_SET_DUMPABLE)") {
		t.Errorf("error should mention PR_SET_DUMPABLE, got: %v", err)
	}
}

// TestHardenProcess_CoreLimitError verifies that hardenProcess returns an error
// when setrlimit(RLIMIT_CORE) fails.
func TestHardenProcess_CoreLimitError(t *testing.T) {
	origPrctl := prctlFunc
	origSetrlimit := setrlimitFunc
	t.Cleanup(func() {
		prctlFunc = origPrctl
		setrlimitFunc = origSetrlimit
	})

	// Both prctl calls succeed.
	prctlFunc = func(option, arg2, arg3, arg4, arg5, arg6 uintptr) (uintptr, uintptr, syscall.Errno) {
		return 0, 0, 0
	}
	// setrlimit fails.
	setrlimitFunc = func(resource int, rlim *syscall.Rlimit) error {
		return errors.New("simulated setrlimit error")
	}

	err := hardenProcess()
	if err == nil {
		t.Fatal("hardenProcess() expected error when setrlimit fails, got nil")
	}
	if !strings.Contains(err.Error(), "setrlimit(RLIMIT_CORE)") {
		t.Errorf("error should mention setrlimit(RLIMIT_CORE), got: %v", err)
	}
}

// TestHardenProcess_NoNewPrivs verifies PR_SET_NO_NEW_PRIVS is set after hardenProcess().
func TestHardenProcess_NoNewPrivs(t *testing.T) {
	if os.Getenv("TEST_SUBPROCESS") == "1" {
		if err := hardenProcess(); err != nil {
			fmt.Fprintf(os.Stderr, "hardenProcess error: %v", err)
			os.Exit(1)
		}
		// The prctl constant PR_GET_NO_NEW_PRIVS has value 39.
		val, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, 39, 0, 0, 0, 0, 0)
		if errno != 0 {
			fmt.Fprintf(os.Stderr, "prctl(PR_GET_NO_NEW_PRIVS) error: %v", errno)
			os.Exit(1)
		}
		// Print the value so the parent can verify.
		fmt.Fprintf(os.Stdout, "NO_NEW_PRIVS=%d", val)
		os.Exit(0)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHardenProcess_NoNewPrivs$", "-test.v")
	cmd.Env = append(os.Environ(), "TEST_SUBPROCESS=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v\noutput: %s", err, output)
	}
	outStr := string(output)
	if !strings.Contains(outStr, "NO_NEW_PRIVS=1") {
		t.Fatalf("expected NO_NEW_PRIVS=1 in output, got: %s", outStr)
	}
}

// TestHardenProcess_NotDumpable verifies PR_SET_DUMPABLE=0 after hardenProcess().
func TestHardenProcess_NotDumpable(t *testing.T) {
	if os.Getenv("TEST_SUBPROCESS") == "1" {
		if err := hardenProcess(); err != nil {
			fmt.Fprintf(os.Stderr, "hardenProcess error: %v", err)
			os.Exit(1)
		}
		// The prctl constant PR_GET_DUMPABLE has value 3.
		val, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, 3, 0, 0, 0, 0, 0)
		if errno != 0 {
			fmt.Fprintf(os.Stderr, "prctl(PR_GET_DUMPABLE) error: %v", errno)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stdout, "DUMPABLE=%d", val)
		os.Exit(0)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHardenProcess_NotDumpable$", "-test.v")
	cmd.Env = append(os.Environ(), "TEST_SUBPROCESS=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v\noutput: %s", err, output)
	}
	outStr := string(output)
	if !strings.Contains(outStr, "DUMPABLE=0") {
		t.Fatalf("expected DUMPABLE=0 in output, got: %s", outStr)
	}
}

// TestHardenProcess_CoreLimitZero verifies RLIMIT_CORE is 0 after hardenProcess().
func TestHardenProcess_CoreLimitZero(t *testing.T) {
	if os.Getenv("TEST_SUBPROCESS") == "1" {
		if err := hardenProcess(); err != nil {
			fmt.Fprintf(os.Stderr, "hardenProcess error: %v", err)
			os.Exit(1)
		}
		var rlim syscall.Rlimit
		if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &rlim); err != nil {
			fmt.Fprintf(os.Stderr, "getrlimit error: %v", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stdout, "CORE_CUR=%d CORE_MAX=%d", rlim.Cur, rlim.Max)
		os.Exit(0)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHardenProcess_CoreLimitZero$", "-test.v")
	cmd.Env = append(os.Environ(), "TEST_SUBPROCESS=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v\noutput: %s", err, output)
	}
	outStr := string(output)
	// Parse CORE_CUR and CORE_MAX values.
	for _, key := range []string{"CORE_CUR", "CORE_MAX"} {
		idx := strings.Index(outStr, key+"=")
		if idx == -1 {
			t.Fatalf("expected %s= in output, got: %s", key, outStr)
		}
		valStr := outStr[idx+len(key)+1:]
		// Take until space or end of string.
		if spIdx := strings.IndexByte(valStr, ' '); spIdx != -1 {
			valStr = valStr[:spIdx]
		}
		// Trim any trailing newlines or whitespace.
		valStr = strings.TrimSpace(valStr)
		val, err := strconv.ParseUint(valStr, 10, 64)
		if err != nil {
			t.Fatalf("failed to parse %s value %q: %v", key, valStr, err)
		}
		if val != 0 {
			t.Errorf("%s = %d, want 0", key, val)
		}
	}
}
