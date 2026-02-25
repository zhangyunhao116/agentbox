//go:build darwin

package darwin

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// ---------------------------------------------------------------------------
// hardenProcess tests
//
// These tests run hardenProcess in a subprocess to avoid modifying the test
// process itself. ptrace(PT_DENY_ATTACH) and setrlimit(RLIMIT_CORE) are
// irreversible process-level operations — calling them in the test process
// would permanently alter its state for all subsequent tests.
// ---------------------------------------------------------------------------

const hardenSubprocessEnv = "AGENTBOX_TEST_HARDEN_SUBPROCESS"

func Test_hardenProcess(t *testing.T) {
	if os.Getenv(hardenSubprocessEnv) == "1" {
		if err := hardenProcess(); err != nil {
			fmt.Fprintf(os.Stderr, "hardenProcess() error: %v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^Test_hardenProcess$", "-test.v")
	cmd.Env = append(os.Environ(), hardenSubprocessEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v\noutput: %s", err, out)
	}
}

func Test_hardenProcessIdempotent(t *testing.T) {
	if os.Getenv(hardenSubprocessEnv) == "1" {
		if err := hardenProcess(); err != nil {
			fmt.Fprintf(os.Stderr, "first call error: %v", err)
			os.Exit(1)
		}
		if err := hardenProcess(); err != nil {
			fmt.Fprintf(os.Stderr, "second call error: %v", err)
			os.Exit(2)
		}
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^Test_hardenProcessIdempotent$", "-test.v")
	cmd.Env = append(os.Environ(), hardenSubprocessEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v\noutput: %s", err, out)
	}
}

func Test_hardenProcessImpl(t *testing.T) {
	if os.Getenv(hardenSubprocessEnv) == "1" {
		if err := hardenProcessImpl(); err != nil {
			fmt.Fprintf(os.Stderr, "hardenProcessImpl() error: %v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^Test_hardenProcessImpl$", "-test.v")
	cmd.Env = append(os.Environ(), hardenSubprocessEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v\noutput: %s", err, out)
	}
}

// ---------------------------------------------------------------------------
// sanitizeEnv LD_* removal tests
// ---------------------------------------------------------------------------

func TestSanitizeEnvRemovesLD(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"LD_PRELOAD=/evil.so",
		"HOME=/Users/test",
		"LD_LIBRARY_PATH=/bad/path",
		"SHELL=/bin/zsh",
	}
	got := sanitizeEnv(env)

	for _, e := range got {
		key := e
		if idx := strings.IndexByte(e, '='); idx >= 0 {
			key = e[:idx]
		}
		if strings.HasPrefix(key, "LD_") {
			t.Errorf("sanitizeEnv should remove LD_* vars, found: %s", e)
		}
	}

	// Should keep non-LD vars.
	expected := map[string]bool{
		"PATH=/usr/bin":    true,
		"HOME=/Users/test": true,
		"SHELL=/bin/zsh":   true,
	}
	for _, e := range got {
		delete(expected, e)
	}
	if len(expected) > 0 {
		t.Errorf("sanitizeEnv removed non-LD vars: %v", expected)
	}
}

func TestSanitizeEnvRemovesDYLD(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"DYLD_INSERT_LIBRARIES=/evil.dylib",
		"HOME=/Users/test",
		"DYLD_LIBRARY_PATH=/bad/path",
		"DYLD_FRAMEWORK_PATH=/another/bad",
	}
	got := sanitizeEnv(env)

	for _, e := range got {
		key := e
		if idx := strings.IndexByte(e, '='); idx >= 0 {
			key = e[:idx]
		}
		if strings.HasPrefix(key, "DYLD_") {
			t.Errorf("sanitizeEnv should remove DYLD_* vars, found: %s", e)
		}
	}

	// Should keep non-DYLD vars.
	expected := map[string]bool{
		"PATH=/usr/bin":    true,
		"HOME=/Users/test": true,
	}
	for _, e := range got {
		delete(expected, e)
	}
	if len(expected) > 0 {
		t.Errorf("sanitizeEnv removed non-DYLD vars: %v", expected)
	}
}

func TestSanitizeEnvRemovesBothLDAndDYLD(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"DYLD_INSERT_LIBRARIES=/evil.dylib",
		"LD_PRELOAD=/evil.so",
		"HOME=/Users/test",
		"LD_LIBRARY_PATH=/bad",
		"DYLD_LIBRARY_PATH=/also/bad",
	}
	got := sanitizeEnv(env)

	for _, e := range got {
		key := e
		if idx := strings.IndexByte(e, '='); idx >= 0 {
			key = e[:idx]
		}
		if strings.HasPrefix(key, "DYLD_") || strings.HasPrefix(key, "LD_") {
			t.Errorf("sanitizeEnv should remove DYLD_*/LD_* vars, found: %s", e)
		}
	}

	if len(got) != 2 {
		t.Errorf("expected 2 remaining vars, got %d: %v", len(got), got)
	}
}

func TestSanitizeEnvOnlyLD(t *testing.T) {
	env := []string{"LD_PRELOAD=/evil.so", "LD_LIBRARY_PATH=/bad"}
	got := sanitizeEnv(env)
	if len(got) != 0 {
		t.Errorf("sanitizeEnv should remove all LD_* vars, got %v", got)
	}
}
