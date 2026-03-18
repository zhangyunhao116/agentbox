package agentbox

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/zhangyunhao116/agentbox/testutil"
)

// TestExecHelperBasic verifies that execHelper captures stdout and returns
// the correct exit code.
func TestExecHelperBasic(t *testing.T) {
	shell, args := testutil.EchoCommand("hello")
	cmd := exec.CommandContext(context.Background(), shell, args...)
	result, err := execHelper(cmd, 0, false)
	if err != nil {
		t.Fatalf("execHelper() error: %v", err)
	}
	if got := strings.TrimSpace(result.Stdout); got != "hello" {
		t.Errorf("Stdout = %q, want %q", got, "hello")
	}
	if result.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", result.ExitCode)
	}
	if result.Sandboxed {
		t.Error("Sandboxed should be false")
	}
}

// TestExecHelperSandboxedFlag verifies that the sandboxed flag is correctly
// propagated to the result.
func TestExecHelperSandboxedFlag(t *testing.T) {
	shell, args := testutil.EchoCommand("test")
	cmd := exec.CommandContext(context.Background(), shell, args...)
	result, err := execHelper(cmd, 0, true)
	if err != nil {
		t.Fatalf("execHelper() error: %v", err)
	}
	if !result.Sandboxed {
		t.Error("Sandboxed should be true")
	}
}

// TestExecHelperNonZeroExit verifies that non-zero exit codes are captured
// without returning a Go error.
func TestExecHelperNonZeroExit(t *testing.T) {
	shell, args := testutil.ExitCommand(42)
	cmd := exec.CommandContext(context.Background(), shell, args...)
	result, err := execHelper(cmd, 0, false)
	if err != nil {
		t.Fatalf("execHelper() error: %v", err)
	}
	if result.ExitCode != 42 {
		t.Errorf("ExitCode = %d, want 42", result.ExitCode)
	}
}

// TestExecHelperMaxOutput verifies that output is truncated when maxOutput
// is set.
func TestExecHelperMaxOutput(t *testing.T) {
	shell, args := testutil.EchoCommand("this is a long output string that exceeds the limit")
	cmd := exec.CommandContext(context.Background(), shell, args...)
	result, err := execHelper(cmd, 10, false)
	if err != nil {
		t.Fatalf("execHelper() error: %v", err)
	}
	if len(result.Stdout) > 10 {
		t.Errorf("Stdout length = %d, want <= 10", len(result.Stdout))
	}
	if !result.Truncated {
		t.Error("Truncated should be true")
	}
}

// TestExecHelperStderr verifies that stderr is captured.
func TestExecHelperStderr(t *testing.T) {
	shell, args := testutil.StderrCommand("error")
	cmd := exec.CommandContext(context.Background(), shell, args...)
	result, err := execHelper(cmd, 0, false)
	if err != nil {
		t.Fatalf("execHelper() error: %v", err)
	}
	if got := strings.TrimSpace(result.Stderr); got != "error" {
		t.Errorf("Stderr = %q, want %q", got, "error")
	}
}

// TestExecHelperDuration verifies that duration is positive.
func TestExecHelperDuration(t *testing.T) {
	shell, args := testutil.EchoCommand("test")
	cmd := exec.CommandContext(context.Background(), shell, args...)
	result, err := execHelper(cmd, 0, false)
	if err != nil {
		t.Fatalf("execHelper() error: %v", err)
	}
	if result.Duration <= 0 {
		t.Error("Duration should be positive")
	}
}

// TestExecHelperInvalidCommand verifies that execHelper returns an error
// for a nonexistent binary.
func TestExecHelperInvalidCommand(t *testing.T) {
	cmd := exec.CommandContext(context.Background(), "/nonexistent_binary_xyz")
	_, err := execHelper(cmd, 0, false)
	if err == nil {
		t.Fatal("execHelper() should return error for nonexistent binary")
	}
}

// TestNormalizeCommand verifies that normalizeCommand collapses whitespace.
func TestNormalizeCommand(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"echo hello", "echo hello"},
		{"echo  hello", "echo hello"},
		{"  echo   hello  ", "echo hello"},
		{"pip install requests", "pip install requests"},
		{"pip  install  requests", "pip install requests"},
		{"\techo\thello\t", "echo hello"},
		{"", ""},
		{"single", "single"},
	}
	for _, tt := range tests {
		got := normalizeCommand(tt.input)
		if got != tt.want {
			t.Errorf("normalizeCommand(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
