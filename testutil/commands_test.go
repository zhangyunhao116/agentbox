package testutil

import (
	"bytes"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// TestEchoCommand verifies that EchoCommand produces runnable output.
func TestEchoCommand(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{name: "simple", text: "hello", want: "hello"},
		{name: "multi_word", text: "hello world", want: "hello world"},
		{name: "numbers", text: "42", want: "42"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shell, args := EchoCommand(tt.text)
			out, err := exec.Command(shell, args...).Output()
			if err != nil {
				t.Fatalf("EchoCommand(%q) execution failed: %v", tt.text, err)
			}
			got := strings.TrimSpace(string(out))
			if got != tt.want {
				t.Errorf("EchoCommand(%q) output = %q, want %q", tt.text, got, tt.want)
			}
		})
	}
}

// TestEchoCommandReturnsShell verifies the shell binary.
func TestEchoCommandReturnsShell(t *testing.T) {
	shell, _ := EchoCommand("x")
	if shell != Shell() {
		t.Errorf("EchoCommand shell = %q, want %q", shell, Shell())
	}
}

// TestExitCommand verifies that ExitCommand exits with the correct code.
func TestExitCommand(t *testing.T) {
	tests := []struct {
		name string
		code int
	}{
		{name: "zero", code: 0},
		{name: "one", code: 1},
		{name: "forty_two", code: 42},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shell, args := ExitCommand(tt.code)
			err := exec.Command(shell, args...).Run()
			if tt.code == 0 {
				if err != nil {
					t.Fatalf("ExitCommand(0) should succeed, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ExitCommand(%d) should fail, got nil error", tt.code)
			}
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("ExitCommand(%d) error type = %T, want *exec.ExitError", tt.code, err)
			}
			if exitErr.ExitCode() != tt.code {
				t.Errorf("ExitCommand(%d) exit code = %d, want %d", tt.code, exitErr.ExitCode(), tt.code)
			}
		})
	}
}

// TestPrintEnvCommand verifies that PrintEnvCommand prints an env variable.
func TestPrintEnvCommand(t *testing.T) {
	// HOME is set on macOS/Linux; USERPROFILE on Windows. Use PATH which is
	// universally available on all platforms.
	varName := "PATH"
	shell, args := PrintEnvCommand(varName)
	out, err := exec.Command(shell, args...).Output()
	if err != nil {
		t.Fatalf("PrintEnvCommand(%q) execution failed: %v", varName, err)
	}
	got := strings.TrimSpace(string(out))
	if got == "" {
		t.Error("PrintEnvCommand(\"PATH\") returned empty output")
	}
}

// TestPrintEnvCommandShell verifies the shell binary.
func TestPrintEnvCommandShell(t *testing.T) {
	shell, _ := PrintEnvCommand("X")
	if shell != Shell() {
		t.Errorf("PrintEnvCommand shell = %q, want %q", shell, Shell())
	}
}

// TestPwdCommand verifies that PwdCommand prints a directory path.
func TestPwdCommand(t *testing.T) {
	shell, args := PwdCommand()
	out, err := exec.Command(shell, args...).Output()
	if err != nil {
		t.Fatalf("PwdCommand() execution failed: %v", err)
	}
	got := strings.TrimSpace(string(out))
	if got == "" {
		t.Error("PwdCommand() returned empty output")
	}
}

// TestPwdCommandShell verifies the shell binary.
func TestPwdCommandShell(t *testing.T) {
	shell, _ := PwdCommand()
	if shell != Shell() {
		t.Errorf("PwdCommand shell = %q, want %q", shell, Shell())
	}
}

// TestStderrCommand verifies that StderrCommand writes to stderr.
func TestStderrCommand(t *testing.T) {
	shell, args := StderrCommand("errmsg")
	cmd := exec.Command(shell, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("StderrCommand(\"errmsg\") execution failed: %v", err)
	}
	got := strings.TrimSpace(stderr.String())
	if !strings.Contains(got, "errmsg") {
		t.Errorf("StderrCommand(\"errmsg\") stderr = %q, want to contain %q", got, "errmsg")
	}
	if strings.TrimSpace(stdout.String()) != "" {
		t.Errorf("StderrCommand(\"errmsg\") stdout = %q, want empty", stdout.String())
	}
}

// TestStderrCommandShell verifies the shell binary.
func TestStderrCommandShell(t *testing.T) {
	shell, _ := StderrCommand("x")
	if shell != Shell() {
		t.Errorf("StderrCommand shell = %q, want %q", shell, Shell())
	}
}

// TestSleepCommandShell verifies the shell binary.
func TestSleepCommandShell(t *testing.T) {
	shell, _ := SleepCommand(1)
	if shell != Shell() {
		t.Errorf("SleepCommand shell = %q, want %q", shell, Shell())
	}
}

// TestAllCommandsUseShell verifies that all command helpers return the
// platform shell as their first element.
func TestAllCommandsUseShell(t *testing.T) {
	wantShell := Shell()
	fns := []struct {
		name  string
		shell string
	}{
		{"EchoCommand", func() string { s, _ := EchoCommand("x"); return s }()},
		{"ExitCommand", func() string { s, _ := ExitCommand(0); return s }()},
		{"PrintEnvCommand", func() string { s, _ := PrintEnvCommand("X"); return s }()},
		{"PwdCommand", func() string { s, _ := PwdCommand(); return s }()},
		{"StderrCommand", func() string { s, _ := StderrCommand("x"); return s }()},
		{"SleepCommand", func() string { s, _ := SleepCommand(1); return s }()},
	}
	for _, fn := range fns {
		if fn.shell != wantShell {
			t.Errorf("%s shell = %q, want %q", fn.name, fn.shell, wantShell)
		}
	}
}
