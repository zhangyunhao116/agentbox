package main

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/zhangyunhao116/agentbox/testutil"
)

func TestSandboxBench(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode: requires real sandbox execution")
	}

	// Test successful command execution.
	// Use testutil helpers so that the command works on both Unix and Windows.
	// EchoCommand returns (shell, shellArgs) — e.g. ("/bin/sh", ["-c", "echo hello"])
	// on Unix or ("cmd.exe", ["/c", "echo hello"]) on Windows.
	echoShell, echoArgs := testutil.EchoCommand("hello")
	goRunArgs := append([]string{"run", "."}, echoShell)
	goRunArgs = append(goRunArgs, echoArgs...)
	cmd := exec.Command("go", goRunArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run failed: %v\nOutput: %s", err, out)
	}
	// Use TrimSpace to handle both \n (Unix) and \r\n (Windows) line endings.
	if got := strings.TrimSpace(string(out)); got != "hello" {
		t.Errorf("expected 'hello', got %q", got)
	}

	// Test exit code propagation using a cross-platform exit command.
	// ExitCommand returns (shell, shellArgs) for "exit 1" on all platforms.
	exitShell, exitArgs := testutil.ExitCommand(1)
	goRunArgs = append([]string{"run", "."}, exitShell)
	goRunArgs = append(goRunArgs, exitArgs...)
	cmd = exec.Command("go", goRunArgs...)
	err = cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit code from exit command")
	}

	// Test usage message.
	cmd = exec.Command("go", "run", ".")
	err = cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit code for no arguments")
	}
}
