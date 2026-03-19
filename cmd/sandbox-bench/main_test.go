package main

import (
	"os/exec"
	"testing"
)

func TestSandboxBench(t *testing.T) {
	// Test successful command execution.
	cmd := exec.Command("go", "run", ".", "echo", "hello")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run failed: %v\nOutput: %s", err, out)
	}
	if string(out) != "hello\n" {
		t.Errorf("expected 'hello\\n', got %q", out)
	}

	// Test exit code propagation using false command.
	cmd = exec.Command("go", "run", ".", "false")
	err = cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit code from 'false' command")
	}

	// Test usage message.
	cmd = exec.Command("go", "run", ".")
	err = cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit code for no arguments")
	}
}
