// Example agentsim simulates a realistic AI coding agent workflow: receive a
// task, write code with a bug, run tests to discover the failure, fix the bug,
// and re-test until all checks pass.
//
// It uses [agentbox.Manager.ExecArgs] exclusively (no shell), making it fully
// cross-platform (macOS, Linux, Windows).
//
// Usage:
//
//	go run ./examples/agentsim
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/zhangyunhao116/agentbox"
)

func main() {
	if agentbox.MaybeSandboxInit() {
		return
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()

	// Create a temporary workspace that the sandbox will allow writes to.
	workdir, err := os.MkdirTemp("", "agentbox-agentsim-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(workdir)

	// GOCACHE and GOPATH must reside inside writable roots so the Go
	// toolchain can write build-cache and module artifacts.
	gocache := filepath.Join(workdir, "cache")
	gopath := filepath.Join(workdir, "gopath")
	for _, d := range []string{gocache, gopath} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("create dir %s: %w", d, err)
		}
	}

	cfg := agentbox.DefaultConfig()
	cfg.FallbackPolicy = agentbox.FallbackWarn
	cfg.Shell = defaultShellPath()
	cfg.Filesystem.WritableRoots = []string{workdir, os.TempDir()}
	if runtime.GOOS == "windows" {
		// On Windows, os.TempDir() is under $HOME which is in the deny list.
		// Clear deny lists so the example can use temp dirs as writable roots.
		cfg.Filesystem.DenyWrite = nil
		cfg.Filesystem.DenyRead = nil
	}

	mgr, err := agentbox.NewManager(cfg)
	if err != nil {
		return fmt.Errorf("new manager: %w", err)
	}
	defer mgr.Cleanup(ctx)

	// Common exec options reused across all go commands.
	execOpts := []agentbox.Option{
		agentbox.WithWorkingDir(workdir),
		agentbox.WithEnv("GOCACHE="+gocache, "GOPATH="+gopath),
		agentbox.WithTimeout(30 * time.Second),
	}

	step := 0

	// Step 1: Agent receives a task.
	step++
	printStep(step, "Agent receives task")
	fmt.Println("  Task: Implement a Sum function for integer slices with full test coverage.")

	// Step 2: Agent writes initial code (with an off-by-one bug).
	step++
	printStep(step, "Agent writes initial code")
	if err := writeProjectFiles(workdir, buggyCalcGo); err != nil {
		return err
	}
	fmt.Println("  Created go.mod, calc.go (with bug), calc_test.go")

	// Step 3: Agent runs tests — expects failure.
	step++
	printStep(step, "Agent runs tests (attempt 1)")
	result, err := mgr.ExecArgs(ctx, "go", []string{"test", "-v", "./..."}, execOpts...)
	if err != nil {
		return fmt.Errorf("go test attempt 1: %w", err)
	}
	printResult(result)
	if result.ExitCode == 0 {
		return errors.New("expected test failure on buggy code, but tests passed")
	}
	fmt.Println("  ✗ Tests failed as expected — bug detected.")

	// Step 4: Agent analyzes the failure.
	step++
	printStep(step, "Agent analyzes failure")
	if strings.Contains(result.Stdout+result.Stderr, "FAIL") {
		fmt.Println("  Found FAIL in output — the Sum function skips the first element.")
	}

	// Step 5: Agent fixes the bug.
	step++
	printStep(step, "Agent fixes the bug")
	if err := os.WriteFile(filepath.Join(workdir, "calc.go"), []byte(fixedCalcGo), 0o644); err != nil {
		return fmt.Errorf("write fixed calc.go: %w", err)
	}
	fmt.Println("  Overwrote calc.go with corrected implementation.")

	// Step 6: Agent runs tests again — expects success.
	step++
	printStep(step, "Agent runs tests (attempt 2)")
	result, err = mgr.ExecArgs(ctx, "go", []string{"test", "-v", "./..."}, execOpts...)
	if err != nil {
		return fmt.Errorf("go test attempt 2: %w", err)
	}
	printResult(result)
	if result.ExitCode != 0 {
		return fmt.Errorf("tests still failing after fix: exit=%d stderr=%q", result.ExitCode, result.Stderr)
	}
	fmt.Println("  ✓ All tests pass.")

	// Step 7: Agent runs go vet.
	step++
	printStep(step, "Agent runs vet")
	result, err = mgr.ExecArgs(ctx, "go", []string{"vet", "./..."}, execOpts...)
	if err != nil {
		return fmt.Errorf("go vet: %w", err)
	}
	printResult(result)
	if result.ExitCode != 0 {
		return fmt.Errorf("vet failed: exit=%d stderr=%q", result.ExitCode, result.Stderr)
	}
	fmt.Println("  ✓ No issues found.")

	// Step 8: Agent delivers result.
	step++
	printStep(step, "Agent delivers result")
	fmt.Printf("  Task completed in %d steps with 1 fix iteration.\n", step)
	fmt.Println("  Summary: wrote Sum(), caught off-by-one via tests, fixed, verified.")
	fmt.Println("\nAll steps completed successfully.")
	return nil
}

func printStep(n int, desc string) {
	fmt.Printf("\n=== Step %d: %s ===\n", n, desc)
}

func printResult(r *agentbox.ExecResult) {
	fmt.Printf("  exit=%d sandboxed=%v duration=%s\n", r.ExitCode, r.Sandboxed, r.Duration.Round(time.Millisecond))
	if out := strings.TrimSpace(r.Stdout); out != "" {
		for _, line := range strings.Split(out, "\n") {
			fmt.Printf("  stdout: %s\n", line)
		}
	}
	if out := strings.TrimSpace(r.Stderr); out != "" {
		for _, line := range strings.Split(out, "\n") {
			fmt.Printf("  stderr: %s\n", line)
		}
	}
}

func writeProjectFiles(dir, calcSrc string) error {
	files := map[string]string{
		"go.mod":       goModContent,
		"calc.go":      calcSrc,
		"calc_test.go": calcTestGo,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}

// defaultShellPath returns a valid shell path; ExecArgs never uses it but NewManager validates it.
func defaultShellPath() string {
	if runtime.GOOS == "windows" {
		if root := os.Getenv("SYSTEMROOT"); root != "" {
			return filepath.Join(root, "System32", "cmd.exe")
		}
		return `C:\Windows\System32\cmd.exe`
	}
	return "/bin/sh"
}

// Embedded source files for the agent's micro-project.

const goModContent = `module example.com/agent-task

go 1.21
`

// buggyCalcGo has an off-by-one bug: the loop starts at index 1.
const buggyCalcGo = `package calc

// Sum returns the sum of all integers in nums.
func Sum(nums []int) int {
	total := 0
	for i := 1; i < len(nums); i++ {
		total += nums[i]
	}
	return total
}
`

const fixedCalcGo = `package calc

// Sum returns the sum of all integers in nums.
func Sum(nums []int) int {
	total := 0
	for i := 0; i < len(nums); i++ {
		total += nums[i]
	}
	return total
}
`

const calcTestGo = `package calc

import "testing"

func TestSum(t *testing.T) {
	tests := []struct {
		name string
		nums []int
		want int
	}{
		{name: "empty", nums: nil, want: 0},
		{name: "single", nums: []int{42}, want: 42},
		{name: "multiple", nums: []int{1, 2, 3, 4, 5}, want: 15},
		{name: "negatives", nums: []int{-1, -2, -3}, want: -6},
		{name: "mixed", nums: []int{10, -5, 3}, want: 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Sum(tt.nums); got != tt.want {
				t.Errorf("Sum(%v) = %d, want %d", tt.nums, got, tt.want)
			}
		})
	}
}
`
