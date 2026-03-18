// Example codemod simulates a code-modification agent that iteratively fixes
// lint and formatting issues in a Go project. It scaffolds a project with
// intentional problems (wrong indentation, unused import), then uses gofmt
// and go vet to detect and fix issues, and verifies the result with go test.
//
// It uses [agentbox.Manager.ExecArgs] exclusively (no shell).
//
// Usage:
//
//	go run ./examples/codemod
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
	workdir, err := os.MkdirTemp("", "agentbox-codemod-*")
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

	// Common exec options reused across all go/gofmt commands.
	execOpts := []agentbox.Option{
		agentbox.WithWorkingDir(workdir),
		agentbox.WithEnv("GOCACHE="+gocache, "GOPATH="+gopath),
		agentbox.WithTimeout(30 * time.Second),
	}

	step := 0
	fixRounds := 0

	step++
	printStep(step, "Create temporary workspace")
	fmt.Printf("  Workspace: %s\n", workdir)

	step++
	printStep(step, "Configure sandbox with FallbackWarn")
	fmt.Println("  Sandbox manager ready.")

	// Scaffold a Go project with intentional issues.
	step++
	printStep(step, "Scaffold Go project with intentional issues")
	if err := writeProjectFiles(workdir); err != nil {
		return err
	}
	fmt.Println("  Created go.mod, mathutil.go (bad formatting + unused import), mathutil_test.go")

	// Detect formatting issues.
	step++
	printStep(step, "Run gofmt -l to detect formatting issues")
	result, err := mgr.ExecArgs(ctx, "gofmt", []string{"-l", "."}, execOpts...)
	if err != nil {
		return fmt.Errorf("gofmt -l: %w", err)
	}
	printResult(result)
	fmtFiles := strings.TrimSpace(result.Stdout)
	if fmtFiles == "" {
		return errors.New("expected gofmt to find formatting issues, but none found")
	}
	fmt.Printf("  ✗ Formatting issues in: %s\n", fmtFiles)

	// Auto-fix formatting.
	step++
	printStep(step, "Run gofmt -w to auto-fix formatting")
	result, err = mgr.ExecArgs(ctx, "gofmt", []string{"-w", "."}, execOpts...)
	if err != nil {
		return fmt.Errorf("gofmt -w: %w", err)
	}
	printResult(result)
	if result.ExitCode != 0 {
		return fmt.Errorf("gofmt -w failed: exit=%d stderr=%q", result.ExitCode, result.Stderr)
	}
	fixRounds++
	fmt.Println("  ✓ Formatting fixed.")

	// Detect unused import.
	step++
	printStep(step, "Run go vet to detect unused import")
	result, err = mgr.ExecArgs(ctx, "go", []string{"vet", "./..."}, execOpts...)
	if err != nil {
		return fmt.Errorf("go vet (first): %w", err)
	}
	printResult(result)
	if result.ExitCode == 0 {
		return errors.New("expected go vet to find unused import, but no issues found")
	}
	combined := result.Stdout + result.Stderr
	if !strings.Contains(combined, "\"fmt\" imported and not used") {
		return fmt.Errorf("expected unused import diagnostic, got: %s", combined)
	}
	fmt.Println("  ✗ Unused import detected: \"fmt\"")

	// Fix the source code — remove unused import.
	step++
	printStep(step, "Fix source code (remove unused import)")
	if err := os.WriteFile(filepath.Join(workdir, "mathutil.go"), []byte(fixedMathutilGo), 0o644); err != nil {
		return fmt.Errorf("write fixed mathutil.go: %w", err)
	}
	fixRounds++
	fmt.Println("  Overwrote mathutil.go with corrected version.")

	// Verify vet is clean.
	step++
	printStep(step, "Run go vet again (verify clean)")
	result, err = mgr.ExecArgs(ctx, "go", []string{"vet", "./..."}, execOpts...)
	if err != nil {
		return fmt.Errorf("go vet (second): %w", err)
	}
	printResult(result)
	if result.ExitCode != 0 {
		return fmt.Errorf("vet still failing after fix: exit=%d stderr=%q", result.ExitCode, result.Stderr)
	}
	fmt.Println("  ✓ No issues found.")

	// Verify all tests pass.
	step++
	printStep(step, "Run go test -v (verify tests pass)")
	result, err = mgr.ExecArgs(ctx, "go", []string{"test", "-v", "./..."}, execOpts...)
	if err != nil {
		return fmt.Errorf("go test: %w", err)
	}
	printResult(result)
	if result.ExitCode != 0 {
		return fmt.Errorf("tests failed: exit=%d stderr=%q", result.ExitCode, result.Stderr)
	}
	fmt.Println("  ✓ All tests pass.")

	// Print iteration summary.
	step++
	printStep(step, "Iteration summary")
	fmt.Printf("  Completed in %d steps with %d fix rounds.\n", step, fixRounds)
	fmt.Println("  Round 1: gofmt -w fixed indentation (spaces → tabs).")
	fmt.Println("  Round 2: Removed unused \"fmt\" import.")
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

func writeProjectFiles(dir string) error {
	for name, content := range map[string]string{
		"go.mod": goModContent, "mathutil.go": badMathutilGo, "mathutil_test.go": mathutilTestGo,
	} {
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

const goModContent = `module example.com/codemod-task

go 1.21
`

// badMathutilGo: spaces not tabs (gofmt), unused "fmt" import (go vet).
const badMathutilGo = "package mathutil\n\nimport (\n  \"fmt\"    // unused import\n  \"math\"   // used\n)\n\n// Sqrt returns the square root of x, or -1 if x is negative.\nfunc Sqrt(x float64) float64 {\n  if x < 0 {\n    return -1\n  }\n  return math.Sqrt(x)\n}\n"

const fixedMathutilGo = `package mathutil

import (
	"math"
)

// Sqrt returns the square root of x, or -1 if x is negative.
func Sqrt(x float64) float64 {
	if x < 0 {
		return -1
	}
	return math.Sqrt(x)
}
`

const mathutilTestGo = `package mathutil

import (
	"math"
	"testing"
)

func TestSqrt(t *testing.T) {
	tests := []struct {
		name string
		x    float64
		want float64
	}{
		{name: "positive", x: 16, want: 4},
		{name: "zero", x: 0, want: 0},
		{name: "negative", x: -1, want: -1},
		{name: "fraction", x: 0.25, want: 0.5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Sqrt(tt.x)
			if math.Abs(got-tt.want) > 1e-9 {
				t.Errorf("Sqrt(%v) = %v, want %v", tt.x, got, tt.want)
			}
		})
	}
}
`
