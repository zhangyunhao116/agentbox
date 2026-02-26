// Example devworkflow simulates an AI agent performing a typical development
// cycle: scaffold a Go project, build, test, and lint — all within a sandboxed
// environment.
//
// This demonstrates how agentbox can be used to safely execute build toolchains
// while restricting filesystem access to a designated working directory.
//
// Usage:
//
//	go run ./examples/devworkflow
package main

import (
	"context"
	"fmt"
	"log"
	"os"

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

	// Create a temporary directory as the writable root for the project.
	workdir, err := os.MkdirTemp("", "agentbox-devworkflow-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(workdir)

	// Configure the sandbox: only the temp dir and /tmp are writable.
	cfg := agentbox.DefaultConfig()
	cfg.Filesystem.WritableRoots = []string{workdir, "/tmp"}

	mgr, err := agentbox.NewManager(cfg)
	if err != nil {
		return fmt.Errorf("new manager: %w", err)
	}
	defer mgr.Cleanup(ctx)

	// Step 1: Scaffold a minimal Go project inside the sandbox.
	goMod := `module example.com/sandbox-demo

go 1.21
`
	goMain := `package main

import "fmt"

func main() {
	fmt.Println("built inside sandbox")
}
`
	goTest := `package main

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

func TestMain_output(t *testing.T) {
	cmd := exec.Command("go", "run", ".")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		t.Fatalf("go run: %v", err)
	}
	got := strings.TrimSpace(buf.String())
	if got != "built inside sandbox" {
		t.Fatalf("unexpected output: %q", got)
	}
}
`

	scaffoldCmd := fmt.Sprintf(
		"cat > %s/go.mod << 'GOMOD'\n%sGOMOD\n"+
			"cat > %s/main.go << 'GOMAIN'\n%sGOMAIN\n"+
			"cat > %s/main_test.go << 'GOTEST'\n%sGOTEST",
		workdir, goMod,
		workdir, goMain,
		workdir, goTest,
	)

	result, err := mgr.Exec(ctx, scaffoldCmd)
	if err != nil {
		return fmt.Errorf("scaffold project: %w", err)
	}
	fmt.Printf("Scaffold project:\n")
	fmt.Printf("  exit=%d sandboxed=%v\n", result.ExitCode, result.Sandboxed)
	if result.ExitCode != 0 {
		return fmt.Errorf("scaffold failed: exit=%d stderr=%q", result.ExitCode, result.Stderr)
	}

	// Step 2: Build the project.
	result, err = mgr.Exec(ctx, fmt.Sprintf("cd %s && go build ./...", workdir))
	if err != nil {
		return fmt.Errorf("go build: %w", err)
	}
	fmt.Printf("Build:\n")
	fmt.Printf("  exit=%d sandboxed=%v\n", result.ExitCode, result.Sandboxed)
	if result.ExitCode != 0 {
		return fmt.Errorf("build failed: exit=%d stderr=%q", result.ExitCode, result.Stderr)
	}

	// Step 3: Run tests.
	result, err = mgr.Exec(ctx, fmt.Sprintf("cd %s && go test ./...", workdir))
	if err != nil {
		return fmt.Errorf("go test: %w", err)
	}
	fmt.Printf("Test:\n")
	fmt.Printf("  exit=%d sandboxed=%v stdout=%q\n", result.ExitCode, result.Sandboxed, result.Stdout)
	if result.ExitCode != 0 {
		return fmt.Errorf("test failed: exit=%d stderr=%q", result.ExitCode, result.Stderr)
	}

	// Step 4: Run vet.
	result, err = mgr.Exec(ctx, fmt.Sprintf("cd %s && go vet ./...", workdir))
	if err != nil {
		return fmt.Errorf("go vet: %w", err)
	}
	fmt.Printf("Vet:\n")
	fmt.Printf("  exit=%d sandboxed=%v\n", result.ExitCode, result.Sandboxed)
	if result.ExitCode != 0 {
		return fmt.Errorf("vet failed: exit=%d stderr=%q", result.ExitCode, result.Stderr)
	}

	fmt.Println("\nAll steps completed successfully.")
	return nil
}
