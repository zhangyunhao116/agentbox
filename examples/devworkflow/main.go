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
	"path/filepath"
	"strings"

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

// shellQuote wraps s in single quotes, escaping any embedded single quotes.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func run() error {
	ctx := context.Background()

	// Create a temporary directory as the writable root for the project.
	workdir, err := os.MkdirTemp("", "agentbox-devworkflow-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(workdir)

	// Create a Go cache directory inside the writable workdir so that
	// sandboxed go commands can write build-cache artifacts without
	// needing access to the user's home directory.
	gocache := filepath.Join(workdir, ".cache")
	if err := os.MkdirAll(gocache, 0o755); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}

	// Configure the sandbox: only the temp dir and /tmp are writable.
	cfg := agentbox.DefaultConfig()
	cfg.Filesystem.WritableRoots = []string{workdir, "/tmp"}

	mgr, err := agentbox.NewManager(cfg)
	if err != nil {
		return fmt.Errorf("new manager: %w", err)
	}
	defer mgr.Cleanup(ctx)

	// Prefix for sandboxed commands that invoke the Go toolchain,
	// ensuring GOCACHE points inside the writable workdir.
	envPrefix := fmt.Sprintf("export GOCACHE=%s && ", shellQuote(gocache))

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
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go run: %v\nstderr: %s", err, stderr.String())
	}
	got := strings.TrimSpace(stdout.String())
	if got != "built inside sandbox" {
		t.Fatalf("unexpected output: %q", got)
	}
}
`

	scaffoldCmd := fmt.Sprintf(
		"cat > %s << 'GOMOD'\n%sGOMOD\n"+
			"cat > %s << 'GOMAIN'\n%sGOMAIN\n"+
			"cat > %s << 'GOTEST'\n%sGOTEST",
		shellQuote(filepath.Join(workdir, "go.mod")), goMod,
		shellQuote(filepath.Join(workdir, "main.go")), goMain,
		shellQuote(filepath.Join(workdir, "main_test.go")), goTest,
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
	result, err = mgr.Exec(ctx, envPrefix+fmt.Sprintf("cd %s && go build ./...", shellQuote(workdir)))
	if err != nil {
		return fmt.Errorf("go build: %w", err)
	}
	fmt.Printf("Build:\n")
	fmt.Printf("  exit=%d sandboxed=%v\n", result.ExitCode, result.Sandboxed)
	if result.ExitCode != 0 {
		return fmt.Errorf("build failed: exit=%d stderr=%q", result.ExitCode, result.Stderr)
	}

	// Step 3: Run tests.
	result, err = mgr.Exec(ctx, envPrefix+fmt.Sprintf("cd %s && go test ./...", shellQuote(workdir)))
	if err != nil {
		return fmt.Errorf("go test: %w", err)
	}
	fmt.Printf("Test:\n")
	fmt.Printf("  exit=%d sandboxed=%v stdout=%q\n", result.ExitCode, result.Sandboxed, result.Stdout)
	if result.ExitCode != 0 {
		return fmt.Errorf("test failed: exit=%d stderr=%q", result.ExitCode, result.Stderr)
	}

	// Step 4: Run vet.
	result, err = mgr.Exec(ctx, envPrefix+fmt.Sprintf("cd %s && go vet ./...", shellQuote(workdir)))
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
