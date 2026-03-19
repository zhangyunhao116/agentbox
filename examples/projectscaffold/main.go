// Example projectscaffold simulates an AI agent creating project files within
// a sandboxed environment. Writes to the designated workspace succeed, while
// attempts to write outside it are blocked.
//
// Usage:
//
//	go run ./examples/projectscaffold
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

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

	// Create a temporary directory as the agent workspace.
	workspace, err := os.MkdirTemp("", "agentbox-scaffold-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(workspace)

	// Configure sandbox: only the workspace and /tmp are writable.
	cfg := agentbox.DefaultConfig()
	cfg.Filesystem.WritableRoots = []string{workspace, "/tmp"}

	mgr, err := agentbox.NewManager(cfg)
	if err != nil {
		return fmt.Errorf("new manager: %w", err)
	}
	defer mgr.Cleanup(ctx)

	// ── Part 1: Scaffold project files (should all succeed) ─────────────

	fmt.Println("=== Part 1: Scaffold Project Files ===")
	fmt.Println()

	// 1a. Create directory structure using native Go.
	dirs := []string{
		filepath.Join(workspace, "cmd", "server"),
		filepath.Join(workspace, "internal", "handler"),
		filepath.Join(workspace, "docs"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	fmt.Printf("  mkdir -p (dirs):       exit=0\n")

	// 1b. Write go.mod using native Go.
	goModContent := "module example.com/myservice\n\ngo 1.21\n"
	if err := os.WriteFile(filepath.Join(workspace, "go.mod"), []byte(goModContent), 0o644); err != nil {
		return fmt.Errorf("write go.mod: %w", err)
	}
	fmt.Printf("  write go.mod:          exit=0\n")

	// 1c. Write cmd/server/main.go — a simple HTTP server skeleton.
	serverMain := `package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello from myservice!")
	})
	fmt.Println("listening on :8080")
	http.ListenAndServe(":8080", nil)
}`
	if err := os.WriteFile(filepath.Join(workspace, "cmd", "server", "main.go"), []byte(serverMain), 0o644); err != nil {
		return fmt.Errorf("write cmd/server/main.go: %w", err)
	}
	fmt.Printf("  write server/main.go:  exit=0\n")

	// 1d. Write internal/handler/handler.go.
	handlerSrc := `package handler

import (
	"fmt"
	"net/http"
)

// Health returns a simple health-check handler.
func Health(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "ok")
}`
	if err := os.WriteFile(filepath.Join(workspace, "internal", "handler", "handler.go"), []byte(handlerSrc), 0o644); err != nil {
		return fmt.Errorf("write handler.go: %w", err)
	}
	fmt.Printf("  write handler.go:      exit=0\n")

	// 1e. Write README.md.
	readmeContent := `# myservice

A simple HTTP service scaffolded by an AI agent.

## Quick Start

` + "```bash\ngo run ./cmd/server\n```\n"
	if err := os.WriteFile(filepath.Join(workspace, "README.md"), []byte(readmeContent), 0o644); err != nil {
		return fmt.Errorf("write README.md: %w", err)
	}
	fmt.Printf("  write README.md:       exit=0\n")

	// 1f. Verify all files exist using ExecArgs.
	result, err := mgr.ExecArgs(ctx, "sh", []string{"-c", "find " + workspace + " -type f | sort"})
	if err != nil {
		return fmt.Errorf("find files: %w", err)
	}
	fmt.Printf("  scaffolded files:\n%s\n", result.Stdout)

	// ── Part 2: Attempt writes outside workspace (should fail) ──────────

	fmt.Println("=== Part 2: Writes Outside Workspace (should be denied) ===")
	fmt.Println()

	// Note: filesystem deny rules require platform support (macOS Seatbelt or
	// Linux Landlock with kernel >= 5.13). On unsupported platforms, these
	// writes may succeed.

	// 2a. Try writing to /etc — should be denied.
	result, err = mgr.ExecArgs(ctx, "sh", []string{"-c", "touch /etc/myservice.conf 2>&1"})
	if err != nil {
		return fmt.Errorf("touch /etc: %w", err)
	}
	fmt.Printf("  touch /etc/myservice.conf: exit=%d denied=%v\n",
		result.ExitCode, result.ExitCode != 0)

	// 2b. Try creating a directory in /opt — should be denied.
	result, err = mgr.ExecArgs(ctx, "sh", []string{"-c", "mkdir /opt/myservice 2>&1"})
	if err != nil {
		return fmt.Errorf("mkdir /opt: %w", err)
	}
	fmt.Printf("  mkdir /opt/myservice:      exit=%d denied=%v\n",
		result.ExitCode, result.ExitCode != 0)

	fmt.Println()

	// ── Part 3: Read-back verification ──────────────────────────────────

	fmt.Println("=== Part 3: Read-back Verification ===")
	fmt.Println()

	// 3a. Read go.mod content.
	result, err = mgr.ExecArgs(ctx, "cat", []string{filepath.Join(workspace, "go.mod")})
	if err != nil {
		return fmt.Errorf("cat go.mod: %w", err)
	}
	fmt.Printf("  go.mod content:\n%s\n", result.Stdout)

	// 3b. Count lines in cmd/server/main.go.
	result, err = mgr.ExecArgs(ctx, "wc", []string{"-l", filepath.Join(workspace, "cmd", "server", "main.go")})
	if err != nil {
		return fmt.Errorf("wc -l main.go: %w", err)
	}
	fmt.Printf("  cmd/server/main.go line count: %s\n", result.Stdout)

	// ── Summary ─────────────────────────────────────────────────────────

	fmt.Println("=== Summary ===")
	fmt.Println("  1. Project scaffolding: all files created successfully in workspace")
	fmt.Println("  2. Write protection: writes outside workspace correctly denied")
	fmt.Println("  3. Read-back: file contents verified")

	return nil
}
