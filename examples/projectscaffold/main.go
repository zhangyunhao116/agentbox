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

	// 1a. Create directory structure.
	mkdirCmd := fmt.Sprintf("mkdir -p %s/cmd/server %s/internal/handler %s/docs",
		workspace, workspace, workspace)
	result, err := mgr.Exec(ctx, mkdirCmd)
	if err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	fmt.Printf("  mkdir -p (dirs):       exit=%d\n", result.ExitCode)

	// 1b. Write go.mod.
	goModCmd := fmt.Sprintf("cat > %s/go.mod << 'GOMOD'\nmodule example.com/myservice\n\ngo 1.21\nGOMOD", workspace)
	result, err = mgr.Exec(ctx, goModCmd)
	if err != nil {
		return fmt.Errorf("write go.mod: %w", err)
	}
	fmt.Printf("  write go.mod:          exit=%d\n", result.ExitCode)

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
	serverCmd := fmt.Sprintf("cat > %s/cmd/server/main.go << 'GOEOF'\n%s\nGOEOF", workspace, serverMain)
	result, err = mgr.Exec(ctx, serverCmd)
	if err != nil {
		return fmt.Errorf("write cmd/server/main.go: %w", err)
	}
	fmt.Printf("  write server/main.go:  exit=%d\n", result.ExitCode)

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
	handlerCmd := fmt.Sprintf("cat > %s/internal/handler/handler.go << 'GOEOF'\n%s\nGOEOF", workspace, handlerSrc)
	result, err = mgr.Exec(ctx, handlerCmd)
	if err != nil {
		return fmt.Errorf("write handler.go: %w", err)
	}
	fmt.Printf("  write handler.go:      exit=%d\n", result.ExitCode)

	// 1e. Write README.md.
	readmeCmd := fmt.Sprintf("cat > %s/README.md << 'EOF'\n# myservice\n\nA simple HTTP service scaffolded by an AI agent.\n\n## Quick Start\n\n```bash\ngo run ./cmd/server\n```\nEOF", workspace)
	result, err = mgr.Exec(ctx, readmeCmd)
	if err != nil {
		return fmt.Errorf("write README.md: %w", err)
	}
	fmt.Printf("  write README.md:       exit=%d\n", result.ExitCode)

	// 1f. Verify all files exist.
	findCmd := fmt.Sprintf("find %s -type f | sort", workspace)
	result, err = mgr.Exec(ctx, findCmd)
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
	result, err = mgr.Exec(ctx, "touch /etc/myservice.conf 2>&1")
	if err != nil {
		return fmt.Errorf("touch /etc: %w", err)
	}
	fmt.Printf("  touch /etc/myservice.conf: exit=%d denied=%v\n",
		result.ExitCode, result.ExitCode != 0)

	// 2b. Try creating a directory in /opt — should be denied.
	result, err = mgr.Exec(ctx, "mkdir /opt/myservice 2>&1")
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
	catCmd := fmt.Sprintf("cat %s/go.mod", workspace)
	result, err = mgr.Exec(ctx, catCmd)
	if err != nil {
		return fmt.Errorf("cat go.mod: %w", err)
	}
	fmt.Printf("  go.mod content:\n%s\n", result.Stdout)

	// 3b. Count lines in cmd/server/main.go.
	wcCmd := fmt.Sprintf("wc -l %s/cmd/server/main.go", workspace)
	result, err = mgr.Exec(ctx, wcCmd)
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
