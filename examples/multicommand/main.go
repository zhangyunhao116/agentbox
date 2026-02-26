// Example multicommand demonstrates running a sequence of related commands
// through a single sandbox Manager. It shows state persistence between commands,
// per-call option overrides, and efficient Manager reuse.
//
// Usage:
//
//	go run ./examples/multicommand
package main

import (
	"context"
	"fmt"
	"log"
	"os"
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
	commandCount := 0

	// Create a temporary directory as the workspace.
	workspace, err := os.MkdirTemp("", "agentbox-multicommand-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(workspace)

	// Configure the sandbox: only the workspace and /tmp are writable.
	cfg := agentbox.DefaultConfig()
	cfg.Filesystem.WritableRoots = []string{workspace, "/tmp"}

	// Create a single manager for all commands.
	mgr, err := agentbox.NewManager(cfg)
	if err != nil {
		return fmt.Errorf("new manager: %w", err)
	}
	defer mgr.Cleanup(ctx)

	// ── Part 1: Sequential commands with shared state ──────────────────

	fmt.Println("=== Part 1: Sequential commands with shared state ===")

	// Create a config file in the workspace.
	result, err := mgr.Exec(ctx, fmt.Sprintf(`echo "version=1.0.0" > %s/config.txt`, workspace))
	if err != nil {
		return fmt.Errorf("create config: %w", err)
	}
	commandCount++
	fmt.Printf("Create config.txt: exit=%d sandboxed=%v\n", result.ExitCode, result.Sandboxed)

	// Read it back — the file persists across commands.
	result, err = mgr.Exec(ctx, fmt.Sprintf("cat %s/config.txt", workspace))
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	commandCount++
	fmt.Printf("Read config.txt:   exit=%d stdout=%q\n", result.ExitCode, strings.TrimSpace(result.Stdout))

	// Append another line.
	result, err = mgr.Exec(ctx, fmt.Sprintf(`echo "debug=false" >> %s/config.txt`, workspace))
	if err != nil {
		return fmt.Errorf("append config: %w", err)
	}
	commandCount++
	fmt.Printf("Append to config:  exit=%d sandboxed=%v\n", result.ExitCode, result.Sandboxed)

	// Read again — both lines should be present.
	result, err = mgr.Exec(ctx, fmt.Sprintf("cat %s/config.txt", workspace))
	if err != nil {
		return fmt.Errorf("read config again: %w", err)
	}
	commandCount++
	lines := strings.TrimSpace(result.Stdout)
	fmt.Printf("Read config again: exit=%d lines=%d stdout=%q\n",
		result.ExitCode, len(strings.Split(lines, "\n")), lines)

	// ── Part 2: Per-call option overrides ──────────────────────────────

	fmt.Println("\n=== Part 2: Per-call option overrides ===")

	// Default timeout.
	result, err = mgr.Exec(ctx, "echo fast-command")
	if err != nil {
		return fmt.Errorf("default timeout: %w", err)
	}
	commandCount++
	fmt.Printf("Default options:   exit=%d stdout=%q\n",
		result.ExitCode, strings.TrimSpace(result.Stdout))

	// Custom short timeout via WithTimeout.
	result, err = mgr.Exec(ctx, "echo timed-command",
		agentbox.WithTimeout(2*time.Second))
	if err != nil {
		return fmt.Errorf("custom timeout: %w", err)
	}
	commandCount++
	fmt.Printf("WithTimeout(2s):   exit=%d stdout=%q\n",
		result.ExitCode, strings.TrimSpace(result.Stdout))

	// Network blocked via WithNetwork.
	result, err = mgr.Exec(ctx, "echo offline-mode",
		agentbox.WithNetwork(&agentbox.NetworkConfig{Mode: agentbox.NetworkBlocked}))
	if err != nil {
		return fmt.Errorf("network blocked: %w", err)
	}
	commandCount++
	fmt.Printf("NetworkBlocked:    exit=%d stdout=%q\n",
		result.ExitCode, strings.TrimSpace(result.Stdout))

	// ── Part 3: ExecArgs vs Exec comparison ────────────────────────────

	fmt.Println("\n=== Part 3: ExecArgs vs Exec comparison ===")

	// Shell string form.
	resultExec, err := mgr.Exec(ctx, "echo hello world")
	if err != nil {
		return fmt.Errorf("exec string: %w", err)
	}
	commandCount++
	fmt.Printf("Exec(string):      stdout=%q\n", strings.TrimSpace(resultExec.Stdout))

	// Explicit args form.
	resultArgs, err := mgr.ExecArgs(ctx, "echo", []string{"hello", "world"})
	if err != nil {
		return fmt.Errorf("exec args: %w", err)
	}
	commandCount++
	fmt.Printf("ExecArgs(args):    stdout=%q\n", strings.TrimSpace(resultArgs.Stdout))

	// Both produce the same output.
	if strings.TrimSpace(resultExec.Stdout) == strings.TrimSpace(resultArgs.Stdout) {
		fmt.Println("Both forms produce identical output ✓")
	}

	// ── Part 4: Summary ────────────────────────────────────────────────

	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("Total commands executed: %d (all through a single Manager)\n", commandCount)

	return nil
}
