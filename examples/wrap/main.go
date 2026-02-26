// Example wrap demonstrates the Wrap mode, which modifies an existing
// *exec.Cmd in-place to run inside the sandbox.
//
// This is useful when you need full control over the command lifecycle
// (e.g., piping stdin, streaming stdout, or attaching to a PTY).
//
// Usage:
//
//	go run ./examples/wrap
package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"

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

	// Build a regular exec.Cmd.
	cmd := exec.CommandContext(ctx, "echo", "wrapped command output")

	// Wrap modifies cmd in-place and returns a cleanup function.
	// The cleanup function MUST be called after the command finishes.
	cleanup, err := agentbox.Wrap(ctx, cmd)
	if err != nil {
		return fmt.Errorf("wrap failed: %w", err)
	}
	defer cleanup()

	// Run the command as usual — it now executes inside the sandbox.
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command failed: %w", err)
	}

	fmt.Printf("Output: %s\n", output)

	// You can also use Wrap with a Manager for more control:
	cfg := agentbox.DefaultConfig()

	mgr, err := agentbox.NewManager(cfg)
	if err != nil {
		return fmt.Errorf("new manager: %w", err)
	}
	defer mgr.Cleanup(ctx)

	cmd2 := exec.CommandContext(ctx, "echo", "manager-wrapped output")
	if err := mgr.Wrap(ctx, cmd2); err != nil {
		return fmt.Errorf("manager wrap failed: %w", err)
	}

	output2, err := cmd2.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command2 failed: %w", err)
	}
	fmt.Printf("Output: %s\n", output2)

	return nil
}
