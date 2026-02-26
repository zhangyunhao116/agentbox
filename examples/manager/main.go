// Example manager demonstrates the Manager lifecycle for running multiple
// commands through a single sandbox instance.
//
// Usage:
//
//	go run ./examples/manager
package main

import (
	"context"
	"fmt"
	"log"

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
	// Create a config with secure defaults.
	cfg := agentbox.DefaultConfig()

	// Allow writes to /tmp for demonstration.
	cfg.Filesystem.WritableRoots = append(cfg.Filesystem.WritableRoots, "/tmp")

	// Create a manager — reuse it for multiple commands.
	mgr, err := agentbox.NewManager(cfg)
	if err != nil {
		return fmt.Errorf("new manager: %w", err)
	}
	defer mgr.Cleanup(context.Background())

	ctx := context.Background()

	// Run several commands through the same manager.
	commands := []string{
		"echo first command",
		"echo second command",
		"ls /tmp",
	}

	for _, cmd := range commands {
		result, execErr := mgr.Exec(ctx, cmd)
		if execErr != nil {
			return fmt.Errorf("command %q failed: %w", cmd, execErr)
		}
		fmt.Printf("--- %s ---\n", cmd)
		fmt.Printf("  exit=%d sandboxed=%v\n", result.ExitCode, result.Sandboxed)
		fmt.Printf("  stdout=%s\n", result.Stdout)
	}

	// ExecArgs lets you pass the program and arguments separately.
	result, err := mgr.ExecArgs(ctx, "echo", []string{"hello", "from", "ExecArgs"})
	if err != nil {
		return fmt.Errorf("ExecArgs failed: %w", err)
	}
	fmt.Printf("--- ExecArgs ---\n")
	fmt.Printf("  exit=%d stdout=%s\n", result.ExitCode, result.Stdout)

	return nil
}
