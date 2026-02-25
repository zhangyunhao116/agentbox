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

	// Create a config with secure defaults.
	cfg := agentbox.DefaultConfig()

	// Allow writes to /tmp for demonstration.
	cfg.Filesystem.WritableRoots = append(cfg.Filesystem.WritableRoots, "/tmp")

	// Create a manager — reuse it for multiple commands.
	mgr, err := agentbox.NewManager(cfg)
	if err != nil {
		log.Fatalf("new manager: %v", err)
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
		result, err := mgr.Exec(ctx, cmd)
		if err != nil {
			log.Printf("command %q failed: %v", cmd, err)
			continue
		}
		fmt.Printf("--- %s ---\n", cmd)
		fmt.Printf("  exit=%d sandboxed=%v\n", result.ExitCode, result.Sandboxed)
		fmt.Printf("  stdout=%s\n", result.Stdout)
	}

	// ExecArgs lets you pass the program and arguments separately.
	result, err := mgr.ExecArgs(ctx, "echo", []string{"hello", "from", "ExecArgs"})
	if err != nil {
		log.Printf("ExecArgs failed: %v", err)
	} else {
		fmt.Printf("--- ExecArgs ---\n")
		fmt.Printf("  exit=%d stdout=%s\n", result.ExitCode, result.Stdout)
	}
}
