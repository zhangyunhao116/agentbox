// Example minimal demonstrates the simplest way to run a sandboxed command.
//
// It uses the package-level Exec convenience function with DefaultConfig.
//
// Usage:
//
//	go run ./examples/minimal
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/zhangyunhao116/agentbox"
)

func main() {
	// MaybeSandboxInit is required on Linux for namespace re-exec.
	// On macOS it is a no-op.
	if agentbox.MaybeSandboxInit() {
		return
	}

	ctx := context.Background()

	// Exec creates a temporary manager with DefaultConfig, runs the command,
	// and cleans up automatically.
	result, err := agentbox.Exec(ctx, "echo hello from sandbox")
	if err != nil {
		log.Fatalf("exec failed: %v", err)
	}

	fmt.Printf("Exit code:  %d\n", result.ExitCode)
	fmt.Printf("Stdout:     %s", result.Stdout)
	fmt.Printf("Stderr:     %s", result.Stderr)
	fmt.Printf("Sandboxed:  %v\n", result.Sandboxed)
	fmt.Printf("Duration:   %v\n", result.Duration)
}
