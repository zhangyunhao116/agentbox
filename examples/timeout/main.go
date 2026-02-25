// Example timeout demonstrates how to use context deadlines and the
// WithTimeout option to limit command execution time.
//
// Usage:
//
//	go run ./examples/timeout
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/zhangyunhao116/agentbox"
)

func main() {
	if agentbox.MaybeSandboxInit() {
		return
	}

	cfg := agentbox.DefaultConfig()
	mgr, err := agentbox.NewManager(cfg)
	if err != nil {
		log.Fatalf("new manager: %v", err)
	}
	defer mgr.Cleanup(context.Background())

	// 1. Normal command completes within timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := mgr.Exec(ctx, "echo fast command")
	if err != nil {
		log.Printf("fast command: %v", err)
		return
	}
	fmt.Printf("Fast command:\n")
	fmt.Printf("  exit=%d stdout=%q duration=%v\n", result.ExitCode, result.Stdout, result.Duration.Truncate(time.Millisecond))

	// 2. Slow command gets killed by context timeout.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel2()

	result, err = mgr.Exec(ctx2, "sleep 30")
	if err != nil {
		// Context cancellation may surface as an error.
		fmt.Printf("Slow command (context timeout):\n")
		fmt.Printf("  error=%v\n", err)
	} else {
		fmt.Printf("Slow command (context timeout):\n")
		fmt.Printf("  exit=%d (non-zero means killed)\n", result.ExitCode)
	}

	// 3. Per-call WithTimeout option.
	result, err = mgr.Exec(context.Background(), "sleep 30",
		agentbox.WithTimeout(500*time.Millisecond),
	)
	if err != nil {
		fmt.Printf("WithTimeout option:\n")
		fmt.Printf("  error=%v\n", err)
	} else {
		fmt.Printf("WithTimeout option:\n")
		fmt.Printf("  exit=%d (non-zero means killed)\n", result.ExitCode)
	}
}
