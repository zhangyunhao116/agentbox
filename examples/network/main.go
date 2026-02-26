// Example network demonstrates network filtering with domain allowlists.
//
// The sandbox can filter outgoing network connections at the domain level,
// allowing only explicitly permitted domains.
//
// Usage:
//
//	go run ./examples/network
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
	cfg := agentbox.DefaultConfig()

	// Configure network filtering with specific allowed domains.
	cfg.Network = agentbox.NetworkConfig{
		Mode: agentbox.NetworkFiltered,
		AllowedDomains: []string{
			"*.golang.org",
			"proxy.golang.org",
			"github.com",
		},
		DeniedDomains: []string{
			"*.evil.com",
		},
	}

	// Allow writes to /tmp for any downloaded files.
	cfg.Filesystem.WritableRoots = append(cfg.Filesystem.WritableRoots, "/tmp")

	mgr, err := agentbox.NewManager(cfg)
	if err != nil {
		return fmt.Errorf("new manager: %w", err)
	}
	defer mgr.Cleanup(context.Background())

	ctx := context.Background()

	// This command runs inside the sandbox with network filtering active.
	// Only requests to allowed domains will succeed.
	result, err := mgr.Exec(ctx, "echo network filtering is active")
	if err != nil {
		return fmt.Errorf("exec failed: %w", err)
	}
	fmt.Printf("Exit: %d\nOutput: %s\n", result.ExitCode, result.Stdout)

	// You can also override network config per-call using WithNetwork.
	result, err = mgr.Exec(ctx, "echo per-call network override",
		agentbox.WithNetwork(&agentbox.NetworkConfig{
			Mode: agentbox.NetworkBlocked,
		}),
	)
	if err != nil {
		return fmt.Errorf("exec with blocked network failed: %w", err)
	}
	fmt.Printf("Exit: %d\nOutput: %s\n", result.ExitCode, result.Stdout)

	// Demonstrate the three network modes.
	fmt.Println()
	fmt.Println("Network modes:")
	fmt.Printf("  NetworkFiltered = %d (%s)\n", agentbox.NetworkFiltered, agentbox.NetworkFiltered)
	fmt.Printf("  NetworkBlocked  = %d (%s)\n", agentbox.NetworkBlocked, agentbox.NetworkBlocked)
	fmt.Printf("  NetworkAllowed  = %d (%s)\n", agentbox.NetworkAllowed, agentbox.NetworkAllowed)

	return nil
}
