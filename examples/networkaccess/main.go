// Example networkaccess demonstrates realistic network access control for AI agents.
// It configures domain-based filtering to allow package registries and documentation
// while blocking private network access.
//
// This is a common SSRF (Server-Side Request Forgery) protection pattern: allow
// known-good external services while denying access to internal infrastructure.
//
// Usage:
//
//	go run ./examples/networkaccess
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
	// Create a temp directory as the writable root for sandboxed commands.
	tmpDir, err := os.MkdirTemp("", "networkaccess-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := agentbox.DefaultConfig()

	// Configure domain-based network filtering.
	// This is a realistic setup for an AI agent that needs to:
	//   - Fetch Go documentation and modules
	//   - Access GitHub API for repository information
	//   - Install npm/Python packages
	//   - Block access to internal/private infrastructure
	cfg.Network = agentbox.NetworkConfig{
		Mode: agentbox.NetworkFiltered,
		AllowedDomains: []string{
			"*.golang.org",       // Go docs and module proxy
			"api.github.com",     // GitHub REST API
			"registry.npmjs.org", // npm package registry
			"pypi.org",           // Python package index
		},
		DeniedDomains: []string{
			"*.internal.corp",          // Internal corporate services
			"metadata.google.internal", // Cloud metadata endpoint (SSRF target)
		},
	}

	// Allow writes to the temp directory and /tmp.
	cfg.Filesystem.WritableRoots = append(cfg.Filesystem.WritableRoots, tmpDir, "/tmp")

	mgr, err := agentbox.NewManager(cfg)
	if err != nil {
		return fmt.Errorf("new manager: %w", err)
	}
	defer mgr.Cleanup(context.Background())

	ctx := context.Background()

	// --- Part 1: Show allowed domains configuration ---
	fmt.Println("=== Network Access Control Configuration ===")
	fmt.Println()
	fmt.Println("Allowed domains:")
	for _, d := range cfg.Network.AllowedDomains {
		fmt.Printf("  + %s\n", d)
	}
	fmt.Println()
	fmt.Println("Denied domains:")
	for _, d := range cfg.Network.DeniedDomains {
		fmt.Printf("  - %s\n", d)
	}
	fmt.Println()

	// --- Part 2: Demonstrate filtered mode ---
	// The sandbox is running with NetworkFiltered — only allowed domains are reachable.
	result, err := mgr.Exec(ctx, `echo "Network mode: filtered"`)
	if err != nil {
		return fmt.Errorf("exec filtered: %w", err)
	}
	fmt.Printf("Filtered mode — Exit: %d, Output: %s\n", result.ExitCode, result.Stdout)

	// --- Part 3: Per-call network overrides ---
	// Override to NetworkBlocked: no network access at all.
	result, err = mgr.Exec(ctx, `echo "Network mode: blocked (per-call override)"`,
		agentbox.WithNetwork(&agentbox.NetworkConfig{
			Mode: agentbox.NetworkBlocked,
		}),
	)
	if err != nil {
		return fmt.Errorf("exec blocked: %w", err)
	}
	fmt.Printf("Blocked mode  — Exit: %d, Output: %s\n", result.ExitCode, result.Stdout)

	// Override to NetworkAllowed: full network access.
	result, err = mgr.Exec(ctx, `echo "Network mode: allowed (per-call override)"`,
		agentbox.WithNetwork(&agentbox.NetworkConfig{
			Mode: agentbox.NetworkAllowed,
		}),
	)
	if err != nil {
		return fmt.Errorf("exec allowed: %w", err)
	}
	fmt.Printf("Allowed mode  — Exit: %d, Output: %s\n", result.ExitCode, result.Stdout)

	// --- Part 4: Summary of the three network modes ---
	fmt.Println()
	fmt.Println("=== Network Mode Summary ===")
	fmt.Println()
	fmt.Println("NetworkFiltered — Default for agents: allow known-good domains only.")
	fmt.Println("  Use case: package installs, API calls to trusted services.")
	fmt.Println()
	fmt.Println("NetworkBlocked  — For pure computation: no network access at all.")
	fmt.Println("  Use case: code formatting, linting, local builds.")
	fmt.Println()
	fmt.Println("NetworkAllowed  — For trusted operations: full network access.")
	fmt.Println("  Use case: admin tasks where the agent is fully trusted.")

	return nil
}
