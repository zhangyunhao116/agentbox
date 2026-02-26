// Example approval demonstrates the ApprovalCallback mechanism.
//
// When a command is classified as "Escalated" (e.g., docker build),
// the callback is invoked to ask the user for permission. This example uses a
// simple auto-approver, but in production you would prompt via stdin, a UI,
// or an API.
//
// Usage:
//
//	go run ./examples/approval
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
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()
	cfg := agentbox.DefaultConfig()

	// Set up an approval callback that auto-approves for this demo.
	// In production, you would prompt the user or call an external API.
	cfg.ApprovalCallback = func(_ context.Context, req agentbox.ApprovalRequest) (agentbox.ApprovalDecision, error) {
		fmt.Printf("Approval requested:\n")
		fmt.Printf("  command=%q\n", req.Command)
		fmt.Printf("  reason=%q\n", req.Reason)
		fmt.Printf("  -> auto-approving for demo\n")
		return agentbox.Approve, nil
	}

	mgr, err := agentbox.NewManager(cfg)
	if err != nil {
		return fmt.Errorf("new manager: %w", err)
	}
	defer mgr.Cleanup(ctx)

	// 1. Normal command — no approval needed.
	result, err := mgr.Exec(ctx, "echo hello")
	if err != nil {
		return fmt.Errorf("echo: %w", err)
	}
	fmt.Printf("Normal command:\n")
	fmt.Printf("  exit=%d stdout=%q\n", result.ExitCode, result.Stdout)

	// 2. Escalated command — triggers approval callback.
	// "docker build" is classified as Escalated by the default classifier.
	// We add a short timeout since docker may not be installed.
	tctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	result, err = mgr.Exec(tctx, "docker build --help 2>&1")
	if err != nil {
		fmt.Printf("Escalated command (approved):\n")
		fmt.Printf("  error=%v\n", err)
	} else {
		fmt.Printf("Escalated command (approved):\n")
		fmt.Printf("  exit=%d\n", result.ExitCode)
	}

	// 3. Without a callback — escalated commands are denied.
	cfg2 := agentbox.DefaultConfig()
	// No ApprovalCallback set.
	mgr2, err := agentbox.NewManager(cfg2)
	if err != nil {
		return fmt.Errorf("new manager2: %w", err)
	}
	defer mgr2.Cleanup(ctx)

	_, err = mgr2.Exec(ctx, "docker build .")
	fmt.Printf("Escalated command (no callback):\n")
	fmt.Printf("  error=%v\n", err)

	return nil
}
