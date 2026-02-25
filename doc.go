// Package agentbox provides process-level sandbox isolation for AI Agents.
//
// It enables secure command execution by wrapping processes with
// platform-specific sandboxing mechanisms (macOS Seatbelt/SBPL,
// Linux Namespaces + Landlock) while providing a unified API.
//
// Key features:
//   - Filesystem isolation with configurable writable roots
//   - Network filtering with domain-level allow/deny lists
//   - Command classification (allow, sandbox, escalate, forbid)
//   - Resource limits (processes, memory, file descriptors, CPU)
//   - Minimal external dependencies, no CGo
//
// Basic usage:
//
//	cfg := agentbox.DefaultConfig()
//	mgr, err := agentbox.NewManager(cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer mgr.Cleanup(context.Background())
//
//	result, err := mgr.Exec(ctx, "ls -la /tmp")
package agentbox
