// Package agentbox provides process-level sandbox isolation for AI Agents.
//
// It enables secure command execution by wrapping processes with
// platform-specific sandboxing mechanisms (macOS Seatbelt/SBPL,
// Linux Namespaces + Landlock, Windows Restricted Token + Job Object +
// Low Integrity Level) while providing a unified API.
//
// Key features:
//   - Filesystem isolation with configurable writable roots
//   - Network filtering with domain-level allow/deny lists
//   - Command classification with 44 built-in rules (allow, sandbox, escalate, forbid)
//   - Custom classification rules with glob patterns
//   - Rule override by name with type-safe constants
//   - Protected path detection for sensitive directories
//   - Approval caching for user decisions
//   - Resource limits (processes, memory, file descriptors, CPU)
//   - JSON-serializable configuration and results
//   - Minimal external dependencies, no CGo
//
// Classification follows a fixed precedence: custom rules → protected paths →
// rule overrides → built-in rules. The first non-Sandboxed result wins.
//
// Basic usage:
//
//	cfg := agentbox.DefaultConfig()
//	mgr, err := agentbox.NewManager(cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer mgr.Close()
//
//	result, err := mgr.Exec(ctx, "ls -la /tmp")
package agentbox
