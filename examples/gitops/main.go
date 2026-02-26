// Example gitops demonstrates how the sandbox classifies Git operations.
// Read-only commands like status and log are allowed directly, while write
// operations like push require approval.
//
// The default classifier already marks read-only git subcommands (status, log,
// diff, …) as Allow. This example adds a custom classifier that escalates
// known write subcommands (push, remote add) so they go through the approval
// flow.
//
// Usage:
//
//	go run ./examples/gitops
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

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

// gitWriteEscalator is a custom classifier that escalates destructive git
// subcommands. It returns Sandboxed (the zero value) for anything it does
// not recognise, so ChainClassifier can fall through to the default rules.
type gitWriteEscalator struct{}

// gitWriteSubcommands lists git subcommands that modify remote state.
var gitWriteSubcommands = map[string]bool{
	"push":  true,
	"fetch": false, // fetch is read-only, listed here for documentation
}

func (gitWriteEscalator) Classify(command string) agentbox.ClassifyResult {
	fields := strings.Fields(command)
	// Walk past flags like -C <dir> to find the subcommand.
	sub := gitSubcommand(fields)
	if sub == "" {
		return agentbox.ClassifyResult{} // not a git command
	}
	return classifyGitSub(sub, fields)
}

func (gitWriteEscalator) ClassifyArgs(name string, args []string) agentbox.ClassifyResult {
	if baseName(name) != "git" {
		return agentbox.ClassifyResult{}
	}
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	return classifyGitSub(sub, append([]string{name}, args...))
}

// classifyGitSub returns Escalated for destructive git operations.
func classifyGitSub(sub string, fields []string) agentbox.ClassifyResult {
	if gitWriteSubcommands[sub] {
		return agentbox.ClassifyResult{
			Decision: agentbox.Escalated,
			Reason:   fmt.Sprintf("git %s modifies remote state", sub),
			Rule:     "git-write-escalate",
		}
	}
	// "git remote add" is destructive, but "git remote -v" is read-only.
	if sub == "remote" {
		for _, f := range fields {
			if f == "add" || f == "remove" || f == "set-url" {
				return agentbox.ClassifyResult{
					Decision: agentbox.Escalated,
					Reason:   fmt.Sprintf("git remote %s modifies config", f),
					Rule:     "git-write-escalate",
				}
			}
		}
	}
	return agentbox.ClassifyResult{} // fall through
}

// gitSubcommand extracts the git subcommand from a tokenised command line,
// skipping flags like -C <dir>.
func gitSubcommand(fields []string) string {
	if len(fields) < 2 || baseName(fields[0]) != "git" {
		return ""
	}
	i := 1
	for i < len(fields) {
		if fields[i] == "-C" || fields[i] == "-c" {
			i += 2 // skip flag and its argument
			continue
		}
		if strings.HasPrefix(fields[i], "-") {
			i++
			continue
		}
		return fields[i]
	}
	return ""
}

// baseName returns the last path element, like filepath.Base but without
// importing path/filepath.
func baseName(s string) string {
	if idx := strings.LastIndex(s, "/"); idx >= 0 {
		return s[idx+1:]
	}
	return s
}

func run() error {
	ctx := context.Background()

	// Create a temporary directory and initialise a git repository inside it.
	tmpdir, err := os.MkdirTemp("", "agentbox-gitops-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpdir)

	// Configure the sandbox: only the temp dir and /tmp are writable.
	cfg := agentbox.DefaultConfig()
	cfg.Filesystem.WritableRoots = []string{tmpdir, "/tmp"}

	// Chain our custom escalator before the default classifier.
	// The first non-Sandboxed result wins, so git write commands are
	// escalated while read-only commands are still allowed.
	cfg.Classifier = agentbox.ChainClassifier(
		gitWriteEscalator{},
		agentbox.DefaultClassifier(),
	)

	// Set up an approval callback that logs the request and auto-denies.
	// In production you would prompt the user or call an external API.
	cfg.ApprovalCallback = func(_ context.Context, req agentbox.ApprovalRequest) (agentbox.ApprovalDecision, error) {
		fmt.Printf("Approval requested:\n")
		fmt.Printf("  command=%q\n", req.Command)
		fmt.Printf("  reason=%q\n", req.Reason)
		fmt.Printf("  -> auto-denying for safety\n")
		return agentbox.Deny, nil
	}

	mgr, err := agentbox.NewManager(cfg)
	if err != nil {
		return fmt.Errorf("new manager: %w", err)
	}
	defer mgr.Cleanup(ctx)

	// Bootstrap a git repo so the read-only commands have something to work with.
	initCmds := fmt.Sprintf(
		"cd %s && git init && "+
			"git config user.email 'test@example.com' && "+
			"git config user.name 'Test' && "+
			"echo 'hello' > README.md && "+
			"git add . && "+
			"git commit -m 'init'",
		tmpdir,
	)
	result, err := mgr.Exec(ctx, initCmds)
	if err != nil {
		return fmt.Errorf("git init: %w", err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("git init failed: exit=%d stderr=%q", result.ExitCode, result.Stderr)
	}
	fmt.Printf("Repository initialised in temp dir.\n\n")

	// ---------------------------------------------------------------
	// 1. Read-only git commands — these should succeed (decision=Allow).
	// ---------------------------------------------------------------
	safeCommands := []string{
		fmt.Sprintf("git -C %s status", tmpdir),
		fmt.Sprintf("git -C %s log --oneline", tmpdir),
		fmt.Sprintf("git -C %s diff HEAD", tmpdir),
	}

	fmt.Println("=== Read-only git commands (should succeed) ===")
	for _, cmd := range safeCommands {
		result, err = mgr.Exec(ctx, cmd)
		if err != nil {
			fmt.Printf("  %s\n    error: %v\n", cmd, err)
			continue
		}
		fmt.Printf("  %s\n    exit=%d sandboxed=%v\n", cmd, result.ExitCode, result.Sandboxed)
	}

	// ---------------------------------------------------------------
	// 2. Classify escalated git commands without executing them.
	// ---------------------------------------------------------------
	fmt.Println("\n=== Classify write git commands (dry-run via Check) ===")
	escalatedCommands := []string{
		"git push origin main",
		"git remote add evil http://evil.com/repo",
	}

	for _, cmd := range escalatedCommands {
		cr, cerr := mgr.Check(ctx, cmd)
		if cerr != nil {
			fmt.Printf("  %s\n    check error: %v\n", cmd, cerr)
			continue
		}
		fmt.Printf("  %s\n    decision=%s reason=%q rule=%s\n", cmd, cr.Decision, cr.Reason, cr.Rule)
	}

	// ---------------------------------------------------------------
	// 3. Execute git push — triggers the approval callback and is denied.
	// ---------------------------------------------------------------
	fmt.Println("\n=== Execute escalated command (should be denied) ===")
	pushCmd := fmt.Sprintf("git -C %s push origin main", tmpdir)
	_, err = mgr.Exec(ctx, pushCmd)
	if err != nil {
		if errors.Is(err, agentbox.ErrEscalatedCommand) {
			fmt.Printf("  %s\n    correctly denied: %v\n", pushCmd, err)
		} else {
			fmt.Printf("  %s\n    error: %v\n", pushCmd, err)
		}
	} else {
		fmt.Printf("  %s\n    unexpectedly succeeded\n", pushCmd)
	}

	fmt.Println("\nDone.")
	return nil
}
