// Example filesystem demonstrates sandbox filesystem isolation.
//
// It shows that a sandboxed process can write to writable roots but is
// denied access to other paths. This is the core value proposition of
// agentbox: untrusted commands cannot escape their designated directories.
//
// Note: filesystem deny rules require platform support (macOS Seatbelt or
// Linux Landlock with kernel >= 5.13). On older Linux kernels without
// Landlock, writes outside writable roots may not be blocked.
//
// Usage:
//
//	go run ./examples/filesystem
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/zhangyunhao116/agentbox"
)

func main() {
	if agentbox.MaybeSandboxInit() {
		return
	}

	ctx := context.Background()

	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("get home dir: %v", err)
	}

	// Create a temporary directory as the writable root.
	workdir, err := os.MkdirTemp("", "agentbox-fs-example-*")
	if err != nil {
		log.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(workdir)

	cfg := agentbox.DefaultConfig()
	cfg.Filesystem.WritableRoots = []string{workdir}

	mgr, err := agentbox.NewManager(cfg)
	if err != nil {
		log.Printf("new manager: %v", err)
		return
	}
	defer mgr.Cleanup(ctx)

	// 1. Write to writable root — should succeed.
	target := filepath.Join(workdir, "hello.txt")
	result, err := mgr.Exec(ctx, fmt.Sprintf("echo sandbox-was-here > %s && cat %s", target, target))
	if err != nil {
		log.Printf("write to writable root: %v", err)
		return
	}
	fmt.Printf("Write to writable root:\n")
	fmt.Printf("  exit=%d stdout=%q\n", result.ExitCode, result.Stdout)

	// 2. Write outside writable root — should be denied by the sandbox.
	// /etc is in DenyWrite by default on both macOS and Linux.
	result, err = mgr.Exec(ctx, "touch /etc/agentbox-escape-attempt 2>&1")
	if err != nil {
		log.Printf("write outside root: %v", err)
		return
	}
	fmt.Printf("Write to /etc:\n")
	fmt.Printf("  exit=%d denied=%v\n", result.ExitCode, result.ExitCode != 0)

	// 3. Read a sensitive path — should be denied.
	// ~/.ssh is in DenyRead by default. We use the absolute path so it
	// works correctly inside Linux namespaces where ~ may differ.
	sshDir := filepath.Join(home, ".ssh")
	result, err = mgr.Exec(ctx, fmt.Sprintf("ls %s 2>&1", sshDir))
	if err != nil {
		log.Printf("read sensitive path: %v", err)
		return
	}
	fmt.Printf("Read %s:\n", sshDir)
	fmt.Printf("  exit=%d denied=%v\n", result.ExitCode, result.ExitCode != 0)
}
