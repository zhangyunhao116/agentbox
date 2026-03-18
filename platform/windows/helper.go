//go:build windows

package windows

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// helperPath is the absolute path to the sandbox helper binary inside the
// WSL2 distro. Matches the install target in installHelper.
const helperPath = "/opt/agentbox/helper"

// helperInstalled checks if the sandbox helper binary exists and is
// executable inside the WSL2 distro.
func (p *Platform) helperInstalled() bool {
	if p.wslPath == "" || !p.distroExists() {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := wslCommandContext(ctx, p.wslPath, "-d", p.distroName, "--", "test", "-x", helperPath)
	return cmd.Run() == nil
}

// installHelper copies the pre-built Linux helper binary from a local
// Windows path into the WSL2 distro at helperPath. The binary must have
// been cross-compiled for GOOS=linux before calling this function.
func (p *Platform) installHelper(ctx context.Context, localBinaryPath string) error {
	// Create the target directory inside the distro.
	mkdirCmd := wslCommandContext(ctx, p.wslPath,
		"-d", p.distroName, "-u", "root", "--",
		"mkdir", "-p", "/opt/agentbox")
	if out, err := mkdirCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("creating helper directory: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Translate the Windows path to a WSL-accessible path.
	wslSrc, err := ToWSL(localBinaryPath)
	if err != nil {
		return fmt.Errorf("translating helper path: %w", err)
	}

	// Copy the binary and set executable permissions.
	// shellQuote wslSrc to prevent injection — it may contain spaces.
	installScript := fmt.Sprintf("cp %s %s && chmod 755 %s", shellQuote(wslSrc), helperPath, helperPath)
	installCmd := wslCommandContext(ctx, p.wslPath,
		"-d", p.distroName, "-u", "root", "--",
		"sh", "-c", installScript)
	if out, err := installCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("installing helper: %s: %w", strings.TrimSpace(string(out)), err)
	}

	return nil
}
