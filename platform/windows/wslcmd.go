//go:build windows

package windows

import (
	"context"
	"os"
	"os/exec"
)

// wslCommand creates an exec.Cmd for a WSL command with WSL_UTF8=1 set in the
// environment. This ensures WSL outputs UTF-8 where supported, reducing the
// need for UTF-16LE decoding. Not all WSL versions honor WSL_UTF8, so callers
// should still use cleanWSLOutput on command output.
func wslCommand(path string, args ...string) *exec.Cmd {
	cmd := exec.Command(path, args...) //nolint:gosec // path is from findWSLExe
	cmd.Env = append(os.Environ(), "WSL_UTF8=1")
	return cmd
}

// wslCommandContext is like wslCommand but accepts a context for cancellation.
func wslCommandContext(ctx context.Context, path string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, path, args...) //nolint:gosec // path is from findWSLExe
	cmd.Env = append(os.Environ(), "WSL_UTF8=1")
	return cmd
}
