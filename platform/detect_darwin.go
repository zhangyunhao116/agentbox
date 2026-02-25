//go:build darwin

package platform

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// SandboxExecPath is the path to the macOS sandbox-exec binary.
// This is a var (not const) so tests can temporarily override it to simulate
// a missing sandbox-exec binary.
var SandboxExecPath = "/usr/bin/sandbox-exec"

// detectPlatform returns the macOS Seatbelt platform.
// This is a lightweight built-in implementation. For the full-featured
// Seatbelt platform with SBPL profile generation, use the platform/darwin
// sub-package directly.
func detectPlatform() Platform {
	return &builtinDarwinPlatform{}
}

// builtinDarwinPlatform is a minimal darwin platform returned by Detect().
// It delegates to the platform/darwin package when available via Register().
type builtinDarwinPlatform struct{}

func (p *builtinDarwinPlatform) Name() string { return "darwin-seatbelt" }

func (p *builtinDarwinPlatform) Available() bool {
	_, err := os.Stat(SandboxExecPath)
	return err == nil
}

func (p *builtinDarwinPlatform) CheckDependencies() *DependencyCheck {
	check := &DependencyCheck{}
	if _, err := os.Stat(SandboxExecPath); err != nil {
		check.Errors = append(check.Errors, fmt.Sprintf("sandbox-exec not found at %s: %v", SandboxExecPath, err))
	}
	return check
}

func (p *builtinDarwinPlatform) WrapCommand(_ context.Context, _ *exec.Cmd, _ *WrapConfig) error {
	// The built-in platform stub does not implement WrapCommand.
	// Use the platform/darwin sub-package for full SBPL profile support.
	return errors.New("darwin-seatbelt: built-in stub does not implement WrapCommand; use platform/darwin package")
}

func (p *builtinDarwinPlatform) Cleanup(_ context.Context) error {
	return nil
}

func (p *builtinDarwinPlatform) Capabilities() Capabilities {
	return Capabilities{
		FileReadDeny:   true,
		FileWriteAllow: true,
		NetworkDeny:    true,
		NetworkProxy:   true,
		ProcessHarden:  true,
	}
}
