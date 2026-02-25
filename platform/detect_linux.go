//go:build linux

package platform

import (
	"context"
	"errors"
	"os/exec"
)

// SandboxExecPath is the path to the macOS sandbox-exec binary.
// On Linux this variable is unused but defined so that cross-platform tests
// that reference it can compile. The tests skip on non-Darwin anyway.
var SandboxExecPath = ""

// detectPlatform returns the built-in Linux namespace platform.
// This is a lightweight implementation. For the full-featured Linux platform
// with Landlock, seccomp, and process hardening, use the platform/linux
// sub-package directly.
func detectPlatform() Platform {
	return &builtinLinuxPlatform{}
}

// builtinLinuxPlatform is a minimal linux platform returned by Detect().
// It delegates to the platform/linux package when used directly.
type builtinLinuxPlatform struct{}

func (p *builtinLinuxPlatform) Name() string { return "linux-namespace" }

func (p *builtinLinuxPlatform) Available() bool { return false }

func (p *builtinLinuxPlatform) CheckDependencies() *DependencyCheck {
	return &DependencyCheck{
		Warnings: []string{"built-in stub: use platform/linux package for full sandbox support"},
	}
}

func (p *builtinLinuxPlatform) WrapCommand(_ context.Context, _ *exec.Cmd, _ *WrapConfig) error {
	// The built-in platform stub does not implement WrapCommand.
	// Use the platform/linux sub-package for full namespace + Landlock support.
	return errors.New("linux-namespace: built-in stub does not implement WrapCommand; use platform/linux package")
}

func (p *builtinLinuxPlatform) Cleanup(_ context.Context) error {
	return nil
}

func (p *builtinLinuxPlatform) Capabilities() Capabilities {
	return Capabilities{
		FileReadDeny:   true,
		FileWriteAllow: true,
		NetworkDeny:    true,
		NetworkProxy:   true,
		PIDIsolation:   true,
		SyscallFilter:  true,
		ProcessHarden:  true,
	}
}
