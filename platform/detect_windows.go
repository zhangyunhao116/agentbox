//go:build windows

package platform

import (
	"context"
	"errors"
	"os/exec"
)

// SandboxExecPath is defined for cross-platform test compatibility.
// On Windows it is unused.
var SandboxExecPath = ""

// detectPlatform returns the built-in Windows native sandbox platform.
// This is a lightweight stub implementation. The actual implementation is
// registered via init() in platform_windows.go at the root package level,
// which imports the platform/windows sub-package.
func detectPlatform() Platform {
	return &builtinWindowsPlatform{}
}

// builtinWindowsPlatform is a minimal Windows platform returned by Detect().
// It delegates to the platform/windows package when available via init() override.
type builtinWindowsPlatform struct{}

func (p *builtinWindowsPlatform) Name() string { return "windows-native" }

func (p *builtinWindowsPlatform) Available() bool { return false }

func (p *builtinWindowsPlatform) CheckDependencies() *DependencyCheck {
	return &DependencyCheck{
		Warnings: []string{"built-in stub: use platform/windows package for full native sandbox support"},
	}
}

func (p *builtinWindowsPlatform) WrapCommand(_ context.Context, _ *exec.Cmd, _ *WrapConfig) error {
	return errors.New("windows-native: built-in stub does not implement WrapCommand; use platform/windows package")
}

func (p *builtinWindowsPlatform) Cleanup(_ context.Context) error {
	return nil
}

func (p *builtinWindowsPlatform) Capabilities() Capabilities {
	return Capabilities{
		FileReadDeny:   false, // Low IL prevents write-up but not read
		FileWriteAllow: true,  // Restricted token + Low IL + ACLs
		NetworkDeny:    false, // No network isolation without Firewall rules
		NetworkProxy:   false, // No proxy support
		PIDIsolation:   false, // No PID namespaces on Windows
		SyscallFilter:  false, // No seccomp equivalent
		ProcessHarden:  true,  // Restricted token + Low IL + Job Object
	}
}
