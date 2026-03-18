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

// detectPlatform returns the built-in Windows WSL2 platform.
// This is a lightweight implementation. For the full-featured Windows
// platform with WSL2 distro management, use the platform/windows
// sub-package directly.
func detectPlatform() Platform {
	return &builtinWindowsPlatform{}
}

// builtinWindowsPlatform is a minimal Windows platform returned by Detect().
// It delegates to the platform/windows package when available via init() override.
type builtinWindowsPlatform struct{}

func (p *builtinWindowsPlatform) Name() string { return "windows-wsl2" }

func (p *builtinWindowsPlatform) Available() bool { return false }

func (p *builtinWindowsPlatform) CheckDependencies() *DependencyCheck {
	return &DependencyCheck{
		Warnings: []string{"built-in stub: use platform/windows package for full WSL2 sandbox support"},
	}
}

func (p *builtinWindowsPlatform) WrapCommand(_ context.Context, _ *exec.Cmd, _ *WrapConfig) error {
	return errors.New("windows-wsl2: built-in stub does not implement WrapCommand; use platform/windows package")
}

func (p *builtinWindowsPlatform) Cleanup(_ context.Context) error {
	return nil
}

func (p *builtinWindowsPlatform) Capabilities() Capabilities {
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
