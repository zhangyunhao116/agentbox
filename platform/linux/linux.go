//go:build linux

package linux

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/zhangyunhao116/agentbox/platform"
)

// Platform implements the platform.Platform interface using Linux namespaces,
// Landlock filesystem restrictions, and seccomp BPF filters.
type Platform struct {
	kernelVersion KernelVersion
	landlockABI   int
}

// New creates a new Platform, detecting kernel version and Landlock
// support at construction time.
func New() *Platform {
	// DetectKernelVersion may fail in restricted environments (e.g., /proc not
	// mounted). A zero KernelVersion safely disables version-gated features.
	kv, _ := DetectKernelVersion()
	ll := DetectLandlock()
	return &Platform{
		kernelVersion: kv,
		landlockABI:   ll.ABIVersion,
	}
}

// Name returns the platform identifier.
func (l *Platform) Name() string {
	return "linux-namespace"
}

// Available reports whether this platform is functional. On Linux, the
// namespace-based sandbox is always available (user namespaces are required).
func (l *Platform) Available() bool {
	return true
}

// CheckDependencies inspects the system for required and optional sandbox
// dependencies.
func (l *Platform) CheckDependencies() *platform.DependencyCheck {
	check := &platform.DependencyCheck{}

	// Require kernel >= 5.13 for Landlock ABI v1.
	if !l.kernelVersion.AtLeast(5, 13) {
		check.Warnings = append(check.Warnings,
			fmt.Sprintf("kernel %s < 5.13: Landlock filesystem restrictions unavailable", l.kernelVersion))
	}

	// Check Landlock support.
	ll := DetectLandlock()
	if !ll.Supported {
		check.Warnings = append(check.Warnings,
			"Landlock not supported: filesystem restrictions will be limited")
	}

	return check
}

// Capabilities returns the set of isolation features supported by the Linux
// namespace + Landlock platform.
func (l *Platform) Capabilities() platform.Capabilities {
	return platform.Capabilities{
		FileReadDeny:   l.landlockABI >= 1,
		FileWriteAllow: l.landlockABI >= 1,
		NetworkDeny:    true, // via CLONE_NEWNET
		NetworkProxy:   true, // via network namespace + proxy bridge
		PIDIsolation:   true, // via CLONE_NEWPID
		SyscallFilter:  true, // via seccomp BPF
		ProcessHarden:  true, // via prctl
	}
}

// WrapCommand modifies cmd in-place to execute within the Linux namespace
// sandbox. It configures namespace isolation, UID/GID mappings, and resource
// limits on the command's SysProcAttr.
func (l *Platform) WrapCommand(_ context.Context, cmd *exec.Cmd, cfg *platform.WrapConfig) error {
	if cfg == nil {
		cfg = &platform.WrapConfig{}
	}

	// Configure namespace isolation (user, mount, PID, and optionally network).
	configureNamespaces(cmd, cfg)

	// NOTE: Resource limits are applied in the re-exec child process
	// (sandboxInit in reexec.go) rather than here, to avoid affecting the
	// parent process. The ResourceLimits are passed via the reExecConfig.

	return nil
}

// Cleanup releases platform-specific resources. For the Linux namespace
// platform, this is currently a no-op since namespaces are cleaned up
// automatically when the sandboxed process exits.
func (l *Platform) Cleanup(_ context.Context) error {
	return nil
}
