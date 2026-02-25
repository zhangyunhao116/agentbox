//go:build linux

package linux

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/zhangyunhao116/agentbox/platform"
)

// configureNamespaces sets up Linux namespace isolation on the command.
// It configures user, mount, and PID namespaces by default, and optionally
// adds a network namespace when network restriction is requested.
func configureNamespaces(cmd *exec.Cmd, cfg *platform.WrapConfig) {
	// CLONE_NEWIPC (0x08000000) isolates System V IPC.
	// CLONE_NEWUTS (0x04000000) isolates hostname.
	const (
		cloneNewIPC = 0x08000000
		cloneNewUTS = 0x04000000
	)
	flags := syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | cloneNewIPC | cloneNewUTS
	if cfg.NeedsNetworkRestriction {
		flags |= syscall.CLONE_NEWNET
	}

	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Cloneflags = uintptr(flags)

	// Map the current user to root inside the user namespace.
	cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{
		{ContainerID: 0, HostID: os.Getuid(), Size: 1},
	}
	cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{
		{ContainerID: 0, HostID: os.Getgid(), Size: 1},
	}
}

// Linux rlimit resource constants. These are defined here because some
// constants (e.g., RLIMIT_NPROC) are not available in Go's syscall package
// when cross-compiling from non-Linux platforms.
const (
	rlimitCPU    = 0 // RLIMIT_CPU
	rlimitAS     = 9 // RLIMIT_AS (address space / virtual memory)
	rlimitNOFILE = 7 // RLIMIT_NOFILE
	rlimitNPROC  = 6 // RLIMIT_NPROC
)

// rlimitEntry pairs a resource type with its limit value.
type rlimitEntry struct {
	resource int
	rlimit   syscall.Rlimit
}

// applyResourceLimits sets resource limits (rlimits) on the current process.
// This function should be called in the child process context (e.g., via the
// re-exec init helper in sandboxInit) to avoid affecting the parent process.
// Limits are applied to the calling process via setrlimit.
func applyResourceLimits(limits *platform.ResourceLimits) error {
	if limits == nil {
		return nil
	}

	var entries []rlimitEntry

	if limits.MaxProcesses > 0 {
		entries = append(entries, rlimitEntry{
			resource: rlimitNPROC,
			rlimit:   syscall.Rlimit{Cur: uint64(limits.MaxProcesses), Max: uint64(limits.MaxProcesses)},
		})
	}

	if limits.MaxFileDescriptors > 0 {
		entries = append(entries, rlimitEntry{
			resource: rlimitNOFILE,
			rlimit:   syscall.Rlimit{Cur: uint64(limits.MaxFileDescriptors), Max: uint64(limits.MaxFileDescriptors)},
		})
	}

	if limits.MaxMemoryBytes > 0 {
		entries = append(entries, rlimitEntry{
			resource: rlimitAS,
			rlimit:   syscall.Rlimit{Cur: uint64(limits.MaxMemoryBytes), Max: uint64(limits.MaxMemoryBytes)},
		})
	}

	if limits.MaxCPUSeconds > 0 {
		entries = append(entries, rlimitEntry{
			resource: rlimitCPU,
			rlimit:   syscall.Rlimit{Cur: uint64(limits.MaxCPUSeconds), Max: uint64(limits.MaxCPUSeconds)},
		})
	}

	if len(entries) == 0 {
		return nil
	}

	// Apply each rlimit via setrlimit.
	for _, e := range entries {
		if err := setrlimitFunc(e.resource, &e.rlimit); err != nil {
			return fmt.Errorf("setrlimit resource %d: %w", e.resource, err)
		}
	}

	return nil
}
