//go:build linux

package linux

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"github.com/zhangyunhao116/agentbox/platform"
)

// Platform implements the platform.Platform interface using Linux namespaces,
// Landlock filesystem restrictions, and seccomp BPF filters.
type Platform struct {
	mu            sync.Mutex
	kernelVersion KernelVersion
	landlockABI   int
	worker        *workerClient // persistent worker (nil if not started)
	workerErr     error         // error from starting worker (prevents retry)
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
// platform, this stops the persistent worker process if running.
func (l *Platform) Cleanup(_ context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.worker != nil {
		err := l.worker.stop()
		l.worker = nil
		return err
	}
	return nil
}

// ensureWorker starts the persistent sandbox worker on first call.
// Subsequent calls return the existing worker or nil if worker failed to start.
// Caller must hold l.mu.
func (l *Platform) ensureWorkerUnlocked(cfg *platform.WrapConfig) *workerClient {
	if l.worker != nil {
		if l.worker.alive() {
			return l.worker
		}
		// Worker died, clean it up and allow retry.
		_ = l.worker.stop()
		l.worker = nil
		l.workerErr = nil
	}
	if l.workerErr != nil {
		return nil // Previously failed, don't retry
	}

	// Build base config from the WrapConfig.
	baseCfg := reExecConfig{
		WritableRoots:           cfg.WritableRoots,
		DenyWrite:               cfg.DenyWrite,
		DenyRead:                cfg.DenyRead,
		NeedsNetworkRestriction: cfg.NeedsNetworkRestriction,
		ResourceLimits:          cfg.ResourceLimits,
	}

	w, err := startWorker(baseCfg)
	if err != nil {
		l.workerErr = err
		return nil
	}
	l.worker = w
	return w
}

// ExecViaWorker executes a command via the persistent worker process.
// Returns nil, nil if worker is not available (caller should fall back to re-exec).
func (l *Platform) ExecViaWorker(ctx context.Context, cfg *platform.WrapConfig, name string, args []string, dir string, env []string) (*platform.WorkerExecResult, error) {
	l.mu.Lock()
	w := l.ensureWorkerUnlocked(cfg)
	l.mu.Unlock()

	if w == nil {
		return nil, nil // No worker, caller falls back
	}

	req := &workerRequest{
		ID:                      fmt.Sprintf("cmd-%d", time.Now().UnixNano()),
		Cmd:                     name,
		Args:                    args,
		Dir:                     dir,
		Env:                     env,
		WritableRoots:           cfg.WritableRoots,
		DenyWrite:               cfg.DenyWrite,
		DenyRead:                cfg.DenyRead,
		NeedsNetworkRestriction: cfg.NeedsNetworkRestriction,
		ResourceLimits:          cfg.ResourceLimits,
	}

	resp, err := w.execCommand(ctx, req)
	if err != nil {
		return nil, err
	}

	return &platform.WorkerExecResult{
		Stdout:   resp.Stdout,
		Stderr:   resp.Stderr,
		ExitCode: resp.ExitCode,
		Error:    resp.Error,
	}, nil
}

