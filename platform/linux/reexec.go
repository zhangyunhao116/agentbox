//go:build linux

package linux

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"syscall"

	"github.com/zhangyunhao116/agentbox/platform"
)

// reExecEnvKey is the environment variable that signals the process is in
// re-exec sandbox-init mode. Its value is the file descriptor number of the
// pipe carrying the serialized WrapConfig.
const reExecEnvKey = "_AGENTBOX_CONFIG"

// Function variables for dependency injection in tests.
var (
	hardenProcessFn    = hardenProcess
	applyLandlockFn    = applyLandlock
	applyResourceLimFn = applyResourceLimits
	applySeccompFn     = ApplySeccomp
	syscallExecFn      = syscall.Exec
	osExitFn           = os.Exit
)

// reExecConfig is the configuration passed to the re-exec child via a pipe.
type reExecConfig struct {
	WritableRoots           []string                 `json:"writable_roots,omitempty"`
	DenyWrite               []string                 `json:"deny_write,omitempty"`
	DenyRead                []string                 `json:"deny_read,omitempty"`
	NeedsNetworkRestriction bool                     `json:"needs_network_restriction,omitempty"`
	ResourceLimits          *platform.ResourceLimits `json:"resource_limits,omitempty"`
}

// MaybeSandboxInit checks if the current process was launched in re-exec
// sandbox-init mode. If so, it applies the sandbox configuration and returns
// true (the caller should then exec the real command). If not in re-exec mode,
// it returns false and the caller continues normally.
func MaybeSandboxInit() bool {
	fdStr := os.Getenv(reExecEnvKey)
	if fdStr == "" {
		return false
	}

	code := sandboxInit(fdStr)
	osExitFn(code)
	return true // unreachable, but satisfies the compiler
}

// sandboxInit is the entry point for the re-exec sandbox helper.
// It reads the configuration from the given file descriptor, applies
// sandbox restrictions, and then execs the real command.
func sandboxInit(fdStr string) int {
	// Lock the OS thread because seccomp, landlock_restrict_self, and prctl
	// are per-thread operations. Since this is the re-exec child process,
	// we lock and never unlock — the process will exec or exit.
	runtime.LockOSThread()

	fd, err := strconv.Atoi(fdStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: invalid config fd %q: %v\n", fdStr, err)
		return 1
	}

	// Read configuration from the pipe.
	configFile := os.NewFile(uintptr(fd), "config-pipe")
	if configFile == nil {
		fmt.Fprintf(os.Stderr, "agentbox: cannot open config fd %d\n", fd)
		return 1
	}
	defer func() { _ = configFile.Close() }()

	var cfg reExecConfig
	if err := json.NewDecoder(configFile).Decode(&cfg); err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: decode config: %v\n", err)
		return 1
	}

	// Apply process hardening.
	if err := hardenProcessFn(); err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: harden: %v\n", err)
		return 1
	}

	// Apply Landlock filesystem restrictions.
	wrapCfg := &platform.WrapConfig{
		WritableRoots:           cfg.WritableRoots,
		DenyWrite:               cfg.DenyWrite,
		DenyRead:                cfg.DenyRead,
		NeedsNetworkRestriction: cfg.NeedsNetworkRestriction,
		ResourceLimits:          cfg.ResourceLimits,
	}
	if err := applyLandlockFn(wrapCfg); err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: landlock: %v\n", err)
		return 1
	}

	// Apply resource limits in the child process context.
	if cfg.ResourceLimits != nil {
		if err := applyResourceLimFn(cfg.ResourceLimits); err != nil {
			fmt.Fprintf(os.Stderr, "agentbox: resource limits: %v\n", err)
			return 1
		}
	}

	// Apply seccomp filter to block AF_UNIX sockets.
	// Seccomp failure is fatal to maintain fail-closed security posture.
	if err := applySeccompFn(); err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: seccomp: %v\n", err)
		return 1
	}

	// Exec the real command (remaining args after the re-exec marker).
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "agentbox: no command to exec\n")
		return 1
	}

	// Clear the re-exec env var so the child doesn't re-enter init.
	_ = os.Unsetenv(reExecEnvKey)

	if err := syscallExecFn(args[0], args, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: exec %s: %v\n", args[0], err)
		return 1
	}

	return 0 // unreachable
}
