//go:build darwin

package darwin

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"

	"github.com/zhangyunhao116/agentbox/platform"
)

// Platform implements the platform.Platform interface using macOS sandbox-exec
// (Seatbelt). It generates SBPL profiles from WrapConfig and rewrites
// exec.Cmd to run under sandbox-exec.
//
// Profile caching: Generated SBPL profiles are cached keyed by a hash of the
// WrapConfig fields that affect profile output plus the TMPDIR environment
// variable. If TMPDIR changes between calls with the same WrapConfig, the
// cache correctly misses and regenerates the profile.
type Platform struct {
	mu            sync.RWMutex
	cachedKey     uint64 // FNV hash of config fields that affect profile output
	cachedProfile string
}

// buildProfile builds an SBPL profile from a WrapConfig.
// It is a package-level variable so tests can override it to simulate errors.
var buildProfile = func(cfg *platform.WrapConfig) (string, error) {
	return newProfileBuilder().Build(cfg)
}

// profileCacheKey computes a hash of the WrapConfig fields that affect the
// generated SBPL profile. Fields that don't affect profile output (e.g.,
// Shell, ResourceLimits, Warnings) are excluded from the hash.
func profileCacheKey(cfg *platform.WrapConfig) uint64 {
	h := fnv.New64a()

	// Hash sorted slices to ensure consistent ordering.
	writeSortedSlice := func(items []string) {
		sorted := make([]string, len(items))
		copy(sorted, items)
		sort.Strings(sorted)
		for _, item := range sorted {
			h.Write([]byte(item))
			h.Write([]byte{0}) // separator
		}
	}

	writeSortedSlice(cfg.WritableRoots)
	writeSortedSlice(cfg.DenyWrite)
	writeSortedSlice(cfg.DenyRead)
	writeSortedSlice(cfg.AllowUnixSockets)

	// Hash boolean flags.
	writeBool := func(b bool) {
		if b {
			h.Write([]byte{1})
		} else {
			h.Write([]byte{0})
		}
	}
	writeBool(cfg.AllowGitConfig)
	writeBool(cfg.NeedsNetworkRestriction)
	writeBool(cfg.AllowLocalBinding)
	writeBool(cfg.AllowAllUnixSockets)

	// Hash integer proxy ports.
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(cfg.HTTPProxyPort))   //nolint:gosec // port numbers are safe for uint64 conversion
	h.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], uint64(cfg.SOCKSProxyPort)) //nolint:gosec // port numbers are safe for uint64 conversion
	h.Write(buf[:])

	// Hash TMPDIR env var since getTmpdirParents() in profile.go reads it.
	tmpdir := os.Getenv("TMPDIR")
	h.Write([]byte(tmpdir))
	h.Write([]byte{0})

	return h.Sum64()
}

// New returns a new Platform instance.
func New() *Platform {
	return &Platform{}
}

// Name returns the platform identifier.
func (d *Platform) Name() string {
	return "darwin-seatbelt"
}

// Available reports whether sandbox-exec is present on this system.
func (d *Platform) Available() bool {
	_, err := os.Stat(platform.SandboxExecPath)
	return err == nil
}

// CheckDependencies inspects the system for sandbox-exec and reports any
// issues.
func (d *Platform) CheckDependencies() *platform.DependencyCheck {
	check := &platform.DependencyCheck{}

	if _, err := os.Stat(platform.SandboxExecPath); err != nil {
		check.Errors = append(check.Errors,
			fmt.Sprintf("sandbox-exec not found at %s: %v", platform.SandboxExecPath, err))
	}

	return check
}

// Capabilities returns the set of isolation features supported by the
// macOS Seatbelt sandbox.
func (d *Platform) Capabilities() platform.Capabilities {
	return platform.Capabilities{
		FileReadDeny:   true,
		FileWriteAllow: true,
		NetworkDeny:    true,
		NetworkProxy:   true,
		ProcessHarden:  true,
	}
}

// WrapCommand modifies cmd in-place to execute under sandbox-exec with an
// SBPL profile generated from cfg.
//
// Security hardening applied:
//   - DYLD_* and LD_* environment variables are stripped to prevent
//     dynamic library injection.
func (d *Platform) WrapCommand(_ context.Context, cmd *exec.Cmd, cfg *platform.WrapConfig) error {
	if cfg == nil {
		cfg = &platform.WrapConfig{}
	}

	// Check profile cache before building.
	cacheKey := profileCacheKey(cfg)
	d.mu.RLock()
	if d.cachedKey == cacheKey && d.cachedProfile != "" {
		profile := d.cachedProfile
		d.mu.RUnlock()
		// Cache hit: use cached profile and skip to command rewriting.
		return d.applyProfile(cmd, cfg, profile)
	}
	d.mu.RUnlock()

	// Cache miss: build the profile.
	d.mu.Lock()
	// Double-check: another goroutine may have built it while we waited for Lock.
	if d.cachedKey == cacheKey && d.cachedProfile != "" {
		profile := d.cachedProfile
		d.mu.Unlock()
		return d.applyProfile(cmd, cfg, profile)
	}

	profile, err := buildProfile(cfg)
	if err != nil {
		d.mu.Unlock()
		return fmt.Errorf("darwin-seatbelt: failed to build profile: %w", err)
	}

	// Store in cache.
	d.cachedKey = cacheKey
	d.cachedProfile = profile
	d.mu.Unlock()

	return d.applyProfile(cmd, cfg, profile)
}

// applyProfile rewrites cmd to execute under sandbox-exec with the given
// profile and applies environment sanitization and proxy configuration.
func (d *Platform) applyProfile(cmd *exec.Cmd, cfg *platform.WrapConfig, profile string) error {
	// Resolve the original command path.
	origPath := cmd.Path
	if origPath == "" {
		return errors.New("darwin-seatbelt: cmd.Path is empty")
	}

	origArgs := make([]string, len(cmd.Args))
	copy(origArgs, cmd.Args)

	// Rewrite the command to run under sandbox-exec.
	// When resource limits are configured, we wrap the command in a shell
	// that applies ulimit commands before exec-ing the original binary.
	// This avoids the race condition of setting rlimits on the parent process.
	ulimitCmds := buildUlimitCommands(cfg.ResourceLimits)
	if ulimitCmds != "" {
		// sandbox-exec -p <profile> -- /bin/sh -c "ulimit ...; exec <cmd> <args...>"
		cmd.Path = platform.SandboxExecPath
		shellCmd := buildShellCommand(ulimitCmds, origPath, origArgs)
		cmd.Args = []string{"sandbox-exec", "-p", profile, "--", "/bin/sh", "-c", shellCmd}
	} else {
		// sandbox-exec -p <profile> -- <original-command> <original-args...>
		cmd.Path = platform.SandboxExecPath
		newArgs := []string{"sandbox-exec", "-p", profile, "--"}
		if len(origArgs) > 0 {
			newArgs = append(newArgs, origArgs...)
		} else {
			newArgs = append(newArgs, origPath)
		}
		cmd.Args = newArgs
	}

	// Sanitize environment: remove DYLD_* and LD_* variables to prevent
	// dynamic library injection into the sandboxed process.
	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	env = sanitizeEnv(env)

	// Add proxy environment variables if proxy ports are configured.
	if cfg.HTTPProxyPort > 0 || cfg.SOCKSProxyPort > 0 {
		env = append(env, proxyEnvVars(cfg.HTTPProxyPort, cfg.SOCKSProxyPort)...)
	}
	cmd.Env = env

	return nil
}

// Cleanup releases platform-specific resources. For the Seatbelt platform,
// this is currently a no-op.
func (d *Platform) Cleanup(_ context.Context) error {
	return nil
}

// buildUlimitCommands generates a string of ulimit shell commands from the
// given ResourceLimits. Returns an empty string if no limits are configured.
// The ulimit commands are applied in the child process via /bin/sh -c,
// avoiding the race condition of setting rlimits on the parent process.
func buildUlimitCommands(limits *platform.ResourceLimits) string {
	if limits == nil {
		return ""
	}

	logger := slog.Default()
	var cmds []string

	if limits.MaxFileDescriptors > 0 {
		cmds = append(cmds, fmt.Sprintf("ulimit -n %d", limits.MaxFileDescriptors))
	}

	if limits.MaxMemoryBytes > 0 {
		// NOTE: ulimit -v (virtual memory) is not supported on macOS,
		// especially on Apple Silicon where the kernel rejects the call with
		// EINVAL. Since DefaultConfig always sets MaxMemoryBytes (2 GB), this
		// would produce a noisy "cannot modify limit" stderr on every command.
		// We skip it entirely and log at Debug, same as MaxProcesses below.
		logger.Debug("MaxMemoryBytes resource limit requested but skipped on macOS",
			"max_memory_bytes", limits.MaxMemoryBytes,
		)
	}

	if limits.MaxCPUSeconds > 0 {
		cmds = append(cmds, fmt.Sprintf("ulimit -t %d", limits.MaxCPUSeconds))
	}

	if limits.MaxProcesses > 0 {
		// NOTE: RLIMIT_NPROC on macOS has unusual kernel behavior.
		// We still log it but skip setting it via ulimit.
		logger.Debug("MaxProcesses resource limit requested but skipped on macOS",
			"max_processes", limits.MaxProcesses,
		)
	}

	if len(cmds) == 0 {
		return ""
	}

	return strings.Join(cmds, "; ")
}

// buildShellCommand constructs a shell command string that applies ulimit
// commands and then exec's the original command with its arguments.
// Arguments are single-quoted and escaped to prevent shell injection.
func buildShellCommand(ulimitCmds, origPath string, origArgs []string) string {
	var b strings.Builder
	b.WriteString(ulimitCmds)
	b.WriteString("; exec ")

	// Use the original args if available (args[0] is the command name).
	args := origArgs
	if len(args) == 0 {
		args = []string{origPath}
	}

	for i, arg := range args {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(shellQuote(arg))
	}

	return b.String()
}

// shellQuote returns a single-quoted shell-safe representation of s.
// Single quotes within s are escaped as '\” (end quote, escaped quote, start quote).
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	// If the string contains no special characters, return as-is for readability.
	if !strings.ContainsAny(s, " \t\n'\"\\$`!#&|;(){}[]<>?*~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
