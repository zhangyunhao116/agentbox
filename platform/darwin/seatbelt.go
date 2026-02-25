//go:build darwin

package darwin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	"github.com/zhangyunhao116/agentbox/platform"
)

// Platform implements the platform.Platform interface using macOS sandbox-exec
// (Seatbelt). It generates SBPL profiles from WrapConfig and rewrites
// exec.Cmd to run under sandbox-exec.
type Platform struct{}

// buildProfile builds an SBPL profile from a WrapConfig.
// It is a package-level variable so tests can override it to simulate errors.
var buildProfile = func(cfg *platform.WrapConfig) (string, error) {
	return newProfileBuilder().Build(cfg)
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

	// Build the SBPL profile.
	profile, err := buildProfile(cfg)
	if err != nil {
		return fmt.Errorf("darwin-seatbelt: failed to build profile: %w", err)
	}

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
		// ulimit -v takes kilobytes.
		kbytes := limits.MaxMemoryBytes / 1024
		if kbytes == 0 {
			kbytes = 1
		}
		cmds = append(cmds, fmt.Sprintf("ulimit -v %d", kbytes))
	}

	if limits.MaxCPUSeconds > 0 {
		cmds = append(cmds, fmt.Sprintf("ulimit -t %d", limits.MaxCPUSeconds))
	}

	if limits.MaxProcesses > 0 {
		// NOTE: RLIMIT_NPROC on macOS has unusual kernel behavior.
		// We still log it but skip setting it via ulimit.
		logger.Info("MaxProcesses resource limit requested but skipped on macOS",
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
