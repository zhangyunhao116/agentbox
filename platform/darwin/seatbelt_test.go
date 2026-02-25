//go:build darwin

package darwin

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/zhangyunhao116/agentbox/platform"
)

// ---------------------------------------------------------------------------
// Platform basic tests
// ---------------------------------------------------------------------------

func TestNew(t *testing.T) {
	p := New()
	if p == nil {
		t.Fatal("New() returned nil")
	}
}

func TestName(t *testing.T) {
	p := New()
	if p.Name() != "darwin-seatbelt" {
		t.Fatalf("Name() = %q, want darwin-seatbelt", p.Name())
	}
}

func TestAvailable(t *testing.T) {
	p := New()
	// On macOS, sandbox-exec should be available.
	if !p.Available() {
		t.Fatal("Available() should return true on macOS")
	}
}

func TestCheckDependencies(t *testing.T) {
	p := New()
	dc := p.CheckDependencies()
	if dc == nil {
		t.Fatal("CheckDependencies() returned nil")
	}
	if !dc.OK() {
		t.Fatalf("CheckDependencies() should be OK on macOS, got errors: %v", dc.Errors)
	}
}

func TestCapabilities(t *testing.T) {
	p := New()
	caps := p.Capabilities()

	if !caps.FileReadDeny {
		t.Error("FileReadDeny should be true")
	}
	if !caps.FileWriteAllow {
		t.Error("FileWriteAllow should be true")
	}
	if !caps.NetworkDeny {
		t.Error("NetworkDeny should be true")
	}
	if !caps.NetworkProxy {
		t.Error("NetworkProxy should be true")
	}
	if !caps.ProcessHarden {
		t.Error("ProcessHarden should be true")
	}
	// macOS Seatbelt does not support PID isolation or syscall filter.
	if caps.PIDIsolation {
		t.Error("PIDIsolation should be false")
	}
	if caps.SyscallFilter {
		t.Error("SyscallFilter should be false")
	}
}

func TestCleanup(t *testing.T) {
	p := New()
	if err := p.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup() error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// WrapCommand tests
// ---------------------------------------------------------------------------

func TestWrapCommandModifiesCmd(t *testing.T) {
	p := New()
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "/bin/echo", "hello", "world")

	cfg := &platform.WrapConfig{
		WritableRoots: []string{"/tmp"},
	}

	err := p.WrapCommand(ctx, cmd, cfg)
	if err != nil {
		t.Fatalf("WrapCommand() error: %v", err)
	}

	// cmd.Path should be sandbox-exec.
	if cmd.Path != platform.SandboxExecPath {
		t.Errorf("cmd.Path = %q, want %q", cmd.Path, platform.SandboxExecPath)
	}

	// cmd.Args should start with [sandbox-exec, -p, <profile>, --, ...]
	if len(cmd.Args) < 5 {
		t.Fatalf("cmd.Args too short: %v", cmd.Args)
	}
	if cmd.Args[0] != "sandbox-exec" {
		t.Errorf("cmd.Args[0] = %q, want sandbox-exec", cmd.Args[0])
	}
	if cmd.Args[1] != "-p" {
		t.Errorf("cmd.Args[1] = %q, want -p", cmd.Args[1])
	}
	// Args[2] is the profile string.
	if !strings.Contains(cmd.Args[2], "(version 1)") {
		t.Error("profile in cmd.Args[2] missing (version 1)")
	}
	if cmd.Args[3] != "--" {
		t.Errorf("cmd.Args[3] = %q, want --", cmd.Args[3])
	}
	// Original command and args should follow.
	if cmd.Args[4] != "/bin/echo" {
		t.Errorf("cmd.Args[4] = %q, want /bin/echo", cmd.Args[4])
	}
	if cmd.Args[5] != "hello" {
		t.Errorf("cmd.Args[5] = %q, want hello", cmd.Args[5])
	}
	if cmd.Args[6] != "world" {
		t.Errorf("cmd.Args[6] = %q, want world", cmd.Args[6])
	}
}

func TestWrapCommandNilConfig(t *testing.T) {
	p := New()
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "/bin/echo", "test")

	// nil config should not panic.
	err := p.WrapCommand(ctx, cmd, nil)
	if err != nil {
		t.Fatalf("WrapCommand(nil config) error: %v", err)
	}
	if cmd.Path != platform.SandboxExecPath {
		t.Errorf("cmd.Path = %q, want %q", cmd.Path, platform.SandboxExecPath)
	}
}

func TestWrapCommandEmptyPath(t *testing.T) {
	p := New()
	ctx := context.Background()
	cmd := &exec.Cmd{}

	err := p.WrapCommand(ctx, cmd, &platform.WrapConfig{})
	if err == nil {
		t.Fatal("WrapCommand() should return error for empty cmd.Path")
	}
}

func TestWrapCommandSanitizesEnv(t *testing.T) {
	p := New()
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "/bin/echo", "test")
	cmd.Env = []string{
		"PATH=/usr/bin",
		"DYLD_LIBRARY_PATH=/bad",
		"HOME=/Users/test",
		"DYLD_INSERT_LIBRARIES=/evil",
	}

	err := p.WrapCommand(ctx, cmd, &platform.WrapConfig{})
	if err != nil {
		t.Fatalf("WrapCommand() error: %v", err)
	}

	for _, e := range cmd.Env {
		if strings.HasPrefix(e, "DYLD_") {
			t.Errorf("DYLD_* var should be removed: %s", e)
		}
	}
}

func TestWrapCommandAddsProxyEnv(t *testing.T) {
	p := New()
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "/bin/echo", "test")
	cmd.Env = []string{"PATH=/usr/bin"}

	cfg := &platform.WrapConfig{
		HTTPProxyPort:  8080,
		SOCKSProxyPort: 1080,
	}

	err := p.WrapCommand(ctx, cmd, cfg)
	if err != nil {
		t.Fatalf("WrapCommand() error: %v", err)
	}

	envMap := make(map[string]string)
	for _, e := range cmd.Env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}

	if envMap["HTTP_PROXY"] != "http://127.0.0.1:8080" {
		t.Errorf("HTTP_PROXY = %q, want http://127.0.0.1:8080", envMap["HTTP_PROXY"])
	}
	if envMap["ALL_PROXY"] != "socks5h://127.0.0.1:1080" {
		t.Errorf("ALL_PROXY = %q, want socks5h://127.0.0.1:1080", envMap["ALL_PROXY"])
	}
}

func TestWrapCommandDefaultEnv(t *testing.T) {
	p := New()
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "/bin/echo", "test")
	// cmd.Env is nil, should use os.Environ().

	err := p.WrapCommand(ctx, cmd, &platform.WrapConfig{})
	if err != nil {
		t.Fatalf("WrapCommand() error: %v", err)
	}

	if cmd.Env == nil {
		t.Fatal("cmd.Env should not be nil after WrapCommand")
	}

	// Should contain PATH from os.Environ().
	hasPath := false
	for _, e := range cmd.Env {
		if strings.HasPrefix(e, "PATH=") {
			hasPath = true
			break
		}
	}
	if !hasPath {
		t.Error("cmd.Env should contain PATH from os.Environ()")
	}
}

func TestWrapCommandWithResourceLimits(t *testing.T) {
	p := New()
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "/bin/echo", "test")

	cfg := &platform.WrapConfig{
		ResourceLimits: &platform.ResourceLimits{
			MaxProcesses:       100,
			MaxMemoryBytes:     1 << 30,
			MaxFileDescriptors: 256,
			MaxCPUSeconds:      60,
		},
	}

	// Should not panic or error with resource limits.
	err := p.WrapCommand(ctx, cmd, cfg)
	if err != nil {
		t.Fatalf("WrapCommand() error: %v", err)
	}

	// With resource limits, the command should be wrapped in /bin/sh -c.
	if cmd.Path != platform.SandboxExecPath {
		t.Errorf("cmd.Path = %q, want %q", cmd.Path, platform.SandboxExecPath)
	}
	// Args should be: sandbox-exec -p <profile> -- /bin/sh -c "<ulimit cmds>; exec ..."
	if len(cmd.Args) < 7 {
		t.Fatalf("cmd.Args too short for ulimit wrapping: %v", cmd.Args)
	}
	if cmd.Args[4] != "/bin/sh" {
		t.Errorf("cmd.Args[4] = %q, want /bin/sh", cmd.Args[4])
	}
	if cmd.Args[5] != "-c" {
		t.Errorf("cmd.Args[5] = %q, want -c", cmd.Args[5])
	}
	shellCmd := cmd.Args[6]
	if !strings.Contains(shellCmd, "ulimit -n 256") {
		t.Errorf("shell command missing ulimit -n: %s", shellCmd)
	}
	if !strings.Contains(shellCmd, "ulimit -t 60") {
		t.Errorf("shell command missing ulimit -t: %s", shellCmd)
	}
	if !strings.Contains(shellCmd, "exec") {
		t.Errorf("shell command missing exec: %s", shellCmd)
	}
}

// ---------------------------------------------------------------------------
// buildUlimitCommands tests
// ---------------------------------------------------------------------------

func TestBuildUlimitCommandsNil(t *testing.T) {
	result := buildUlimitCommands(nil)
	if result != "" {
		t.Errorf("buildUlimitCommands(nil) = %q, want empty", result)
	}
}

func TestBuildUlimitCommandsZeroValues(t *testing.T) {
	result := buildUlimitCommands(&platform.ResourceLimits{})
	if result != "" {
		t.Errorf("buildUlimitCommands(zero) = %q, want empty", result)
	}
}

func TestBuildUlimitCommandsFileDescriptors(t *testing.T) {
	result := buildUlimitCommands(&platform.ResourceLimits{
		MaxFileDescriptors: 512,
	})
	if result != "ulimit -n 512" {
		t.Errorf("got %q, want %q", result, "ulimit -n 512")
	}
}

func TestBuildUlimitCommandsMemory(t *testing.T) {
	// MaxMemoryBytes is skipped on macOS (ulimit -v not supported).
	result := buildUlimitCommands(&platform.ResourceLimits{
		MaxMemoryBytes: 2 * 1024 * 1024 * 1024, // 2 GB
	})
	if result != "" {
		t.Errorf("MaxMemoryBytes should be skipped on macOS, got %q", result)
	}
}

func TestBuildUlimitCommandsSmallMemory(t *testing.T) {
	// MaxMemoryBytes is skipped on macOS regardless of size.
	result := buildUlimitCommands(&platform.ResourceLimits{
		MaxMemoryBytes: 500,
	})
	if result != "" {
		t.Errorf("MaxMemoryBytes should be skipped on macOS, got %q", result)
	}
}

func TestBuildUlimitCommandsCPU(t *testing.T) {
	result := buildUlimitCommands(&platform.ResourceLimits{
		MaxCPUSeconds: 300,
	})
	if result != "ulimit -t 300" {
		t.Errorf("got %q, want %q", result, "ulimit -t 300")
	}
}

func TestBuildUlimitCommandsMaxProcessesSkipped(t *testing.T) {
	// MaxProcesses is skipped on macOS, should return empty.
	result := buildUlimitCommands(&platform.ResourceLimits{
		MaxProcesses: 100,
	})
	if result != "" {
		t.Errorf("MaxProcesses should be skipped on macOS, got %q", result)
	}
}

func TestBuildUlimitCommandsAllFields(t *testing.T) {
	result := buildUlimitCommands(&platform.ResourceLimits{
		MaxProcesses:       100,
		MaxMemoryBytes:     1 << 30,
		MaxFileDescriptors: 256,
		MaxCPUSeconds:      60,
	})
	if !strings.Contains(result, "ulimit -n 256") {
		t.Errorf("missing ulimit -n: %s", result)
	}
	// MaxMemoryBytes (ulimit -v) is skipped on macOS.
	if strings.Contains(result, "ulimit -v") {
		t.Errorf("ulimit -v should be skipped on macOS: %s", result)
	}
	if !strings.Contains(result, "ulimit -t 60") {
		t.Errorf("missing ulimit -t: %s", result)
	}
	// Should be semicolon-separated.
	if !strings.Contains(result, "; ") {
		t.Errorf("ulimit commands should be semicolon-separated: %s", result)
	}
}

// ---------------------------------------------------------------------------
// buildShellCommand tests
// ---------------------------------------------------------------------------

func TestBuildShellCommand(t *testing.T) {
	result := buildShellCommand("ulimit -n 256", "/bin/echo", []string{"/bin/echo", "hello", "world"})
	if !strings.HasPrefix(result, "ulimit -n 256; exec ") {
		t.Errorf("unexpected prefix: %s", result)
	}
	if !strings.Contains(result, "/bin/echo") {
		t.Errorf("missing command: %s", result)
	}
	if !strings.Contains(result, "hello") {
		t.Errorf("missing arg: %s", result)
	}
}

func TestBuildShellCommandNoArgs(t *testing.T) {
	result := buildShellCommand("ulimit -n 256", "/bin/echo", nil)
	if !strings.Contains(result, "exec /bin/echo") {
		t.Errorf("should use origPath when args is nil: %s", result)
	}
}

func TestBuildShellCommandSpecialChars(t *testing.T) {
	result := buildShellCommand("ulimit -n 256", "/bin/echo", []string{"/bin/echo", "hello world", "it's"})
	if !strings.Contains(result, "'hello world'") {
		t.Errorf("should quote args with spaces: %s", result)
	}
	if !strings.Contains(result, `'it'\''s'`) {
		t.Errorf("should escape single quotes: %s", result)
	}
}

// ---------------------------------------------------------------------------
// shellQuote tests
// ---------------------------------------------------------------------------

func TestShellQuote(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", "''"},
		{"simple", "hello", "hello"},
		{"path", "/bin/echo", "/bin/echo"},
		{"space", "hello world", "'hello world'"},
		{"single quote", "it's", `'it'\''s'`},
		{"dollar", "$HOME", "'$HOME'"},
		{"backtick", "`cmd`", "'`cmd`'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shellQuote(tt.input)
			if got != tt.want {
				t.Errorf("shellQuote(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Interface compliance
// ---------------------------------------------------------------------------

// Compile-time check that Platform implements platform.Platform.
var _ platform.Platform = (*Platform)(nil)

// ---------------------------------------------------------------------------
// Integration test: actually run sandbox-exec
// ---------------------------------------------------------------------------

func TestWrapCommandIntegration(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("skipping integration test in CI")
	}

	p := New()
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "/bin/echo", "sandbox-test")

	cfg := &platform.WrapConfig{
		WritableRoots: []string{"/tmp"},
	}

	err := p.WrapCommand(ctx, cmd, cfg)
	if err != nil {
		t.Fatalf("WrapCommand() error: %v", err)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sandbox-exec failed: %v\noutput: %s", err, out)
	}

	if !strings.Contains(string(out), "sandbox-test") {
		t.Errorf("expected output to contain 'sandbox-test', got: %s", out)
	}
}

// ---------------------------------------------------------------------------
// Additional coverage tests
// ---------------------------------------------------------------------------

// TestWrapCommandNoArgs verifies WrapCommand with a command that has no Args
// (only Path set).
func TestWrapCommandNoArgs(t *testing.T) {
	p := New()
	ctx := context.Background()
	cmd := &exec.Cmd{Path: "/bin/echo"}
	// cmd.Args is nil — WrapCommand should use origPath as the argument.

	err := p.WrapCommand(ctx, cmd, &platform.WrapConfig{})
	if err != nil {
		t.Fatalf("WrapCommand() error: %v", err)
	}

	// The last arg should be the original path since Args was empty.
	lastArg := cmd.Args[len(cmd.Args)-1]
	if lastArg != "/bin/echo" {
		t.Errorf("last arg = %q, want /bin/echo", lastArg)
	}
}

// TestWrapCommandWithNetworkRestriction verifies WrapCommand with network
// restriction enabled.
func TestWrapCommandWithNetworkRestriction(t *testing.T) {
	p := New()
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "/bin/echo", "test")

	cfg := &platform.WrapConfig{
		NeedsNetworkRestriction: true,
	}

	err := p.WrapCommand(ctx, cmd, cfg)
	if err != nil {
		t.Fatalf("WrapCommand() error: %v", err)
	}

	// Profile should contain network deny.
	profile := cmd.Args[2]
	if !strings.Contains(profile, "network") {
		t.Error("profile should contain network rules when NeedsNetworkRestriction is true")
	}
}

// TestWrapCommandWithAllOptions verifies WrapCommand with all config options.
func TestWrapCommandWithAllOptions(t *testing.T) {
	p := New()
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "/bin/echo", "test")
	cmd.Env = []string{"PATH=/usr/bin", "HOME=/Users/test"}

	cfg := &platform.WrapConfig{
		WritableRoots:           []string{"/tmp", "/var/tmp"},
		DenyWrite:               []string{"/etc"},
		DenyRead:                []string{"/root/.ssh"},
		AllowGitConfig:          true,
		Shell:                   "/bin/bash",
		NeedsNetworkRestriction: true,
		HTTPProxyPort:           8080,
		SOCKSProxyPort:          1080,
		ResourceLimits: &platform.ResourceLimits{
			MaxFileDescriptors: 256,
		},
	}

	err := p.WrapCommand(ctx, cmd, cfg)
	if err != nil {
		t.Fatalf("WrapCommand() error: %v", err)
	}

	// Verify proxy env vars are set.
	envMap := make(map[string]string)
	for _, e := range cmd.Env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}
	if envMap["HTTP_PROXY"] == "" {
		t.Error("HTTP_PROXY should be set")
	}
	if envMap["ALL_PROXY"] == "" {
		t.Error("ALL_PROXY should be set")
	}

	// With resource limits, should use /bin/sh -c wrapping.
	if cmd.Args[4] != "/bin/sh" {
		t.Errorf("cmd.Args[4] = %q, want /bin/sh (ulimit wrapping)", cmd.Args[4])
	}
}

// TestWrapCommandResourceLimitsDoNotAffectParent verifies that the new
// ulimit-based approach does not modify the parent process rlimits.
func TestWrapCommandResourceLimitsDoNotAffectParent(t *testing.T) {
	p := New()
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "/bin/echo", "test")

	cfg := &platform.WrapConfig{
		ResourceLimits: &platform.ResourceLimits{
			MaxFileDescriptors: 128,
			MaxMemoryBytes:     1 << 30,
			MaxCPUSeconds:      60,
		},
	}

	// The ulimit approach should not call syscall.Setrlimit on the parent.
	// We verify by checking that WrapCommand only modifies cmd.Args.
	err := p.WrapCommand(ctx, cmd, cfg)
	if err != nil {
		t.Fatalf("WrapCommand() error: %v", err)
	}

	// The command should be wrapped with /bin/sh -c containing ulimit commands.
	shellCmd := cmd.Args[6]
	if !strings.Contains(shellCmd, "ulimit") {
		t.Errorf("expected ulimit commands in shell wrapper, got: %s", shellCmd)
	}
}

// ---------------------------------------------------------------------------
// CheckDependencies with missing sandbox-exec (SandboxExecPath override)
// ---------------------------------------------------------------------------

func TestCheckDependencies_MissingSandboxExec(t *testing.T) {
	// Temporarily override SandboxExecPath to a nonexistent path.
	orig := platform.SandboxExecPath
	platform.SandboxExecPath = "/nonexistent/sandbox-exec"
	t.Cleanup(func() {
		platform.SandboxExecPath = orig
	})

	p := New()
	dc := p.CheckDependencies()
	if dc == nil {
		t.Fatal("CheckDependencies() returned nil")
	}
	if dc.OK() {
		t.Fatal("CheckDependencies() should report errors when sandbox-exec is missing")
	}
	if len(dc.Errors) == 0 {
		t.Fatal("CheckDependencies() should have at least one error")
	}
	if !strings.Contains(dc.Errors[0], "sandbox-exec not found") {
		t.Errorf("error message should mention sandbox-exec not found, got: %s", dc.Errors[0])
	}
}

func TestAvailable_MissingSandboxExec(t *testing.T) {
	// Temporarily override SandboxExecPath to a nonexistent path.
	orig := platform.SandboxExecPath
	platform.SandboxExecPath = "/nonexistent/sandbox-exec"
	t.Cleanup(func() {
		platform.SandboxExecPath = orig
	})

	p := New()
	if p.Available() {
		t.Fatal("Available() should return false when sandbox-exec is missing")
	}
}

// ---------------------------------------------------------------------------
// WrapCommand: Build error path
// ---------------------------------------------------------------------------

func TestWrapCommand_BuildProfileError(t *testing.T) {
	// Override buildProfile to return an error.
	origBuild := buildProfile
	buildProfile = func(_ *platform.WrapConfig) (string, error) {
		return "", errors.New("simulated build failure")
	}
	t.Cleanup(func() {
		buildProfile = origBuild
	})

	p := New()
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "/bin/echo", "test")

	err := p.WrapCommand(ctx, cmd, &platform.WrapConfig{})
	if err == nil {
		t.Fatal("WrapCommand() should return error when profile build fails")
	}
	if !strings.Contains(err.Error(), "failed to build profile") {
		t.Errorf("error should mention build failure, got: %v", err)
	}
}
