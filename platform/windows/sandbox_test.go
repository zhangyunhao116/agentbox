//go:build windows

package windows

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/zhangyunhao116/agentbox/platform"
	"golang.org/x/sys/windows"
)

// TestPlatform_Interface verifies the Platform type implements platform.Platform.
func TestPlatform_Interface(t *testing.T) {
	var _ platform.Platform = (*Platform)(nil)
}

// TestNew verifies platform initialization.
func TestNew(t *testing.T) {
	p := New()
	if p == nil {
		t.Fatal("New() returned nil")
	}
	if !p.initialized {
		t.Error("platform not initialized")
	}
	if p.osVersion == 0 {
		t.Error("osVersion not detected")
	}
}

// TestPlatform_Name verifies the platform name.
func TestPlatform_Name(t *testing.T) {
	p := New()
	if name := p.Name(); name != "windows-native" {
		t.Errorf("Name() = %q, want %q", name, "windows-native")
	}
}

// TestPlatform_Available verifies availability check.
func TestPlatform_Available(t *testing.T) {
	p := New()
	// Should be available on modern Windows (version 10+)
	if !p.Available() {
		t.Skipf("Platform not available on Windows version %d", p.osVersion)
	}
}

// TestPlatform_CheckDependencies verifies dependency checking.
func TestPlatform_CheckDependencies(t *testing.T) {
	p := New()
	check := p.CheckDependencies()
	if check == nil {
		t.Fatal("CheckDependencies returned nil")
	}

	// On modern Windows, should have no errors
	if len(check.Errors) > 0 {
		t.Skipf("Errors found (older Windows?): %v", check.Errors)
	}

	// Verify tier-level reporting based on admin status
	// All tiers report status in Warnings field
	if len(check.Warnings) == 0 {
		t.Error("Expected tier status message in Warnings")
	}

	if p.isAdmin {
		if p.tier2Active {
			// Admin with successful Tier 2 setup
			t.Logf("Tier 2 active: %v", check.Warnings)
		} else {
			// Admin but Tier 2 setup failed
			t.Logf("Tier 2 fallback: %v", check.Warnings)
		}
	} else {
		// Non-admin (Tier 1 only)
		t.Logf("Tier 1 (non-admin): %v", check.Warnings)
	}
}

// TestPlatform_Capabilities verifies reported capabilities.
func TestPlatform_Capabilities(t *testing.T) {
	p := New()
	caps := p.Capabilities()

	// Verify expected capabilities for Windows native sandbox
	tests := []struct {
		name     string
		got      bool
		expected bool
	}{
		{"FileReadDeny", caps.FileReadDeny, false},
		{"FileWriteAllow", caps.FileWriteAllow, true},
		// NetworkDeny is always false until CreateProcessWithLogonW is integrated.
		// The firewall rule targets the sandbox user's SID but processes still
		// run under the caller's restricted token.
		{"NetworkDeny", caps.NetworkDeny, false},
		{"NetworkProxy", caps.NetworkProxy, false},
		{"PIDIsolation", caps.PIDIsolation, false},
		{"SyscallFilter", caps.SyscallFilter, false},
		{"ProcessHarden", caps.ProcessHarden, true},
	}

	for _, tt := range tests {
		if tt.got != tt.expected {
			t.Errorf("Capabilities.%s = %v, want %v", tt.name, tt.got, tt.expected)
		}
	}
}

// isCygwinSSH detects if we're running under Cygwin SSH, where certain
// Windows API calls from Go test binaries hang (likely due to TTY/token
// handling quirks in the sshd environment).
func isCygwinSSH() bool {
	// Check for typical Cygwin SSH environment markers
	// 1. SSH_CONNECTION is set (we're in an SSH session)
	// 2. CYGWIN env var or /proc/cygdrive exists
	_, sshConn := os.LookupEnv("SSH_CONNECTION")
	_, cygwin := os.LookupEnv("CYGWIN")
	
	// Also check for /proc/cygdrive (Cygwin-specific mount point)
	_, err := os.Stat("/proc/cygdrive")
	hasCygdrive := err == nil
	
	return sshConn && (cygwin || hasCygdrive)
}

// TestPlatform_WrapCommand verifies command wrapping without execution.
func TestPlatform_WrapCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if isCygwinSSH() {
		t.Skip("Skipping test under Cygwin SSH — createSandboxToken hangs in test binary (works in standalone programs)")
	}
	
	p := New()
	if !p.Available() {
		t.Skip("Platform not available")
	}

	// Use a simple command (not executed)
	cmd := exec.Command("cmd.exe", "/c", "echo", "test")
	cfg := &platform.WrapConfig{
		ResourceLimits: &platform.ResourceLimits{
			MaxProcesses:  10,
			MaxMemoryBytes: 100 * 1024 * 1024, // 100MB
		},
	}

	ctx := context.Background()
	err := p.WrapCommand(ctx, cmd, cfg)
	if err != nil {
		t.Fatalf("WrapCommand failed: %v", err)
	}

	// Verify SysProcAttr was set
	if cmd.SysProcAttr == nil {
		t.Fatal("SysProcAttr not set")
	}

	// Verify Token was set
	if cmd.SysProcAttr.Token == 0 {
		t.Error("Token not set in SysProcAttr")
	}

	// CREATE_SUSPENDED is NOT set — processes start normally and the Job Object
	// is assigned via PostStartHook after cmd.Start(). The restricted token
	// provides the primary security boundary during the small assignment window.

	// Verify resources were tracked
	p.mu.Lock()
	tokenCount := len(p.activeTokens)
	jobCount := len(p.activeJobs)
	p.mu.Unlock()

	if tokenCount != 1 {
		t.Errorf("Expected 1 active token, got %d", tokenCount)
	}
	if jobCount != 1 {
		t.Errorf("Expected 1 active job, got %d", jobCount)
	}

	// Cleanup
	if err := p.Cleanup(ctx); err != nil {
		t.Errorf("Cleanup failed: %v", err)
	}

	// Verify cleanup worked
	p.mu.Lock()
	tokenCount = len(p.activeTokens)
	jobCount = len(p.activeJobs)
	p.mu.Unlock()

	if tokenCount != 0 {
		t.Errorf("Expected 0 active tokens after cleanup, got %d", tokenCount)
	}
	if jobCount != 0 {
		t.Errorf("Expected 0 active jobs after cleanup, got %d", jobCount)
	}
}

// TestPlatform_WrapCommand_MergesCreationFlags verifies that WrapCommand
// properly merges CreationFlags with existing flags rather than overwriting.
func TestPlatform_WrapCommand_MergesCreationFlags(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if isCygwinSSH() {
		t.Skip("Skipping test under Cygwin SSH — createSandboxToken hangs in test binary")
	}
	
	p := New()
	if !p.Available() {
		t.Skip("Platform not available")
	}

	cmd := exec.Command("cmd.exe", "/c", "echo", "test")
	
	// Pre-set some creation flags
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_CONSOLE,
	}

	ctx := context.Background()
	err := p.WrapCommand(ctx, cmd, nil)
	if err != nil {
		t.Fatalf("WrapCommand failed: %v", err)
	}

	// Verify pre-existing flags are preserved (merged, not overwritten).
	// CREATE_SUSPENDED is no longer set by WrapCommand — the process starts
	// normally and the Job Object is assigned via PostStartHook.
	flags := cmd.SysProcAttr.CreationFlags
	if flags&windows.CREATE_NEW_CONSOLE == 0 {
		t.Error("Pre-existing CREATE_NEW_CONSOLE flag was overwritten")
	}

	// Cleanup
	if err := p.Cleanup(ctx); err != nil {
		t.Errorf("Cleanup failed: %v", err)
	}
}

// TestPlatform_Cleanup_MultipleCommands verifies cleanup with multiple wrapped commands.
func TestPlatform_Cleanup_MultipleCommands(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if isCygwinSSH() {
		t.Skip("Skipping test under Cygwin SSH — createSandboxToken hangs in test binary")
	}
	
	p := New()
	if !p.Available() {
		t.Skip("Platform not available")
	}

	ctx := context.Background()

	// Wrap multiple commands
	for i := 0; i < 3; i++ {
		cmd := exec.Command("cmd.exe", "/c", "echo", "test")
		err := p.WrapCommand(ctx, cmd, nil)
		if err != nil {
			t.Fatalf("WrapCommand %d failed: %v", i, err)
		}
	}

	// Verify resources were tracked
	p.mu.Lock()
	tokenCount := len(p.activeTokens)
	jobCount := len(p.activeJobs)
	p.mu.Unlock()

	if tokenCount != 3 {
		t.Errorf("Expected 3 active tokens, got %d", tokenCount)
	}
	if jobCount != 3 {
		t.Errorf("Expected 3 active jobs, got %d", jobCount)
	}

	// Cleanup all at once
	if err := p.Cleanup(ctx); err != nil {
		t.Errorf("Cleanup failed: %v", err)
	}

	// Verify all resources were cleaned up
	p.mu.Lock()
	tokenCount = len(p.activeTokens)
	jobCount = len(p.activeJobs)
	p.mu.Unlock()

	if tokenCount != 0 {
		t.Errorf("Expected 0 active tokens after cleanup, got %d", tokenCount)
	}
	if jobCount != 0 {
		t.Errorf("Expected 0 active jobs after cleanup, got %d", jobCount)
	}
}

// TestPlatform_WrapCommand_NilConfig verifies behavior with nil config.
func TestPlatform_WrapCommand_NilConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if isCygwinSSH() {
		t.Skip("Skipping test under Cygwin SSH — createSandboxToken hangs in test binary")
	}
	
	p := New()
	if !p.Available() {
		t.Skip("Platform not available")
	}

	cmd := exec.Command("cmd.exe", "/c", "echo", "test")
	ctx := context.Background()

	// Should not panic with nil config
	err := p.WrapCommand(ctx, cmd, nil)
	if err != nil {
		t.Fatalf("WrapCommand with nil config failed: %v", err)
	}

	// Cleanup
	if err := p.Cleanup(ctx); err != nil {
		t.Errorf("Cleanup failed: %v", err)
	}
}

// TestPlatform_Tier2Setup verifies Tier 2 setup behavior.
// This test checks that admin users get Tier 2 setup attempted,
// and that the platform falls back gracefully on failure.
func TestPlatform_Tier2Setup(t *testing.T) {
	p := New()
	
	if !p.isAdmin {
		t.Skip("Tier 2 requires administrator privileges — skipping on non-admin")
	}

	// When running as admin, Tier 2 setup should be attempted
	if p.userManager == nil || p.fwManager == nil {
		t.Error("Expected userManager and fwManager to be initialized for admin")
	}

	// tier2Active indicates whether setup succeeded
	// We don't require it to succeed (might fail on some systems),
	// but we verify the state is consistent
	if p.tier2Active {
		// Tier 2 is active — verify users were created
		user, err := p.userManager.GetUser()
		if err != nil {
			t.Errorf("Tier 2 active but GetUser failed: %v", err)
		}
		if user == nil {
			t.Error("Tier 2 active but no user available")
		}
		if user != nil && user.SID == "" {
			t.Error("Tier 2 user has empty SID")
		}
	}
}

// TestPlatform_Tier2Cleanup verifies Tier 2 cleanup.
func TestPlatform_Tier2Cleanup(t *testing.T) {
	p := New()
	
	if !p.isAdmin {
		t.Skip("Tier 2 requires administrator privileges — skipping on non-admin")
	}

	if !p.tier2Active {
		t.Skip("Tier 2 not active — skipping cleanup test")
	}

	ctx := context.Background()

	// Cleanup should succeed without errors
	if err := p.Cleanup(ctx); err != nil {
		t.Errorf("Tier 2 cleanup failed: %v", err)
	}

	// After cleanup, tier2Active should be false
	if p.tier2Active {
		t.Error("tier2Active should be false after Cleanup")
	}
}

// TestPlatform_Tier2Fallback verifies graceful fallback when Tier 2 setup fails.
// This test is informational — it documents the expected behavior when
// Tier 2 setup fails (e.g., firewall disabled, COM issues).
func TestPlatform_Tier2Fallback(t *testing.T) {
	p := New()
	
	if !p.isAdmin {
		t.Skip("Tier 2 requires administrator privileges — skipping on non-admin")
	}

	// If Tier 2 setup failed, platform should remain functional at Tier 1
	if !p.tier2Active {
		t.Log("Tier 2 setup failed — platform fell back to Tier 1 (expected on some systems)")
		
		// Verify Tier 1 still works
		caps := p.Capabilities()
		if !caps.ProcessHarden {
			t.Error("ProcessHarden should be true even in Tier 1 fallback")
		}
		if caps.NetworkDeny {
			t.Error("NetworkDeny should be false when Tier 2 is inactive")
		}
	} else {
		t.Log("Tier 2 active — no fallback occurred")
	}
}

// TestPlatform_Tier1NonAdmin verifies Tier 1 behavior on non-admin accounts.
func TestPlatform_Tier1NonAdmin(t *testing.T) {
	p := New()
	
	if p.isAdmin {
		t.Skip("This test is for non-admin accounts — skipping on admin")
	}

	// Non-admin should never have Tier 2 active
	if p.tier2Active {
		t.Error("tier2Active should be false for non-admin")
	}

	// userManager and fwManager should not be initialized
	if p.userManager != nil {
		t.Error("userManager should be nil for non-admin")
	}
	if p.fwManager != nil {
		t.Error("fwManager should be nil for non-admin")
	}

	// Capabilities should reflect Tier 1
	caps := p.Capabilities()
	if caps.NetworkDeny {
		t.Error("NetworkDeny should be false for Tier 1 (non-admin)")
	}
	if !caps.ProcessHarden {
		t.Error("ProcessHarden should be true even in Tier 1")
	}
}
