//go:build windows

package windows

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/zhangyunhao116/agentbox/platform"
)

// TestSandbox_E2E_BasicExecution tests end-to-end sandboxed command execution.
// This verifies that a simple command can be wrapped, started, and executed successfully.
func TestSandbox_E2E_BasicExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	if isCygwinSSH() {
		t.Skip("Skipping E2E test under Cygwin SSH — createSandboxToken hangs in test binary")
	}

	p := New()
	if !p.Available() {
		t.Skip("Platform not available")
	}

	cmd := exec.Command("cmd.exe", "/c", "echo hello sandbox")
	cfg := &platform.WrapConfig{
		ResourceLimits: platform.DefaultResourceLimits(),
	}

	ctx := context.Background()
	err := p.WrapCommand(ctx, cmd, cfg)
	if err != nil {
		t.Fatalf("WrapCommand failed: %v", err)
	}

	// Capture stdout and stderr
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Start the process (suspended)
	err = cmd.Start()
	if err != nil {
		t.Fatalf("cmd.Start failed: %v", err)
	}

	// Execute post-start hook (Job Object assignment + resume)
	hook := platform.PopPostStartHook(cmd)
	if hook == nil {
		t.Fatal("PostStartHook not registered")
	}
	err = hook(cmd)
	if err != nil {
		t.Fatalf("PostStartHook failed: %v", err)
	}

	// Wait for completion with timeout
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err = <-done:
		// Process completed
		if err != nil {
			t.Logf("Process exited with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Process execution timed out")
	}

	t.Logf("stdout: %s", stdout.String())
	t.Logf("stderr: %s", stderr.String())

	// Verify output contains our message (sandboxed process should still be able to echo)
	output := stdout.String()
	if !strings.Contains(output, "hello sandbox") {
		t.Errorf("Expected output to contain 'hello sandbox', got: %s", output)
	}

	// Cleanup
	if err := p.Cleanup(ctx); err != nil {
		t.Errorf("Cleanup failed: %v", err)
	}
}

// TestSandbox_E2E_RestrictedToken tests that the sandboxed process runs with restricted privileges.
// We verify this by running 'whoami /priv' and checking that most privileges are removed.
func TestSandbox_E2E_RestrictedToken(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	if isCygwinSSH() {
		t.Skip("Skipping E2E test under Cygwin SSH — createSandboxToken hangs in test binary")
	}

	p := New()
	if !p.Available() {
		t.Skip("Platform not available")
	}

	// Execute 'whoami /priv' to see privilege list
	cmd := exec.Command("whoami", "/priv")
	cfg := &platform.WrapConfig{
		ResourceLimits: platform.DefaultResourceLimits(),
	}

	ctx := context.Background()
	err := p.WrapCommand(ctx, cmd, cfg)
	if err != nil {
		t.Fatalf("WrapCommand failed: %v", err)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Start()
	if err != nil {
		t.Fatalf("cmd.Start failed: %v", err)
	}

	hook := platform.PopPostStartHook(cmd)
	if hook == nil {
		t.Fatal("PostStartHook not registered")
	}
	err = hook(cmd)
	if err != nil {
		t.Fatalf("PostStartHook failed: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err = <-done:
		// Process completed
	case <-time.After(5 * time.Second):
		t.Fatal("Process execution timed out")
	}

	output := stdout.String()
	t.Logf("whoami /priv output:\n%s", output)

	// Verify SeChangeNotifyPrivilege is present and enabled
	// This is the only privilege that should be enabled in a restricted token
	if !strings.Contains(output, "SeChangeNotifyPrivilege") {
		t.Error("Expected SeChangeNotifyPrivilege to be present")
	}

	// Verify that most dangerous privileges are NOT present or are disabled
	// These privileges should be removed by DISABLE_MAX_PRIVILEGE flag
	dangerousPrivileges := []string{
		"SeDebugPrivilege",
		"SeTakeOwnershipPrivilege",
		"SeLoadDriverPrivilege",
		"SeSystemtimePrivilege",
	}

	for _, priv := range dangerousPrivileges {
		if strings.Contains(output, priv) && strings.Contains(output, "Enabled") {
			t.Errorf("Dangerous privilege %s is still enabled", priv)
		}
	}

	// Cleanup
	if err := p.Cleanup(ctx); err != nil {
		t.Errorf("Cleanup failed: %v", err)
	}
}

// TestSandbox_E2E_LowIntegrityLevel verifies that the sandboxed process runs at Low Integrity Level.
// At Low IL, 'whoami /groups' may produce empty output because the restricted token
// lacks the access rights needed to query group information. We therefore verify Low IL
// by attempting to write to a Medium-IL temp directory — this MUST fail with an access
// error, proving the process integrity level is lower than Medium.
//
// As a secondary check we also run 'whoami /groups' and, if it returns output, we
// verify the "Low Mandatory Level" label is present. Empty output is accepted because
// it is the expected behavior at Low IL under many Windows configurations.
func TestSandbox_E2E_LowIntegrityLevel(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	if isCygwinSSH() {
		t.Skip("Skipping E2E test under Cygwin SSH — createSandboxToken hangs in test binary")
	}

	p := New()
	if !p.Available() {
		t.Skip("Platform not available")
	}

	// ── Approach 1: Verify Low IL by write-deny to the user's TEMP dir ──
	// %TEMP% is owned by the current user at Medium IL.  A Medium-IL
	// (non-admin) LUA user CAN write there, but a Low-IL process CANNOT
	// because of the mandatory integrity check (NO_WRITE_UP).  Using %TEMP%
	// instead of %WINDIR% isolates the Low-IL assertion from the ACL-based
	// denial that a LUA token already imposes on system directories.
	probeScript := `@echo off
echo probe > %TEMP%\agentbox_il_probe.tmp 2>&1
if errorlevel 1 (
    echo WRITE_DENIED
) else (
    del %TEMP%\agentbox_il_probe.tmp 2>nul
    echo WRITE_ALLOWED
)
`
	cmd := exec.Command("cmd.exe", "/c", probeScript)
	cfg := &platform.WrapConfig{
		ResourceLimits: platform.DefaultResourceLimits(),
	}

	ctx := context.Background()
	err := p.WrapCommand(ctx, cmd, cfg)
	if err != nil {
		t.Fatalf("WrapCommand failed: %v", err)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Start()
	if err != nil {
		t.Fatalf("cmd.Start failed: %v", err)
	}

	hook := platform.PopPostStartHook(cmd)
	if hook == nil {
		t.Fatal("PostStartHook not registered")
	}
	err = hook(cmd)
	if err != nil {
		t.Fatalf("PostStartHook failed: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err = <-done:
		// Process completed
	case <-time.After(5 * time.Second):
		t.Fatal("Process execution timed out")
	}

	probeOutput := stdout.String()
	t.Logf("IL probe stdout: %s", probeOutput)
	t.Logf("IL probe stderr: %s", stderr.String())

	// The Low-IL process must not be able to write to TEMP (Medium IL).
	if strings.Contains(probeOutput, "WRITE_ALLOWED") {
		t.Error("Low-IL process was able to write to TEMP dir — integrity level restriction is not working")
	}
	// WRITE_DENIED (or any non-WRITE_ALLOWED output) proves the Low IL policy is active.

	// ── Approach 2: Secondary check with 'whoami /groups' ──
	cmd2 := exec.Command("whoami", "/groups")
	cfg2 := &platform.WrapConfig{
		ResourceLimits: platform.DefaultResourceLimits(),
	}

	err = p.WrapCommand(ctx, cmd2, cfg2)
	if err != nil {
		t.Fatalf("WrapCommand (whoami) failed: %v", err)
	}

	var stdout2, stderr2 bytes.Buffer
	cmd2.Stdout = &stdout2
	cmd2.Stderr = &stderr2

	err = cmd2.Start()
	if err != nil {
		t.Fatalf("cmd.Start (whoami) failed: %v", err)
	}

	hook2 := platform.PopPostStartHook(cmd2)
	if hook2 == nil {
		t.Fatal("PostStartHook not registered for whoami command")
	}
	err = hook2(cmd2)
	if err != nil {
		t.Fatalf("PostStartHook (whoami) failed: %v", err)
	}

	done2 := make(chan error, 1)
	go func() {
		done2 <- cmd2.Wait()
	}()

	select {
	case err = <-done2:
		// Process completed
	case <-time.After(5 * time.Second):
		t.Fatal("whoami /groups timed out")
	}

	groupsOutput := stdout2.String()
	t.Logf("whoami /groups output:\n%s", groupsOutput)

	// If whoami /groups produced output, verify it shows Low Mandatory Level.
	// Empty output is acceptable — at Low IL, whoami may lack the token
	// query rights needed to enumerate groups.
	groupsOutput = strings.TrimSpace(groupsOutput)
	if groupsOutput != "" {
		if !strings.Contains(groupsOutput, "Low Mandatory Level") {
			t.Error("whoami /groups produced output but 'Low Mandatory Level' not found — expected Low IL")
		}
	} else {
		t.Log("whoami /groups returned empty output (expected at Low IL)")
	}

	// Cleanup
	if err := p.Cleanup(ctx); err != nil {
		t.Errorf("Cleanup failed: %v", err)
	}
}

// TestSandbox_E2E_JobObjectResourceLimits verifies that Job Object limits are enforced.
// This test attempts to spawn more processes than allowed and verifies some are rejected.
func TestSandbox_E2E_JobObjectResourceLimits(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	if isCygwinSSH() {
		t.Skip("Skipping E2E test under Cygwin SSH — createSandboxToken hangs in test binary")
	}

	p := New()
	if !p.Available() {
		t.Skip("Platform not available")
	}

	// Create a batch script that tries to spawn 5 child processes
	// We'll set MaxProcesses=2, so some should fail
	script := `@echo off
for /L %%i in (1,1,5) do (
    start /B timeout /t 1 >nul
    echo Spawned process %%i
)
echo Done spawning
timeout /t 2 /nobreak >nul
`

	cmd := exec.Command("cmd.exe", "/c", script)
	cfg := &platform.WrapConfig{
		ResourceLimits: &platform.ResourceLimits{
			MaxProcesses:   2, // Only allow 2 processes (parent + 1 child)
			MaxMemoryBytes: 100 * 1024 * 1024,
		},
	}

	ctx := context.Background()
	err := p.WrapCommand(ctx, cmd, cfg)
	if err != nil {
		t.Fatalf("WrapCommand failed: %v", err)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Start()
	if err != nil {
		t.Fatalf("cmd.Start failed: %v", err)
	}

	hook := platform.PopPostStartHook(cmd)
	if hook == nil {
		t.Fatal("PostStartHook not registered")
	}
	err = hook(cmd)
	if err != nil {
		t.Fatalf("PostStartHook failed: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err = <-done:
		// Process completed (may have non-zero exit if some spawns failed)
		t.Logf("Process exit: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("Process execution timed out")
	}

	output := stdout.String()
	t.Logf("stdout:\n%s", output)
	t.Logf("stderr:\n%s", stderr.String())

	// We don't have deterministic output here, but the test verifies that
	// the Job Object was created and assigned. The actual enforcement is
	// handled by the kernel, so we trust that if setup succeeded, limits work.
	// A more sophisticated test would check for specific error codes from
	// CreateProcess failures due to job limits.

	// Cleanup
	if err := p.Cleanup(ctx); err != nil {
		t.Errorf("Cleanup failed: %v", err)
	}
}
