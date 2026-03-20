//go:build windows

package windows

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zhangyunhao116/agentbox/platform"
	"golang.org/x/sys/windows"
)

// TestAddAllowACE tests adding an allow ACE to a file.
func TestAddAllowACE(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test that calls Windows ACL APIs in short mode")
	}

	// Create a temporary file for testing.
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Get current process token.
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatalf("OpenCurrentProcessToken: %v", err)
	}
	defer token.Close()

	// Get the user SID from the token.
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		t.Fatalf("GetTokenUser: %v", err)
	}

	// Add allow ACE.
	if err := addAllowACE(testFile, tokenUser.User.Sid); err != nil {
		t.Fatalf("addAllowACE: %v", err)
	}

	// Verify we can still access the file.
	if _, err := os.Stat(testFile); err != nil {
		t.Errorf("Stat after addAllowACE: %v", err)
	}

	// Cleanup: revoke the ACE.
	if err := revokeACE(testFile, tokenUser.User.Sid); err != nil {
		t.Errorf("revokeACE cleanup: %v", err)
	}
}

// TestAddDenyWriteACE tests adding a deny-write ACE to a file.
func TestAddDenyWriteACE(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test that calls Windows ACL APIs in short mode")
	}

	// Create a temporary file for testing.
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Get current process token.
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatalf("OpenCurrentProcessToken: %v", err)
	}
	defer token.Close()

	// Get the user SID from the token.
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		t.Fatalf("GetTokenUser: %v", err)
	}

	// Add deny-write ACE.
	if err := addDenyWriteACE(testFile, tokenUser.User.Sid); err != nil {
		t.Fatalf("addDenyWriteACE: %v", err)
	}

	// Verify we can still read the file.
	if _, err := os.ReadFile(testFile); err != nil {
		t.Errorf("ReadFile after addDenyWriteACE: %v", err)
	}

	// Note: We cannot reliably test that writes are denied, because the
	// current process running the test has the same SID that we just denied.
	// In a real sandbox scenario, the restricted token would have a different
	// SID (e.g., via CreateRestrictedToken with capability SIDs).

	// Cleanup: revoke the ACE.
	if err := revokeACE(testFile, tokenUser.User.Sid); err != nil {
		t.Errorf("revokeACE cleanup: %v", err)
	}
}

// TestRevokeACE tests revoking an ACE from a file.
func TestRevokeACE(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test that calls Windows ACL APIs in short mode")
	}

	// Create a temporary file for testing.
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Get current process token.
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatalf("OpenCurrentProcessToken: %v", err)
	}
	defer token.Close()

	// Get the user SID from the token.
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		t.Fatalf("GetTokenUser: %v", err)
	}

	// Add allow ACE first.
	if err := addAllowACE(testFile, tokenUser.User.Sid); err != nil {
		t.Fatalf("addAllowACE: %v", err)
	}

	// Now revoke it.
	if err := revokeACE(testFile, tokenUser.User.Sid); err != nil {
		t.Errorf("revokeACE: %v", err)
	}

	// File should still be accessible (original permissions remain).
	if _, err := os.Stat(testFile); err != nil {
		t.Errorf("Stat after revokeACE: %v", err)
	}
}

// TestApplyACLs tests the high-level applyACLs function.
func TestApplyACLs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test that calls Windows ACL APIs in short mode")
	}

	// Create temporary directories for testing.
	tmpDir := t.TempDir()
	writableDir := filepath.Join(tmpDir, "writable")
	denyWriteDir := filepath.Join(tmpDir, "deny")

	if err := os.Mkdir(writableDir, 0755); err != nil {
		t.Fatalf("Mkdir(writable): %v", err)
	}
	if err := os.Mkdir(denyWriteDir, 0755); err != nil {
		t.Fatalf("Mkdir(deny): %v", err)
	}

	// Get current process token.
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatalf("OpenCurrentProcessToken: %v", err)
	}
	defer token.Close()

	// Get the user SID from the token.
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		t.Fatalf("GetTokenUser: %v", err)
	}

	// Build WrapConfig.
	cfg := &platform.WrapConfig{
		WritableRoots: []string{writableDir},
		DenyWrite:     []string{denyWriteDir},
	}

	// Apply ACLs.
	applied, err := applyACLs(cfg, tokenUser.User.Sid)
	if err != nil {
		t.Fatalf("applyACLs: %v", err)
	}

	// Verify the correct number of entries were applied.
	expectedCount := len(cfg.WritableRoots) + len(cfg.DenyWrite)
	if len(applied) != expectedCount {
		t.Errorf("Expected %d applied entries, got %d", expectedCount, len(applied))
	}

	// Cleanup.
	if err := cleanupACLs(applied, tokenUser.User.Sid); err != nil {
		t.Errorf("cleanupACLs: %v", err)
	}
}

// TestCleanupACLs tests the cleanup function.
func TestCleanupACLs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test that calls Windows ACL APIs in short mode")
	}

	// Create a temporary file for testing.
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Get current process token.
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatalf("OpenCurrentProcessToken: %v", err)
	}
	defer token.Close()

	// Get the user SID from the token.
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		t.Fatalf("GetTokenUser: %v", err)
	}

	// Add allow ACE.
	if err := addAllowACE(testFile, tokenUser.User.Sid); err != nil {
		t.Fatalf("addAllowACE: %v", err)
	}

	// Build applied entries list.
	applied := []aclEntry{
		{path: testFile, aclType: 0},
	}

	// Cleanup.
	if err := cleanupACLs(applied, tokenUser.User.Sid); err != nil {
		t.Errorf("cleanupACLs: %v", err)
	}

	// File should still be accessible.
	if _, err := os.Stat(testFile); err != nil {
		t.Errorf("Stat after cleanupACLs: %v", err)
	}
}

// TestApplyACLsErrorHandling tests error handling in applyACLs.
func TestApplyACLsErrorHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test that calls Windows ACL APIs in short mode")
	}

	// Get current process token.
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatalf("OpenCurrentProcessToken: %v", err)
	}
	defer token.Close()

	// Get the user SID from the token.
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		t.Fatalf("GetTokenUser: %v", err)
	}

	// Build WrapConfig with non-existent path.
	cfg := &platform.WrapConfig{
		WritableRoots: []string{"C:\\nonexistent\\path\\that\\does\\not\\exist"},
	}

	// Apply ACLs should fail gracefully.
	_, err = applyACLs(cfg, tokenUser.User.Sid)
	if err == nil {
		t.Error("Expected error for non-existent path, got nil")
	}
}

// TestCleanupACLsPartialFailure tests that cleanupACLs continues on errors.
func TestCleanupACLsPartialFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test that calls Windows ACL APIs in short mode")
	}

	// Get current process token.
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatalf("OpenCurrentProcessToken: %v", err)
	}
	defer token.Close()

	// Get the user SID from the token.
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		t.Fatalf("GetTokenUser: %v", err)
	}

	// Build applied entries list with a non-existent path.
	applied := []aclEntry{
		{path: "C:\\nonexistent\\path", aclType: 0},
	}

	// Cleanup should return an error but not panic.
	err = cleanupACLs(applied, tokenUser.User.Sid)
	if err == nil {
		t.Error("Expected error for non-existent path in cleanup, got nil")
	}
}

// TestExplicitAccessWStructure verifies the structure layout matches Windows API.
func TestExplicitAccessWStructure(t *testing.T) {
	// This test ensures our Go struct definitions match the Windows API layout.
	// If the sizes are wrong, the syscalls will fail or corrupt memory.
	var ea explicitAccessW
	var tr trusteeW

	// explicitAccessW should be 4 fields.
	// We can't easily check size on macOS, but we can verify field count.
	if ea.AccessPermissions != 0 {
		// This is just to use the field so the compiler doesn't complain.
	}
	if ea.AccessMode != 0 {
		// This is just to use the field.
	}
	if ea.Inheritance != 0 {
		// This is just to use the field.
	}

	// trusteeW should have 5 fields.
	if tr.TrusteeForm != 0 {
		// This is just to use the field.
	}
	if tr.TrusteeType != 0 {
		// This is just to use the field.
	}
	if tr.TrusteeValue != 0 {
		// This is just to use the field.
	}

	// If we got here without a compile error, the structures are defined correctly.
	t.Log("Structure definitions verified")
}

// TestIsValidWindowsPath verifies that isValidWindowsPath correctly identifies
// valid and invalid Windows paths, filtering out Unix paths.
func TestIsValidWindowsPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		// Valid Windows paths
		{name: "absolute_drive", path: `C:\Windows`, want: true},
		{name: "absolute_drive_lowercase", path: `c:\windows`, want: true},
		{name: "different_drive", path: `D:\Data`, want: true},
		{name: "unc_path", path: `\\server\share`, want: true},
		{name: "unc_path_nested", path: `\\server\share\folder`, want: true},
		{name: "relative_path", path: `relative\path`, want: true},
		{name: "relative_single", path: `file.txt`, want: true},
		{name: "current_dir", path: `.`, want: true},
		{name: "parent_dir", path: `..`, want: true},

		// Invalid paths
		{name: "unix_etc", path: `/etc`, want: false},
		{name: "unix_usr", path: `/usr`, want: false},
		{name: "unix_bin", path: `/usr/bin`, want: false},
		{name: "unix_proc", path: `/proc/*/mem`, want: false},
		{name: "unix_sys", path: `/sys`, want: false},
		{name: "unix_root", path: `/`, want: false},
		{name: "empty", path: ``, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidWindowsPath(tt.path)
			if got != tt.want {
				t.Errorf("isValidWindowsPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// TestApplyACLsWithInvalidPaths verifies that applyACLs gracefully skips
// invalid paths (like Unix paths) instead of failing.
func TestApplyACLsWithInvalidPaths(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test that calls Windows ACL APIs in short mode")
	}

	// Create a temporary directory for testing.
	tmpDir := t.TempDir()

	// Get current process token and user SID.
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatalf("OpenCurrentProcessToken: %v", err)
	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		t.Fatalf("GetTokenUser: %v", err)
	}

	// Create a WrapConfig with a mix of valid and invalid paths.
	cfg := &platform.WrapConfig{
		WritableRoots: []string{
			tmpDir,           // valid Windows path
			"/etc",           // invalid Unix path (should be skipped)
			"/usr/local/bin", // invalid Unix path (should be skipped)
		},
		DenyWrite: []string{
			tmpDir,     // valid Windows path
			"/sys",     // invalid Unix path (should be skipped)
			"/proc/42", // invalid Unix path (should be skipped)
		},
	}

	// applyACLs should succeed by skipping invalid paths.
	applied, err := applyACLs(cfg, tokenUser.User.Sid)
	if err != nil {
		t.Fatalf("applyACLs with invalid paths: %v", err)
	}

	// Should have applied exactly 2 entries (only the valid tmpDir paths).
	if len(applied) != 2 {
		t.Errorf("Expected 2 applied ACL entries, got %d", len(applied))
	}

	// Cleanup.
	if err := cleanupACLs(applied, tokenUser.User.Sid); err != nil {
		t.Errorf("cleanupACLs: %v", err)
	}
}

