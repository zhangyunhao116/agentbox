//go:build linux

package linux

import (
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/zhangyunhao116/agentbox/platform"
)

// saveLandlockFns saves all function variables and returns a restore function.
func saveLandlockFns(t *testing.T) {
	t.Helper()
	origCreate := landlockCreateRulesetFn
	origAddRule := landlockAddRuleFn
	origRestrict := landlockRestrictSelfFn
	origOpen := openPathFn
	origClose := closePathFn
	origStat := statPathFn
	t.Cleanup(func() {
		landlockCreateRulesetFn = origCreate
		landlockAddRuleFn = origAddRule
		landlockRestrictSelfFn = origRestrict
		openPathFn = origOpen
		closePathFn = origClose
		statPathFn = origStat
	})
}

// mockAllSuccess sets up all mocks to simulate a successful Landlock environment.
// The createRuleset mock distinguishes between version query (flags=1) and
// ruleset creation (flags=0) using a call counter.
func mockAllSuccess(t *testing.T, abiVersion uintptr) {
	t.Helper()
	var createCalls atomic.Int64
	landlockCreateRulesetFn = func(attr, size, flags uintptr) (uintptr, uintptr, syscall.Errno) {
		n := createCalls.Add(1)
		if n == 1 {
			// First call: version query from DetectLandlock (flags=1).
			return abiVersion, 0, 0
		}
		// Subsequent calls: ruleset creation (flags=0), return fake fd.
		return 42, 0, 0
	}
	landlockAddRuleFn = func(rulesetFd, ruleType, ruleAttr, flags, _, _ uintptr) (uintptr, uintptr, syscall.Errno) {
		return 0, 0, 0
	}
	landlockRestrictSelfFn = func(rulesetFd, flags, _ uintptr) (uintptr, uintptr, syscall.Errno) {
		return 0, 0, 0
	}
	openPathFn = func(path string, flags int, mode uint32) (int, error) {
		return 10, nil
	}
	closePathFn = func(fd int) error {
		return nil
	}
	statPathFn = func(path string) (os.FileInfo, error) {
		return nil, nil // Stat succeeds for all paths.
	}
}

// ---------------------------------------------------------------------------
// DetectLandlock tests
// ---------------------------------------------------------------------------

// TestDetectLandlock_Supported_ABIv1 verifies ABI v1 detection.
func TestDetectLandlock_Supported_ABIv1(t *testing.T) {
	saveLandlockFns(t)
	landlockCreateRulesetFn = func(attr, size, flags uintptr) (uintptr, uintptr, syscall.Errno) {
		return 1, 0, 0
	}

	info := DetectLandlock()
	if !info.Supported {
		t.Fatal("expected Supported=true")
	}
	if info.ABIVersion != 1 {
		t.Fatalf("expected ABIVersion=1, got %d", info.ABIVersion)
	}
	if !strings.Contains(info.Features, "fs access") {
		t.Fatalf("expected Features to contain 'fs access', got %q", info.Features)
	}
	// v1 should NOT contain "refer" or "truncate".
	if strings.Contains(info.Features, "refer") {
		t.Fatalf("v1 Features should not contain 'refer', got %q", info.Features)
	}
}

// TestDetectLandlock_Supported_ABIv2 verifies ABI v2 detection.
func TestDetectLandlock_Supported_ABIv2(t *testing.T) {
	saveLandlockFns(t)
	landlockCreateRulesetFn = func(attr, size, flags uintptr) (uintptr, uintptr, syscall.Errno) {
		return 2, 0, 0
	}

	info := DetectLandlock()
	if !info.Supported {
		t.Fatal("expected Supported=true")
	}
	if info.ABIVersion != 2 {
		t.Fatalf("expected ABIVersion=2, got %d", info.ABIVersion)
	}
	if !strings.Contains(info.Features, "refer") {
		t.Fatalf("expected Features to contain 'refer', got %q", info.Features)
	}
	if !strings.Contains(info.Features, "fs access") {
		t.Fatalf("expected Features to contain 'fs access', got %q", info.Features)
	}
	// v2 should NOT contain "truncate".
	if strings.Contains(info.Features, "truncate") {
		t.Fatalf("v2 Features should not contain 'truncate', got %q", info.Features)
	}
}

// TestDetectLandlock_Supported_ABIv3 verifies ABI v3 detection.
func TestDetectLandlock_Supported_ABIv3(t *testing.T) {
	saveLandlockFns(t)
	landlockCreateRulesetFn = func(attr, size, flags uintptr) (uintptr, uintptr, syscall.Errno) {
		return 3, 0, 0
	}

	info := DetectLandlock()
	if !info.Supported {
		t.Fatal("expected Supported=true")
	}
	if info.ABIVersion != 3 {
		t.Fatalf("expected ABIVersion=3, got %d", info.ABIVersion)
	}
	if !strings.Contains(info.Features, "truncate") {
		t.Fatalf("expected Features to contain 'truncate', got %q", info.Features)
	}
	if !strings.Contains(info.Features, "refer") {
		t.Fatalf("expected Features to contain 'refer', got %q", info.Features)
	}
	if !strings.Contains(info.Features, "fs access") {
		t.Fatalf("expected Features to contain 'fs access', got %q", info.Features)
	}
}

// TestDetectLandlock_NotSupported verifies ENOSYS returns unsupported.
func TestDetectLandlock_NotSupported(t *testing.T) {
	saveLandlockFns(t)
	landlockCreateRulesetFn = func(attr, size, flags uintptr) (uintptr, uintptr, syscall.Errno) {
		return 0, 0, syscall.ENOSYS
	}

	info := DetectLandlock()
	if info.Supported {
		t.Fatal("expected Supported=false")
	}
	if info.ABIVersion != 0 {
		t.Fatalf("expected ABIVersion=0, got %d", info.ABIVersion)
	}
	if !strings.Contains(info.Features, "landlock not available") {
		t.Fatalf("expected Features to contain 'landlock not available', got %q", info.Features)
	}
}

// ---------------------------------------------------------------------------
// applyLandlock tests
// ---------------------------------------------------------------------------

// TestApplyLandlock_UnsupportedKernel verifies fail-closed error when unsupported.
func TestApplyLandlock_UnsupportedKernel(t *testing.T) {
	saveLandlockFns(t)
	landlockCreateRulesetFn = func(attr, size, flags uintptr) (uintptr, uintptr, syscall.Errno) {
		return 0, 0, syscall.ENOSYS
	}

	cfg := &platform.WrapConfig{}
	err := applyLandlock(cfg)
	if err == nil {
		t.Fatal("expected error for unsupported kernel, got nil")
	}
	if !strings.Contains(err.Error(), "landlock not available") {
		t.Fatalf("expected error to mention 'landlock not available', got: %v", err)
	}
	if !strings.Contains(err.Error(), "kernel >= 5.13") {
		t.Fatalf("expected error to mention 'kernel >= 5.13', got: %v", err)
	}
}

// TestApplyLandlock_CreateRulesetError verifies error when ruleset creation fails.
func TestApplyLandlock_CreateRulesetError(t *testing.T) {
	saveLandlockFns(t)
	var createCalls atomic.Int64
	landlockCreateRulesetFn = func(attr, size, flags uintptr) (uintptr, uintptr, syscall.Errno) {
		n := createCalls.Add(1)
		if n == 1 {
			// Version query succeeds (ABI v1).
			return 1, 0, 0
		}
		// Ruleset creation fails.
		return 0, 0, syscall.ENOMEM
	}

	cfg := &platform.WrapConfig{}
	err := applyLandlock(cfg)
	if err == nil {
		t.Fatal("expected error for create_ruleset failure")
	}
	if !strings.Contains(err.Error(), "landlock_create_ruleset") {
		t.Fatalf("expected error to mention 'landlock_create_ruleset', got: %v", err)
	}
}

// TestApplyLandlock_WritableRoots verifies writable roots are added with write access.
func TestApplyLandlock_WritableRoots(t *testing.T) {
	saveLandlockFns(t)
	mockAllSuccess(t, 1)

	var addRulePaths []string
	origOpen := openPathFn
	openPathFn = func(path string, flags int, mode uint32) (int, error) {
		addRulePaths = append(addRulePaths, path)
		return origOpen(path, flags, mode)
	}

	cfg := &platform.WrapConfig{
		WritableRoots: []string{"/tmp"},
	}
	err := applyLandlock(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// /tmp should be in the paths that were opened for rule addition.
	found := false
	for _, p := range addRulePaths {
		if p == "/tmp" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected /tmp in addRulePaths, got: %v", addRulePaths)
	}
}

// TestApplyLandlock_DenyWriteOverride verifies DenyWrite overrides WritableRoots to read-only.
func TestApplyLandlock_DenyWriteOverride(t *testing.T) {
	saveLandlockFns(t)
	mockAllSuccess(t, 1)

	openPathFn = func(path string, flags int, mode uint32) (int, error) {
		return 10, nil
	}
	landlockAddRuleFn = func(rulesetFd, ruleType, ruleAttr, flags, _, _ uintptr) (uintptr, uintptr, syscall.Errno) {
		return 0, 0, 0
	}

	// We track via openPathFn which paths are opened.
	var openedPaths []string
	openPathFn = func(path string, flags int, mode uint32) (int, error) {
		openedPaths = append(openedPaths, path)
		return 10, nil
	}

	cfg := &platform.WrapConfig{
		WritableRoots: []string{"/tmp"},
		DenyWrite:     []string{"/tmp"},
	}
	err := applyLandlock(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// /tmp should still be opened (as read-only rule).
	found := false
	for _, p := range openedPaths {
		if p == "/tmp" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected /tmp to be opened for read-only rule, got: %v", openedPaths)
	}
}

// TestApplyLandlock_DenyRead verifies DenyRead paths are excluded from system paths.
func TestApplyLandlock_DenyRead(t *testing.T) {
	saveLandlockFns(t)
	mockAllSuccess(t, 1)

	var openedPaths []string
	openPathFn = func(path string, flags int, mode uint32) (int, error) {
		openedPaths = append(openedPaths, path)
		return 10, nil
	}

	cfg := &platform.WrapConfig{
		DenyRead: []string{"/usr", "/lib"},
	}
	err := applyLandlock(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// /usr and /lib should NOT be in the opened paths.
	for _, p := range openedPaths {
		if p == "/usr" || p == "/lib" {
			t.Fatalf("DenyRead path %q should not have been opened, got: %v", p, openedPaths)
		}
	}
}

// TestApplyLandlock_RestrictSelfError verifies error when restrict_self fails.
func TestApplyLandlock_RestrictSelfError(t *testing.T) {
	saveLandlockFns(t)
	mockAllSuccess(t, 1)

	landlockRestrictSelfFn = func(rulesetFd, flags, _ uintptr) (uintptr, uintptr, syscall.Errno) {
		return 0, 0, syscall.EPERM
	}

	cfg := &platform.WrapConfig{}
	err := applyLandlock(cfg)
	if err == nil {
		t.Fatal("expected error for restrict_self failure")
	}
	if !strings.Contains(err.Error(), "landlock_restrict_self") {
		t.Fatalf("expected error to mention 'landlock_restrict_self', got: %v", err)
	}
}

// TestApplyLandlock_SystemPaths verifies system paths are added with read access.
func TestApplyLandlock_SystemPaths(t *testing.T) {
	saveLandlockFns(t)
	mockAllSuccess(t, 1)

	var openedPaths []string
	openPathFn = func(path string, flags int, mode uint32) (int, error) {
		openedPaths = append(openedPaths, path)
		return 10, nil
	}

	cfg := &platform.WrapConfig{}
	err := applyLandlock(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// System paths that exist should be in the opened paths.
	expectedPaths := []string{"/usr", "/lib", "/etc", "/bin", "/sbin", "/proc", "/dev"}
	for _, ep := range expectedPaths {
		if _, err := os.Stat(ep); err != nil {
			continue // Path doesn't exist on this system.
		}
		found := false
		for _, p := range openedPaths {
			if p == ep {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected system path %q in opened paths, got: %v", ep, openedPaths)
		}
	}
}

// TestApplyLandlock_ABIv2Access verifies ABI v2 adds refer access.
func TestApplyLandlock_ABIv2Access(t *testing.T) {
	saveLandlockFns(t)
	mockAllSuccess(t, 2)

	cfg := &platform.WrapConfig{
		WritableRoots: []string{"/tmp"},
	}
	err := applyLandlock(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestApplyLandlock_ABIv3Access verifies ABI v3 adds truncate access.
func TestApplyLandlock_ABIv3Access(t *testing.T) {
	saveLandlockFns(t)
	mockAllSuccess(t, 3)

	cfg := &platform.WrapConfig{
		WritableRoots: []string{"/tmp"},
	}
	err := applyLandlock(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestApplyLandlock_StatFails verifies that stat failure skips the path.
func TestApplyLandlock_StatFails(t *testing.T) {
	saveLandlockFns(t)
	mockAllSuccess(t, 1)

	// Make stat fail for all paths so system paths are skipped.
	statPathFn = func(path string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}

	var openedPaths []string
	openPathFn = func(path string, flags int, mode uint32) (int, error) {
		openedPaths = append(openedPaths, path)
		return 10, nil
	}

	cfg := &platform.WrapConfig{}
	err := applyLandlock(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No system paths should have been opened since stat failed for all.
	systemPaths := []string{"/usr", "/lib", "/lib64", "/etc", "/bin", "/sbin", "/proc", "/dev"}
	for _, sp := range systemPaths {
		for _, p := range openedPaths {
			if p == sp {
				t.Errorf("system path %q should not have been opened when stat fails", sp)
			}
		}
	}
}

// TestApplyLandlock_AddRuleErrorForSystemPath verifies non-fatal error for system path rule.
func TestApplyLandlock_AddRuleErrorForSystemPath(t *testing.T) {
	saveLandlockFns(t)
	mockAllSuccess(t, 1)

	// Make addRule fail for system paths (non-fatal).
	landlockAddRuleFn = func(rulesetFd, ruleType, ruleAttr, flags, _, _ uintptr) (uintptr, uintptr, syscall.Errno) {
		return 0, 0, syscall.EINVAL
	}

	cfg := &platform.WrapConfig{}
	err := applyLandlock(cfg)
	if err != nil {
		t.Fatalf("expected nil error (non-fatal system path errors), got: %v", err)
	}
}

// TestApplyLandlock_WritableRootAddRuleError verifies error when adding writable root rule fails.
func TestApplyLandlock_WritableRootAddRuleError(t *testing.T) {
	saveLandlockFns(t)
	mockAllSuccess(t, 1)

	// Make openPathFn succeed but addRule fail.
	landlockAddRuleFn = func(rulesetFd, ruleType, ruleAttr, flags, _, _ uintptr) (uintptr, uintptr, syscall.Errno) {
		return 0, 0, syscall.EINVAL
	}

	cfg := &platform.WrapConfig{
		WritableRoots: []string{"/tmp"},
	}
	err := applyLandlock(cfg)
	if err == nil {
		t.Fatal("expected error for writable root add rule failure")
	}
	if !strings.Contains(err.Error(), "landlock add writable rule") {
		t.Fatalf("expected error to mention 'landlock add writable rule', got: %v", err)
	}
}

// TestApplyLandlock_DenyWriteAddRuleError verifies error when adding denied-write read-only rule fails.
func TestApplyLandlock_DenyWriteAddRuleError(t *testing.T) {
	saveLandlockFns(t)
	mockAllSuccess(t, 1)

	// Make openPathFn succeed but addRule fail.
	landlockAddRuleFn = func(rulesetFd, ruleType, ruleAttr, flags, _, _ uintptr) (uintptr, uintptr, syscall.Errno) {
		return 0, 0, syscall.EINVAL
	}

	cfg := &platform.WrapConfig{
		WritableRoots: []string{"/tmp"},
		DenyWrite:     []string{"/tmp"},
	}
	err := applyLandlock(cfg)
	if err == nil {
		t.Fatal("expected error for denied-write add rule failure")
	}
	if !strings.Contains(err.Error(), "landlock add read-only rule for denied-write") {
		t.Fatalf("expected error to mention 'landlock add read-only rule for denied-write', got: %v", err)
	}
}

// TestApplyLandlock_WritableRootOpenError verifies error when opening writable root fails.
func TestApplyLandlock_WritableRootOpenError(t *testing.T) {
	saveLandlockFns(t)
	mockAllSuccess(t, 1)

	openPathFn = func(path string, flags int, mode uint32) (int, error) {
		return -1, syscall.ENOENT
	}

	cfg := &platform.WrapConfig{
		WritableRoots: []string{"/nonexistent"},
	}
	err := applyLandlock(cfg)
	if err == nil {
		t.Fatal("expected error for writable root open failure")
	}
	if !strings.Contains(err.Error(), "landlock add writable rule") {
		t.Fatalf("expected error to mention 'landlock add writable rule', got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// landlockAddPathRule tests
// ---------------------------------------------------------------------------

// TestLandlockAddPathRule_Success verifies successful path rule addition.
func TestLandlockAddPathRule_Success(t *testing.T) {
	saveLandlockFns(t)
	openPathFn = func(path string, flags int, mode uint32) (int, error) {
		return 10, nil
	}
	closePathFn = func(fd int) error {
		return nil
	}
	landlockAddRuleFn = func(rulesetFd, ruleType, ruleAttr, flags, _, _ uintptr) (uintptr, uintptr, syscall.Errno) {
		return 0, 0, 0
	}

	err := landlockAddPathRule(42, "/tmp", accessFSReadFile|accessFSReadDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestLandlockAddPathRule_OpenError verifies error when open fails.
func TestLandlockAddPathRule_OpenError(t *testing.T) {
	saveLandlockFns(t)
	openPathFn = func(path string, flags int, mode uint32) (int, error) {
		return -1, syscall.ENOENT
	}

	err := landlockAddPathRule(42, "/nonexistent", accessFSReadFile)
	if err == nil {
		t.Fatal("expected error for open failure")
	}
	if !strings.Contains(err.Error(), "open") {
		t.Fatalf("expected error to mention 'open', got: %v", err)
	}
}

// TestLandlockAddPathRule_AddRuleError verifies error when add_rule syscall fails.
func TestLandlockAddPathRule_AddRuleError(t *testing.T) {
	saveLandlockFns(t)
	openPathFn = func(path string, flags int, mode uint32) (int, error) {
		return 10, nil
	}
	closePathFn = func(fd int) error {
		return nil
	}
	landlockAddRuleFn = func(rulesetFd, ruleType, ruleAttr, flags, _, _ uintptr) (uintptr, uintptr, syscall.Errno) {
		return 0, 0, syscall.EINVAL
	}

	err := landlockAddPathRule(42, "/tmp", accessFSReadFile)
	if err == nil {
		t.Fatal("expected error for add_rule failure")
	}
	if !strings.Contains(err.Error(), "landlock_add_rule") {
		t.Fatalf("expected error to mention 'landlock_add_rule', got: %v", err)
	}
}
