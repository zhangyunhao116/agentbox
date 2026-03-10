//go:build linux

package linux

import (
	"errors"
	"os"
	"syscall"
	"testing"

	"github.com/zhangyunhao116/agentbox/platform"
)

// saveBindMountFns saves mount/stat/evalSymlinks function variables and restores them on cleanup.
func saveBindMountFns(t *testing.T) {
	t.Helper()
	origMount := mountFn
	origStat := statPathFn
	origEvalSymlinks := evalSymlinksFn
	t.Cleanup(func() {
		mountFn = origMount
		statPathFn = origStat
		evalSymlinksFn = origEvalSymlinks
	})
}

// ---------------------------------------------------------------------------
// denyWriteSubpaths tests
// ---------------------------------------------------------------------------

// TestDenyWriteSubpaths verifies denyWriteSubpaths returns correct subpaths.
func TestDenyWriteSubpaths(t *testing.T) {
	// Save and restore evalSymlinksFn for all subtests.
	origEvalSymlinks := evalSymlinksFn
	t.Cleanup(func() { evalSymlinksFn = origEvalSymlinks })
	evalSymlinksFn = func(path string) (string, error) { return path, nil }
	tests := []struct {
		name          string
		denyWrite     []string
		writableRoots []string
		want          []string
	}{
		{
			name:          "subpath of writable root",
			denyWrite:     []string{"/project/.git/hooks"},
			writableRoots: []string{"/project"},
			want:          []string{"/project/.git/hooks"},
		},
		{
			name:          "exact match is not a strict subpath",
			denyWrite:     []string{"/project"},
			writableRoots: []string{"/project"},
			want:          nil,
		},
		{
			name:          "no overlap",
			denyWrite:     []string{"/other/path"},
			writableRoots: []string{"/project"},
			want:          nil,
		},
		{
			name:          "multiple deny-write subpaths",
			denyWrite:     []string{"/project/.git/hooks", "/project/.env"},
			writableRoots: []string{"/project"},
			want:          []string{"/project/.git/hooks", "/project/.env"},
		},
		{
			name:          "prefix overlap not a subpath",
			denyWrite:     []string{"/project2/secret"},
			writableRoots: []string{"/project"},
			want:          nil,
		},
		{
			name:          "multiple writable roots",
			denyWrite:     []string{"/home/user/.ssh"},
			writableRoots: []string{"/tmp", "/home/user"},
			want:          []string{"/home/user/.ssh"},
		},
		{
			name:          "empty inputs",
			denyWrite:     nil,
			writableRoots: nil,
			want:          nil,
		},
		{
			name:          "trailing slashes cleaned",
			denyWrite:     []string{"/project/.git/hooks/"},
			writableRoots: []string{"/project/"},
			want:          []string{"/project/.git/hooks"},
		},
		{
			name:          "redundant components cleaned",
			denyWrite:     []string{"/project/./sub/../.git/hooks"},
			writableRoots: []string{"/project"},
			want:          []string{"/project/.git/hooks"},
		},
		{
			name:          "root writable root",
			denyWrite:     []string{"/home/user/.gitconfig"},
			writableRoots: []string{"/"},
			want:          []string{"/home/user/.gitconfig"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := denyWriteSubpaths(tt.denyWrite, tt.writableRoots)
			if len(got) != len(tt.want) {
				t.Fatalf("denyWriteSubpaths() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("denyWriteSubpaths()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// denyWriteSubpaths symlink resolution test
// ---------------------------------------------------------------------------

// TestDenyWriteSubpaths_SymlinkResolution verifies that symlinks in deny-write
// and writable-root paths are resolved before comparison.
func TestDenyWriteSubpaths_SymlinkResolution(t *testing.T) {
	origEvalSymlinks := evalSymlinksFn
	t.Cleanup(func() { evalSymlinksFn = origEvalSymlinks })

	// Simulate symlinks: /project -> /real/project, /project/.git -> /real/project/.git
	evalSymlinksFn = func(path string) (string, error) {
		switch path {
		case "/symlink/project":
			return "/real/project", nil
		case "/symlink/project/.git/hooks":
			return "/real/project/.git/hooks", nil
		default:
			return path, nil
		}
	}

	// Without symlink resolution, /symlink/project/.git/hooks is a subpath of
	// /symlink/project. With resolution, /real/project/.git/hooks is a subpath
	// of /real/project, which should still match.
	got := denyWriteSubpaths(
		[]string{"/symlink/project/.git/hooks"},
		[]string{"/symlink/project"},
	)
	if len(got) != 1 {
		t.Fatalf("expected 1 subpath, got %d: %v", len(got), got)
	}
	if got[0] != "/real/project/.git/hooks" {
		t.Errorf("got %q, want %q", got[0], "/real/project/.git/hooks")
	}
}

// TestDenyWriteSubpaths_SymlinkBreaksSubpath verifies that resolving symlinks
// can prevent a path from being treated as a subpath when it isn't really one.
func TestDenyWriteSubpaths_SymlinkBreaksSubpath(t *testing.T) {
	origEvalSymlinks := evalSymlinksFn
	t.Cleanup(func() { evalSymlinksFn = origEvalSymlinks })

	// /project/link resolves to /other/location, which is NOT under /real/project.
	evalSymlinksFn = func(path string) (string, error) {
		switch path {
		case "/project/link":
			return "/other/location", nil
		case "/project":
			return "/real/project", nil
		default:
			return path, nil
		}
	}

	got := denyWriteSubpaths(
		[]string{"/project/link"},
		[]string{"/project"},
	)
	if len(got) != 0 {
		t.Fatalf("expected 0 subpaths (symlink breaks relationship), got %d: %v", len(got), got)
	}
}

// TestDenyWriteSubpaths_DedupAfterSymlinkResolution verifies that duplicate
// paths after symlink resolution are deduplicated.
func TestDenyWriteSubpaths_DedupAfterSymlinkResolution(t *testing.T) {
	origEvalSymlinks := evalSymlinksFn
	t.Cleanup(func() { evalSymlinksFn = origEvalSymlinks })

	// Both paths resolve to the same real path.
	evalSymlinksFn = func(path string) (string, error) {
		switch path {
		case "/project/.git/hooks":
			return "/real/.git/hooks", nil
		case "/project/symlink-to-hooks":
			return "/real/.git/hooks", nil
		case "/project":
			return "/real", nil
		default:
			return path, nil
		}
	}

	got := denyWriteSubpaths(
		[]string{"/project/.git/hooks", "/project/symlink-to-hooks"},
		[]string{"/project"},
	)
	if len(got) != 1 {
		t.Fatalf("expected 1 deduplicated subpath, got %d: %v", len(got), got)
	}
	if got[0] != "/real/.git/hooks" {
		t.Errorf("got %q, want %q", got[0], "/real/.git/hooks")
	}
}

// ---------------------------------------------------------------------------
// applyReadOnlyBindMounts tests
// ---------------------------------------------------------------------------

// TestApplyReadOnlyBindMounts_NoSubpaths verifies no-op when no DenyWrite
// paths are subpaths of writable roots.
func TestApplyReadOnlyBindMounts_NoSubpaths(t *testing.T) {
	saveBindMountFns(t)

	evalSymlinksFn = func(path string) (string, error) { return path, nil }
	mountCalled := false
	mountFn = func(source, target, fstype string, flags uintptr, data string) error {
		mountCalled = true
		return nil
	}
	statPathFn = func(path string) (os.FileInfo, error) {
		return nil, nil
	}

	cfg := &platform.WrapConfig{
		WritableRoots: []string{"/project"},
		DenyWrite:     []string{"/other/path"},
	}
	err := applyReadOnlyBindMounts(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mountCalled {
		t.Error("mount should not have been called when no subpaths match")
	}
}

// TestApplyReadOnlyBindMounts_Success verifies successful bind mount + remount
// sequence for a DenyWrite subpath.
func TestApplyReadOnlyBindMounts_Success(t *testing.T) {
	saveBindMountFns(t)

	evalSymlinksFn = func(path string) (string, error) { return path, nil }
	var mountCalls []struct {
		source string
		target string
		flags  uintptr
	}
	mountFn = func(source, target, fstype string, flags uintptr, data string) error {
		mountCalls = append(mountCalls, struct {
			source string
			target string
			flags  uintptr
		}{source, target, flags})
		return nil
	}
	statPathFn = func(path string) (os.FileInfo, error) {
		return nil, nil // All paths exist.
	}

	cfg := &platform.WrapConfig{
		WritableRoots: []string{"/project"},
		DenyWrite:     []string{"/project/.git/hooks"},
	}
	err := applyReadOnlyBindMounts(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expect exactly 3 mount calls: MS_PRIVATE + bind mount + remount read-only.
	if len(mountCalls) != 3 {
		t.Fatalf("expected 3 mount calls, got %d", len(mountCalls))
	}

	// First call: make root mount private.
	expectedPrivateFlags := uintptr(syscall.MS_REC | syscall.MS_PRIVATE)
	if mountCalls[0].target != "/" || mountCalls[0].flags != expectedPrivateFlags {
		t.Errorf("first call: target=%q flags=%d, want target=%q flags=%d",
			mountCalls[0].target, mountCalls[0].flags, "/", expectedPrivateFlags)
	}

	// Second call: bind mount.
	if mountCalls[1].source != "/project/.git/hooks" {
		t.Errorf("bind mount source = %q, want %q", mountCalls[1].source, "/project/.git/hooks")
	}
	if mountCalls[1].target != "/project/.git/hooks" {
		t.Errorf("bind mount target = %q, want %q", mountCalls[1].target, "/project/.git/hooks")
	}
	expectedBindFlags := uintptr(syscall.MS_BIND | syscall.MS_REC)
	if mountCalls[1].flags != expectedBindFlags {
		t.Errorf("bind mount flags = %d, want %d (MS_BIND|MS_REC)", mountCalls[1].flags, expectedBindFlags)
	}

	// Third call: remount read-only.
	if mountCalls[2].target != "/project/.git/hooks" {
		t.Errorf("remount target = %q, want %q", mountCalls[2].target, "/project/.git/hooks")
	}
	expectedRemountFlags := uintptr(syscall.MS_REMOUNT | syscall.MS_BIND | syscall.MS_RDONLY)
	if mountCalls[2].flags != expectedRemountFlags {
		t.Errorf("remount flags = %d, want %d (MS_REMOUNT|MS_BIND|MS_RDONLY)", mountCalls[2].flags, expectedRemountFlags)
	}
}

// TestApplyReadOnlyBindMounts_NonExistentPathSkipped verifies that paths that
// do not exist on disk are silently skipped.
func TestApplyReadOnlyBindMounts_NonExistentPathSkipped(t *testing.T) {
	saveBindMountFns(t)

	evalSymlinksFn = func(path string) (string, error) { return path, nil }
	var mountCalls []struct {
		target string
		flags  uintptr
	}
	mountFn = func(source, target, fstype string, flags uintptr, data string) error {
		mountCalls = append(mountCalls, struct {
			target string
			flags  uintptr
		}{target, flags})
		return nil
	}
	statPathFn = func(path string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}

	cfg := &platform.WrapConfig{
		WritableRoots: []string{"/project"},
		DenyWrite:     []string{"/project/.git/hooks"},
	}
	err := applyReadOnlyBindMounts(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only the MS_PRIVATE call should have been made; bind mount is skipped.
	if len(mountCalls) != 1 {
		t.Fatalf("expected 1 mount call (MS_PRIVATE only), got %d", len(mountCalls))
	}
	expectedPrivateFlags := uintptr(syscall.MS_REC | syscall.MS_PRIVATE)
	if mountCalls[0].target != "/" || mountCalls[0].flags != expectedPrivateFlags {
		t.Errorf("expected MS_PRIVATE on '/', got target=%q flags=%d", mountCalls[0].target, mountCalls[0].flags)
	}
}

// TestApplyReadOnlyBindMounts_BindMountError verifies error propagation when
// the initial bind mount fails.
func TestApplyReadOnlyBindMounts_BindMountError(t *testing.T) {
	saveBindMountFns(t)

	evalSymlinksFn = func(path string) (string, error) { return path, nil }
	callCount := 0
	mountFn = func(source, target, fstype string, flags uintptr, data string) error {
		callCount++
		if callCount == 1 {
			return nil // MS_PRIVATE succeeds.
		}
		return errors.New("mock bind mount error")
	}
	statPathFn = func(path string) (os.FileInfo, error) {
		return nil, nil
	}

	cfg := &platform.WrapConfig{
		WritableRoots: []string{"/project"},
		DenyWrite:     []string{"/project/.git/hooks"},
	}
	err := applyReadOnlyBindMounts(cfg)
	if err == nil {
		t.Fatal("expected error for bind mount failure")
	}
	if got := err.Error(); got != `bind mount "/project/.git/hooks": mock bind mount error` {
		t.Errorf("unexpected error message: %s", got)
	}
}

// TestApplyReadOnlyBindMounts_RemountError verifies error propagation when
// the read-only remount fails.
func TestApplyReadOnlyBindMounts_RemountError(t *testing.T) {
	saveBindMountFns(t)

	evalSymlinksFn = func(path string) (string, error) { return path, nil }
	callCount := 0
	mountFn = func(source, target, fstype string, flags uintptr, data string) error {
		callCount++
		if callCount == 3 {
			return errors.New("mock remount error")
		}
		return nil
	}
	statPathFn = func(path string) (os.FileInfo, error) {
		return nil, nil
	}

	cfg := &platform.WrapConfig{
		WritableRoots: []string{"/project"},
		DenyWrite:     []string{"/project/.git/hooks"},
	}
	err := applyReadOnlyBindMounts(cfg)
	if err == nil {
		t.Fatal("expected error for remount failure")
	}
	if got := err.Error(); got != `remount read-only "/project/.git/hooks": mock remount error` {
		t.Errorf("unexpected error message: %s", got)
	}
}

// TestApplyReadOnlyBindMounts_MultipleSubpaths verifies that multiple DenyWrite
// subpaths each get their own bind mount pair.
func TestApplyReadOnlyBindMounts_MultipleSubpaths(t *testing.T) {
	saveBindMountFns(t)

	evalSymlinksFn = func(path string) (string, error) { return path, nil }
	var mountTargets []string
	mountFn = func(source, target, fstype string, flags uintptr, data string) error {
		mountTargets = append(mountTargets, target)
		return nil
	}
	statPathFn = func(path string) (os.FileInfo, error) {
		return nil, nil
	}

	cfg := &platform.WrapConfig{
		WritableRoots: []string{"/project"},
		DenyWrite:     []string{"/project/.git/hooks", "/project/.ssh"},
	}
	err := applyReadOnlyBindMounts(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 1 MS_PRIVATE + 2 subpaths × 2 mount calls each = 5 total.
	if len(mountTargets) != 5 {
		t.Fatalf("expected 5 mount calls, got %d: %v", len(mountTargets), mountTargets)
	}
	// First call: MS_PRIVATE on "/".
	if mountTargets[0] != "/" {
		t.Errorf("first mount target = %q, want %q", mountTargets[0], "/")
	}
	// Second pair for .git/hooks.
	if mountTargets[1] != "/project/.git/hooks" || mountTargets[2] != "/project/.git/hooks" {
		t.Errorf("unexpected targets for first subpath: %v", mountTargets[1:3])
	}
	// Third pair for .ssh.
	if mountTargets[3] != "/project/.ssh" || mountTargets[4] != "/project/.ssh" {
		t.Errorf("unexpected targets for second subpath: %v", mountTargets[3:5])
	}
}

// TestApplyReadOnlyBindMounts_EmptyConfig verifies no-op with empty config.
func TestApplyReadOnlyBindMounts_EmptyConfig(t *testing.T) {
	saveBindMountFns(t)

	evalSymlinksFn = func(path string) (string, error) { return path, nil }
	mountCalled := false
	mountFn = func(source, target, fstype string, flags uintptr, data string) error {
		mountCalled = true
		return nil
	}

	cfg := &platform.WrapConfig{}
	err := applyReadOnlyBindMounts(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mountCalled {
		t.Error("mount should not have been called with empty config")
	}
}

// TestApplyReadOnlyBindMounts_MSPrivateError verifies that a failure to make
// the root mount private is propagated as an error.
func TestApplyReadOnlyBindMounts_MSPrivateError(t *testing.T) {
	saveBindMountFns(t)

	evalSymlinksFn = func(path string) (string, error) { return path, nil }
	mountFn = func(source, target, fstype string, flags uintptr, data string) error {
		return errors.New("mock MS_PRIVATE error")
	}
	statPathFn = func(path string) (os.FileInfo, error) {
		return nil, nil
	}

	cfg := &platform.WrapConfig{
		WritableRoots: []string{"/project"},
		DenyWrite:     []string{"/project/.git/hooks"},
	}
	err := applyReadOnlyBindMounts(cfg)
	if err == nil {
		t.Fatal("expected error for MS_PRIVATE failure")
	}
	if got := err.Error(); got != "make root mount private: mock MS_PRIVATE error" {
		t.Errorf("unexpected error message: %s", got)
	}
}

// TestApplyReadOnlyBindMounts_StatPermissionError verifies that a non-ENOENT
// stat error (e.g. EACCES) is propagated rather than silently skipped.
func TestApplyReadOnlyBindMounts_StatPermissionError(t *testing.T) {
	saveBindMountFns(t)

	evalSymlinksFn = func(path string) (string, error) { return path, nil }
	mountFn = func(source, target, fstype string, flags uintptr, data string) error {
		return nil
	}
	statPathFn = func(path string) (os.FileInfo, error) {
		return nil, errors.New("permission denied")
	}

	cfg := &platform.WrapConfig{
		WritableRoots: []string{"/project"},
		DenyWrite:     []string{"/project/.git/hooks"},
	}
	err := applyReadOnlyBindMounts(cfg)
	if err == nil {
		t.Fatal("expected error for stat permission failure")
	}
	want := `stat deny-write path "/project/.git/hooks": permission denied`
	if got := err.Error(); got != want {
		t.Errorf("unexpected error: got %q, want %q", got, want)
	}
}
