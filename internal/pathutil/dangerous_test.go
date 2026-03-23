package pathutil

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/zhangyunhao116/agentbox/testutil"
)

// ---------------------------------------------------------------------------
// DangerousFiles / ScanDangerousFiles
// ---------------------------------------------------------------------------

func TestScanDangerousFiles(t *testing.T) {
	testutil.SkipIfWindows(t, "dangerous file detection uses Unix-specific dotfile patterns")
	tmp := t.TempDir()

	// Create some dangerous files.
	mkFile(t, tmp, ".gitconfig")
	mkFile(t, tmp, ".bashrc")
	mkFile(t, tmp, "safe.txt")
	mkDir(t, tmp, ".git/hooks")
	mkDir(t, tmp, ".vscode")
	mkDir(t, tmp, "sub")
	mkFile(t, tmp, "sub/.npmrc")
	mkDir(t, tmp, "sub/.idea")

	found, err := ScanDangerousFiles(tmp, 0)
	if err != nil {
		t.Fatal(err)
	}

	// We expect: .gitconfig, .bashrc, .git/hooks, .vscode, sub/.npmrc, sub/.idea
	if len(found) < 6 {
		t.Errorf("expected at least 6 dangerous entries, got %d: %v", len(found), found)
	}

	// safe.txt should NOT be in the list.
	for _, f := range found {
		if strings.HasSuffix(f, "safe.txt") {
			t.Errorf("safe.txt should not be flagged as dangerous")
		}
	}

	t.Run("maxDepth limits scan", func(t *testing.T) {
		found2, err := ScanDangerousFiles(tmp, 1)
		if err != nil {
			t.Fatal(err)
		}
		// At depth 1 we should find root-level items but not sub/.idea or sub/.npmrc
		for _, f := range found2 {
			rel, _ := filepath.Rel(tmp, f)
			depth := strings.Count(rel, string(filepath.Separator))
			if depth > 1 {
				t.Errorf("maxDepth=1 should not reach %q (depth %d)", rel, depth)
			}
		}
	})

	t.Run("non-existent root", func(t *testing.T) {
		_, err := ScanDangerousFiles(filepath.Join(tmp, "nonexistent"), 0)
		// filepath.Walk returns an error for non-existent root, but we skip walk errors.
		// The function should not panic.
		if err != nil {
			// It's acceptable to return an error here.
			_ = err
		}
	})
}

// ---------------------------------------------------------------------------
// DangerousFiles variable checks
// ---------------------------------------------------------------------------

func TestDangerousFilesNotEmpty(t *testing.T) {
	if len(GetDangerousFiles()) == 0 {
		t.Error("GetDangerousFiles() should not be empty")
	}
	if len(GetDangerousDirectories()) == 0 {
		t.Error("GetDangerousDirectories() should not be empty")
	}
}

// ---------------------------------------------------------------------------
// Additional edge-case tests
// ---------------------------------------------------------------------------

func TestScanDangerousFiles_InaccessibleDir(t *testing.T) {
	testutil.SkipIfWindows(t, "Unix file permissions do not apply on Windows")
	if os.Getuid() == 0 {
		t.Skip("skipping permission test when running as root")
	}
	tmp := t.TempDir()
	mkDir(t, tmp, "noperm/child")
	mkFile(t, tmp, "noperm/child/.bashrc")

	noPermDir := filepath.Join(tmp, "noperm")
	if err := os.Chmod(noPermDir, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(noPermDir, 0755) //nolint: errcheck

	// Should not fail, just skip inaccessible entries.
	found, err := ScanDangerousFiles(tmp, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range found {
		if strings.Contains(f, "noperm") {
			t.Errorf("should not find files in inaccessible dir: %s", f)
		}
	}
}

func TestScanDangerousFiles_DeepMaxDepth(t *testing.T) {
	// Test that maxDepth properly skips deep directories and files.
	tmp := t.TempDir()
	// Create a structure deeper than maxDepth=1:
	// root/sub/deep/.bashrc  (depth 3 from root)
	// root/sub/deep/deepdir/ (depth 3 from root, directory)
	mkDir(t, tmp, "sub/deep/deepdir")
	mkFile(t, tmp, "sub/deep/.bashrc")

	found, err := ScanDangerousFiles(tmp, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range found {
		if strings.Contains(f, "deep") {
			t.Errorf("maxDepth=1 should not reach deep entries: %s", f)
		}
	}
}

// TestScanDangerousFiles_AbsError triggers the filepath.Abs error path
// by removing the current working directory so that os.Getwd (called
// internally by filepath.Abs for relative paths) fails.
func TestScanDangerousFiles_AbsError(t *testing.T) {
	testutil.SkipIfWindows(t, "cannot remove CWD on Windows")
	if runtime.GOOS == "darwin" {
		t.Skip("filepath.Abs does not fail on macOS when CWD is deleted")
	}

	// Save original working directory so we can restore it.
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	// Create a temporary directory, chdir into it, then remove it.
	tmp := t.TempDir()
	doomed := filepath.Join(tmp, "doomed")
	if err := os.Mkdir(doomed, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(doomed); err != nil {
		t.Fatal(err)
	}
	// Ensure we restore CWD even on failure.
	defer func() {
		_ = os.Chdir(origDir)
	}()

	if err := os.Remove(doomed); err != nil {
		t.Fatal(err)
	}

	// Now filepath.Abs("relative") will fail because Getwd fails.
	_, err = ScanDangerousFiles("relative", 0)
	if err == nil {
		t.Fatal("expected error from ScanDangerousFiles with invalid CWD, got nil")
	}
	if !strings.Contains(err.Error(), "cannot resolve root") {
		t.Fatalf("unexpected error message: %v", err)
	}
}
