package pathutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zhangyunhao116/agentbox/testutil"
)

// ---------------------------------------------------------------------------
// IsGitWorktree
// ---------------------------------------------------------------------------

func TestIsGitWorktree(t *testing.T) {
	tmp := t.TempDir()

	t.Run("no .git entry", func(t *testing.T) {
		if IsGitWorktree(tmp) {
			t.Error("expected false when no .git exists")
		}
	})

	t.Run(".git is directory (normal repo)", func(t *testing.T) {
		dir := filepath.Join(tmp, "normalrepo")
		mkDir(t, dir, ".git")
		if IsGitWorktree(dir) {
			t.Error("expected false when .git is a directory")
		}
	})

	t.Run(".git is file (worktree)", func(t *testing.T) {
		dir := filepath.Join(tmp, "worktree")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		gitFile := filepath.Join(dir, ".git")
		if err := os.WriteFile(gitFile, []byte("gitdir: /some/path"), 0644); err != nil {
			t.Fatal(err)
		}
		if !IsGitWorktree(dir) {
			t.Error("expected true when .git is a file")
		}
	})
}

// ---------------------------------------------------------------------------
// ResolveGitWorktree
// ---------------------------------------------------------------------------

// resolveSymlinks calls filepath.EvalSymlinks, returning the original path on error.
// This is needed because platforms like macOS have system-level symlinks
// (e.g., /var → /private/var) that EvalSymlinks in the production code resolves.
func resolveSymlinks(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return path
	}
	return resolved
}

func TestResolveGitWorktree(t *testing.T) {
	tmp := t.TempDir()

	t.Run("regular git repo returns empty", func(t *testing.T) {
		dir := filepath.Join(tmp, "regularrepo")
		mkDir(t, dir, ".git")
		got, err := ResolveGitWorktree(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "" {
			t.Errorf("expected empty string for regular repo, got %q", got)
		}
	})

	t.Run("non-existent directory returns empty", func(t *testing.T) {
		got, err := ResolveGitWorktree(filepath.Join(tmp, "nonexistent"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "" {
			t.Errorf("expected empty string for non-existent dir, got %q", got)
		}
	})

	t.Run("worktree with absolute gitdir path", func(t *testing.T) {
		dir := filepath.Join(tmp, "wt-abs")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(tmp, "main-repo", ".git", "worktrees", "wt-abs")
		if err := os.MkdirAll(target, 0o755); err != nil {
			t.Fatal(err)
		}
		gitFile := filepath.Join(dir, ".git")
		if err := os.WriteFile(gitFile, []byte("gitdir: "+target), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := ResolveGitWorktree(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// EvalSymlinks resolves platform symlinks (e.g., /var → /private/var on macOS).
		want := resolveSymlinks(t, target)
		if got != want {
			t.Errorf("expected %q, got %q", want, got)
		}
	})

	t.Run("worktree with relative gitdir path", func(t *testing.T) {
		dir := filepath.Join(tmp, "wt-rel")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		// Create target directory relative to dir.
		target := filepath.Join(dir, "..", "main-repo-rel", ".git", "worktrees", "wt-rel")
		if err := os.MkdirAll(target, 0o755); err != nil {
			t.Fatal(err)
		}
		gitFile := filepath.Join(dir, ".git")
		if err := os.WriteFile(gitFile, []byte("gitdir: ../main-repo-rel/.git/worktrees/wt-rel"), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := ResolveGitWorktree(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := filepath.Clean(filepath.Join(dir, "..", "main-repo-rel", ".git", "worktrees", "wt-rel"))
		// EvalSymlinks resolves platform symlinks (e.g., /var → /private/var on macOS).
		want = resolveSymlinks(t, want)
		if got != want {
			t.Errorf("expected %q, got %q", want, got)
		}
	})

	t.Run("malformed .git file returns error", func(t *testing.T) {
		dir := filepath.Join(tmp, "wt-malformed")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		gitFile := filepath.Join(dir, ".git")
		if err := os.WriteFile(gitFile, []byte("not a valid gitdir reference"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := ResolveGitWorktree(dir)
		if err == nil {
			t.Fatal("expected error for malformed .git file")
		}
		if !strings.Contains(err.Error(), "gitdir:") {
			t.Errorf("expected error about gitdir: prefix, got: %v", err)
		}
	})

	t.Run("extra whitespace in .git file", func(t *testing.T) {
		dir := filepath.Join(tmp, "wt-whitespace")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(tmp, "main-ws", ".git", "worktrees", "wt-ws")
		if err := os.MkdirAll(target, 0o755); err != nil {
			t.Fatal(err)
		}
		gitFile := filepath.Join(dir, ".git")
		// Content with extra whitespace and trailing newline.
		if err := os.WriteFile(gitFile, []byte("gitdir: "+target+"  \n\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := ResolveGitWorktree(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// EvalSymlinks resolves platform symlinks (e.g., /var → /private/var on macOS).
		want := resolveSymlinks(t, target)
		if got != want {
			t.Errorf("expected %q, got %q", want, got)
		}
	})
}

// TestResolveGitWorktree_Parsing verifies that ResolveGitWorktree correctly
// handles multi-line .git files and rejects paths with control characters.
func TestResolveGitWorktree_Parsing(t *testing.T) {
	tmp := t.TempDir()

	t.Run("multi-line .git file uses only first line", func(t *testing.T) {
		dir := filepath.Join(tmp, "wt-multiline")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(tmp, "main-multi", ".git", "worktrees", "wt-multi")
		if err := os.MkdirAll(target, 0o755); err != nil {
			t.Fatal(err)
		}
		gitFile := filepath.Join(dir, ".git")
		content := "gitdir: " + target + "\nextra-line: should-be-ignored\n"
		if err := os.WriteFile(gitFile, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := ResolveGitWorktree(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := resolveSymlinks(t, target)
		if got != want {
			t.Errorf("expected %q, got %q", want, got)
		}
	})

	t.Run("gitdir with NUL byte returns error", func(t *testing.T) {
		dir := filepath.Join(tmp, "wt-nul")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		gitFile := filepath.Join(dir, ".git")
		content := "gitdir: /some/path\x00injected"
		if err := os.WriteFile(gitFile, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := ResolveGitWorktree(dir)
		if err == nil {
			t.Fatal("expected error for gitdir with NUL byte")
		}
		if !strings.Contains(err.Error(), "invalid characters") {
			t.Errorf("expected 'invalid characters' error, got: %v", err)
		}
	})
}

// TestResolveGitWorktree_PermissionError verifies that a non-ErrNotExist
// error from Lstat (e.g., EACCES) is propagated instead of silently ignored.
func TestResolveGitWorktree_PermissionError(t *testing.T) {
	testutil.SkipIfWindows(t, "permission-based test not reliable on Windows")
	if os.Getuid() == 0 {
		t.Skip("cannot test permission errors as root")
	}

	tmp := t.TempDir()
	dir := filepath.Join(tmp, "wt-noperm")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Create a .git file so it exists.
	gitFile := filepath.Join(dir, ".git")
	if err := os.WriteFile(gitFile, []byte("gitdir: /some/path"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Remove all permissions from the parent directory so Lstat returns EACCES.
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o755) // Restore so cleanup can remove the temp dir.
	})
	_, err := ResolveGitWorktree(dir)
	if err == nil {
		t.Fatal("expected error for permission-denied .git Lstat")
	}
	if !strings.Contains(err.Error(), "pathutil: stat .git:") {
		t.Errorf("unexpected error format: %v", err)
	}
}
