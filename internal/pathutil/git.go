// Package pathutil git.go provides git worktree detection and resolution.
// It identifies whether a directory is a git worktree (where .git is a file
// rather than a directory) and resolves the gitdir path from the .git file.
package pathutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// IsGitWorktree checks if the .git entry at the given path is a file
// (indicating a git worktree) rather than a directory.
func IsGitWorktree(dir string) bool {
	gitPath := filepath.Join(dir, ".git")
	info, err := os.Lstat(gitPath)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// ResolveGitWorktree reads the .git file in dir (which must be a worktree)
// and returns the resolved gitdir path. Returns ("", nil) if dir is not a
// worktree. Returns an error if the .git file exists but cannot be parsed.
func ResolveGitWorktree(dir string) (string, error) {
	gitPath := filepath.Join(dir, ".git")
	info, err := os.Lstat(gitPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("pathutil: stat .git: %w", err)
	}
	if info.IsDir() {
		return "", nil // Not a worktree (regular git repo)
	}

	data, err := os.ReadFile(gitPath)
	if err != nil {
		return "", fmt.Errorf("pathutil: read .git file: %w", err)
	}

	// Parse only the first non-empty line to avoid treating extra lines,
	// embedded newlines, or NUL bytes as part of the gitdir path.
	firstLine := strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
	if !strings.HasPrefix(firstLine, "gitdir: ") {
		return "", errors.New("pathutil: .git file does not contain gitdir: prefix")
	}

	gitdir := strings.TrimPrefix(firstLine, "gitdir: ")
	gitdir = strings.TrimSpace(gitdir)

	// Reject paths containing control characters that could produce
	// invalid or unsafe DenyWrite entries.
	if strings.ContainsAny(gitdir, "\n\r\x00") {
		return "", errors.New("pathutil: .git gitdir path contains invalid characters")
	}

	// Resolve relative paths against the worktree directory.
	if !filepath.IsAbs(gitdir) {
		gitdir = filepath.Join(dir, gitdir)
	}
	gitdir = filepath.Clean(gitdir)

	// Resolve symlinks so that the returned path matches what bind-mount
	// and Landlock enforcement will see at the filesystem level.
	if resolved, err := filepath.EvalSymlinks(gitdir); err == nil {
		gitdir = resolved
	}

	return gitdir, nil
}
